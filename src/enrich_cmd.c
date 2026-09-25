/* enrich: the only command. build, fetch, lookup, and delta-apply.
 *
 * URLs and credentials live in the JSON file given by -c. Search order
 * when -c is omitted: ./enrich.json, then /etc/enrich.json.
 *
 * Copyright 2026 Advens. Apache-2.0. See LICENSE.
 */
#define _POSIX_C_SOURCE 200809L

#include "enrich.h"

#include <json.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int thrtutil_main(int argc, char **argv);
int thrt_cli_main(int argc, char **argv);
int overlay_tool_main(int argc, char **argv);
int prev_lookup_main(int argc, char **argv);

#define MAX_ARGV 256
#define MAX_FEEDS 128

static void die(const char *msg)
{
    fprintf(stderr, "enrich: %s\n", msg);
    exit(1);
}

static const char *jstr(struct json_object *obj, const char *key)
{
    struct json_object *v = NULL;
    if (obj == NULL || !json_object_object_get_ex(obj, key, &v) || v == NULL)
        return NULL;
    return json_object_get_string(v);
}

static struct json_object *load_config(const char *path)
{
    struct stat st;
    FILE *f;
    char *buf;
    struct json_object *root;
    size_t n;

    if (stat(path, &st) != 0)
        die("cannot stat config");
    if (st.st_size <= 0 || st.st_size > 1024 * 1024)
        die("config is empty or larger than 1MB");
    buf = malloc((size_t)st.st_size + 1);
    if (buf == NULL)
        die("out of memory");
    f = fopen(path, "r");
    if (f == NULL) {
        free(buf);
        die("cannot open config");
    }
    n = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);
    buf[n] = '\0';
    root = json_tokener_parse(buf);
    free(buf);
    if (root == NULL)
        die("cannot parse config");
    if ((st.st_mode & 077) != 0) {
        struct json_object *geo = NULL;
        const char *lic = NULL;
        if (json_object_object_get_ex(root, "geoip", &geo))
            lic = jstr(geo, "license_key");
        if (lic != NULL && lic[0] != '\0')
            fprintf(stderr, "enrich: %s holds a license key and is readable by group or other\n", path);
    }
    return root;
}

static const char *find_config(const char *opt)
{
    if (opt != NULL && opt[0] != '\0')
        return opt;
    if (access("enrich.json", R_OK) == 0)
        return "enrich.json";
    if (access("/etc/enrich.json", R_OK) == 0)
        return "/etc/enrich.json";
    die("no config (pass -c, or create ./enrich.json or /etc/enrich.json)");
    return NULL;
}

/* curl writes to dest. user is user:pass for Basic auth, or NULL.
 * hdr is an extra header, or NULL. body is a POST body, or NULL. */
static int curl_to_file(const char *url, const char *user, const char *hdr,
                        const char *body, const char *dest)
{
    char tmp[1024];
    pid_t pid;
    int status;
    char *argv[16];
    int n = 0;

    snprintf(tmp, sizeof tmp, "%s.tmp", dest);
    argv[n++] = "curl";
    argv[n++] = "-fsS";
    argv[n++] = "-L";
    argv[n++] = "--max-time";
    argv[n++] = "120";
    if (user != NULL && user[0] != '\0') {
        argv[n++] = "-u";
        argv[n++] = (char *)user;
    }
    if (hdr != NULL) {
        argv[n++] = "-H";
        argv[n++] = (char *)hdr;
    }
    if (body != NULL) {
        argv[n++] = "-d";
        argv[n++] = (char *)body;
    }
    argv[n++] = "-o";
    argv[n++] = tmp;
    argv[n++] = (char *)url;
    argv[n] = NULL;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execvp("curl", argv);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, dest) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int read_text(const char *path, char *dst, size_t dstsz)
{
    FILE *f = fopen(path, "r");
    size_t n;
    if (f == NULL)
        return -1;
    n = fread(dst, 1, dstsz - 1, f);
    fclose(f);
    dst[n] = '\0';
    return 0;
}

static int tar_member(const char *archive, char *member, size_t membersz)
{
    int pipefd[2];
    pid_t pid;
    FILE *in;
    char line[512];
    int status;

    if (pipe(pipefd) != 0)
        return -1;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        char *argv[] = {"tar", "-tzf", (char *)archive, NULL};
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execvp("tar", argv);
        _exit(127);
    }
    close(pipefd[1]);
    in = fdopen(pipefd[0], "r");
    member[0] = '\0';
    if (in != NULL) {
        while (fgets(line, sizeof line, in) != NULL) {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                line[--len] = '\0';
            if (len > 5 && strcmp(line + len - 5, ".mmdb") == 0) {
                snprintf(member, membersz, "%s", line);
                break;
            }
        }
        fclose(in);
    } else {
        close(pipefd[0]);
    }
    waitpid(pid, &status, 0);
    return member[0] == '\0' ? -1 : 0;
}

static int tar_extract_member(const char *archive, const char *member, const char *dest)
{
    int fd, status;
    pid_t pid;

    fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(fd);
        return -1;
    }
    if (pid == 0) {
        char *argv[] = {"tar", "-xOzf", (char *)archive, (char *)member, NULL};
        dup2(fd, STDOUT_FILENO);
        close(fd);
        execvp("tar", argv);
        _exit(127);
    }
    close(fd);
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return 0;
}

static void fetch_geoip(struct json_object *geo)
{
    const char *account, *key, *dest_dir;
    struct json_object *editions = NULL;
    char user[256];
    int i, n;

    account = jstr(geo, "account_id");
    key = jstr(geo, "license_key");
    dest_dir = jstr(geo, "dest_dir");
    if (dest_dir == NULL)
        dest_dir = "out";
    if (account == NULL || account[0] == '\0' || key == NULL || key[0] == '\0')
        die("geoip.account_id and geoip.license_key are empty in the config");
    mkdir(dest_dir, 0755);
    snprintf(user, sizeof user, "%s:%s", account, key);
    if (!json_object_object_get_ex(geo, "editions", &editions) || editions == NULL)
        die("geoip.editions is missing");
    n = json_object_array_length(editions);
    for (i = 0; i < n; i++) {
        const char *edition = json_object_get_string(json_object_array_get_idx(editions, i));
        char sha_url[512], tar_url[512], mmdb[512], marker_path[512];
        char archive[512], remote_path[512], member[512];
        char remote_sha[160], local_sha[160];
        char *sp;

        snprintf(sha_url, sizeof sha_url,
                 "https://download.maxmind.com/geoip/databases/%s/download?suffix=tar.gz.sha256",
                 edition);
        snprintf(tar_url, sizeof tar_url,
                 "https://download.maxmind.com/geoip/databases/%s/download?suffix=tar.gz",
                 edition);
        snprintf(mmdb, sizeof mmdb, "%s/%s.mmdb", dest_dir, edition);
        snprintf(marker_path, sizeof marker_path, "%s/%s.sha256", dest_dir, edition);
        snprintf(archive, sizeof archive, "%s/%s.tar.gz", dest_dir, edition);
        snprintf(remote_path, sizeof remote_path, "%s/%s.sha256.remote", dest_dir, edition);
        if (curl_to_file(sha_url, user, NULL, NULL, remote_path) != 0)
            die("geoip checksum download failed");
        if (read_text(remote_path, remote_sha, sizeof remote_sha) != 0)
            die("geoip checksum unreadable");
        sp = strchr(remote_sha, ' ');
        if (sp != NULL)
            *sp = '\0';
        if (read_text(marker_path, local_sha, sizeof local_sha) == 0) {
            sp = strchr(local_sha, '\n');
            if (sp != NULL)
                *sp = '\0';
            if (strcmp(local_sha, remote_sha) == 0 && access(mmdb, R_OK) == 0)
                continue;
        }
        if (curl_to_file(tar_url, user, NULL, NULL, archive) != 0)
            die("geoip archive download failed");
        if (tar_member(archive, member, sizeof member) != 0)
            die("geoip archive has no .mmdb");
        if (tar_extract_member(archive, member, mmdb) != 0)
            die("geoip extract failed");
        {
            FILE *mf = fopen(marker_path, "w");
            if (mf == NULL)
                die("cannot write geoip checksum marker");
            fprintf(mf, "%s\n", remote_sha);
            fclose(mf);
        }
        unlink(archive);
        unlink(remote_path);
    }
}

static void fetch_misp(struct json_object *feed)
{
    const char *url = jstr(feed, "url");
    const char *key = jstr(feed, "key");
    const char *dest = jstr(feed, "dest");
    const char *since = jstr(feed, "since");
    char endpoint[1024], hdr[512], body[256];

    if (url == NULL || key == NULL || key[0] == '\0' || dest == NULL)
        die("misp feed needs url, key, and dest in the config");
    if (since == NULL)
        since = "7d";
    snprintf(endpoint, sizeof endpoint, "%s/attributes/restSearch", url);
    snprintf(hdr, sizeof hdr, "Authorization: %s", key);
    snprintf(body, sizeof body,
             "{\"returnFormat\":\"json\",\"last\":\"%s\",\"to_ids\":1,\"limit\":10000}",
             since);
    if (curl_to_file(endpoint, NULL, hdr, body, dest) != 0)
        die("misp download failed");
}

static void fetch_plain(struct json_object *feed, const char *what)
{
    const char *url = jstr(feed, "url");
    const char *dest = jstr(feed, "dest");
    if (url == NULL || dest == NULL) {
        fprintf(stderr, "enrich: %s feed needs url and dest\n", what);
        exit(1);
    }
    if (curl_to_file(url, NULL, NULL, NULL, dest) != 0)
        die("download failed");
}

static void cmd_fetch(struct json_object *cfg)
{
    struct json_object *geo = NULL;
    struct json_object *feeds = NULL;
    int i, n;

    if (json_object_object_get_ex(cfg, "geoip", &geo) && geo != NULL)
        fetch_geoip(geo);
    if (!json_object_object_get_ex(cfg, "feeds", &feeds) || feeds == NULL)
        return;
    n = json_object_array_length(feeds);
    for (i = 0; i < n && i < MAX_FEEDS; i++) {
        struct json_object *feed = json_object_array_get_idx(feeds, i);
        const char *type = jstr(feed, "type");
        if (type == NULL)
            continue;
        if (strcmp(type, "misp") == 0 && jstr(feed, "url") != NULL)
            fetch_misp(feed);
        else if (strcmp(type, "ua") == 0 || strcmp(type, "tld") == 0 ||
                 strcmp(type, "file") == 0)
            fetch_plain(feed, type);
    }
}

static int is_thrt_type(const char *type)
{
    return strcmp(type, "csv") == 0 || strcmp(type, "json") == 0 ||
           strcmp(type, "lookup") == 0 || strcmp(type, "txt") == 0 ||
           strcmp(type, "ioc") == 0 || strcmp(type, "misp") == 0 ||
           strcmp(type, "tags") == 0;
}

static void cmd_build(struct json_object *cfg)
{
    const char *out = jstr(cfg, "output");
    struct json_object *feeds = NULL;
    char *argv[MAX_ARGV];
    int argc = 0;
    int i, n;

    if (out == NULL)
        die("config output is missing");
    argv[argc++] = "enrich";
    argv[argc++] = "-o";
    argv[argc++] = (char *)out;

    if (json_object_object_get_ex(cfg, "feeds", &feeds) && feeds != NULL) {
        n = json_object_array_length(feeds);
        for (i = 0; i < n; i++) {
            struct json_object *feed = json_object_array_get_idx(feeds, i);
            const char *type = jstr(feed, "type");
            const char *path, *layer;
            if (type == NULL)
                continue;
            if (strcmp(type, "overlay") == 0) {
                const char *dest = jstr(feed, "dest");
                char *ov[5];
                if (dest == NULL)
                    die("overlay feed needs dest");
                ov[0] = "enrich";
                ov[1] = "write";
                ov[2] = (char *)dest;
                ov[3] = (char *)jstr(feed, "path");
                ov[4] = NULL;
                if (overlay_tool_main(ov[3] != NULL ? 4 : 3, ov) != 0)
                    die("overlay write failed");
                continue;
            }
            if (!is_thrt_type(type))
                continue;
            path = jstr(feed, "path");
            if (path == NULL)
                path = jstr(feed, "dest");
            if (path == NULL)
                die("feed has no path");
            layer = jstr(feed, "layer");
            if (layer == NULL)
                layer = (strcmp(type, "tags") == 0) ? "tags" : "cti";
            if (argc + 3 >= MAX_ARGV)
                die("too many feeds");
            argv[argc++] = "-l";
            argv[argc++] = (char *)layer;
            argv[argc++] = (char *)path;
        }
    }
    if (argc < 4)
        die("no .thrt inputs in feeds");
    argv[argc] = NULL;
    if (thrtutil_main(argc, argv) != 0)
        die("thrt build failed");
}

static void cmd_lookup(struct json_object *cfg, const char *indicator)
{
    const char *out = jstr(cfg, "output");
    char *argv[4];
    if (out == NULL || indicator == NULL)
        die("lookup needs config output and an indicator");
    argv[0] = "enrich";
    argv[1] = (char *)out;
    argv[2] = (char *)indicator;
    argv[3] = NULL;
    exit(thrt_cli_main(3, argv));
}

static void usage(void)
{
    fprintf(stderr,
            "usage: enrich [-c file] build\n"
            "       enrich [-c file] fetch\n"
            "       enrich [-c file] run\n"
            "       enrich [-c file] lookup <indicator>\n"
            "       enrich [-c file] apply-delta --segment <file> [--feed-key K]\n"
            "              [--snapshot] [--ttl-days N] [--generation G]\n"
            "\n"
            "Config, when -c is omitted: ./enrich.json then /etc/enrich.json.\n"
            "Feeds in that file:\n"
            "  misp     url, key, since, dest, layer   live /attributes/restSearch\n"
            "  csv json lookup txt ioc misp           local files, layer cti or cti_r\n"
            "  tags     path                           context layer of the same database\n"
            "  overlay  path, dest\n"
            "  geoip    account_id, license_key, dest_dir, editions\n"
            "  ua tld   url, dest\n");
}

int main(int argc, char **argv)
{
    const char *config = NULL;
    const char *cmd = NULL;
    const char *indicator = NULL;
    const char *segment = NULL;
    const char *feed_key = NULL;
    int snapshot = 0;
    const char *ttl = NULL;
    const char *generation = NULL;
    struct json_object *cfg;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--segment") == 0 && i + 1 < argc) {
            segment = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--feed-key") == 0 && i + 1 < argc) {
            feed_key = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--snapshot") == 0) {
            snapshot = 1;
            continue;
        }
        if (strcmp(argv[i], "--ttl-days") == 0 && i + 1 < argc) {
            ttl = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--generation") == 0 && i + 1 < argc) {
            generation = argv[++i];
            continue;
        }
        if (cmd == NULL) {
            cmd = argv[i];
            continue;
        }
        if (indicator == NULL)
            indicator = argv[i];
    }
    if (cmd == NULL) {
        usage();
        return 2;
    }
    if (strcmp(cmd, "version") == 0) {
        printf("%s\n", enrich_version());
        return 0;
    }
    cfg = load_config(find_config(config));
    if (strcmp(cmd, "build") == 0)
        cmd_build(cfg);
    else if (strcmp(cmd, "fetch") == 0)
        cmd_fetch(cfg);
    else if (strcmp(cmd, "run") == 0) {
        cmd_fetch(cfg);
        cmd_build(cfg);
    } else if (strcmp(cmd, "lookup") == 0)
        cmd_lookup(cfg, indicator);
    else if (strcmp(cmd, "apply-delta") == 0) {
        const char *out = jstr(cfg, "output");
        char *av[16];
        int ac = 0;
        if (segment == NULL || out == NULL)
            die("apply-delta needs --segment and config output");
        av[ac++] = "enrich";
        av[ac++] = "--apply-delta";
        av[ac++] = (char *)segment;
        av[ac++] = "-o";
        av[ac++] = (char *)out;
        if (feed_key != NULL) {
            av[ac++] = "--feed-key";
            av[ac++] = (char *)feed_key;
        }
        if (snapshot)
            av[ac++] = "--snapshot";
        if (ttl != NULL) {
            av[ac++] = "--ttl-days";
            av[ac++] = (char *)ttl;
        }
        if (generation != NULL) {
            av[ac++] = "--generation";
            av[ac++] = (char *)generation;
        }
        av[ac] = NULL;
        if (thrtutil_main(ac, av) != 0)
            die("apply-delta failed");
    } else {
        usage();
        return 2;
    }
    json_object_put(cfg);
    return 0;
}
