/* enrich: the only command. build, fetch, lookup, delta-apply, and sync.
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
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_LIBZMQ
#include <zmq.h>
#endif

int thrtutil_main(int argc, char **argv);
int thrt_cli_main(int argc, char **argv);
int overlay_tool_main(int argc, char **argv);
int prev_lookup_main(int argc, char **argv);
void thrt_misp_delta_mode(int on);

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

/* Open path once. required means -c was given: a missing file or a
 * non-regular file is fatal. Otherwise a failure means "try the next
 * candidate". The returned descriptor is the only handle used to stat
 * and read, so a later replacement of the path is not the file we parse. */
static int open_config(const char *path, int required)
{
    int fd;
    struct stat st;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (required)
            die("cannot open config");
        return -1;
    }
    if (fstat(fd, &st) != 0) {
        close(fd);
        if (required)
            die("cannot stat config");
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        if (required)
            die("config is not a regular file");
        return -1;
    }
    return fd;
}

static struct json_object *load_config(int fd, const char *path)
{
    struct stat st;
    char *buf;
    struct json_object *root;
    size_t got;
    ssize_t n;

    if (fstat(fd, &st) != 0) {
        close(fd);
        die("cannot stat config");
    }
    if (st.st_size <= 0 || st.st_size > 1024 * 1024) {
        close(fd);
        die("config is empty or larger than 1MB");
    }
    buf = malloc((size_t)st.st_size + 1);
    if (buf == NULL) {
        close(fd);
        die("out of memory");
    }
    got = 0;
    while (got < (size_t)st.st_size) {
        n = read(fd, buf + got, (size_t)st.st_size - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            free(buf);
            close(fd);
            die("cannot read config");
        }
        if (n == 0)
            break;
        got += (size_t)n;
    }
    close(fd);
    buf[got] = '\0';
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

static int open_chosen_config(const char *opt, const char **path_out)
{
    int fd;

    if (opt != NULL && opt[0] != '\0') {
        *path_out = opt;
        return open_config(opt, 1);
    }
    fd = open_config("enrich.json", 0);
    if (fd >= 0) {
        *path_out = "enrich.json";
        return fd;
    }
    fd = open_config("/etc/enrich.json", 0);
    if (fd >= 0) {
        *path_out = "/etc/enrich.json";
        return fd;
    }
    die("no config (pass -c, or create ./enrich.json or /etc/enrich.json)");
    return -1;
}

/* curl writes to dest. user is user:pass for Basic auth, or NULL.
 * hdr is an extra header, or NULL. body is a POST body, or NULL. */
/* Create every directory above path. Existing directories are left as they are. */
static void mkdir_parent(const char *path)
{
    char buf[1024];
    char *slash;
    char *p;
    size_t n;

    if (path == NULL)
        return;
    n = strlen(path);
    if (n == 0 || n >= sizeof buf)
        return;
    memcpy(buf, path, n + 1);
    slash = strrchr(buf, '/');
    if (slash == NULL || slash == buf)
        return;
    *slash = '\0';
    for (p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        mkdir(buf, 0755);
        *p = '/';
    }
    mkdir(buf, 0755);
}

static int curl_to_file(const char *url, const char *user, const char *hdr,
                        const char *body, const char *dest)
{
    char tmp[1024];
    pid_t pid;
    int status;
    char *argv[20];
    int n = 0;

    mkdir_parent(dest);
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
        argv[n++] = "-H";
        argv[n++] = "Accept: application/json";
        argv[n++] = "-H";
        argv[n++] = "Content-Type: application/json";
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
    if ((account == NULL || account[0] == '\0') && (key == NULL || key[0] == '\0'))
        return;
    if (account == NULL || account[0] == '\0' || key == NULL || key[0] == '\0')
        die("geoip.account_id and geoip.license_key must both be set");
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
        else if (strcmp(type, "stix") == 0 && jstr(feed, "url") != NULL)
            fetch_plain(feed, type);
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
           strcmp(type, "stix") == 0 || strcmp(type, "tags") == 0;
}

static int compile_output(struct json_object *cfg)
{
    const char *out = jstr(cfg, "output");
    struct json_object *feeds = NULL;
    char *argv[MAX_ARGV];
    int argc = 0;
    int i, n;

    if (out == NULL) {
        fprintf(stderr, "enrich: config output is missing\n");
        return -1;
    }
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
                if (dest == NULL) {
                    fprintf(stderr, "enrich: overlay feed needs dest\n");
                    return -1;
                }
                ov[0] = "enrich";
                ov[1] = "write";
                ov[2] = (char *)dest;
                ov[3] = (char *)jstr(feed, "path");
                ov[4] = NULL;
                if (overlay_tool_main(ov[3] != NULL ? 4 : 3, ov) != 0) {
                    fprintf(stderr, "enrich: overlay write failed\n");
                    return -1;
                }
                continue;
            }
            if (!is_thrt_type(type))
                continue;
            path = jstr(feed, "path");
            if (path == NULL)
                path = jstr(feed, "dest");
            if (path == NULL) {
                fprintf(stderr, "enrich: feed has no path\n");
                return -1;
            }
            layer = jstr(feed, "layer");
            if (layer == NULL)
                layer = (strcmp(type, "tags") == 0) ? "tags" : "cti";
            if (argc + 3 >= MAX_ARGV) {
                fprintf(stderr, "enrich: too many feeds\n");
                return -1;
            }
            argv[argc++] = "-l";
            argv[argc++] = (char *)layer;
            argv[argc++] = (char *)path;
        }
    }
    if (argc < 4) {
        fprintf(stderr, "enrich: no .thrt inputs in feeds\n");
        return -1;
    }
    argv[argc] = NULL;
    thrt_misp_delta_mode(0);
    if (thrtutil_main(argc, argv) != 0) {
        fprintf(stderr, "enrich: thrt build failed\n");
        return -1;
    }
    return 0;
}

static void cmd_build(struct json_object *cfg)
{
    if (compile_output(cfg) != 0)
        exit(1);
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

static int run_wait(char *const av[])
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execvp(av[0], av);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return 0;
}

static int parse_u(const char *s, int maxv, int *out)
{
    char *end = NULL;
    long v;

    if (s == NULL || s[0] == '\0')
        return -1;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 1 || v > maxv)
        return -1;
    *out = (int)v;
    return 0;
}

/* 7d, 12h, 30m, or a unix timestamp. Nothing else is copied into JSON. */
static int is_window_token(const char *s)
{
    size_t i;

    if (s == NULL || s[0] < '0' || s[0] > '9')
        return 0;
    for (i = 0; s[i] != '\0'; i++) {
        if (s[i] >= '0' && s[i] <= '9')
            continue;
        if ((s[i] == 'd' || s[i] == 'h' || s[i] == 'm') && s[i + 1] == '\0' && i > 0)
            return 1;
        return 0;
    }
    return 1;
}

static void feed_stem(const char *path, char *out, size_t outsz)
{
    const char *base;
    char *dot;

    base = strrchr(path, '/');
    base = base != NULL ? base + 1 : path;
    snprintf(out, outsz, "%s", base);
    dot = strrchr(out, '.');
    if (dot != NULL)
        *dot = '\0';
}

static int next_generation(const char *out, const char *feed, char *dst, size_t dstsz)
{
    char path[1100];
    FILE *f;
    unsigned long long prev = 0;
    unsigned long long found;
    int saw = 0;

    snprintf(path, sizeof path, "%s.gen", out);
    f = fopen(path, "r");
    if (f != NULL) {
        char line[256];
        while (fgets(line, sizeof line, f) != NULL) {
            char name[64];
            unsigned long long g = 0;
            if (sscanf(line, "%63[^\t]\t%llu", name, &g) == 2 &&
                strcasecmp(name, feed) == 0) {
                prev = g;
                saw = 1;
                break;
            }
        }
        fclose(f);
    }
    if (!saw)
        found = 1;
    else if (prev + 1 < prev)
        return -1;
    else
        found = prev + 1;
    snprintf(dst, dstsz, "%llu", found);
    return 0;
}

static int fold_segment(const char *segment, const char *out, const char *feed_key,
                        int snapshot, const char *ttl, const char *generation,
                        int misp_delta)
{
    char *av[16];
    int ac = 0;
    int rc;

    if (segment == NULL || out == NULL)
        return -1;
    av[ac++] = "enrich";
    av[ac++] = "--apply-delta";
    av[ac++] = (char *)segment;
    av[ac++] = "-o";
    av[ac++] = (char *)out;
    if (feed_key != NULL && feed_key[0] != '\0') {
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
    thrt_misp_delta_mode(misp_delta);
    rc = thrtutil_main(ac, av);
    thrt_misp_delta_mode(0);
    return rc == 0 ? 0 : -1;
}

static int write_cursor(const char *dest, uint64_t newest)
{
    char path[1100];
    char tmp[1100];
    FILE *f;

    if (newest == 0)
        return 0;
    if (strlen(dest) + 32 >= sizeof path)
        return -1;
    snprintf(path, sizeof path, "%s.cursor", dest);
    snprintf(tmp, sizeof tmp, "%s.cursor.tmp.%d", dest, (int)getpid());
    f = fopen(tmp, "w");
    if (f == NULL)
        return -1;
    fprintf(f, "%llu\n", (unsigned long long)newest);
    if (fclose(f) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int read_cursor(const char *dest, char *dst, size_t dstsz)
{
    char path[1100];
    FILE *f;
    size_t n;

    if (strlen(dest) + 16 >= sizeof path)
        return 0;
    snprintf(path, sizeof path, "%s.cursor", dest);
    f = fopen(path, "r");
    if (f == NULL)
        return 0;
    if (fgets(dst, (int)dstsz, f) == NULL) {
        fclose(f);
        return 0;
    }
    fclose(f);
    n = strlen(dst);
    while (n > 0 && (dst[n - 1] == '\n' || dst[n - 1] == '\r'))
        dst[--n] = '\0';
    return is_window_token(dst);
}

static int sighup_named(const char *name)
{
    char cmd[64];
    FILE *p;
    int any = 0;
    int rc = 0;
    unsigned long pid;

    snprintf(cmd, sizeof cmd, "pgrep -x %s", name);
    p = popen(cmd, "r");
    if (p == NULL)
        return -1;
    while (fscanf(p, "%lu", &pid) == 1) {
        if (pid > 1 && kill((pid_t)pid, SIGHUP) == 0)
            any = 1;
        else
            rc = -1;
    }
    pclose(p);
    if (!any)
        return -1;
    return rc;
}

/* hup_cmd NULL runs the platform default. A failed signal does not
 * undo a fold that already landed. */
static void signal_rsyslog(const char *hup_cmd)
{
    int rc;

    if (hup_cmd != NULL && hup_cmd[0] != '\0') {
        char *av[4];
        av[0] = "/bin/sh";
        av[1] = "-c";
        av[2] = (char *)hup_cmd;
        av[3] = NULL;
        rc = run_wait(av);
    } else {
#ifdef __linux__
        char *av[6];
        av[0] = "systemctl";
        av[1] = "kill";
        av[2] = "-s";
        av[3] = "HUP";
        av[4] = "rsyslog";
        av[5] = NULL;
        rc = run_wait(av);
#else
        rc = sighup_named("rsyslogd");
#endif
    }
    if (rc != 0)
        fprintf(stderr, "enrich: rsyslog was not signalled\n");
}

static int swap_in(const char *tmp, const char *dest, char *bak, size_t baksz, int *had)
{
    *had = access(dest, F_OK) == 0;
    if (*had) {
        if (strlen(dest) + 24 >= baksz)
            return -1;
        snprintf(bak, baksz, "%s.bak.%d", dest, (int)getpid());
        if (rename(dest, bak) != 0)
            return -1;
    }
    if (rename(tmp, dest) != 0) {
        if (*had)
            rename(bak, dest);
        return -1;
    }
    return 0;
}

static void restore_swap(const char *dest, const char *bak, int had)
{
    unlink(dest);
    if (had)
        rename(bak, dest);
}

static uint64_t json_timestamp(struct json_object *obj)
{
    struct json_object *v = NULL;
    const char *s;

    if (obj == NULL || !json_object_object_get_ex(obj, "timestamp", &v) || v == NULL)
        return 0;
    if (json_object_is_type(v, json_type_int)) {
        int64_t n = json_object_get_int64(v);
        return n > 0 ? (uint64_t)n : 0;
    }
    if (!json_object_is_type(v, json_type_string))
        return 0;
    s = json_object_get_string(v);
    if (!is_window_token(s) || s[0] == '\0')
        return 0;
    /* A relative window is not an attribute timestamp. */
    if (s[strlen(s) - 1] == 'd' || s[strlen(s) - 1] == 'h' || s[strlen(s) - 1] == 'm')
        return 0;
    return strtoull(s, NULL, 10);
}

static struct json_object *attribute_array(struct json_object *root)
{
    struct json_object *resp = NULL;
    struct json_object *attrs = NULL;

    if (root == NULL || !json_object_is_type(root, json_type_object))
        return NULL;
    if (json_object_object_get_ex(root, "response", &resp) && resp != NULL) {
        if (!json_object_is_type(resp, json_type_object))
            return NULL;
        if (!json_object_object_get_ex(resp, "Attribute", &attrs))
            return NULL;
        return attrs;
    }
    if (!json_object_object_get_ex(root, "Attribute", &attrs))
        return NULL;
    return attrs;
}

static struct json_object *load_json_file(const char *path)
{
    struct stat st;
    FILE *f;
    char *buf;
    size_t got;
    struct json_object *obj;

    if (stat(path, &st) != 0 || st.st_size <= 0 || st.st_size > 64 * 1024 * 1024)
        return NULL;
    buf = malloc((size_t)st.st_size + 1);
    if (buf == NULL)
        return NULL;
    f = fopen(path, "r");
    if (f == NULL) {
        free(buf);
        return NULL;
    }
    got = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);
    buf[got] = '\0';
    obj = json_tokener_parse(buf);
    free(buf);
    return obj;
}

static void misp_endpoint(const char *url, char *endpoint, size_t n)
{
    size_t len;
    const char *suffix = "/attributes/restSearch";

    if (strncmp(url, "https://", 8) != 0 && strncmp(url, "http://", 7) != 0)
        die("misp url must be http or https");
    len = strlen(url);
    if (len > 0 && url[len - 1] == '/')
        len--;
    if (len + strlen(suffix) >= n)
        die("misp url is too long");
    memcpy(endpoint, url, len);
    memcpy(endpoint + len, suffix, strlen(suffix) + 1);
}

/* Pull every page into one attribute-search body. 0 writes body_path.
 * 1 means the window was empty. -1 leaves dest alone. */
static int pull_misp(const char *url, const char *key, const char *last,
                     int page_size, const char *dest, char *body_path, size_t body_pathsz,
                     uint64_t *newest_out)
{
    char endpoint[1024];
    char hdr[700];
    char page_path[1100];
    struct json_object *merged;
    int page;
    uint64_t newest = 0;
    int saw = 0;

    if (strlen(dest) + 32 >= sizeof page_path || strlen(dest) + 32 >= body_pathsz)
        return -1;
    if (strlen(key) + strlen("Authorization: ") >= sizeof hdr)
        die("misp key is too long");
    misp_endpoint(url, endpoint, sizeof endpoint);
    snprintf(hdr, sizeof hdr, "Authorization: %s", key);
    snprintf(page_path, sizeof page_path, "%s.page.%d", dest, (int)getpid());
    snprintf(body_path, body_pathsz, "%s.pull.%d.misp.json", dest, (int)getpid());
    merged = json_object_new_array();
    if (merged == NULL)
        return -1;

    for (page = 1; page <= 1000; page++) {
        char body[256];
        struct json_object *root;
        struct json_object *attrs;
        int n, i;

        snprintf(body, sizeof body,
                 "{\"returnFormat\":\"json\",\"last\":\"%s\",\"to_ids\":1,\"limit\":%d,\"page\":%d}",
                 last, page_size, page);
        if (curl_to_file(endpoint, NULL, hdr, body, page_path) != 0) {
            unlink(page_path);
            json_object_put(merged);
            fprintf(stderr, "enrich: misp download failed\n");
            return -1;
        }
        root = load_json_file(page_path);
        unlink(page_path);
        if (root == NULL) {
            json_object_put(merged);
            fprintf(stderr, "enrich: misp page is not an attribute search\n");
            return -1;
        }
        attrs = attribute_array(root);
        if (attrs == NULL || !json_object_is_type(attrs, json_type_array)) {
            json_object_put(root);
            json_object_put(merged);
            fprintf(stderr, "enrich: misp page is not an attribute search\n");
            return -1;
        }
        n = json_object_array_length(attrs);
        for (i = 0; i < n; i++) {
            struct json_object *one = json_object_array_get_idx(attrs, i);
            uint64_t ts;
            if (one == NULL || !json_object_is_type(one, json_type_object))
                continue;
            ts = json_timestamp(one);
            if (ts > newest)
                newest = ts;
            json_object_get(one);
            if (json_object_array_add(merged, one) != 0) {
                json_object_put(one);
                json_object_put(root);
                json_object_put(merged);
                return -1;
            }
            saw = 1;
        }
        json_object_put(root);
        if (n < page_size)
            break;
        if (page == 1000) {
            json_object_put(merged);
            fprintf(stderr, "enrich: misp page limit reached\n");
            return -1;
        }
    }
    if (!saw) {
        json_object_put(merged);
        return 1;
    }
    {
        struct json_object *resp = json_object_new_object();
        struct json_object *wrap = json_object_new_object();
        const char *text;
        FILE *f;
        int failed = 0;

        if (resp == NULL || wrap == NULL) {
            if (resp != NULL)
                json_object_put(resp);
            if (wrap != NULL)
                json_object_put(wrap);
            json_object_put(merged);
            return -1;
        }
        json_object_get(merged);
        json_object_object_add(resp, "Attribute", merged);
        json_object_object_add(wrap, "response", resp);
        text = json_object_to_json_string(wrap);
        f = fopen(body_path, "w");
        if (f == NULL || text == NULL || fputs(text, f) == EOF) {
            failed = 1;
            if (f != NULL)
                fclose(f);
        } else if (fclose(f) != 0) {
            failed = 1;
        }
        json_object_put(wrap);
        json_object_put(merged);
        if (failed) {
            unlink(body_path);
            return -1;
        }
    }
    *newest_out = newest;
    return 0;
}

static struct json_object *misp_feed(struct json_object *cfg, const char *name)
{
    struct json_object *feeds = NULL;
    struct json_object *found = NULL;
    int i, n, seen = 0;

    if (!json_object_object_get_ex(cfg, "feeds", &feeds) || feeds == NULL)
        die("no misp feed");
    n = json_object_array_length(feeds);
    for (i = 0; i < n && i < MAX_FEEDS; i++) {
        struct json_object *feed = json_object_array_get_idx(feeds, i);
        const char *type = jstr(feed, "type");
        const char *dest;
        if (type == NULL || strcmp(type, "misp") != 0)
            continue;
        dest = jstr(feed, "dest");
        if (dest == NULL)
            continue;
        if (name != NULL && name[0] != '\0') {
            const char *got = jstr(feed, "name");
            if (got == NULL || strcmp(got, name) != 0)
                continue;
        }
        if (found == NULL)
            found = feed;
        seen++;
    }
    if (found == NULL)
        die("no misp feed");
    if ((name == NULL || name[0] == '\0') && seen > 1)
        fprintf(stderr, "enrich: sync uses the first misp feed\n");
    return found;
}

/* Rename body onto dest when the fold is not a build. snapshot installs
 * dest first, then build, and puts the previous dest back if build fails. */
static int commit_body(struct json_object *cfg, const char *dest, const char *body,
                       uint64_t newest, int apply, int snapshot, int misp_delta,
                       const char *feed_key, int do_hup, const char *hup_cmd)
{
    const char *out;
    const char *feed;
    char stem[64];
    char gen[32];
    char bak[1100];
    int had = 0;

    if (!apply) {
        if (rename(body, dest) != 0)
            return -1;
        if (write_cursor(dest, newest) != 0)
            fprintf(stderr, "enrich: cursor was not written\n");
        return 0;
    }
    out = jstr(cfg, "output");
    if (out == NULL) {
        fprintf(stderr, "enrich: config output is missing\n");
        return -1;
    }
    if (snapshot) {
        if (swap_in(body, dest, bak, sizeof bak, &had) != 0)
            return -1;
        if (compile_output(cfg) != 0) {
            restore_swap(dest, bak, had);
            return -1;
        }
        if (had)
            unlink(bak);
        if (write_cursor(dest, newest) != 0)
            fprintf(stderr, "enrich: cursor was not written\n");
        if (do_hup)
            signal_rsyslog(hup_cmd);
        return 0;
    }
    feed = (feed_key != NULL && feed_key[0] != '\0') ? feed_key : NULL;
    if (feed == NULL) {
        feed_stem(dest, stem, sizeof stem);
        feed = stem;
    }
    if (next_generation(out, feed, gen, sizeof gen) != 0)
        return -1;
    if (fold_segment(body, out, feed, 0, NULL, gen, misp_delta) != 0)
        return -1;
    if (rename(body, dest) != 0)
        return -1;
    if (write_cursor(dest, newest) != 0)
        fprintf(stderr, "enrich: cursor was not written\n");
    if (do_hup)
        signal_rsyslog(hup_cmd);
    return 0;
}

static void sync_segment(struct json_object *cfg, const char *segment,
                         const char *feed_key, int apply, int full,
                         int do_hup, const char *hup_cmd)
{
    const char *out;
    const char *feed;
    char stem[64];
    char gen[32];

    if (segment[0] == '\0' || access(segment, R_OK) != 0)
        die("segment is not readable");
    if (!apply)
        return;
    out = jstr(cfg, "output");
    if (out == NULL)
        die("config output is missing");
    feed = (feed_key != NULL && feed_key[0] != '\0') ? feed_key : NULL;
    if (feed == NULL) {
        feed_stem(segment, stem, sizeof stem);
        feed = stem;
    }
    if (next_generation(out, feed, gen, sizeof gen) != 0)
        die("cannot read generation");
    if (fold_segment(segment, out, feed, full ? 1 : 0, NULL, gen, 0) != 0)
        die("apply-delta failed");
    if (do_hup)
        signal_rsyslog(hup_cmd);
}

static void sync_pull(struct json_object *cfg, const char *cfg_path,
                      const char *feed_key, int apply, int full, int page_size,
                      int do_hup, const char *hup_cmd)
{
    struct json_object *feed;
    const char *url;
    const char *key;
    const char *dest;
    const char *since;
    const char *last;
    char cursor[64];
    char body_path[1100];
    uint64_t newest = 0;
    int have;
    int pulled;
    int snapshot;
    struct stat st;

    feed = misp_feed(cfg, feed_key);
    url = jstr(feed, "url");
    key = jstr(feed, "key");
    dest = jstr(feed, "dest");
    since = jstr(feed, "since");
    if (url == NULL || key == NULL || key[0] == '\0' || dest == NULL)
        die("misp feed needs url, key, and dest in the config");
    if (cfg_path != NULL && stat(cfg_path, &st) == 0 && (st.st_mode & 077) != 0)
        fprintf(stderr, "enrich: %s holds a MISP key and is readable by group or other\n",
                cfg_path);
    if (since == NULL || since[0] == '\0')
        since = "7d";
    if (!is_window_token(since))
        die("misp since is not a window");
    have = read_cursor(dest, cursor, sizeof cursor);
    if (full || !have) {
        last = since;
        snapshot = 1;
    } else {
        last = cursor;
        snapshot = 0;
    }
    pulled = pull_misp(url, key, last, page_size, dest, body_path, sizeof body_path, &newest);
    if (pulled < 0)
        die("misp sync failed");
    if (pulled > 0) {
        fprintf(stderr, "enrich: misp returned no attributes\n");
        return;
    }
    if (commit_body(cfg, dest, body_path, newest, apply, snapshot, 1,
                    NULL, do_hup, hup_cmd) != 0) {
        unlink(body_path);
        die("misp sync failed");
    }
}

#ifdef HAVE_LIBZMQ
static volatile sig_atomic_t g_sync_stop = 0;

static void on_sync_stop(int sig)
{
    (void)sig;
    g_sync_stop = 1;
}

static int misp_tcp(const char *url, char *endpoint, size_t n)
{
    const char *p = url;
    size_t i = 0;

    if (strncmp(p, "https://", 8) == 0)
        p += 8;
    else if (strncmp(p, "http://", 7) == 0)
        p += 7;
    else
        return -1;
    while (p[i] != '\0' && p[i] != '/' && p[i] != ':' && i + 1 < 200) {
        if (p[i] <= ' ' || p[i] == '"' || p[i] == '\'')
            return -1;
        i++;
    }
    if (i == 0 || i + strlen("tcp://:50000") >= n)
        return -1;
    snprintf(endpoint, n, "tcp://%.*s:50000", (int)i, p);
    return 0;
}

static void absorb_text(struct json_object *bucket, const char *data, size_t len,
                        uint64_t *newest)
{
    const char *brace;
    char *copy;
    size_t n;
    struct json_object *obj;
    struct json_object *attrs;

    if (data == NULL || len == 0)
        return;
    brace = memchr(data, '{', len);
    if (brace == NULL)
        return;
    n = len - (size_t)(brace - data);
    copy = malloc(n + 1);
    if (copy == NULL)
        return;
    memcpy(copy, brace, n);
    copy[n] = '\0';
    obj = json_tokener_parse(copy);
    free(copy);
    if (obj == NULL)
        return;
    attrs = attribute_array(obj);
    if (attrs != NULL && json_object_is_type(attrs, json_type_array)) {
        int i, count = json_object_array_length(attrs);
        for (i = 0; i < count; i++) {
            struct json_object *one = json_object_array_get_idx(attrs, i);
            uint64_t ts;
            if (one == NULL || !json_object_is_type(one, json_type_object))
                continue;
            ts = json_timestamp(one);
            if (ts > *newest)
                *newest = ts;
            json_object_get(one);
            json_object_array_add(bucket, one);
        }
    } else if (json_object_is_type(obj, json_type_object)) {
        uint64_t ts = json_timestamp(obj);
        if (ts > *newest)
            *newest = ts;
        json_object_get(obj);
        json_object_array_add(bucket, obj);
    }
    json_object_put(obj);
}

static int flush_bucket(struct json_object *cfg, const char *dest,
                        struct json_object *bucket, uint64_t newest,
                        int apply, const char *feed_key, int do_hup, const char *hup_cmd)
{
    char body_path[1100];
    struct json_object *resp;
    struct json_object *wrap;
    const char *text;
    FILE *f;
    int failed = 0;

    if (json_object_array_length(bucket) == 0)
        return 0;
    if (strlen(dest) + 32 >= sizeof body_path)
        return -1;
    snprintf(body_path, sizeof body_path, "%s.pull.%d.misp.json", dest, (int)getpid());
    resp = json_object_new_object();
    wrap = json_object_new_object();
    if (resp == NULL || wrap == NULL) {
        if (resp != NULL)
            json_object_put(resp);
        if (wrap != NULL)
            json_object_put(wrap);
        return -1;
    }
    json_object_get(bucket);
    json_object_object_add(resp, "Attribute", bucket);
    json_object_object_add(wrap, "response", resp);
    text = json_object_to_json_string(wrap);
    f = fopen(body_path, "w");
    if (f == NULL || text == NULL || fputs(text, f) == EOF) {
        failed = 1;
        if (f != NULL)
            fclose(f);
    } else if (fclose(f) != 0) {
        failed = 1;
    }
    json_object_put(wrap);
    /* object_add stole one ref. The caller still holds the bucket. */
    if (failed) {
        unlink(body_path);
        return -1;
    }
    if (commit_body(cfg, dest, body_path, newest, apply, 0, 1,
                    feed_key, do_hup, hup_cmd) != 0) {
        unlink(body_path);
        return -1;
    }
    return 0;
}
#endif

static void sync_follow(struct json_object *cfg, const char *cfg_path,
                        const char *feed_key, const char *zmq_endpoint,
                        int flush_seconds, int apply, int do_hup, const char *hup_cmd)
{
#ifndef HAVE_LIBZMQ
    (void)cfg;
    (void)cfg_path;
    (void)feed_key;
    (void)zmq_endpoint;
    (void)flush_seconds;
    (void)apply;
    (void)do_hup;
    (void)hup_cmd;
    fprintf(stderr, "enrich: sync --follow needs libzmq\n");
    exit(2);
#else
    struct json_object *feed;
    struct json_object *bucket;
    const char *url;
    const char *dest;
    const char *key;
    char endpoint[256];
    void *ctx;
    void *sock;
    int linger = 0;
    int rcv = 1000;
    time_t next_flush;
    uint64_t newest = 0;
    struct sigaction sa;
    struct stat st;

    feed = misp_feed(cfg, NULL);
    url = jstr(feed, "url");
    dest = jstr(feed, "dest");
    key = jstr(feed, "key");
    if (dest == NULL)
        die("misp feed needs url, key, and dest in the config");
    if (zmq_endpoint != NULL && zmq_endpoint[0] != '\0') {
        snprintf(endpoint, sizeof endpoint, "%s", zmq_endpoint);
    } else {
        if (url == NULL || misp_tcp(url, endpoint, sizeof endpoint) != 0)
            die("sync --follow needs --zmq or a misp url");
    }
    if (key != NULL && key[0] != '\0' && cfg_path != NULL &&
        stat(cfg_path, &st) == 0 && (st.st_mode & 077) != 0)
        fprintf(stderr, "enrich: %s holds a MISP key and is readable by group or other\n",
                cfg_path);
    ctx = zmq_ctx_new();
    sock = ctx != NULL ? zmq_socket(ctx, ZMQ_SUB) : NULL;
    if (sock == NULL)
        die("libzmq socket failed");
    zmq_setsockopt(sock, ZMQ_LINGER, &linger, sizeof linger);
    zmq_setsockopt(sock, ZMQ_RCVTIMEO, &rcv, sizeof rcv);
    zmq_setsockopt(sock, ZMQ_SUBSCRIBE, "misp_json_attribute", 19);
    if (zmq_connect(sock, endpoint) != 0) {
        zmq_close(sock);
        zmq_ctx_term(ctx);
        die("libzmq connect failed");
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sync_stop;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    bucket = json_object_new_array();
    if (bucket == NULL)
        die("out of memory");
    next_flush = time(NULL) + flush_seconds;
    while (!g_sync_stop) {
        zmq_msg_t msg;
        int more = 1;
        if (time(NULL) >= next_flush) {
            if (flush_bucket(cfg, dest, bucket, newest, apply, feed_key,
                             do_hup, hup_cmd) != 0)
                fprintf(stderr, "enrich: misp sync failed\n");
            else if (json_object_array_length(bucket) > 0) {
                json_object_put(bucket);
                bucket = json_object_new_array();
                if (bucket == NULL)
                    die("out of memory");
                newest = 0;
            }
            next_flush = time(NULL) + flush_seconds;
        }
        zmq_msg_init(&msg);
        if (zmq_msg_recv(&msg, sock, 0) < 0) {
            zmq_msg_close(&msg);
            continue;
        }
        while (more) {
            size_t more_sz = sizeof more;
            absorb_text(bucket, (const char *)zmq_msg_data(&msg), zmq_msg_size(&msg), &newest);
            more = 0;
            zmq_getsockopt(sock, ZMQ_RCVMORE, &more, &more_sz);
            zmq_msg_close(&msg);
            if (!more)
                break;
            zmq_msg_init(&msg);
            if (zmq_msg_recv(&msg, sock, 0) < 0) {
                zmq_msg_close(&msg);
                more = 0;
            }
        }
    }
    if (flush_bucket(cfg, dest, bucket, newest, apply, feed_key, do_hup, hup_cmd) != 0)
        fprintf(stderr, "enrich: misp sync failed\n");
    json_object_put(bucket);
    zmq_close(sock);
    zmq_ctx_term(ctx);
#endif
}

static void cmd_sync(struct json_object *cfg, const char *cfg_path,
                     const char *segment, const char *feed_key, int apply, int full,
                     int page_size, int follow, const char *zmq_endpoint,
                     int flush_seconds, int do_hup, const char *hup_cmd)
{
    if (follow && segment != NULL)
        die("sync --follow does not take --segment");
    if (follow) {
        sync_follow(cfg, cfg_path, feed_key, zmq_endpoint, flush_seconds,
                    apply, do_hup, hup_cmd);
        return;
    }
    if (segment != NULL) {
        sync_segment(cfg, segment, feed_key, apply, full, do_hup, hup_cmd);
        return;
    }
    /* A pull selects the feed by name. --feed-key on a segment is the
     * fold identity, not a MISP feed name. */
    sync_pull(cfg, cfg_path, feed_key, apply, full, page_size, do_hup, hup_cmd);
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
            "       enrich [-c file] sync [--apply] [--full] [--hup]\n"
            "              [--segment file] [--feed-key K] [--page-size N]\n"
            "              [--follow] [--flush-seconds N] [--zmq ENDPOINT]\n"
            "              [--hup-cmd CMD]\n"
            "\n"
            "Config, when -c is omitted: ./enrich.json then /etc/enrich.json.\n"
            "Feeds in that file:\n"
            "  misp     url, key, since, dest, layer   live /attributes/restSearch\n"
            "  stix     url, dest, or path, layer      STIX 2.1 bundle\n"
            "  csv json lookup txt ioc misp stix      local files, layer cti or cti_r\n"
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
    int sync_apply = 0;
    int sync_full = 0;
    int sync_hup = 0;
    int sync_follow = 0;
    int page_size = 2000;
    int flush_seconds = 300;
    const char *zmq_endpoint = NULL;
    const char *hup_cmd = NULL;
    const char *cfg_path = NULL;
    struct json_object *cfg;
    int cfg_fd;
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
        if (strcmp(argv[i], "--apply") == 0) {
            sync_apply = 1;
            continue;
        }
        if (strcmp(argv[i], "--full") == 0) {
            sync_full = 1;
            continue;
        }
        if (strcmp(argv[i], "--hup") == 0) {
            sync_hup = 1;
            continue;
        }
        if (strcmp(argv[i], "--follow") == 0) {
            sync_follow = 1;
            continue;
        }
        if (strcmp(argv[i], "--page-size") == 0 && i + 1 < argc) {
            if (parse_u(argv[++i], 10000, &page_size) != 0) {
                usage();
                return 2;
            }
            continue;
        }
        if (strcmp(argv[i], "--flush-seconds") == 0 && i + 1 < argc) {
            if (parse_u(argv[++i], 86400, &flush_seconds) != 0) {
                usage();
                return 2;
            }
            continue;
        }
        if (strcmp(argv[i], "--zmq") == 0 && i + 1 < argc) {
            zmq_endpoint = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--hup-cmd") == 0 && i + 1 < argc) {
            hup_cmd = argv[++i];
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
    cfg_fd = open_chosen_config(config, &cfg_path);
    cfg = load_config(cfg_fd, cfg_path);
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
        if (segment == NULL || out == NULL)
            die("apply-delta needs --segment and config output");
        if (fold_segment(segment, out, feed_key, snapshot, ttl, generation, 0) != 0)
            die("apply-delta failed");
    } else if (strcmp(cmd, "sync") == 0) {
        if (indicator != NULL) {
            usage();
            return 2;
        }
        cmd_sync(cfg, cfg_path, segment, feed_key, sync_apply, sync_full, page_size,
                 sync_follow, zmq_endpoint, flush_seconds,
                 sync_hup || hup_cmd != NULL, hup_cmd);
    } else {
        usage();
        return 2;
    }
    json_object_put(cfg);
    return 0;
}
