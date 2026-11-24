/* enrichd.c
 * Lookup service over HTTP: the same snapshot, policy and lookup as a log
 * enricher, for clients that ask about one value or a batch.
 *
 *   GET  /v1/health              no key; 200 when a database is loaded
 *   GET  /v1/db                  snapshot facts
 *   GET  /v1/lookup/<value>      one value (or ?value=)
 *   POST /v1/lookup              {"values": [...]}
 *   POST /attributes/restSearch  MISP attribute search, exact values only
 *
 * Results use ECS threat.indicator.* names, with the libenrich detail
 * under "enrich" in the shape mmenrich writes. Each API key carries a
 * TLP clearance and two grants: "restricted" (the score of a restricted
 * CTI match) and "context" (tags, overlay entries, whitelist disposition,
 * prevalence). What a key may not see is removed before the response is
 * built, never filtered by the client.
 *
 * Usage:   enrichd [-c enrichd.json] [-t]
 *          enrichd -k < key            print the key file digest of a key
 *
 * Copyright 2026 Advens.
 *
 * This file is part of libenrich.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see LICENSE in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "enrich.h"
#include "enrichd_sha256.h"

#include <json.h>
#include <microhttpd.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if MHD_VERSION < 0x00097100
#error "enrichd needs libmicrohttpd 0.9.71 or later"
#endif

#define ENRICHD_CONFIG_MAX (1024 * 1024)
#define ENRICHD_KEYFILE_MAX (1024 * 1024)
#define ENRICHD_TLS_FILE_MAX (256 * 1024)
#define ENRICHD_KEYS_MAX 1024
#define ENRICHD_KEY_NAME_MAX 64
#define ENRICHD_KEY_MIN 32
#define ENRICHD_KEY_MAX 512
#define ENRICHD_READERS_MAX 1024
#define ENRICHD_JSON_DEPTH 8

/* ------------------------------------------------------------------------
 * Logging. One line per event on stderr; the service manager keeps it.
 * ------------------------------------------------------------------------ */
static void logf_(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void logf_(const char *fmt, ...) {
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fprintf(stderr, "enrichd: %s\n", line);
}

static void die(const char *fmt, ...) __attribute__((format(printf, 1, 2), noreturn));
static void die(const char *fmt, ...) {
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fprintf(stderr, "enrichd: %s\n", line);
    exit(1);
}

/* ------------------------------------------------------------------------
 * Files read whole, bounded.
 * ------------------------------------------------------------------------ */
static char *read_file(const char *path, size_t max, size_t *len_out, struct stat *st_out, char *err, size_t err_len) {
    struct stat st;
    char *buf;
    size_t got = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, err_len, "%s: %s", path, strerror(errno));
        return NULL;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        snprintf(err, err_len, "%s: not a regular file", path);
        close(fd);
        return NULL;
    }
    if (st.st_size < 0 || (uint64_t)st.st_size > max) {
        snprintf(err, err_len, "%s: larger than %zu bytes", path, max);
        close(fd);
        return NULL;
    }
    buf = malloc((size_t)st.st_size + 1);
    if (buf == NULL) {
        snprintf(err, err_len, "%s: out of memory", path);
        close(fd);
        return NULL;
    }
    while (got < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + got, (size_t)st.st_size - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    if (got != (size_t)st.st_size) {
        snprintf(err, err_len, "%s: short read", path);
        free(buf);
        return NULL;
    }
    buf[got] = '\0';
    if (len_out) *len_out = got;
    if (st_out) *st_out = st;
    return buf;
}

/* ------------------------------------------------------------------------
 * Configuration.
 * ------------------------------------------------------------------------ */
enum { TLP_CLEAR = 0, TLP_GREEN = 1, TLP_AMBER = 2, TLP_RED = 3 };

typedef struct {
    char listen[64];
    unsigned port;
    unsigned threads;
    char *thrt, *overlay, *prev;
    int skip_private;
    unsigned reload_seconds;
    char *keys;
    char *tls_cert, *tls_key;
    int allow_plaintext;
    int unmarked_tlp;
    unsigned max_batch;
    size_t max_body;
    unsigned max_connections;
    unsigned per_ip_connections;
    unsigned timeout_seconds;
    int access_log;
} config_t;

static int tlp_level(const char *s) {
    if (s == NULL) return -1;
    if (strcmp(s, "clear") == 0) return TLP_CLEAR;
    if (strcmp(s, "green") == 0) return TLP_GREEN;
    if (strcmp(s, "amber") == 0) return TLP_AMBER;
    if (strcmp(s, "red") == 0) return TLP_RED;
    return -1;
}

static const char *cfg_str(struct json_object *o, const char *key) {
    struct json_object *v;
    if (!json_object_object_get_ex(o, key, &v) || v == NULL) return NULL;
    if (!json_object_is_type(v, json_type_string)) die("config: %s must be a string", key);
    return json_object_get_string(v);
}

static char *cfg_dup(struct json_object *o, const char *key) {
    const char *s = cfg_str(o, key);
    char *d;
    if (s == NULL || s[0] == '\0') return NULL;
    d = strdup(s);
    if (d == NULL) die("out of memory");
    return d;
}

static unsigned long long cfg_uint(struct json_object *o, const char *key, unsigned long long def,
                                   unsigned long long lo, unsigned long long hi) {
    struct json_object *v;
    int64_t n;
    if (!json_object_object_get_ex(o, key, &v) || v == NULL) return def;
    if (!json_object_is_type(v, json_type_int)) die("config: %s must be an integer", key);
    n = json_object_get_int64(v);
    if (n < 0 || (unsigned long long)n < lo || (unsigned long long)n > hi)
        die("config: %s must be between %llu and %llu", key, lo, hi);
    return (unsigned long long)n;
}

static int cfg_bool(struct json_object *o, const char *key, int def) {
    struct json_object *v;
    if (!json_object_object_get_ex(o, key, &v) || v == NULL) return def;
    if (!json_object_is_type(v, json_type_boolean)) die("config: %s must be true or false", key);
    return json_object_get_boolean(v) ? 1 : 0;
}

static void config_load(config_t *c, const char *path) {
    static const char *known[] = {
        "listen",          "port",         "threads",   "thrt",     "overlay",         "prev",
        "skip_private",    "reload_seconds", "keys",    "tls_cert", "tls_key",         "allow_plaintext",
        "unmarked_tlp",    "max_batch",    "max_body",  "max_connections", "per_ip_connections",
        "timeout_seconds", "access_log"};
    char err[512];
    char *text = read_file(path, ENRICHD_CONFIG_MAX, NULL, NULL, err, sizeof err);
    struct json_object *root;
    const char *s;
    if (text == NULL) die("config: %s", err);
    root = json_tokener_parse(text);
    free(text);
    if (root == NULL || !json_object_is_type(root, json_type_object)) die("config: %s is not a JSON object", path);
    {
        struct json_object_iterator it = json_object_iter_begin(root), end = json_object_iter_end(root);
        for (; !json_object_iter_equal(&it, &end); json_object_iter_next(&it)) {
            const char *k = json_object_iter_peek_name(&it);
            size_t i;
            for (i = 0; i < sizeof known / sizeof known[0]; i++)
                if (strcmp(k, known[i]) == 0) break;
            if (i == sizeof known / sizeof known[0]) die("config: unknown key \"%s\"", k);
        }
    }
    memset(c, 0, sizeof *c);
    s = cfg_str(root, "listen");
    if (s == NULL) s = "127.0.0.1";
    if (strlen(s) >= sizeof c->listen) die("config: listen is too long");
    memcpy(c->listen, s, strlen(s) + 1);
    c->port = (unsigned)cfg_uint(root, "port", 8470, 1, 65535);
    c->threads = (unsigned)cfg_uint(root, "threads", 4, 1, 256);
    c->thrt = cfg_dup(root, "thrt");
    c->overlay = cfg_dup(root, "overlay");
    c->prev = cfg_dup(root, "prev");
    c->skip_private = cfg_bool(root, "skip_private", 1);
    c->reload_seconds = (unsigned)cfg_uint(root, "reload_seconds", 30, 0, 86400);
    c->keys = cfg_dup(root, "keys");
    c->tls_cert = cfg_dup(root, "tls_cert");
    c->tls_key = cfg_dup(root, "tls_key");
    c->allow_plaintext = cfg_bool(root, "allow_plaintext", 0);
    s = cfg_str(root, "unmarked_tlp");
    c->unmarked_tlp = s ? tlp_level(s) : TLP_AMBER;
    if (c->unmarked_tlp < 0) die("config: unmarked_tlp must be clear, green, amber or red");
    c->max_batch = (unsigned)cfg_uint(root, "max_batch", 1000, 1, 100000);
    c->max_body = (size_t)cfg_uint(root, "max_body", 1024 * 1024, 1024, 64 * 1024 * 1024);
    c->max_connections = (unsigned)cfg_uint(root, "max_connections", 256, 1, 65536);
    c->per_ip_connections = (unsigned)cfg_uint(root, "per_ip_connections", 32, 0, 65536);
    c->timeout_seconds = (unsigned)cfg_uint(root, "timeout_seconds", 10, 1, 3600);
    c->access_log = cfg_bool(root, "access_log", 0);
    json_object_put(root);
    if (c->thrt == NULL && c->overlay == NULL && c->prev == NULL)
        die("config: set at least one of thrt, overlay, prev");
    if (c->keys == NULL) die("config: keys (the API key file) is required");
    if ((c->tls_cert == NULL) != (c->tls_key == NULL)) die("config: tls_cert and tls_key go together");
}

/* ------------------------------------------------------------------------
 * API keys.
 *
 * One key per line: <name> <sha256 hex of the key> [grant,...]
 * Grants: tlp:clear|green|amber|red (default clear), restricted, context.
 * '#' starts a comment. The file holds digests, not keys, and must not be
 * writable by group or other: whoever writes it grants access.
 * ------------------------------------------------------------------------ */
typedef struct {
    char name[ENRICHD_KEY_NAME_MAX + 1];
    uint8_t digest[SHA256_LEN];
    int tlp;
    int restricted;
    int context;
} api_key_t;

typedef struct {
    api_key_t *keys;
    size_t n;
} keyset_t;

static pthread_rwlock_t g_keys_lock = PTHREAD_RWLOCK_INITIALIZER;
static keyset_t *g_keys;

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_grants(api_key_t *k, char *grants, char *err, size_t err_len) {
    char *save = NULL;
    for (char *g = strtok_r(grants, ",", &save); g != NULL; g = strtok_r(NULL, ",", &save)) {
        if (strncmp(g, "tlp:", 4) == 0) {
            k->tlp = tlp_level(g + 4);
            if (k->tlp < 0) {
                snprintf(err, err_len, "unknown TLP \"%s\"", g + 4);
                return -1;
            }
        } else if (strcmp(g, "restricted") == 0) {
            k->restricted = 1;
        } else if (strcmp(g, "context") == 0) {
            k->context = 1;
        } else {
            snprintf(err, err_len, "unknown grant \"%s\"", g);
            return -1;
        }
    }
    return 0;
}

static int valid_name(const char *s) {
    if (*s == '\0' || strlen(s) > ENRICHD_KEY_NAME_MAX) return 0;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '-' ||
              *s == '_' || *s == '.'))
            return 0;
    return 1;
}

static void keys_free(keyset_t *ks) {
    if (ks == NULL) return;
    free(ks->keys);
    free(ks);
}

/* Parse the key file text (len bytes, NUL-terminated). Takes text and
 * frees it. path only names the file in errors. */
static keyset_t *keys_parse(char *text, size_t len, const char *path, char *err, size_t err_len) {
    char line_err[256];
    keyset_t *ks;
    char *save = NULL;
    unsigned lineno = 0;
    if (memchr(text, '\0', len) != NULL) {
        snprintf(err, err_len, "%s holds a NUL byte", path);
        free(text);
        return NULL;
    }
    ks = calloc(1, sizeof *ks);
    if (ks != NULL) ks->keys = calloc(ENRICHD_KEYS_MAX, sizeof *ks->keys);
    if (ks == NULL || ks->keys == NULL) {
        snprintf(err, err_len, "out of memory");
        keys_free(ks);
        free(text);
        return NULL;
    }
    for (char *line = strtok_r(text, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        char *f[4] = {NULL, NULL, NULL, NULL}, *fs = NULL, *mark;
        api_key_t *k;
        int nf = 0;
        lineno++;
        mark = strchr(line, '#');
        if (mark != NULL) *mark = '\0';
        for (char *t = strtok_r(line, " \t\r", &fs); t != NULL; t = strtok_r(NULL, " \t\r", &fs)) {
            if (nf == 4) break;
            f[nf++] = t;
        }
        if (nf == 0) continue;
        if (nf < 2 || nf > 3) {
            snprintf(err, err_len, "%s:%u: want <name> <sha256> [grants]", path, lineno);
            goto fail;
        }
        if (ks->n == ENRICHD_KEYS_MAX) {
            snprintf(err, err_len, "%s: more than %d keys", path, ENRICHD_KEYS_MAX);
            goto fail;
        }
        k = &ks->keys[ks->n];
        if (!valid_name(f[0])) {
            snprintf(err, err_len, "%s:%u: a name is 1 to %d letters, digits, '-', '_' or '.'", path, lineno,
                     ENRICHD_KEY_NAME_MAX);
            goto fail;
        }
        memcpy(k->name, f[0], strlen(f[0]) + 1);
        if (strlen(f[1]) != 2 * SHA256_LEN) {
            snprintf(err, err_len, "%s:%u: the digest is 64 hex characters (enrichd -k)", path, lineno);
            goto fail;
        }
        for (int i = 0; i < SHA256_LEN; i++) {
            int hi = hexval((unsigned char)f[1][2 * i]), lo = hexval((unsigned char)f[1][2 * i + 1]);
            if (hi < 0 || lo < 0) {
                snprintf(err, err_len, "%s:%u: the digest is 64 hex characters (enrichd -k)", path, lineno);
                goto fail;
            }
            k->digest[i] = (uint8_t)(hi << 4 | lo);
        }
        k->tlp = TLP_CLEAR;
        if (f[2] != NULL && parse_grants(k, f[2], line_err, sizeof line_err) != 0) {
            snprintf(err, err_len, "%s:%u: %s", path, lineno, line_err);
            goto fail;
        }
        for (size_t i = 0; i < ks->n; i++)
            if (strcmp(ks->keys[i].name, k->name) == 0 || memcmp(ks->keys[i].digest, k->digest, SHA256_LEN) == 0) {
                snprintf(err, err_len, "%s:%u: name or digest repeated", path, lineno);
                goto fail;
            }
        ks->n++;
    }
    free(text);
    if (ks->n == 0) {
        snprintf(err, err_len, "%s holds no key", path);
        keys_free(ks);
        return NULL;
    }
    return ks;
fail:
    free(text);
    keys_free(ks);
    return NULL;
}

static keyset_t *keys_load(const char *path, char *err, size_t err_len) {
    struct stat st;
    size_t len;
    char *text = read_file(path, ENRICHD_KEYFILE_MAX, &len, &st, err, err_len);
    if (text == NULL) return NULL;
    if (st.st_mode & 022) {
        snprintf(err, err_len, "%s is writable by group or other", path);
        free(text);
        return NULL;
    }
    return keys_parse(text, len, path, err, err_len);
}

/* Copy the grants of the key whose digest matches. Every entry is
 * compared, without an early exit, so the time does not depend on which
 * key matched. */
static int keys_match(const char *key, size_t len, api_key_t *out) {
    uint8_t d[SHA256_LEN];
    int found = 0;
    if (len < ENRICHD_KEY_MIN || len > ENRICHD_KEY_MAX) return 0;
    sha256(key, len, d);
    pthread_rwlock_rdlock(&g_keys_lock);
    for (size_t i = 0; g_keys != NULL && i < g_keys->n; i++) {
        uint8_t diff = 0;
        for (int j = 0; j < SHA256_LEN; j++) diff |= (uint8_t)(d[j] ^ g_keys->keys[i].digest[j]);
        if (diff == 0) {
            *out = g_keys->keys[i];
            found = 1;
        }
    }
    pthread_rwlock_unlock(&g_keys_lock);
    return found;
}

/* ------------------------------------------------------------------------
 * Global state.
 * ------------------------------------------------------------------------ */
static config_t g_cfg;
static enrich_t *g_enrich;
static uint32_t g_lookup_flags;

static pthread_mutex_t g_readers_lock = PTHREAD_MUTEX_INITIALIZER;
static enrich_reader_t *g_readers[ENRICHD_READERS_MAX];
static size_t g_nreaders;
static _Thread_local enrich_reader_t *tl_reader;

static volatile sig_atomic_t g_stop, g_hup;

/* The reader of the calling thread, made on first use. */
static enrich_reader_t *thread_reader(void) {
    enrich_reader_t *r;
    if (tl_reader != NULL) return tl_reader;
    pthread_mutex_lock(&g_readers_lock);
    if (g_nreaders == ENRICHD_READERS_MAX) {
        pthread_mutex_unlock(&g_readers_lock);
        return NULL;
    }
    r = enrich_reader_new(g_enrich);
    if (r != NULL) g_readers[g_nreaders++] = r;
    pthread_mutex_unlock(&g_readers_lock);
    tl_reader = r;
    return r;
}

/* ------------------------------------------------------------------------
 * Values.
 * ------------------------------------------------------------------------ */
typedef enum { V_IPV4, V_IPV6, V_MD5, V_SHA1, V_SHA256, V_SHA512, V_URL, V_EMAIL, V_DOMAIN } vtype_t;

static vtype_t value_type(const enrich_result_t *r, const char *v, size_t len) {
    size_t hex = 0;
    if (r->kind == ENRICH_KIND_IPV4) return V_IPV4;
    if (r->kind == ENRICH_KIND_IPV6) return V_IPV6;
    while (hex < len && hexval((unsigned char)v[hex]) >= 0) hex++;
    if (hex == len) {
        if (len == 32) return V_MD5;
        if (len == 40) return V_SHA1;
        if (len == 64) return V_SHA256;
        if (len == 128) return V_SHA512;
    }
    for (size_t i = 0; i + 2 < len; i++)
        if (v[i] == ':' && v[i + 1] == '/' && v[i + 2] == '/') return V_URL;
    if (memchr(v, '@', len) != NULL && memchr(v, '/', len) == NULL) return V_EMAIL;
    return V_DOMAIN;
}

static int vtype_is_hash(vtype_t t) {
    return t == V_MD5 || t == V_SHA1 || t == V_SHA256 || t == V_SHA512;
}

static const char *ecs_type(vtype_t t) {
    switch (t) {
        case V_IPV4:
            return "ipv4-addr";
        case V_IPV6:
            return "ipv6-addr";
        case V_MD5:
        case V_SHA1:
        case V_SHA256:
        case V_SHA512:
            return "file";
        case V_URL:
            return "url";
        case V_EMAIL:
            return "email-addr";
        default:
            return "domain-name";
    }
}

static const char *misp_type(vtype_t t) {
    switch (t) {
        case V_IPV4:
        case V_IPV6:
            return "ip-dst";
        case V_MD5:
            return "md5";
        case V_SHA1:
            return "sha1";
        case V_SHA256:
            return "sha256";
        case V_SHA512:
            return "sha512";
        case V_URL:
            return "url";
        case V_EMAIL:
            return "email-src";
        default:
            return "domain";
    }
}

/* STIX 2.1 confidence scale, as ECS threat.indicator.confidence takes it. */
static const char *ecs_confidence(unsigned c) {
    if (c == 0) return "None";
    if (c < 30) return "Low";
    if (c < 70) return "Medium";
    return "High";
}

/* ------------------------------------------------------------------------
 * Policy: what one key may see of one result.
 * ------------------------------------------------------------------------ */
typedef struct {
    int cti;             /* public CTI, within the key's TLP clearance */
    int restricted;      /* restricted CTI score */
    int overlay_add;     /* site indicator from the overlay */
    int context;         /* tags, overlay tags, disposition, prevalence */
    int matched;
    unsigned confidence; /* best visible score */
} view_t;

static int tlp_of_mask(uint8_t m, int unmarked) {
    if (m & THRT_TLP_RED) return TLP_RED;
    if (m & THRT_TLP_AMBER) return TLP_AMBER;
    if (m & THRT_TLP_GREEN) return TLP_GREEN;
    if (m & THRT_TLP_CLEAR) return TLP_CLEAR;
    return unmarked;
}

static void view_of(const api_key_t *k, const enrich_result_t *r, view_t *v) {
    memset(v, 0, sizeof *v);
    if (r->flags & ENRICH_R_SUPPRESSED) return;
    v->context = k->context;
    if ((r->type_mask & THRT_TYPE_CTI) && tlp_of_mask(r->tlp_mask, g_cfg.unmarked_tlp) <= k->tlp) {
        v->cti = 1;
        if (r->confidence > v->confidence) v->confidence = r->confidence;
    }
    if ((r->type_mask & THRT_TYPE_CTI_R) && k->restricted) {
        v->restricted = 1;
        if (r->confidence_r > v->confidence) v->confidence = r->confidence_r;
    }
    if (k->context && (r->flags & ENRICH_R_OVERLAY) && (r->ovl_confidence > 0 || r->ovl_category_mask != 0)) {
        v->overlay_add = 1;
        if (r->ovl_confidence > v->confidence) v->confidence = r->ovl_confidence;
    }
    v->matched = v->cti || v->restricted || v->overlay_add;
}

/* ------------------------------------------------------------------------
 * JSON output.
 * ------------------------------------------------------------------------ */
static struct json_object *json_array_text(const char *text, uint32_t len) {
    struct json_tokener *tok;
    struct json_object *arr;
    if (text == NULL || len == 0 || len > INT32_MAX) return NULL;
    tok = json_tokener_new();
    if (tok == NULL) return NULL;
    arr = json_tokener_parse_ex(tok, text, (int)len);
    json_tokener_free(tok);
    if (arr != NULL && !json_object_is_type(arr, json_type_array)) {
        json_object_put(arr);
        arr = NULL;
    }
    return arr;
}

static struct json_object *categories_json(uint16_t mask) {
    struct json_object *a = json_object_new_array();
    for (unsigned b = 0; a && b < 16; b++) {
        const char *n = (mask & (1u << b)) ? enrich_category_name((uint16_t)(1u << b)) : NULL;
        if (n) json_object_array_add(a, json_object_new_string(n));
    }
    return a;
}

static struct json_object *tlps_json(uint8_t mask) {
    struct json_object *a = json_object_new_array();
    for (unsigned b = 0; a && b < 8; b++) {
        const char *n = (mask & (1u << b)) ? enrich_tlp_name((uint8_t)(1u << b)) : NULL;
        if (n) json_object_array_add(a, json_object_new_string(n));
    }
    return a;
}

static struct json_object *feeds_json(const enrich_snap_t *s, uint64_t mask) {
    struct json_object *a = json_object_new_array();
    for (unsigned i = 0; a && i < 64; i++) {
        const char *n = (mask & (1ULL << i)) ? enrich_feed_name(s, i) : NULL;
        if (n) json_object_array_add(a, json_object_new_string(n));
    }
    return a;
}

static void add_upper(struct json_object *o, const char *key, const char *s) {
    char up[16];
    size_t i;
    for (i = 0; s[i] && i + 1 < sizeof up; i++) up[i] = (s[i] >= 'a' && s[i] <= 'z') ? (char)(s[i] - 32) : s[i];
    up[i] = '\0';
    json_object_object_add(o, key, json_object_new_string(up));
}

static struct json_object *threat_ecs(const enrich_snap_t *s, const enrich_result_t *r, const view_t *v, vtype_t t) {
    struct json_object *threat = json_object_new_object(), *ind = json_object_new_object();
    if (threat == NULL || ind == NULL) {
        if (threat) json_object_put(threat);
        if (ind) json_object_put(ind);
        return NULL;
    }
    json_object_object_add(ind, "type", json_object_new_string(ecs_type(t)));
    json_object_object_add(ind, "confidence", json_object_new_string(ecs_confidence(v->confidence)));
    if (v->cti) {
        const char *tlp = enrich_tlp_strictest(r->tlp_mask);
        if (tlp != NULL) {
            struct json_object *marking = json_object_new_object();
            if (marking) {
                add_upper(marking, "tlp", tlp);
                json_object_object_add(ind, "marking", marking);
            }
        }
        json_object_object_add(ind, "provider", feeds_json(s, r->feed_mask));
    }
    json_object_object_add(threat, "indicator", ind);
    if (v->cti) {
        struct json_object *feed = json_object_new_object();
        if (feed) {
            json_object_object_add(feed, "name", feeds_json(s, r->feed_mask));
            json_object_object_add(threat, "feed", feed);
        }
    }
    return threat;
}

static struct json_object *detail_enrich(const enrich_snap_t *s, const enrich_result_t *r, const view_t *v,
                                         const char *val, size_t len) {
    struct json_object *en = json_object_new_object();
    if (en == NULL) return NULL;
    if (v->cti) {
        struct json_object *cti = json_object_new_object(), *labels;
        if (cti) {
            json_object_object_add(cti, "confidence", json_object_new_int(r->confidence));
            json_object_object_add(cti, "categories", categories_json(r->category_mask));
            json_object_object_add(cti, "tlp", tlps_json(r->tlp_mask));
            json_object_object_add(cti, "feeds", feeds_json(s, r->feed_mask));
            labels = json_array_text(r->labels, r->labels_len);
            if (labels) json_object_object_add(cti, "labels", labels);
            json_object_object_add(en, "cti", cti);
        }
    }
    if (v->restricted) {
        struct json_object *rs = json_object_new_object();
        if (rs) {
            json_object_object_add(rs, "confidence", json_object_new_int(r->confidence_r));
            json_object_object_add(en, "restricted", rs);
        }
    }
    if (v->overlay_add) {
        struct json_object *ov = json_object_new_object();
        if (ov) {
            json_object_object_add(ov, "confidence", json_object_new_int(r->ovl_confidence));
            json_object_object_add(ov, "categories", categories_json(r->ovl_category_mask));
            json_object_object_add(en, "overlay", ov);
        }
    }
    if (v->context && !(r->flags & ENRICH_R_SUPPRESSED)) {
        struct json_object *tags = json_array_text(r->tags, r->tags_len);
        struct json_object *otags = json_array_text(r->overlay_tags, r->overlay_tags_len);
        enrich_prev_t p;
        if (tags) json_object_object_add(en, "tags", tags);
        if (otags) json_object_object_add(en, "overlay_tags", otags);
        if (r->flags & ENRICH_R_WHITELISTED)
            json_object_object_add(en, "disposition", json_object_new_string("allowed"));
        if (enrich_prevalence(s, val, len, &p) == 1) {
            struct json_object *po = json_object_new_object();
            if (po) {
                json_object_object_add(po, "count", json_object_new_int64(p.count));
                json_object_object_add(po, "edges", json_object_new_int(p.edges));
                json_object_object_add(po, "sources", json_object_new_int(p.sources));
                json_object_object_add(en, "prevalence", po);
            }
        }
    }
    if (r->flags & ENRICH_R_PRIVATE) json_object_object_add(en, "private", json_object_new_boolean(1));
    if (json_object_object_length(en) == 0) {
        json_object_put(en);
        return NULL;
    }
    return en;
}

static struct json_object *result_native(const enrich_snap_t *s, const api_key_t *k, const char *val, size_t len,
                                         const enrich_result_t *r, int status) {
    struct json_object *o = json_object_new_object(), *x;
    view_t v;
    vtype_t t;
    if (o == NULL) return NULL;
    if (status < 0) {
        json_object_object_add(o, "error", json_object_new_string(enrich_strerror(status)));
        return o;
    }
    json_object_object_add(o, "value", json_object_new_string_len(val, (int)len));
    view_of(k, r, &v);
    t = value_type(r, val, len);
    json_object_object_add(o, "matched", json_object_new_boolean(v.matched));
    if (v.matched && (x = threat_ecs(s, r, &v, t)) != NULL) json_object_object_add(o, "threat", x);
    if ((x = detail_enrich(s, r, &v, val, len)) != NULL) json_object_object_add(o, "enrich", x);
    return o;
}

static void misp_tag(struct json_object *tags, const char *prefix, const char *name, const char *suffix) {
    char buf[320];
    struct json_object *t;
    int n = snprintf(buf, sizeof buf, "%s%s%s", prefix, name, suffix);
    if (n < 0 || (size_t)n >= sizeof buf) return;
    t = json_object_new_object();
    if (t == NULL) return;
    json_object_object_add(t, "name", json_object_new_string(buf));
    json_object_array_add(tags, t);
}

/* One MISP Attribute, or NULL when the key sees no match. */
static struct json_object *result_misp(const enrich_snap_t *s, const api_key_t *k, const char *val, size_t len,
                                       const enrich_result_t *r, int64_t stamp) {
    struct json_object *a, *tags;
    char num[32];
    view_t v;
    vtype_t t;
    view_of(k, r, &v);
    if (!v.matched) return NULL;
    t = value_type(r, val, len);
    a = json_object_new_object();
    tags = json_object_new_array();
    if (a == NULL || tags == NULL) {
        if (a) json_object_put(a);
        if (tags) json_object_put(tags);
        return NULL;
    }
    json_object_object_add(a, "id", json_object_new_string("0"));
    json_object_object_add(a, "event_id", json_object_new_string("0"));
    json_object_object_add(a, "object_id", json_object_new_string("0"));
    json_object_object_add(a, "type", json_object_new_string(misp_type(t)));
    json_object_object_add(a, "category",
                           json_object_new_string(vtype_is_hash(t) ? "Payload delivery" : "Network activity"));
    json_object_object_add(a, "to_ids", json_object_new_boolean(1));
    json_object_object_add(a, "value", json_object_new_string_len(val, (int)len));
    json_object_object_add(a, "comment", json_object_new_string(""));
    json_object_object_add(a, "deleted", json_object_new_boolean(0));
    json_object_object_add(a, "disable_correlation", json_object_new_boolean(0));
    snprintf(num, sizeof num, "%" PRId64, stamp);
    json_object_object_add(a, "timestamp", json_object_new_string(num));
    snprintf(num, sizeof num, "%u", v.confidence);
    misp_tag(tags, "enrich:confidence=\"", num, "\"");
    if (v.cti) {
        const char *tlp = enrich_tlp_strictest(r->tlp_mask);
        struct json_object *labels = json_array_text(r->labels, r->labels_len);
        if (tlp) misp_tag(tags, "tlp:", tlp, "");
        for (unsigned i = 0; i < 64; i++) {
            const char *n = (r->feed_mask & (1ULL << i)) ? enrich_feed_name(s, i) : NULL;
            if (n) misp_tag(tags, "enrich:feed=\"", n, "\"");
        }
        for (unsigned b = 0; b < 16; b++) {
            const char *n = (r->category_mask & (1u << b)) ? enrich_category_name((uint16_t)(1u << b)) : NULL;
            if (n) misp_tag(tags, "enrich:category=\"", n, "\"");
        }
        for (int i = 0; labels && i < (int)json_object_array_length(labels); i++) {
            struct json_object *l = json_object_array_get_idx(labels, i);
            if (l && json_object_is_type(l, json_type_string)) misp_tag(tags, "", json_object_get_string(l), "");
        }
        if (labels) json_object_put(labels);
    }
    if (v.restricted) misp_tag(tags, "", "enrich:restricted", "");
    if (v.overlay_add) misp_tag(tags, "", "enrich:overlay", "");
    json_object_object_add(a, "Tag", tags);
    return a;
}

/* ------------------------------------------------------------------------
 * HTTP.
 * ------------------------------------------------------------------------ */
typedef struct {
    char *body;
    size_t len, cap;
    int too_large;
} req_t;

static enum MHD_Result send_text(struct MHD_Connection *c, unsigned status, const char *text, size_t len) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(len, (void *)(uintptr_t)text, MHD_RESPMEM_MUST_COPY);
    enum MHD_Result ret;
    if (resp == NULL) return MHD_NO;
    MHD_add_response_header(resp, "Content-Type", "application/json");
    MHD_add_response_header(resp, "Cache-Control", "no-store");
    MHD_add_response_header(resp, "X-Content-Type-Options", "nosniff");
    if (status == 401) MHD_add_response_header(resp, "WWW-Authenticate", "Bearer");
    if (status == 405) MHD_add_response_header(resp, "Allow", "GET, POST");
    ret = MHD_queue_response(c, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result send_json(struct MHD_Connection *c, unsigned status, struct json_object *o) {
    static const char oom[] = "{\"error\":\"out of memory\"}";
    const char *text;
    enum MHD_Result ret;
    if (o == NULL) return send_text(c, 500, oom, sizeof oom - 1);
    text = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
    ret = text ? send_text(c, status, text, strlen(text)) : send_text(c, 500, oom, sizeof oom - 1);
    json_object_put(o);
    return ret;
}

static enum MHD_Result send_error(struct MHD_Connection *c, unsigned status, const char *msg) {
    struct json_object *o = json_object_new_object();
    if (o) json_object_object_add(o, "error", json_object_new_string(msg));
    return send_json(c, status, o);
}

/* Decode %XX in place over (s, len). Refuses a bad escape and %00.
 * Returns the new length or -1. '+' stays '+': a value may hold one. */
static long pct_decode(char *s, size_t len) {
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '%') {
            int hi, lo;
            if (i + 2 >= len) return -1;
            hi = hexval((unsigned char)s[i + 1]);
            lo = hexval((unsigned char)s[i + 2]);
            if (hi < 0 || lo < 0 || (hi == 0 && lo == 0)) return -1;
            s[o++] = (char)(hi << 4 | lo);
            i += 2;
        } else {
            s[o++] = s[i];
        }
    }
    return (long)o;
}

/* MHD leaves the URL and the query alone; enrichd decodes values itself
 * so a %00 is refused instead of cutting a value short. */
static size_t no_unescape(void *cls, struct MHD_Connection *c, char *s) {
    (void)cls;
    (void)c;
    return strlen(s);
}

static void client_ip(struct MHD_Connection *c, char *buf, size_t cap) {
    const union MHD_ConnectionInfo *ci = MHD_get_connection_info(c, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    snprintf(buf, cap, "-");
    if (ci == NULL || ci->client_addr == NULL) return;
    if (ci->client_addr->sa_family == AF_INET)
        inet_ntop(AF_INET, &((const struct sockaddr_in *)(const void *)ci->client_addr)->sin_addr, buf,
                  (socklen_t)cap);
    else if (ci->client_addr->sa_family == AF_INET6)
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)(const void *)ci->client_addr)->sin6_addr, buf,
                  (socklen_t)cap);
}

/* Route and counts only: a looked-up value never reaches the log. */
static void access_log(struct MHD_Connection *c, const char *method, const char *route, const char *key,
                       unsigned status, size_t nvalues) {
    char ip[INET6_ADDRSTRLEN];
    if (!g_cfg.access_log) return;
    client_ip(c, ip, sizeof ip);
    logf_("%s %s %s %s %u %zu", ip, key ? key : "-", method, route, status, nvalues);
}

/* The presented key: "Authorization: Bearer <key>" or, as MISP clients
 * send it, "Authorization: <key>". */
static int authenticate(struct MHD_Connection *c, api_key_t *out) {
    const char *h = MHD_lookup_connection_value(c, MHD_HEADER_KIND, "Authorization");
    size_t len;
    if (h == NULL) return 0;
    if (strncasecmp(h, "Bearer ", 7) == 0) h += 7;
    while (*h == ' ') h++;
    len = strlen(h);
    while (len > 0 && (h[len - 1] == ' ' || h[len - 1] == '\t')) len--;
    return keys_match(h, len, out);
}

/* Parse a request body as one JSON object, all of it. */
static struct json_object *parse_body(const char *body, size_t len) {
    struct json_tokener *tok;
    struct json_object *o;
    size_t end;
    if (len == 0 || len > INT32_MAX) return NULL;
    tok = fjson_tokener_new_ex(ENRICHD_JSON_DEPTH);
    if (tok == NULL) return NULL;
    o = json_tokener_parse_ex(tok, body, (int)len);
    if (o == NULL || fjson_tokener_get_error(tok) != fjson_tokener_success) {
        if (o) json_object_put(o);
        json_tokener_free(tok);
        return NULL;
    }
    end = tok->char_offset < 0 ? 0 : (size_t)tok->char_offset;
    json_tokener_free(tok);
    for (; end < len; end++)
        if (body[end] != ' ' && body[end] != '\n' && body[end] != '\r' && body[end] != '\t') {
            json_object_put(o);
            return NULL;
        }
    if (!json_object_is_type(o, json_type_object)) {
        json_object_put(o);
        return NULL;
    }
    return o;
}

/* Collect the strings of a JSON string or array of strings. */
static int collect_values(struct json_object *v, enrich_value_t **out, size_t *n, const char **err) {
    size_t cnt;
    int is_array = json_object_is_type(v, json_type_array);
    enrich_value_t *vals;
    if (json_object_is_type(v, json_type_string)) {
        cnt = 1;
    } else if (is_array) {
        cnt = (size_t)json_object_array_length(v);
    } else {
        *err = "values must be a string or an array of strings";
        return -1;
    }
    if (cnt == 0) {
        *err = "no value";
        return -1;
    }
    if (cnt > g_cfg.max_batch) {
        *err = "more values than max_batch";
        return -1;
    }
    vals = calloc(cnt, sizeof *vals);
    if (vals == NULL) {
        *err = "out of memory";
        return -1;
    }
    for (size_t i = 0; i < cnt; i++) {
        struct json_object *s = is_array ? json_object_array_get_idx(v, (int)i) : v;
        if (s == NULL || !json_object_is_type(s, json_type_string)) {
            free(vals);
            *err = "every value must be a string";
            return -1;
        }
        vals[i].value = json_object_get_string(s);
        vals[i].len = (size_t)json_object_get_string_len(s);
    }
    *out = vals;
    *n = cnt;
    return 0;
}

static int run_lookup(const enrich_snap_t *s, const enrich_value_t *vals, size_t n, enrich_result_t **res, int **st) {
    *res = calloc(n, sizeof **res);
    *st = calloc(n, sizeof **st);
    if (*res == NULL || *st == NULL) {
        free(*res);
        free(*st);
        *res = NULL;
        *st = NULL;
        return -1;
    }
    if (n == 1)
        (*st)[0] = enrich_lookup(s, g_lookup_flags, vals[0].value, vals[0].len, &(*res)[0]);
    else
        (void)enrich_lookup_batch(s, g_lookup_flags, vals, n, *res, *st);
    return 0;
}

static enum MHD_Result do_health(struct MHD_Connection *c) {
    enrich_reader_t *rd = thread_reader();
    enrich_info_t info;
    struct json_object *o;
    unsigned status;
    if (rd == NULL) return send_error(c, 503, "no reader");
    enrich_snap_info(enrich_reader_enter(rd), &info);
    enrich_reader_leave(rd);
    status = (info.components & ENRICH_C_THRT) || (g_cfg.thrt == NULL && info.components != 0) ? 200 : 503;
    o = json_object_new_object();
    if (o) {
        json_object_object_add(o, "status", json_object_new_string(status == 200 ? "ok" : "no database"));
        json_object_object_add(o, "generation", json_object_new_int64((int64_t)info.generation));
    }
    return send_json(c, status, o);
}

static enum MHD_Result do_db(struct MHD_Connection *c) {
    enrich_reader_t *rd = thread_reader();
    enrich_info_t i;
    struct json_object *o, *t;
    if (rd == NULL) return send_error(c, 503, "no reader");
    enrich_snap_info(enrich_reader_enter(rd), &i);
    enrich_reader_leave(rd);
    o = json_object_new_object();
    if (o == NULL) return send_json(c, 500, NULL);
    json_object_object_add(o, "version", json_object_new_string(enrich_version()));
    json_object_object_add(o, "generation", json_object_new_int64((int64_t)i.generation));
    if ((i.components & ENRICH_C_THRT) && (t = json_object_new_object()) != NULL) {
        json_object_object_add(t, "format", json_object_new_int64(i.thrt_version));
        json_object_object_add(t, "ipv4_ranges", json_object_new_int64(i.thrt_ipv4_ranges));
        json_object_object_add(t, "ipv6_ranges", json_object_new_int64(i.thrt_ipv6_ranges));
        json_object_object_add(t, "hash_slots", json_object_new_int64(i.thrt_hash_slots));
        json_object_object_add(t, "feeds", json_object_new_int64(i.thrt_feeds));
        json_object_object_add(t, "mtime", json_object_new_int64(i.thrt_mtime));
        json_object_object_add(o, "thrt", t);
    }
    if ((i.components & ENRICH_C_OVERLAY) && (t = json_object_new_object()) != NULL) {
        json_object_object_add(t, "entries", json_object_new_int64(i.overlay_entries));
        json_object_object_add(t, "mtime", json_object_new_int64(i.overlay_mtime));
        json_object_object_add(o, "overlay", t);
    }
    if ((i.components & ENRICH_C_PREV) && (t = json_object_new_object()) != NULL) {
        json_object_object_add(t, "entries", json_object_new_int64(i.prev_entries));
        json_object_object_add(t, "reporting_edges", json_object_new_int64(i.prev_reporting_edges));
        json_object_object_add(t, "mtime", json_object_new_int64(i.prev_mtime));
        json_object_object_add(o, "prev", t);
    }
    return send_json(c, 200, o);
}

/* The responses below build a JSON document from the request and set
 * *status. On an error they return NULL and set *err, except that a 500
 * may come with neither. They do not touch the connection, so the fuzz
 * harness calls them directly. */

/* GET /v1/lookup/<value> and GET /v1/lookup?value=<value>. raw is still
 * percent-encoded. */
static struct json_object *resp_lookup_one(const api_key_t *k, const char *raw, unsigned *status,
                                           const char **err) {
    enrich_reader_t *rd = thread_reader();
    const enrich_snap_t *s;
    enrich_result_t res;
    struct json_object *o;
    size_t rawlen = strlen(raw);
    char *val;
    long len;
    int st;
    *status = 400;
    if (rawlen == 0) {
        *err = "no value";
        return NULL;
    }
    if (rawlen > 3 * (size_t)ENRICH_VALUE_MAX) {
        *err = enrich_strerror(ENRICH_ETOOLONG);
        return NULL;
    }
    if (rd == NULL) {
        *status = 503;
        *err = "no reader";
        return NULL;
    }
    val = malloc(rawlen + 1);
    if (val == NULL) {
        *status = 500;
        *err = "out of memory";
        return NULL;
    }
    memcpy(val, raw, rawlen + 1);
    len = pct_decode(val, rawlen);
    if (len <= 0) {
        free(val);
        *err = "bad percent escape in the value";
        return NULL;
    }
    s = enrich_reader_enter(rd);
    st = enrich_lookup(s, g_lookup_flags, val, (size_t)len, &res);
    o = result_native(s, k, val, (size_t)len, &res, st);
    enrich_reader_leave(rd);
    free(val);
    *status = o == NULL ? 500 : st < 0 ? 400 : 200;
    return o;
}

/* Values of a POST body, looked up under the reader's current snapshot.
 * On success the reader is entered and the caller leaves it. */
typedef struct {
    struct json_object *body;
    enrich_value_t *vals;
    enrich_result_t *res;
    int *st;
    size_t n;
    enrich_reader_t *rd;
    const enrich_snap_t *s;
} batch_t;

static void batch_free(batch_t *b) {
    if (b->rd != NULL) enrich_reader_leave(b->rd);
    free(b->res);
    free(b->st);
    free(b->vals);
    if (b->body) json_object_put(b->body);
    memset(b, 0, sizeof *b);
}

static unsigned batch_run(batch_t *b, struct json_object *v, const char **err) {
    enrich_reader_t *rd = thread_reader();
    if (collect_values(v, &b->vals, &b->n, err) != 0) return 400;
    if (rd == NULL) {
        *err = "no reader";
        return 503;
    }
    b->rd = rd;
    b->s = enrich_reader_enter(rd);
    if (run_lookup(b->s, b->vals, b->n, &b->res, &b->st) != 0) {
        *err = "out of memory";
        return 500;
    }
    return 200;
}

/* POST /v1/lookup {"values": [...]}. */
static struct json_object *resp_lookup_batch(const api_key_t *k, const char *body, size_t len, unsigned *status,
                                             const char **err, size_t *nvalues) {
    batch_t b;
    struct json_object *v, *out = NULL, *arr = NULL;
    enrich_info_t info;
    memset(&b, 0, sizeof b);
    *status = 400;
    b.body = parse_body(body, len);
    if (b.body == NULL) {
        *err = "the body is not a JSON object";
        return NULL;
    }
    if (!json_object_object_get_ex(b.body, "values", &v) || v == NULL) {
        batch_free(&b);
        *err = "values is required";
        return NULL;
    }
    *status = batch_run(&b, v, err);
    *nvalues = b.n;
    if (*status != 200) {
        batch_free(&b);
        return NULL;
    }
    out = json_object_new_object();
    arr = json_object_new_array();
    if (out != NULL && arr != NULL) {
        for (size_t i = 0; i < b.n; i++)
            json_object_array_add(arr, result_native(b.s, k, b.vals[i].value, b.vals[i].len, &b.res[i], b.st[i]));
        enrich_snap_info(b.s, &info);
        json_object_object_add(out, "generation", json_object_new_int64((int64_t)info.generation));
        json_object_object_add(out, "results", arr);
    } else {
        if (out) json_object_put(out);
        if (arr) json_object_put(arr);
        out = NULL;
    }
    batch_free(&b);
    *status = out ? 200 : 500;
    return out;
}

/* POST /attributes/restSearch. The filter is "value" (a string or a list),
 * matched exactly; MISP wildcards and negation are refused instead of
 * missing silently. Other filters are ignored. */
static struct json_object *resp_misp(const api_key_t *k, const char *body, size_t len, unsigned *status,
                                     const char **err, size_t *nvalues) {
    batch_t b;
    struct json_object *req, *v, *fmt, *out = NULL, *resp = NULL, *attrs = NULL;
    enrich_info_t info;
    memset(&b, 0, sizeof b);
    *status = 400;
    b.body = parse_body(body, len);
    if (b.body == NULL) {
        *err = "the body is not a JSON object";
        return NULL;
    }
    req = b.body;
    if (json_object_object_get_ex(b.body, "request", &v) && v && json_object_is_type(v, json_type_object)) req = v;
    if (json_object_object_get_ex(req, "returnFormat", &fmt) && fmt &&
        (!json_object_is_type(fmt, json_type_string) || strcmp(json_object_get_string(fmt), "json") != 0)) {
        batch_free(&b);
        *err = "returnFormat json is the only format";
        return NULL;
    }
    if (!json_object_object_get_ex(req, "value", &v) || v == NULL) {
        batch_free(&b);
        *err = "value is required";
        return NULL;
    }
    *status = batch_run(&b, v, err);
    *nvalues = b.n;
    if (*status != 200) {
        batch_free(&b);
        return NULL;
    }
    for (size_t i = 0; i < b.n; i++) {
        const char *x = b.vals[i].value;
        size_t l = b.vals[i].len;
        if (l > 0 && (x[0] == '!' || x[0] == '%' || x[l - 1] == '%')) {
            batch_free(&b);
            *status = 400;
            *err = "wildcards and negation are not supported: values match exactly";
            return NULL;
        }
    }
    enrich_snap_info(b.s, &info);
    out = json_object_new_object();
    resp = json_object_new_object();
    attrs = json_object_new_array();
    if (out != NULL && resp != NULL && attrs != NULL) {
        for (size_t i = 0; i < b.n; i++) {
            struct json_object *a;
            if (b.st[i] < 0) continue;
            a = result_misp(b.s, k, b.vals[i].value, b.vals[i].len, &b.res[i], info.thrt_mtime);
            if (a) json_object_array_add(attrs, a);
        }
        json_object_object_add(resp, "Attribute", attrs);
        json_object_object_add(out, "response", resp);
    } else {
        if (out) json_object_put(out);
        if (resp) json_object_put(resp);
        if (attrs) json_object_put(attrs);
        out = NULL;
    }
    batch_free(&b);
    *status = out ? 200 : 500;
    return out;
}

static enum MHD_Result send_resp(struct MHD_Connection *c, unsigned status, struct json_object *o, const char *err) {
    if (o == NULL && err != NULL) return send_error(c, status, err);
    return send_json(c, status, o);
}

static int route_known(const char *url) {
    return strcmp(url, "/v1/lookup") == 0 || strcmp(url, "/v1/db") == 0 || strncmp(url, "/v1/lookup/", 11) == 0 ||
           strcmp(url, "/attributes/restSearch") == 0 || strcmp(url, "/attributes/restSearch/json") == 0;
}

static enum MHD_Result handler(void *cls, struct MHD_Connection *c, const char *url, const char *method,
                               const char *version, const char *upload, size_t *upload_size, void **req_cls) {
    req_t *rq = *req_cls;
    api_key_t key;
    struct json_object *o;
    const char *err = NULL;
    unsigned status = 200;
    size_t nvalues = 0;
    int is_get, is_post;
    enum MHD_Result ret;
    (void)cls;
    (void)version;
    is_get = strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0;
    is_post = strcmp(method, "POST") == 0;

    if (rq == NULL) {
        const char *cl;
        rq = calloc(1, sizeof *rq);
        if (rq == NULL) return MHD_NO;
        *req_cls = rq;
        cl = MHD_lookup_connection_value(c, MHD_HEADER_KIND, "Content-Length");
        if (cl != NULL) {
            char *end;
            unsigned long long n;
            errno = 0;
            n = strtoull(cl, &end, 10);
            if (errno != 0 || end == cl || *end != '\0' || n > g_cfg.max_body) {
                rq->too_large = 1;
                access_log(c, method, "-", NULL, 413, 0);
                return send_error(c, 413, "the body is larger than max_body");
            }
        }
        return MHD_YES;
    }
    if (*upload_size > 0) {
        size_t take = *upload_size;
        if (!is_post || rq->too_large || take > g_cfg.max_body - rq->len) {
            rq->too_large = 1;
        } else {
            if (rq->len + take > rq->cap) {
                size_t cap = rq->cap ? rq->cap : 4096;
                char *nb;
                while (cap < rq->len + take) cap *= 2;
                if (cap > g_cfg.max_body) cap = g_cfg.max_body;
                nb = realloc(rq->body, cap);
                if (nb == NULL) return MHD_NO;
                rq->body = nb;
                rq->cap = cap;
            }
            memcpy(rq->body + rq->len, upload, take);
            rq->len += take;
        }
        *upload_size = 0;
        return MHD_YES;
    }
    if (rq->too_large) {
        access_log(c, method, "-", NULL, 413, 0);
        return send_error(c, 413, "the body is larger than max_body");
    }

    if (strcmp(url, "/v1/health") == 0) {
        if (!is_get) return send_error(c, 405, "method not allowed");
        return do_health(c);
    }
    if (!is_get && !is_post) {
        access_log(c, method, "-", NULL, 405, 0);
        return send_error(c, 405, "method not allowed");
    }
    if (!authenticate(c, &key)) {
        access_log(c, method, "-", NULL, 401, 0);
        return send_error(c, 401, "a valid API key is required");
    }

    if (strcmp(url, "/v1/db") == 0 && is_get) {
        ret = do_db(c);
        access_log(c, method, "/v1/db", key.name, 200, 0);
        return ret;
    }
    if (strncmp(url, "/v1/lookup/", 11) == 0 && is_get) {
        o = resp_lookup_one(&key, url + 11, &status, &err);
        ret = send_resp(c, status, o, err);
        access_log(c, method, "/v1/lookup/", key.name, status, 1);
        return ret;
    }
    if (strcmp(url, "/v1/lookup") == 0 && is_get) {
        const char *q = MHD_lookup_connection_value(c, MHD_GET_ARGUMENT_KIND, "value");
        o = resp_lookup_one(&key, q ? q : "", &status, &err);
        ret = send_resp(c, status, o, err);
        access_log(c, method, "/v1/lookup", key.name, status, 1);
        return ret;
    }
    if (strcmp(url, "/v1/lookup") == 0 && is_post) {
        o = resp_lookup_batch(&key, rq->body, rq->len, &status, &err, &nvalues);
        ret = send_resp(c, status, o, err);
        access_log(c, method, "/v1/lookup", key.name, status, nvalues);
        return ret;
    }
    if ((strcmp(url, "/attributes/restSearch") == 0 || strcmp(url, "/attributes/restSearch/json") == 0) &&
        is_post) {
        o = resp_misp(&key, rq->body, rq->len, &status, &err, &nvalues);
        ret = send_resp(c, status, o, err);
        access_log(c, method, "/attributes/restSearch", key.name, status, nvalues);
        return ret;
    }
    if (route_known(url)) {
        access_log(c, method, "-", key.name, 405, 0);
        return send_error(c, 405, "method not allowed");
    }
    access_log(c, method, "-", key.name, 404, 0);
    return send_error(c, 404, "no such endpoint");
}

static void completed(void *cls, struct MHD_Connection *c, void **req_cls, enum MHD_RequestTerminationCode toe) {
    req_t *rq = *req_cls;
    (void)cls;
    (void)c;
    (void)toe;
    if (rq == NULL) return;
    free(rq->body);
    free(rq);
    *req_cls = NULL;
}

static void mhd_log(void *cls, const char *fmt, va_list ap) {
    char line[512];
    size_t n;
    (void)cls;
    vsnprintf(line, sizeof line, fmt, ap);
    n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
    logf_("http: %s", line);
}

/* ------------------------------------------------------------------------
 * Startup.
 * ------------------------------------------------------------------------ */
static void on_signal(int sig) {
    if (sig == SIGHUP)
        g_hup = 1;
    else
        g_stop = 1;
}

static int is_loopback(const struct sockaddr_storage *ss) {
    if (ss->ss_family == AF_INET)
        return (ntohl(((const struct sockaddr_in *)(const void *)ss)->sin_addr.s_addr) >> 24) == 127;
    if (ss->ss_family == AF_INET6)
        return IN6_IS_ADDR_LOOPBACK(&((const struct sockaddr_in6 *)(const void *)ss)->sin6_addr);
    return 0;
}

static void listen_addr(struct sockaddr_storage *ss) {
    struct sockaddr_in *s4 = (struct sockaddr_in *)(void *)ss;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)(void *)ss;
    memset(ss, 0, sizeof *ss);
    if (inet_pton(AF_INET, g_cfg.listen, &s4->sin_addr) == 1) {
        s4->sin_family = AF_INET;
        s4->sin_port = htons((uint16_t)g_cfg.port);
#if defined(__APPLE__) || defined(__FreeBSD__)
        s4->sin_len = sizeof *s4;
#endif
    } else if (inet_pton(AF_INET6, g_cfg.listen, &s6->sin6_addr) == 1) {
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons((uint16_t)g_cfg.port);
#if defined(__APPLE__) || defined(__FreeBSD__)
        s6->sin6_len = sizeof *s6;
#endif
    } else {
        die("config: listen \"%s\" is not a numeric IPv4 or IPv6 address", g_cfg.listen);
    }
}

static int hash_key_from_stdin(void) {
    char key[ENRICHD_KEY_MAX + 2];
    uint8_t d[SHA256_LEN];
    size_t len;
    if (fgets(key, sizeof key, stdin) == NULL) {
        fprintf(stderr, "enrichd: no key on stdin\n");
        return 1;
    }
    len = strlen(key);
    while (len > 0 && (key[len - 1] == '\n' || key[len - 1] == '\r')) key[--len] = '\0';
    if (len < ENRICHD_KEY_MIN || len > ENRICHD_KEY_MAX) {
        fprintf(stderr, "enrichd: a key is %d to %d characters (openssl rand -hex 32)\n", ENRICHD_KEY_MIN,
                ENRICHD_KEY_MAX);
        return 1;
    }
    sha256(key, len, d);
    memset(key, 0, sizeof key);
    for (int i = 0; i < SHA256_LEN; i++) printf("%02x", d[i]);
    printf("\n");
    return 0;
}

static void usage(void) {
    fprintf(stderr,
            "usage: enrichd [-c enrichd.json] [-t]\n"
            "       enrichd -k < key\n"
            "  -c  config file (default ./enrichd.json, then /etc/enrichd.json)\n"
            "  -t  check the config, the key file and the database, then exit\n"
            "  -k  read a key on stdin and print the digest the key file holds\n");
    exit(2);
}

static void reload_keys(void) {
    char err[512];
    keyset_t *nk = keys_load(g_cfg.keys, err, sizeof err), *old;
    if (nk == NULL) {
        logf_("keys: %s; keeping the previous keys", err);
        return;
    }
    pthread_rwlock_wrlock(&g_keys_lock);
    old = g_keys;
    g_keys = nk;
    pthread_rwlock_unlock(&g_keys_lock);
    keys_free(old);
    logf_("keys: %zu loaded", nk->n);
}

static void reload_db(void) {
    char err[512];
    unsigned what = 0;
    int rc;
    err[0] = '\0';
    rc = enrich_reload(g_enrich, &what, err, sizeof err);
    if (rc != ENRICH_OK) logf_("reload: %s", err[0] ? err : enrich_strerror(rc));
    if (what)
        logf_("reload: replaced%s%s%s", (what & ENRICH_C_THRT) ? " thrt" : "",
              (what & ENRICH_C_OVERLAY) ? " overlay" : "", (what & ENRICH_C_PREV) ? " prev" : "");
}

int main(int argc, char **argv) {
    const char *cfg_path = NULL;
    int check_only = 0, opt, rc;
    char err[512];
    struct sockaddr_storage ss;
    struct MHD_Daemon *d;
    struct MHD_OptionItem mo[16];
    size_t nmo = 0;
    unsigned flags;
    char *tls_cert = NULL, *tls_key = NULL;
    enrich_options_t eo;
    struct sigaction sa;
    time_t last_reload;

    while ((opt = getopt(argc, argv, "c:tkh")) != -1) {
        switch (opt) {
            case 'c':
                cfg_path = optarg;
                break;
            case 't':
                check_only = 1;
                break;
            case 'k':
                return hash_key_from_stdin();
            default:
                usage();
        }
    }
    if (optind != argc) usage();
    if (cfg_path == NULL) cfg_path = access("enrichd.json", R_OK) == 0 ? "enrichd.json" : "/etc/enrichd.json";
    config_load(&g_cfg, cfg_path);

    g_keys = keys_load(g_cfg.keys, err, sizeof err);
    if (g_keys == NULL) die("keys: %s", err);

    listen_addr(&ss);
    if (g_cfg.tls_cert == NULL && !is_loopback(&ss) && !g_cfg.allow_plaintext)
        die("config: listen %s is not loopback; set tls_cert and tls_key, or allow_plaintext behind a TLS proxy",
            g_cfg.listen);
    if (g_cfg.tls_cert != NULL) {
        struct stat st;
        if (MHD_is_feature_supported(MHD_FEATURE_TLS) != MHD_YES)
            die("config: this libmicrohttpd is built without TLS");
        tls_cert = read_file(g_cfg.tls_cert, ENRICHD_TLS_FILE_MAX, NULL, NULL, err, sizeof err);
        if (tls_cert == NULL) die("tls_cert: %s", err);
        tls_key = read_file(g_cfg.tls_key, ENRICHD_TLS_FILE_MAX, NULL, &st, err, sizeof err);
        if (tls_key == NULL) die("tls_key: %s", err);
        if (st.st_mode & 077) die("tls_key: %s is readable by group or other", g_cfg.tls_key);
    }

    memset(&eo, 0, sizeof eo);
    eo.size = sizeof eo;
    eo.thrt_path = g_cfg.thrt;
    eo.overlay_path = g_cfg.overlay;
    eo.prev_path = g_cfg.prev;
    eo.flags = (g_cfg.skip_private ? ENRICH_OPT_SKIP_PRIVATE : 0) | (check_only ? 0 : ENRICH_OPT_PARTIAL);
    err[0] = '\0';
    rc = enrich_open(&g_enrich, &eo, err, sizeof err);
    if (rc != ENRICH_OK && (check_only || g_enrich == NULL)) die("open: %s", err[0] ? err : enrich_strerror(rc));
    if (rc != ENRICH_OK) logf_("open: %s; serving without it until a reload loads it", err);
    g_lookup_flags = enrich_lookup_flags(g_enrich);
    if (check_only) {
        printf("enrichd: %s ok, %zu keys\n", cfg_path, g_keys->n);
        enrich_close(g_enrich);
        keys_free(g_keys);
        return 0;
    }

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    flags = MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG | MHD_USE_AUTO;
    if (ss.ss_family == AF_INET6) flags |= MHD_USE_IPv6;
    if (tls_cert != NULL) flags |= MHD_USE_TLS;
    mo[nmo++] = (struct MHD_OptionItem){MHD_OPTION_SOCK_ADDR, 0, &ss};
    mo[nmo++] = (struct MHD_OptionItem){MHD_OPTION_THREAD_POOL_SIZE, (intptr_t)g_cfg.threads, NULL};
    mo[nmo++] = (struct MHD_OptionItem){MHD_OPTION_CONNECTION_LIMIT, (intptr_t)g_cfg.max_connections, NULL};
    mo[nmo++] = (struct MHD_OptionItem){MHD_OPTION_PER_IP_CONNECTION_LIMIT, (intptr_t)g_cfg.per_ip_connections, NULL};
    mo[nmo++] = (struct MHD_OptionItem){MHD_OPTION_CONNECTION_TIMEOUT, (intptr_t)g_cfg.timeout_seconds, NULL};
    if (tls_cert != NULL) {
        mo[nmo++] = (struct MHD_OptionItem){MHD_OPTION_HTTPS_MEM_CERT, 0, tls_cert};
        mo[nmo++] = (struct MHD_OptionItem){MHD_OPTION_HTTPS_MEM_KEY, 0, tls_key};
    }
    mo[nmo++] = (struct MHD_OptionItem){MHD_OPTION_END, 0, NULL};
    d = MHD_start_daemon(flags, (uint16_t)g_cfg.port, NULL, NULL, &handler, NULL, MHD_OPTION_EXTERNAL_LOGGER,
                         &mhd_log, NULL, MHD_OPTION_ARRAY, mo, MHD_OPTION_NOTIFY_COMPLETED, &completed, NULL,
                         MHD_OPTION_UNESCAPE_CALLBACK, &no_unescape, NULL, MHD_OPTION_END);
    if (d == NULL) die("cannot listen on %s port %u", g_cfg.listen, g_cfg.port);
    logf_("listening on %s port %u (%s), %u threads, %zu keys", g_cfg.listen, g_cfg.port,
          tls_cert ? "TLS" : "plain HTTP", g_cfg.threads, g_keys->n);

    last_reload = time(NULL);
    while (!g_stop) {
        time_t now;
        poll(NULL, 0, 1000);
        now = time(NULL);
        if (g_hup) {
            g_hup = 0;
            reload_keys();
            reload_db();
            last_reload = now;
        }
        if (g_cfg.reload_seconds > 0 && now - last_reload >= (time_t)g_cfg.reload_seconds) {
            reload_db();
            last_reload = now;
        }
    }

    logf_("stopping");
    MHD_stop_daemon(d);
    for (size_t i = 0; i < g_nreaders; i++) enrich_reader_free(g_readers[i]);
    enrich_close(g_enrich);
    keys_free(g_keys);
    if (tls_key) {
        memset(tls_key, 0, strlen(tls_key));
        free(tls_key);
    }
    free(tls_cert);
    return 0;
}
