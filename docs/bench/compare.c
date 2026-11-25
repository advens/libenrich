/* compare.c: one query stream against several indicator stores.
 *
 *   compare <engine> <store> <queries> <threads> [expected hits]
 *
 * Engines:
 *   enrich   libenrich .thrt, enrich_lookup() (full result, policy applied)
 *   mmdb     MaxMind DB, inet_pton + MMDB_lookup_sockaddr + one field read
 *   mmdbstr  MaxMind DB, MMDB_lookup_string (what log shippers call)
 *   cdb      tinycdb, cdb_find + value pointer
 *   lmdb     LMDB, mdb_get in a read transaction per thread
 *   ghash    GLib GHashTable built in memory from a list file
 *   redis    Redis GET over loopback, one round trip per value
 *   redisp   Redis, pipelined, 100 GETs per round trip
 *
 * The queries are read into memory first. Each engine opens its store,
 * runs the stream once to warm the page cache, then five timed passes on
 * one thread; the median is reported in ns per lookup. Then <threads>
 * threads run the stream at once and the aggregate rate is reported. A
 * hit count that differs from [expected hits] fails the run.
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0. See LICENSE.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "enrich.h"
#include <cdb.h>
#include <fcntl.h>
#include <glib.h>
#include <hiredis/hiredis.h>
#include <lmdb.h>
#include <maxminddb.h>
#include <unistd.h>

typedef struct {
    char **v;
    size_t *len;
    size_t n;
} queries_t;

typedef struct engine engine_t;
struct engine {
    const char *name;
    int (*open)(engine_t *e, const char *store);
    void *(*thread_init)(engine_t *e);
    int (*lookup)(engine_t *e, void *t, const char *v, size_t len);
    /* Optional: a whole stream at once (pipelined engines). */
    long (*run)(engine_t *e, void *t, const queries_t *q);
    void (*thread_done)(engine_t *e, void *t);
    void *h;
};

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void die(const char *m) {
    fprintf(stderr, "compare: %s\n", m);
    exit(1);
}

static queries_t load_queries(const char *path) {
    queries_t q = {0};
    size_t cap = 1 << 20;
    FILE *f = fopen(path, "r");
    char *line = NULL;
    size_t lcap = 0;
    ssize_t got;
    if (f == NULL) die("cannot open the query file");
    q.v = malloc(cap * sizeof *q.v);
    q.len = malloc(cap * sizeof *q.len);
    if (q.v == NULL || q.len == NULL) die("out of memory");
    while ((got = getline(&line, &lcap, f)) > 0) {
        if (line[got - 1] == '\n') line[--got] = '\0';
        if (q.n == cap) {
            cap *= 2;
            q.v = realloc(q.v, cap * sizeof *q.v);
            q.len = realloc(q.len, cap * sizeof *q.len);
            if (q.v == NULL || q.len == NULL) die("out of memory");
        }
        q.v[q.n] = strndup(line, (size_t)got);
        if (q.v[q.n] == NULL) die("out of memory");
        q.len[q.n++] = (size_t)got;
    }
    free(line);
    fclose(f);
    return q;
}

/* ---- libenrich ---------------------------------------------------- */
static int en_open(engine_t *e, const char *store) {
    enrich_options_t o = {sizeof o, store, NULL, NULL, 0};
    char err[256];
    enrich_t *h = NULL;
    if (enrich_open(&h, &o, err, sizeof err) != ENRICH_OK) {
        fprintf(stderr, "enrich_open: %s\n", err);
        return -1;
    }
    e->h = h;
    return 0;
}
static void *en_thread(engine_t *e) { return enrich_reader_new((enrich_t *)e->h); }
static int en_lookup(engine_t *e, void *t, const char *v, size_t len) {
    enrich_result_t r;
    const enrich_snap_t *s = enrich_reader_enter((enrich_reader_t *)t);
    int rc = enrich_lookup(s, 0, v, len, &r);
    (void)e;
    return rc == 1 && (r.flags & ENRICH_R_MATCH) && r.confidence > 0;
}
static void en_done(engine_t *e, void *t) {
    (void)e;
    enrich_reader_leave((enrich_reader_t *)t);
    enrich_reader_free((enrich_reader_t *)t);
}

/* ---- MaxMind DB ------------------------------------------------------ */
static int mm_open(engine_t *e, const char *store) {
    MMDB_s *m = calloc(1, sizeof *m);
    if (m == NULL || MMDB_open(store, MMDB_MODE_MMAP, m) != MMDB_SUCCESS) return -1;
    e->h = m;
    return 0;
}
static void *mm_thread(engine_t *e) {
    (void)e;
    return (void *)1;
}
static int mm_value(MMDB_lookup_result_s *r) {
    MMDB_entry_data_s d;
    if (!r->found_entry) return 0;
    if (MMDB_get_value(&r->entry, &d, "c", NULL) != MMDB_SUCCESS || !d.has_data) return 0;
    return d.uint32 > 0;
}
static int mm_lookup(engine_t *e, void *t, const char *v, size_t len) {
    struct sockaddr_in sa;
    MMDB_lookup_result_s r;
    int err;
    (void)t;
    (void)len;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, v, &sa.sin_addr) != 1) return 0;
    r = MMDB_lookup_sockaddr((MMDB_s *)e->h, (struct sockaddr *)&sa, &err);
    return err == MMDB_SUCCESS && mm_value(&r);
}
static int mms_lookup(engine_t *e, void *t, const char *v, size_t len) {
    int gai, err;
    MMDB_lookup_result_s r;
    (void)t;
    (void)len;
    r = MMDB_lookup_string((MMDB_s *)e->h, v, &gai, &err);
    return gai == 0 && err == MMDB_SUCCESS && mm_value(&r);
}

/* ---- tinycdb ------------------------------------------------------- */
static int cdb_open_(engine_t *e, const char *store) {
    struct cdb *c = calloc(1, sizeof *c);
    int fd = open(store, O_RDONLY);
    if (c == NULL || fd < 0 || cdb_init(c, fd) != 0) return -1;
    e->h = c;
    return 0;
}
static void *cdb_thread(engine_t *e) {
    (void)e;
    return (void *)1;
}
static int cdb_lookup(engine_t *e, void *t, const char *v, size_t len) {
    struct cdb *c = (struct cdb *)e->h;
    const unsigned char *p;
    (void)t;
    /* cdb_find keeps its position in the struct; a per-call copy makes it
     * safe across threads (the map is shared and read-only). */
    struct cdb local = *c;
    if (cdb_find(&local, v, (unsigned)len) <= 0) return 0;
    p = cdb_getdata(&local);
    return cdb_datalen(&local) > 0 && p[0] != '0';
}

/* ---- LMDB ------------------------------------------------------------ */
typedef struct {
    MDB_env *env;
    MDB_dbi dbi;
} lm_t;
typedef struct {
    MDB_txn *txn;
} lm_thread_t;
static int lm_open(engine_t *e, const char *store) {
    lm_t *l = calloc(1, sizeof *l);
    MDB_txn *txn;
    if (l == NULL || mdb_env_create(&l->env) != 0) return -1;
    mdb_env_set_maxreaders(l->env, 256);
    if (mdb_env_open(l->env, store, MDB_RDONLY | MDB_NOSUBDIR | MDB_NOLOCK | MDB_NOTLS, 0) != 0) return -1;
    if (mdb_txn_begin(l->env, NULL, MDB_RDONLY, &txn) != 0 || mdb_dbi_open(txn, NULL, 0, &l->dbi) != 0) return -1;
    mdb_txn_abort(txn);
    e->h = l;
    return 0;
}
static void *lm_thread(engine_t *e) {
    lm_t *l = e->h;
    lm_thread_t *t = calloc(1, sizeof *t);
    if (t == NULL || mdb_txn_begin(l->env, NULL, MDB_RDONLY, &t->txn) != 0) die("lmdb txn");
    return t;
}
static int lm_lookup(engine_t *e, void *tv, const char *v, size_t len) {
    lm_t *l = e->h;
    lm_thread_t *t = tv;
    MDB_val k = {len, (void *)v}, d;
    if (mdb_get(t->txn, l->dbi, &k, &d) != 0) return 0;
    return d.mv_size > 0 && ((const char *)d.mv_data)[0] != '0';
}
static void lm_done(engine_t *e, void *tv) {
    lm_thread_t *t = tv;
    (void)e;
    mdb_txn_abort(t->txn);
    free(t);
}

/* ---- GHashTable -------------------------------------------------------- */
static double g_load_seconds;
static int gh_open(engine_t *e, const char *store) {
    queries_t keys;
    GHashTable *h;
    double t0 = now();
    keys = load_queries(store);
    h = g_hash_table_new(g_str_hash, g_str_equal);
    for (size_t i = 0; i < keys.n; i++) g_hash_table_insert(h, keys.v[i], (gpointer) "70");
    g_load_seconds = now() - t0;
    free(keys.v);
    free(keys.len);
    e->h = h;
    return 0;
}
static void *gh_thread(engine_t *e) {
    (void)e;
    return (void *)1;
}
static int gh_lookup(engine_t *e, void *t, const char *v, size_t len) {
    const char *d;
    (void)t;
    (void)len;
    d = g_hash_table_lookup((GHashTable *)e->h, v);
    return d != NULL && d[0] != '0';
}

/* ---- Redis ------------------------------------------------------------- */
static const char *g_redis_sock;
static int rd_open(engine_t *e, const char *store) {
    g_redis_sock = store;
    e->h = NULL;
    return 0;
}
static void *rd_thread(engine_t *e) {
    redisContext *c = redisConnectUnix(g_redis_sock);
    (void)e;
    if (c == NULL || c->err) die("redis connect");
    return c;
}
static int rd_lookup(engine_t *e, void *t, const char *v, size_t len) {
    redisReply *r = redisCommand((redisContext *)t, "GET %b", v, len);
    int hit;
    (void)e;
    if (r == NULL) die("redis");
    hit = r->type == REDIS_REPLY_STRING && r->len > 0 && r->str[0] != '0';
    freeReplyObject(r);
    return hit;
}
static long rd_run(engine_t *e, void *t, const queries_t *q) {
    redisContext *c = t;
    long hits = 0;
    (void)e;
    for (size_t i = 0; i < q->n; i += 100) {
        size_t end = i + 100 < q->n ? i + 100 : q->n;
        for (size_t j = i; j < end; j++) redisAppendCommand(c, "GET %b", q->v[j], q->len[j]);
        for (size_t j = i; j < end; j++) {
            redisReply *r;
            if (redisGetReply(c, (void **)&r) != REDIS_OK || r == NULL) die("redis");
            hits += r->type == REDIS_REPLY_STRING && r->len > 0 && r->str[0] != '0';
            freeReplyObject(r);
        }
    }
    return hits;
}
static void rd_done(engine_t *e, void *t) {
    (void)e;
    redisFree((redisContext *)t);
}

static void *noop_thread(engine_t *e) {
    (void)e;
    return (void *)1;
}

static engine_t g_engines[] = {
    {"enrich", en_open, en_thread, en_lookup, NULL, en_done, NULL},
    {"mmdb", mm_open, mm_thread, mm_lookup, NULL, NULL, NULL},
    {"mmdbstr", mm_open, mm_thread, mms_lookup, NULL, NULL, NULL},
    {"cdb", cdb_open_, cdb_thread, cdb_lookup, NULL, NULL, NULL},
    {"lmdb", lm_open, lm_thread, lm_lookup, NULL, lm_done, NULL},
    {"ghash", gh_open, gh_thread, gh_lookup, NULL, NULL, NULL},
    {"redis", rd_open, rd_thread, rd_lookup, NULL, rd_done, NULL},
    {"redisp", rd_open, rd_thread, NULL, rd_run, rd_done, NULL},
};

static long run_stream(engine_t *e, void *t, const queries_t *q) {
    long hits = 0;
    if (e->run) return e->run(e, t, q);
    for (size_t i = 0; i < q->n; i++) hits += e->lookup(e, t, q->v[i], q->len[i]);
    return hits;
}

typedef struct {
    engine_t *e;
    const queries_t *q;
    long hits;
} job_t;

static void *job(void *arg) {
    job_t *j = arg;
    void *t = j->e->thread_init(j->e);
    j->hits = run_stream(j->e, t, j->q);
    if (j->e->thread_done) j->e->thread_done(j->e, t);
    return NULL;
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    engine_t *e = NULL;
    queries_t q;
    double t0, open_s, pass[5];
    long hits = 0, expect = -1;
    int threads;
    void *t;
    if (argc < 5) die("usage: compare <engine> <store> <queries> <threads> [expected hits]");
    for (size_t i = 0; i < sizeof g_engines / sizeof g_engines[0]; i++)
        if (strcmp(g_engines[i].name, argv[1]) == 0) e = &g_engines[i];
    if (e == NULL) die("unknown engine");
    if (e->thread_init == NULL) e->thread_init = noop_thread;
    threads = atoi(argv[4]);
    if (argc > 5) expect = atol(argv[5]);
    q = load_queries(argv[3]);

    t0 = now();
    if (e->open(e, argv[2]) != 0) die("cannot open the store");
    open_s = now() - t0;
    if (strcmp(e->name, "ghash") == 0) open_s = g_load_seconds;

    t = e->thread_init(e);
    hits = run_stream(e, t, &q); /* warm */
    for (int p = 0; p < 5; p++) {
        long h;
        t0 = now();
        h = run_stream(e, t, &q);
        pass[p] = (now() - t0) / (double)q.n * 1e9;
        if (h != hits) die("hit count changed between passes");
    }
    if (e->thread_done) e->thread_done(e, t);
    qsort(pass, 5, sizeof pass[0], cmp_d);
    if (expect >= 0 && hits != expect) {
        fprintf(stderr, "compare: %s found %ld hits, expected %ld\n", e->name, hits, expect);
        return 2;
    }

    {
        pthread_t th[256];
        job_t jobs[256];
        double el;
        if (threads < 1 || threads > 256) die("threads must be 1 to 256");
        t0 = now();
        for (int i = 0; i < threads; i++) {
            jobs[i] = (job_t){e, &q, 0};
            pthread_create(&th[i], NULL, job, &jobs[i]);
        }
        for (int i = 0; i < threads; i++) pthread_join(th[i], NULL);
        el = now() - t0;
        for (int i = 0; i < threads; i++)
            if (jobs[i].hits != hits) die("hit count differs between threads");
        printf("%-8s %-18s open %8.3f s  1 thread %8.1f ns/lookup (min %.1f max %.1f)  %d threads %7.2f M lookups/s  hits %ld\n",
               e->name, strrchr(argv[3], '/') ? strrchr(argv[3], '/') + 1 : argv[3], open_s, pass[2], pass[0], pass[4],
               threads, (double)q.n * threads / el / 1e6, hits);
    }
    return 0;
}
