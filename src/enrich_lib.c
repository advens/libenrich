/* enrich_lib.c
 * The compiled lookup API declared in enrich.h: load and validate a .thrt,
 * an overlay and a .prev as one snapshot, look values up under the shared
 * policy, and swap snapshots while readers run.
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0. See LICENSE.
 */
#include "enrich.h"
#include "thrt_validate.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define CACHE_LINE 64
#define BATCH_CHUNK 64
#define IP_TEXT_MAX 46 /* INET6_ADDRSTRLEN */

/* ------------------------------------------------------------------------
 * Errors
 * ------------------------------------------------------------------------ */

static void seterr(char *err, size_t len, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

static void seterr(char *err, size_t len, const char *fmt, ...) {
    va_list ap;
    if (err == NULL || len == 0) return;
    va_start(ap, fmt);
    vsnprintf(err, len, fmt, ap);
    va_end(ap);
}

const char *enrich_strerror(int status) {
    switch (status) {
        case ENRICH_OK:
            return "ok";
        case ENRICH_EINVAL:
            return "invalid argument";
        case ENRICH_ETOOLONG:
            return "value too long";
        case ENRICH_ENOENT:
            return "file missing";
        case ENRICH_EFORMAT:
            return "file layout invalid";
        case ENRICH_EVERSION:
            return "unsupported format version";
        case ENRICH_ECHECKSUM:
            return "checksum mismatch";
        case ENRICH_ENOMEM:
            return "out of memory";
        case ENRICH_EIO:
            return "cannot open or map file";
        default:
            return "unknown status";
    }
}

/* ------------------------------------------------------------------------
 * File identity: a file replaced by rename has a new inode, a file
 * rewritten in place a new size or mtime.
 * ------------------------------------------------------------------------ */

typedef struct {
    dev_t dev;
    ino_t ino;
    off_t size;
    int64_t mtime_s;
    long mtime_ns;
} file_id_t;

static void file_id_of(const struct stat *st, file_id_t *id) {
    memset(id, 0, sizeof *id);
    id->dev = st->st_dev;
    id->ino = st->st_ino;
    id->size = st->st_size;
#if defined(__APPLE__)
    id->mtime_s = (int64_t)st->st_mtimespec.tv_sec;
    id->mtime_ns = st->st_mtimespec.tv_nsec;
#else
    id->mtime_s = (int64_t)st->st_mtim.tv_sec;
    id->mtime_ns = st->st_mtim.tv_nsec;
#endif
}

static int file_id_eq(const file_id_t *a, const file_id_t *b) {
    return a->dev == b->dev && a->ino == b->ino && a->size == b->size && a->mtime_s == b->mtime_s &&
           a->mtime_ns == b->mtime_ns;
}

/* Open, fstat and map read-only. The fd is closed before returning. */
static int map_file(const char *path, void **map, size_t *size, file_id_t *id) {
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? ENRICH_ENOENT : ENRICH_EIO;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        close(fd);
        return ENRICH_EIO;
    }
    *size = (size_t)st.st_size;
    *map = mmap(NULL, *size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (*map == MAP_FAILED) return ENRICH_EIO;
    file_id_of(&st, id);
    return ENRICH_OK;
}

/* ------------------------------------------------------------------------
 * Components. Each is shared by every snapshot that holds it and freed
 * when the last of those snapshots is freed.
 * ------------------------------------------------------------------------ */

typedef struct {
    atomic_uint refs;
    file_id_t id;
    void *map;
    size_t size;
    const thrt_header_t *hdr;
    thrt_metadata_t *meta;
    thrt_ipv4_range_t *v4;
    thrt_ipv6_range_t *v6;
    const void *accel;
    thrt_hash_entry_t *ht;
    const uint8_t *bloom;
    const char *pool;
    size_t pool_size;
    const thrt_feed_entry_t *feeds;
} thrt_db_t;

typedef struct {
    atomic_uint refs;
    file_id_t id;
    thrt_overlay_t *o;
} ovl_db_t;

typedef struct {
    atomic_uint refs;
    file_id_t id;
    void *map;
    size_t size;
    const prev_header_t *hdr;
    const prev_entry_t *table;
    uint32_t slots;
} prev_db_t;

static void thrt_db_unref(thrt_db_t *d) {
    if (d == NULL || atomic_fetch_sub(&d->refs, 1) != 1) return;
    munmap(d->map, d->size);
    free(d);
}

static void ovl_db_unref(ovl_db_t *d) {
    if (d == NULL || atomic_fetch_sub(&d->refs, 1) != 1) return;
    thrt_overlay_free(d->o);
    free(d);
}

static void prev_db_unref(prev_db_t *d) {
    if (d == NULL || atomic_fetch_sub(&d->refs, 1) != 1) return;
    munmap(d->map, d->size);
    free(d);
}

/* thrt_validate() status to an ENRICH_* status. */
static int thrt_check(const unsigned char *base, size_t size, const char *path, char *err, size_t err_len) {
    switch (thrt_validate(base, size, path, err, err_len)) {
        case THRT_VALID_OK:
            return ENRICH_OK;
        case THRT_VALID_EVERSION:
            return ENRICH_EVERSION;
        case THRT_VALID_ECHECKSUM:
            return ENRICH_ECHECKSUM;
        default:
            return ENRICH_EFORMAT;
    }
}

static int thrt_db_load(const char *path, thrt_db_t **out, char *err, size_t err_len) {
    thrt_db_t *d;
    void *map;
    size_t size;
    file_id_t id;
    const thrt_header_t *h;
    unsigned char *b;
    int rc = map_file(path, &map, &size, &id);
    if (rc != ENRICH_OK) {
        seterr(err, err_len, "%s: %s", path, enrich_strerror(rc));
        return rc;
    }
    rc = thrt_check(map, size, path, err, err_len);
    if (rc != ENRICH_OK) {
        munmap(map, size);
        return rc;
    }
    d = (thrt_db_t *)calloc(1, sizeof *d);
    if (d == NULL) {
        munmap(map, size);
        seterr(err, err_len, "%s: out of memory", path);
        return ENRICH_ENOMEM;
    }
    b = (unsigned char *)map;
    h = (const thrt_header_t *)map;
    atomic_init(&d->refs, 0);
    d->id = id;
    d->map = map;
    d->size = size;
    d->hdr = h;
    d->meta = (thrt_metadata_t *)(void *)(b + h->offset_metadata);
    d->v4 = (thrt_ipv4_range_t *)(void *)(b + h->offset_ipv4);
    d->v6 = (thrt_ipv6_range_t *)(void *)(b + h->offset_ipv6);
    d->accel = b + h->offset_ip_accel;
    d->ht = (thrt_hash_entry_t *)(void *)(b + h->offset_hashtable);
    d->bloom = h->bloom_size_bits ? b + h->offset_bloom : NULL;
    d->pool = (const char *)b + h->offset_strings;
    d->pool_size = size - h->offset_strings;
    d->feeds = (const thrt_feed_entry_t *)(const void *)(b + h->offset_feeds);
    *out = d;
    return ENRICH_OK;
}

static int ovl_db_load(const char *path, ovl_db_t **out, char *err, size_t err_len) {
    struct stat st;
    int why = 0;
    ovl_db_t *d;
    thrt_overlay_t *o;

    if (stat(path, &st) != 0) {
        seterr(err, err_len, "%s: %s", path, strerror(errno));
        return errno == ENOENT ? ENRICH_ENOENT : ENRICH_EIO;
    }
    o = thrt_overlay_load_ex(path, &why);
    if (o == NULL) {
        int rc = why == THRT_OVERLAY_ERR_VERSION    ? ENRICH_EVERSION
                 : why == THRT_OVERLAY_ERR_CHECKSUM ? ENRICH_ECHECKSUM
                 : why == THRT_OVERLAY_ERR_NOMEM    ? ENRICH_ENOMEM
                 : why == THRT_OVERLAY_ERR_FORMAT   ? ENRICH_EFORMAT
                                                    : ENRICH_EIO;
        seterr(err, err_len, "%s: overlay: %s", path, enrich_strerror(rc));
        return rc;
    }
    d = (ovl_db_t *)calloc(1, sizeof *d);
    if (d == NULL) {
        thrt_overlay_free(o);
        seterr(err, err_len, "%s: out of memory", path);
        return ENRICH_ENOMEM;
    }
    atomic_init(&d->refs, 0);
    /* The identity comes from before the load, so a file replaced during
     * the load is seen as changed on the next reload. */
    file_id_of(&st, &d->id);
    d->o = o;
    *out = d;
    return ENRICH_OK;
}

static int prev_db_load(const char *path, prev_db_t **out, char *err, size_t err_len) {
    prev_db_t *d;
    void *map;
    size_t size;
    file_id_t id;
    uint32_t slots = 0;
    const prev_entry_t *table;
    const prev_header_t *h;
    int rc = map_file(path, &map, &size, &id);
    if (rc != ENRICH_OK) {
        seterr(err, err_len, "%s: %s", path, enrich_strerror(rc));
        return rc;
    }
    h = (const prev_header_t *)map;
    if (size < sizeof *h || h->magic != PREV_MAGIC) {
        munmap(map, size);
        seterr(err, err_len, "%s: not a .prev file", path);
        return ENRICH_EFORMAT;
    }
    if (h->version != PREV_VERSION) {
        /* Read the header before it is unmapped. */
        seterr(err, err_len, "%s: .prev version %u, this library reads %u", path, h->version, PREV_VERSION);
        munmap(map, size);
        return ENRICH_EVERSION;
    }
    table = prev_table_map(map, size, &slots);
    if (table == NULL) {
        munmap(map, size);
        seterr(err, err_len, "%s: a table lies outside the file", path);
        return ENRICH_EFORMAT;
    }
    d = (prev_db_t *)calloc(1, sizeof *d);
    if (d == NULL) {
        munmap(map, size);
        seterr(err, err_len, "%s: out of memory", path);
        return ENRICH_ENOMEM;
    }
    atomic_init(&d->refs, 0);
    d->id = id;
    d->map = map;
    d->size = size;
    d->hdr = h;
    d->table = table;
    d->slots = slots;
    *out = d;
    return ENRICH_OK;
}

/* ------------------------------------------------------------------------
 * Snapshots, readers and reclamation.
 * ------------------------------------------------------------------------ */

struct enrich_snap {
    thrt_db_t *thrt;
    ovl_db_t *ovl;
    prev_db_t *prev;
    uint64_t generation;
    uint64_t retire_tag; /* grace period counter value at retirement */
    struct enrich_snap *next;
};

struct enrich_reader {
    /* 0 = outside, else the grace period counter seen at enter(). Alone on
     * its cache line: only this reader writes it. */
    _Alignas(CACHE_LINE) _Atomic uint64_t epoch;
    uint64_t seen; /* last value this thread published */
    enrich_t *e;
    struct enrich_reader *next;
};

struct enrich {
    char *path[3];
    uint32_t flags;
    pthread_mutex_t lock; /* reload, the reader list and the retired list */
    _Atomic(struct enrich_snap *) cur;
    _Atomic uint64_t gp; /* grace period counter, +1 per publish */
    uint64_t generation;
    struct enrich_reader *readers;
    struct enrich_snap *retired;
};

enum { P_THRT = 0, P_OVL = 1, P_PREV = 2 };

static struct enrich_snap *snap_make(thrt_db_t *t, ovl_db_t *o, prev_db_t *p, uint64_t generation) {
    struct enrich_snap *s = (struct enrich_snap *)calloc(1, sizeof *s);
    if (s == NULL) return NULL;
    s->thrt = t;
    s->ovl = o;
    s->prev = p;
    s->generation = generation;
    if (t) atomic_fetch_add(&t->refs, 1);
    if (o) atomic_fetch_add(&o->refs, 1);
    if (p) atomic_fetch_add(&p->refs, 1);
    return s;
}

static void snap_free(struct enrich_snap *s) {
    if (s == NULL) return;
    thrt_db_unref(s->thrt);
    ovl_db_unref(s->ovl);
    prev_db_unref(s->prev);
    free(s);
}

/* A snapshot retired at tag t may be held by a reader whose epoch is
 * below t. Free those every active reader has passed. Lock held. */
static void reclaim_locked(enrich_t *e) {
    uint64_t min = UINT64_MAX;
    struct enrich_snap **pp;
    for (struct enrich_reader *r = e->readers; r != NULL; r = r->next) {
        uint64_t ep = atomic_load(&r->epoch);
        if (ep != 0 && ep < min) min = ep;
    }
    pp = &e->retired;
    while (*pp != NULL) {
        struct enrich_snap *s = *pp;
        if (s->retire_tag <= min) {
            *pp = s->next;
            snap_free(s);
        } else {
            pp = &s->next;
        }
    }
}

/* Swap in a new snapshot and retire the old one. Lock held. */
static void publish_locked(enrich_t *e, struct enrich_snap *s) {
    struct enrich_snap *old = atomic_exchange(&e->cur, s);
    uint64_t tag = atomic_fetch_add(&e->gp, 1) + 1;
    if (old != NULL) {
        old->retire_tag = tag;
        old->next = e->retired;
        e->retired = old;
    }
    reclaim_locked(e);
}

enrich_reader_t *enrich_reader_new(enrich_t *e) {
    void *mem = NULL;
    enrich_reader_t *r;
    if (e == NULL || posix_memalign(&mem, CACHE_LINE, sizeof(enrich_reader_t)) != 0) return NULL;
    r = (enrich_reader_t *)mem;
    memset(r, 0, sizeof *r);
    atomic_init(&r->epoch, 0);
    r->e = e;
    pthread_mutex_lock(&e->lock);
    r->next = e->readers;
    e->readers = r;
    pthread_mutex_unlock(&e->lock);
    return r;
}

void enrich_reader_free(enrich_reader_t *r) {
    enrich_t *e;
    if (r == NULL) return;
    e = r->e;
    atomic_store(&r->epoch, 0);
    pthread_mutex_lock(&e->lock);
    for (struct enrich_reader **pp = &e->readers; *pp != NULL; pp = &(*pp)->next) {
        if (*pp == r) {
            *pp = r->next;
            break;
        }
    }
    reclaim_locked(e);
    pthread_mutex_unlock(&e->lock);
    free(r);
}

const enrich_snap_t *enrich_reader_enter(enrich_reader_t *r) {
    enrich_t *e = r->e;
    uint64_t g = atomic_load_explicit(&e->gp, memory_order_acquire);
    if (r->seen != g) {
        /* Publish the epoch before reading the snapshot pointer. The
         * writer swaps the pointer before it scans the epochs, so either
         * it sees this epoch or this load sees its new snapshot. */
        atomic_store_explicit(&r->epoch, g, memory_order_relaxed);
        atomic_thread_fence(memory_order_seq_cst);
        r->seen = g;
    }
    return atomic_load_explicit(&e->cur, memory_order_acquire);
}

void enrich_reader_leave(enrich_reader_t *r) {
    atomic_store_explicit(&r->epoch, 0, memory_order_release);
    r->seen = 0;
}

void enrich_reclaim(enrich_t *e) {
    if (e == NULL) return;
    pthread_mutex_lock(&e->lock);
    reclaim_locked(e);
    pthread_mutex_unlock(&e->lock);
}

/* ------------------------------------------------------------------------
 * Open, reload, close.
 * ------------------------------------------------------------------------ */

/* Load whatever changed and publish. first is the first failure. Lock held. */
static int reload_locked(enrich_t *e, unsigned *reloaded, char *err, size_t err_len) {
    struct enrich_snap *cur = atomic_load(&e->cur);
    thrt_db_t *t = cur ? cur->thrt : NULL;
    ovl_db_t *o = cur ? cur->ovl : NULL;
    prev_db_t *p = cur ? cur->prev : NULL;
    thrt_db_t *nt = NULL;
    ovl_db_t *no = NULL;
    prev_db_t *np = NULL;
    unsigned changed = 0;
    int first = ENRICH_OK;
    struct stat st;
    file_id_t id;
    char *ebuf = err;
    size_t elen = err_len;
    int rc;

    if (reloaded) *reloaded = 0;
    if (err && err_len) err[0] = '\0';

#define NOTE_FAIL(rc_)                                                                                                 \
    do {                                                                                                               \
        if (first == ENRICH_OK) {                                                                                      \
            first = (rc_);                                                                                             \
            ebuf = NULL;                                                                                               \
            elen = 0;                                                                                                  \
        }                                                                                                              \
    } while (0)

    if (e->path[P_THRT] != NULL) {
        if (stat(e->path[P_THRT], &st) != 0) {
            seterr(ebuf, elen, "%s: %s", e->path[P_THRT], strerror(errno));
            NOTE_FAIL(errno == ENOENT ? ENRICH_ENOENT : ENRICH_EIO);
        } else {
            file_id_of(&st, &id);
            if (t == NULL || !file_id_eq(&id, &t->id)) {
                rc = thrt_db_load(e->path[P_THRT], &nt, ebuf, elen);
                if (rc == ENRICH_OK)
                    changed |= ENRICH_C_THRT;
                else
                    NOTE_FAIL(rc);
            }
        }
    }
    if (e->path[P_OVL] != NULL) {
        if (stat(e->path[P_OVL], &st) != 0) {
            seterr(ebuf, elen, "%s: %s", e->path[P_OVL], strerror(errno));
            NOTE_FAIL(errno == ENOENT ? ENRICH_ENOENT : ENRICH_EIO);
        } else {
            file_id_of(&st, &id);
            if (o == NULL || !file_id_eq(&id, &o->id)) {
                rc = ovl_db_load(e->path[P_OVL], &no, ebuf, elen);
                if (rc == ENRICH_OK)
                    changed |= ENRICH_C_OVERLAY;
                else
                    NOTE_FAIL(rc);
            }
        }
    }
    if (e->path[P_PREV] != NULL) {
        if (stat(e->path[P_PREV], &st) != 0) {
            seterr(ebuf, elen, "%s: %s", e->path[P_PREV], strerror(errno));
            NOTE_FAIL(errno == ENOENT ? ENRICH_ENOENT : ENRICH_EIO);
        } else {
            file_id_of(&st, &id);
            if (p == NULL || !file_id_eq(&id, &p->id)) {
                rc = prev_db_load(e->path[P_PREV], &np, ebuf, elen);
                if (rc == ENRICH_OK)
                    changed |= ENRICH_C_PREV;
                else
                    NOTE_FAIL(rc);
            }
        }
    }
#undef NOTE_FAIL

    if (changed != 0 || cur == NULL) {
        struct enrich_snap *s = snap_make(nt ? nt : t, no ? no : o, np ? np : p, e->generation + 1);
        if (s == NULL) {
            /* The new components have no holder yet. */
            if (nt) munmap(nt->map, nt->size), free(nt);
            if (no) thrt_overlay_free(no->o), free(no);
            if (np) munmap(np->map, np->size), free(np);
            if (first == ENRICH_OK) seterr(err, err_len, "out of memory");
            return ENRICH_ENOMEM;
        }
        e->generation++;
        publish_locked(e, s);
    }
    if (reloaded) *reloaded = changed;
    return first;
}

int enrich_open(enrich_t **out, const enrich_options_t *opt, char *err, size_t err_len) {
    enrich_t *e;
    const char *src[3];
    int rc;

    if (err && err_len) err[0] = '\0';
    if (out == NULL || opt == NULL || opt->size < offsetof(enrich_options_t, flags) + sizeof(uint32_t) ||
        ((opt->thrt_path == NULL || opt->thrt_path[0] == '\0') &&
         (opt->overlay_path == NULL || opt->overlay_path[0] == '\0') &&
         (opt->prev_path == NULL || opt->prev_path[0] == '\0'))) {
        seterr(err, err_len, "enrich_open: no file to open");
        return ENRICH_EINVAL;
    }
    *out = NULL;
    e = (enrich_t *)calloc(1, sizeof *e);
    if (e == NULL) return ENRICH_ENOMEM;
    src[P_THRT] = opt->thrt_path;
    src[P_OVL] = opt->overlay_path;
    src[P_PREV] = opt->prev_path;
    for (int i = 0; i < 3; i++) {
        if (src[i] == NULL || src[i][0] == '\0') continue;
        e->path[i] = strdup(src[i]);
        if (e->path[i] == NULL) {
            enrich_close(e);
            return ENRICH_ENOMEM;
        }
    }
    e->flags = opt->flags;
    atomic_init(&e->cur, NULL);
    atomic_init(&e->gp, 1);
    if (pthread_mutex_init(&e->lock, NULL) != 0) {
        for (int i = 0; i < 3; i++) free(e->path[i]);
        free(e);
        return ENRICH_ENOMEM;
    }

    pthread_mutex_lock(&e->lock);
    rc = reload_locked(e, NULL, err, err_len);
    pthread_mutex_unlock(&e->lock);
    if (rc == ENRICH_ENOMEM || (rc != ENRICH_OK && !(e->flags & ENRICH_OPT_PARTIAL))) {
        enrich_close(e);
        return rc;
    }
    *out = e;
    return rc;
}

int enrich_reload(enrich_t *e, unsigned *reloaded, char *err, size_t err_len) {
    int rc;
    if (e == NULL) return ENRICH_EINVAL;
    pthread_mutex_lock(&e->lock);
    rc = reload_locked(e, reloaded, err, err_len);
    pthread_mutex_unlock(&e->lock);
    return rc;
}

void enrich_close(enrich_t *e) {
    struct enrich_snap *s;
    struct enrich_reader *r;
    if (e == NULL) return;
    /* Readers left behind by the caller are released with the handle. */
    r = e->readers;
    while (r != NULL) {
        struct enrich_reader *n = r->next;
        free(r);
        r = n;
    }
    s = e->retired;
    while (s != NULL) {
        struct enrich_snap *n = s->next;
        snap_free(s);
        s = n;
    }
    snap_free(atomic_load(&e->cur));
    pthread_mutex_destroy(&e->lock);
    for (int i = 0; i < 3; i++) free(e->path[i]);
    free(e);
}

uint32_t enrich_lookup_flags(const enrich_t *e) {
    return e ? (e->flags & ENRICH_OPT_SKIP_PRIVATE) : 0;
}

/* ------------------------------------------------------------------------
 * Lookup.
 * ------------------------------------------------------------------------ */

typedef struct {
    uint8_t kind;
    uint8_t has_hash;
    uint32_t v4;
    uint8_t v6[16];
    uint64_t hash;
} query_t;

static inline uint64_t value_hash(const char *v, size_t len) {
    return (uint64_t)(crc32c_platform(0xFFFFFFFFu, v, len) ^ 0xFFFFFFFFu);
}

static int value_check(const char *v, size_t len) {
    if (v == NULL || len == 0) return ENRICH_EINVAL;
    if (len > ENRICH_VALUE_MAX) return ENRICH_ETOOLONG;
    if (memchr(v, '\0', len) != NULL) return ENRICH_EINVAL;
    return ENRICH_OK;
}

static int classify(const char *v, size_t len, query_t *q) {
    int rc = value_check(v, len);
    q->kind = ENRICH_KIND_STRING;
    q->has_hash = 0;
    if (rc != ENRICH_OK) return rc;
    /* The builder reads addresses with the same two functions. */
    if (len <= 15 && thrt_ipv4_strict(v, len, &q->v4)) {
        q->kind = ENRICH_KIND_IPV4;
        return ENRICH_OK;
    }
    if (len < IP_TEXT_MAX && thrt_ipv6_strict(v, len, q->v6)) {
        q->kind = ENRICH_KIND_IPV6;
        return ENRICH_OK;
    }
    q->hash = value_hash(v, len);
    q->has_hash = 1;
    return ENRICH_OK;
}

/* thrt_lookup_string() for a counted value. Offsets were validated at
 * load, and the compare stays inside the pool. The builder keeps every
 * entry within THRT_PROBE_MAX slots of its home slot. */
static const thrt_metadata_t *thrt_find_string(const thrt_db_t *d, const char *v, size_t len, uint64_t hash) {
    uint32_t mask = d->hdr->hash_slots - 1;
    uint32_t idx = (uint32_t)hash & mask;
    for (int probes = 0; probes < THRT_PROBE_MAX; probes++) {
        const thrt_hash_entry_t *e = &d->ht[idx];
        if (e->meta_idx == 0xFFFFFFFFu) return NULL;
        if (e->hash_key == hash && len < d->pool_size - e->string_offset) {
            const char *s = d->pool + e->string_offset;
            if (s[len] == '\0' && memcmp(s, v, len) == 0) return &d->meta[e->meta_idx];
        }
        idx = (idx + 1) & mask;
    }
    return NULL;
}

static int has_report(const enrich_result_t *r) {
    return (r->flags & (ENRICH_R_MATCH | ENRICH_R_WHITELISTED | ENRICH_R_SUPPRESSED)) != 0 || r->tags != NULL ||
           r->labels != NULL || r->overlay_tags != NULL;
}

static int resolve(const enrich_snap_t *s, uint32_t opt_flags, const char *v, size_t len, query_t *q,
                   enrich_result_t *out) {
    const thrt_metadata_t *m = NULL;
    const thrt_db_t *d = s ? s->thrt : NULL;
    int priv = 0;

    memset(out, 0, sizeof *out);
    out->kind = q->kind;

    if (s != NULL && s->ovl != NULL) {
        const thrt_overlay_entry_t *oe;
        if (!q->has_hash) {
            q->hash = value_hash(v, len);
            q->has_hash = 1;
        }
        oe = thrt_overlay_find(s->ovl->o, q->hash, v, len);
        if (oe != NULL) {
            out->flags |= ENRICH_R_OVERLAY;
            if (oe->action == OVERLAY_ACTION_WHITELIST) {
                if (oe->suppress_mode == OVERLAY_SUPPRESS_FULL) {
                    out->flags = ENRICH_R_OVERLAY | ENRICH_R_SUPPRESSED;
                    return 1;
                }
                out->flags |= ENRICH_R_WHITELISTED;
            } else if (oe->action == OVERLAY_ACTION_TAG) {
                out->ovl_type_mask = oe->type_mask;
                if (oe->tags_length != 0) {
                    out->overlay_tags = s->ovl->o->string_pool + oe->tags_offset;
                    out->overlay_tags_len = oe->tags_length;
                }
            } else {
                out->flags |= ENRICH_R_MATCH;
                out->ovl_type_mask = oe->type_mask;
                out->ovl_confidence = oe->confidence;
                out->ovl_category_mask = oe->category_mask;
            }
        }
    }

    if (q->kind == ENRICH_KIND_IPV4) {
        priv = thrt_is_private_ipv4(q->v4);
        if (d) m = thrt_lookup_ip_accel(d->v4, d->accel, d->meta, q->v4);
    } else if (q->kind == ENRICH_KIND_IPV6) {
        priv = thrt_is_private_ipv6(q->v6);
        if (d) m = thrt_lookup_ipv6(d->v6, (int)d->hdr->ipv6_range_count, d->meta, q->v6);
    } else if (d) {
        if (d->bloom == NULL || thrt_bloom_check(d->bloom, d->hdr->bloom_size_bits, q->hash))
            m = thrt_find_string(d, v, len, q->hash);
    }
    if (priv) out->flags |= ENRICH_R_PRIVATE;

    if (m != NULL) {
        out->flags |= ENRICH_R_THRT;
        int skip = priv && (opt_flags & ENRICH_OPT_SKIP_PRIVATE);
        if (m->tags_length != 0) {
            out->tags = d->pool + m->tags_offset;
            out->tags_len = m->tags_length;
        }
        /* Labels belong to public CTI, which a skipped address drops. */
        if (m->labels_length != 0 && !skip) {
            out->labels = d->pool + m->labels_offset;
            out->labels_len = m->labels_length;
        }
        if (skip) {
            if (m->type_mask & (THRT_TYPE_CTI | THRT_TYPE_CTI_R)) out->flags |= ENRICH_R_PRIVATE_SKIP;
        } else {
            out->type_mask = m->type_mask;
            if (m->type_mask & THRT_TYPE_CTI) {
                out->flags |= ENRICH_R_MATCH;
                out->confidence = m->confidence;
                out->tlp_mask = m->tlp_mask;
                out->category_mask = m->category_mask;
                out->feed_mask = m->feed_mask & d->hdr->public_feed_mask;
            }
            if (m->type_mask & THRT_TYPE_CTI_R) {
                out->flags |= ENRICH_R_MATCH;
                out->confidence_r = m->confidence_r;
            }
        }
    }
    return has_report(out);
}

int enrich_lookup(const enrich_snap_t *s, uint32_t opt_flags, const char *value, size_t len, enrich_result_t *out) {
    query_t q;
    int rc;
    if (out == NULL) return ENRICH_EINVAL;
    rc = classify(value, len, &q);
    if (rc != ENRICH_OK) {
        memset(out, 0, sizeof *out);
        return rc;
    }
    return resolve(s, opt_flags, value, len, &q, out);
}

size_t enrich_lookup_batch(const enrich_snap_t *s, uint32_t opt_flags, const enrich_value_t *v, size_t n,
                           enrich_result_t *out, int *status) {
    query_t q[BATCH_CHUNK];
    int qrc[BATCH_CHUNK];
    size_t hits = 0;
    const thrt_db_t *d = s ? s->thrt : NULL;

    if (v == NULL || out == NULL) return 0;
    for (size_t base = 0; base < n; base += BATCH_CHUNK) {
        size_t m = n - base < BATCH_CHUNK ? n - base : BATCH_CHUNK;
        for (size_t i = 0; i < m; i++) {
            qrc[i] = classify(v[base + i].value, v[base + i].len, &q[i]);
            if (qrc[i] == ENRICH_OK && q[i].kind == ENRICH_KIND_STRING && d && d->bloom) {
                uint32_t bit = (uint32_t)q[i].hash % d->hdr->bloom_size_bits;
                PREFETCH(&d->bloom[bit >> 3]);
            }
        }
        for (size_t i = 0; i < m; i++) {
            int rc = qrc[i];
            if (rc == ENRICH_OK)
                rc = resolve(s, opt_flags, v[base + i].value, v[base + i].len, &q[i], &out[base + i]);
            else
                memset(&out[base + i], 0, sizeof out[base + i]);
            if (status) status[base + i] = rc;
            if (rc == 1) hits++;
        }
    }
    return hits;
}

void enrich_event_fold(enrich_event_t *ev, const enrich_result_t *r) {
    uint8_t c;
    if (ev == NULL || r == NULL) return;
    c = ev->confidence;
    if (r->flags & ENRICH_R_MATCH) ev->match = 1;
    if (r->flags & ENRICH_R_WHITELISTED) ev->whitelisted = 1;
    ev->type_mask |= r->type_mask | r->ovl_type_mask;
    if (r->type_mask & THRT_TYPE_CTI) {
        if (r->confidence > c) c = r->confidence;
        ev->tlp_mask |= r->tlp_mask;
        ev->category_mask |= r->category_mask;
        ev->feed_mask |= r->feed_mask;
    }
    if ((r->type_mask & THRT_TYPE_CTI_R) && r->confidence_r > c) c = r->confidence_r;
    if (r->ovl_confidence > c) c = r->ovl_confidence;
    ev->category_mask |= r->ovl_category_mask;
    ev->confidence = c;
}

int enrich_prevalence(const enrich_snap_t *s, const char *value, size_t len, enrich_prev_t *out) {
    int rc;
    if (out == NULL) return ENRICH_EINVAL;
    memset(out, 0, sizeof *out);
    rc = value_check(value, len);
    if (rc != ENRICH_OK) return rc;
    if (s == NULL || s->prev == NULL || s->prev->hdr->count_max == 0) return 0;
    out->count = prev_lookup_n(s->prev->hdr, s->prev->table, s->prev->slots, value, len, &out->edges, &out->sources);
    return 1;
}

uint32_t enrich_prev_reporting_edges(const enrich_snap_t *s) {
    return (s && s->prev && s->prev->hdr->count_max > 0) ? s->prev->hdr->reporting_edges : 0;
}

/* ------------------------------------------------------------------------
 * Names and facts.
 * ------------------------------------------------------------------------ */

const char *enrich_feed_name(const enrich_snap_t *s, unsigned idx) {
    if (s == NULL || s->thrt == NULL || idx >= s->thrt->hdr->feed_count) return NULL;
    return s->thrt->feeds[idx].name;
}

const char *enrich_category_name(uint16_t one_bit) {
    switch (one_bit) {
        case THRT_CAT_ATTACK:
            return "attack";
        case THRT_CAT_MALWARE:
            return "malware";
        case THRT_CAT_PHISHING:
            return "phishing";
        case THRT_CAT_BOTNET:
            return "botnet";
        case THRT_CAT_C2:
            return "c2";
        case THRT_CAT_EXPLOIT:
            return "exploit";
        case THRT_CAT_RANSOMWARE:
            return "ransomware";
        case THRT_CAT_SPAM:
            return "spam";
        case THRT_CAT_SCANNER:
            return "scanner";
        case THRT_CAT_TOR_EXIT:
            return "tor_exit";
        case THRT_CAT_PROXY:
            return "proxy";
        default:
            return NULL;
    }
}

const char *enrich_tlp_name(uint8_t one_bit) {
    switch (one_bit) {
        case THRT_TLP_CLEAR:
            return "clear";
        case THRT_TLP_GREEN:
            return "green";
        case THRT_TLP_AMBER:
            return "amber";
        case THRT_TLP_RED:
            return "red";
        default:
            return NULL;
    }
}

const char *enrich_tlp_strictest(uint8_t tlp_mask) {
    if (tlp_mask & THRT_TLP_RED) return "red";
    if (tlp_mask & THRT_TLP_AMBER) return "amber";
    if (tlp_mask & THRT_TLP_GREEN) return "green";
    if (tlp_mask & THRT_TLP_CLEAR) return "clear";
    return NULL;
}

void enrich_snap_info(const enrich_snap_t *s, enrich_info_t *out) {
    if (out == NULL) return;
    memset(out, 0, sizeof *out);
    if (s == NULL) return;
    out->generation = s->generation;
    if (s->thrt) {
        const thrt_header_t *h = s->thrt->hdr;
        out->components |= ENRICH_C_THRT;
        out->thrt_version = h->version;
        out->thrt_metadata = h->metadata_count;
        out->thrt_ipv4_ranges = h->ipv4_range_count;
        out->thrt_ipv6_ranges = h->ipv6_range_count;
        out->thrt_hash_slots = h->hash_slots;
        out->thrt_feeds = h->feed_count;
        out->thrt_checksum = h->checksum;
        out->thrt_mtime = s->thrt->id.mtime_s;
    }
    if (s->ovl) {
        out->components |= ENRICH_C_OVERLAY;
        out->overlay_entries = s->ovl->o->header->entry_count;
        out->overlay_tenant = s->ovl->o->header->tenant_id;
        out->overlay_built = s->ovl->o->header->timestamp;
        out->overlay_mtime = s->ovl->id.mtime_s;
    }
    if (s->prev) {
        out->components |= ENRICH_C_PREV;
        out->prev_entries = s->prev->hdr->entry_count;
        out->prev_epoch = s->prev->hdr->epoch;
        out->prev_count_max = s->prev->hdr->count_max;
        out->prev_reporting_edges = s->prev->hdr->reporting_edges;
        out->prev_mtime = s->prev->id.mtime_s;
    }
}
