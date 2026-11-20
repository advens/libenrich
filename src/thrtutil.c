/* thrtutil.c
 * Standalone tool that builds the CTI database (.thrt). Imports:
 *   - CSV (.csv)
 *   - CTI dictionary JSON (.json), multi-feed, with mmap for 1+ GB files
 *   - rsyslog JSON lookup tables (.lookup)
 *   - MISP JSON exports (.misp, .misp.json)
 *   - STIX 2.1 bundles (.stix, .stix.json)
 *   - plain-text IOC lists (.txt, .ioc)
 *   - tag files (.tags, .tags.json)
 *
 * Incremental updates: --apply-delta <seg> folds one CTI delta segment into the
 * live .thrt then exits (dedup by (type, value), per-feed snapshot replace,
 * feed-level TTL and generation anti-resurrection via a .gen companion file).
 * The rewrite is atomic. Consumers reload it when the mtime changes.
 *
 * Layers (-l cti|cti_r|tags, default cti): control how much of a match is
 * revealed. cti = public intel, fully attributed (feed/category/TLP emitted).
 * cti_r = restricted intel: a match raises the threat flag but feed/category/TLP
 * are withheld from the message. tags = asset/CMDB/carto context, no threat flag.
 * Supports per-feed bitmasks (up to 64 feeds), pre-computed TLP masks and tags
 * stored as a JSON array in the string pool.
 *
 * Compile: cc -O3 thrtutil.c -o thrtutil
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>
#include <dirent.h>
#include <signal.h>
#include <libgen.h>

#include "thrt_format.h"
#include "thrt_ipparse.h"
#include "thrt_logic.h"
#include "thrt_validate.h"

// Constants
#define MAX_LINE_LEN 65536
#define INITIAL_CAPACITY 65536
#define BLOOM_BITS_DEFAULT (64 * 1024 * 1024)
#define MAX_FEEDS 64
#define MAX_TAGS_JSON 4096

/* ============================================================================
 * LAYER TYPES (V4)
 * ============================================================================ */
typedef enum {
    LAYER_CTI   = 0,    /* Public CTI feeds */
    LAYER_CTI_R = 1,    /* Restricted CTI feeds */
    LAYER_TAGS  = 2     /* Tags/CMDB/Carto */
} layer_type_t;

/* Current layer being processed */
static layer_type_t g_current_layer = LAYER_CTI;

/* Feeds that contributed to the public CTI layer. Written to the header
 * (public_feed_mask) so readers print only these feed names. */
static uint64_t g_public_feeds = 0;

/* --- Colors & Icons --- */
#define COL_RESET   "\033[0m"
#define COL_BOLD    "\033[1m"
#define COL_GREEN   "\033[1;32m"
#define COL_CYAN    "\033[0;36m"
#define COL_YELLOW  "\033[1;33m"
#define COL_RED     "\033[1;31m"
#define ICON_DB     "[DB]"
#define ICON_STAT   "[STAT]"
#define ICON_CHECK  "[OK]"
#define ICON_INFO   "[INFO] "
#define ICON_WARN   "[WARN] "
#define ICON_GEAR   "[CFG] "

/* ============================================================================
 * V4 BUILDER METADATA STRUCTURE
 * Matches the new thrt_metadata_t layout
 * ============================================================================ */
typedef struct {
    uint8_t  confidence;      /* public CTI only */
    uint8_t  confidence_r;    /* restricted CTI only */
    uint8_t  type_mask;       /* THRT_TYPE_CTI | THRT_TYPE_CTI_R | THRT_TYPE_TAGS */
    uint8_t  tlp_mask;        /* THRT_TLP_* flags */
    uint16_t category_mask;   /* THRT_CAT_* flags */
    uint64_t feed_mask;       /* Every contributing feed, any layer. Eviction
                               * needs the full provenance. The writer records
                               * which feeds are public in the header. */
    uint32_t tags_offset;     /* Context tags (tags layer), string pool */
    uint32_t tags_length;
    uint32_t labels_offset;   /* Public CTI labels, string pool */
    uint32_t labels_length;
} builder_meta_v4_t;

typedef struct {
    uint32_t start; uint32_t end; uint32_t meta_idx;
} builder_ip_t;

typedef struct {
    uint8_t start[16]; uint8_t end[16]; uint32_t meta_idx;
} builder_ipv6_t;

typedef struct {
    uint64_t hash; uint32_t offset; uint32_t meta_idx;
} builder_string_t;

/* --- Feed Dictionary (up to 64 feeds) --- */
typedef struct {
    char name[THRT_FEED_NAME_MAX];
    uint8_t feed_idx;     /* 0-63 for bitmask position */
} feed_entry_t;

/* --- Deletion Tracking (Hash Set) ---
 * A withdrawn indicator is matched by identity, never by hash alone: an
 * address or network by its exact range, anything else by its exact string.
 * A 32-bit hash match would also delete every other indicator that shares
 * the hash. */
#define DELETE_SET_BUCKETS 65536
#define DEL_KIND_IPV4 0
#define DEL_KIND_IPV6 1
#define DEL_KIND_STR 2
typedef struct delete_entry {
    uint64_t key;
    uint8_t kind;
    uint32_t v4_start, v4_end;
    uint8_t v6_start[16], v6_end[16];
    char *str;
    struct delete_entry *next;
} delete_entry_t;

typedef struct {
    delete_entry_t *buckets[DELETE_SET_BUCKETS];
    size_t count;
} delete_set_t;

static delete_set_t *g_delete_set = NULL;

/* Checked allocation wrappers. thrtutil is an offline build tool, so an
 * allocation failure means it cannot produce a correct .thrt: fail loudly
 * instead of dereferencing NULL or writing a truncated database. */
__attribute__((malloc, returns_nonnull, alloc_size(1))) static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) {
        fprintf(stderr, "thrtutil: out of memory (malloc %zu)\n", n);
        exit(1);
    }
    return p;
}
__attribute__((malloc, returns_nonnull, alloc_size(1, 2))) static void *xcalloc(size_t nmemb, size_t sz) {
    void *p = calloc(nmemb, sz);
    if (!p) {
        fprintf(stderr, "thrtutil: out of memory (calloc %zux%zu)\n", nmemb, sz);
        exit(1);
    }
    return p;
}
__attribute__((returns_nonnull, alloc_size(2))) static void *xrealloc(void *ptr, size_t n) {
    void *p = realloc(ptr, n);
    if (!p) {
        fprintf(stderr, "thrtutil: out of memory (realloc %zu)\n", n);
        exit(1);
    }
    return p;
}

static void delete_set_init(void) {
    if (g_delete_set) return;
    g_delete_set = xcalloc(1, sizeof(delete_set_t));
}

static uint64_t ioc_key_ipv4(uint32_t s, uint32_t e);
static uint64_t ioc_key_ipv6(const uint8_t *s, const uint8_t *e);
static uint64_t ioc_key_str(uint64_t strhash);

static int delete_entry_eq(const delete_entry_t *a, const delete_entry_t *b) {
    if (a->key != b->key || a->kind != b->kind) return 0;
    if (a->kind == DEL_KIND_IPV4) return a->v4_start == b->v4_start && a->v4_end == b->v4_end;
    if (a->kind == DEL_KIND_IPV6)
        return memcmp(a->v6_start, b->v6_start, 16) == 0 && memcmp(a->v6_end, b->v6_end, 16) == 0;
    return strcmp(a->str, b->str) == 0;
}

/* Describe a value the way add_ioc() stores it. str is borrowed. */
static void delete_probe_of(const char *value, int is_ip_type, delete_entry_t *d) {
    parsed_ip_t ip;
    memset(d, 0, sizeof *d);
    if (parse_ip_or_cidr(value, is_ip_type, &ip)) {
        if (ip.family == 4) {
            d->kind = DEL_KIND_IPV4;
            d->v4_start = ip.v4_start;
            d->v4_end = ip.v4_end;
            d->key = ioc_key_ipv4(ip.v4_start, ip.v4_end);
        } else {
            d->kind = DEL_KIND_IPV6;
            memcpy(d->v6_start, ip.v6_start, 16);
            memcpy(d->v6_end, ip.v6_end, 16);
            d->key = ioc_key_ipv6(ip.v6_start, ip.v6_end);
        }
        return;
    }
    d->kind = DEL_KIND_STR;
    d->str = (char *)value;
    d->key = ioc_key_str(thrt_hash(value));
}

static int delete_set_has(const delete_entry_t *probe) {
    if (!g_delete_set) return 0;
    for (delete_entry_t *e = g_delete_set->buckets[probe->key % DELETE_SET_BUCKETS]; e; e = e->next)
        if (delete_entry_eq(e, probe)) return 1;
    return 0;
}

static void delete_set_add(const char *value, int is_ip_type) {
    delete_entry_t probe;
    delete_entry_t *entry;
    uint32_t bucket;
    if (!g_delete_set) delete_set_init();
    delete_probe_of(value, is_ip_type, &probe);
    if (delete_set_has(&probe)) return;
    entry = xmalloc(sizeof(delete_entry_t));
    *entry = probe;
    if (probe.kind == DEL_KIND_STR) {
        entry->str = strdup(value);
        if (entry->str == NULL) {
            fprintf(stderr, "thrtutil: out of memory (delete set)\n");
            exit(1);
        }
    }
    bucket = (uint32_t)(probe.key % DELETE_SET_BUCKETS);
    entry->next = g_delete_set->buckets[bucket];
    g_delete_set->buckets[bucket] = entry;
    g_delete_set->count++;
}

static void delete_set_free(void) {
    if (!g_delete_set) return;
    for (int i = 0; i < DELETE_SET_BUCKETS; i++) {
        delete_entry_t *e = g_delete_set->buckets[i];
        while (e) {
            delete_entry_t *next = e->next;
            free(e->str);
            free(e);
            e = next;
        }
    }
    free(g_delete_set);
    g_delete_set = NULL;
}

/* --- Global State --- */
static struct { builder_meta_v4_t *items; size_t count; size_t cap; } meta_db = {0};
static struct { builder_ip_t *items; size_t count; size_t cap; } ip_db = {0};
static struct { builder_ipv6_t *items; size_t count; size_t cap; } ip6_db = {0};
static struct { builder_string_t *items; size_t count; size_t cap; } str_db = {0};
static struct { char *data; size_t len; size_t cap; } str_pool = {0};
static struct { feed_entry_t *items; size_t count; size_t cap; } feed_db = {0};

/* Default source name (set per-file) */
static char g_default_source[64] = "Unknown";

/* enrich sync sets this around one incremental MISP fold. A full build
 * leaves it off: to_ids false is skipped and deleted is not read.
 * When it is on, deleted or to_ids false emits a '-' row. */
static int g_misp_delta = 0;

void thrt_misp_delta_mode(int on);
void thrt_misp_delta_mode(int on)
{
    g_misp_delta = on ? 1 : 0;
}

// Stats
static struct {
    size_t ipv4_count; size_t ipv6_count; size_t domain_count;
    size_t email_count; size_t hash_count; size_t skipped_count;
    size_t deleted_count; size_t added_count; size_t tags_count;
    size_t rejected_cidr_count;
} stats = {0};

static thrt_ip_accel_t ip_accel_db[THRT_IP_ACCEL_SLOTS];
static uint8_t *bloom_filter = NULL;
static uint32_t bloom_size_bits = BLOOM_BITS_DEFAULT;
static int g_verbose = 0;
static int g_incremental = 0;

/* --- Helpers --- */
static char* trim(char* str) {
    char* end;
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return str;
    end = str + strlen(str) - 1;
    while(end > str && (isspace((unsigned char)*end) || *end == '"' || *end == '\'')) end--;
    *(end+1) = 0;
    if(*str == '"' || *str == '\'') str++;
    return str;
}

/* --- Memory Management --- */
static void ensure_capacity(void) {
    if (meta_db.count >= meta_db.cap) {
        meta_db.cap = (meta_db.cap==0)?1024:meta_db.cap*2;
        meta_db.items = xrealloc(meta_db.items, meta_db.cap*sizeof(builder_meta_v4_t));
    }
    if (ip_db.count >= ip_db.cap) {
        ip_db.cap = (ip_db.cap==0)?INITIAL_CAPACITY:ip_db.cap*2;
        ip_db.items = xrealloc(ip_db.items, ip_db.cap*sizeof(builder_ip_t));
    }
    if (ip6_db.count >= ip6_db.cap) {
        ip6_db.cap = (ip6_db.cap==0)?INITIAL_CAPACITY:ip6_db.cap*2;
        ip6_db.items = xrealloc(ip6_db.items, ip6_db.cap*sizeof(builder_ipv6_t));
    }
    if (str_db.count >= str_db.cap) {
        str_db.cap = (str_db.cap==0)?INITIAL_CAPACITY:str_db.cap*2;
        str_db.items = xrealloc(str_db.items, str_db.cap*sizeof(builder_string_t));
    }
    if (str_pool.len + MAX_TAGS_JSON >= str_pool.cap) {
        str_pool.cap = (str_pool.cap==0)?4*1024*1024:str_pool.cap*2;
        str_pool.data = xrealloc(str_pool.data, str_pool.cap);
    }
    if (feed_db.count >= feed_db.cap) {
        feed_db.cap = (feed_db.cap==0)?64:feed_db.cap*2;
        feed_db.items = xrealloc(feed_db.items, feed_db.cap*sizeof(feed_entry_t));
    }
    if (!meta_db.items || !ip_db.items || !ip6_db.items || !str_db.items || !str_pool.data) {
        fprintf(stderr, "FATAL: Out of Memory\n"); exit(1);
    }
}

/* tags_offset 0 means "no tags" on read. A full build used to store the
 * first tag list at offset 0, so that list disappeared. Keep a NUL there,
 * matching compact_str_pool on the delta path. */
static void str_pool_reserve_sentinel(void) {
    if (str_pool.len > 0) return;
    ensure_capacity();
    str_pool.data[0] = '\0';
    str_pool.len = 1;
}

/* --- Helper: Get/Create Feed Index (returns bitmask position 0-63) --- */
static uint8_t get_feed_idx(const char* name) {
    uint8_t idx;
    if (!name || strlen(name) == 0) name = "Unknown";

    /* Search existing */
    for (size_t i = 0; i < feed_db.count; i++) {
        if (strcasecmp(feed_db.items[i].name, name) == 0)
            return feed_db.items[i].feed_idx;
    }

    /* Add new (max 64) */
    if (feed_db.count >= MAX_FEEDS) {
        fprintf(stderr, "%s Too many feeds (max %d), '%s' mapped to 'overflow'\n",
                ICON_WARN, MAX_FEEDS, name);
        return 63; /* Overflow bucket */
    }

    ensure_capacity();
    idx = (uint8_t)feed_db.count;
    snprintf(feed_db.items[feed_db.count].name, THRT_FEED_NAME_MAX, "%s", name);
    feed_db.items[feed_db.count].feed_idx = idx;
    feed_db.count++;

    return idx;
}

/* --- Helper: Parse TLP to bitmask --- */
static uint8_t parse_tlp_mask(const char* s) {
    if (!s) return THRT_TLP_CLEAR;
    if (strcasestr(s, "red")) return THRT_TLP_RED;
    if (strcasestr(s, "amber")) return THRT_TLP_AMBER;
    if (strcasestr(s, "green")) return THRT_TLP_GREEN;
    return THRT_TLP_CLEAR;
}

/* --- Helper: Parse Category to bitmask --- */
/* A feed's confidence, clamped to 0..100. Like atoi, leading space is
 * skipped and trailing text ignored, but an out-of-range number is clamped
 * instead of undefined, and nothing wraps: 300 is 100, not 300 mod 256. */
static uint8_t parse_confidence(const char* s) {
    char* end;
    long v;
    if (!s) return 0;
    errno = 0;
    v = strtol(s, &end, 10);
    if (end == s) return 0;
    if (v < 0) return 0;
    if (v > 100 || errno == ERANGE) return 100;
    return (uint8_t)v;
}

static uint16_t parse_category_mask(const char* s) {
    uint16_t mask;
    if (!s) return THRT_CAT_UNKNOWN;
    if (isdigit((unsigned char)s[0])) {
        char* end;
        long cat;
        errno = 0;
        cat = strtol(s, &end, 10);
        if (errno == 0 && cat > 0 && cat <= 16) return (uint16_t)(1u << (cat - 1));
        return THRT_CAT_UNKNOWN;
    }

    mask = 0;

    if (strcasestr(s, "malicious-activity") || strcasestr(s, "attack"))
        mask |= THRT_CAT_ATTACK;
    if (strcasestr(s, "command-and-control") || strcasestr(s, "c2"))
        mask |= THRT_CAT_C2;
    if (strcasestr(s, "ransomware"))
        mask |= THRT_CAT_RANSOMWARE;
    if (strcasestr(s, "exploit"))
        mask |= THRT_CAT_EXPLOIT;
    if (strcasestr(s, "malware") || strcasestr(s, "payload"))
        mask |= THRT_CAT_MALWARE;
    if (strcasestr(s, "phish") || strcasestr(s, "social"))
        mask |= THRT_CAT_PHISHING;
    if (strcasestr(s, "botnet"))
        mask |= THRT_CAT_BOTNET;
    if (strcasestr(s, "spam"))
        mask |= THRT_CAT_SPAM;
    if (strcasestr(s, "scan") || strcasestr(s, "recon"))
        mask |= THRT_CAT_SCANNER;
    if (strcasestr(s, "tor") || strcasestr(s, "exit"))
        mask |= THRT_CAT_TOR_EXIT;
    if (strcasestr(s, "proxy") || strcasestr(s, "anonym"))
        mask |= THRT_CAT_PROXY;

    return mask ? mask : THRT_CAT_UNKNOWN;
}

/* --- Helper: Type mask from current layer --- */
static uint8_t layer_to_type_mask(layer_type_t layer) {
    switch (layer) {
        case LAYER_CTI:   return THRT_TYPE_CTI;
        case LAYER_CTI_R: return THRT_TYPE_CTI_R;
        case LAYER_TAGS:  return THRT_TYPE_TAGS;
        default:          return THRT_TYPE_CTI;
    }
}

/* ============================================================================
 * NORMALIZED IOC RECORD (V4)
 * ============================================================================ */
typedef struct {
    char value[512];
    char type[32];
    uint8_t confidence;
    uint16_t category_mask;
    char feed[64];
    uint8_t tlp_mask;
    char tags_json[MAX_TAGS_JSON];  /* JSON array: ["tag1","tag2",...] */
    char action;
} normalized_ioc_v4_t;

/* Forward declarations */
static uint32_t add_meta_v4(uint8_t confidence, uint8_t type_mask, uint8_t tlp_mask,
                            uint16_t category_mask, uint64_t feed_mask,
                            const char *tags_json);
static uint32_t add_meta_raw(uint8_t confidence, uint8_t confidence_r, uint8_t type_mask,
                             uint8_t tlp_mask, uint16_t category_mask, uint64_t feed_mask,
                             const char *tags_json, const char *labels_json);
static void add_ioc(const char* value, const char* type, uint32_t meta_idx);

/* ============================================================================
 * ADD METADATA (V4)
 * Deduplicates based on all fields
 * ============================================================================ */
/* Hash table for metadata dedup - avoids O(n) linear scan */
#define META_DEDUP_BUCKETS 65536
typedef struct meta_dedup_entry {
    uint64_t key;                   /* hash of all metadata fields */
    uint32_t meta_idx;
    struct meta_dedup_entry *next;
} meta_dedup_entry_t;
static meta_dedup_entry_t *meta_dedup_ht[META_DEDUP_BUCKETS] = {0};

/* Canonical metadata dedup key (FNV-1a over all fields + tags content). Shared
 * by add_meta_v4 and rebuild_meta_dedup so the two can never diverge. */
static uint64_t meta_make_key(uint8_t confidence, uint8_t confidence_r, uint8_t type_mask,
                              uint8_t tlp_mask, uint16_t category_mask,
                              uint64_t feed_mask, const char *tags_json,
                              const char *labels_json) {
    uint64_t k = 0xcbf29ce484222325ULL;
    k ^= confidence;    k *= 0x100000001b3ULL;
    k ^= confidence_r;  k *= 0x100000001b3ULL;
    k ^= type_mask;     k *= 0x100000001b3ULL;
    k ^= tlp_mask;      k *= 0x100000001b3ULL;
    k ^= category_mask; k *= 0x100000001b3ULL;
    k ^= feed_mask;     k *= 0x100000001b3ULL;
    if (tags_json && tags_json[0] != '\0') {
        for (const char *t = tags_json; *t; t++) {
            k ^= (unsigned char)*t;
            k *= 0x100000001b3ULL;
        }
    }
    k ^= 0x1f; k *= 0x100000001b3ULL;   /* separates tags from labels */
    if (labels_json && labels_json[0] != '\0') {
        for (const char *t = labels_json; *t; t++) {
            k ^= (unsigned char)*t;
            k *= 0x100000001b3ULL;
        }
    }
    return k;
}

/* One layer's contribution. The public fields (confidence, TLP, categories)
 * carry public CTI only: a restricted contribution keeps its score in
 * confidence_r and drops its labels, a public CTI contribution keeps its
 * labels apart from context tags, and a tags contribution keeps only its
 * tags. merge_meta()
 * then ORs layers without mixing a restricted value into a public field. */
static uint32_t add_meta_v4(uint8_t confidence, uint8_t type_mask, uint8_t tlp_mask,
                            uint16_t category_mask, uint64_t feed_mask,
                            const char *tags_json) {
    if (type_mask == THRT_TYPE_CTI) {
        g_public_feeds |= feed_mask;
        return add_meta_raw(confidence, 0, type_mask, tlp_mask, category_mask, feed_mask, NULL, tags_json);
    }
    if (type_mask == THRT_TYPE_CTI_R)
        return add_meta_raw(0, confidence, type_mask, 0, 0, feed_mask, NULL, NULL);
    return add_meta_raw(0, 0, type_mask, 0, 0, feed_mask, tags_json, NULL);
}

/* A JSON blob in the pool equals text. */
static int pool_blob_eq(uint32_t off, uint32_t len, const char *text, size_t tlen) {
    if (len != tlen) return 0;
    return len == 0 || memcmp(str_pool.data + off, text, len) == 0;
}

/* Copy a JSON blob into the pool. 0/0 for none. */
static void pool_blob_put(const char *text, uint32_t *off, uint32_t *len) {
    size_t n = text ? strlen(text) : 0;
    *off = 0;
    *len = 0;
    if (n == 0) return;
    ensure_capacity();
    *off = (uint32_t)str_pool.len;
    memcpy(str_pool.data + str_pool.len, text, n + 1);
    str_pool.len += n + 1;
    *len = (uint32_t)n;
}

static uint32_t add_meta_raw(uint8_t confidence, uint8_t confidence_r, uint8_t type_mask,
                             uint8_t tlp_mask, uint16_t category_mask, uint64_t feed_mask,
                             const char *tags_json, const char *labels_json) {
    size_t tlen = tags_json ? strlen(tags_json) : 0;
    size_t llen = labels_json ? strlen(labels_json) : 0;
    uint64_t dedup_key;
    uint32_t bucket;
    uint32_t idx;
    builder_meta_v4_t m = {0};
    meta_dedup_entry_t *entry;

    /* An identical record already exists: reuse it, and store nothing. */
    dedup_key = meta_make_key(confidence, confidence_r, type_mask, tlp_mask,
                              category_mask, feed_mask, tags_json, labels_json);
    bucket = (uint32_t)(dedup_key % META_DEDUP_BUCKETS);
    for (meta_dedup_entry_t *e = meta_dedup_ht[bucket]; e; e = e->next) {
        const builder_meta_v4_t *c;
        if (e->key != dedup_key) continue;
        c = &meta_db.items[e->meta_idx];
        if (c->confidence == confidence && c->confidence_r == confidence_r &&
            c->type_mask == type_mask && c->tlp_mask == tlp_mask &&
            c->category_mask == category_mask && c->feed_mask == feed_mask &&
            pool_blob_eq(c->tags_offset, c->tags_length, tags_json, tlen) &&
            pool_blob_eq(c->labels_offset, c->labels_length, labels_json, llen))
            return e->meta_idx;
    }

    m.confidence = confidence;
    m.confidence_r = confidence_r;
    m.type_mask = type_mask;
    m.tlp_mask = tlp_mask;
    m.category_mask = category_mask;
    m.feed_mask = feed_mask;
    pool_blob_put(tags_json, &m.tags_offset, &m.tags_length);
    pool_blob_put(labels_json, &m.labels_offset, &m.labels_length);
    ensure_capacity();
    idx = meta_db.count;
    meta_db.items[idx] = m;
    meta_db.count++;

    entry = xmalloc(sizeof(meta_dedup_entry_t));
    entry->key = dedup_key;
    entry->meta_idx = idx;
    entry->next = meta_dedup_ht[bucket];
    meta_dedup_ht[bucket] = entry;
    return idx;
}

/* ============================================================================
 * (type,value) IOC DEDUP + feed snapshot-replace support
 *
 * Active in full builds and in --apply-delta folds. The fold path seeds this
 * set from the just-loaded DB. A re-delivered IOC, or the same IOC from
 * another feed or layer, is NOT appended: its metadata merges into the
 * existing row, so a lookup sees every layer. Identity is the exact range or
 * the exact string; the key only picks the bucket.
 * ============================================================================ */
#define IOC_DEDUP_BUCKETS 65536
#define IOC_KIND_IPV4 0
#define IOC_KIND_IPV6 1
#define IOC_KIND_STR  2

typedef struct ioc_dedup_entry {
    uint64_t key;
    uint8_t  kind;            /* IOC_KIND_* */
    uint32_t index;           /* index into ip_db / ip6_db / str_db */
    struct ioc_dedup_entry *next;
} ioc_dedup_entry_t;
static ioc_dedup_entry_t *g_ioc_dedup_ht[IOC_DEDUP_BUCKETS];
static int g_ioc_dedup_active = 0;

static uint64_t ioc_key_ipv4(uint32_t s, uint32_t e) {
    uint64_t k = 0xcbf29ce484222325ULL;
    k ^= 0x41; k *= 0x100000001b3ULL;   /* 'A' type tag */
    k ^= s;    k *= 0x100000001b3ULL;
    k ^= e;    k *= 0x100000001b3ULL;
    return k;
}
static uint64_t ioc_key_ipv6(const uint8_t *s, const uint8_t *e) {
    uint64_t k = 0xcbf29ce484222325ULL;
    k ^= 0x61; k *= 0x100000001b3ULL;   /* 'a' type tag */
    for (int i = 0; i < 16; i++) { k ^= s[i]; k *= 0x100000001b3ULL; }
    for (int i = 0; i < 16; i++) { k ^= e[i]; k *= 0x100000001b3ULL; }
    return k;
}
static uint64_t ioc_key_str(uint64_t strhash) {
    uint64_t k = 0xcbf29ce484222325ULL;
    k ^= 0x53;      k *= 0x100000001b3ULL;   /* 'S' type tag */
    k ^= strhash;   k *= 0x100000001b3ULL;
    return k;
}

/* The row an entry points at holds this exact indicator. The key is a
 * hash, so a match on it alone is not identity. */
static int ioc_dedup_same(const ioc_dedup_entry_t *e, const delete_entry_t *id) {
    if (e->kind == IOC_KIND_IPV4)
        return id->kind == DEL_KIND_IPV4 && e->index < ip_db.count && ip_db.items[e->index].start == id->v4_start &&
               ip_db.items[e->index].end == id->v4_end;
    if (e->kind == IOC_KIND_IPV6)
        return id->kind == DEL_KIND_IPV6 && e->index < ip6_db.count &&
               memcmp(ip6_db.items[e->index].start, id->v6_start, 16) == 0 &&
               memcmp(ip6_db.items[e->index].end, id->v6_end, 16) == 0;
    return id->kind == DEL_KIND_STR && e->index < str_db.count &&
           strcmp(str_pool.data + str_db.items[e->index].offset, id->str) == 0;
}

static ioc_dedup_entry_t *ioc_dedup_find(uint64_t key, const delete_entry_t *id) {
    uint32_t b = (uint32_t)(key % IOC_DEDUP_BUCKETS);
    for (ioc_dedup_entry_t *e = g_ioc_dedup_ht[b]; e; e = e->next)
        if (e->key == key && ioc_dedup_same(e, id)) return e;
    return NULL;
}
static void ioc_dedup_insert(uint64_t key, uint8_t kind, uint32_t index) {
    uint32_t b = (uint32_t)(key % IOC_DEDUP_BUCKETS);
    ioc_dedup_entry_t *e = malloc(sizeof(*e));
    if (!e) { fprintf(stderr, "FATAL: Out of Memory (ioc dedup)\n"); exit(1); }
    e->key = key; e->kind = kind; e->index = index;
    e->next = g_ioc_dedup_ht[b]; g_ioc_dedup_ht[b] = e;
}
static void ioc_dedup_reset(void) {
    for (int i = 0; i < IOC_DEDUP_BUCKETS; i++) {
        ioc_dedup_entry_t *e = g_ioc_dedup_ht[i];
        while (e) { ioc_dedup_entry_t *n = e->next; free(e); e = n; }
        g_ioc_dedup_ht[i] = NULL;
    }
}
/* Pointer to the meta_idx field of an already-recorded IOC row (stable across
 * meta_db/str_pool reallocs because it points into the ip/ip6/str arrays). */
static uint32_t *ioc_meta_slot(uint8_t kind, uint32_t index) {
    if (kind == IOC_KIND_IPV4 && index < ip_db.count)  return &ip_db.items[index].meta_idx;
    if (kind == IOC_KIND_IPV6 && index < ip6_db.count) return &ip6_db.items[index].meta_idx;
    if (kind == IOC_KIND_STR  && index < str_db.count) return &str_db.items[index].meta_idx;
    return NULL;
}

/* Tags are stored as a JSON array of strings. Scan one array into raw
 * string tokens (quotes included). Returns the count, or -1 when the text
 * is not such an array or holds more than max items. */
static int tags_tokens(const char *s, const char **tok, size_t *tlen, int max) {
    int n = 0;
    while (*s == ' ') s++;
    if (*s++ != '[') return -1;
    for (;;) {
        const char *start;
        while (*s == ' ') s++;
        if (*s == ']') return n;
        if (*s != '"' || n == max) return -1;
        start = s++;
        while (*s && *s != '"') s += (*s == '\\' && s[1]) ? 2 : 1;
        if (*s != '"') return -1;
        s++;
        tok[n] = start;
        tlen[n] = (size_t)(s - start);
        n++;
        while (*s == ' ') s++;
        if (*s == ',') {
            s++;
            continue;
        }
        if (*s == ']') return n;
        return -1;
    }
}

/* Union of two tag arrays into out: a's tags in order, then each tag of b
 * that a lacks. A tag that would not fit is left out. Falls back to a, or
 * b, when the other is not a tag array. */
static void tags_union(const char *a, const char *b, char *out, size_t cap) {
    enum { TAGS_MAX = 256 };
    const char *ta[TAGS_MAX], *tb[TAGS_MAX];
    size_t la[TAGS_MAX], lb[TAGS_MAX];
    int na = (a && *a) ? tags_tokens(a, ta, la, TAGS_MAX) : 0;
    int nb = (b && *b) ? tags_tokens(b, tb, lb, TAGS_MAX) : 0;
    size_t used;
    int any = 0;
    if (cap < 3) {
        if (cap) out[0] = '\0';
        return;
    }
    if (na < 0 || nb < 0) {
        snprintf(out, cap, "%s", (a && *a) ? a : (b ? b : ""));
        return;
    }
    out[0] = '[';
    used = 1;
    for (int pass = 0; pass < 2; pass++) {
        const char **t = pass ? tb : ta;
        size_t *l = pass ? lb : la;
        int n = pass ? nb : na;
        for (int i = 0; i < n; i++) {
            int dup = 0;
            for (int j = 0; j < na && pass && !dup; j++) dup = la[j] == l[i] && memcmp(ta[j], t[i], l[i]) == 0;
            for (int j = 0; j < i && !dup; j++) dup = l[j] == l[i] && memcmp(t[j], t[i], l[i]) == 0;
            if (dup || used + (any ? 1 : 0) + l[i] + 2 > cap) continue;
            if (any) out[used++] = ',';
            memcpy(out + used, t[i], l[i]);
            used += l[i];
            any = 1;
        }
    }
    out[used++] = ']';
    out[used] = '\0';
    if (!any) out[0] = '\0';
}

/* tags_union() of two pool blobs. */
static void blob_union(uint32_t ao, uint32_t al, uint32_t bo, uint32_t bl, char *out, size_t cap) {
    char ta[MAX_TAGS_JSON], tb[MAX_TAGS_JSON];
    ta[0] = tb[0] = '\0';
    if (al && al < MAX_TAGS_JSON) {
        memcpy(ta, str_pool.data + ao, al);
        ta[al] = '\0';
    }
    if (bl && bl < MAX_TAGS_JSON) {
        memcpy(tb, str_pool.data + bo, bl);
        tb[bl] = '\0';
    }
    tags_union(ta, tb, out, cap);
}

/* Union two metadata records -> a deduped meta_idx covering both feeds.
 * Scalar fields are copied to locals + tags to a stack buffer BEFORE calling
 * add_meta_v4 (which may realloc meta_db, invalidating a/b). */
static uint32_t merge_meta(uint32_t a_idx, uint32_t b_idx) {
    builder_meta_v4_t *a;
    builder_meta_v4_t *b;
    uint8_t  conf;
    uint8_t  conf_r;
    uint8_t  type;
    uint8_t  tlp;
    uint16_t cat;
    uint64_t feeds;
    char tagbuf[MAX_TAGS_JSON];
    char labbuf[MAX_TAGS_JSON];
    if (a_idx == b_idx) return a_idx;
    if (a_idx >= meta_db.count || b_idx >= meta_db.count) return a_idx;
    a = &meta_db.items[a_idx];
    b = &meta_db.items[b_idx];
    conf = a->confidence > b->confidence ? a->confidence : b->confidence;
    conf_r = a->confidence_r > b->confidence_r ? a->confidence_r : b->confidence_r;
    type = a->type_mask | b->type_mask;
    tlp = a->tlp_mask  | b->tlp_mask;
    cat = (uint16_t)(a->category_mask | b->category_mask);
    feeds = a->feed_mask | b->feed_mask;
    blob_union(a->tags_offset, a->tags_length, b->tags_offset, b->tags_length, tagbuf, sizeof tagbuf);
    blob_union(a->labels_offset, a->labels_length, b->labels_offset, b->labels_length, labbuf, sizeof labbuf);
    return add_meta_raw(conf, conf_r, type, tlp, cat, feeds, tagbuf, labbuf);
}

/* Returns 1 if the caller should append a NEW IOC row; 0 if the IOC was a
 * duplicate (feed metadata merged into the existing row, no new row). */
static int ioc_dedup_pre_add(uint64_t key, const delete_entry_t *id, uint32_t meta_idx) {
    ioc_dedup_entry_t *e;
    uint32_t *slot;
    if (!g_ioc_dedup_active) return 1;
    e = ioc_dedup_find(key, id);
    if (!e) return 1;
    slot = ioc_meta_slot(e->kind, e->index);
    if (slot) *slot = merge_meta(*slot, meta_idx);
    return 0;
}
static void ioc_dedup_commit(uint64_t key, uint8_t kind, uint32_t index) {
    if (g_ioc_dedup_active) ioc_dedup_insert(key, kind, index);
}

/* Non-creating feed lookup (get_feed_idx CREATES; this returns -1 if absent).
 * feed_idx is assigned == array position, so it doubles as the meta bitmask bit. */
static int find_feed_idx(const char *name) {
    if (!name || !*name) return -1;
    for (size_t i = 0; i < feed_db.count; i++)
        if (strcasecmp(feed_db.items[i].name, name) == 0)
            return (int)feed_db.items[i].feed_idx;
    return -1;
}

/* ============================================================================
 * ADD IOC (unified for all types)
 * ============================================================================ */
static void add_ioc(const char* value, const char* type, uint32_t meta_idx) {
    parsed_ip_t ip;

    /* Address indicators (bare IP or CIDR) become an [ip_start, ip_end] range;
     * the engine matches by range (thrt_lookup_ip), so a netblock IOC such as
     * Spamhaus DROP stays a single entry. The slash form is honoured only for a
     * declared address type (or an unclassified value), so a URL indicator can
     * never be read as a network. Anything the strict parser rejects falls
     * through to the string table, where a value like "1.2.3.4/admin.php" is
     * still matchable as the URL it actually is. */
    if (parse_ip_or_cidr(value, ioc_type_is_ip(type), &ip)) {
        uint64_t key;
        uint32_t idx;
        builder_ipv6_t *e;
        if (ip.family == 4) {
            delete_entry_t id = {0};
            id.kind = DEL_KIND_IPV4;
            id.v4_start = ip.v4_start;
            id.v4_end = ip.v4_end;
            key = ioc_key_ipv4(ip.v4_start, ip.v4_end);
            if (!ioc_dedup_pre_add(key, &id, meta_idx)) return;
            ensure_capacity();
            idx = (uint32_t)ip_db.count;
            ip_db.items[ip_db.count++] = (builder_ip_t){ ip.v4_start, ip.v4_end, meta_idx };
            ioc_dedup_commit(key, IOC_KIND_IPV4, idx);
            stats.ipv4_count++;
            return;
        }
        {
            delete_entry_t id = {0};
            id.kind = DEL_KIND_IPV6;
            memcpy(id.v6_start, ip.v6_start, 16);
            memcpy(id.v6_end, ip.v6_end, 16);
            key = ioc_key_ipv6(ip.v6_start, ip.v6_end);
            if (!ioc_dedup_pre_add(key, &id, meta_idx)) return;
        }
        ensure_capacity();
        idx = (uint32_t)ip6_db.count;
        e = &ip6_db.items[ip6_db.count];
        memcpy(e->start, ip.v6_start, 16);
        memcpy(e->end, ip.v6_end, 16);
        e->meta_idx = meta_idx;
        ip6_db.count++;
        ioc_dedup_commit(key, IOC_KIND_IPV6, idx);
        stats.ipv6_count++;
        return;
    }

    /* A slash-bearing value that did not parse as a network is a URL path or a
     * malformed prefix. Count it so a feed that starts shipping them shows up
     * in the build summary instead of silently reshaping the database. */
    if (strchr(value, '/') && ioc_type_is_ip(type)) {
        stats.rejected_cidr_count++;
        if (g_verbose)
            fprintf(stderr, "  [reject] not a network, indexed as string: %s\n", value);
    }

    {
        uint64_t h = thrt_hash(value);
        uint64_t key = ioc_key_str(h);
        size_t len;
        size_t offset;
        uint32_t idx;
        delete_entry_t id = {0};
        id.kind = DEL_KIND_STR;
        id.str = (char *)value;
        if (!ioc_dedup_pre_add(key, &id, meta_idx)) return;
        ensure_capacity();
        len = strlen(value);
        offset = str_pool.len;
        memcpy(str_pool.data + offset, value, len + 1);
        str_pool.len += len + 1;

        idx = (uint32_t)str_db.count;
        str_db.items[str_db.count++] = (builder_string_t){ h, (uint32_t)offset, meta_idx };
        ioc_dedup_commit(key, IOC_KIND_STR, idx);

        if (type && strcasestr(type, "hash")) stats.hash_count++;
        else if (strchr(value, '@')) stats.email_count++;
        else if (len >= 32 && strspn(value, "0123456789abcdefABCDEF") == len) stats.hash_count++;
        else stats.domain_count++;
    }
}

/* ============================================================================
 * EMIT NORMALIZED IOC (V4)
 * ============================================================================ */
static void emit_normalized_ioc_v4(normalized_ioc_v4_t *ioc) {
    uint8_t type_mask;
    uint8_t feed_idx;
    uint64_t feed_mask;
    uint8_t tlp;
    uint32_t meta_idx;
    if (!ioc || strlen(ioc->value) == 0) return;

    if (ioc->action == '-') {
        delete_set_add(ioc->value, ioc_type_is_ip(ioc->type));
        stats.deleted_count++;
        if (g_verbose) {
            printf("  [DELETE] %s\n", ioc->value);
        }
        return;
    }

    type_mask = layer_to_type_mask(g_current_layer);
    feed_idx = get_feed_idx(ioc->feed);
    feed_mask = (1ULL << feed_idx);

    /* For tags layer, TLP is not applicable */
    tlp = (g_current_layer == LAYER_TAGS) ? 0 : ioc->tlp_mask;

    meta_idx = add_meta_v4(
        ioc->confidence,
        type_mask,
        tlp,
        ioc->category_mask,
        feed_mask,
        ioc->tags_json
    );

    add_ioc(ioc->value, ioc->type, meta_idx);

    if (g_current_layer == LAYER_TAGS) stats.tags_count++;
    else stats.added_count++;
}

/* ============================================================================
 * JSON HELPERS
 * ============================================================================ */
static char* json_get_val(char* json, const char* key, char* out_buf, size_t max_len) {
    char search[64];
    char *p;
    snprintf(search, sizeof(search), "\"%s\"", key);
    p = strstr(json, search);
    if (!p) return NULL;
    p = strchr(p, ':'); if (!p) return NULL;
    p++; while(*p && isspace(*p)) p++;

    if (*p == '"') {
        char *end;
        size_t len;
        p++; end = strchr(p, '"'); if (!end) return NULL;
        len = end - p; if (len >= max_len) len = max_len - 1;
        strncpy(out_buf, p, len); out_buf[len] = 0;
        return out_buf;
    } else if (*p == '[') {
        p++; while(*p && isspace(*p)) p++;
        if (*p == '"') {
            char *end;
            size_t len;
            p++; end = strchr(p, '"'); if (!end) return NULL;
            len = end - p; if (len >= max_len) len = max_len - 1;
            strncpy(out_buf, p, len); out_buf[len] = 0;
            return out_buf;
        }
    } else {
        char *end = p;
        size_t len;
        while(isdigit(*end) || *end == '-') end++;
        len = end - p; if (len >= max_len) len = max_len - 1;
        strncpy(out_buf, p, len); out_buf[len] = 0;
        return out_buf;
    }
    return NULL;
}

static void unescape_json(char *str) {
    char *r = str, *w = str;
    while (*r) { if (*r == '\\' && *(r+1) == '"') r++; *w++ = *r++; }
    *w = 0;
}

/* ============================================================================
 * JSON CURSOR HELPERS (safe, bounded, single-pass)
 * All functions take (p, end) and never read past end.
 * ============================================================================ */

/* Skip whitespace - inline for hot path */
static inline const char *skip_ws(const char *p, const char *end) {
    while (p < end && (unsigned char)*p <= ' ') p++;
    return p;
}

/* Skip a JSON quoted string. p must point to opening '"'.
 * Returns pointer past closing '"', or end on unterminated string. */
static const char *skip_json_str(const char *p, const char *end) {
    if (p >= end || *p != '"') return p;
    p++; /* skip opening quote */
    while (p < end) {
        if (*p == '\\') { p += 2; continue; }
        if (*p == '"') return p + 1;
        p++;
    }
    return p; /* unterminated - fail safe at end */
}

/* Skip any JSON value (string, number, object, array, bool, null).
 * Returns pointer past the value. */
static const char *skip_json_val(const char *p, const char *end) {
    p = skip_ws(p, end);
    if (p >= end) return p;

    if (*p == '"') return skip_json_str(p, end);

    if (*p == '{' || *p == '[') {
        char open = *p, close = (open == '{') ? '}' : ']';
        int depth = 1;
        p++;
        while (p < end && depth > 0) {
            if (*p == '"') { p = skip_json_str(p, end); continue; }
            if (*p == open) depth++;
            else if (*p == close) depth--;
            p++;
        }
        return p;
    }

    /* number, bool, null - scan to next structural char */
    while (p < end && *p != ',' && *p != '}' && *p != ']' &&
           !((unsigned char)*p <= ' ')) p++;
    return p;
}

/* Extract a JSON string value into buf (with basic unescape).
 * p must point to opening '"'. Returns pointer past closing '"'. */
static const char *extract_json_str(const char *p, const char *end,
                                     char *buf, size_t bufsz) {
    size_t i;
    buf[0] = '\0';
    if (p >= end || *p != '"') return p;
    p++; /* skip opening quote */
    i = 0;
    while (p < end && *p != '"') {
        if (*p == '\\' && p + 1 < end) {
            char c;
            p++; /* skip backslash */
            c = *p;
            switch (c) {
                case 'n': c = '\n'; break;
                case 't': c = '\t'; break;
                case 'r': c = '\r'; break;
                default: break; /* \", \\, \/ pass through as-is */
            }
            if (i < bufsz - 1) buf[i++] = c;
            p++;
        } else {
            if (i < bufsz - 1) buf[i++] = *p;
            p++;
        }
    }
    buf[i] = '\0';
    if (p < end && *p == '"') p++; /* skip closing quote */
    return p;
}

/* Extract an integer value. Returns pointer past the number. */
static const char *extract_json_int(const char *p, const char *end, int *out) {
    int neg = 0, val = 0;
    p = skip_ws(p, end);
    if (p < end && *p == '-') { neg = 1; p++; }
    while (p < end && *p >= '0' && *p <= '9') {
        val = val * 10 + (*p - '0');
        p++;
    }
    *out = neg ? -val : val;
    return p;
}

/* Extract a boolean value (true/false/1/0, including quoted variants).
 * Returns pointer past the token. */
static const char *extract_json_bool(const char *p, const char *end, int *out) {
    p = skip_ws(p, end);
    if (p + 4 <= end && memcmp(p, "true", 4) == 0) {
        *out = 1;
        return p + 4;
    }
    if (p + 5 <= end && memcmp(p, "false", 5) == 0) {
        *out = 0;
        return p + 5;
    }
    /* MISP sometimes uses 1/0 as boolean */
    if (p < end && *p == '1') { *out = 1; return p + 1; }
    if (p < end && *p == '0') { *out = 0; return p + 1; }
    /* Quoted: "true"/"false"/"1"/"0" */
    if (p < end && *p == '"') {
        char buf[8];
        const char *np = extract_json_str(p, end, buf, sizeof(buf));
        *out = (strcmp(buf, "true") == 0 || strcmp(buf, "1") == 0) ? 1 : 0;
        return np;
    }
    *out = 0;
    return skip_json_val(p, end);
}

/* ============================================================================
 * PROCESS TAGS FILE
 * Format: CSV or JSON with value,tags[] structure
 * CSV: value,tag1,tag2,tag3,...
 * JSON: {"index":"value","tags":["tag1","tag2"]}
 * ============================================================================ */
static void process_tags_csv(const char* filename) {
    FILE *f = fopen(filename, "r");
    char line[MAX_LINE_LEN];
    size_t count;
    if (!f) { fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno)); exit(1); }

    if (g_verbose) printf("%s %sProcessing %-14s: %s%s\n",
                          ICON_INFO, COL_BOLD, "Tags CSV", filename, COL_RESET);

    count = 0;

    while (fgets(line, sizeof(line), f)) {
        char *value;
        char tags_json[MAX_TAGS_JSON] = "[";
        size_t tags_len = 1;
        char *tag;
        int first;
        int tags_truncated;
        normalized_ioc_v4_t ioc = {0};
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == 0 || line[0] == '#') continue;

        /* Parse: value,tag1,tag2,tag3,... */
        value = strtok(line, ",");
        if (!value) continue;
        value = trim(value);

        /* Build JSON array from remaining tokens */
        first = 1;
        tags_truncated = 0;

        while ((tag = strtok(NULL, ",")) != NULL) {
            size_t tag_len;
            tag = trim(tag);
            tag_len = strlen(tag);
            if (tag_len == 0) continue;

            /* Room needed: optional ',' + '"' + tag + '"' + closing ']' + NUL.
             * Stop cleanly if this tag would not fit rather than overflow the
             * buffer (feed data is external and untrusted). */
            if (tags_len + (first ? 0 : 1) + tag_len + 4 >= sizeof(tags_json)) {
                tags_truncated = 1;
                break;
            }
            if (!first) tags_json[tags_len++] = ',';
            tags_json[tags_len++] = '"';
            memcpy(tags_json + tags_len, tag, tag_len);
            tags_len += tag_len;
            tags_json[tags_len++] = '"';
            first = 0;
        }
        tags_json[tags_len++] = ']';
        tags_json[tags_len] = '\0';
        if (tags_truncated) {
            fprintf(stderr, "%s tags for '%s' exceed %d bytes, list truncated\n", ICON_WARN, value,
                    MAX_TAGS_JSON);
        }

        if (first) continue; /* No tags found */

        ioc.action = '+';
        snprintf(ioc.value, sizeof(ioc.value), "%s", value);
        snprintf(ioc.type, sizeof(ioc.type), "%s", "auto");
        ioc.confidence = 100; /* Tags are definitive */
        ioc.category_mask = 0;
        ioc.tlp_mask = 0;
        snprintf(ioc.feed, sizeof(ioc.feed), "%s", g_default_source);
        snprintf(ioc.tags_json, sizeof(ioc.tags_json), "%s", tags_json);

        emit_normalized_ioc_v4(&ioc);
        count++;
    }

    if (g_verbose) printf("   %s Loaded %zu tagged entries\n", ICON_CHECK, count);
    fclose(f);
}

/* Process JSON tags file: {"index":"ip/hostname","tags":["tag1","tag2"]} per line */
static void process_tags_json(const char* filename) {
    FILE *f = fopen(filename, "r");
    char line[MAX_LINE_LEN];
    size_t count;
    if (!f) { fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno)); exit(1); }

    if (g_verbose) printf("%s %sProcessing %-14s: %s%s\n",
                          ICON_INFO, COL_BOLD, "Tags JSON", filename, COL_RESET);

    count = 0;

    while (fgets(line, sizeof(line), f)) {
        char value[512] = {0};
        char *tags_start;
        char *tags_end;
        char tags_json[MAX_TAGS_JSON] = {0};
        size_t len;
        normalized_ioc_v4_t ioc = {0};
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == 0 || line[0] != '{') continue;

        if (!json_get_val(line, "index", value, sizeof(value))) continue;

        /* Extract tags array as-is */
        tags_start = strstr(line, "\"tags\"");
        if (!tags_start) continue;
        tags_start = strchr(tags_start, '[');
        if (!tags_start) continue;

        tags_end = strchr(tags_start, ']');
        if (!tags_end) continue;

        len = tags_end - tags_start + 1;
        if (len >= sizeof(tags_json)) len = sizeof(tags_json) - 1;
        strncpy(tags_json, tags_start, len);

        ioc.action = '+';
        snprintf(ioc.value, sizeof(ioc.value), "%s", value);
        snprintf(ioc.type, sizeof(ioc.type), "%s", "auto");
        ioc.confidence = 100;
        ioc.category_mask = 0;
        ioc.tlp_mask = 0;
        snprintf(ioc.feed, sizeof(ioc.feed), "%s", g_default_source);
        snprintf(ioc.tags_json, sizeof(ioc.tags_json), "%s", tags_json);

        emit_normalized_ioc_v4(&ioc);
        count++;
    }

    if (g_verbose) printf("   %s Loaded %zu tagged entries\n", ICON_CHECK, count);
    fclose(f);
}

/* ============================================================================
 * PROCESS CTI CSV
 * Format: type,value,confidence,category,feed,tlp
 * ============================================================================ */
static void process_csv(const char *filename) {
    FILE *f = fopen(filename, "r");
    char line[MAX_LINE_LEN];
    if (!f) { fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno)); exit(1); }

    if (g_verbose) printf("%s %sProcessing %-14s: %s%s\n",
                          ICON_INFO, COL_BOLD, "CSV", filename, COL_RESET);

    while (fgets(line, sizeof(line), f)) {
        char *tokens[7] = {0};
        char *p;
        int i;
        int col_offset;
        char action;
        int ncols;
        normalized_ioc_v4_t ioc = {0};
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == 0 || line[0] == '#') continue;

        p = strtok(line, ",");
        i = 0;
        while (p && i < 7) { tokens[i++] = trim(p); p = strtok(NULL, ","); }

        if (i < 2) { stats.skipped_count++; continue; }

        /*
         * Delta format detection:
         *   +,type,value,confidence,category,feed,tlp   (add)
         *   -,type,value                                 (delete)
         * Standard format:
         *   type,value,confidence,category,feed,tlp
         *
         * If tokens[0] is "+" or "-", shift the field indices by 1.
         */
        col_offset = 0;
        action = '+';
        if (tokens[0][0] == '+' && tokens[0][1] == '\0') {
            action = '+'; col_offset = 1;
        } else if (tokens[0][0] == '-' && tokens[0][1] == '\0') {
            action = '-'; col_offset = 1;
        }

        ncols = i - col_offset;
        if (ncols < 2) { stats.skipped_count++; continue; }

        ioc.action = action;
        snprintf(ioc.type, sizeof(ioc.type), "%s", tokens[col_offset + 0]);
        snprintf(ioc.value, sizeof(ioc.value), "%s", tokens[col_offset + 1]);
        ioc.confidence = (ncols > 2) ? parse_confidence(tokens[col_offset + 2]) : 50;
        ioc.category_mask = (ncols > 3) ? parse_category_mask(tokens[col_offset + 3]) : 0;
        snprintf(ioc.feed, sizeof(ioc.feed), "%s", (ncols > 4) ? tokens[col_offset + 4] : g_default_source);
        ioc.tlp_mask = (ncols > 5) ? parse_tlp_mask(tokens[col_offset + 5]) : THRT_TLP_CLEAR;

        emit_normalized_ioc_v4(&ioc);
    }
    fclose(f);
}

/* ============================================================================
 * PROCESS RSYSLOG LOOKUP JSON
 * ============================================================================ */
static void process_rsyslog_json(const char* filename) {
    FILE *f = fopen(filename, "r");
    long fsize;
    char *content;
    size_t nread;
    char *cursor;
    if (!f) { fprintf(stderr, "Error opening %s\n", filename); exit(1); }

    fseek(f, 0, SEEK_END); fsize = ftell(f); rewind(f);
    if (fsize < 0) { fprintf(stderr, "Error: cannot determine size of %s\n", filename); fclose(f); exit(1); }
    content = xmalloc((size_t)fsize + 1);
    nread = fread(content, 1, (size_t)fsize, f);
    content[nread] = 0;
    fclose(f);

    if (g_verbose) printf("%s %sProcessing %-14s: %s (%.2f MB)%s\n",
                          ICON_INFO, COL_BOLD, "Lookup (JSON)", filename,
                          fsize/(1024.0*1024.0), COL_RESET);

    cursor = content;

    while ((cursor = strstr(cursor, "\"index\":"))) {
        char *idx_start = strchr(cursor, ':');
        char *idx_end;
        char *ioc_val;
        char *val_marker;
        char *val_start;
        char *val_end;
        char tlp_str[32] = "clear";
        char feed_str[256] = "Unknown";
        char score_str[16] = "50";
        char type_str[32] = "unknown";
        normalized_ioc_v4_t ioc = {0};
        if (!idx_start) break;
        idx_start = strchr(idx_start, '"'); if (!idx_start) break; idx_start++;
        idx_end = strchr(idx_start, '"'); if (!idx_end) break;
        *idx_end = 0; ioc_val = idx_start;

        val_marker = strstr(idx_end + 1, "\"value\":"); if (!val_marker) break;
        val_start = strchr(val_marker, ':'); if (!val_start) break;
        val_start = strchr(val_start, '"'); if (!val_start) break; val_start++;

        val_end = val_start;
        while (*val_end) { if (*val_end == '"' && *(val_end-1) != '\\') break; val_end++; }
        *val_end = 0;

        unescape_json(val_start);


        json_get_val(val_start, "tlp", tlp_str, sizeof(tlp_str));
        json_get_val(val_start, "max_score", score_str, sizeof(score_str));
        json_get_val(val_start, "type", type_str, sizeof(type_str));
        json_get_val(val_start, "feed", feed_str, sizeof(feed_str));

        ioc.action = '+';
        snprintf(ioc.value, sizeof(ioc.value), "%s", ioc_val);
        snprintf(ioc.type, sizeof(ioc.type), "%s", type_str);
        ioc.confidence = parse_confidence(score_str);
        ioc.category_mask = parse_category_mask(type_str);
        snprintf(ioc.feed, sizeof(ioc.feed), "%s", feed_str);
        ioc.tlp_mask = parse_tlp_mask(tlp_str);

        emit_normalized_ioc_v4(&ioc);
        cursor = val_end + 1;
    }
    free(content);
}

/* ============================================================================
 * PROCESS PLAIN TEXT IOC LIST
 * ============================================================================ */
static void process_plaintext(const char* filename) {
    FILE *f = fopen(filename, "r");
    char line[MAX_LINE_LEN];
    size_t count;
    if (!f) { fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno)); exit(1); }

    if (g_verbose) printf("%s %sProcessing %-14s: %s%s\n",
                          ICON_INFO, COL_BOLD, "Plain Text", filename, COL_RESET);

    count = 0;

    while (fgets(line, sizeof(line), f)) {
        char *val;
        normalized_ioc_v4_t ioc = {0};
        struct in_addr a4;
        struct in6_addr a6;
        line[strcspn(line, "\r\n")] = 0;
        val = trim(line);
        if (val[0] == 0 || val[0] == '#' || val[0] == ';') continue;

        ioc.action = '+';
        snprintf(ioc.value, sizeof(ioc.value), "%s", val);
        ioc.confidence = 50;
        ioc.category_mask = 0;
        ioc.tlp_mask = THRT_TLP_CLEAR;
        snprintf(ioc.feed, sizeof(ioc.feed), "%s", g_default_source);

        /* Auto-detect type */
        if (inet_pton(AF_INET, val, &a4) == 1 || inet_pton(AF_INET6, val, &a6) == 1) {
            snprintf(ioc.type, sizeof(ioc.type), "%s", "ip");
        } else if (strchr(val, '@')) {
            snprintf(ioc.type, sizeof(ioc.type), "%s", "email");
        } else {
            size_t len = strlen(val);
            if ((len == 32 || len == 40 || len == 64 || len == 128) &&
                strspn(val, "0123456789abcdefABCDEF") == len) {
                snprintf(ioc.type, sizeof(ioc.type), "%s", "hash");
            } else if (strstr(val, "://")) {
                snprintf(ioc.type, sizeof(ioc.type), "%s", "url");
            } else {
                snprintf(ioc.type, sizeof(ioc.type), "%s", "domain");
            }
        }

        emit_normalized_ioc_v4(&ioc);
        count++;
    }

    if (g_verbose) printf("   %s Extracted %zu indicators\n", ICON_CHECK, count);
    fclose(f);
}

/* ============================================================================
 * PROCESS CTI DICTIONARY JSON
 * Format: {"ioc_value": {"tlp":"...", "feed":["F1","F2"], "max_score":N,
 *          "type":"...", "feed_objects":[{"feed_name":"F1","lbl":[...]},...] }, ...}
 *
 * Uses mmap for zero-copy parsing of large (1+ GB) single-line files.
 * Builds feed_mask directly from the "feed" array (multi-feed support).
 * Merges "lbl" arrays from all feed_objects into a single tags_json.
 * ============================================================================ */

/* Append a label string to the merged tags_json buffer with dedup */
static void append_label(char *buf, int *pos, int maxlen, const char *label) {
    size_t label_len = strlen(label);
    int need;
    if (label_len == 0) return;

    /* Quick linear dedup: check if this label is already in the buffer.
     * Search for ,"label" or ["label" - we look for the quoted form. */
    {
        char needle[520];
        int nlen = snprintf(needle, sizeof(needle), "\"%s\"", label);
        if (nlen > 0 && (size_t)nlen < sizeof(needle)) {
            if (memmem(buf, *pos, needle, nlen) != NULL) return;
        }
    }

    /* Format: ,"label" (or "label" if first) */
    need = (*pos > 1 ? 1 : 0) + 1 + (int)label_len + 1; /* comma + quote + label + quote */
    if (*pos + need + 2 > maxlen) return; /* +2 for closing ] and \0 */

    if (*pos > 1) buf[(*pos)++] = ',';
    buf[(*pos)++] = '"';
    memcpy(buf + *pos, label, label_len);
    *pos += (int)label_len;
    buf[(*pos)++] = '"';
    buf[*pos] = '\0';
}

/* Parse the "feed" array and OR feed bits into feed_mask.
 * p points to '['. Returns pointer past ']'. */
static const char *parse_cti_feed_array(const char *p, const char *end,
                                         uint64_t *feed_mask) {
    if (p >= end || *p != '[') return skip_json_val(p, end);
    p++; /* skip '[' */

    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == ']') break;
        if (*p == ',') { p++; continue; }

        if (*p == '"') {
            char feed_name[THRT_FEED_NAME_MAX];
            p = extract_json_str(p, end, feed_name, sizeof(feed_name));
            if (feed_name[0]) {
                uint8_t idx = get_feed_idx(feed_name);
                *feed_mask |= (1ULL << idx);
            }
        } else {
            p = skip_json_val(p, end);
        }
    }

    if (p < end && *p == ']') p++;
    return p;
}

/* Parse the "feed_objects" array and extract labels from "lbl" sub-arrays.
 * p points to '['. Returns pointer past ']'. */
static const char *parse_cti_feed_objects(const char *p, const char *end,
                                           char *labels_json, int *labels_pos,
                                           int labels_maxlen) {
    if (p >= end || *p != '[') return skip_json_val(p, end);
    p++; /* skip '[' */

    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == ']') break;
        if (*p == ',') { p++; continue; }

        if (*p != '{') { p = skip_json_val(p, end); continue; }
        p++; /* skip '{' */

        /* Walk fields of this feed_object */
        while (p < end) {
            char key[32];
            p = skip_ws(p, end);
            if (p >= end || *p == '}') break;
            if (*p == ',') { p++; continue; }

            if (*p != '"') break;

            p = extract_json_str(p, end, key, sizeof(key));
            p = skip_ws(p, end);
            if (p >= end || *p != ':') break;
            p++; /* skip ':' */
            p = skip_ws(p, end);

            if (strcmp(key, "lbl") == 0 && *p == '[') {
                /* Parse labels array */
                p++; /* skip '[' */
                while (p < end) {
                    p = skip_ws(p, end);
                    if (p >= end || *p == ']') break;
                    if (*p == ',') { p++; continue; }
                    if (*p == '"') {
                        char label[512];
                        p = extract_json_str(p, end, label, sizeof(label));
                        append_label(labels_json, labels_pos, labels_maxlen, label);
                    } else {
                        p = skip_json_val(p, end);
                    }
                }
                if (p < end && *p == ']') p++;
            } else {
                p = skip_json_val(p, end);
            }
        }

        if (p < end && *p == '}') p++;
    }

    if (p < end && *p == ']') p++;
    return p;
}

/* Parse one CTI entry: {"tlp":"...", "feed":[...], "max_score":N, ...}
 * p points to '{'. Returns pointer past '}'. */
static const char *parse_cti_entry(const char *p, const char *end,
                                    const char *ioc_value) {
    char tlp_str[64] = "";
    char type_str[64] = "";
    int max_score;
    uint64_t feed_mask;
    char labels_json[MAX_TAGS_JSON];
    int labels_pos;
    uint8_t confidence;
    uint8_t type_mask;
    uint8_t tlp_mask;
    uint16_t category_mask;
    const char *tags;
    uint32_t meta_idx;
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++; /* skip '{' */

    max_score = 0;
    feed_mask = 0;
    labels_pos = 1;

    labels_json[0] = '[';
    labels_json[1] = '\0';

    while (p < end) {
        char key[32];
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') break;

        p = extract_json_str(p, end, key, sizeof(key));
        p = skip_ws(p, end);
        if (p >= end || *p != ':') break;
        p++; /* skip ':' */
        p = skip_ws(p, end);

        switch (key[0]) {
        case 't':
            if (strcmp(key, "tlp") == 0) {
                p = extract_json_str(p, end, tlp_str, sizeof(tlp_str));
            } else if (strcmp(key, "type") == 0) {
                p = extract_json_str(p, end, type_str, sizeof(type_str));
            } else {
                p = skip_json_val(p, end);
            }
            break;
        case 'm':
            if (strcmp(key, "max_score") == 0) {
                p = extract_json_int(p, end, &max_score);
            } else {
                p = skip_json_val(p, end);
            }
            break;
        case 'f':
            if (strcmp(key, "feed") == 0) {
                p = parse_cti_feed_array(p, end, &feed_mask);
            } else if (strcmp(key, "feed_objects") == 0) {
                p = parse_cti_feed_objects(p, end, labels_json, &labels_pos,
                                            (int)sizeof(labels_json));
            } else {
                p = skip_json_val(p, end);
            }
            break;
        default:
            p = skip_json_val(p, end);
            break;
        }
    }

    if (p < end && *p == '}') p++;

    /* Close labels JSON array */
    if (labels_pos < (int)sizeof(labels_json) - 1) {
        labels_json[labels_pos++] = ']';
        labels_json[labels_pos] = '\0';
    }

    /* Clamp confidence */
    confidence = (max_score > 100) ? 100 : (max_score < 0) ? 0 : (uint8_t)max_score;

    /* If no feeds were found, assign default */
    if (feed_mask == 0) {
        uint8_t idx = get_feed_idx(g_default_source);
        feed_mask = (1ULL << idx);
    }

    /* Build metadata directly (bypasses normalized_ioc_v4_t for multi-feed) */
    type_mask = layer_to_type_mask(g_current_layer);
    tlp_mask = parse_tlp_mask(tlp_str);
    category_mask = parse_category_mask(type_str);
    tags = (labels_pos > 2) ? labels_json : NULL; /* >2 means we have at least one label */

    meta_idx = add_meta_v4(confidence, type_mask, tlp_mask,
                                     category_mask, feed_mask, tags);
    add_ioc(ioc_value, type_str, meta_idx);
    stats.added_count++;

    return p;
}

/* Main CTI dictionary JSON processor */
static void process_cti_json(const char *filename) {
    int fd = open(filename, O_RDONLY);
    struct stat sb;
    const char *map;
    const char *end;
    const char *p;
    size_t count;
    size_t errors;
    if (fd < 0) {
        fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno));
        exit(1);
    }

    if (fstat(fd, &sb) < 0 || sb.st_size == 0) {
        fprintf(stderr, "%s Empty or unreadable file: %s\n", ICON_WARN, filename);
        close(fd);
        return;
    }

    map = (const char *)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "mmap failed for %s: %s\n", filename, strerror(errno));
        close(fd);
        exit(1);
    }

#ifdef MADV_SEQUENTIAL
    madvise((void *)map, sb.st_size, MADV_SEQUENTIAL);
#endif

    end = map + sb.st_size;
    p = map;

    if (g_verbose) printf("%s %sProcessing %-14s: %s (%.2f MB)%s\n",
                           ICON_INFO, COL_BOLD, "CTI JSON", filename,
                           sb.st_size / (1024.0 * 1024.0), COL_RESET);

    /* Expect opening '{' for the top-level dictionary */
    p = skip_ws(p, end);
    if (p >= end || *p != '{') {
        fprintf(stderr, "%s %s is not a JSON object (expected '{')\n", ICON_WARN, filename);
        munmap((void *)map, sb.st_size);
        close(fd);
        return;
    }
    p++; /* skip '{' */

    count = 0;
    errors = 0;

    while (p < end) {
        char ioc_value[512];
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }

        if (*p != '"') {
            /* Unexpected character - try to recover */
            errors++;
            p++;
            continue;
        }

        /* Extract the IOC value (top-level key) */
        p = extract_json_str(p, end, ioc_value, sizeof(ioc_value));

        /* Expect ':' */
        p = skip_ws(p, end);
        if (p >= end || *p != ':') {
            errors++;
            p = skip_json_val(p, end);
            continue;
        }
        p++; /* skip ':' */
        p = skip_ws(p, end);

        if (ioc_value[0] == '\0') {
            p = skip_json_val(p, end);
            errors++;
            continue;
        }

        p = parse_cti_entry(p, end, ioc_value);
        count++;
    }

    if (g_verbose) {
        printf("   %s Loaded %zu IOC entries", ICON_CHECK, count);
        if (errors > 0) printf(" (%zu parse errors)", errors);
        printf("\n");
    }

    munmap((void *)map, sb.st_size);
    close(fd);
}

/* ============================================================================
 * MISP JSON EXPORT PARSER
 *
 * Handles MISP JSON export formats:
 *   Single event:       {"Event": {"info":"...", "Attribute":[...], ...}}
 *   Event search:       {"response": [{"Event":{...}}, {"Event":{...}}]}
 *   Attribute search:   {"response": {"Attribute":[ {...}, ... ]}}
 *   Attribute list:     {"Attribute":[ {...}, ... ]}
 * An attribute from /attributes/restSearch may carry a nested Event.
 * That Event supplies info, threat_level_id, and event tags.
 *
 * MISP attribute type -> IOC type mapping:
 *   ip-src, ip-dst                    -> "ip"
 *   ip-src|port, ip-dst|port          -> "ip" (port stripped)
 *   domain, hostname                  -> "domain"
 *   domain|ip                         -> both "domain" and "ip"
 *   md5, sha1, sha256                 -> hash type
 *   filename|md5, filename|sha1, etc  -> hash (filename stripped)
 *   url                               -> "url"
 *   email-src, email-dst              -> "email"
 *
 * Only attributes with to_ids=true are imported (MISP IDS convention).
 * TLP: attribute-level Tag overrides event-level Tag.
 * ============================================================================ */

/* Map MISP attribute type string to thrt IOC type.
 * Returns NULL for unsupported types (caller should skip). */
static const char *misp_type_to_ioc_type(const char *misp_type) {
    if (!misp_type || !misp_type[0]) return NULL;

    if (strcmp(misp_type, "ip-src") == 0 || strcmp(misp_type, "ip-dst") == 0)
        return "ip";
    if (strcmp(misp_type, "ip-src|port") == 0 || strcmp(misp_type, "ip-dst|port") == 0)
        return "ip";
    if (strcmp(misp_type, "domain") == 0 || strcmp(misp_type, "hostname") == 0)
        return "domain";
    if (strcmp(misp_type, "domain|ip") == 0)
        return "domain|ip"; /* composite - emit both */
    if (strcmp(misp_type, "md5") == 0) return "md5";
    if (strcmp(misp_type, "sha1") == 0) return "sha1";
    if (strcmp(misp_type, "sha256") == 0) return "sha256";
    if (strcmp(misp_type, "filename|md5") == 0) return "md5";
    if (strcmp(misp_type, "filename|sha1") == 0) return "sha1";
    if (strcmp(misp_type, "filename|sha256") == 0) return "sha256";
    if (strcmp(misp_type, "url") == 0) return "url";
    if (strcmp(misp_type, "email-src") == 0 || strcmp(misp_type, "email-dst") == 0)
        return "email";

    return NULL;
}

/* Map MISP category to THRT_CAT_* bitmask */
static uint16_t misp_category_to_mask(const char *cat) {
    if (!cat || !cat[0]) return THRT_CAT_UNKNOWN;

    if (strcasecmp(cat, "Network activity") == 0)      return THRT_CAT_ATTACK;
    if (strcasecmp(cat, "Payload delivery") == 0)       return THRT_CAT_MALWARE;
    if (strcasecmp(cat, "Payload installation") == 0)   return THRT_CAT_MALWARE;
    if (strcasecmp(cat, "Persistence mechanism") == 0)  return THRT_CAT_MALWARE;
    if (strcasecmp(cat, "Artifacts dropped") == 0)      return THRT_CAT_MALWARE;
    if (strcasecmp(cat, "Antivirus detection") == 0)    return THRT_CAT_MALWARE;
    if (strcasecmp(cat, "Targeting data") == 0)         return THRT_CAT_PHISHING;
    if (strcasecmp(cat, "Attribution") == 0)            return THRT_CAT_ATTACK;
    if (strcasecmp(cat, "Financial fraud") == 0)        return THRT_CAT_PHISHING;

    return THRT_CAT_UNKNOWN;
}

/* Map MISP Event threat_level_id to confidence:
 *   1=High -> 90, 2=Medium -> 70, 3=Low -> 50, 4/other -> 70 */
static uint8_t misp_threat_level_to_confidence(int level) {
    switch (level) {
    case 1:  return 90;
    case 2:  return 70;
    case 3:  return 50;
    default: return 70;
    }
}

/* Parse MISP Tag array: extract TLP and collect tag names.
 * p points to '['. Returns pointer past ']'. */
static const char *parse_misp_tags(const char *p, const char *end,
                                    char *tlp_out, size_t tlp_size,
                                    char *tags_json, int *tags_pos, int tags_max) {
    if (p >= end || *p != '[') return skip_json_val(p, end);
    p++; /* skip '[' */

    while (p < end) {
        char tag_name[256] = "";
        p = skip_ws(p, end);
        if (p >= end || *p == ']') break;
        if (*p == ',') { p++; continue; }
        if (*p != '{') { p = skip_json_val(p, end); continue; }
        p++; /* skip '{' */


        while (p < end) {
            char key[32];
            p = skip_ws(p, end);
            if (p >= end || *p == '}') break;
            if (*p == ',') { p++; continue; }
            if (*p != '"') break;

            p = extract_json_str(p, end, key, sizeof(key));
            p = skip_ws(p, end);
            if (p >= end || *p != ':') break;
            p++;
            p = skip_ws(p, end);

            if (strcmp(key, "name") == 0) {
                p = extract_json_str(p, end, tag_name, sizeof(tag_name));
            } else {
                p = skip_json_val(p, end);
            }
        }

        if (p < end && *p == '}') p++;

        /* Check for TLP tag (e.g. "tlp:green", "tlp:amber") */
        if (strncasecmp(tag_name, "tlp:", 4) == 0) {
            strncpy(tlp_out, tag_name + 4, tlp_size - 1);
            tlp_out[tlp_size - 1] = '\0';
        } else if (tag_name[0]) {
            append_label(tags_json, tags_pos, tags_max, tag_name);
        }
    }

    if (p < end && *p == ']') p++;
    return p;
}

/* Emit one MISP attribute as normalized IOC(s).
 * Handles composite types:
 *   ip-src|port -> strip port, emit IP only
 *   filename|hash -> strip filename, emit hash only
 *   domain|ip -> emit domain + IP as separate IOCs
 * Returns number of IOCs emitted (0 if skipped). */
static int emit_misp_ioc(const char *misp_type, const char *value,
                          uint8_t confidence, uint16_t cat_mask,
                          uint8_t tlp_mask, const char *tags_json,
                          char action) {
    const char *ioc_type = misp_type_to_ioc_type(misp_type);
    char clean_value[512];
    normalized_ioc_v4_t ioc = {0};
    if (!ioc_type) return 0;

    /* Composite: domain|ip -> emit both parts separately */
    if (strcmp(ioc_type, "domain|ip") == 0) {
        char vbuf[512];
        char *pipe;
        int count;
        snprintf(vbuf, sizeof(vbuf), "%s", value);
        pipe = strchr(vbuf, '|');
        count = 0;

        if (pipe) {
            const char *ip_part;
            *pipe = '\0';
            /* Emit domain (left of pipe) */
            ioc.action = action;
            snprintf(ioc.value, sizeof(ioc.value), "%s", vbuf);
            snprintf(ioc.type, sizeof(ioc.type), "%s", "domain");
            ioc.confidence = confidence;
            ioc.category_mask = cat_mask;
            snprintf(ioc.feed, sizeof(ioc.feed), "%s", g_default_source);
            ioc.tlp_mask = tlp_mask;
            if (tags_json) snprintf(ioc.tags_json, sizeof(ioc.tags_json), "%s", tags_json);
            emit_normalized_ioc_v4(&ioc);
            count++;

            /* Emit IP (right of pipe) */
            ip_part = pipe + 1;
            if (ip_part[0]) {
                memset(&ioc, 0, sizeof(ioc));
                ioc.action = action;
                snprintf(ioc.value, sizeof(ioc.value), "%s", ip_part);
                snprintf(ioc.type, sizeof(ioc.type), "%s", "ip");
                ioc.confidence = confidence;
                ioc.category_mask = cat_mask;
                snprintf(ioc.feed, sizeof(ioc.feed), "%s", g_default_source);
                ioc.tlp_mask = tlp_mask;
                if (tags_json) snprintf(ioc.tags_json, sizeof(ioc.tags_json), "%s", tags_json);
                emit_normalized_ioc_v4(&ioc);
                count++;
            }
        }
        return count;
    }

    /* Handle pipe-separated composites: strip to the relevant part */
    snprintf(clean_value, sizeof(clean_value), "%s", value);

    if (strchr(misp_type, '|')) {
        char *pipe = strchr(clean_value, '|');
        if (pipe) {
            /* filename|hash -> keep part AFTER pipe (the hash) */
            if (strncmp(misp_type, "filename|", 9) == 0) {
                memmove(clean_value, pipe + 1, strlen(pipe + 1) + 1);
            } else {
                /* ip-src|port -> keep part BEFORE pipe (the IP) */
                *pipe = '\0';
            }
        }
    }

    ioc.action = action;
    snprintf(ioc.value, sizeof(ioc.value), "%s", clean_value);
    snprintf(ioc.type, sizeof(ioc.type), "%s", ioc_type);
    ioc.confidence = confidence;
    ioc.category_mask = cat_mask;
    snprintf(ioc.feed, sizeof(ioc.feed), "%s", g_default_source);
    ioc.tlp_mask = tlp_mask;
    if (tags_json) snprintf(ioc.tags_json, sizeof(ioc.tags_json), "%s", tags_json);

    emit_normalized_ioc_v4(&ioc);
    return 1;
}

/* Parse one MISP Attribute object.
 * p points to '{'. Returns pointer past '}'.
 * event_tlp / event_tags provide fallback from Event-level Tag. */
static const char *parse_misp_attribute(const char *p, const char *end,
                                         uint8_t event_confidence,
                                         uint8_t event_tlp,
                                         const char *event_tags,
                                         size_t *emitted, size_t *skipped) {
    char misp_type[64] = "";
    char value[512] = "";
    char category[128] = "";
    int to_ids;
    int deleted;
    char attr_tlp[64] = "";
    char attr_tags[MAX_TAGS_JSON];
    int attr_tags_pos;
    uint8_t tlp;
    char merged_tags[MAX_TAGS_JSON];
    int merged_pos;
    uint16_t cat_mask;
    const char *tags;
    int n;
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++; /* skip '{' */

    to_ids = 1; /* default: import */
    deleted = 0;

    /* Attribute-level TLP and tags */
    attr_tags_pos = 1;
    attr_tags[0] = '[';
    attr_tags[1] = '\0';

    while (p < end) {
        char key[32];
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') break;

        p = extract_json_str(p, end, key, sizeof(key));
        p = skip_ws(p, end);
        if (p >= end || *p != ':') break;
        p++;
        p = skip_ws(p, end);

        switch (key[0]) {
        case 't':
            if (strcmp(key, "type") == 0)
                p = extract_json_str(p, end, misp_type, sizeof(misp_type));
            else if (strcmp(key, "to_ids") == 0)
                p = extract_json_bool(p, end, &to_ids);
            else
                p = skip_json_val(p, end);
            break;
        case 'v':
            if (strcmp(key, "value") == 0)
                p = extract_json_str(p, end, value, sizeof(value));
            else
                p = skip_json_val(p, end);
            break;
        case 'c':
            if (strcmp(key, "category") == 0)
                p = extract_json_str(p, end, category, sizeof(category));
            else
                p = skip_json_val(p, end);
            break;
        case 'd':
            if (strcmp(key, "deleted") == 0)
                p = extract_json_bool(p, end, &deleted);
            else
                p = skip_json_val(p, end);
            break;
        case 'T':
            if (strcmp(key, "Tag") == 0)
                p = parse_misp_tags(p, end, attr_tlp, sizeof(attr_tlp),
                                     attr_tags, &attr_tags_pos,
                                     (int)sizeof(attr_tags));
            else
                p = skip_json_val(p, end);
            break;
        default:
            p = skip_json_val(p, end);
            break;
        }
    }

    if (p < end && *p == '}') p++;

    /* A full build drops to_ids false and does not read deleted.
     * An incremental sync fold turns either into a withdrawal. */
    if (!g_misp_delta && !to_ids) {
        (*skipped)++;
        return p;
    }
    if (!misp_type_to_ioc_type(misp_type)) {
        (*skipped)++;
        return p;
    }
    if (g_misp_delta && (deleted || !to_ids)) {
        emit_misp_ioc(misp_type, value, 0, 0, 0, NULL, '-');
        return p;
    }

    /* Resolve TLP: attribute-level overrides event-level */
    tlp = attr_tlp[0] ? parse_tlp_mask(attr_tlp) : event_tlp;

    /* Merge tags: event tags + attribute tags */
    merged_pos = 1;
    merged_tags[0] = '[';
    merged_tags[1] = '\0';

    /* Copy event tags content (between [ and ]) */
    if (event_tags) {
        size_t elen = strlen(event_tags);
        if (elen > 2) { /* more than just "[]" */
            size_t copy_len = elen - 2; /* skip [ and ] */
            if (merged_pos + (int)copy_len < (int)sizeof(merged_tags) - 2) {
                memcpy(merged_tags + merged_pos, event_tags + 1, copy_len);
                merged_pos += (int)copy_len;
            }
        }
    }

    /* Append attribute-level tags */
    if (attr_tags_pos > 1) {
        size_t copy_len = attr_tags_pos - 1;
        if (copy_len > 0 && merged_pos + (int)copy_len < (int)sizeof(merged_tags) - 2) {
            if (merged_pos > 1) merged_tags[merged_pos++] = ',';
            memcpy(merged_tags + merged_pos, attr_tags + 1, copy_len);
            merged_pos += (int)copy_len;
        }
    }

    merged_tags[merged_pos++] = ']';
    merged_tags[merged_pos] = '\0';

    cat_mask = misp_category_to_mask(category);
    tags = (merged_pos > 2) ? merged_tags : NULL;

    n = emit_misp_ioc(misp_type, value, event_confidence, cat_mask, tlp, tags, '+');
    *emitted += n;

    return p;
}

/* Parse one MISP Event object.
 * p points to '{'. Returns pointer past '}'.
 * Uses two-pass approach: first pass collects metadata + saves positions
 * of Attribute/Object arrays, second pass emits IOCs. */
static const char *parse_misp_event(const char *p, const char *end,
                                     size_t *emitted, size_t *skipped) {
    char event_info[256] = "";
    int threat_level;
    char event_tlp[64] = "";
    char event_tags[MAX_TAGS_JSON];
    int event_tags_pos;
    const char *attr_start;
    const char *obj_start;
    uint8_t ev_tlp;
    uint8_t ev_confidence;
    const char *ev_tags;
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++; /* skip '{' */

    threat_level = 0;

    /* Event-level TLP and tags */
    event_tags_pos = 1;
    event_tags[0] = '[';
    event_tags[1] = '\0';

    /* Save positions for second-pass parsing (data stays in mmap) */
    attr_start = NULL;
    obj_start = NULL;

    /* First pass: collect event metadata, save array positions */
    while (p < end) {
        char key[32];
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') break;

        p = extract_json_str(p, end, key, sizeof(key));
        p = skip_ws(p, end);
        if (p >= end || *p != ':') break;
        p++;
        p = skip_ws(p, end);

        if (strcmp(key, "info") == 0) {
            p = extract_json_str(p, end, event_info, sizeof(event_info));
        } else if (strcmp(key, "threat_level_id") == 0) {
            /* Can be string "1" or int 1 */
            if (p < end && *p == '"') {
                char tlid[8];
                p = extract_json_str(p, end, tlid, sizeof(tlid));
                threat_level = atoi(tlid);
            } else {
                p = extract_json_int(p, end, &threat_level);
            }
        } else if (strcmp(key, "Tag") == 0) {
            p = parse_misp_tags(p, end, event_tlp, sizeof(event_tlp),
                                 event_tags, &event_tags_pos,
                                 (int)sizeof(event_tags));
        } else if (strcmp(key, "Attribute") == 0) {
            attr_start = p;
            p = skip_json_val(p, end);
        } else if (strcmp(key, "Object") == 0) {
            obj_start = p;
            p = skip_json_val(p, end);
        } else {
            p = skip_json_val(p, end);
        }
    }

    if (p < end && *p == '}') p++;

    /* Close event tags and add event info as label */
    if (event_info[0]) {
        char info_tag[300];
        snprintf(info_tag, sizeof(info_tag), "misp-event:%.280s", event_info);
        append_label(event_tags, &event_tags_pos, (int)sizeof(event_tags), info_tag);
    }
    if (event_tags_pos < (int)sizeof(event_tags) - 1) {
        event_tags[event_tags_pos++] = ']';
        event_tags[event_tags_pos] = '\0';
    }

    ev_tlp = parse_tlp_mask(event_tlp);
    ev_confidence = misp_threat_level_to_confidence(threat_level);
    ev_tags = (event_tags_pos > 2) ? event_tags : NULL;

    if (g_verbose && event_info[0]) {
        printf("   %s Event: %s (threat_level=%d, tlp=%s)\n",
               ICON_INFO, event_info, threat_level,
               event_tlp[0] ? event_tlp : "clear");
    }

    /* Second pass: parse Attribute array */
    if (attr_start && attr_start < end && *attr_start == '[') {
        const char *ap = attr_start + 1; /* skip '[' */
        while (ap < end) {
            ap = skip_ws(ap, end);
            if (ap >= end || *ap == ']') break;
            if (*ap == ',') { ap++; continue; }
            ap = parse_misp_attribute(ap, end, ev_confidence, ev_tlp,
                                       ev_tags, emitted, skipped);
        }
    }

    /* Parse Object array -> each Object has a nested Attribute array */
    if (obj_start && obj_start < end && *obj_start == '[') {
        const char *op = obj_start + 1; /* skip '[' */
        while (op < end) {
            const char *nested_attr;
            op = skip_ws(op, end);
            if (op >= end || *op == ']') break;
            if (*op == ',') { op++; continue; }
            if (*op != '{') { op = skip_json_val(op, end); continue; }

            /* Walk Object fields looking for nested Attribute array */
            nested_attr = NULL;
            op++; /* skip '{' */
            while (op < end) {
                char okey[32];
                op = skip_ws(op, end);
                if (op >= end || *op == '}') break;
                if (*op == ',') { op++; continue; }
                if (*op != '"') break;

                op = extract_json_str(op, end, okey, sizeof(okey));
                op = skip_ws(op, end);
                if (op >= end || *op != ':') break;
                op++;
                op = skip_ws(op, end);

                if (strcmp(okey, "Attribute") == 0) {
                    nested_attr = op;
                    op = skip_json_val(op, end);
                } else {
                    op = skip_json_val(op, end);
                }
            }
            if (op < end && *op == '}') op++;

            /* Parse nested attributes within this Object */
            if (nested_attr && nested_attr < end && *nested_attr == '[') {
                const char *np = nested_attr + 1; /* skip '[' */
                while (np < end) {
                    np = skip_ws(np, end);
                    if (np >= end || *np == ']') break;
                    if (*np == ',') { np++; continue; }
                    np = parse_misp_attribute(np, end, ev_confidence, ev_tlp,
                                               ev_tags, emitted, skipped);
                }
            }
        }
    }

    return p;
}

/* Read info, threat_level_id, and Tag from an Event object. p points at '{'. */
static const char *misp_read_event_context(const char *p, const char *end,
                                            char *info, size_t infosz,
                                            int *threat_level,
                                            char *tlp, size_t tlpsz,
                                            char *tags, int *tags_pos, int tags_max) {
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++;
    while (p < end) {
        char key[32];
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') break;
        p = extract_json_str(p, end, key, sizeof(key));
        p = skip_ws(p, end);
        if (p >= end || *p != ':') break;
        p++;
        p = skip_ws(p, end);
        if (strcmp(key, "info") == 0) {
            p = extract_json_str(p, end, info, infosz);
        } else if (strcmp(key, "threat_level_id") == 0) {
            if (p < end && *p == '"') {
                char tlid[8];
                p = extract_json_str(p, end, tlid, sizeof(tlid));
                *threat_level = atoi(tlid);
            } else {
                p = extract_json_int(p, end, threat_level);
            }
        } else if (strcmp(key, "Tag") == 0) {
            p = parse_misp_tags(p, end, tlp, tlpsz, tags, tags_pos, tags_max);
        } else {
            p = skip_json_val(p, end);
        }
    }
    if (p < end && *p == '}') p++;
    return p;
}

static void misp_close_event_tags(char *tags, int *pos, int max, const char *info) {
    if (info && info[0]) {
        char info_tag[300];
        snprintf(info_tag, sizeof(info_tag), "misp-event:%.280s", info);
        append_label(tags, pos, max, info_tag);
    }
    if (*pos < max - 1) {
        tags[(*pos)++] = ']';
        tags[*pos] = '\0';
    }
}

/* One attribute from /attributes/restSearch. A nested Event is context. */
static const char *parse_misp_search_attribute(const char *p, const char *end,
                                                size_t *emitted, size_t *skipped) {
    const char *start = p;
    const char *event_at = NULL;
    const char *q;
    char info[256] = "";
    int threat_level = 0;
    char event_tlp[64] = "";
    char event_tags[MAX_TAGS_JSON];
    int event_tags_pos = 1;
    uint8_t ev_tlp, ev_confidence;
    const char *ev_tags;

    event_tags[0] = '[';
    event_tags[1] = '\0';
    if (p >= end || *p != '{') return skip_json_val(p, end);
    q = p + 1;
    while (q < end) {
        char key[32];
        q = skip_ws(q, end);
        if (q >= end || *q == '}') break;
        if (*q == ',') { q++; continue; }
        if (*q != '"') break;
        q = extract_json_str(q, end, key, sizeof(key));
        q = skip_ws(q, end);
        if (q >= end || *q != ':') break;
        q++;
        q = skip_ws(q, end);
        if (strcmp(key, "Event") == 0 && q < end && *q == '{') {
            event_at = q;
            q = skip_json_val(q, end);
        } else {
            q = skip_json_val(q, end);
        }
    }
    if (event_at)
        misp_read_event_context(event_at, end, info, sizeof(info), &threat_level,
                                event_tlp, sizeof(event_tlp),
                                event_tags, &event_tags_pos, (int)sizeof(event_tags));
    misp_close_event_tags(event_tags, &event_tags_pos, (int)sizeof(event_tags), info);
    ev_tlp = parse_tlp_mask(event_tlp);
    ev_confidence = misp_threat_level_to_confidence(threat_level);
    ev_tags = (event_tags_pos > 2) ? event_tags : NULL;
    return parse_misp_attribute(start, end, ev_confidence, ev_tlp, ev_tags,
                                emitted, skipped);
}

static const char *misp_parse_search_list(const char *p, const char *end,
                                           size_t *emitted, size_t *skipped) {
    if (p >= end || *p != '[') return skip_json_val(p, end);
    p++;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == ']') break;
        if (*p == ',') { p++; continue; }
        p = parse_misp_search_attribute(p, end, emitted, skipped);
    }
    if (p < end && *p == ']') p++;
    return p;
}

/* {"response":{"Attribute":[...]}} as returned by /attributes/restSearch. */
static const char *misp_parse_response_object(const char *p, const char *end,
                                               const char *filename,
                                               size_t *emitted, size_t *skipped) {
    int saw_attr = 0;
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++;
    while (p < end) {
        char key[32];
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') { p = skip_json_val(p, end); continue; }
        p = extract_json_str(p, end, key, sizeof(key));
        p = skip_ws(p, end);
        if (p >= end || *p != ':') break;
        p++;
        p = skip_ws(p, end);
        if (strcmp(key, "Attribute") == 0 && p < end && *p == '[') {
            saw_attr = 1;
            p = misp_parse_search_list(p, end, emitted, skipped);
        } else {
            p = skip_json_val(p, end);
        }
    }
    if (p < end && *p == '}') p++;
    if (!saw_attr)
        fprintf(stderr, "%s %s: MISP response has no Attribute array\n",
                ICON_WARN, filename);
    return p;
}

/* Main MISP JSON processor.
 * Event export, event search, and attribute search.
 * Returns 0 when the file was read. Returns -1 when it could not be opened.
 * An unrecognized body is a warning and still returns 0. */
static int process_misp_json(const char *filename) {
    int fd = open(filename, O_RDONLY);
    struct stat sb;
    const char *map;
    const char *end;
    const char *p;
    char first_key[32];
    size_t emitted = 0, skipped = 0;
    if (fd < 0) {
        fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno));
        return -1;
    }

    if (fstat(fd, &sb) < 0 || sb.st_size == 0) {
        fprintf(stderr, "%s Empty or unreadable file: %s\n", ICON_WARN, filename);
        close(fd);
        return 0;
    }

    map = (const char *)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "mmap failed for %s: %s\n", filename, strerror(errno));
        close(fd);
        return -1;
    }

#ifdef MADV_SEQUENTIAL
    madvise((void *)map, sb.st_size, MADV_SEQUENTIAL);
#endif

    end = map + sb.st_size;
    p = map;

    if (g_verbose) printf("%s %sProcessing %-14s: %s (%.2f MB)%s\n",
                           ICON_INFO, COL_BOLD, "MISP JSON", filename,
                           sb.st_size / (1024.0 * 1024.0), COL_RESET);

    /* Detect format: {"Event":{...}} or {"response":[...]} */
    p = skip_ws(p, end);
    if (p >= end || *p != '{') {
        fprintf(stderr, "%s %s is not a JSON object\n", ICON_WARN, filename);
        goto done;
    }
    p++; /* skip '{' */

    p = skip_ws(p, end);
    if (p >= end || *p != '"') goto done;

    p = extract_json_str(p, end, first_key, sizeof(first_key));
    p = skip_ws(p, end);
    if (p >= end || *p != ':') goto done;
    p++;
    p = skip_ws(p, end);

    if (strcmp(first_key, "Event") == 0) {
        /* Single event: {"Event": {...}} */
        p = parse_misp_event(p, end, &emitted, &skipped);
    } else if (strcmp(first_key, "Attribute") == 0) {
        misp_parse_search_list(p, end, &emitted, &skipped);
    } else if (strcmp(first_key, "response") == 0 && p < end && *p == '{') {
        /* Attribute search: {"response":{"Attribute":[...]}} */
        misp_parse_response_object(p, end, filename, &emitted, &skipped);
    } else if (strcmp(first_key, "response") == 0) {
        /* Event search: {"response": [{"Event":{...}}, ...]} */
        if (p >= end || *p != '[') {
            fprintf(stderr, "%s %s: MISP response is not an event list or an Attribute object\n",
                    ICON_WARN, filename);
            goto done;
        }
        p++; /* skip '[' */

        while (p < end) {
            p = skip_ws(p, end);
            if (p >= end || *p == ']') break;
            if (*p == ',') { p++; continue; }
            if (*p != '{') { p = skip_json_val(p, end); continue; }
            p++; /* skip '{' of wrapper */
            p = skip_ws(p, end);

            /* Expect "Event": {...} inside each array element */
            if (p < end && *p == '"') {
                char evkey[32];
                p = extract_json_str(p, end, evkey, sizeof(evkey));
                p = skip_ws(p, end);
                if (p < end && *p == ':') {
                    p++;
                    p = skip_ws(p, end);
                    if (strcmp(evkey, "Event") == 0) {
                        p = parse_misp_event(p, end, &emitted, &skipped);
                    } else {
                        p = skip_json_val(p, end);
                    }
                }
            }

            /* Skip remaining keys in wrapper object */
            while (p < end) {
                p = skip_ws(p, end);
                if (p >= end || *p == '}') break;
                if (*p == ',') { p++; continue; }
                if (*p == '"') {
                    p = skip_json_str(p, end);
                    p = skip_ws(p, end);
                    if (p < end && *p == ':') {
                        p++;
                        p = skip_json_val(p, end);
                    }
                } else {
                    p = skip_json_val(p, end);
                }
            }
            if (p < end && *p == '}') p++;
        }
    } else {
        fprintf(stderr, "%s %s: unrecognized MISP format (first key: \"%s\")\n",
                ICON_WARN, filename, first_key);
    }

done:
    if (g_verbose) {
        printf("   %s Loaded %zu IOCs from MISP", ICON_CHECK, emitted);
        if (skipped > 0)
            printf(" (%zu skipped: non-IDS or unsupported type)", skipped);
        printf("\n");
    }

    munmap((void *)map, sb.st_size);
    close(fd);
    return 0;
}

/* ============================================================================
 * BUILDER UTILITIES
 * ============================================================================ */
static int cmp_ip(const void *a, const void *b) {
    builder_ip_t *ipA = (builder_ip_t*)a;
    builder_ip_t *ipB = (builder_ip_t*)b;
    return (ipA->start > ipB->start) - (ipA->start < ipB->start);
}

static int cmp_ipv6(const void *a, const void *b) {
    builder_ipv6_t *ipA = (builder_ipv6_t*)a;
    builder_ipv6_t *ipB = (builder_ipv6_t*)b;
    return memcmp(ipA->start, ipB->start, 16);
}

/* ============================================================================
 * DISJOINT RANGES
 *
 * The readers binary-search the sorted range arrays, which only works when no
 * two ranges overlap. Feeds overlap all the time: a /24 from one blocklist
 * contains a /32 from another, and the CMDB tags an address a CTI feed also
 * lists. After sorting, overlapping ranges are cut at every boundary and each
 * piece gets the merge of every range covering it. Adjacent pieces with the
 * same record are joined again.
 * ============================================================================ */
typedef struct {
    uint64_t pos;  /* start, or end + 1 (2^32 for the last address) */
    uint32_t meta;
    uint8_t open;
} ev4_t;

static int cmp_ev4(const void *a, const void *b) {
    const ev4_t *x = (const ev4_t *)a, *y = (const ev4_t *)b;
    return (x->pos > y->pos) - (x->pos < y->pos);
}

/* Active covering records: a multiset kept as a small array. */
typedef struct {
    uint32_t *items;
    size_t count, cap;
} active_t;

static void active_add(active_t *a, uint32_t meta) {
    if (a->count == a->cap) {
        a->cap = a->cap ? a->cap * 2 : 16;
        a->items = xrealloc(a->items, a->cap * sizeof(uint32_t));
    }
    a->items[a->count++] = meta;
}

static void active_del(active_t *a, uint32_t meta) {
    for (size_t i = 0; i < a->count; i++) {
        if (a->items[i] == meta) {
            a->items[i] = a->items[--a->count];
            return;
        }
    }
}

static uint32_t active_merge(const active_t *a) {
    uint32_t m = a->items[0];
    for (size_t i = 1; i < a->count; i++) m = merge_meta(m, a->items[i]);
    return m;
}

static void flatten_ipv4(void) {
    size_t n = ip_db.count, ne = 0, out_n = 0, out_cap;
    uint32_t max_end;
    int overlap = 0;
    ev4_t *ev;
    builder_ip_t *out;
    active_t act = {0};

    if (n < 2) return;
    max_end = ip_db.items[0].end;
    for (size_t i = 1; i < n && !overlap; i++) {
        if (ip_db.items[i].start <= max_end) overlap = 1;
        if (ip_db.items[i].end > max_end) max_end = ip_db.items[i].end;
    }
    if (!overlap) return;

    ev = xmalloc(2 * n * sizeof(ev4_t));
    for (size_t i = 0; i < n; i++) {
        ev[ne++] = (ev4_t){ip_db.items[i].start, ip_db.items[i].meta_idx, 1};
        ev[ne++] = (ev4_t){(uint64_t)ip_db.items[i].end + 1, ip_db.items[i].meta_idx, 0};
    }
    qsort(ev, ne, sizeof(ev4_t), cmp_ev4);

    out_cap = n;
    out = xmalloc(out_cap * sizeof(builder_ip_t));
    for (size_t i = 0; i < ne;) {
        uint64_t pos = ev[i].pos;
        while (i < ne && ev[i].pos == pos) {
            if (ev[i].open)
                active_add(&act, ev[i].meta);
            else
                active_del(&act, ev[i].meta);
            i++;
        }
        if (act.count > 0 && i < ne) {
            uint32_t meta = active_merge(&act);
            uint32_t s = (uint32_t)pos, e = (uint32_t)(ev[i].pos - 1);
            if (out_n > 0 && out[out_n - 1].meta_idx == meta && (uint64_t)out[out_n - 1].end + 1 == pos) {
                out[out_n - 1].end = e;
            } else {
                if (out_n == out_cap) {
                    out_cap *= 2;
                    out = xrealloc(out, out_cap * sizeof(builder_ip_t));
                }
                out[out_n++] = (builder_ip_t){s, e, meta};
            }
        }
    }
    free(act.items);
    free(ev);
    free(ip_db.items);
    ip_db.items = out;
    ip_db.count = out_n;
    ip_db.cap = out_cap;
}

/* 128-bit positions, big-endian, with a 17th bit for the end + 1 of the
 * last address. */
typedef struct {
    uint8_t pos[16];
    uint8_t past_end;
    uint8_t open;
    uint32_t meta;
} ev6_t;

static int cmp_ev6(const void *a, const void *b) {
    const ev6_t *x = (const ev6_t *)a, *y = (const ev6_t *)b;
    if (x->past_end != y->past_end) return x->past_end ? 1 : -1;
    return memcmp(x->pos, y->pos, 16);
}

static int ev6_same(const ev6_t *x, const ev6_t *y) {
    return x->past_end == y->past_end && memcmp(x->pos, y->pos, 16) == 0;
}

static void v6_inc(const uint8_t *in, uint8_t *out, uint8_t *carry) {
    int c = 1;
    for (int k = 15; k >= 0; k--) {
        int v = in[k] + c;
        out[k] = (uint8_t)v;
        c = v >> 8;
    }
    *carry = (uint8_t)c;
}

static void v6_dec(const ev6_t *p, uint8_t *out) {
    if (p->past_end) {
        memset(out, 0xFF, 16);
        return;
    }
    memcpy(out, p->pos, 16);
    for (int k = 15; k >= 0; k--) {
        if (out[k]-- != 0) break;
    }
}

static void flatten_ipv6(void) {
    size_t n = ip6_db.count, ne = 0, out_n = 0, out_cap;
    uint8_t max_end[16];
    int overlap = 0;
    ev6_t *ev;
    builder_ipv6_t *out;
    active_t act = {0};

    if (n < 2) return;
    memcpy(max_end, ip6_db.items[0].end, 16);
    for (size_t i = 1; i < n && !overlap; i++) {
        if (memcmp(ip6_db.items[i].start, max_end, 16) <= 0) overlap = 1;
        if (memcmp(ip6_db.items[i].end, max_end, 16) > 0) memcpy(max_end, ip6_db.items[i].end, 16);
    }
    if (!overlap) return;

    ev = xmalloc(2 * n * sizeof(ev6_t));
    for (size_t i = 0; i < n; i++) {
        ev6_t o = {{0}, 0, 1, ip6_db.items[i].meta_idx};
        ev6_t c = {{0}, 0, 0, ip6_db.items[i].meta_idx};
        memcpy(o.pos, ip6_db.items[i].start, 16);
        v6_inc(ip6_db.items[i].end, c.pos, &c.past_end);
        ev[ne++] = o;
        ev[ne++] = c;
    }
    qsort(ev, ne, sizeof(ev6_t), cmp_ev6);

    out_cap = n;
    out = xmalloc(out_cap * sizeof(builder_ipv6_t));
    for (size_t i = 0; i < ne;) {
        size_t first = i;
        while (i < ne && ev6_same(&ev[i], &ev[first])) {
            if (ev[i].open)
                active_add(&act, ev[i].meta);
            else
                active_del(&act, ev[i].meta);
            i++;
        }
        if (act.count > 0 && i < ne) {
            uint32_t meta = active_merge(&act);
            uint8_t e[16];
            v6_dec(&ev[i], e);
            if (out_n > 0 && out[out_n - 1].meta_idx == meta) {
                uint8_t nx[16], carry;
                v6_inc(out[out_n - 1].end, nx, &carry);
                if (!carry && memcmp(nx, ev[first].pos, 16) == 0) {
                    memcpy(out[out_n - 1].end, e, 16);
                    continue;
                }
            }
            if (out_n == out_cap) {
                out_cap *= 2;
                out = xrealloc(out, out_cap * sizeof(builder_ipv6_t));
            }
            memcpy(out[out_n].start, ev[first].pos, 16);
            memcpy(out[out_n].end, e, 16);
            out[out_n].meta_idx = meta;
            out_n++;
        }
    }
    free(act.items);
    free(ev);
    free(ip6_db.items);
    ip6_db.items = out;
    ip6_db.count = out_n;
    ip6_db.cap = out_cap;
}

/* The rows as declared, saved before flatten_*() rewrites ip_db/ip6_db.
 * write_thrt() stores them so a fold reloads exact networks. */
static builder_ip_t *g_src_v4 = NULL;
static size_t g_src_v4_n = 0;
static builder_ipv6_t *g_src_v6 = NULL;
static size_t g_src_v6_n = 0;

static void save_source_rows(void) {
    free(g_src_v4);
    free(g_src_v6);
    g_src_v4 = NULL;
    g_src_v6 = NULL;
    g_src_v4_n = ip_db.count;
    g_src_v6_n = ip6_db.count;
    if (g_src_v4_n) {
        g_src_v4 = xmalloc(g_src_v4_n * sizeof(builder_ip_t));
        memcpy(g_src_v4, ip_db.items, g_src_v4_n * sizeof(builder_ip_t));
    }
    if (g_src_v6_n) {
        g_src_v6 = xmalloc(g_src_v6_n * sizeof(builder_ipv6_t));
        memcpy(g_src_v6, ip6_db.items, g_src_v6_n * sizeof(builder_ipv6_t));
    }
}

static void free_source_rows(void) {
    free(g_src_v4);
    free(g_src_v6);
    g_src_v4 = NULL;
    g_src_v6 = NULL;
    g_src_v4_n = g_src_v6_n = 0;
}

/* Drop metadata no row points at. Flattening and folds create merged
 * records; without this, each fold would carry the ones it no longer
 * uses into the next file. */
static void compact_meta(void) {
    uint32_t *remap;
    size_t w = 0;
    if (meta_db.count == 0) return;
    remap = xmalloc(meta_db.count * sizeof(uint32_t));
    for (size_t i = 0; i < meta_db.count; i++) remap[i] = UINT32_MAX;
#define MARK(arr, n) for (size_t i = 0; i < (n); i++) remap[(arr)[i].meta_idx] = 0
    MARK(ip_db.items, ip_db.count);
    MARK(ip6_db.items, ip6_db.count);
    MARK(str_db.items, str_db.count);
    MARK(g_src_v4, g_src_v4_n);
    MARK(g_src_v6, g_src_v6_n);
#undef MARK
    for (size_t i = 0; i < meta_db.count; i++) {
        if (remap[i] == UINT32_MAX) continue;
        meta_db.items[w] = meta_db.items[i];
        remap[i] = (uint32_t)w++;
    }
    if (w != meta_db.count) {
#define REMAP(arr, n) for (size_t i = 0; i < (n); i++) (arr)[i].meta_idx = remap[(arr)[i].meta_idx]
        REMAP(ip_db.items, ip_db.count);
        REMAP(ip6_db.items, ip6_db.count);
        REMAP(str_db.items, str_db.count);
        REMAP(g_src_v4, g_src_v4_n);
        REMAP(g_src_v6, g_src_v6_n);
#undef REMAP
        meta_db.count = w;
    }
    free(remap);
}

static void build_ip_accel(void) {
    memset(ip_accel_db, 0, sizeof(ip_accel_db));
    for (size_t i = 0; i < ip_db.count; i++) {
        uint32_t idx_start = ip_db.items[i].start >> (32 - THRT_IP_ACCEL_BITS);
        uint32_t idx_end   = ip_db.items[i].end   >> (32 - THRT_IP_ACCEL_BITS);
        for (uint32_t k = idx_start; k <= idx_end; k++) {
            if (ip_accel_db[k].range_count == 0) ip_accel_db[k].range_start_idx = i;
            ip_accel_db[k].range_count = (i - ip_accel_db[k].range_start_idx) + 1;
        }
    }
}

/* 32 bits per string keeps the false positive rate near 0.07 % with three
 * probes. A power of two, so readers index it with a mask, at least 64 Kbit
 * and at most BLOOM_BITS_DEFAULT, which large databases keep. */
static uint32_t bloom_bits_for(size_t strings) {
    uint64_t want = (uint64_t)strings * 32u, bits = 1u << 16;
    while (bits < want && bits < BLOOM_BITS_DEFAULT) bits <<= 1;
    return (uint32_t)bits;
}

static void build_bloom(void) {
    bloom_size_bits = bloom_bits_for(str_db.count);
    bloom_filter = xcalloc(1, bloom_size_bits / 8);
    for (size_t i = 0; i < str_db.count; i++) {
        uint64_t h = str_db.items[i].hash;
        uint32_t h1 = (uint32_t)h;
        uint32_t h2 = thrt_bloom_h2(h1);
        for (int k = 0; k < 3; k++) {
            uint32_t bit_idx = (h1 + k * h2) & (bloom_size_bits - 1);
            bloom_filter[bit_idx / 8] |= (1 << (bit_idx & 7));
        }
    }
}

/* Compute CRC32C checksum */
static uint32_t compute_file_checksum(FILE *f, size_t checksum_field_offset) {
    uint32_t crc = 0xFFFFFFFF;
    uint8_t buffer[8192];
    size_t bytes_read;
    size_t current_pos = 0;

    fseek(f, 0, SEEK_SET);

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            size_t file_pos = current_pos + i;
            if (file_pos >= checksum_field_offset &&
                file_pos < checksum_field_offset + sizeof(uint32_t)) {
                continue;
            }
            crc = crc32c_platform(crc, &buffer[i], 1);
        }
        current_pos += bytes_read;
    }

    return crc ^ 0xFFFFFFFF;
}

#include "stix_feed.inc"

/* ============================================================================
 * PROCESS FILE (with layer detection)
 * ============================================================================ */
static void process_file(const char* filename) {
    /* Set default source to filename (basename) */
    const char* basename = strrchr(filename, '/');
    char *dot;
    const char* ext;
    basename = basename ? basename + 1 : filename;
    snprintf(g_default_source, sizeof(g_default_source), "%s", basename);
    dot = strrchr(g_default_source, '.');
    if (dot) *dot = 0;

    ext = strrchr(filename, '.');
    /* sample.stix.json keeps one suffix after the first cut. Drop it so the
     * feed name is the stem the operator typed. */
    if (strcasestr(filename, ".stix.json") != NULL ||
        (ext && strcasecmp(ext, ".stix") == 0)) {
        char *suf = strrchr(g_default_source, '.');
        if (suf && strcasecmp(suf, ".stix") == 0)
            *suf = '\0';
    }
    if (!ext) {
        fprintf(stderr, "%s No extension found for %s, skipping.\n", ICON_WARN, filename);
        return;
    }

    /* Tags files */
    if (strcasecmp(ext, ".tags") == 0) {
        process_tags_csv(filename);
    }
    else if (strcasestr(filename, ".tags.json")) {
        process_tags_json(filename);
    }
    /* Standard formats */
    else if (strcasecmp(ext, ".csv") == 0) {
        process_csv(filename);
    }
    else if (strcasecmp(ext, ".lookup") == 0) {
        process_rsyslog_json(filename);
    }
    else if (strcasecmp(ext, ".txt") == 0 || strcasecmp(ext, ".ioc") == 0) {
        process_plaintext(filename);
    }
    /* STIX 2.1 bundles (.stix, .stix.json). Before .json: the suffix is .json. */
    else if (strcasestr(filename, ".stix.json") || strcasecmp(ext, ".stix") == 0) {
        process_stix_json(filename);
    }
    /* MISP JSON exports (.misp, .misp.json) */
    else if (strcasestr(filename, ".misp.json") || strcasecmp(ext, ".misp") == 0) {
        if (process_misp_json(filename) != 0)
            exit(1);
    }
    else if (strcasecmp(ext, ".json") == 0) {
        process_cti_json(filename);
    }
    else {
        fprintf(stderr, "%s Unsupported extension %s for %s\n", ICON_WARN, ext, filename);
    }
}

/* ============================================================================
 * LOAD EXISTING DATABASE (for incremental mode)
 * Re-imports all entries from an existing V4 .thrt into builder arrays.
 * ============================================================================ */
static void load_existing_thrt(const char *filename) {
    int fd = open(filename, O_RDONLY);
    struct stat sb;
    void *map;
    thrt_header_t *hdr;
    char *base;
    thrt_metadata_t *meta;
    thrt_ipv4_range_t *ipv4;
    thrt_ipv6_range_t *ipv6;
    thrt_hash_entry_t *ht;
    char *str_base;
    if (fd < 0) {
        fprintf(stderr, "%s Cannot open existing DB %s: %s\n", ICON_WARN, filename, strerror(errno));
        fprintf(stderr, "  Incremental mode requires an existing database. Build a full one first.\n");
        exit(1);
    }

    if (fstat(fd, &sb) != 0 || sb.st_size < (off_t)sizeof(thrt_header_t)) {
        fprintf(stderr, "%s Existing DB %s is not a .thrt. Build a fresh one first.\n", ICON_WARN, filename);
        close(fd);
        exit(1);
    }
    map = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); close(fd); exit(1); }

    hdr = (thrt_header_t*)map;
    {
        char why[512];
        if (thrt_validate((const unsigned char *)map, (size_t)sb.st_size, filename, why, sizeof why) !=
            THRT_VALID_OK) {
            fprintf(stderr, "%s %s. Build a fresh one first.\n", ICON_WARN, why);
            munmap(map, sb.st_size); close(fd); exit(1);
        }
    }

    base = (char*)map;
    meta = (thrt_metadata_t*)(base + hdr->offset_metadata);
    ipv4 = (thrt_ipv4_range_t*)(base + hdr->offset_ipv4);
    ipv6 = (thrt_ipv6_range_t*)(base + hdr->offset_ipv6);
    ht = (thrt_hash_entry_t*)(base + hdr->offset_hashtable);
    str_base = base + hdr->offset_strings;

    /* Import feed names (preserve exact ordering for bitmask compat) */
    if (hdr->feed_count > 0 && hdr->offset_feeds > 0) {
        thrt_feed_entry_t *feeds = (thrt_feed_entry_t*)(base + hdr->offset_feeds);
        for (uint32_t i = 0; i < hdr->feed_count && i < MAX_FEEDS; i++) {
            get_feed_idx(feeds[i].name);  /* This creates feed entries in order */
        }
    }

    g_public_feeds |= hdr->public_feed_mask;

    /* Import metadata entries (direct copy, preserving indices) */
    for (uint32_t i = 0; i < hdr->metadata_count; i++) {
        builder_meta_v4_t m = {
            .confidence    = meta[i].confidence,
            .confidence_r  = meta[i].confidence_r,
            .type_mask     = meta[i].type_mask,
            .tlp_mask      = meta[i].tlp_mask,
            .category_mask = meta[i].category_mask,
            .feed_mask     = meta[i].feed_mask,
            .tags_offset   = 0, /* Re-import tags and labels below */
            .tags_length   = 0,
            .labels_offset = 0,
            .labels_length = 0
        };
        ensure_capacity();
        meta_db.items[meta_db.count++] = m;

        /* Re-import tags and labels into our string pool */
        if (meta[i].tags_offset > 0 && meta[i].tags_length > 0) {
            uint32_t new_offset;
            ensure_capacity();
            new_offset = str_pool.len;
            memcpy(str_pool.data + new_offset, str_base + meta[i].tags_offset, meta[i].tags_length);
            str_pool.len += meta[i].tags_length;
            str_pool.data[str_pool.len++] = '\0';
            meta_db.items[i].tags_offset = new_offset;
            meta_db.items[i].tags_length = meta[i].tags_length;
        }
        if (meta[i].labels_offset > 0 && meta[i].labels_length > 0) {
            uint32_t new_offset;
            ensure_capacity();
            new_offset = str_pool.len;
            memcpy(str_pool.data + new_offset, str_base + meta[i].labels_offset, meta[i].labels_length);
            str_pool.len += meta[i].labels_length;
            str_pool.data[str_pool.len++] = '\0';
            meta_db.items[i].labels_offset = new_offset;
            meta_db.items[i].labels_length = meta[i].labels_length;
        }
    }

    /* Import the declared address rows, not the disjoint lookup pieces:
     * a fold merges, withdraws and evicts exact networks. */
    (void)ipv4;
    (void)ipv6;
    ipv4 = (thrt_ipv4_range_t*)(base + hdr->offset_src_ipv4);
    ipv6 = (thrt_ipv6_range_t*)(base + hdr->offset_src_ipv6);
    for (uint32_t i = 0; i < hdr->src_ipv4_count; i++) {
        if (ipv4[i].meta_idx >= hdr->metadata_count) {
            fprintf(stderr, "%s Existing DB %s is corrupt (IPv4 row %u)\n", ICON_WARN, filename, i);
            exit(1);
        }
        ensure_capacity();
        ip_db.items[ip_db.count++] = (builder_ip_t){
            .start = ipv4[i].ip_start,
            .end   = ipv4[i].ip_end,
            .meta_idx = ipv4[i].meta_idx
        };
    }
    for (uint32_t i = 0; i < hdr->src_ipv6_count; i++) {
        builder_ipv6_t *e;
        if (ipv6[i].meta_idx >= hdr->metadata_count) {
            fprintf(stderr, "%s Existing DB %s is corrupt (IPv6 row %u)\n", ICON_WARN, filename, i);
            exit(1);
        }
        ensure_capacity();
        e = &ip6_db.items[ip6_db.count++];
        memcpy(e->start, ipv6[i].ip_start, 16);
        memcpy(e->end, ipv6[i].ip_end, 16);
        e->meta_idx = ipv6[i].meta_idx;
    }

    /* Import string entries (domains, hashes, emails) */
    for (uint32_t i = 0; i < hdr->hash_slots; i++) {
        const char *str_val;
        size_t len;
        uint32_t new_offset;
        if (ht[i].meta_idx == 0xFFFFFFFF) continue; /* Empty slot */

        str_val = str_base + ht[i].string_offset;
        len = strlen(str_val);

        ensure_capacity();
        new_offset = str_pool.len;
        memcpy(str_pool.data + new_offset, str_val, len + 1);
        str_pool.len += len + 1;

        str_db.items[str_db.count++] = (builder_string_t){
            .hash = ht[i].hash_key,
            .offset = new_offset,
            .meta_idx = ht[i].meta_idx
        };
    }

    if (g_verbose) {
        printf("%s %sLoaded existing DB:%s %s (v%u)\n", ICON_DB, COL_BOLD, COL_RESET, filename, (unsigned)hdr->version);
        printf("   %u IPv4, %u IPv6, %zu strings, %u feeds, %u meta\n",
               hdr->ipv4_range_count, hdr->ipv6_range_count, str_db.count,
               hdr->feed_count, hdr->metadata_count);
    }

    munmap(map, sb.st_size);
    close(fd);
}

/* ============================================================================
 * WRITE THRT DATABASE (V4)
 * ============================================================================ */
/* Drop IOC rows named by the delete set. Meta rows stay. The caller
 * rebuilds dedup when another page may add those values back. */
static void apply_delete_set(void) {
    size_t orig;
    size_t w;
    delete_entry_t probe;

    if (!g_delete_set || g_delete_set->count == 0)
        return;

    orig = ip_db.count;
    w = 0;
    for (size_t i = 0; i < ip_db.count; i++) {
        memset(&probe, 0, sizeof probe);
        probe.kind = DEL_KIND_IPV4;
        probe.v4_start = ip_db.items[i].start;
        probe.v4_end = ip_db.items[i].end;
        probe.key = ioc_key_ipv4(probe.v4_start, probe.v4_end);
        if (!delete_set_has(&probe))
            ip_db.items[w++] = ip_db.items[i];
    }
    if (g_verbose && w < orig)
        printf("   [DELETE] Removed %zu/%zu IPv4 entries\n", orig - w, orig);
    ip_db.count = w;

    orig = ip6_db.count;
    w = 0;
    for (size_t i = 0; i < ip6_db.count; i++) {
        memset(&probe, 0, sizeof probe);
        probe.kind = DEL_KIND_IPV6;
        memcpy(probe.v6_start, ip6_db.items[i].start, 16);
        memcpy(probe.v6_end, ip6_db.items[i].end, 16);
        probe.key = ioc_key_ipv6(probe.v6_start, probe.v6_end);
        if (!delete_set_has(&probe))
            ip6_db.items[w++] = ip6_db.items[i];
    }
    if (g_verbose && w < orig)
        printf("   [DELETE] Removed %zu/%zu IPv6 entries\n", orig - w, orig);
    ip6_db.count = w;

    orig = str_db.count;
    w = 0;
    for (size_t i = 0; i < str_db.count; i++) {
        memset(&probe, 0, sizeof probe);
        probe.kind = DEL_KIND_STR;
        probe.str = str_pool.data + str_db.items[i].offset;
        probe.key = ioc_key_str(str_db.items[i].hash);
        if (!delete_set_has(&probe))
            str_db.items[w++] = str_db.items[i];
    }
    if (g_verbose && w < orig)
        printf("   [DELETE] Removed %zu/%zu string entries\n", orig - w, orig);
    str_db.count = w;
}

/* The string hash is CRC32C, which anyone can steer: a feed can ship
 * values whose home slots pile up on the slot of a value another feed
 * lists, and push it past the THRT_PROBE_MAX slots a lookup walks. Such
 * a value would be in the file and never found. A table like that is not
 * written. The run of occupied slots around the entry is counted per
 * feed, so the error names the feed that filled it. */
static void report_probe_run(const thrt_hash_entry_t *ht, uint32_t slots, uint32_t at, uint32_t dist) {
    uint32_t mask = slots - 1, lo = at, n = 0;
    size_t per_feed[MAX_FEEDS] = {0};
    fprintf(stderr, "%sA string sits %u slots from its home slot; lookups stop at %d.\n", ICON_WARN, dist,
            THRT_PROBE_MAX);
    while (ht[(lo - 1) & mask].meta_idx != 0xFFFFFFFFu && n < slots) {
        lo = (lo - 1) & mask;
        n++;
    }
    n = 0;
    for (uint32_t i = lo; ht[i].meta_idx != 0xFFFFFFFFu && n < slots; i = (i + 1) & mask, n++) {
        uint64_t fm = meta_db.items[ht[i].meta_idx].feed_mask;
        for (int b = 0; b < MAX_FEEDS; b++)
            if (fm >> b & 1u) per_feed[b]++;
    }
    fprintf(stderr, "  The run of %u occupied slots holds values from:\n", n);
    for (size_t i = 0; i < feed_db.count; i++) {
        uint8_t b = feed_db.items[i].feed_idx;
        if (b < MAX_FEEDS && per_feed[b] > 0)
            fprintf(stderr, "    %-32s %zu\n", feed_db.items[i].name, per_feed[b]);
    }
    fprintf(stderr, "  Values whose hashes collide like this are crafted. Drop the feed that\n"
                    "  holds most of them and build again. The previous database is kept.\n");
}

static void write_thrt(const char *filename) {
    char tmp_filename[PATH_MAX + 32];
    FILE *f;
    uint32_t hash_slots;
    thrt_hash_entry_t *ht;
    thrt_header_t hdr = {0};
    uint64_t offset;
    size_t accel_pad;
    uint32_t checksum;

    apply_delete_set();

    /* Sort arrays */
    if (ip_db.count > 0) qsort(ip_db.items, ip_db.count, sizeof(builder_ip_t), cmp_ip);
    if (ip6_db.count > 0) qsort(ip6_db.items, ip6_db.count, sizeof(builder_ipv6_t), cmp_ipv6);
    save_source_rows();
    flatten_ipv4();
    flatten_ipv6();
    compact_meta();

    build_ip_accel();
    build_bloom();

    /* Atomic file replacement */
       /* room for ".tmp.<pid>" suffix */
    snprintf(tmp_filename, sizeof(tmp_filename), "%s.tmp.%d", filename, getpid());

    f = fopen(tmp_filename, "w+b");
    if (!f) { perror("fopen output"); exit(1); }

    /* Build hash table */
    hash_slots = 1024;
    while (hash_slots < str_db.count * 2) hash_slots *= 2;
    ht = xcalloc(hash_slots, sizeof(thrt_hash_entry_t));
    memset(ht, 0xFF, hash_slots * sizeof(thrt_hash_entry_t));

    for (size_t i = 0; i < str_db.count; i++) {
        uint64_t h = str_db.items[i].hash;
        uint32_t idx = (uint32_t)h & (hash_slots - 1), dist = 0;
        while (ht[idx].meta_idx != 0xFFFFFFFF) {
            idx = (idx + 1) & (hash_slots - 1);
            dist++;
        }
        ht[idx].hash_key = h;
        ht[idx].string_offset = str_db.items[i].offset;
        ht[idx].meta_idx = str_db.items[i].meta_idx;
        if (dist >= THRT_PROBE_MAX) {
            report_probe_run(ht, hash_slots, idx, dist);
            fclose(f);
            unlink(tmp_filename);
            exit(1);
        }
    }

    /* Calculate offsets */
    hdr.magic = THRT_MAGIC;
    hdr.version = THRT_VERSION;
    hdr.metadata_count = meta_db.count;
    hdr.ipv4_range_count = ip_db.count;
    hdr.ipv6_range_count = ip6_db.count;
    hdr.hash_slots = hash_slots;
    hdr.bloom_size_bits = bloom_size_bits;
    hdr.feed_count = feed_db.count;
    hdr.checksum_offset = offsetof(thrt_header_t, checksum);

    offset = sizeof(thrt_header_t);
    hdr.offset_metadata = offset;  offset += meta_db.count * sizeof(thrt_metadata_t);
    hdr.offset_ipv4 = offset;      offset += ip_db.count * sizeof(thrt_ipv4_range_t);
    hdr.offset_ipv6 = offset;      offset += ip6_db.count * sizeof(thrt_ipv6_range_t);
    hdr.offset_hashtable = offset; offset += hash_slots * sizeof(thrt_hash_entry_t);
    hdr.offset_strings = offset;   offset += str_pool.len;
    /* The string pool has any length. Pad so the accelerator table starts
     * on an 8-byte boundary. */
    accel_pad = (size_t)((8 - (offset % 8)) % 8);
    offset += accel_pad;
    hdr.offset_ip_accel = offset;  offset += sizeof(ip_accel_db);
    hdr.offset_bloom = offset;     offset += (bloom_size_bits / 8);
    hdr.offset_feeds = offset;     offset += feed_db.count * sizeof(thrt_feed_entry_t);
    hdr.public_feed_mask = g_public_feeds;
    hdr.offset_src_ipv4 = offset;  offset += g_src_v4_n * sizeof(thrt_ipv4_range_t);
    hdr.offset_src_ipv6 = offset;  offset += g_src_v6_n * sizeof(thrt_ipv6_range_t);
    hdr.src_ipv4_count = (uint32_t)g_src_v4_n;
    hdr.src_ipv6_count = (uint32_t)g_src_v6_n;
    hdr.total_size = offset;

    /* Write header */
    fwrite(&hdr, sizeof(hdr), 1, f);

    /* Write metadata (V4 format) */
    for (size_t i = 0; i < meta_db.count; i++) {
        thrt_metadata_t m = {
            .confidence = meta_db.items[i].confidence,
            .type_mask = meta_db.items[i].type_mask,
            .tlp_mask = meta_db.items[i].tlp_mask,
            .confidence_r = meta_db.items[i].confidence_r,
            .category_mask = meta_db.items[i].category_mask,
            .pad2 = 0,
            .feed_mask = meta_db.items[i].feed_mask,
            .tags_offset = meta_db.items[i].tags_offset,
            .tags_length = meta_db.items[i].tags_length,
            .labels_offset = meta_db.items[i].labels_offset,
            .labels_length = meta_db.items[i].labels_length
        };
        fwrite(&m, sizeof(m), 1, f);
    }

    /* Write IP ranges */
    for (size_t i = 0; i < ip_db.count; i++) {
        thrt_ipv4_range_t r = {ip_db.items[i].start, ip_db.items[i].end, ip_db.items[i].meta_idx, 0};
        fwrite(&r, sizeof(r), 1, f);
    }
    for (size_t i = 0; i < ip6_db.count; i++) {
        thrt_ipv6_range_t r;
        memcpy(r.ip_start, ip6_db.items[i].start, 16);
        memcpy(r.ip_end, ip6_db.items[i].end, 16);
        r.meta_idx = ip6_db.items[i].meta_idx;
        r.pad = 0;
        fwrite(&r, sizeof(r), 1, f);
    }

    /* Write hash table and string pool.  A feed that parses to zero entries
     * leaves str_pool (and, at the minimum table size, the hash/bloom bases)
     * NULL; fwrite() with a NULL first argument is undefined even when the
     * element count is 0, so skip the empty writes (they emit no bytes anyway,
     * keeping the on-disk layout identical). */
    if (hash_slots > 0) fwrite(ht, sizeof(thrt_hash_entry_t), hash_slots, f);
    if (str_pool.len > 0) fwrite(str_pool.data, 1, str_pool.len, f);
    if (accel_pad > 0) {
        static const unsigned char zeros[8];
        fwrite(zeros, 1, accel_pad, f);
    }

    /* Write acceleration structures (ip_accel_db is a fixed array, never NULL) */
    fwrite(ip_accel_db, sizeof(ip_accel_db), 1, f);
    if (bloom_size_bits > 0) fwrite(bloom_filter, 1, bloom_size_bits / 8, f);

    /* Write feed name table */
    for (size_t i = 0; i < feed_db.count; i++) {
        thrt_feed_entry_t fe = {0};
        snprintf(fe.name, THRT_FEED_NAME_MAX, "%s", feed_db.items[i].name);
        fwrite(&fe, sizeof(fe), 1, f);
    }

    /* Write the declared address rows */
    for (size_t i = 0; i < g_src_v4_n; i++) {
        thrt_ipv4_range_t r = {g_src_v4[i].start, g_src_v4[i].end, g_src_v4[i].meta_idx, 0};
        fwrite(&r, sizeof(r), 1, f);
    }
    for (size_t i = 0; i < g_src_v6_n; i++) {
        thrt_ipv6_range_t r;
        memcpy(r.ip_start, g_src_v6[i].start, 16);
        memcpy(r.ip_end, g_src_v6[i].end, 16);
        r.meta_idx = g_src_v6[i].meta_idx;
        r.pad = 0;
        fwrite(&r, sizeof(r), 1, f);
    }
    free_source_rows();

    /* Compute and write checksum */
    fflush(f);
    checksum = compute_file_checksum(f, hdr.checksum_offset);
    fseek(f, hdr.checksum_offset, SEEK_SET);
    fwrite(&checksum, sizeof(checksum), 1, f);

    /* A short write (a full disk) must not be renamed over the live file. */
    if (ferror(f) || fflush(f) != 0 || fsync(fileno(f)) != 0 || ftell(f) < 0) {
        fprintf(stderr, "%s Failed to write %s: %s\n", ICON_WARN, tmp_filename, strerror(errno));
        fclose(f);
        unlink(tmp_filename);
        exit(1);
    }
    if (fclose(f) != 0) {
        fprintf(stderr, "%s Failed to close %s: %s\n", ICON_WARN, tmp_filename, strerror(errno));
        unlink(tmp_filename);
        exit(1);
    }
    free(ht);
    free(bloom_filter);

    /* Atomic rename */
    if (rename(tmp_filename, filename) != 0) {
        fprintf(stderr, "%s Failed to rename %s -> %s: %s\n",
                ICON_WARN, tmp_filename, filename, strerror(errno));
        unlink(tmp_filename);
        exit(1);
    }

    /* Statistics */
    if (g_verbose) {
        printf("\n%s %sDATABASE STATISTICS (V4)%s\n", ICON_STAT, COL_BOLD, COL_RESET);
        printf("----------------------------------------\n");
        printf("   %s Output File : %s\n", ICON_DB, filename);
        printf("   %s Total Size  : %.2f MB\n", ICON_INFO, hdr.total_size / (1024.0 * 1024.0));
        printf("   %s Checksum    : %s0x%08X%s (CRC32C)\n", ICON_CHECK, COL_GREEN, checksum, COL_RESET);
        printf("   %s Total Items : %zu\n", ICON_STAT, ip_db.count + ip6_db.count + str_db.count);
        printf("\n%s Breakdown:\n", ICON_INFO);
        printf("   IPv4 Ranges    : %s%zu%s\n", COL_CYAN, ip_db.count, COL_RESET);
        printf("   IPv6 Ranges    : %s%zu%s\n", COL_CYAN, ip6_db.count, COL_RESET);
        printf("   Domains/URLs   : %s%zu%s\n", COL_YELLOW, stats.domain_count, COL_RESET);
        printf("   Emails         : %s%zu%s\n", COL_YELLOW, stats.email_count, COL_RESET);
        printf("   File Hashes    : %s%zu%s\n", COL_YELLOW, stats.hash_count, COL_RESET);
        printf("   Unique Meta    : %zu\n", meta_db.count);
        printf("   Unique Feeds   : %zu\n", feed_db.count);
        printf("\n%s Layer Stats:\n", ICON_INFO);
        printf("   CTI entries    : %s%zu%s\n", COL_GREEN, stats.added_count, COL_RESET);
        printf("   Tags entries   : %s%zu%s\n", COL_CYAN, stats.tags_count, COL_RESET);
        if (stats.deleted_count > 0)
            printf("   Deleted (Delta): %s%zu%s\n", COL_RED, stats.deleted_count, COL_RESET);
        if (stats.skipped_count > 0)
            printf("   Skipped (Err)  : %s%zu%s\n", COL_RED, stats.skipped_count, COL_RESET);
        if (stats.rejected_cidr_count > 0)
            printf("   Not a network  : %s%zu%s (indexed as strings; -v lists them)\n", COL_RED,
                   stats.rejected_cidr_count, COL_RESET);

        printf("\n%s Feeds:\n", ICON_INFO);
        for (size_t i = 0; i < feed_db.count && i < 10; i++) {
            printf("   [%2zu] %s\n", i, feed_db.items[i].name);
        }
        if (feed_db.count > 10) printf("   ... and %zu more\n", feed_db.count - 10);

        printf("\n%s Build Complete.\n", ICON_CHECK);
    }
}

/* ============================================================================
 * GLOBAL-STATE RESET
 *
 * The one-shot full build accumulates every input file into the global builder
 * arrays and writes once at exit. A fold reloads the on-disk DB
 * (load_existing_thrt), applies one or more segments, and rewrites.
 * This reset runs before that reload. Without it the previous run's
 * entries would be re-emitted into the next write (double count).
 * ============================================================================ */
static void builder_state_reset(void) {
    free(meta_db.items);  meta_db.items = NULL;  meta_db.count = 0;  meta_db.cap = 0;
    free(ip_db.items);    ip_db.items = NULL;    ip_db.count = 0;    ip_db.cap = 0;
    free(ip6_db.items);   ip6_db.items = NULL;   ip6_db.count = 0;   ip6_db.cap = 0;
    free(str_db.items);   str_db.items = NULL;   str_db.count = 0;   str_db.cap = 0;
    free(str_pool.data);  str_pool.data = NULL;  str_pool.len = 0;   str_pool.cap = 0;
    free(feed_db.items);  feed_db.items = NULL;  feed_db.count = 0;  feed_db.cap = 0;

    /* meta dedup hash table */
    for (int i = 0; i < META_DEDUP_BUCKETS; i++) {
        meta_dedup_entry_t *e = meta_dedup_ht[i];
        while (e) { meta_dedup_entry_t *next = e->next; free(e); e = next; }
        meta_dedup_ht[i] = NULL;
    }

    /* delete set */
    if (g_delete_set) delete_set_free();

    /* stats + layer */
    memset(&stats, 0, sizeof(stats));
    g_current_layer = LAYER_CTI;
    g_public_feeds = 0;
    snprintf(g_default_source, sizeof(g_default_source), "%s", "Unknown");
    str_pool_reserve_sentinel();
}

/* ============================================================================
 * HEADER-AWARE CSV PARSER (parse_csv_file)
 *
 * Distinct from the legacy positional process_csv() (type,value,conf,...). This
 * is the operator-drop / delta CSV format folded by --apply-delta:
 *
 *   - Optional header row: first non-comment line whose tokens name known
 *     columns (indicator/value/ioc, type, confidence, category, tlp, feed).
 *     A leading '+'/'-' action column is also recognised in the header.
 *   - No/!header  -> column 0 = indicator, type AUTO-DETECTED from the value.
 *   - Leading '+'/'-' action token per row (delete = '-,<value>').
 *   - Blank lines and '#' comments skipped. Sane defaults when columns absent
 *     (confidence 50, tlp amber, feed = filename stem).
 *
 * Reuses the existing emit_normalized_ioc_v4 / add_meta_v4 / add_ioc path and
 * the shared parse_tlp_mask / parse_category_mask helpers.
 * ============================================================================ */

/* Column roles we recognise in a header. -1 = not present. */
typedef struct {
    int ind;   /* indicator / value / ioc */
    int type;
    int conf;  /* confidence */
    int cat;   /* category */
    int tlp;
    int feed;
    int action;
} csv_colmap_t;

/* Detect the IOC type from a bare value (used when no 'type' column). */
static void csv_autodetect_type(const char *val, char *out, size_t outsz) {
    /* Bare address or a well-formed CIDR -> an IP range. The same strict parse
     * add_ioc uses, so the two cannot disagree: testing only the part before
     * the slash classified "103.117.72.60/ptj" (a scheme-less URL) as an IP. */
    parsed_ip_t ip;
    size_t len;
    if (parse_ip_or_cidr(val, 1, &ip)) {
        snprintf(out, outsz, "%s", "ip");
        return;
    }
    len = strlen(val);
    if ((len == 32 || len == 40 || len == 64 || len == 128) &&
        strspn(val, "0123456789abcdefABCDEF") == len) {
        snprintf(out, outsz, "%s", "hash");
        return;
    }
    /* A scheme, or any path separator, means a URL. Feeds commonly ship
     * scheme-less URLs ("103.117.72.60/ptj"); calling those domains would put a
     * path into the domain table where no lookup can ever match it. */
    if (strstr(val, "://") || strchr(val, '/')) {
        snprintf(out, outsz, "%s", "url");
        return;
    }
    if (strchr(val, '@')) {
        snprintf(out, outsz, "%s", "email");
        return;
    }
    snprintf(out, outsz, "%s", "domain");
}

/* Try to interpret tokens as a header row. Returns 1 if it looks like a header
 * (at least an indicator-naming column matched), filling *cm; else 0. */
static int csv_parse_header(char **tokens, int ntok, csv_colmap_t *cm) {
    int matched;
    cm->ind = cm->type = cm->conf = cm->cat = cm->tlp = cm->feed = cm->action = -1;
    matched = 0;
    for (int i = 0; i < ntok; i++) {
        const char *t = tokens[i];
        if (!t) continue;
        if (strcasecmp(t, "indicator") == 0 || strcasecmp(t, "value") == 0 ||
            strcasecmp(t, "ioc") == 0) {
            if (cm->ind < 0) cm->ind = i;
            matched = 1;
        } else if (strcasecmp(t, "type") == 0) {
            cm->type = i;
        } else if (strcasecmp(t, "confidence") == 0 || strcasecmp(t, "conf") == 0 ||
                   strcasecmp(t, "score") == 0) {
            cm->conf = i;
        } else if (strcasecmp(t, "category") == 0 || strcasecmp(t, "cat") == 0) {
            cm->cat = i;
        } else if (strcasecmp(t, "tlp") == 0) {
            cm->tlp = i;
        } else if (strcasecmp(t, "feed") == 0 || strcasecmp(t, "source") == 0) {
            cm->feed = i;
        } else if (strcasecmp(t, "action") == 0 || strcasecmp(t, "op") == 0) {
            cm->action = i;
        }
    }
    return matched;
}

static void parse_csv_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    char line[MAX_LINE_LEN];
    int have_header;
    int header_checked;
    csv_colmap_t cm = { .ind = -1, .type = -1, .conf = -1, .cat = -1,
                        .tlp = -1, .feed = -1, .action = -1 };
    if (!f) {
        fprintf(stderr, "%s Error opening %s: %s\n", ICON_WARN, filename, strerror(errno));
        return;
    }

    /* Default feed = filename stem (apply_delta_segment sets g_default_source
     * from --feed-key, but be self-sufficient if called directly). */
    if (strcmp(g_default_source, "Unknown") == 0) {
        const char *bn = strrchr(filename, '/');
        char *dot;
        bn = bn ? bn + 1 : filename;
        snprintf(g_default_source, sizeof(g_default_source), "%s", bn);
        dot = strrchr(g_default_source, '.');
        if (dot) *dot = 0;
    }

    if (g_verbose) printf("%s %sProcessing %-14s: %s%s\n",
                          ICON_INFO, COL_BOLD, "CSV (delta)", filename, COL_RESET);

    have_header = 0;
    header_checked = 0;

    while (fgets(line, sizeof(line), f)) {
        char *tokens[16] = {0};
        char *p;
        int n;
        normalized_ioc_v4_t ioc = {0};
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == 0 || line[0] == '#') continue;

        p = strtok(line, ",");
        n = 0;
        while (p && n < 16) { tokens[n++] = trim(p); p = strtok(NULL, ","); }
        if (n == 0) continue;

        /* First data row: decide header vs. data. */
        if (!header_checked) {
            csv_colmap_t probe;
            header_checked = 1;
            if (csv_parse_header(tokens, n, &probe)) {
                cm = probe;
                have_header = 1;
                continue; /* consumed the header row */
            }
            /* No header: column 0 is the indicator, auto-detect type. */
            have_header = 0;
        }

        ioc.action = '+';

        if (have_header) {
            int ai = cm.ind >= 0 ? cm.ind : 0;
            if (ai >= n || !tokens[ai] || tokens[ai][0] == 0) { stats.skipped_count++; continue; }

            /* explicit action column */
            if (cm.action >= 0 && cm.action < n && tokens[cm.action]) {
                char a = tokens[cm.action][0];
                if (a == '-' || strcasecmp(tokens[cm.action], "delete") == 0 ||
                    strcasecmp(tokens[cm.action], "del") == 0 ||
                    strcasecmp(tokens[cm.action], "remove") == 0) ioc.action = '-';
            }

            snprintf(ioc.value, sizeof(ioc.value), "%s", tokens[ai]);

            if (cm.type >= 0 && cm.type < n && tokens[cm.type] && tokens[cm.type][0]) {
                snprintf(ioc.type, sizeof(ioc.type), "%s", tokens[cm.type]);
            } else {
                csv_autodetect_type(ioc.value, ioc.type, sizeof(ioc.type));
            }
            ioc.confidence = (cm.conf >= 0 && cm.conf < n && tokens[cm.conf] &&
                              tokens[cm.conf][0]) ? parse_confidence(tokens[cm.conf]) : 50;
            ioc.category_mask = (cm.cat >= 0 && cm.cat < n && tokens[cm.cat]) ?
                                parse_category_mask(tokens[cm.cat]) : 0;
            ioc.tlp_mask = (cm.tlp >= 0 && cm.tlp < n && tokens[cm.tlp]) ?
                           parse_tlp_mask(tokens[cm.tlp]) : THRT_TLP_AMBER;
            if (cm.feed >= 0 && cm.feed < n && tokens[cm.feed] && tokens[cm.feed][0]) {
                snprintf(ioc.feed, sizeof(ioc.feed), "%s", tokens[cm.feed]);
            } else {
                snprintf(ioc.feed, sizeof(ioc.feed), "%s", g_default_source);
            }
        } else {
            /* No header: optional leading '+'/'-' action, else col0 = indicator. */
            int col0 = 0;
            if (tokens[0][0] == '-' && tokens[0][1] == '\0') { ioc.action = '-'; col0 = 1; }
            else if (tokens[0][0] == '+' && tokens[0][1] == '\0') { ioc.action = '+'; col0 = 1; }
            if (col0 >= n || !tokens[col0] || tokens[col0][0] == 0) { stats.skipped_count++; continue; }

            snprintf(ioc.value, sizeof(ioc.value), "%s", tokens[col0]);
            csv_autodetect_type(ioc.value, ioc.type, sizeof(ioc.type));
            ioc.confidence = 50;
            ioc.category_mask = 0;
            ioc.tlp_mask = THRT_TLP_AMBER;
            snprintf(ioc.feed, sizeof(ioc.feed), "%s", g_default_source);
        }

        emit_normalized_ioc_v4(&ioc);
    }
    fclose(f);
}

/* Rebuild the string pool to contain ONLY live bytes (surviving meta tags +
 * surviving string IOC values), reclaiming the space freed by eviction so the
 * fold is size-idempotent. Reserves offset 0 as a NUL so tags_offset==0 keeps
 * meaning "no tags". Preserves str_pool.cap (>=4 MB) so ensure_capacity's
 * single-double headroom invariant (len + MAX_TAGS_JSON) still holds. */
static void compact_str_pool(void) {
    struct { char *data; size_t len; size_t cap; } np = {0};
    np.cap = str_pool.cap ? str_pool.cap : (4 * 1024 * 1024);
    if (np.cap < str_pool.len + MAX_TAGS_JSON + 1)
        np.cap = str_pool.len + MAX_TAGS_JSON + 1;
    np.data = malloc(np.cap);
    if (!np.data) { fprintf(stderr, "FATAL: Out of Memory (str compact)\n"); exit(1); }
    np.data[0] = '\0';
    np.len = 1;   /* reserve offset 0 */

    /* Live meta tags */
    for (size_t i = 0; i < meta_db.count; i++) {
        builder_meta_v4_t *m = &meta_db.items[i];
        uint32_t off;
        if (m->tags_length == 0) {
            m->tags_offset = 0;
        } else {
            off = (uint32_t)np.len;
            memcpy(np.data + np.len, str_pool.data + m->tags_offset, m->tags_length);
            np.len += m->tags_length;
            np.data[np.len++] = '\0';
            m->tags_offset = off;
        }
        if (m->labels_length == 0) {
            m->labels_offset = 0;
        } else {
            off = (uint32_t)np.len;
            memcpy(np.data + np.len, str_pool.data + m->labels_offset, m->labels_length);
            np.len += m->labels_length;
            np.data[np.len++] = '\0';
            m->labels_offset = off;
        }
    }
    /* Live string IOC values */
    for (size_t i = 0; i < str_db.count; i++) {
        const char *v = str_pool.data + str_db.items[i].offset;
        size_t vl = strlen(v);
        uint32_t off = (uint32_t)np.len;
        memcpy(np.data + np.len, v, vl + 1);
        np.len += vl + 1;
        str_db.items[i].offset = off;
    }

    free(str_pool.data);
    str_pool.data = np.data;
    str_pool.len = np.len;
    str_pool.cap = np.cap;
}

/* Rebuild meta_dedup_ht from the current meta_db. load_existing_thrt imports
 * metadata directly (NOT via add_meta_v4), so without this every re-added
 * identical meta would allocate a NEW entry, growing meta_db on every fold.
 * Also required after eviction renumbers meta indices. */
static void rebuild_meta_dedup(void) {
    for (int i = 0; i < META_DEDUP_BUCKETS; i++) {
        meta_dedup_entry_t *e = meta_dedup_ht[i];
        while (e) { meta_dedup_entry_t *n = e->next; free(e); e = n; }
        meta_dedup_ht[i] = NULL;
    }
    for (size_t i = 0; i < meta_db.count; i++) {
        builder_meta_v4_t *m = &meta_db.items[i];
        char tagbuf[MAX_TAGS_JSON], labbuf[MAX_TAGS_JSON];
        const char *tags = "", *labels = "";
        uint64_t key;
        uint32_t bkt;
        meta_dedup_entry_t *ent;
        if (m->tags_length && m->tags_length < MAX_TAGS_JSON) {
            memcpy(tagbuf, str_pool.data + m->tags_offset, m->tags_length);
            tagbuf[m->tags_length] = '\0';
            tags = tagbuf;
        }
        if (m->labels_length && m->labels_length < MAX_TAGS_JSON) {
            memcpy(labbuf, str_pool.data + m->labels_offset, m->labels_length);
            labbuf[m->labels_length] = '\0';
            labels = labbuf;
        }
        key = meta_make_key(m->confidence, m->confidence_r, m->type_mask, m->tlp_mask,
                            m->category_mask, m->feed_mask, tags, labels);
        bkt = (uint32_t)(key % META_DEDUP_BUCKETS);
        ent = malloc(sizeof(*ent));
        if (!ent) { fprintf(stderr, "FATAL: Out of Memory (meta dedup rebuild)\n"); exit(1); }
        ent->key = key; ent->meta_idx = (uint32_t)i;
        ent->next = meta_dedup_ht[bkt]; meta_dedup_ht[bkt] = ent;
    }
}

/* Seed the (type,value) IOC dedup set from the current (post-load, post-evict)
 * IOC rows so re-delivered IOCs in the incoming segment are deduped. */
static void ioc_dedup_seed(void) {
    ioc_dedup_reset();
    for (size_t i = 0; i < ip_db.count; i++)
        ioc_dedup_insert(ioc_key_ipv4(ip_db.items[i].start, ip_db.items[i].end),
                         IOC_KIND_IPV4, (uint32_t)i);
    for (size_t i = 0; i < ip6_db.count; i++)
        ioc_dedup_insert(ioc_key_ipv6(ip6_db.items[i].start, ip6_db.items[i].end),
                         IOC_KIND_IPV6, (uint32_t)i);
    for (size_t i = 0; i < str_db.count; i++)
        ioc_dedup_insert(ioc_key_str(str_db.items[i].hash),
                         IOC_KIND_STR, (uint32_t)i);
}

/* Evict every IOC contributed ONLY by feed `feed_key` ahead of applying that
 * feed's fresh snapshot. Uses the existing thrt_metadata_t.feed_mask (NO ABI
 * change): clear the feed's bit on every meta; any meta left with feed_mask==0
 * is dropped (it was feed-exclusive); compact the meta array + renumber; then
 * drop the IOC rows that referenced a dropped meta. The string pool is reclaimed
 * separately by compact_str_pool(); ip_accel + bloom are rebuilt in write_thrt.
 * Returns the number of IOC rows dropped. */
static size_t feed_snapshot_evict(const char *feed_key) {
    int fidx = find_feed_idx(feed_key);
    uint64_t fbit;
    uint32_t *remap;
    size_t mw;
    size_t dropped = 0, w;
    if (fidx < 0) return 0;            /* feed never seen - nothing to replace */
    fbit = (1ULL << (unsigned)fidx);

    /* 1. Clear the feed bit on every metadata record. */
    for (size_t i = 0; i < meta_db.count; i++)
        meta_db.items[i].feed_mask &= ~fbit;

    /* 2. Compact meta_db, dropping feed-exclusive (now feed_mask==0) records;
     *    build an old->new index remap (UINT32_MAX = dropped). */
    remap = malloc((meta_db.count ? meta_db.count : 1) * sizeof(uint32_t));
    if (!remap) { fprintf(stderr, "FATAL: Out of Memory (evict remap)\n"); exit(1); }
    mw = 0;
    for (size_t i = 0; i < meta_db.count; i++) {
        if (meta_db.items[i].feed_mask == 0) {
            remap[i] = UINT32_MAX;
        } else {
            meta_db.items[mw] = meta_db.items[i];
            remap[i] = (uint32_t)mw;
            mw++;
        }
    }
    meta_db.count = mw;

    /* 3. Compact IOC rows: drop those referencing a dropped meta, remap survivors. */
    w = 0;
    for (size_t i = 0; i < ip_db.count; i++) {
        uint32_t nm = remap[ip_db.items[i].meta_idx];
        if (nm == UINT32_MAX) { dropped++; continue; }
        ip_db.items[i].meta_idx = nm;
        ip_db.items[w++] = ip_db.items[i];
    }
    ip_db.count = w;
    w = 0;
    for (size_t i = 0; i < ip6_db.count; i++) {
        uint32_t nm = remap[ip6_db.items[i].meta_idx];
        if (nm == UINT32_MAX) { dropped++; continue; }
        ip6_db.items[i].meta_idx = nm;
        ip6_db.items[w++] = ip6_db.items[i];
    }
    ip6_db.count = w;
    w = 0;
    for (size_t i = 0; i < str_db.count; i++) {
        uint32_t nm = remap[str_db.items[i].meta_idx];
        if (nm == UINT32_MAX) { dropped++; continue; }
        str_db.items[i].meta_idx = nm;
        str_db.items[w++] = str_db.items[i];
    }
    str_db.count = w;

    free(remap);
    if (g_verbose && dropped)
        printf("%s [SNAPSHOT-REPLACE] evicted %zu IOC rows for feed '%s'\n",
               ICON_GEAR, dropped, feed_key);
    return dropped;
}

/* ============================================================================
 * PER-FEED GENERATION COMPANION FILE  (<out.thrt>.gen)
 *
 * Per-IOC expiry/generation does not live in the .thrt (the 24-byte
 * thrt_metadata_t is shared by every IOC with the same fields and has no
 * room), so generation and last-update live in a tiny TEXT file next to the
 * .thrt, never in the header. It powers:
 *   - anti-resurrection: a snapshot carrying a generation <= the stored one is
 *     dropped (a re-delivered/out-of-order snapshot can't resurrect withdrawn
 *     IOCs).
 *   - feed-level TTL: feeds not refreshed within --ttl-days are evicted. This is
 *     the granularity V4 supports without per-IOC timestamps; per-IOC TTL stays
 *     in the overlay.
 * Format (tab-separated, one line per feed):  feed<TAB>generation<TAB>updated
 * ============================================================================ */
typedef struct {
    char     feed[THRT_FEED_NAME_MAX];
    uint64_t generation;
    uint64_t updated;            /* unix seconds of last fold for this feed */
} feed_gen_t;
static struct { feed_gen_t *items; size_t count; size_t cap; } g_gen = {0};

static void gen_load(const char *path) {
    FILE *f;
    char line[256];
    g_gen.count = 0;
    f = fopen(path, "r");
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        char feed[THRT_FEED_NAME_MAX];
        unsigned long long g = 0, u = 0;
        if (sscanf(line, "%63[^\t]\t%llu\t%llu", feed, &g, &u) >= 2) {
            if (g_gen.count >= g_gen.cap) {
                g_gen.cap = g_gen.cap ? g_gen.cap * 2 : 16;
                g_gen.items = xrealloc(g_gen.items, g_gen.cap * sizeof(feed_gen_t));
                if (!g_gen.items) { fprintf(stderr, "FATAL: OOM (gen)\n"); exit(1); }
            }
            snprintf(g_gen.items[g_gen.count].feed, THRT_FEED_NAME_MAX, "%s", feed);
            g_gen.items[g_gen.count].generation = g;
            g_gen.items[g_gen.count].updated = u;
            g_gen.count++;
        }
    }
    fclose(f);
}
static feed_gen_t *gen_find(const char *feed) {
    for (size_t i = 0; i < g_gen.count; i++)
        if (strcasecmp(g_gen.items[i].feed, feed) == 0) return &g_gen.items[i];
    return NULL;
}
static void gen_set(const char *feed, uint64_t generation, uint64_t updated) {
    feed_gen_t *e = gen_find(feed);
    if (!e) {
        if (g_gen.count >= g_gen.cap) {
            g_gen.cap = g_gen.cap ? g_gen.cap * 2 : 16;
            g_gen.items = xrealloc(g_gen.items, g_gen.cap * sizeof(feed_gen_t));
            if (!g_gen.items) { fprintf(stderr, "FATAL: OOM (gen)\n"); exit(1); }
        }
        e = &g_gen.items[g_gen.count++];
        snprintf(e->feed, THRT_FEED_NAME_MAX, "%s", feed);
    }
    e->generation = generation;
    e->updated = updated;
}
static void gen_remove(const char *feed) {
    for (size_t i = 0; i < g_gen.count; i++)
        if (strcasecmp(g_gen.items[i].feed, feed) == 0) {
            g_gen.items[i] = g_gen.items[--g_gen.count];   /* swap-remove */
            return;
        }
}
static void gen_save(const char *path) {
    char tmp[PATH_MAX + 32];
    FILE *f;
    int n;
    n = snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        fprintf(stderr, "%s gen file path too long: %s\n", ICON_WARN, path);
        return;
    }
    f = fopen(tmp, "w");
    if (!f) { fprintf(stderr, "%s cannot write gen file %s: %s\n", ICON_WARN, tmp, strerror(errno)); return; }
    for (size_t i = 0; i < g_gen.count; i++)
        fprintf(f, "%s\t%llu\t%llu\n", g_gen.items[i].feed,
                (unsigned long long)g_gen.items[i].generation,
                (unsigned long long)g_gen.items[i].updated);
    fclose(f);
    if (rename(tmp, path) != 0) unlink(tmp);
}
static void gen_free(void) {
    free(g_gen.items);
    g_gen.items = NULL; g_gen.count = 0; g_gen.cap = 0;
}

/* ============================================================================
 * DELTA FOLD
 *
 * Load the database once, fold one or more segments, then write once.
 * apply-delta is one segment. enrich sync is one segment per MISP page
 * and one write for the pull. A malformed segment does not write.
 *
 * Three guards keep a re-delivered segment from growing the database:
 *   (1) snapshot-replace. is_snapshot evicts feed_key's prior IOCs first.
 *   (2) (type,value) dedup. Re-delivered IOCs, including IP ranges, do not append.
 *   (3) one write. load, apply, write_thrt (atomic tmp+rename).
 * A generation companion file adds anti-resurrection and feed-level TTL.
 * One successful pull advances that generation by one, not by one per page.
 *
 * A page that withdraws an indicator applies that delete before the next
 * page, then rebuilds dedup, so a later page can add the same value back.
 *
 * TTL: per-IOC expiry is NOT persisted in .thrt (thrt_metadata_t is a full
 * 24-byte record shared across IOCs). ttl_days only prunes expired entries at
 * fold time, before the write; it is not stored as a per-IOC field.
 * ============================================================================ */
static int g_fold_active = 0;
static char g_fold_out[PATH_MAX];
static char g_fold_feed[THRT_FEED_NAME_MAX];
static char g_fold_genpath[PATH_MAX + 32];
static uint64_t g_fold_gen = 0;

static void fold_close_state(void) {
    g_ioc_dedup_active = 0;
    ioc_dedup_reset();
    gen_free();
    builder_state_reset();
    thrt_misp_delta_mode(0);
    g_fold_active = 0;
    g_fold_out[0] = '\0';
    g_fold_feed[0] = '\0';
    g_fold_genpath[0] = '\0';
    g_fold_gen = 0;
}

/* 0 and g_fold_active: ready for pages. 0 and not active: stale generation,
 * nothing to write. -1: the fold was not started. */
int thrt_fold_begin(const char *out_thrt, const char *feed_key, int snapshot,
                    int misp_delta, uint32_t ttl_days, uint64_t generation);
int thrt_fold_begin(const char *out_thrt, const char *feed_key,
                    int is_snapshot, int misp_delta,
                    uint32_t ttl_days, uint64_t generation) {
    struct stat sb;
    feed_gen_t *fg;
    uint64_t prev_gen;
    uint64_t new_gen;
    int n;

    if (out_thrt == NULL || out_thrt[0] == '\0' ||
        feed_key == NULL || feed_key[0] == '\0')
        return -1;
    if (g_fold_active)
        fold_close_state();
    builder_state_reset();
    ioc_dedup_reset();
    g_ioc_dedup_active = 0;
    thrt_misp_delta_mode(misp_delta);

    n = snprintf(g_fold_out, sizeof g_fold_out, "%s", out_thrt);
    if (n < 0 || (size_t)n >= sizeof g_fold_out)
        goto fail;
    n = snprintf(g_fold_feed, sizeof g_fold_feed, "%s", feed_key);
    if (n < 0 || (size_t)n >= sizeof g_fold_feed)
        goto fail;
    n = snprintf(g_fold_genpath, sizeof g_fold_genpath, "%s.gen", g_fold_out);
    if (n < 0 || (size_t)n >= sizeof g_fold_genpath)
        goto fail;
    snprintf(g_default_source, sizeof g_default_source, "%s", g_fold_feed);

    if (stat(g_fold_out, &sb) == 0)
        load_existing_thrt(g_fold_out);

    gen_load(g_fold_genpath);
    fg = gen_find(g_fold_feed);
    prev_gen = fg ? fg->generation : 0;
    if (generation > 0 && fg && generation <= prev_gen) {
        fprintf(stderr,
                "%s apply-delta: stale generation %llu <= %llu for feed '%s' - "
                "skipping (anti-resurrection)\n",
                ICON_WARN, (unsigned long long)generation,
                (unsigned long long)prev_gen, g_fold_feed);
        fold_close_state();
        return 0;
    }
    new_gen = (generation > 0) ? generation : prev_gen + 1;

    if (is_snapshot)
        feed_snapshot_evict(g_fold_feed);

    if (ttl_days > 0) {
        time_t now = time(NULL);
        uint64_t horizon = (uint64_t)now - (uint64_t)ttl_days * 86400ULL;
        for (size_t i = 0; i < g_gen.count; ) {
            feed_gen_t *e = &g_gen.items[i];
            if (strcasecmp(e->feed, g_fold_feed) != 0 && e->updated > 0 &&
                e->updated < horizon) {
                char stale[THRT_FEED_NAME_MAX];
                snprintf(stale, sizeof stale, "%s", e->feed);
                feed_snapshot_evict(stale);
                gen_remove(stale);
            } else {
                i++;
            }
        }
    }

    /* Reclaim freed string-pool bytes so the reserved offset-0 NUL is
     * present on every fold. The .thrt size stays the same whether or
     * not an eviction happened. */
    compact_str_pool();
    rebuild_meta_dedup();
    ioc_dedup_seed();
    g_ioc_dedup_active = 1;
    g_fold_gen = new_gen;
    g_fold_active = 1;
    return 0;

fail:
    fold_close_state();
    return -1;
}

int thrt_fold_page(const char *seg_path);
int thrt_fold_page(const char *seg_path) {
    const char *bn;
    const char *ext;
    int is_stix;
    int is_misp;
    int is_json;
    int is_csv;
    int rc = 0;

    if (!g_fold_active || seg_path == NULL || seg_path[0] == '\0')
        return -1;
    /* Keep the feed key set by thrt_fold_begin. Do not take it from the
     * page filename. */
    bn = strrchr(seg_path, '/');
    bn = bn ? bn + 1 : seg_path;
    is_stix = (strcasestr(bn, ".stix.json") != NULL) ||
              (strrchr(bn, '.') && strcasecmp(strrchr(bn, '.'), ".stix") == 0);
    is_misp = (strcasestr(bn, ".misp.json") != NULL);
    ext = strrchr(bn, '.');
    is_json = (ext && strcasecmp(ext, ".json") == 0);
    is_csv = (ext && strcasecmp(ext, ".csv") == 0);
    if (is_stix)
        process_stix_json(seg_path);
    else if (is_misp || is_json)
        rc = process_misp_json(seg_path);
    else if (is_csv)
        parse_csv_file(seg_path);
    else {
        fprintf(stderr, "%s apply-delta: unknown segment format: %s\n",
                ICON_WARN, bn);
        return -1;
    }
    if (rc != 0)
        return -1;

    /* Apply withdrawals before the next page. Dedup is rebuilt from the
     * rows that remain, so a later page may add the same indicator. */
    if (g_delete_set && g_delete_set->count > 0) {
        apply_delete_set();
        delete_set_free();
        g_ioc_dedup_active = 0;
        rebuild_meta_dedup();
        ioc_dedup_seed();
        g_ioc_dedup_active = 1;
    }
    return 0;
}

int thrt_fold_commit(void);
int thrt_fold_commit(void) {
    if (!g_fold_active)
        return -1;
    g_ioc_dedup_active = 0;
    write_thrt(g_fold_out);
    gen_set(g_fold_feed, g_fold_gen, (uint64_t)time(NULL));
    gen_save(g_fold_genpath);
    fold_close_state();
    return 0;
}

void thrt_fold_abort(void);
void thrt_fold_abort(void) {
    if (!g_fold_active)
        return;
    fold_close_state();
}

static int apply_delta_segment(const char *seg_path, const char *out_thrt,
                               const char *feed_key, int is_snapshot,
                               uint32_t ttl_days, uint64_t generation) {
    char feedbuf[THRT_FEED_NAME_MAX];
    const char *bn;

    if (feed_key && *feed_key) {
        snprintf(feedbuf, sizeof feedbuf, "%s", feed_key);
    } else {
        char *dot;
        bn = strrchr(seg_path, '/');
        bn = bn ? bn + 1 : seg_path;
        snprintf(feedbuf, sizeof feedbuf, "%s", bn);
        dot = strrchr(feedbuf, '.');
        if (dot)
            *dot = '\0';
        if (strcasestr(bn, ".stix.json") != NULL ||
            (strrchr(bn, '.') && strcasecmp(strrchr(bn, '.'), ".stix") == 0)) {
            char *suf = strrchr(feedbuf, '.');
            if (suf && strcasecmp(suf, ".stix") == 0)
                *suf = '\0';
        }
    }
    if (thrt_fold_begin(out_thrt, feedbuf, is_snapshot, g_misp_delta,
                        ttl_days, generation) != 0)
        return 1;
    if (!g_fold_active)
        return 0;
    if (thrt_fold_page(seg_path) != 0) {
        thrt_fold_abort();
        return 1;
    }
    return thrt_fold_commit() != 0 ? 1 : 0;
}

/* ============================================================================
 * USAGE
 * ============================================================================ */
static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s -o <out.thrt> [OPTIONS] <input1> [input2 ...]\n", prog);
    fprintf(stderr, "       %s --apply-delta <seg> -o <out.thrt> [--feed-key K] [--snapshot] [--ttl-days N]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -o <file>       Output .thrt database file (required)\n");
    fprintf(stderr, "  -i              Incremental mode: load existing DB, apply delta files\n");
    fprintf(stderr, "  -l <layer>      Set layer for subsequent files: cti, cti_r, tags\n");
    fprintf(stderr, "  -v              Verbose output\n");
    fprintf(stderr, "  -h              Show this help\n");
    fprintf(stderr, "\nOne-shot delta fold (an external process calls this per received segment):\n");
    fprintf(stderr, "  --apply-delta <seg>  Fold ONE segment into -o then exit (dedup/snapshot-replace/TTL)\n");
    fprintf(stderr, "  --feed-key K         Feed identity for snapshot-replace (defaults to filename stem)\n");
    fprintf(stderr, "  --snapshot           Segment is a full feed snapshot: evict feed's prior IOCs first\n");
    fprintf(stderr, "  --ttl-days N         Evict feeds not refreshed within N days (feed-level TTL via .gen file)\n");
    fprintf(stderr, "  --generation G       Monotonic feed generation; a snapshot with G <= stored is dropped (anti-resurrection)\n");
    fprintf(stderr, "\nLayers:\n");
    fprintf(stderr, "  cti             Public CTI feeds (default) - full enrichment output\n");
    fprintf(stderr, "  cti_r           Restricted CTI feeds - only sets cti_match flag\n");
    fprintf(stderr, "  tags            Tags/CMDB/Carto - outputs tag list\n");
    fprintf(stderr, "\nSupported input formats:\n");
    fprintf(stderr, "  .csv            CSV: type,value,confidence,category,feed,tlp\n");
    fprintf(stderr, "  .json           CTI Dictionary JSON: {\"ioc\": {\"feed\":[...], ...}}\n");
    fprintf(stderr, "  .lookup         Rsyslog JSON lookup table\n");
    fprintf(stderr, "  .txt, .ioc      Plain text IOC list (one per line)\n");
    fprintf(stderr, "  .tags           Tags CSV: value,tag1,tag2,tag3,...\n");
    fprintf(stderr, "  .tags.json      Tags JSON: {\"index\":\"value\",\"tags\":[...]}\n");
    fprintf(stderr, "  .stix, .stix.json  STIX 2.1 bundle (indicator patterns, or SCOs if no indicator)\n");
    fprintf(stderr, "\nDelta format (for incremental mode -i):\n");
    fprintf(stderr, "  +,type,value,confidence,category,feed,tlp   (add entry)\n");
    fprintf(stderr, "  -,type,value                                 (delete entry)\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  # Build with public CTI only\n");
    fprintf(stderr, "  %s -v -o threat.thrt feeds/*.csv\n\n", prog);
    fprintf(stderr, "  # Build from CTI dictionary JSON files\n");
    fprintf(stderr, "  %s -v -o threat.thrt cti_public_ip.json cti_public_hash.json\n\n", prog);
    fprintf(stderr, "  # Build with multiple layers\n");
    fprintf(stderr, "  %s -v -o combined.thrt \\\n", prog);
    fprintf(stderr, "      -l cti public_feeds/*.csv \\\n");
    fprintf(stderr, "      -l cti_r restricted/*.csv \\\n");
    fprintf(stderr, "      -l tags cmdb.tags carto.tags\n\n");
    fprintf(stderr, "  # Incremental update from delta file\n");
    fprintf(stderr, "  %s -v -i -o threat.thrt updates.csv\n", prog);
}

/* ============================================================================
 * MAIN
 * ============================================================================ */
int main(int argc, char **argv) {
    char *thrt_out = NULL;
    int opt;

    /* ---- one-shot delta fold (--apply-delta) - parsed before getopt
     * because its long options (--feed-key/--snapshot/--ttl-days/--generation)
     * intermix with -o. -o is still read by getopt below too. ---- */
    const char *delta_seg = NULL;
    const char *delta_feed_key = NULL;
    int delta_is_snapshot = 0;
    uint32_t delta_ttl_days = 0;
    uint64_t delta_generation = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--apply-delta") == 0 && i + 1 < argc) {
            delta_seg = argv[++i];
        } else if (strcmp(argv[i], "--feed-key") == 0 && i + 1 < argc) {
            delta_feed_key = argv[++i];
        } else if (strcmp(argv[i], "--snapshot") == 0) {
            delta_is_snapshot = 1;
        } else if (strcmp(argv[i], "--ttl-days") == 0 && i + 1 < argc) {
            char* end;
            unsigned long long v;
            errno = 0;
            v = strtoull(argv[++i], &end, 10);
            if (errno != 0 || end == argv[i] || *end != '\0' || argv[i][0] == '-' || v > UINT32_MAX) {
                fprintf(stderr, "thrtutil: --ttl-days takes a number of days\n");
                return 2;
            }
            delta_ttl_days = (uint32_t)v;
        } else if (strcmp(argv[i], "--generation") == 0 && i + 1 < argc) {
            char* end;
            errno = 0;
            delta_generation = strtoull(argv[++i], &end, 10);
            if (errno != 0 || end == argv[i] || *end != '\0' || argv[i][0] == '-') {
                fprintf(stderr, "thrtutil: --generation takes a number\n");
                return 2;
            }
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            thrt_out = argv[i + 1];   /* don't consume i: getopt below also reads it */
        } else if (strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        }
    }

    if (delta_seg) {
        int rc;
        if (!thrt_out) {
            fprintf(stderr, "Error: --apply-delta requires -o <out.thrt>\n\n");
            print_usage(argv[0]);
            exit(1);
        }
        rc = apply_delta_segment(delta_seg, thrt_out, delta_feed_key,
                                     delta_is_snapshot, delta_ttl_days,
                                     delta_generation);
        return rc;
    }

    /* Process options, handling -l for layer switching */
    while ((opt = getopt(argc, argv, "+o:l:vih")) != -1) {
        switch (opt) {
            case 'o':
                thrt_out = optarg;
                break;
            case 'l':
                if (strcasecmp(optarg, "cti") == 0) {
                    g_current_layer = LAYER_CTI;
                } else if (strcasecmp(optarg, "cti_r") == 0) {
                    g_current_layer = LAYER_CTI_R;
                } else if (strcasecmp(optarg, "tags") == 0) {
                    g_current_layer = LAYER_TAGS;
                } else {
                    fprintf(stderr, "Unknown layer: %s (use: cti, cti_r, tags)\n", optarg);
                    exit(1);
                }
                if (g_verbose) {
                    printf("%s Layer set to: %s\n", ICON_GEAR,
                           g_current_layer == LAYER_CTI ? "cti" :
                           g_current_layer == LAYER_CTI_R ? "cti_r" : "tags");
                }
                break;
            case 'v':
                g_verbose = 1;
                break;
            case 'i':
                g_incremental = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }

    if (!thrt_out) {
        fprintf(stderr, "Error: Output file (-o) is required\n\n");
        print_usage(argv[0]);
        exit(1);
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: At least one input file is required\n\n");
        print_usage(argv[0]);
        exit(1);
    }

    /* In incremental mode, load the existing database first */
    str_pool_reserve_sentinel();
    if (g_incremental) {
        if (g_verbose) printf("%s Incremental mode: loading existing database\n", ICON_GEAR);
        load_existing_thrt(thrt_out);
    }

    /* One row per indicator: the same value from several feeds or layers
     * merges into one record, so a lookup sees every layer. */
    ioc_dedup_reset();
    if (g_incremental) ioc_dedup_seed();
    g_ioc_dedup_active = 1;

    /* Process remaining arguments as files, respecting -l switches */
    /* Re-parse argv to handle interleaved -l options */
    g_current_layer = LAYER_CTI; /* Reset to default */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            i++; /* Skip output file */
            continue;
        }
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            i++;
            if (strcasecmp(argv[i], "cti") == 0) g_current_layer = LAYER_CTI;
            else if (strcasecmp(argv[i], "cti_r") == 0) g_current_layer = LAYER_CTI_R;
            else if (strcasecmp(argv[i], "tags") == 0) g_current_layer = LAYER_TAGS;
            if (g_verbose) {
                printf("%s Layer: %s\n", ICON_GEAR,
                       g_current_layer == LAYER_CTI ? "cti" :
                       g_current_layer == LAYER_CTI_R ? "cti_r" : "tags");
            }
            continue;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "-h") == 0 ||
            strcmp(argv[i], "-i") == 0) {
            continue;
        }
        if (argv[i][0] == '-') {
            continue; /* Skip other options */
        }

        /* It's a file - process it with current layer */
        process_file(argv[i]);
    }

    g_ioc_dedup_active = 0;
    write_thrt(thrt_out);
    ioc_dedup_reset();

    /* Cleanup */
    free(meta_db.items);
    free(ip_db.items);
    free(ip6_db.items);
    free(str_db.items);
    free(str_pool.data);
    free(feed_db.items);
    if (g_delete_set) delete_set_free();
    for (int i = 0; i < META_DEDUP_BUCKETS; i++) {
        meta_dedup_entry_t *e = meta_dedup_ht[i];
        while (e) { meta_dedup_entry_t *next = e->next; free(e); e = next; }
    }

    return 0;
}
