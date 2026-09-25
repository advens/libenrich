/* thrtutil.c
 * Standalone tool that builds the mmenrich CTI database (.thrt). Imports:
 *   - CSV (.csv)
 *   - CTI dictionary JSON (.json), multi-feed, with mmap for 1+ GB files
 *   - rsyslog JSON lookup tables (.lookup)
 *   - MISP JSON exports (.misp, .misp.json)
 *   - plain-text IOC lists (.txt, .ioc)
 *   - tag files (.tags, .tags.json)
 *
 * Incremental updates: --apply-delta <seg> folds one CTI delta segment into the
 * live .thrt then exits (dedup by (type, value), per-feed snapshot replace,
 * feed-level TTL and generation anti-resurrection via a .gen companion file). mmenrich
 * picks up the atomic rewrite through its mtime reload.
 *
 * Layers (-l cti|cti_r|tags, default cti): control how much of a match mmenrich
 * reveals. cti = public intel, fully attributed (feed/category/TLP emitted).
 * cti_r = restricted intel: a match raises the threat flag but feed/category/TLP
 * are withheld from the message. tags = asset/CMDB/carto context, no threat flag.
 * Supports per-feed bitmasks (up to 64 feeds), pre-computed TLP masks and tags
 * stored as a JSON array in the string pool.
 *
 * Compile: cc -O3 thrtutil.c -o thrtutil
 *
 * Copyright 2026 Advens.
 * Author: Jeremie Jourdin <jeremie.jourdin@advens.fr>
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
    uint8_t  confidence;
    uint8_t  type_mask;       /* THRT_TYPE_CTI | THRT_TYPE_CTI_R | THRT_TYPE_TAGS */
    uint8_t  tlp_mask;        /* THRT_TLP_* flags */
    uint16_t category_mask;   /* THRT_CAT_* flags */
    uint64_t feed_mask;       /* Bitmask of contributing feeds */
    uint32_t tags_offset;     /* Offset into string pool */
    uint32_t tags_length;     /* Length of tags JSON blob */
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

/* --- Deletion Tracking (Hash Set) --- */
#define DELETE_SET_BUCKETS 65536
typedef struct delete_entry {
    uint64_t hash;
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

static void delete_set_add(uint64_t hash) {
    if (!g_delete_set) delete_set_init();
    uint32_t bucket = hash % DELETE_SET_BUCKETS;

    for (delete_entry_t *e = g_delete_set->buckets[bucket]; e; e = e->next) {
        if (e->hash == hash) return;
    }

    delete_entry_t *entry = xmalloc(sizeof(delete_entry_t));
    entry->hash = hash;
    entry->next = g_delete_set->buckets[bucket];
    g_delete_set->buckets[bucket] = entry;
    g_delete_set->count++;
}

static int delete_set_contains(uint64_t hash) {
    if (!g_delete_set) return 0;
    uint32_t bucket = hash % DELETE_SET_BUCKETS;
    for (delete_entry_t *e = g_delete_set->buckets[bucket]; e; e = e->next) {
        if (e->hash == hash) return 1;
    }
    return 0;
}

static void delete_set_free(void) {
    if (!g_delete_set) return;
    for (int i = 0; i < DELETE_SET_BUCKETS; i++) {
        delete_entry_t *e = g_delete_set->buckets[i];
        while (e) {
            delete_entry_t *next = e->next;
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
char* trim(char* str) {
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return str;
    char* end = str + strlen(str) - 1;
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

/* --- Helper: Get/Create Feed Index (returns bitmask position 0-63) --- */
static uint8_t get_feed_idx(const char* name) {
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
    uint8_t idx = (uint8_t)feed_db.count;
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
static uint16_t parse_category_mask(const char* s) {
    if (!s) return THRT_CAT_UNKNOWN;
    if (isdigit((unsigned char)s[0])) {
        int cat = atoi(s);
        if (cat > 0 && cat <= 16) return (1 << (cat - 1));
        return THRT_CAT_UNKNOWN;
    }

    uint16_t mask = 0;

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
static uint64_t meta_make_key(uint8_t confidence, uint8_t type_mask,
                              uint8_t tlp_mask, uint16_t category_mask,
                              uint64_t feed_mask, const char *tags_json) {
    uint64_t k = 0xcbf29ce484222325ULL;
    k ^= confidence;    k *= 0x100000001b3ULL;
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
    return k;
}

static uint32_t add_meta_v4(uint8_t confidence, uint8_t type_mask, uint8_t tlp_mask,
                            uint16_t category_mask, uint64_t feed_mask,
                            const char *tags_json) {
    uint32_t tags_offset = 0;
    uint32_t tags_length = 0;

    /* Store tags JSON in string pool if present */
    if (tags_json && tags_json[0] != '\0') {
        tags_length = strlen(tags_json);
        ensure_capacity();
        tags_offset = str_pool.len;
        memcpy(str_pool.data + tags_offset, tags_json, tags_length + 1);
        str_pool.len += tags_length + 1;
    }

    /* Build a dedup key by hashing all metadata fields + tags content. */
    uint64_t dedup_key = meta_make_key(confidence, type_mask, tlp_mask,
                                       category_mask, feed_mask, tags_json);

    /* Lookup in hash table */
    uint32_t bucket = (uint32_t)(dedup_key % META_DEDUP_BUCKETS);
    for (meta_dedup_entry_t *e = meta_dedup_ht[bucket]; e; e = e->next) {
        if (e->key == dedup_key) {
            /* Verify fields match (handle hash collision) */
            builder_meta_v4_t *m = &meta_db.items[e->meta_idx];
            if (m->confidence == confidence &&
                m->type_mask == type_mask &&
                m->tlp_mask == tlp_mask &&
                m->category_mask == category_mask &&
                m->feed_mask == feed_mask &&
                m->tags_length == tags_length &&
                (tags_length == 0 ||
                 memcmp(str_pool.data + m->tags_offset,
                        str_pool.data + tags_offset, tags_length) == 0)) {
                return e->meta_idx;
            }
        }
    }

    /* Add new metadata entry */
    ensure_capacity();
    uint32_t idx = meta_db.count;
    meta_db.items[idx] = (builder_meta_v4_t){
        .confidence = confidence,
        .type_mask = type_mask,
        .tlp_mask = tlp_mask,
        .category_mask = category_mask,
        .feed_mask = feed_mask,
        .tags_offset = tags_offset,
        .tags_length = tags_length
    };
    meta_db.count++;

    /* Insert into dedup hash table */
    meta_dedup_entry_t *entry = xmalloc(sizeof(meta_dedup_entry_t));
    entry->key = dedup_key;
    entry->meta_idx = idx;
    entry->next = meta_dedup_ht[bucket];
    meta_dedup_ht[bucket] = entry;

    return idx;
}

/* ============================================================================
 * (type,value) IOC DEDUP + feed snapshot-replace support
 *
 * Active ONLY in --apply-delta fold mode (g_ioc_dedup_active). In a normal full
 * build it is inert, so full-build output is byte-for-byte unchanged.
 *
 * The fold path seeds this set from the just-loaded DB, so a re-delivered IOC
 * is NOT appended: a duplicate (type,value) merges its feed metadata into the
 * existing row. Identity is by VALUE, so IP ranges are deduped too, not just
 * strings.
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

static ioc_dedup_entry_t *ioc_dedup_find(uint64_t key) {
    uint32_t b = (uint32_t)(key % IOC_DEDUP_BUCKETS);
    for (ioc_dedup_entry_t *e = g_ioc_dedup_ht[b]; e; e = e->next)
        if (e->key == key) return e;
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

/* Union two metadata records -> a deduped meta_idx covering both feeds.
 * Scalar fields are copied to locals + tags to a stack buffer BEFORE calling
 * add_meta_v4 (which may realloc meta_db, invalidating a/b). */
static uint32_t merge_meta(uint32_t a_idx, uint32_t b_idx) {
    if (a_idx == b_idx) return a_idx;
    if (a_idx >= meta_db.count || b_idx >= meta_db.count) return a_idx;
    builder_meta_v4_t *a = &meta_db.items[a_idx];
    builder_meta_v4_t *b = &meta_db.items[b_idx];
    uint8_t  conf = a->confidence > b->confidence ? a->confidence : b->confidence;
    uint8_t  type = a->type_mask | b->type_mask;
    uint8_t  tlp  = a->tlp_mask  | b->tlp_mask;
    uint16_t cat  = (uint16_t)(a->category_mask | b->category_mask);
    uint64_t feeds = a->feed_mask | b->feed_mask;
    char tagbuf[MAX_TAGS_JSON]; tagbuf[0] = '\0';
    if (a->tags_length && a->tags_length < MAX_TAGS_JSON) {
        memcpy(tagbuf, str_pool.data + a->tags_offset, a->tags_length);
        tagbuf[a->tags_length] = '\0';
    } else if (b->tags_length && b->tags_length < MAX_TAGS_JSON) {
        memcpy(tagbuf, str_pool.data + b->tags_offset, b->tags_length);
        tagbuf[b->tags_length] = '\0';
    }
    return add_meta_v4(conf, type, tlp, cat, feeds, tagbuf);
}

/* Returns 1 if the caller should append a NEW IOC row; 0 if the IOC was a
 * duplicate (feed metadata merged into the existing row, no new row). */
static int ioc_dedup_pre_add(uint64_t key, uint32_t meta_idx) {
    if (!g_ioc_dedup_active) return 1;
    ioc_dedup_entry_t *e = ioc_dedup_find(key);
    if (!e) return 1;
    uint32_t *slot = ioc_meta_slot(e->kind, e->index);
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
        if (ip.family == 4) {
            uint64_t key = ioc_key_ipv4(ip.v4_start, ip.v4_end);
            if (!ioc_dedup_pre_add(key, meta_idx)) return;
            ensure_capacity();
            uint32_t idx = (uint32_t)ip_db.count;
            ip_db.items[ip_db.count++] = (builder_ip_t){ ip.v4_start, ip.v4_end, meta_idx };
            ioc_dedup_commit(key, IOC_KIND_IPV4, idx);
            stats.ipv4_count++;
            return;
        }
        uint64_t key = ioc_key_ipv6(ip.v6_start, ip.v6_end);
        if (!ioc_dedup_pre_add(key, meta_idx)) return;
        ensure_capacity();
        uint32_t idx = (uint32_t)ip6_db.count;
        builder_ipv6_t *e = &ip6_db.items[ip6_db.count];
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
        if (!ioc_dedup_pre_add(key, meta_idx)) return;
        ensure_capacity();
        size_t len = strlen(value);
        size_t offset = str_pool.len;
        memcpy(str_pool.data + offset, value, len + 1);
        str_pool.len += len + 1;

        uint32_t idx = (uint32_t)str_db.count;
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
    if (!ioc || strlen(ioc->value) == 0) return;

    if (ioc->action == '-') {
        uint64_t hash = thrt_hash(ioc->value);
        delete_set_add(hash);
        stats.deleted_count++;
        if (g_verbose) {
            printf("  [DELETE] %s\n", ioc->value);
        }
        return;
    }

    uint8_t type_mask = layer_to_type_mask(g_current_layer);
    uint8_t feed_idx = get_feed_idx(ioc->feed);
    uint64_t feed_mask = (1ULL << feed_idx);

    /* For tags layer, TLP is not applicable */
    uint8_t tlp = (g_current_layer == LAYER_TAGS) ? 0 : ioc->tlp_mask;

    uint32_t meta_idx = add_meta_v4(
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
char* json_get_val(char* json, const char* key, char* out_buf, size_t max_len) {
    char search[64]; snprintf(search, sizeof(search), "\"%s\"", key);
    char *p = strstr(json, search);
    if (!p) return NULL;
    p = strchr(p, ':'); if (!p) return NULL;
    p++; while(*p && isspace(*p)) p++;

    if (*p == '"') {
        p++; char *end = strchr(p, '"'); if (!end) return NULL;
        size_t len = end - p; if (len >= max_len) len = max_len - 1;
        strncpy(out_buf, p, len); out_buf[len] = 0;
        return out_buf;
    } else if (*p == '[') {
        p++; while(*p && isspace(*p)) p++;
        if (*p == '"') {
            p++; char *end = strchr(p, '"'); if (!end) return NULL;
            size_t len = end - p; if (len >= max_len) len = max_len - 1;
            strncpy(out_buf, p, len); out_buf[len] = 0;
            return out_buf;
        }
    } else {
        char *end = p; while(isdigit(*end) || *end == '-') end++;
        size_t len = end - p; if (len >= max_len) len = max_len - 1;
        strncpy(out_buf, p, len); out_buf[len] = 0;
        return out_buf;
    }
    return NULL;
}

void unescape_json(char *str) {
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
    buf[0] = '\0';
    if (p >= end || *p != '"') return p;
    p++; /* skip opening quote */
    size_t i = 0;
    while (p < end && *p != '"') {
        if (*p == '\\' && p + 1 < end) {
            p++; /* skip backslash */
            char c = *p;
            switch (c) {
                case 'n': c = '\n'; break;
                case 't': c = '\t'; break;
                case 'r': c = '\r'; break;
                /* \", \\, \/ pass through as-is */
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
    p = skip_ws(p, end);
    int neg = 0, val = 0;
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
void process_tags_csv(const char* filename) {
    FILE *f = fopen(filename, "r");
    if (!f) { fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno)); exit(1); }

    if (g_verbose) printf("%s %sProcessing %-14s: %s%s\n",
                          ICON_INFO, COL_BOLD, "Tags CSV", filename, COL_RESET);

    char line[MAX_LINE_LEN];
    size_t count = 0;

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == 0 || line[0] == '#') continue;

        /* Parse: value,tag1,tag2,tag3,... */
        char *value = strtok(line, ",");
        if (!value) continue;
        value = trim(value);

        /* Build JSON array from remaining tokens */
        char tags_json[MAX_TAGS_JSON] = "[";
        char *tag;
        int first = 1;
        int tags_truncated = 0;

        while ((tag = strtok(NULL, ",")) != NULL) {
            tag = trim(tag);
            size_t tag_len = strlen(tag);
            if (tag_len == 0) continue;

            /* Room needed: optional ',' + '"' + tag + '"' + closing ']' + NUL.
             * Stop cleanly if this tag would not fit rather than overflow the
             * buffer (feed data is external and untrusted). */
            if (strlen(tags_json) + (first ? 0 : 1) + tag_len + 4 >= sizeof(tags_json)) {
                tags_truncated = 1;
                break;
            }
            if (!first) strcat(tags_json, ",");
            strcat(tags_json, "\"");
            strcat(tags_json, tag);
            strcat(tags_json, "\"");
            first = 0;
        }
        strcat(tags_json, "]");
        if (tags_truncated) {
            fprintf(stderr, "%s tags for '%s' exceed %d bytes, list truncated\n", ICON_WARN, value,
                    MAX_TAGS_JSON);
        }

        if (first) continue; /* No tags found */

        normalized_ioc_v4_t ioc = {0};
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
void process_tags_json(const char* filename) {
    FILE *f = fopen(filename, "r");
    if (!f) { fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno)); exit(1); }

    if (g_verbose) printf("%s %sProcessing %-14s: %s%s\n",
                          ICON_INFO, COL_BOLD, "Tags JSON", filename, COL_RESET);

    char line[MAX_LINE_LEN];
    size_t count = 0;

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == 0 || line[0] != '{') continue;

        char value[512] = {0};
        if (!json_get_val(line, "index", value, sizeof(value))) continue;

        /* Extract tags array as-is */
        char *tags_start = strstr(line, "\"tags\"");
        if (!tags_start) continue;
        tags_start = strchr(tags_start, '[');
        if (!tags_start) continue;

        char *tags_end = strchr(tags_start, ']');
        if (!tags_end) continue;

        char tags_json[MAX_TAGS_JSON] = {0};
        size_t len = tags_end - tags_start + 1;
        if (len >= sizeof(tags_json)) len = sizeof(tags_json) - 1;
        strncpy(tags_json, tags_start, len);

        normalized_ioc_v4_t ioc = {0};
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
void process_csv(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) { fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno)); exit(1); }

    char line[MAX_LINE_LEN];
    if (g_verbose) printf("%s %sProcessing %-14s: %s%s\n",
                          ICON_INFO, COL_BOLD, "CSV", filename, COL_RESET);

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == 0 || line[0] == '#') continue;

        char *tokens[7] = {0};
        char *p = strtok(line, ",");
        int i = 0;
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
        int col_offset = 0;
        char action = '+';
        if (tokens[0][0] == '+' && tokens[0][1] == '\0') {
            action = '+'; col_offset = 1;
        } else if (tokens[0][0] == '-' && tokens[0][1] == '\0') {
            action = '-'; col_offset = 1;
        }

        int ncols = i - col_offset;
        if (ncols < 2) { stats.skipped_count++; continue; }

        normalized_ioc_v4_t ioc = {0};
        ioc.action = action;
        snprintf(ioc.type, sizeof(ioc.type), "%s", tokens[col_offset + 0]);
        snprintf(ioc.value, sizeof(ioc.value), "%s", tokens[col_offset + 1]);
        ioc.confidence = (ncols > 2) ? atoi(tokens[col_offset + 2]) : 50;
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
void process_rsyslog_json(const char* filename) {
    FILE *f = fopen(filename, "r");
    if (!f) { fprintf(stderr, "Error opening %s\n", filename); exit(1); }

    fseek(f, 0, SEEK_END); long fsize = ftell(f); rewind(f);
    if (fsize < 0) { fprintf(stderr, "Error: cannot determine size of %s\n", filename); fclose(f); exit(1); }
    char *content = xmalloc((size_t)fsize + 1);
    size_t nread = fread(content, 1, (size_t)fsize, f);
    content[nread] = 0;
    fclose(f);

    if (g_verbose) printf("%s %sProcessing %-14s: %s (%.2f MB)%s\n",
                          ICON_INFO, COL_BOLD, "Lookup (JSON)", filename,
                          fsize/(1024.0*1024.0), COL_RESET);

    char *cursor = content;

    while ((cursor = strstr(cursor, "\"index\":"))) {
        char *idx_start = strchr(cursor, ':'); if (!idx_start) break;
        idx_start = strchr(idx_start, '"'); if (!idx_start) break; idx_start++;
        char *idx_end = strchr(idx_start, '"'); if (!idx_end) break;
        *idx_end = 0; char *ioc_val = idx_start;

        char *val_marker = strstr(idx_end + 1, "\"value\":"); if (!val_marker) break;
        char *val_start = strchr(val_marker, ':'); if (!val_start) break;
        val_start = strchr(val_start, '"'); if (!val_start) break; val_start++;

        char *val_end = val_start;
        while (*val_end) { if (*val_end == '"' && *(val_end-1) != '\\') break; val_end++; }
        *val_end = 0;

        unescape_json(val_start);

        char tlp_str[32] = "clear";
        char feed_str[256] = "Unknown";
        char score_str[16] = "50";
        char type_str[32] = "unknown";

        json_get_val(val_start, "tlp", tlp_str, sizeof(tlp_str));
        json_get_val(val_start, "max_score", score_str, sizeof(score_str));
        json_get_val(val_start, "type", type_str, sizeof(type_str));
        json_get_val(val_start, "feed", feed_str, sizeof(feed_str));

        normalized_ioc_v4_t ioc = {0};
        ioc.action = '+';
        snprintf(ioc.value, sizeof(ioc.value), "%s", ioc_val);
        snprintf(ioc.type, sizeof(ioc.type), "%s", type_str);
        ioc.confidence = atoi(score_str);
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
void process_plaintext(const char* filename) {
    FILE *f = fopen(filename, "r");
    if (!f) { fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno)); exit(1); }

    if (g_verbose) printf("%s %sProcessing %-14s: %s%s\n",
                          ICON_INFO, COL_BOLD, "Plain Text", filename, COL_RESET);

    char line[MAX_LINE_LEN];
    size_t count = 0;

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        char *val = trim(line);
        if (val[0] == 0 || val[0] == '#' || val[0] == ';') continue;

        normalized_ioc_v4_t ioc = {0};
        ioc.action = '+';
        snprintf(ioc.value, sizeof(ioc.value), "%s", val);
        ioc.confidence = 50;
        ioc.category_mask = 0;
        ioc.tlp_mask = THRT_TLP_CLEAR;
        snprintf(ioc.feed, sizeof(ioc.feed), "%s", g_default_source);

        /* Auto-detect type */
        struct in_addr a4;
        struct in6_addr a6;
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
    int need = (*pos > 1 ? 1 : 0) + 1 + (int)label_len + 1; /* comma + quote + label + quote */
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
            p = skip_ws(p, end);
            if (p >= end || *p == '}') break;
            if (*p == ',') { p++; continue; }

            if (*p != '"') break;

            char key[32];
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
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++; /* skip '{' */

    char tlp_str[64] = "";
    char type_str[64] = "";
    int max_score = 0;
    uint64_t feed_mask = 0;
    char labels_json[MAX_TAGS_JSON];
    int labels_pos = 1;

    labels_json[0] = '[';
    labels_json[1] = '\0';

    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') break;

        char key[32];
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
    uint8_t confidence = (max_score > 100) ? 100 : (max_score < 0) ? 0 : (uint8_t)max_score;

    /* If no feeds were found, assign default */
    if (feed_mask == 0) {
        uint8_t idx = get_feed_idx(g_default_source);
        feed_mask = (1ULL << idx);
    }

    /* Build metadata directly (bypasses normalized_ioc_v4_t for multi-feed) */
    uint8_t type_mask = layer_to_type_mask(g_current_layer);
    uint8_t tlp_mask = parse_tlp_mask(tlp_str);
    uint16_t category_mask = parse_category_mask(type_str);
    const char *tags = (labels_pos > 2) ? labels_json : NULL; /* >2 means we have at least one label */

    uint32_t meta_idx = add_meta_v4(confidence, type_mask, tlp_mask,
                                     category_mask, feed_mask, tags);
    add_ioc(ioc_value, type_str, meta_idx);
    stats.added_count++;

    return p;
}

/* Main CTI dictionary JSON processor */
void process_cti_json(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno));
        exit(1);
    }

    struct stat sb;
    if (fstat(fd, &sb) < 0 || sb.st_size == 0) {
        fprintf(stderr, "%s Empty or unreadable file: %s\n", ICON_WARN, filename);
        close(fd);
        return;
    }

    const char *map = (const char *)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "mmap failed for %s: %s\n", filename, strerror(errno));
        close(fd);
        exit(1);
    }

#ifdef MADV_SEQUENTIAL
    madvise((void *)map, sb.st_size, MADV_SEQUENTIAL);
#endif

    const char *end = map + sb.st_size;
    const char *p = map;

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

    size_t count = 0;
    size_t errors = 0;

    while (p < end) {
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
        char ioc_value[512];
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
 *   Single event:  {"Event": {"info":"...", "Attribute":[...], ...}}
 *   Multi-event:   {"response": [{"Event":{...}}, {"Event":{...}}]}
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
        p = skip_ws(p, end);
        if (p >= end || *p == ']') break;
        if (*p == ',') { p++; continue; }
        if (*p != '{') { p = skip_json_val(p, end); continue; }
        p++; /* skip '{' */

        char tag_name[256] = "";

        while (p < end) {
            p = skip_ws(p, end);
            if (p >= end || *p == '}') break;
            if (*p == ',') { p++; continue; }
            if (*p != '"') break;

            char key[32];
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
                          uint8_t tlp_mask, const char *tags_json) {
    const char *ioc_type = misp_type_to_ioc_type(misp_type);
    if (!ioc_type) return 0;

    /* Composite: domain|ip -> emit both parts separately */
    if (strcmp(ioc_type, "domain|ip") == 0) {
        char vbuf[512];
        snprintf(vbuf, sizeof(vbuf), "%s", value);
        char *pipe = strchr(vbuf, '|');
        int count = 0;

        if (pipe) {
            *pipe = '\0';
            /* Emit domain (left of pipe) */
            normalized_ioc_v4_t ioc = {0};
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
            const char *ip_part = pipe + 1;
            if (ip_part[0]) {
                memset(&ioc, 0, sizeof(ioc));
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
    char clean_value[512];
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

    normalized_ioc_v4_t ioc = {0};
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
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++; /* skip '{' */

    char misp_type[64] = "";
    char value[512] = "";
    char category[128] = "";
    int to_ids = 1; /* default: import */

    /* Attribute-level TLP and tags */
    char attr_tlp[64] = "";
    char attr_tags[MAX_TAGS_JSON];
    int attr_tags_pos = 1;
    attr_tags[0] = '[';
    attr_tags[1] = '\0';

    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') break;

        char key[32];
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

    /* Skip non-IDS attributes */
    if (!to_ids) {
        (*skipped)++;
        return p;
    }

    /* Skip unsupported types */
    if (!misp_type_to_ioc_type(misp_type)) {
        (*skipped)++;
        return p;
    }

    /* Resolve TLP: attribute-level overrides event-level */
    uint8_t tlp = attr_tlp[0] ? parse_tlp_mask(attr_tlp) : event_tlp;

    /* Merge tags: event tags + attribute tags */
    char merged_tags[MAX_TAGS_JSON];
    int merged_pos = 1;
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

    uint16_t cat_mask = misp_category_to_mask(category);
    const char *tags = (merged_pos > 2) ? merged_tags : NULL;

    int n = emit_misp_ioc(misp_type, value, event_confidence, cat_mask, tlp, tags);
    *emitted += n;

    return p;
}

/* Parse one MISP Event object.
 * p points to '{'. Returns pointer past '}'.
 * Uses two-pass approach: first pass collects metadata + saves positions
 * of Attribute/Object arrays, second pass emits IOCs. */
static const char *parse_misp_event(const char *p, const char *end,
                                     size_t *emitted, size_t *skipped) {
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++; /* skip '{' */

    char event_info[256] = "";
    int threat_level = 0;

    /* Event-level TLP and tags */
    char event_tlp[64] = "";
    char event_tags[MAX_TAGS_JSON];
    int event_tags_pos = 1;
    event_tags[0] = '[';
    event_tags[1] = '\0';

    /* Save positions for second-pass parsing (data stays in mmap) */
    const char *attr_start = NULL;
    const char *obj_start = NULL;

    /* First pass: collect event metadata, save array positions */
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') break;

        char key[32];
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

    uint8_t ev_tlp = parse_tlp_mask(event_tlp);
    uint8_t ev_confidence = misp_threat_level_to_confidence(threat_level);
    const char *ev_tags = (event_tags_pos > 2) ? event_tags : NULL;

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
            op = skip_ws(op, end);
            if (op >= end || *op == ']') break;
            if (*op == ',') { op++; continue; }
            if (*op != '{') { op = skip_json_val(op, end); continue; }

            /* Walk Object fields looking for nested Attribute array */
            const char *nested_attr = NULL;
            op++; /* skip '{' */
            while (op < end) {
                op = skip_ws(op, end);
                if (op >= end || *op == '}') break;
                if (*op == ',') { op++; continue; }
                if (*op != '"') break;

                char okey[32];
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

/* Main MISP JSON processor.
 * Handles both single-event and multi-event (restSearch) formats. */
void process_misp_json(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno));
        exit(1);
    }

    struct stat sb;
    if (fstat(fd, &sb) < 0 || sb.st_size == 0) {
        fprintf(stderr, "%s Empty or unreadable file: %s\n", ICON_WARN, filename);
        close(fd);
        return;
    }

    const char *map = (const char *)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "mmap failed for %s: %s\n", filename, strerror(errno));
        close(fd);
        exit(1);
    }

#ifdef MADV_SEQUENTIAL
    madvise((void *)map, sb.st_size, MADV_SEQUENTIAL);
#endif

    const char *end = map + sb.st_size;
    const char *p = map;

    if (g_verbose) printf("%s %sProcessing %-14s: %s (%.2f MB)%s\n",
                           ICON_INFO, COL_BOLD, "MISP JSON", filename,
                           sb.st_size / (1024.0 * 1024.0), COL_RESET);

    size_t emitted = 0, skipped = 0;

    /* Detect format: {"Event":{...}} or {"response":[...]} */
    p = skip_ws(p, end);
    if (p >= end || *p != '{') {
        fprintf(stderr, "%s %s is not a JSON object\n", ICON_WARN, filename);
        goto done;
    }
    p++; /* skip '{' */

    p = skip_ws(p, end);
    if (p >= end || *p != '"') goto done;

    char first_key[32];
    p = extract_json_str(p, end, first_key, sizeof(first_key));
    p = skip_ws(p, end);
    if (p >= end || *p != ':') goto done;
    p++;
    p = skip_ws(p, end);

    if (strcmp(first_key, "Event") == 0) {
        /* Single event: {"Event": {...}} */
        p = parse_misp_event(p, end, &emitted, &skipped);
    } else if (strcmp(first_key, "response") == 0) {
        /* Multi-event (restSearch): {"response": [{"Event":{...}}, ...]} */
        if (p >= end || *p != '[') goto done;
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
}

/* ============================================================================
 * BUILDER UTILITIES
 * ============================================================================ */
int cmp_ip(const void *a, const void *b) {
    builder_ip_t *ipA = (builder_ip_t*)a;
    builder_ip_t *ipB = (builder_ip_t*)b;
    return (ipA->start > ipB->start) - (ipA->start < ipB->start);
}

int cmp_ipv6(const void *a, const void *b) {
    builder_ipv6_t *ipA = (builder_ipv6_t*)a;
    builder_ipv6_t *ipB = (builder_ipv6_t*)b;
    return memcmp(ipA->start, ipB->start, 16);
}

void build_ip_accel(void) {
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

void build_bloom(void) {
    bloom_filter = xcalloc(1, bloom_size_bits / 8);
    for (size_t i = 0; i < str_db.count; i++) {
        uint64_t h = str_db.items[i].hash;
        uint32_t h1 = (uint32_t)h;
        uint32_t h2 = (uint32_t)((h >> 32) | (h << 32));
        for (int k = 0; k < 3; k++) {
            uint32_t bit_idx = (h1 + k * h2) % bloom_size_bits;
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

/* ============================================================================
 * PROCESS FILE (with layer detection)
 * ============================================================================ */
void process_file(const char* filename) {
    /* Set default source to filename (basename) */
    const char* basename = strrchr(filename, '/');
    basename = basename ? basename + 1 : filename;
    snprintf(g_default_source, sizeof(g_default_source), "%s", basename);
    char *dot = strrchr(g_default_source, '.');
    if (dot) *dot = 0;

    const char* ext = strrchr(filename, '.');
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
    /* MISP JSON exports (.misp, .misp.json) */
    else if (strcasestr(filename, ".misp.json") || strcasecmp(ext, ".misp") == 0) {
        process_misp_json(filename);
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
    if (fd < 0) {
        fprintf(stderr, "%s Cannot open existing DB %s: %s\n", ICON_WARN, filename, strerror(errno));
        fprintf(stderr, "  Incremental mode requires an existing database. Build a full one first.\n");
        exit(1);
    }

    struct stat sb;
    fstat(fd, &sb);
    void *map = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); close(fd); exit(1); }

    thrt_header_t *hdr = (thrt_header_t*)map;
    if (hdr->magic != THRT_MAGIC || hdr->version < THRT_VERSION) {
        fprintf(stderr, "%s Existing DB is v%d - v%d required. Build a fresh V4 first.\n",
                ICON_WARN, hdr->version, THRT_VERSION);
        munmap(map, sb.st_size); close(fd); exit(1);
    }

    char *base = (char*)map;
    thrt_metadata_t *meta = (thrt_metadata_t*)(base + hdr->offset_metadata);
    thrt_ipv4_range_t *ipv4 = (thrt_ipv4_range_t*)(base + hdr->offset_ipv4);
    thrt_ipv6_range_t *ipv6 = (thrt_ipv6_range_t*)(base + hdr->offset_ipv6);
    thrt_hash_entry_t *ht = (thrt_hash_entry_t*)(base + hdr->offset_hashtable);
    char *str_base = base + hdr->offset_strings;

    /* Import feed names (preserve exact ordering for bitmask compat) */
    if (hdr->feed_count > 0 && hdr->offset_feeds > 0) {
        thrt_feed_entry_t *feeds = (thrt_feed_entry_t*)(base + hdr->offset_feeds);
        for (uint32_t i = 0; i < hdr->feed_count && i < MAX_FEEDS; i++) {
            get_feed_idx(feeds[i].name);  /* This creates feed entries in order */
        }
    }

    /* Import metadata entries (direct copy, preserving indices) */
    for (uint32_t i = 0; i < hdr->metadata_count; i++) {
        ensure_capacity();
        meta_db.items[meta_db.count++] = (builder_meta_v4_t){
            .confidence    = meta[i].confidence,
            .type_mask     = meta[i].type_mask,
            .tlp_mask      = meta[i].tlp_mask,
            .category_mask = meta[i].category_mask,
            .feed_mask     = meta[i].feed_mask,
            .tags_offset   = 0, /* Re-import tags below */
            .tags_length   = 0
        };

        /* Re-import tags into our string pool */
        if (meta[i].tags_offset > 0 && meta[i].tags_length > 0) {
            ensure_capacity();
            uint32_t new_offset = str_pool.len;
            memcpy(str_pool.data + new_offset, str_base + meta[i].tags_offset, meta[i].tags_length);
            str_pool.len += meta[i].tags_length;
            /* Null-terminate */
            str_pool.data[str_pool.len++] = '\0';
            meta_db.items[i].tags_offset = new_offset;
            meta_db.items[i].tags_length = meta[i].tags_length;
        }
    }

    /* Import IPv4 ranges */
    for (uint32_t i = 0; i < hdr->ipv4_range_count; i++) {
        ensure_capacity();
        ip_db.items[ip_db.count++] = (builder_ip_t){
            .start = ipv4[i].ip_start,
            .end   = ipv4[i].ip_end,
            .meta_idx = ipv4[i].meta_idx
        };
    }

    /* Import IPv6 ranges */
    for (uint32_t i = 0; i < hdr->ipv6_range_count; i++) {
        ensure_capacity();
        builder_ipv6_t *e = &ip6_db.items[ip6_db.count++];
        memcpy(e->start, ipv6[i].ip_start, 16);
        memcpy(e->end, ipv6[i].ip_end, 16);
        e->meta_idx = ipv6[i].meta_idx;
    }

    /* Import string entries (domains, hashes, emails) */
    for (uint32_t i = 0; i < hdr->hash_slots; i++) {
        if (ht[i].meta_idx == 0xFFFFFFFF) continue; /* Empty slot */

        const char *str_val = str_base + ht[i].string_offset;
        size_t len = strlen(str_val);

        ensure_capacity();
        uint32_t new_offset = str_pool.len;
        memcpy(str_pool.data + new_offset, str_val, len + 1);
        str_pool.len += len + 1;

        str_db.items[str_db.count++] = (builder_string_t){
            .hash = ht[i].hash_key,
            .offset = new_offset,
            .meta_idx = ht[i].meta_idx
        };
    }

    if (g_verbose) {
        printf("%s %sLoaded existing DB:%s %s (v%d)\n", ICON_DB, COL_BOLD, COL_RESET, filename, hdr->version);
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
void write_thrt(const char *filename) {
    /* --- Incremental: filter out deleted entries before building --- */
    if (g_delete_set && g_delete_set->count > 0) {
        size_t orig;

        /* Filter IPv4 ranges: hash the string representation of each IP */
        orig = ip_db.count;
        size_t w = 0;
        for (size_t i = 0; i < ip_db.count; i++) {
            char buf[INET_ADDRSTRLEN];
            uint32_t ip_net = htonl(ip_db.items[i].start);
            inet_ntop(AF_INET, &ip_net, buf, sizeof(buf));
            if (!delete_set_contains(thrt_hash(buf))) {
                ip_db.items[w++] = ip_db.items[i];
            }
        }
        if (g_verbose && w < orig)
            printf("   [DELETE] Removed %zu/%zu IPv4 entries\n", orig - w, orig);
        ip_db.count = w;

        /* Filter IPv6 ranges */
        orig = ip6_db.count;
        w = 0;
        for (size_t i = 0; i < ip6_db.count; i++) {
            char buf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, ip6_db.items[i].start, buf, sizeof(buf));
            if (!delete_set_contains(thrt_hash(buf))) {
                ip6_db.items[w++] = ip6_db.items[i];
            }
        }
        if (g_verbose && w < orig)
            printf("   [DELETE] Removed %zu/%zu IPv6 entries\n", orig - w, orig);
        ip6_db.count = w;

        /* Filter string entries (domains, hashes, emails) - hash is already stored */
        orig = str_db.count;
        w = 0;
        for (size_t i = 0; i < str_db.count; i++) {
            if (!delete_set_contains(str_db.items[i].hash)) {
                str_db.items[w++] = str_db.items[i];
            }
        }
        if (g_verbose && w < orig)
            printf("   [DELETE] Removed %zu/%zu string entries\n", orig - w, orig);
        str_db.count = w;
    }

    /* Sort arrays */
    if (ip_db.count > 0) qsort(ip_db.items, ip_db.count, sizeof(builder_ip_t), cmp_ip);
    if (ip6_db.count > 0) qsort(ip6_db.items, ip6_db.count, sizeof(builder_ipv6_t), cmp_ipv6);

    build_ip_accel();
    build_bloom();

    /* Atomic file replacement */
    char tmp_filename[PATH_MAX + 32];   /* room for ".tmp.<pid>" suffix */
    snprintf(tmp_filename, sizeof(tmp_filename), "%s.tmp.%d", filename, getpid());

    FILE *f = fopen(tmp_filename, "w+b");
    if (!f) { perror("fopen output"); exit(1); }

    /* Build hash table */
    uint32_t hash_slots = 1024;
    while (hash_slots < str_db.count * 2) hash_slots *= 2;
    thrt_hash_entry_t *ht = xcalloc(hash_slots, sizeof(thrt_hash_entry_t));
    memset(ht, 0xFF, hash_slots * sizeof(thrt_hash_entry_t));

    for (size_t i = 0; i < str_db.count; i++) {
        uint64_t h = str_db.items[i].hash;
        uint32_t idx = (uint32_t)h & (hash_slots - 1);
        while (ht[idx].meta_idx != 0xFFFFFFFF) idx = (idx + 1) & (hash_slots - 1);
        ht[idx].hash_key = h;
        ht[idx].string_offset = str_db.items[i].offset;
        ht[idx].meta_idx = str_db.items[i].meta_idx;
    }

    /* Calculate offsets */
    thrt_header_t hdr = {0};
    hdr.magic = THRT_MAGIC;
    hdr.version = THRT_VERSION;
    hdr.metadata_count = meta_db.count;
    hdr.ipv4_range_count = ip_db.count;
    hdr.ipv6_range_count = ip6_db.count;
    hdr.hash_slots = hash_slots;
    hdr.bloom_size_bits = bloom_size_bits;
    hdr.feed_count = feed_db.count;
    hdr.checksum_offset = offsetof(thrt_header_t, checksum);

    uint64_t offset = sizeof(thrt_header_t);
    hdr.offset_metadata = offset;  offset += meta_db.count * sizeof(thrt_metadata_t);
    hdr.offset_ipv4 = offset;      offset += ip_db.count * sizeof(thrt_ipv4_range_t);
    hdr.offset_ipv6 = offset;      offset += ip6_db.count * sizeof(thrt_ipv6_range_t);
    hdr.offset_hashtable = offset; offset += hash_slots * sizeof(thrt_hash_entry_t);
    hdr.offset_strings = offset;   offset += str_pool.len;
    hdr.offset_ip_accel = offset;  offset += sizeof(ip_accel_db);
    hdr.offset_bloom = offset;     offset += (bloom_size_bits / 8);
    hdr.offset_feeds = offset;     offset += feed_db.count * sizeof(thrt_feed_entry_t);
    hdr.offset_sources = offset;   /* Legacy compat - same as feeds for now */
    hdr.total_size = offset;

    /* Write header */
    fwrite(&hdr, sizeof(hdr), 1, f);

    /* Write metadata (V4 format) */
    for (size_t i = 0; i < meta_db.count; i++) {
        thrt_metadata_t m = {
            .confidence = meta_db.items[i].confidence,
            .type_mask = meta_db.items[i].type_mask,
            .tlp_mask = meta_db.items[i].tlp_mask,
            .pad1 = 0,
            .category_mask = meta_db.items[i].category_mask,
            .pad2 = 0,
            .feed_mask = meta_db.items[i].feed_mask,
            .tags_offset = meta_db.items[i].tags_offset,
            .tags_length = meta_db.items[i].tags_length
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

    /* Write acceleration structures (ip_accel_db is a fixed array, never NULL) */
    fwrite(ip_accel_db, sizeof(ip_accel_db), 1, f);
    if (bloom_size_bits > 0) fwrite(bloom_filter, 1, bloom_size_bits / 8, f);

    /* Write feed name table */
    for (size_t i = 0; i < feed_db.count; i++) {
        thrt_feed_entry_t fe = {0};
        snprintf(fe.name, THRT_FEED_NAME_MAX, "%s", feed_db.items[i].name);
        fwrite(&fe, sizeof(fe), 1, f);
    }

    /* Compute and write checksum */
    fflush(f);
    uint32_t checksum = compute_file_checksum(f, hdr.checksum_offset);
    fseek(f, hdr.checksum_offset, SEEK_SET);
    fwrite(&checksum, sizeof(checksum), 1, f);

    fclose(f);
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
 * arrays and writes once at exit. The --apply-delta fold instead
 * reloads the on-disk DB (load_existing_thrt), applies ONE segment, and rewrites
 * - so it clears the in-memory arrays first via this reset. Without it the
 * previous run's entries would be re-emitted into the next write (double count).
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
    snprintf(g_default_source, sizeof(g_default_source), "%s", "Unknown");
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
    if (parse_ip_or_cidr(val, 1, &ip)) {
        snprintf(out, outsz, "%s", "ip");
        return;
    }
    size_t len = strlen(val);
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
    cm->ind = cm->type = cm->conf = cm->cat = cm->tlp = cm->feed = cm->action = -1;
    int matched = 0;
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

void parse_csv_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "%s Error opening %s: %s\n", ICON_WARN, filename, strerror(errno));
        return;
    }

    /* Default feed = filename stem (apply_delta_segment sets g_default_source
     * from --feed-key, but be self-sufficient if called directly). */
    if (strcmp(g_default_source, "Unknown") == 0) {
        const char *bn = strrchr(filename, '/');
        bn = bn ? bn + 1 : filename;
        snprintf(g_default_source, sizeof(g_default_source), "%s", bn);
        char *dot = strrchr(g_default_source, '.');
        if (dot) *dot = 0;
    }

    if (g_verbose) printf("%s %sProcessing %-14s: %s%s\n",
                          ICON_INFO, COL_BOLD, "CSV (delta)", filename, COL_RESET);

    char line[MAX_LINE_LEN];
    csv_colmap_t cm = { .ind = -1, .type = -1, .conf = -1, .cat = -1,
                        .tlp = -1, .feed = -1, .action = -1 };
    int have_header = 0;
    int header_checked = 0;

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == 0 || line[0] == '#') continue;

        char *tokens[16] = {0};
        char *p = strtok(line, ",");
        int n = 0;
        while (p && n < 16) { tokens[n++] = trim(p); p = strtok(NULL, ","); }
        if (n == 0) continue;

        /* First data row: decide header vs. data. */
        if (!header_checked) {
            header_checked = 1;
            csv_colmap_t probe;
            if (csv_parse_header(tokens, n, &probe)) {
                cm = probe;
                have_header = 1;
                continue; /* consumed the header row */
            }
            /* No header: column 0 is the indicator, auto-detect type. */
            have_header = 0;
        }

        normalized_ioc_v4_t ioc = {0};
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
                              tokens[cm.conf][0]) ? (uint8_t)atoi(tokens[cm.conf]) : 50;
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
        if (m->tags_length == 0) { m->tags_offset = 0; continue; }
        uint32_t off = (uint32_t)np.len;
        memcpy(np.data + np.len, str_pool.data + m->tags_offset, m->tags_length);
        np.len += m->tags_length;
        np.data[np.len++] = '\0';
        m->tags_offset = off;
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
        char tagbuf[MAX_TAGS_JSON];
        const char *tags = "";
        if (m->tags_length && m->tags_length < MAX_TAGS_JSON) {
            memcpy(tagbuf, str_pool.data + m->tags_offset, m->tags_length);
            tagbuf[m->tags_length] = '\0';
            tags = tagbuf;
        }
        uint64_t key = meta_make_key(m->confidence, m->type_mask, m->tlp_mask,
                                     m->category_mask, m->feed_mask, tags);
        uint32_t bkt = (uint32_t)(key % META_DEDUP_BUCKETS);
        meta_dedup_entry_t *ent = malloc(sizeof(*ent));
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
    if (fidx < 0) return 0;            /* feed never seen - nothing to replace */
    uint64_t fbit = (1ULL << (unsigned)fidx);

    /* 1. Clear the feed bit on every metadata record. */
    for (size_t i = 0; i < meta_db.count; i++)
        meta_db.items[i].feed_mask &= ~fbit;

    /* 2. Compact meta_db, dropping feed-exclusive (now feed_mask==0) records;
     *    build an old->new index remap (UINT32_MAX = dropped). */
    uint32_t *remap = malloc((meta_db.count ? meta_db.count : 1) * sizeof(uint32_t));
    if (!remap) { fprintf(stderr, "FATAL: Out of Memory (evict remap)\n"); exit(1); }
    size_t mw = 0;
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
    size_t dropped = 0, w;
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
 * Per-IOC expiry/generation cannot live in the V4 .thrt (the 24B
 * thrt_metadata_t is full; per-IOC TTL would be a V5 ABI bump), so generation
 * and last-update live in a tiny TEXT file next to the .thrt, never in the
 * header, and cost no ABI change. It powers:
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
    g_gen.count = 0;
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
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
    char tmp[PATH_MAX + 32];            /* room for ".tmp.<pid>" suffix */
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, getpid());
    FILE *f = fopen(tmp, "w");
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
 * ONE-SHOT DELTA FOLD
 *
 * Folds exactly ONE delta segment into out_thrt, idempotently, then exits.
 * One segment per invocation, in a separate process, so a malformed segment
 * cannot take down a long-running reader. It does not scan a directory or move
 * files: whoever delivers a segment owns staging it and signalling the reload.
 *
 * Three guards keep a re-delivered segment from growing the database:
 *   (1) snapshot-replace - is_snapshot evicts feed_key's prior IOCs first.
 *   (2) (type,value) dedup - re-delivered IOCs (incl. IP ranges) don't append.
 *   (3) bounded write - load -> apply -> write_thrt (atomic tmp+rename).
 * A generation companion file adds anti-resurrection and feed-level TTL.
 *
 * TTL: per-IOC expiry is NOT persisted in .thrt (the V4 thrt_metadata_t is a
 * full 24B dedup-shared record; per-IOC expiry would need a V5 ABI bump and a
 * matching reader change). ttl_days only prunes expired entries at fold time,
 * before the write; it is not stored as a per-IOC field.
 * ============================================================================ */
static int apply_delta_segment(const char *seg_path, const char *out_thrt,
                               const char *feed_key, int is_snapshot,
                               uint32_t ttl_days, uint64_t generation) {
    builder_state_reset();
    ioc_dedup_reset();
    g_ioc_dedup_active = 0;

    /* Resolve the feed identity: explicit feed_key, else the filename stem. */
    char feedbuf[THRT_FEED_NAME_MAX];
    if (feed_key && *feed_key) {
        snprintf(feedbuf, sizeof(feedbuf), "%s", feed_key);
    } else {
        const char *bn = strrchr(seg_path, '/');
        bn = bn ? bn + 1 : seg_path;
        snprintf(feedbuf, sizeof(feedbuf), "%s", bn);
        char *dot = strrchr(feedbuf, '.');
        if (dot) *dot = 0;
    }
    snprintf(g_default_source, sizeof(g_default_source), "%s", feedbuf);

    /* Reload the current on-disk DB to fold INTO it. */
    struct stat sb;
    if (stat(out_thrt, &sb) == 0)
        load_existing_thrt(out_thrt);

    /* Generation companion file (anti-resurrection). */
    char genpath[PATH_MAX + 32];        /* room for ".gen" suffix */
    snprintf(genpath, sizeof(genpath), "%s.gen", out_thrt);
    gen_load(genpath);
    feed_gen_t *fg = gen_find(feedbuf);
    uint64_t prev_gen = fg ? fg->generation : 0;
    if (generation > 0 && fg && generation <= prev_gen) {
        fprintf(stderr,
                "%s apply-delta: stale generation %llu <= %llu for feed '%s' - "
                "skipping (anti-resurrection)\n",
                ICON_WARN, (unsigned long long)generation,
                (unsigned long long)prev_gen, feedbuf);
        gen_free();
        return 0;
    }
    uint64_t new_gen = (generation > 0) ? generation : prev_gen + 1;

    /* (1) Snapshot-replace: drop this feed's prior contents before re-adding. */
    if (is_snapshot)
        feed_snapshot_evict(feedbuf);

    /* Feed-level TTL: evict feeds not refreshed within ttl_days. */
    if (ttl_days > 0) {
        time_t now = time(NULL);
        uint64_t horizon = (uint64_t)now - (uint64_t)ttl_days * 86400ULL;
        for (size_t i = 0; i < g_gen.count; ) {
            feed_gen_t *e = &g_gen.items[i];
            if (strcasecmp(e->feed, feedbuf) != 0 && e->updated > 0 && e->updated < horizon) {
                char stale[THRT_FEED_NAME_MAX];
                snprintf(stale, sizeof(stale), "%s", e->feed);
                feed_snapshot_evict(stale);
                gen_remove(stale);          /* swap-remove -> re-check same i */
            } else {
                i++;
            }
        }
    }

    /* Reclaim freed string-pool bytes UNCONDITIONALLY so the reserved offset-0
     * NUL is present on every fold - this makes the .thrt size deterministic
     * (byte-idempotent) whether or not an eviction happened this fold. */
    compact_str_pool();

    /* Seed dedup tables from survivors, then fold the segment with dedup ON. */
    rebuild_meta_dedup();
    ioc_dedup_seed();
    g_ioc_dedup_active = 1;

    const char *bn = strrchr(seg_path, '/');
    bn = bn ? bn + 1 : seg_path;
    int is_misp = (strcasestr(bn, ".misp.json") != NULL);
    const char *ext = strrchr(bn, '.');
    int is_json = (ext && strcasecmp(ext, ".json") == 0);
    int is_csv  = (ext && strcasecmp(ext, ".csv")  == 0);
    if (is_misp || is_json) {
        process_misp_json(seg_path);
    } else if (is_csv) {
        parse_csv_file(seg_path);          /* honours +/- rows incl. deletes */
    } else {
        fprintf(stderr, "%s apply-delta: unknown segment format: %s\n", ICON_WARN, bn);
        g_ioc_dedup_active = 0;
        ioc_dedup_reset();
        gen_free();
        return 1;
    }

    g_ioc_dedup_active = 0;
    write_thrt(out_thrt);                  /* applies deletes, sorts, atomic rename */

    /* Persist the advanced generation cursor for this feed. */
    gen_set(feedbuf, new_gen, (uint64_t)time(NULL));
    gen_save(genpath);

    ioc_dedup_reset();
    gen_free();
    return 0;
}

/* ============================================================================
 * USAGE
 * ============================================================================ */
void print_usage(const char* prog) {
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
            delta_ttl_days = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--generation") == 0 && i + 1 < argc) {
            delta_generation = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            thrt_out = argv[i + 1];   /* don't consume i: getopt below also reads it */
        } else if (strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        }
    }

    if (delta_seg) {
        if (!thrt_out) {
            fprintf(stderr, "Error: --apply-delta requires -o <out.thrt>\n\n");
            print_usage(argv[0]);
            exit(1);
        }
        int rc = apply_delta_segment(delta_seg, thrt_out, delta_feed_key,
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
    if (g_incremental) {
        if (g_verbose) printf("%s Incremental mode: loading existing database\n", ICON_GEAR);
        load_existing_thrt(thrt_out);
    }

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

    write_thrt(thrt_out);

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
