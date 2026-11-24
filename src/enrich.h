/* Public surface of libenrich.
 *
 * The on-disk formats stay header-only (thrt_format.h, thrt_overlay.h,
 * prev_format.h). The compiled API below opens a set of those files, looks
 * values up under one policy and reloads them while readers keep running.
 * A log enricher and a lookup service share it, so the policy lives here
 * once.
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0. See LICENSE.
 */
#ifndef ENRICH_H
#define ENRICH_H

#include <stddef.h>
#include <stdint.h>

#include "thrt_format.h"
#include "thrt_logic.h"
#include "thrt_ipparse.h"
#include "thrt_overlay.h"
#include "prev_format.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ENRICH_VERSION_MAJOR 0
#define ENRICH_VERSION_MINOR 1
#define ENRICH_VERSION_PATCH 0

const char *enrich_version(void);

/* ------------------------------------------------------------------------
 * Status codes. A call that can fail returns ENRICH_OK, a non-negative
 * result, or one of these.
 * ------------------------------------------------------------------------ */
#define ENRICH_OK 0
#define ENRICH_EINVAL (-1)    /* bad argument, or a NUL inside a value */
#define ENRICH_ETOOLONG (-2)  /* value longer than ENRICH_VALUE_MAX */
#define ENRICH_ENOENT (-3)    /* file missing */
#define ENRICH_EFORMAT (-4)   /* magic, layout or index check failed */
#define ENRICH_EVERSION (-5)  /* format version this library does not read */
#define ENRICH_ECHECKSUM (-6) /* CRC32C mismatch */
#define ENRICH_ENOMEM (-7)
#define ENRICH_EIO (-8)       /* open, fstat or mmap failed */

const char *enrich_strerror(int status);

/* ------------------------------------------------------------------------
 * Handle.
 *
 * An enrich_t owns the paths, the policy flags and the current snapshot. A
 * snapshot is one immutable set of the .thrt, the optional overlay and the
 * optional .prev, each mapped read-only and fully validated before it is
 * published. Readers never see a half-loaded set.
 *
 * The library reads .thrt version THRT_VERSION, overlay version
 * THRT_OVERLAY_VERSION and .prev version PREV_VERSION, and refuses others
 * with ENRICH_EVERSION.
 * ------------------------------------------------------------------------ */
typedef struct enrich enrich_t;
typedef struct enrich_snap enrich_snap_t;

typedef struct {
    size_t size;              /* sizeof(enrich_options_t); later fields append */
    const char *thrt_path;    /* NULL: no threat database */
    const char *overlay_path; /* NULL: no overlay */
    const char *prev_path;    /* NULL: no prevalence table */
    uint32_t flags;           /* ENRICH_OPT_* */
} enrich_options_t;

/* For a private, loopback, link-local, CGNAT or ULA address, drop the CTI
 * and CTI_R parts of a match and keep the tags. */
#define ENRICH_OPT_SKIP_PRIVATE 0x1u
/* enrich_open() returns a handle even when a file is missing or invalid.
 * The return value is still the first failure. Lookups miss on the
 * missing part until enrich_reload() loads it. Without this flag any
 * configured file that fails to load fails the open. */
#define ENRICH_OPT_PARTIAL 0x2u

/* At least one path is set. err (optional) receives one line that names
 * the file and the check that failed. The handle copies the paths. */
int enrich_open(enrich_t **out, const enrich_options_t *opt, char *err, size_t err_len);

/* All readers must be freed first. */
void enrich_close(enrich_t *e);

/* Components, for reload results and snapshot facts. */
#define ENRICH_C_THRT 0x1u
#define ENRICH_C_OVERLAY 0x2u
#define ENRICH_C_PREV 0x4u

/* Stat each file (device, inode, size, mtime). Load and validate the ones
 * that changed and publish a new snapshot that shares the unchanged parts.
 * A file that is missing or fails to load keeps its previous version, and
 * the first such failure is returned with err filled. Calls are serialized
 * internally and never block readers. *reloaded (optional) receives the
 * ENRICH_C_* bits that were replaced. Also frees retired snapshots that no
 * reader can still see. */
int enrich_reload(enrich_t *e, unsigned *reloaded, char *err, size_t err_len);

/* Free retired snapshots that no reader can still see. enrich_reload()
 * and enrich_reader_free() already do this. */
void enrich_reclaim(enrich_t *e);

/* Flags the handle was opened with, for enrich_lookup(). */
uint32_t enrich_lookup_flags(const enrich_t *e);

/* ------------------------------------------------------------------------
 * Readers.
 *
 * Each thread that looks values up owns one reader. enter() returns the
 * current snapshot and keeps it mapped until leave(). Reclamation is
 * quiescent-state based: when no reload happened since the last enter(),
 * enter() is two loads and writes nothing. After a reload, the first
 * enter() of each reader writes its own cache line once and issues one
 * full fence. A snapshot replaced by a reload is unmapped once every
 * reader has left or entered again. A reader that stays entered while
 * idle keeps the snapshot it holds mapped, so a thread that may idle for
 * long calls leave() first.
 *
 * Calling enter() again while entered moves the reader to the current
 * snapshot: pointers taken from the previous one stop being valid.
 * ------------------------------------------------------------------------ */
typedef struct enrich_reader enrich_reader_t;

enrich_reader_t *enrich_reader_new(enrich_t *e);
void enrich_reader_free(enrich_reader_t *r);

const enrich_snap_t *enrich_reader_enter(enrich_reader_t *r);
void enrich_reader_leave(enrich_reader_t *r);

/* ------------------------------------------------------------------------
 * Lookup.
 *
 * A value is an IPv4 or IPv6 address when inet_pton() accepts it, and a
 * string otherwise. It is taken as (pointer, length), need not be
 * NUL-terminated, and is never truncated: a longer value is refused.
 *
 * Order:
 *   1. Overlay, compared on the full value. A full whitelist ends the
 *      lookup with ENRICH_R_SUPPRESSED and nothing else set. A soft
 *      whitelist sets ENRICH_R_WHITELISTED and goes on. A tag entry fills
 *      overlay_tags. An add entry fills ovl_confidence, ovl_type_mask and
 *      ovl_category_mask and sets ENRICH_R_MATCH.
 *   2. .thrt. With ENRICH_OPT_SKIP_PRIVATE and a private address, only the
 *      tags survive and ENRICH_R_PRIVATE_SKIP is set.
 *
 * confidence, tlp_mask, category_mask and feed_mask describe public CTI
 * only. A restricted match shows as THRT_TYPE_CTI_R in type_mask and its
 * score in confidence_r, never as a feed name or a marking.
 * ------------------------------------------------------------------------ */
#define ENRICH_VALUE_MAX 4096

typedef enum {
    ENRICH_KIND_STRING = 0,
    ENRICH_KIND_IPV4 = 1,
    ENRICH_KIND_IPV6 = 2,
} enrich_kind_t;

#define ENRICH_R_MATCH 0x01u        /* CTI, CTI_R or overlay add, after policy */
#define ENRICH_R_PRIVATE 0x02u      /* the value is a private address */
#define ENRICH_R_PRIVATE_SKIP 0x04u /* CTI dropped by ENRICH_OPT_SKIP_PRIVATE */
#define ENRICH_R_WHITELISTED 0x08u  /* overlay soft whitelist */
#define ENRICH_R_SUPPRESSED 0x10u   /* overlay full whitelist: nothing else is set */
#define ENRICH_R_OVERLAY 0x20u      /* an overlay entry matched */
#define ENRICH_R_THRT 0x40u         /* a .thrt entry matched */

/* Pointers point into the pinned snapshot and stay valid until the reader
 * leaves or enters again. tags, labels and overlay_tags are JSON arrays of
 * strings, not NUL-terminated. tags are the context layer (inventory,
 * cartography). labels are what public CTI sources attached (MISP tags,
 * STIX labels); a restricted source adds none, and a skipped private
 * address keeps only its tags. */
typedef struct {
    uint8_t kind;               /* enrich_kind_t */
    uint8_t flags;              /* ENRICH_R_* */
    uint8_t type_mask;          /* THRT_TYPE_* from the .thrt, after policy */
    uint8_t confidence;         /* public CTI, 0-100 */
    uint8_t confidence_r;       /* restricted CTI, 0-100 */
    uint8_t tlp_mask;           /* THRT_TLP_* of public CTI */
    uint16_t category_mask;     /* THRT_CAT_* of public CTI */
    uint64_t feed_mask;         /* public CTI feeds: bit i is enrich_feed_name(s, i) */
    uint8_t ovl_type_mask;      /* overlay add or tag entry */
    uint8_t ovl_confidence;     /* overlay add entry */
    uint16_t ovl_category_mask; /* overlay add entry */
    uint32_t tags_len;
    const char *tags;           /* .thrt context tags */
    const char *labels;         /* .thrt public CTI labels */
    const char *overlay_tags;   /* overlay tag entry */
    uint32_t labels_len;
    uint32_t overlay_tags_len;
    uint64_t reserved[2];
} enrich_result_t;

/* 1: something to report: a match, a whitelist, a suppression, tags or
 * labels.
 * 0: nothing to report (flags may still say ENRICH_R_PRIVATE).
 * Negative: ENRICH_EINVAL or ENRICH_ETOOLONG, with *out zeroed. A NULL
 * snapshot, or one without a .thrt, misses on that part. opt_flags is
 * ENRICH_OPT_SKIP_PRIVATE or 0; enrich_lookup_flags() gives the handle's. */
int enrich_lookup(const enrich_snap_t *s, uint32_t opt_flags, const char *value, size_t len, enrich_result_t *out);

typedef struct {
    const char *value;
    size_t len;
} enrich_value_t;

/* enrich_lookup() over n values. Addresses are parsed and strings hashed
 * first, with their bloom filter lines prefetched, then the tables are
 * probed. status[i] (optional) receives each per-value return. Returns how
 * many values have something to report. */
size_t enrich_lookup_batch(const enrich_snap_t *s, uint32_t opt_flags, const enrich_value_t *v, size_t n,
                           enrich_result_t *out, int *status);

/* Event-level summary over several lookups, as a log enricher folds the
 * fields of one message. Start from a zeroed struct. */
typedef struct {
    uint8_t match;          /* any ENRICH_R_MATCH */
    uint8_t whitelisted;    /* any ENRICH_R_WHITELISTED */
    uint8_t confidence;     /* max of public, restricted and overlay add scores */
    uint8_t type_mask;      /* OR of .thrt and overlay types */
    uint8_t tlp_mask;       /* OR of public CTI markings */
    uint8_t reserved0;
    uint16_t category_mask; /* OR of public CTI and overlay add categories */
    uint64_t feed_mask;     /* OR of public CTI feeds */
} enrich_event_t;

void enrich_event_fold(enrich_event_t *ev, const enrich_result_t *r);

/* ------------------------------------------------------------------------
 * Prevalence, separate from lookup. Returns 1 and fills *out when the
 * snapshot has a warmed table (count_max > 0); an absent value counts 0,
 * which means rare. Returns 0 when there is no usable table, negative for
 * a bad value.
 * ------------------------------------------------------------------------ */
typedef struct {
    uint32_t count;   /* occurrences across all reporting edges */
    uint16_t edges;   /* distinct reporting edges */
    uint16_t sources; /* distinct internal sources */
} enrich_prev_t;

int enrich_prevalence(const enrich_snap_t *s, const char *value, size_t len, enrich_prev_t *out);

/* Reporting edges behind the .prev; 0 when unknown, absent, or the
 * table is not warmed (count_max == 0). */
uint32_t enrich_prev_reporting_edges(const enrich_snap_t *s);

/* ------------------------------------------------------------------------
 * Names and snapshot facts, for output builders.
 * ------------------------------------------------------------------------ */
const char *enrich_feed_name(const enrich_snap_t *s, unsigned idx); /* NULL past the table */
const char *enrich_category_name(uint16_t one_bit);                  /* NULL if not a known bit */
const char *enrich_tlp_name(uint8_t one_bit);                        /* NULL if not a known bit */
const char *enrich_tlp_strictest(uint8_t tlp_mask);                  /* red, amber, green, clear, or NULL */

typedef struct {
    uint32_t components; /* ENRICH_C_* present */
    uint32_t thrt_version;
    uint32_t thrt_metadata;
    uint32_t thrt_ipv4_ranges;
    uint32_t thrt_ipv6_ranges;
    uint32_t thrt_hash_slots;
    uint32_t thrt_feeds;
    uint32_t thrt_checksum;
    int64_t thrt_mtime;
    uint32_t overlay_entries;
    uint32_t overlay_tenant;
    uint64_t overlay_built;
    int64_t overlay_mtime;
    uint32_t prev_entries;
    uint32_t prev_epoch;
    uint32_t prev_count_max;
    uint32_t prev_reporting_edges;
    int64_t prev_mtime;
    uint64_t generation; /* +1 per published snapshot */
} enrich_info_t;

void enrich_snap_info(const enrich_snap_t *s, enrich_info_t *out);

#ifdef __cplusplus
}
#endif

#endif
