/* prev_format.h — fleet-prevalence lookup table (mmap, read-only on the edge).
 *
 * A distributed "how common is this observable across the whole fleet" table:
 * the collector aggregates per-observable counts reported by every edge, writes
 * this table (Python, mirrors this layout byte-for-byte), and distributes it to
 * the edges like the .thrt CTI table. mmenrich mmaps it read-only and, per
 * event, looks up the query name / destination address and emits the fleet
 * count as a $! fact. A LOW (or absent = 0) count is the rarity signal: a domain
 * or address seen almost nowhere else in the fleet is a first-seen / targeted
 * C2 rendezvous, which a Sigma rule can threshold (optionally ANDed with entropy
 * or beaconing). High counts (common CDN/SaaS) are the benign baseline.
 *
 * Design mirrors the .thrt string hash table (thrt_format.h) but stores only a
 * count, no threat metadata and no string pool: the 64-bit FNV-1a key is kept
 * for the match and full strings are NOT stored (a hash collision merely returns
 * a slightly-off count for one observable, harmless for a fuzzy prevalence
 * prior, and the birthday bound at <1e6 entries in 2^64 is ~1e-8). This keeps
 * the table tiny (16 B/entry) and the lookup a single cache-line probe.
 *
 * Copyright 2026 Advens.
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
 */
#ifndef PREV_FORMAT_H
#define PREV_FORMAT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PREV_MAGIC 0x50524556u /* "PREV" */
#define PREV_VERSION 2u
#define PREV_PROBE_MAX 64 /* bounded linear probe (corruption guard) */

/* FNV-1a 64-bit over the observable bytes. Deliberately NOT CRC32C: prevalence
 * is one lookup per event (never the bottleneck vs mmenrich's CTI/SIMD work), so
 * a scalar hash is free, and FNV-1a is trivial to reproduce BYTE-IDENTICALLY in
 * the collector's Python writer (no CRC32C table/polynomial to match). The
 * writer and this reader MUST stay in lockstep on this function. */
static inline uint64_t prev_hash(const char* s) {
    uint64_t h = 0xcbf29ce484222325ULL; /* FNV offset basis */
    for (; *s != '\0'; s++) {
        h ^= (uint64_t)(uint8_t)*s;
        h *= 0x100000001b3ULL; /* FNV prime */
    }
    return h;
}

/* On-disk / mmap layout: [prev_header_t][prev_entry_t * hash_slots].
 * hash_slots is a power of two; the entry array is the open-addressing table.
 * All integers little-endian (the fleet is homogeneous LE; the writer asserts). */
typedef struct {
    uint32_t magic; /* "PREV" */
    uint32_t version; /* 1 */
    uint64_t total_size; /* full file size in bytes */
    uint32_t hash_slots; /* power of two; size of the entry array */
    uint32_t entry_count; /* populated (non-empty) entries */
    uint32_t checksum; /* optional CRC32C of entries; 0 = unset (map does not verify) */
    uint32_t epoch; /* build epoch seconds (staleness/telemetry) */
    uint64_t offset_entries; /* byte offset of the entry array */
    uint32_t count_max; /* the largest fleet_count in the table (for scaling) */
    uint32_t reporting_edges; /* G3: distinct edges in this rebuild; 0 = unknown */
    uint32_t _reserved[8]; /* zero; ABI-stable expansion room */
} prev_header_t;

/* Open-addressing entry. hash_key == 0 marks an EMPTY slot (a real observable
 * hashing to 0 is bumped to 1 by the writer AND the lookup, so 0 is unambiguous
 * end-of-chain). 16 bytes: two per cache line pair, one probe touches one line. */
typedef struct {
    uint64_t hash_key; /* prev_hash (FNV-1a) of observable; 0 = empty slot */
    uint32_t fleet_count; /* fleet-wide occurrence count */
    uint16_t edge_count; /* distinct edges that reported it (fleet spread) */
    uint16_t source_count; /* distinct internal SOURCES that contacted it. The
                            * volume-invariant rarity metric: one host beaconing
                            * hard keeps this at 1 no matter the flow count, and
                            * unlike edge_count it still discriminates when the
                            * fleet reports through a single egress/edge (a CDN
                            * is hit by many sources, a C2 by one). */
} prev_entry_t;

/* Lock the on-disk layout: the Python writer (prev_write.py) packs these exact
 * sizes with '<' (LE, no padding). A field reorder that introduced struct
 * padding would silently desync the two; catch it at compile time. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(prev_header_t) == 80, "prev_header_t must be 80 bytes (matches prev_write.py)");
_Static_assert(sizeof(prev_entry_t) == 16, "prev_entry_t must be 16 bytes (matches prev_write.py)");
#endif

/* Lookup: fleet count for `key` (a NUL-terminated observable string), or 0 if
 * absent (= rarest). Lockfree read over the read-only mmap; ~1 cache line.
 * `edge_out` (optional) receives the distinct-edge spread; `src_out` (optional)
 * the distinct-internal-source count. Both are 0 on a miss (= rarest). */
static inline uint32_t prev_lookup(
    const prev_entry_t* table, uint32_t slots, const char* key, uint16_t* edge_out, uint16_t* src_out) {
    if (table == NULL || slots == 0 || key == NULL || key[0] == '\0') {
        if (edge_out) *edge_out = 0;
        if (src_out) *src_out = 0;
        return 0;
    }
    uint64_t hash = prev_hash(key);
    if (hash == 0) hash = 1; /* 0 is the empty marker; keep real keys off it */
    uint32_t mask = slots - 1;
    uint32_t idx = (uint32_t)hash & mask;
    for (int probes = 0; probes < PREV_PROBE_MAX; probes++) {
        const prev_entry_t* e = &table[idx];
        if (e->hash_key == 0) break; /* empty slot => not found => rare */
        if (e->hash_key == hash) {
            if (edge_out) *edge_out = e->edge_count;
            if (src_out) *src_out = e->source_count;
            return e->fleet_count;
        }
        idx = (idx + 1) & mask;
    }
    if (edge_out) *edge_out = 0;
    if (src_out) *src_out = 0;
    return 0;
}

/* Validate a mapped region as a prev table; returns the entry array (and slot
 * count via *slots_out) on success, NULL on any structural problem. Cheap:
 * magic/version/bounds + power-of-two slots. Callers mmap read-only then map. */
static inline const prev_entry_t* prev_table_map(const void* base, size_t map_len, uint32_t* slots_out) {
    if (base == NULL || map_len < sizeof(prev_header_t)) return NULL;
    const prev_header_t* h = (const prev_header_t*)base;
    if (h->magic != PREV_MAGIC || h->version != PREV_VERSION) return NULL;
    uint32_t slots = h->hash_slots;
    if (slots == 0 || (slots & (slots - 1)) != 0) return NULL; /* must be pow2 */
    if (h->offset_entries < sizeof(prev_header_t)) return NULL;
    /* entry array must fit inside the mapping */
    size_t need = (size_t)h->offset_entries + (size_t)slots * sizeof(prev_entry_t);
    if (need > map_len) return NULL;
    if (slots_out) *slots_out = slots;
    return (const prev_entry_t*)((const uint8_t*)base + h->offset_entries);
}

#endif /* PREV_FORMAT_H */
