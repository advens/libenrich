/* prev_format.h: prevalence lookup table (mmap, read-only).
 *
 * How common an observable is across every reporting edge: a writer
 * aggregates per-observable counts and writes this table; readers map it
 * read-only and look up a query name or destination address per event. A
 * low (or absent, 0) count is the rarity signal a detection rule
 * thresholds.
 *
 * Only a 64-bit hash of each observable is stored, not the string, which
 * keeps an entry at 16 bytes and a lookup at one cache line. The hash is
 * SipHash-1-3 under a 128-bit key the writer draws at random and stores in
 * the header. An unkeyed hash would let an attacker who knows the function
 * choose a rare domain whose hash equals a common one's, so the rare domain
 * reads as common. With a secret key that collision has to be found blind,
 * one 2^-64 guess at a time. Readers take the key from the file they map.
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
#define PREV_VERSION 3u
#define PREV_PROBE_MAX 64 /* bounded linear probe (corruption guard) */

/* On-disk / mmap layout: [prev_header_t][prev_entry_t * hash_slots].
 * hash_slots is a power of two; the entry array is the open-addressing table.
 * All integers little-endian. */
typedef struct {
    uint32_t magic; /* "PREV" */
    uint32_t version; /* PREV_VERSION */
    uint64_t total_size; /* full file size in bytes */
    uint32_t hash_slots; /* power of two; size of the entry array */
    uint32_t entry_count; /* populated (non-empty) entries */
    uint32_t checksum; /* optional CRC32C of entries; 0 = unset (map does not verify) */
    uint32_t epoch; /* build epoch seconds (staleness/telemetry) */
    uint64_t offset_entries; /* byte offset of the entry array */
    uint32_t count_max; /* the largest total_count in the table (for scaling) */
    uint32_t reporting_edges; /* distinct edges in this rebuild; 0 = unknown */
    uint64_t sip_key[2]; /* SipHash-1-3 key of every hash_key in this file */
    uint32_t _reserved[4]; /* zero */
} prev_header_t;

/* Open-addressing entry. hash_key == 0 marks an EMPTY slot (a real observable
 * hashing to 0 is bumped to 1 by the writer AND the lookup, so 0 is unambiguous
 * end-of-chain). */
typedef struct {
    uint64_t hash_key; /* prev_hash_n() of the observable; 0 = empty slot */
    /* Occurrence count across all edges. fleet_count is a deprecated alias
     * of total_count over the same bytes, removed at the next major version. */
    __extension__ union {
        uint32_t total_count;
        uint32_t fleet_count __attribute__((deprecated("use total_count")));
    };
    uint16_t edge_count; /* distinct edges that reported it */
    uint16_t source_count; /* distinct internal sources that contacted it:
                            * the rarity metric that one host beaconing hard
                            * cannot inflate, and that still discriminates when
                            * every event arrives through a single edge. */
} prev_entry_t;

/* The Python writer packs these exact sizes with '<' (LE, no padding). */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(prev_header_t) == 80, "prev_header_t must be 80 bytes");
_Static_assert(sizeof(prev_entry_t) == 16, "prev_entry_t must be 16 bytes");
#endif

/* SipHash with c compression and d finalization rounds over len bytes. The
 * table uses c = 1, d = 3 (SipHash-1-3); SipHash-2-4 is the published
 * reference the tests check this code against. Bytes are read one at a time,
 * so the input needs no alignment and the result is the same on any host. */
static __attribute__((unused)) uint64_t prev_siphash(uint64_t k0, uint64_t k1, const void* data, size_t len, int c, int d) {
    const uint8_t* p = (const uint8_t*)data;
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;
    uint64_t b = (uint64_t)len << 56;
    size_t left = len & 7;
    const uint8_t* end = p + (len - left);
#define PREV_ROTL(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define PREV_SIPROUND                                                                                                  \
    do {                                                                                                               \
        v0 += v1;                                                                                                      \
        v1 = PREV_ROTL(v1, 13);                                                                                        \
        v1 ^= v0;                                                                                                      \
        v0 = PREV_ROTL(v0, 32);                                                                                        \
        v2 += v3;                                                                                                      \
        v3 = PREV_ROTL(v3, 16);                                                                                        \
        v3 ^= v2;                                                                                                      \
        v0 += v3;                                                                                                      \
        v3 = PREV_ROTL(v3, 21);                                                                                        \
        v3 ^= v0;                                                                                                      \
        v2 += v1;                                                                                                      \
        v1 = PREV_ROTL(v1, 17);                                                                                        \
        v1 ^= v2;                                                                                                      \
        v2 = PREV_ROTL(v2, 32);                                                                                        \
    } while (0)
    for (; p != end; p += 8) {
        uint64_t m = (uint64_t)p[0] | (uint64_t)p[1] << 8 | (uint64_t)p[2] << 16 | (uint64_t)p[3] << 24 |
                     (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40 | (uint64_t)p[6] << 48 | (uint64_t)p[7] << 56;
        v3 ^= m;
        for (int i = 0; i < c; i++) PREV_SIPROUND;
        v0 ^= m;
    }
    for (size_t i = 0; i < left; i++) b |= (uint64_t)p[i] << (8 * i);
    v3 ^= b;
    for (int i = 0; i < c; i++) PREV_SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    for (int i = 0; i < d; i++) PREV_SIPROUND;
#undef PREV_SIPROUND
#undef PREV_ROTL
    return v0 ^ v1 ^ v2 ^ v3;
}

/* The table key of an observable under a file's key. Never 0: 0 marks an
 * empty slot, so a real hash of 0 becomes 1. */
static inline uint64_t prev_hash_n(const uint64_t sip_key[2], const char* s, size_t len) {
    uint64_t h = prev_siphash(sip_key[0], sip_key[1], s, len, 1, 3);
    return h == 0 ? 1 : h;
}

static __attribute__((unused)) uint64_t prev_hash(const uint64_t sip_key[2], const char* s) {
    return prev_hash_n(sip_key, s, strlen(s));
}

/* Occurrence count for a counted value under the table's header, or 0 if absent
 * (= rarest). edge_out / src_out (optional) receive the spreads, 0 on a miss.
 * The value need not be NUL-terminated. */
static inline uint32_t prev_lookup_n(const prev_header_t* h, const prev_entry_t* table, uint32_t slots,
                                     const char* key, size_t len, uint16_t* edge_out, uint16_t* src_out) {
    uint64_t hash;
    uint32_t mask;
    uint32_t idx;
    if (edge_out) *edge_out = 0;
    if (src_out) *src_out = 0;
    if (h == NULL || table == NULL || slots == 0 || key == NULL || len == 0) return 0;
    hash = prev_hash_n(h->sip_key, key, len);
    mask = slots - 1;
    idx = (uint32_t)hash & mask;
    for (int probes = 0; probes < PREV_PROBE_MAX; probes++) {
        const prev_entry_t* e = &table[idx];
        if (e->hash_key == 0) break;
        if (e->hash_key == hash) {
            if (edge_out) *edge_out = e->edge_count;
            if (src_out) *src_out = e->source_count;
            return e->total_count;
        }
        idx = (idx + 1) & mask;
    }
    return 0;
}

static __attribute__((unused)) uint32_t prev_lookup(const prev_header_t* h, const prev_entry_t* table, uint32_t slots,
                                   const char* key, uint16_t* edge_out, uint16_t* src_out) {
    return prev_lookup_n(h, table, slots, key, key ? strlen(key) : 0, edge_out, src_out);
}

/* Validate a mapped region as a prev table; returns the entry array (and slot
 * count via *slots_out) on success, NULL on any structural problem: magic,
 * version, power-of-two slots, entries inside the mapping. */
static __attribute__((unused)) const prev_entry_t* prev_table_map(const void* base, size_t map_len, uint32_t* slots_out) {
    const prev_header_t* h;
    uint32_t slots;
    if (base == NULL || map_len < sizeof(prev_header_t)) return NULL;
    h = (const prev_header_t*)base;
    if (h->magic != PREV_MAGIC || h->version != PREV_VERSION) return NULL;
    slots = h->hash_slots;
    if (slots == 0 || (slots & (slots - 1)) != 0) return NULL;
    if (h->offset_entries < sizeof(prev_header_t) || h->offset_entries % 8 != 0) return NULL;
    if (h->offset_entries > map_len || (map_len - h->offset_entries) / sizeof(prev_entry_t) < slots) return NULL;
    if (slots_out) *slots_out = slots;
    return (const prev_entry_t*)(const void*)((const uint8_t*)base + h->offset_entries);
}

#endif /* PREV_FORMAT_H */
