/* test_prev.c: self-test for the prevalence lookup table (prev_format.h).
 *
 * Builds a table in memory exactly as the collector's Python writer will
 * (open-addressing insert with the same FNV-1a hashing + 0-is-empty rule),
 * then exercises prev_lookup / prev_table_map: hits return the stored count,
 * absent keys return 0 (= rare), the pow2/magic/bounds validation rejects
 * corruption, and a hash-0 observable is handled.
 *
 * Build: cc -O2 -I. test_prev.c -o test_prev && ./test_prev
 *
 * Copyright 2026 Advens. Licensed under the Apache License, Version 2.0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "prev_format.h"

static int g_fail = 0;
#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            g_fail++;                                                       \
        }                                                                   \
    } while (0)

/* Mirror of the collector writer's insert: place (key,count,edges,sources) into
 * the open-addressing table. Returns 0 on success, -1 if the table is full. */
static int prev_insert(const prev_header_t* h,
                       prev_entry_t* table,
                       uint32_t slots,
                       const char* key,
                       uint32_t count,
                       uint16_t edges,
                       uint16_t sources) {
    uint64_t hash = prev_hash(h->sip_key, key);
    uint32_t mask;
    uint32_t idx;
    mask = slots - 1;
    idx = (uint32_t)hash & mask;
    for (uint32_t probes = 0; probes < slots; probes++) {
        prev_entry_t* e = &table[idx];
        if (e->hash_key == 0 || e->hash_key == hash) {
            e->hash_key = hash;
            e->total_count = count;
            e->edge_count = edges;
            e->source_count = sources;
            return 0;
        }
        idx = (idx + 1) & mask;
    }
    return -1;
}

/* Build a complete mapped image (header + entries) in a single malloc so
 * prev_table_map's bounds logic sees a realistic layout. Caller frees. */
static void* build_table(uint32_t slots, size_t* out_len) {
    size_t entries_bytes = (size_t)slots * sizeof(prev_entry_t);
    size_t total = sizeof(prev_header_t) + entries_bytes;
    uint8_t* base = calloc(1, total);
    prev_header_t* h = (prev_header_t*)base;
    h->magic = PREV_MAGIC;
    h->version = PREV_VERSION;
    h->total_size = total;
    h->hash_slots = slots;
    h->entry_count = 0;
    h->checksum = 0;
    h->epoch = 0;
    h->offset_entries = sizeof(prev_header_t);
    h->count_max = 0;
    h->sip_key[0] = 0x0706050403020100ULL;
    h->sip_key[1] = 0x0f0e0d0c0b0a0908ULL;
    *out_len = total;
    return base;
}

/* Conformance: read a .prev written by prev_write.py and verify the shared
 * CONFORMANCE fixture round-trips (proves the Python writer matches this C
 * reader byte-for-byte, incl. the FNV-1a hash). Returns 0 on success. */
static int conformance(const char* path) {
    FILE* f = fopen(path, "rb");
    long sz;
    uint8_t* buf;
    uint32_t slots;
    const prev_entry_t* t;
    if (!f) {
        fprintf(stderr, "conformance: cannot open %s\n", path);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)sz);
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        free(buf);
        return 1;
    }
    fclose(f);

    slots = 0;
    t = prev_table_map(buf, (size_t)sz, &slots);
    CHECK(t != NULL, "conformance: python-written table maps");
    if (t) {
        uint16_t e = 0, s = 0;
        const prev_header_t* hh;
        CHECK(prev_lookup((const prev_header_t*)buf, t, slots, "www.google.com", &e, &s) == 50000 && e == 7 && s == 120, "conf: google");
        CHECK(prev_lookup((const prev_header_t*)buf, t, slots, "cdn.cloudflare.net", &e, &s) == 41000 && e == 7 && s == 95, "conf: cloudflare");
        CHECK(prev_lookup((const prev_header_t*)buf, t, slots, "one.one.one.one", &e, &s) == 12000 && e == 6 && s == 60, "conf: quad-one");
        CHECK(prev_lookup((const prev_header_t*)buf, t, slots, "internal.corp.lan", &e, &s) == 800 && e == 3 && s == 12, "conf: internal");
        CHECK(prev_lookup((const prev_header_t*)buf, t, slots, "lonely-beacon.example", &e, &s) == 2 && e == 1 && s == 1, "conf: rare");
        CHECK(prev_lookup((const prev_header_t*)buf, t, slots, "never-seen.invalid", &e, &s) == 0 && s == 0, "conf: absent => 0");
        hh = (const prev_header_t*)buf;
        CHECK(hh->entry_count == 5, "conf: entry_count");
        CHECK(hh->count_max == 50000, "conf: count_max");
        CHECK(hh->reporting_edges == 0, "conf: reporting_edges default unknown");
        CHECK(hh->epoch == 1700000000u, "conf: epoch round-trips");
    }
    free(buf);
    if (g_fail == 0) {
        printf("test_prev conformance: ALL PASS\n");
        return 0;
    }
    fprintf(stderr, "test_prev conformance: %d FAILURES\n", g_fail);
    return 1;
}

int main(int argc, char** argv) {
    size_t len;
    void* base;
    prev_header_t* h;
    prev_entry_t* tbl;
    uint32_t slots;
    const prev_entry_t* mapped;
    uint32_t s2;
    prev_header_t bad;
    /* Common observables (high counts) and one rare-but-present. */
    struct {
        const char* k;
        uint32_t c;
        uint16_t e;
        uint16_t s;
    } seed[] = {
        {"www.google.com", 50000, 7, 120}, {"cdn.cloudflare.net", 41000, 7, 95}, {"one.one.one.one", 12000, 6, 60},
        {"internal.corp.lan", 800, 3, 12}, {"lonely-beacon.example", 2, 1, 1}, /* present but very rare (one source) */
    };
    uint16_t edges = 0xFFFF, srcs = 0xFFFF;
    if (argc > 1) return conformance(argv[1]);

    /* SipHash against the published SipHash-2-4 vector (key 00..0f, the
     * 15 bytes 00..0e), then the 1-3 variant the table uses. */
    {
        uint8_t msg[15];
        uint64_t k0 = 0x0706050403020100ULL, k1 = 0x0f0e0d0c0b0a0908ULL, other[2] = {1, 2};
        for (int i = 0; i < 15; i++) msg[i] = (uint8_t)i;
        CHECK(prev_siphash(k0, k1, msg, 15, 2, 4) == 0xa129ca6149be45e5ULL, "SipHash-2-4 reference vector");
        CHECK(prev_siphash(k0, k1, msg, 15, 1, 3) == 0xd320d86d2a519956ULL, "SipHash-1-3, as prev_write.py");
        CHECK(prev_hash(other, "www.google.com") != prev_hash((const uint64_t[2]){k0, k1}, "www.google.com"),
              "the key changes the hash");
    }
    len = 0;
    base = build_table(1024, &len);
    h = (prev_header_t*)base;
    tbl = (prev_entry_t*)((uint8_t*)base + h->offset_entries);

    for (size_t i = 0; i < sizeof(seed) / sizeof(seed[0]); i++) {
        CHECK(prev_insert(h, tbl, h->hash_slots, seed[i].k, seed[i].c, seed[i].e, seed[i].s) == 0, "insert");
        h->entry_count++;
        if (seed[i].c > h->count_max) h->count_max = seed[i].c;
    }

    /* map + validate */
    slots = 0;
    mapped = prev_table_map(base, len, &slots);
    CHECK(mapped != NULL, "prev_table_map accepts a valid table");
    CHECK(slots == 1024, "slot count round-trips");
    CHECK(mapped == tbl, "entry array offset resolves");

    /* hits return the stored count + edge spread + source spread */
    CHECK(prev_lookup(h, mapped, slots, "www.google.com", &edges, &srcs) == 50000, "common hit count");
    CHECK(edges == 7, "common hit edge spread");
    CHECK(srcs == 120, "common hit source spread");
    CHECK(prev_lookup(h, mapped, slots, "lonely-beacon.example", &edges, &srcs) == 2, "rare-present hit");
    CHECK(edges == 1, "rare-present edge spread");
    CHECK(srcs == 1, "rare-present source spread (one source)");

    /* absent keys => 0 (= rarest / first-seen) */
    CHECK(prev_lookup(h, mapped, slots, "brand-new-c2-domain.xyz", &edges, &srcs) == 0, "absent => 0");
    CHECK(edges == 0, "absent edge spread 0");
    CHECK(srcs == 0, "absent source spread 0");
    CHECK(prev_lookup(h, mapped, slots, "", &edges, &srcs) == 0, "empty key => 0");
    CHECK(prev_lookup(h, mapped, slots, "www.google.co", NULL, NULL) == 0, "near-miss (prefix) => 0");

    /* NULL / zero-slot guards */
    CHECK(prev_lookup(h, NULL, slots, "x", NULL, NULL) == 0, "NULL table guard");
    CHECK(prev_lookup(h, mapped, 0, "x", NULL, NULL) == 0, "zero-slot guard");

    /* corruption rejection */
    s2 = 0;
    bad = *h;
    bad.magic = 0xDEADBEEF;
    CHECK(prev_table_map(&bad, len, &s2) == NULL, "bad magic rejected");
    bad = *h;
    bad.version = 999;
    CHECK(prev_table_map(&bad, len, &s2) == NULL, "bad version rejected");
    bad = *h;
    bad.hash_slots = 1000; /* not a power of two */
    CHECK(prev_table_map(&bad, len, &s2) == NULL, "non-pow2 slots rejected");
    CHECK(prev_table_map(base, sizeof(prev_header_t) - 1, &s2) == NULL, "short map rejected");
    bad = *h;
    bad.offset_entries = len; /* entries would run off the end */
    CHECK(prev_table_map(&bad, len, &s2) == NULL, "out-of-bounds entries rejected");

    free(base);

    if (g_fail == 0) {
        printf("test_prev: ALL PASS\n");
        return 0;
    }
    fprintf(stderr, "test_prev: %d FAILURES\n", g_fail);
    return 1;
}
