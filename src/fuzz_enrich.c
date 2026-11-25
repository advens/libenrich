/* fuzz_enrich.c
 * libFuzzer harness for the loaders behind the lookup API.
 *
 *   FUZZ_TARGET=thrt  The input is a list of 8-byte patches (4-byte offset,
 *                     4-byte value) applied to a valid .thrt from
 *                     FUZZ_SEED. The CRC is recomputed, so the layout and
 *                     index checks behind it are what gets exercised. A file
 *                     that passes them is looked up.
 *                     The seed's bloom filter (up to 8 MB) is
 *                     cut out first, so a run copies and checks a few
 *                     hundred KB instead; FUZZ_KEEP_BLOOM=1 keeps it.
 *   FUZZ_TARGET=ovly  The input is an overlay file. Its CRC trailer is
 *                     recomputed for the same reason.
 *   FUZZ_TARGET=prev  The input is a .prev file, checked and mapped in
 *                     memory the way enrich_open() does, then looked up.
 *
 * Build: make fuzz (needs a clang with libFuzzer).
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0. See LICENSE.
 */
#include "enrich_lib.c"

#include <stdio.h>
#include <stdlib.h>

static unsigned char *g_seed;
static size_t g_seed_len;
static int g_mode; /* 1 thrt, 2 overlay, 3 prev */
static char g_tmp[64];

static const char *g_values[] = {"198.51.100.10", "10.1.2.3", "2001:db8::5", "evil.example", "wl.example",
                                 "add.example",   "tag.example", "0.0.0.0", "255.255.255.255", "::"};

/* Look every value up one by one, then as one batch, and stop on any
 * difference: the batch prefetches from the same file. */
static void probe_thrt(thrt_db_t *d) {
    enum { N = sizeof g_values / sizeof g_values[0] };
    struct enrich_snap s;
    enrich_result_t r[N], rb[N];
    enrich_value_t v[N];
    int rc[N], st[N];
    memset(&s, 0, sizeof s);
    s.thrt = d;
    for (size_t i = 0; i < N; i++) {
        v[i] = (enrich_value_t){g_values[i], strlen(g_values[i])};
        rc[i] = enrich_lookup(&s, ENRICH_OPT_SKIP_PRIVATE, v[i].value, v[i].len, &r[i]);
    }
    (void)enrich_lookup_batch(&s, ENRICH_OPT_SKIP_PRIVATE, v, N, rb, st);
    for (size_t i = 0; i < N; i++)
        if (st[i] != rc[i] || memcmp(&r[i], &rb[i], sizeof r[i]) != 0) {
            fprintf(stderr, "fuzz_enrich: batch differs from one by one for %s\n", g_values[i]);
            abort();
        }
    for (unsigned i = 0; i < 64; i++) (void)enrich_feed_name(&s, i);
}

/* Cut the bloom filter out of the seed: every section after it moves
 * down, its offsets with it, and bloom_size_bits becomes 0. The result
 * must still validate, or the seed is kept whole. */
static void shrink_seed(void) {
    thrt_header_t *h = (thrt_header_t *)(void *)g_seed;
    uint64_t at, cut, *offs[9];
    unsigned char *b;
    size_t n = g_seed_len;
    uint32_t crc;
    if (n < sizeof *h || h->bloom_size_bits == 0) return;
    at = h->offset_bloom;
    cut = (uint64_t)h->bloom_size_bits / 8;
    if (at > n || cut > n - at) return;
    b = malloc(n);
    if (b == NULL) return;
    memcpy(b, g_seed, n);
    h = (thrt_header_t *)(void *)b;
    memmove(b + at, b + at + cut, n - at - cut);
    n -= cut;
    offs[0] = &h->offset_metadata;
    offs[1] = &h->offset_ipv4;
    offs[2] = &h->offset_ipv6;
    offs[3] = &h->offset_hashtable;
    offs[4] = &h->offset_strings;
    offs[5] = &h->offset_ip_accel;
    offs[6] = &h->offset_feeds;
    offs[7] = &h->offset_src_ipv4;
    offs[8] = &h->offset_src_ipv6;
    for (size_t i = 0; i < sizeof offs / sizeof offs[0]; i++)
        if (*offs[i] > at) *offs[i] -= cut;
    h->bloom_size_bits = 0;
    h->total_size = n;
    crc = crc32c_platform(0xFFFFFFFFu, b, h->checksum_offset);
    crc = crc32c_platform(crc, b + h->checksum_offset + 4, n - h->checksum_offset - 4) ^ 0xFFFFFFFFu;
    h->checksum = crc;
    if (thrt_validate(b, n, "seed", NULL, 0) != THRT_VALID_OK) {
        fprintf(stderr, "fuzz_enrich: the seed without its bloom filter does not validate, kept whole\n");
        free(b);
        return;
    }
    fprintf(stderr, "fuzz_enrich: seed %zu bytes, %zu without its bloom filter\n", g_seed_len, n);
    free(g_seed);
    g_seed = b;
    g_seed_len = n;
}

static void fuzz_prev(const uint8_t *data, size_t size) {
    const prev_entry_t *table;
    const prev_header_t *h;
    uint64_t *b;
    uint32_t slots = 0;
    if (size < sizeof(prev_header_t)) return;
    /* A mapped file is page-aligned; the fuzzer's buffer is not. */
    b = malloc((size + 7) & ~(size_t)7);
    if (b == NULL) return;
    memcpy(b, data, size);
    h = (const prev_header_t *)(const void *)b;
    table = prev_table_map(b, size, &slots);
    if (table != NULL) {
        uint16_t edges, srcs;
        volatile uint32_t sink = 0;
        for (size_t i = 0; i < sizeof g_values / sizeof g_values[0]; i++)
            sink += prev_lookup_n(h, table, slots, g_values[i], strlen(g_values[i]), &edges, &srcs);
        for (uint32_t i = 0; i < slots && i < 4096; i++) sink += table[i].fleet_count;
        (void)sink;
    }
    free(b);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    const char *t = getenv("FUZZ_TARGET");
    const char *seed = getenv("FUZZ_SEED");
    FILE *f;
    long n;
    (void)argc;
    (void)argv;
    g_mode = (t && strcmp(t, "ovly") == 0) ? 2 : (t && strcmp(t, "prev") == 0) ? 3 : 1;
    snprintf(g_tmp, sizeof g_tmp, "/tmp/fuzz_enrich.%ld.ovly", (long)getpid());
    if (g_mode != 1) return 0;
    if (seed == NULL || (f = fopen(seed, "rb")) == NULL) {
        fprintf(stderr, "FUZZ_SEED must name a valid .thrt\n");
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    g_seed = malloc((size_t)n);
    if (g_seed == NULL || fread(g_seed, 1, (size_t)n, f) != (size_t)n) exit(2);
    fclose(f);
    g_seed_len = (size_t)n;
    if (!(getenv("FUZZ_KEEP_BLOOM") && strcmp(getenv("FUZZ_KEEP_BLOOM"), "1") == 0)) shrink_seed();
    return 0;
}

static void fuzz_thrt(const uint8_t *data, size_t size) {
    unsigned char *b = malloc(g_seed_len);
    thrt_header_t *h;
    thrt_db_t d;
    uint32_t crc;
    if (b == NULL) return;
    memcpy(b, g_seed, g_seed_len);
    /* Patches land in the header half the time, anywhere otherwise. */
    for (size_t i = 0; i + 8 <= size; i += 8) {
        uint32_t off, val;
        memcpy(&off, data + i, 4);
        memcpy(&val, data + i + 4, 4);
        off = (off & 1u) ? (off >> 1) % (uint32_t)sizeof(thrt_header_t) : (off >> 1) % (uint32_t)g_seed_len;
        if (off + 4 > g_seed_len) off = (uint32_t)g_seed_len - 4;
        memcpy(b + off, &val, 4);
    }
    h = (thrt_header_t *)(void *)b;
    if (h->checksum_offset == offsetof(thrt_header_t, checksum)) {
        crc = crc32c_platform(0xFFFFFFFFu, b, h->checksum_offset);
        crc = crc32c_platform(crc, b + h->checksum_offset + 4, g_seed_len - h->checksum_offset - 4) ^ 0xFFFFFFFFu;
        h->checksum = crc;
    }
    if (thrt_validate(b, g_seed_len, "fuzz", NULL, 0) == THRT_VALID_OK) {
        memset(&d, 0, sizeof d);
        d.map = b;
        d.size = g_seed_len;
        d.hdr = h;
        d.meta = (thrt_metadata_t *)(void *)(b + h->offset_metadata);
        d.v4 = (thrt_ipv4_range_t *)(void *)(b + h->offset_ipv4);
        d.v6 = (thrt_ipv6_range_t *)(void *)(b + h->offset_ipv6);
        d.accel = b + h->offset_ip_accel;
        d.ht = (thrt_hash_entry_t *)(void *)(b + h->offset_hashtable);
        d.bloom = h->bloom_size_bits ? b + h->offset_bloom : NULL;
        d.pool = (const char *)b + h->offset_strings;
        d.pool_size = g_seed_len - h->offset_strings;
        d.feeds = (const thrt_feed_entry_t *)(const void *)(b + h->offset_feeds);
        probe_thrt(&d);
    }
    free(b);
}

static void fuzz_ovly(const uint8_t *data, size_t size) {
    unsigned char *b;
    FILE *f;
    thrt_overlay_t *o;
    if (size < 4) return;
    b = malloc(size);
    if (b == NULL) return;
    memcpy(b, data, size);
    {
        uint32_t crc = crc32c_platform(0xFFFFFFFFu, b, size - 4) ^ 0xFFFFFFFFu;
        memcpy(b + size - 4, &crc, 4);
    }
    f = fopen(g_tmp, "wb");
    if (f != NULL) {
        fwrite(b, 1, size, f);
        fclose(f);
        o = thrt_overlay_load_ex(g_tmp, NULL);
        if (o != NULL) {
            for (size_t i = 0; i < sizeof g_values / sizeof g_values[0]; i++) {
                const thrt_overlay_entry_t *e =
                    thrt_overlay_find(o, thrt_hash(g_values[i]), g_values[i], strlen(g_values[i]));
                if (e && e->tags_length) {
                    volatile char c = o->string_pool[e->tags_offset + e->tags_length - 1];
                    (void)c;
                }
            }
            thrt_overlay_free(o);
        }
    }
    free(b);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (g_mode == 1)
        fuzz_thrt(data, size);
    else if (g_mode == 3)
        fuzz_prev(data, size);
    else
        fuzz_ovly(data, size);
    return 0;
}
