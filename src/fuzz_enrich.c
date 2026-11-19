/* fuzz_enrich.c
 * libFuzzer harness for the loaders behind the lookup API.
 *
 *   FUZZ_TARGET=thrt  The input is a list of 8-byte patches (4-byte offset,
 *                     4-byte value) applied to a valid .thrt from
 *                     FUZZ_SEED. The CRC is recomputed, so the layout and
 *                     index checks behind it are what gets exercised. A file
 *                     that passes them is looked up.
 *   FUZZ_TARGET=ovly  The input is an overlay file. Its CRC trailer is
 *                     recomputed for the same reason.
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
static int g_mode; /* 1 thrt, 2 overlay */
static char g_tmp[64];

static const char *g_values[] = {"198.51.100.10", "10.1.2.3", "2001:db8::5", "evil.example", "wl.example",
                                 "add.example",   "tag.example", "0.0.0.0", "255.255.255.255", "::"};

static void probe_thrt(thrt_db_t *d) {
    struct enrich_snap s;
    enrich_result_t r;
    memset(&s, 0, sizeof s);
    s.thrt = d;
    for (size_t i = 0; i < sizeof g_values / sizeof g_values[0]; i++)
        (void)enrich_lookup(&s, ENRICH_OPT_SKIP_PRIVATE, g_values[i], strlen(g_values[i]), &r);
    for (unsigned i = 0; i < 64; i++) (void)enrich_feed_name(&s, i);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    const char *t = getenv("FUZZ_TARGET");
    const char *seed = getenv("FUZZ_SEED");
    FILE *f;
    long n;
    (void)argc;
    (void)argv;
    g_mode = (t && strcmp(t, "ovly") == 0) ? 2 : 1;
    snprintf(g_tmp, sizeof g_tmp, "/tmp/fuzz_enrich.%ld.ovly", (long)getpid());
    if (g_mode == 2) return 0;
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
    else
        fuzz_ovly(data, size);
    return 0;
}
