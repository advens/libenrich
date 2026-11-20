/* thrt_validate.h
 * Structural check of a mapped .thrt: version, sizes, every table offset
 * and index, and the CRC32C. The lookup API runs it before it publishes a
 * file, and the builder before a fold reads an existing one, so neither
 * dereferences an offset the file did not prove.
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0. See LICENSE.
 */
#ifndef THRT_VALIDATE_H
#define THRT_VALIDATE_H

#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "thrt_format.h"
#include "thrt_logic.h"

#define THRT_VALID_OK 0
#define THRT_VALID_EFORMAT 1
#define THRT_VALID_EVERSION 2
#define THRT_VALID_ECHECKSUM 3

static void thrt_valid_err(char *err, size_t len, const char *fmt, ...) __attribute__((unused, format(printf, 3, 4)));

static void thrt_valid_err(char *err, size_t len, const char *fmt, ...) {
    va_list ap;
    if (err == NULL || len == 0) return;
    va_start(ap, fmt);
    vsnprintf(err, len, fmt, ap);
    va_end(ap);
}

/* [off, off + count * elem) lies inside a file of size bytes. */
static inline int thrt_region_ok(uint64_t off, uint64_t count, uint64_t elem, size_t size) {
    if (off > (uint64_t)size) return 0;
    return count <= ((uint64_t)size - off) / elem;
}

static __attribute__((unused)) int thrt_validate(const unsigned char *base, size_t size, const char *path, char *err, size_t err_len) {
    const thrt_header_t *h = (const thrt_header_t *)(const void *)base;
    const thrt_metadata_t *md;
    const thrt_ipv4_range_t *v4;
    const thrt_ipv6_range_t *v6;
    const thrt_hash_entry_t *ht;
    const thrt_feed_entry_t *fd;
    uint64_t pool_size;
    uint32_t crc, co;

    if (size < sizeof *h || h->magic != THRT_MAGIC) {
        thrt_valid_err(err, err_len, "%s: not a .thrt file", path);
        return THRT_VALID_EFORMAT;
    }
    if (h->version != THRT_VERSION) {
        thrt_valid_err(err, err_len, "%s: .thrt version %u, this library reads %u; rebuild it", path, h->version,
               THRT_VERSION);
        return THRT_VALID_EVERSION;
    }
    /* The readers index the bloom filter with a mask. */
    if (h->bloom_size_bits != 0 && (h->bloom_size_bits < 64 || (h->bloom_size_bits & (h->bloom_size_bits - 1)) != 0)) {
        thrt_valid_err(err, err_len, "%s: bloom filter of %u bits, not a power of two", path, h->bloom_size_bits);
        return THRT_VALID_EFORMAT;
    }
    if (h->total_size != (uint64_t)size) {
        thrt_valid_err(err, err_len, "%s: size %zu, header says %llu", path, size, (unsigned long long)h->total_size);
        return THRT_VALID_EFORMAT;
    }
    if (h->hash_slots == 0 || (h->hash_slots & (h->hash_slots - 1)) != 0 || h->hash_slots > INT_MAX ||
        h->ipv4_range_count > INT_MAX || h->ipv6_range_count > INT_MAX || h->feed_count > 64 ||
        h->checksum_offset != offsetof(thrt_header_t, checksum) || h->offset_metadata % 8 != 0 ||
        h->offset_ipv4 % 8 != 0 || h->offset_ipv6 % 8 != 0 || h->offset_hashtable % 8 != 0 ||
        !thrt_region_ok(h->offset_metadata, h->metadata_count, sizeof(thrt_metadata_t), size) ||
        !thrt_region_ok(h->offset_ipv4, h->ipv4_range_count, sizeof(thrt_ipv4_range_t), size) ||
        !thrt_region_ok(h->offset_ipv6, h->ipv6_range_count, sizeof(thrt_ipv6_range_t), size) ||
        !thrt_region_ok(h->offset_hashtable, h->hash_slots, sizeof(thrt_hash_entry_t), size) ||
        !thrt_region_ok(h->offset_ip_accel, THRT_IP_ACCEL_SLOTS, sizeof(thrt_ip_accel_t), size) ||
        !thrt_region_ok(h->offset_bloom, (uint64_t)h->bloom_size_bits / 8, 1, size) ||
        !thrt_region_ok(h->offset_feeds, h->feed_count, sizeof(thrt_feed_entry_t), size) ||
        !thrt_region_ok(h->offset_src_ipv4, h->src_ipv4_count, sizeof(thrt_ipv4_range_t), size) ||
        !thrt_region_ok(h->offset_src_ipv6, h->src_ipv6_count, sizeof(thrt_ipv6_range_t), size) ||
        h->offset_src_ipv4 % 8 != 0 || h->offset_src_ipv6 % 8 != 0 || h->offset_strings >= (uint64_t)size) {
        thrt_valid_err(err, err_len, "%s: a table lies outside the file", path);
        return THRT_VALID_EFORMAT;
    }

    co = h->checksum_offset;
    crc = crc32c_platform(0xFFFFFFFFu, base, co);
    crc = crc32c_platform(crc, base + co + sizeof(uint32_t), size - co - sizeof(uint32_t));
    crc ^= 0xFFFFFFFFu;
    if (crc != h->checksum) {
        thrt_valid_err(err, err_len, "%s: CRC32C 0x%08x, header says 0x%08x", path, crc, h->checksum);
        return THRT_VALID_ECHECKSUM;
    }

    /* Every index the lookups follow stays inside its table, so the hot
     * path needs no bounds check. */
    pool_size = (uint64_t)size - h->offset_strings;
    v4 = (const thrt_ipv4_range_t *)(const void *)(base + h->offset_ipv4);
    for (uint32_t i = 0; i < h->ipv4_range_count; i++)
        if (v4[i].meta_idx >= h->metadata_count || v4[i].ip_start > v4[i].ip_end) goto bad_index;
    v6 = (const thrt_ipv6_range_t *)(const void *)(base + h->offset_ipv6);
    for (uint32_t i = 0; i < h->ipv6_range_count; i++)
        if (v6[i].meta_idx >= h->metadata_count) goto bad_index;
    for (uint32_t i = 0; i < THRT_IP_ACCEL_SLOTS; i++) {
        thrt_ip_accel_t slot = thrt_ip_accel_at(base + h->offset_ip_accel, i);
        if (slot.range_count == 0) continue;
        if (slot.range_start_idx >= h->ipv4_range_count ||
            slot.range_count > h->ipv4_range_count - slot.range_start_idx)
            goto bad_index;
    }
    ht = (const thrt_hash_entry_t *)(const void *)(base + h->offset_hashtable);
    for (uint32_t i = 0; i < h->hash_slots; i++) {
        if (ht[i].meta_idx == 0xFFFFFFFFu) continue;
        if (ht[i].meta_idx >= h->metadata_count || (uint64_t)ht[i].string_offset >= pool_size) goto bad_index;
    }
    md = (const thrt_metadata_t *)(const void *)(base + h->offset_metadata);
    for (uint32_t i = 0; i < h->metadata_count; i++) {
        if (md[i].tags_length != 0 && ((uint64_t)md[i].tags_offset >= pool_size ||
                                       (uint64_t)md[i].tags_length > pool_size - md[i].tags_offset))
            goto bad_index;
        if (md[i].labels_length != 0 && ((uint64_t)md[i].labels_offset >= pool_size ||
                                         (uint64_t)md[i].labels_length > pool_size - md[i].labels_offset))
            goto bad_index;
    }
    v4 = (const thrt_ipv4_range_t *)(const void *)(base + h->offset_src_ipv4);
    for (uint32_t i = 0; i < h->src_ipv4_count; i++)
        if (v4[i].meta_idx >= h->metadata_count || v4[i].ip_start > v4[i].ip_end) goto bad_index;
    v6 = (const thrt_ipv6_range_t *)(const void *)(base + h->offset_src_ipv6);
    for (uint32_t i = 0; i < h->src_ipv6_count; i++)
        if (v6[i].meta_idx >= h->metadata_count) goto bad_index;
    fd = (const thrt_feed_entry_t *)(const void *)(base + h->offset_feeds);
    for (uint32_t i = 0; i < h->feed_count; i++)
        if (memchr(fd[i].name, '\0', sizeof fd[i].name) == NULL) goto bad_index;
    return THRT_VALID_OK;

bad_index:
    thrt_valid_err(err, err_len, "%s: an entry points outside its table", path);
    return THRT_VALID_EFORMAT;
}

#endif /* THRT_VALIDATE_H */
