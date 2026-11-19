/* thrt_overlay.h
 * Site-local CTI overlay (.ovly) for local IOC additions and whitelists.
 * A small binary file loaded alongside the main .thrt database and checked
 * before the normal CTI lookup on the hot path.
 *
 * Layout (version 2):
 *   [thrt_overlay_header_t]     32 bytes
 *   [thrt_overlay_entry_t * N]  40 bytes each
 *   [string pool]               NUL at offset 0, then NUL-terminated
 *                               indicator values and tags JSON arrays
 *   [uint32_t CRC32C]           4-byte trailer
 *
 * Version 1 stored only the 32-bit CRC32C of each indicator and matched on
 * it, so an unrelated value with the same CRC hit the entry, by chance or by
 * construction. Version 2 stores the value and a lookup compares it.
 * Version 1 files are refused.
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

#ifndef THRT_OVERLAY_H
#define THRT_OVERLAY_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "thrt_logic.h" /* for crc32c_platform(), thrt_hash() */

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

#define THRT_OVERLAY_MAGIC 0x4F564C59 /* "OVLY" */
#define THRT_OVERLAY_VERSION 2
#define THRT_OVERLAY_ENTRIES_MAX (1u << 24)

#define OVERLAY_ACTION_ADD '+'
#define OVERLAY_ACTION_WHITELIST '-'
#define OVERLAY_ACTION_TAG 'T' /* Tag-only: inject tags without CTI match */

#define OVERLAY_SUPPRESS_SCORE_ONLY 0
#define OVERLAY_SUPPRESS_FULL 1

/* thrt_overlay_load_ex() reasons. */
#define THRT_OVERLAY_OK 0
#define THRT_OVERLAY_ERR_IO 1       /* open, fstat or mmap failed */
#define THRT_OVERLAY_ERR_FORMAT 2   /* magic, size or an entry is out of bounds */
#define THRT_OVERLAY_ERR_VERSION 3  /* not version 2 */
#define THRT_OVERLAY_ERR_CHECKSUM 4 /* trailing CRC32C mismatch */
#define THRT_OVERLAY_ERR_NOMEM 5

/* ============================================================================
 * BINARY FORMAT STRUCTURES
 * ============================================================================ */

typedef struct {
    uint32_t magic; /* THRT_OVERLAY_MAGIC */
    uint32_t version; /* THRT_OVERLAY_VERSION */
    uint32_t entry_count; /* Number of overlay entries */
    uint32_t tenant_id; /* Overlay isolation key */
    uint64_t timestamp; /* Build timestamp (epoch seconds) */
    uint32_t checksum; /* Reserved (header-level checksum, unused - file CRC is trailer) */
    uint32_t reserved; /* Padding to 32 bytes */
} thrt_overlay_header_t;

_Static_assert(sizeof(thrt_overlay_header_t) == 32, "header must be 32 bytes");

typedef struct {
    uint64_t ioc_hash; /* thrt_hash() of the value, checked at load */
    uint32_t value_offset; /* Offset of the NUL-terminated value in the string pool */
    uint32_t value_length; /* Value length, without the NUL */
    uint8_t action; /* '+' add, '-' whitelist, 'T' tag */
    uint8_t suppress_mode; /* 0 = soft (flag, keep enrichment), 1 = full_suppress (whitelist only) */
    uint8_t confidence; /* 0-100 confidence level */
    uint8_t type_mask; /* THRT_TYPE_* flags */
    uint16_t category_mask; /* THRT_CAT_* flags */
    uint16_t pad; /* Zero */
    uint32_t tags_offset; /* Offset of a JSON array in the string pool (0 = none) */
    uint32_t tags_length; /* Its length, without the NUL */
    uint64_t feed_mask; /* Reserved, zero */
} thrt_overlay_entry_t;

_Static_assert(sizeof(thrt_overlay_entry_t) == 40, "entry must be 40 bytes");

/* ============================================================================
 * LOADED OVERLAY (in-memory, with hash index for O(1) lookup)
 * ============================================================================ */

#define THRT_OVERLAY_IDX_EMPTY 0xFFFFFFFFu

typedef struct {
    void* map_base; /* mmap base pointer */
    size_t map_size; /* mmap region size */
    const thrt_overlay_header_t* header; /* Points into map_base */
    const thrt_overlay_entry_t* entries; /* Points into map_base (after header) */
    const char* string_pool; /* Points into map_base (after entries) */
    size_t pool_size; /* Bytes in the string pool */

    /* Hash index for O(1) lookup - open addressing, linear probing */
    uint32_t idx_capacity; /* Power of 2, >= entry_count * 2 */
    uint32_t* idx_slots; /* hash -> entry index (THRT_OVERLAY_IDX_EMPTY = empty) */
} thrt_overlay_t;

/* ============================================================================
 * IMPLEMENTATION
 * ============================================================================ */

/* Round up to next power of 2 (minimum 4). v <= 2^31. */
static inline uint32_t overlay_next_pow2(uint32_t v) {
    if (v < 4) return 4;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1;
}

/* A [off, off + len] string with its NUL fits the pool. */
static inline bool overlay_str_ok(const char* pool, size_t pool_size, uint32_t off, uint32_t len) {
    if ((size_t)off >= pool_size) return false;
    if ((size_t)len >= pool_size - (size_t)off) return false;
    return pool[(size_t)off + len] == '\0' && memchr(pool + off, '\0', len) == NULL;
}

/* Load and validate an overlay. Returns NULL and sets *why (optional) on
 * failure. Every entry is checked before the overlay is returned: its value
 * and tags lie inside the pool, are NUL-terminated, and the stored hash is
 * the hash of the stored value. A lookup then trusts the file. */
static __attribute__((unused)) thrt_overlay_t* thrt_overlay_load_ex(const char* path, int* why) {
    int fd;
    struct stat sb;
    size_t file_size, entries_size, data_len, pool_off;
    void* map;
    const thrt_overlay_header_t* hdr;
    const thrt_overlay_entry_t* ents;
    const char* pool;
    size_t pool_size;
    uint32_t stored_crc, computed_crc, mask;
    thrt_overlay_t* ovl;
    int err = THRT_OVERLAY_ERR_FORMAT;

    if (why) *why = THRT_OVERLAY_ERR_IO;
    if (!path || !*path) return NULL;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        close(fd);
        return NULL;
    }
    file_size = (size_t)sb.st_size;
    if (file_size < sizeof(thrt_overlay_header_t) + 1 + sizeof(uint32_t)) {
        close(fd);
        if (why) *why = THRT_OVERLAY_ERR_FORMAT;
        return NULL;
    }
    map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return NULL;

    hdr = (const thrt_overlay_header_t*)map;
    if (hdr->magic != THRT_OVERLAY_MAGIC) goto fail;
    if (hdr->version != THRT_OVERLAY_VERSION) {
        err = THRT_OVERLAY_ERR_VERSION;
        goto fail;
    }
    if (hdr->entry_count > THRT_OVERLAY_ENTRIES_MAX) goto fail;

    /* header + entries + at least the pool's leading NUL + CRC trailer */
    entries_size = (size_t)hdr->entry_count * sizeof(thrt_overlay_entry_t);
    if (file_size - sizeof(thrt_overlay_header_t) - sizeof(uint32_t) < entries_size + 1) goto fail;

    data_len = file_size - sizeof(uint32_t);
    memcpy(&stored_crc, (const uint8_t*)map + data_len, sizeof(uint32_t));
    computed_crc = crc32c_platform(0xFFFFFFFF, map, data_len) ^ 0xFFFFFFFF;
    if (computed_crc != stored_crc) {
        err = THRT_OVERLAY_ERR_CHECKSUM;
        goto fail;
    }

    ents = (const thrt_overlay_entry_t*)(const void*)((const uint8_t*)map + sizeof(thrt_overlay_header_t));
    pool_off = sizeof(thrt_overlay_header_t) + entries_size;
    pool = (const char*)map + pool_off;
    pool_size = data_len - pool_off;
    if (pool[0] != '\0') goto fail;

    for (uint32_t i = 0; i < hdr->entry_count; i++) {
        const thrt_overlay_entry_t* e = &ents[i];
        if (e->action != OVERLAY_ACTION_ADD && e->action != OVERLAY_ACTION_WHITELIST && e->action != OVERLAY_ACTION_TAG)
            goto fail;
        if (e->value_length == 0 || !overlay_str_ok(pool, pool_size, e->value_offset, e->value_length)) goto fail;
        if (thrt_hash(pool + e->value_offset) != e->ioc_hash) goto fail;
        if (e->tags_length != 0 && !overlay_str_ok(pool, pool_size, e->tags_offset, e->tags_length)) goto fail;
    }

    ovl = (thrt_overlay_t*)calloc(1, sizeof(thrt_overlay_t));
    if (!ovl) {
        err = THRT_OVERLAY_ERR_NOMEM;
        goto fail;
    }
    ovl->map_base = map;
    ovl->map_size = file_size;
    ovl->header = hdr;
    ovl->entries = ents;
    ovl->string_pool = pool;
    ovl->pool_size = pool_size;

    /* Load factor <= 0.5, so every probe chain ends on an empty slot. */
    ovl->idx_capacity = overlay_next_pow2(hdr->entry_count * 2);
    ovl->idx_slots = (uint32_t*)malloc((size_t)ovl->idx_capacity * sizeof(uint32_t));
    if (!ovl->idx_slots) {
        free(ovl);
        err = THRT_OVERLAY_ERR_NOMEM;
        goto fail;
    }
    memset(ovl->idx_slots, 0xFF, (size_t)ovl->idx_capacity * sizeof(uint32_t));
    mask = ovl->idx_capacity - 1;
    for (uint32_t i = 0; i < hdr->entry_count; i++) {
        uint32_t slot = (uint32_t)(ents[i].ioc_hash & mask);
        while (ovl->idx_slots[slot] != THRT_OVERLAY_IDX_EMPTY) slot = (slot + 1) & mask;
        ovl->idx_slots[slot] = i;
    }
    if (why) *why = THRT_OVERLAY_OK;
    return ovl;

fail:
    munmap(map, file_size);
    if (why) *why = err;
    return NULL;
}

static __attribute__((unused)) thrt_overlay_t* thrt_overlay_load(const char* path) {
    return thrt_overlay_load_ex(path, NULL);
}

/* Find the entry for a value. hash is thrt_hash() of the same bytes. The
 * value is compared, so a different value with the same CRC32C misses.
 * When the file lists one value twice, the first entry wins. */
static inline const thrt_overlay_entry_t* thrt_overlay_find(const thrt_overlay_t* ovl,
                                                            uint64_t hash,
                                                            const char* value,
                                                            size_t len) {
    uint32_t mask, slot;
    if (!ovl || !ovl->idx_slots || !value) return NULL;
    mask = ovl->idx_capacity - 1;
    slot = (uint32_t)(hash & mask);
    for (;;) {
        uint32_t idx = ovl->idx_slots[slot];
        const thrt_overlay_entry_t* e;
        if (idx == THRT_OVERLAY_IDX_EMPTY) return NULL;
        e = &ovl->entries[idx];
        if (e->ioc_hash == hash && e->value_length == len && memcmp(ovl->string_pool + e->value_offset, value, len) == 0)
            return e;
        slot = (slot + 1) & mask;
    }
}

/* Free overlay: munmap the file mapping and free heap allocations. */
static inline void thrt_overlay_free(thrt_overlay_t* ovl) {
    if (!ovl) return;
    if (ovl->map_base && ovl->map_base != MAP_FAILED) munmap(ovl->map_base, ovl->map_size);
    free(ovl->idx_slots);
    free(ovl);
}

#endif /* THRT_OVERLAY_H */
