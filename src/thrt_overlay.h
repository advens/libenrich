/* thrt_overlay.h
 * Site-local CTI overlay (.ovly) for local IOC additions and whitelists.
 * A small binary file loaded alongside the main .thrt database and checked
 * before the normal CTI lookup on the hot path.
 *
 * Layout:
 *   [thrt_overlay_header_t]     32 bytes
 *   [thrt_overlay_entry_t * N]  32 bytes each
 *   [string pool]               variable (tags JSON)
 *   [uint32_t CRC32C]           4-byte trailer
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
#define THRT_OVERLAY_VERSION 1

#define OVERLAY_ACTION_ADD '+'
#define OVERLAY_ACTION_WHITELIST '-'
#define OVERLAY_ACTION_TAG 'T' /* Tag-only: inject tags without CTI match */

#define OVERLAY_SUPPRESS_SCORE_ONLY 0
#define OVERLAY_SUPPRESS_FULL 1

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
    uint64_t ioc_hash; /* CRC32C hash of IOC value string (same as thrt_hash()) */
    uint8_t action; /* '+' = add, '-' = whitelist */
    uint8_t suppress_mode; /* 0 = soft (flag, keep enrichment), 1 = full_suppress (whitelist only) */
    uint8_t confidence; /* 0-100 confidence level */
    uint8_t type_mask; /* THRT_TYPE_* flags */
    uint16_t category_mask; /* THRT_CAT_* flags */
    uint16_t pad; /* Alignment padding */
    uint64_t feed_mask; /* Which feeds contributed */
    uint32_t tags_offset; /* Offset into string pool (0 = none) */
    uint32_t tags_length; /* Length of tags JSON in string pool */
} thrt_overlay_entry_t;

_Static_assert(sizeof(thrt_overlay_entry_t) == 32, "entry must be 32 bytes");

/* ============================================================================
 * LOADED OVERLAY (in-memory, with hash index for O(1) lookup)
 * ============================================================================ */

#define THRT_OVERLAY_IDX_EMPTY 0xFFFFFFFFu

typedef struct {
    void* map_base; /* mmap base pointer */
    size_t map_size; /* mmap region size */
    thrt_overlay_header_t* header; /* Points into map_base */
    thrt_overlay_entry_t* entries; /* Points into map_base (after header) */
    char* string_pool; /* Points into map_base (after entries) */

    /* Hash index for O(1) lookup - open addressing, linear probing */
    uint32_t idx_capacity; /* Power of 2, >= entry_count * 2 */
    uint32_t* idx_slots; /* hash -> entry index (THRT_OVERLAY_IDX_EMPTY = empty) */
} thrt_overlay_t;

/* ============================================================================
 * IMPLEMENTATION
 * ============================================================================ */

/* Round up to next power of 2 (minimum 4) */
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

/* Load overlay from file. Returns NULL on failure (not an error - overlay is optional).
 *
 * Steps:
 *   1. open + fstat + mmap(MAP_PRIVATE, PROT_READ)
 *   2. Validate magic, version, minimum size
 *   3. Verify trailing CRC32C (same pattern as the .thrt database)
 *   4. Set up pointers: header, entries, string_pool
 *   5. Build hash index: power-of-2 capacity >= entry_count * 2, linear probing
 *   6. Return allocated thrt_overlay_t
 */
static inline thrt_overlay_t* thrt_overlay_load(const char* path) {
    if (!path || !*path) return NULL;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;

    struct stat sb;
    if (fstat(fd, &sb) != 0 || sb.st_size == 0) {
        close(fd);
        return NULL;
    }

    size_t file_size = (size_t)sb.st_size;

    /* Minimum: header + CRC32C trailer */
    if (file_size < sizeof(thrt_overlay_header_t) + sizeof(uint32_t)) {
        close(fd);
        return NULL;
    }

    void* map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED) return NULL;

    /* Validate header */
    thrt_overlay_header_t* hdr = (thrt_overlay_header_t*)map;
    if (hdr->magic != THRT_OVERLAY_MAGIC) {
        munmap(map, file_size);
        return NULL;
    }
    if (hdr->version != THRT_OVERLAY_VERSION) {
        munmap(map, file_size);
        return NULL;
    }

    /* Validate file size: header + entries + CRC trailer (string pool is variable) */
    size_t entries_size = (size_t)hdr->entry_count * sizeof(thrt_overlay_entry_t);
    size_t min_size = sizeof(thrt_overlay_header_t) + entries_size + sizeof(uint32_t);
    if (file_size < min_size) {
        munmap(map, file_size);
        return NULL;
    }

    /* Verify trailing CRC32C */
    size_t data_len = file_size - sizeof(uint32_t);
    uint32_t stored_crc;
    memcpy(&stored_crc, (uint8_t*)map + data_len, sizeof(uint32_t));
    uint32_t computed_crc = crc32c_platform(0xFFFFFFFF, map, data_len) ^ 0xFFFFFFFF;

    if (computed_crc != stored_crc) {
        munmap(map, file_size);
        return NULL;
    }

    /* Set up pointers into the mmap'd region */
    thrt_overlay_entry_t* entries_ptr = (thrt_overlay_entry_t*)(void*)((uint8_t*)map + sizeof(thrt_overlay_header_t));

    char* pool_ptr = (char*)((uint8_t*)map + sizeof(thrt_overlay_header_t) + entries_size);

    /* Allocate the overlay descriptor */
    thrt_overlay_t* ovl = (thrt_overlay_t*)calloc(1, sizeof(thrt_overlay_t));
    if (!ovl) {
        munmap(map, file_size);
        return NULL;
    }

    ovl->map_base = map;
    ovl->map_size = file_size;
    ovl->header = hdr;
    ovl->entries = entries_ptr;
    ovl->string_pool = pool_ptr;

    /* Build hash index for O(1) lookup.
     * Capacity = next power of 2 >= entry_count * 2 (load factor <= 0.5).
     * Linear probing with ioc_hash as key. */
    ovl->idx_capacity = overlay_next_pow2(hdr->entry_count * 2);
    ovl->idx_slots = (uint32_t*)malloc(ovl->idx_capacity * sizeof(uint32_t));
    if (!ovl->idx_slots) {
        munmap(map, file_size);
        free(ovl);
        return NULL;
    }

    /* Initialize all slots to empty */
    memset(ovl->idx_slots, 0xFF, ovl->idx_capacity * sizeof(uint32_t));

    /* Insert each entry into the hash index */
    uint32_t mask = ovl->idx_capacity - 1;
    for (uint32_t i = 0; i < hdr->entry_count; i++) {
        uint32_t slot = (uint32_t)(entries_ptr[i].ioc_hash & mask);
        while (ovl->idx_slots[slot] != THRT_OVERLAY_IDX_EMPTY) {
            slot = (slot + 1) & mask;
        }
        ovl->idx_slots[slot] = i;
    }

    return ovl;
}

/* Look up an IOC in the overlay by its hash (produced by thrt_hash()).
 * Returns pointer to the matching entry, or NULL if not found.
 *
 * O(1) average via open-addressed hash table with linear probing.
 * Load factor <= 0.5 guarantees short probe chains. */
static inline const thrt_overlay_entry_t* thrt_overlay_lookup(const thrt_overlay_t* ovl, uint64_t ioc_hash) {
    if (!ovl || !ovl->idx_slots) return NULL;

    uint32_t mask = ovl->idx_capacity - 1;
    uint32_t slot = (uint32_t)(ioc_hash & mask);

    for (;;) {
        uint32_t idx = ovl->idx_slots[slot];
        if (idx == THRT_OVERLAY_IDX_EMPTY) return NULL; /* Empty slot - not found */
        if (ovl->entries[idx].ioc_hash == ioc_hash) return &ovl->entries[idx]; /* Match */
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
