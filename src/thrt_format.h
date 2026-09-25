/* thrt_format.h
 * On-disk binary layout of the mmenrich CTI database (.thrt). Structures are
 * 8-byte aligned for safe 64-bit access on all platforms. Carries per-entry
 * type, feed, TLP and category bitmasks plus a tags-JSON string pool and a
 * feed-name table in the header.
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

#ifndef THRT_FORMAT_H
#define THRT_FORMAT_H

#include <stdint.h>

/* Global Shared Constants --- */
// 16 bits = 65536 slots (Covering /16 networks).
// Memory cost: 65536 * 8 bytes = 512 KB (negligible).
#define THRT_IP_ACCEL_BITS 16
#define THRT_IP_ACCEL_SLOTS (1 << THRT_IP_ACCEL_BITS)
#define THRT_IP_ACCEL_MASK (THRT_IP_ACCEL_SLOTS - 1)

#define THRT_MAGIC 0x54485254  // "THRT" in ASCII
#define THRT_VERSION 4

/* ============================================================================
 * ENTRY TYPE FLAGS
 * Indicates which data sources contributed to this entry
 * ============================================================================ */
#define THRT_TYPE_CTI 0x01 /* Public CTI feed match */
#define THRT_TYPE_CTI_R 0x02 /* Restricted CTI feed match (sensitive) */
#define THRT_TYPE_TAGS 0x04 /* Tags/CMDB/Carto match */

/* ============================================================================
 * TLP FLAGS (Traffic Light Protocol)
 * Pre-computed from feed metadata by thrtutil
 * ============================================================================ */
#define THRT_TLP_CLEAR 0x01 /* TLP:CLEAR (formerly WHITE) */
#define THRT_TLP_GREEN 0x02 /* TLP:GREEN */
#define THRT_TLP_AMBER 0x04 /* TLP:AMBER */
#define THRT_TLP_RED 0x08 /* TLP:RED */

/* ============================================================================
 * CATEGORY FLAGS
 * Multiple categories can apply to a single IOC
 * ============================================================================ */
#define THRT_CAT_UNKNOWN 0x00
#define THRT_CAT_ATTACK 0x01 /* Generic attack/malicious-activity */
#define THRT_CAT_MALWARE 0x02 /* Malware, payload delivery */
#define THRT_CAT_PHISHING 0x04 /* Phishing, social engineering */
#define THRT_CAT_BOTNET 0x08 /* Botnet */
#define THRT_CAT_C2 0x10 /* Command-and-control */
#define THRT_CAT_EXPLOIT 0x20 /* Exploitation */
#define THRT_CAT_RANSOMWARE 0x40 /* Ransomware */
#define THRT_CAT_SPAM 0x80 /* Spam */

/* Extended categories (second byte if needed) */
#define THRT_CAT_SCANNER 0x0100 /* Reconnaissance/scanning */
#define THRT_CAT_TOR_EXIT 0x0200 /* Tor exit nodes */
#define THRT_CAT_PROXY 0x0400 /* Open proxies */

/* ============================================================================
 * FILE HEADER (V4)
 * ============================================================================ */
typedef struct {
    uint32_t magic;  // "THRT"
    uint32_t version;  // Version 4

    uint64_t total_size;  // Total file size

    // Counts
    uint32_t metadata_count;
    uint32_t ipv4_range_count;
    uint32_t ipv6_range_count;
    uint32_t hash_slots;  // Must be power of 2

    // Filter Config
    uint32_t bloom_size_bits;

    // [V3+] Integrity Check
    uint32_t checksum;  // CRC32C of file content (excluding this field)
    uint32_t checksum_offset;  // Byte offset of checksum field for verification

    // [V4] Feed Table
    uint32_t feed_count;  // Number of feed names (max 64)
    uint32_t pad_v4;  // Alignment padding

    // Offsets (bytes from start of file)
    uint64_t offset_metadata;
    uint64_t offset_ipv4;
    uint64_t offset_ipv6;
    uint64_t offset_hashtable;
    uint64_t offset_strings;  // Pool of null-terminated strings (IOC values + tag JSON blobs)

    // High-Speed Structures Offsets
    uint64_t offset_ip_accel;  // Points to thrt_ip_accel_t array
    uint64_t offset_bloom;  // Points to raw bit array

    // [V4] Additional offsets
    uint64_t offset_feeds;  // Points to feed name table (array of 64-byte strings)
    uint64_t offset_sources;  // Points to source_entry_t table (legacy compat)

} thrt_header_t;


/* ============================================================================
 * ACCELERATION TABLE ENTRY (Dirty Table)
 * ============================================================================ */
typedef struct {
    uint32_t range_start_idx;  // Index in the main IPv4 Range Array
    uint32_t range_count;  // How many ranges overlap with this /16
} thrt_ip_accel_t;

/* ============================================================================
 * METADATA RECORD V4 (The Enrichment Data)
 *
 * Each unique combination of (confidence, categories, tlp, type, feeds, tags)
 * gets one entry. Multiple IOCs can reference the same metadata entry.
 * ============================================================================ */
typedef struct {
    uint8_t confidence;  // 0-100 (max across all contributing sources)
    uint8_t type_mask;  // THRT_TYPE_* flags: which entry types matched
    uint8_t tlp_mask;  // THRT_TLP_* flags: pre-computed from feeds
    uint8_t pad1;  // Alignment

    uint16_t category_mask;  // THRT_CAT_* flags: categories from all feeds
    uint16_t pad2;  // Alignment

    uint64_t feed_mask;  // Bitmask: which feeds (up to 64) contributed

    uint32_t tags_offset;  // Offset into string pool for JSON tags array
                           // 0 = no tags. Format: ["tag1","tag2",...]
    uint32_t tags_length;  // Length of tags JSON blob (0 if no tags)

} thrt_metadata_t;

/* Static assert for size/alignment */
_Static_assert(sizeof(thrt_metadata_t) == 24, "thrt_metadata_t must be 24 bytes");
_Static_assert(sizeof(thrt_metadata_t) % 8 == 0, "thrt_metadata_t must be 8-byte aligned");

/* ============================================================================
 * IPv4 RANGE (Sorted Array for Binary Search)
 * ============================================================================ */
typedef struct {
    uint32_t ip_start;  // Host byte order
    uint32_t ip_end;  // Host byte order
    uint32_t meta_idx;  // Index into Metadata array
    uint32_t pad;  // Alignment
} thrt_ipv4_range_t;

/* ============================================================================
 * IPv6 RANGE (Sorted Array)
 * ============================================================================ */
typedef struct {
    uint8_t ip_start[16];  // 128-bit start address
    uint8_t ip_end[16];  // 128-bit end address
    uint32_t meta_idx;  // Index into Metadata array
    uint32_t pad;  // Alignment/Future use
} thrt_ipv6_range_t;

/* ============================================================================
 * STRING HASH ENTRY (Linear Probing Hash Table)
 * ============================================================================ */
typedef struct {
    uint64_t hash_key;  // CRC32C/xxHash of the string
    uint32_t string_offset;  // Offset into String Pool (for exact match verification)
    uint32_t meta_idx;  // Index into Metadata array. 0xFFFFFFFF = Empty
} thrt_hash_entry_t;

/* ============================================================================
 * FEED NAME ENTRY
 * Fixed-size entry for feed name lookup by index
 * ============================================================================ */
#define THRT_FEED_NAME_MAX 64

typedef struct {
    char name[THRT_FEED_NAME_MAX];  // Null-terminated feed name
} thrt_feed_entry_t;

/* ============================================================================
 * LEGACY SOURCE ENTRY (V2/V3 compatibility)
 * ============================================================================ */
typedef struct {
    char name[64];
    uint16_t id;
    uint16_t pad[3];  // Alignment to 8 bytes
} thrt_source_entry_t;

#endif /* THRT_FORMAT_H */
