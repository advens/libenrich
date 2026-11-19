/* thrt_format.h
 * On-disk binary layout of the CTI database (.thrt). Structures are
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
#define THRT_VERSION 5

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
 * FILE HEADER (V4 layout, also used by V5)
 * ============================================================================ */
typedef struct {
    uint32_t magic;  // "THRT"
    uint32_t version;  // THRT_VERSION

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
    // Bit i is set when feed i is a public CTI feed. A reader that prints
    // feed names masks feed_mask with it, so restricted and tags feeds stay
    // out of the output.
    uint64_t public_feed_mask;

    // The address rows as the feeds declared them, before overlapping
    // ranges are cut into the disjoint pieces lookups search. Only the
    // builder reads them back, so a fold can merge, withdraw or evict an
    // exact network. Same entry layouts as the lookup tables.
    uint64_t offset_src_ipv4;
    uint64_t offset_src_ipv6;
    uint32_t src_ipv4_count;
    uint32_t src_ipv6_count;

} thrt_header_t;


/* ============================================================================
 * ACCELERATION TABLE ENTRY (Dirty Table)
 * ============================================================================ */
typedef struct {
    uint32_t range_start_idx;  // Index in the main IPv4 Range Array
    uint32_t range_count;  // How many ranges overlap with this /16
} thrt_ip_accel_t;

/* ============================================================================
 * METADATA RECORD (The Enrichment Data)
 *
 * Each unique combination of fields gets one entry. Multiple IOCs can
 * reference the same metadata entry.
 *
 * Since v5, confidence, tlp_mask, category_mask and feed_mask describe the
 * public CTI layer only. A restricted (CTI_R) contribution sets the
 * THRT_TYPE_CTI_R bit and confidence_r, nothing else, so a reader that prints
 * the public fields never prints a restricted feed, marking or score. A tags
 * contribution sets THRT_TYPE_TAGS and the tags only. The labels a public CTI
 * source attaches (MISP tags, STIX labels) are kept apart from those context
 * tags.
 * ============================================================================ */
typedef struct {
    uint8_t confidence;  // 0-100, max across public CTI sources
    uint8_t type_mask;  // THRT_TYPE_* flags: which entry types matched
    uint8_t tlp_mask;  // THRT_TLP_* flags of public CTI sources
    uint8_t confidence_r;  // 0-100, max across restricted sources

    uint16_t category_mask;  // THRT_CAT_* flags of public CTI sources
    uint16_t pad2;  // Alignment

    uint64_t feed_mask;  // Bitmask: which public CTI feeds (up to 64) contributed

    uint32_t tags_offset;  // Context tags (tags layer): JSON array of strings
                           // in the string pool, 0 = none
    uint32_t tags_length;  // Length of that JSON, 0 if none

    uint32_t labels_offset;  // Labels of public CTI sources (MISP tags, STIX
                             // labels): JSON array of strings, 0 = none
    uint32_t labels_length;  // Length of that JSON, 0 if none

} thrt_metadata_t;

/* Static assert for size/alignment */
_Static_assert(sizeof(thrt_metadata_t) == 32, "thrt_metadata_t must be 32 bytes");
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
