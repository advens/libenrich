/* thrt_logic.h
 * Shared lookup logic and hardware-accelerated CRC32C helpers for the mmenrich
 * CTI database (.thrt). Enables the hardware CRC32C path on __SSE4_2__ (x86-64)
 * and __ARM_FEATURE_CRC32 (arm64), with a scalar fallback otherwise.
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
#ifndef THRT_LOGIC_H
#define THRT_LOGIC_H

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "thrt_format.h"

/* Hardware CRC32C acceleration, gated at compile time on the ISA feature macro,
 * matching the TurboVM turbo_simd.h pattern: only emit an SSE4.2 / ARM-CRC
 * instruction when the build target actually provides it, and fall back to the
 * scalar path otherwise. This avoids force-compiling an instruction the build
 * baseline did not opt into, which would SIGILL on a CPU that lacks it (old
 * x86-64 without SSE4.2, or an ARMv8.0 core without the CRC extension). To get
 * the hardware path, build with the matching -march/-msse4.2 flags. */
#if (defined(__x86_64__) || defined(_M_X64)) && defined(__SSE4_2__)
    #include <nmmintrin.h>  // SSE4.2
    #define THRT_HW_ACCEL 1

static inline uint32_t crc32c_platform(uint32_t crc, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    while (len >= 8) {
        uint64_t chunk;
        memcpy(&chunk, p, 8);
        crc = (uint32_t)_mm_crc32_u64((uint64_t)crc, chunk);
        p += 8;
        len -= 8;
    }
    if (len >= 4) {
        uint32_t chunk;
        memcpy(&chunk, p, 4);
        crc = _mm_crc32_u32(crc, chunk);
        p += 4;
        len -= 4;
    }
    if (len >= 2) {
        uint16_t chunk;
        memcpy(&chunk, p, 2);
        crc = _mm_crc32_u16(crc, chunk);
        p += 2;
        len -= 2;
    }
    if (len & 1) crc = _mm_crc32_u8(crc, *p);
    return crc;
}
#elif (defined(__aarch64__) || defined(_M_ARM64)) && defined(__ARM_FEATURE_CRC32)
    #include <arm_acle.h>
    #define THRT_HW_ACCEL 1

static inline uint32_t crc32c_platform(uint32_t crc, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    while (len >= 8) {
        uint64_t chunk;
        memcpy(&chunk, p, 8);
        crc = __crc32cd(crc, chunk);
        p += 8;
        len -= 8;
    }
    if (len >= 4) {
        uint32_t chunk;
        memcpy(&chunk, p, 4);
        crc = __crc32cw(crc, chunk);
        p += 4;
        len -= 4;
    }
    if (len >= 2) {
        uint16_t chunk;
        memcpy(&chunk, p, 2);
        crc = __crc32ch(crc, chunk);
        p += 2;
        len -= 2;
    }
    if (len & 1) crc = __crc32cb(crc, *p);
    return crc;
}

#else
    // SOFTWARE FALLBACK (generic CPU, or a build without the CRC ISA feature).
    // bit-wise compact implementation of Castagnoli polynom (0x82F63B78).
    #define THRT_HW_ACCEL 0
    // Warn only on SIMD-capable targets where the feature flag was simply not
    // passed: this is almost always a build misconfiguration that silently costs
    // throughput. Genuinely scalar-only targets stay quiet.
    #if defined(__x86_64__) || defined(_M_X64)
        #warning \
            "mmenrich: hardware CRC32C disabled, using the scalar fallback (slow). Build with -msse4.2 (or -march=x86-64-v2 or newer) to enable it."
    #elif defined(__aarch64__) || defined(_M_ARM64)
        #warning \
            "mmenrich: hardware CRC32C disabled, using the scalar fallback (slow). Build with -march=armv8-a+crc (or a -mcpu that implies +crc) to enable it."
    #endif
static inline uint32_t crc32c_platform(uint32_t crc, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    while (len--) {
        crc ^= *p++;
        for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0x82F63B78 & (-(crc & 1)));
    }
    return crc;
}
#endif

// CORE HASH FUNCTION
static inline uint64_t thrt_hash(const char* str) {
    // Initial Seed: 0xFFFFFFFF (Standard for CRC32C)
    // We invert the result (XOR) at the end to match Python/Go/Hardware
    return (uint64_t)(crc32c_platform(0xFFFFFFFF, str, strlen(str)) ^ 0xFFFFFFFF);
}


// Fast IPv4 parser (Zero-Copy, No Validation - assumed validated by Miner)
static inline uint32_t thrt_parse_ipv4_fast(const char* s, size_t len) {
    uint32_t ip = 0;
    uint32_t val = 0;
    const char* end = s + len;

    while (s < end) {
        char c = *s++;
        if (c == '.') {
            ip = (ip << 8) | val;
            val = 0;
        } else {
            val = (val * 10) + (c - '0');
        }
    }
    ip = (ip << 8) | val;
    return ip;  // Returns Host Byte Order (Needs htonl for comparison if DB is Big Endian)
    // Note: The thrtutil stores IPs in Host Byte Order (ntohl calls),
    // so we can compare directly without byteswap if we stay consistent.
}

// Fast IPv6 parser
static inline bool thrt_parse_ipv6_fast(const char* src, size_t len, uint8_t* dst) {
    memset(dst, 0, 16);
    const char* p = src;
    const char* end = src + len;
    int idx = 0;
    int double_colon_idx = -1;

    while (p < end && idx < 8) {
        // Handle double colon '::'
        if (*p == ':') {
            if (p + 1 < end && *(p + 1) == ':') {
                if (double_colon_idx != -1) return false;  // Error: Two '::'
                double_colon_idx = idx;
                p += 2;
                continue;
            }
            if (p == src) return false;  // specific case leading colon
            p++;
        }

        // Parse Hextet
        uint16_t val = 0;
        while (p < end) {
            char c = *p;
            int v = -1;
            if (c >= '0' && c <= '9')
                v = c - '0';
            else if (c >= 'a' && c <= 'f')
                v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')
                v = c - 'A' + 10;
            else
                break;  // separator or end

            val = (val << 4) | v;
            p++;
        }

        // Store in Network Byte Order (Big Endian)
        dst[idx * 2] = (val >> 8) & 0xFF;
        dst[idx * 2 + 1] = val & 0xFF;
        idx++;
    }

    // Expand Double Colon if present
    if (double_colon_idx != -1) {
        int slots_parsed = idx;
        // Shift the tail to the right
        int tail_len = (slots_parsed - double_colon_idx) * 2;
        if (tail_len > 0) {
            memmove(dst + (16 - tail_len), dst + (double_colon_idx * 2), tail_len);
            memset(dst + (double_colon_idx * 2), 0, 16 - tail_len - (double_colon_idx * 2));
        }
    } else if (idx != 8) {
        return false;  // Incomplete IP
    }

    return true;
}

/* Optimized Bloom Filter Check
 * Key optimizations:
 * 1. Unrolled loop for 3 checks (no loop overhead)
 * 2. Software prefetching for next lookup
 * 3. Early exit on first miss
 */

#if defined(__x86_64__) || defined(_M_X64)
    #include <immintrin.h>
    #define PREFETCH(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T0)
#elif defined(__aarch64__) || defined(_M_ARM64)
    #include <arm_acle.h>
    #define PREFETCH(addr) __builtin_prefetch((const void*)(addr), 0, 3)
#else
    #define PREFETCH(addr) ((void)0)
#endif

/* Standard bloom check - optimized for early exit */
static inline bool thrt_bloom_check(const uint8_t* bloom, uint32_t total_bits, uint64_t hash) {
    if (!bloom || !total_bits) return true;  // Fail open

    uint32_t h1 = (uint32_t)hash;
    uint32_t h2 = (uint32_t)((hash >> 32) | (hash << 32));

    // Check bit 0
    uint32_t idx0 = h1 % total_bits;
    if (!(bloom[idx0 >> 3] & (1 << (idx0 & 7)))) {
        return false;  // Early exit - most common case
    }

    // Check bit 1
    uint32_t idx1 = (h1 + h2) % total_bits;
    if (!(bloom[idx1 >> 3] & (1 << (idx1 & 7)))) {
        return false;
    }

    // Check bit 2
    uint32_t idx2 = (h1 + (h2 << 1)) % total_bits;
    return (bloom[idx2 >> 3] & (1 << (idx2 & 7))) != 0;
}

/* Batch bloom check with prefetching
 * We use this when checking multiple hashes in sequence
 * Example: checking all fields (src_ip, dst_ip, domain) in one message
 */
static inline void thrt_bloom_check_batch(
    const uint8_t* bloom, uint32_t total_bits, const uint64_t* hashes, bool* results, int count) {
    if (!bloom || !total_bits) {
        for (int i = 0; i < count; i++) results[i] = true;
        return;
    }

    for (int i = 0; i < count; i++) {
        uint64_t hash = hashes[i];
        uint32_t h1 = (uint32_t)hash;
        uint32_t h2 = (uint32_t)((hash >> 32) | (hash << 32));

        // Prefetch next hash's first location
        if (i + 1 < count) {
            uint64_t next_hash = hashes[i + 1];
            uint32_t next_h1 = (uint32_t)next_hash;
            uint32_t next_idx = next_h1 % total_bits;
            PREFETCH(&bloom[next_idx >> 3]);
        }

        // Check current hash
        uint32_t idx0 = h1 % total_bits;
        if (!(bloom[idx0 >> 3] & (1 << (idx0 & 7)))) {
            results[i] = false;
            continue;
        }

        uint32_t idx1 = (h1 + h2) % total_bits;
        if (!(bloom[idx1 >> 3] & (1 << (idx1 & 7)))) {
            results[i] = false;
            continue;
        }

        uint32_t idx2 = (h1 + (h2 << 1)) % total_bits;
        results[i] = (bloom[idx2 >> 3] & (1 << (idx2 & 7))) != 0;
    }
}

/* Alternative Bloom Check : Using multiplication for second hash (faster modulo)
 * Only works if h2 is carefully chosen to avoid collisions
 */
static inline bool thrt_bloom_check_fast(const uint8_t* bloom, uint32_t total_bits, uint64_t hash) {
    if (!bloom || !total_bits) return true;

    // Ensure total_bits is power of 2 for fast modulo
    // If not, fall back to standard version
    if ((total_bits & (total_bits - 1)) != 0) {
        return thrt_bloom_check(bloom, total_bits, hash);
    }

    uint32_t mask = total_bits - 1;
    uint32_t h1 = (uint32_t)hash;
    uint32_t h2 = (uint32_t)(hash >> 32);

    // Fast modulo using bitwise AND
    uint32_t idx0 = h1 & mask;
    if (!(bloom[idx0 >> 3] & (1 << (idx0 & 7)))) return false;

    uint32_t idx1 = (h1 + h2) & mask;
    if (!(bloom[idx1 >> 3] & (1 << (idx1 & 7)))) return false;

    uint32_t idx2 = (h1 + (h2 << 1)) & mask;
    return (bloom[idx2 >> 3] & (1 << (idx2 & 7))) != 0;
}

// Legacy V1 Binary Search (needed by Accelerated Lookup)
static inline thrt_metadata_t* thrt_lookup_ip(thrt_ipv4_range_t* table,
                                              int count,
                                              thrt_metadata_t* meta_base,
                                              uint32_t ip) {
    int low = 0, high = count - 1;
    while (low <= high) {
        int mid = low + (high - low) / 2;
        thrt_ipv4_range_t* range = &table[mid];
        if (ip < range->ip_start)
            high = mid - 1;
        else if (ip > range->ip_end)
            low = mid + 1;
        else
            return &meta_base[range->meta_idx];
    }
    return NULL;
}

// Accelerated IPv4 Lookup
static inline thrt_metadata_t* thrt_lookup_ip_accel(thrt_ipv4_range_t* ranges,
                                                    thrt_ip_accel_t* accel,
                                                    thrt_metadata_t* meta_base,
                                                    uint32_t ip) {
    // 1. O(1) Jump to the correct /16 block
    uint32_t idx = ip >> (32 - THRT_IP_ACCEL_BITS);
    thrt_ip_accel_t* entry = &accel[idx];

    if (entry->range_count == 0) return NULL;

    // 2. O(log n) Search on small subset (usually < 100 items)
    return thrt_lookup_ip(&ranges[entry->range_start_idx], entry->range_count, meta_base, ip);
}

// IPv6 Lookup
static inline thrt_metadata_t* thrt_lookup_ipv6(thrt_ipv6_range_t* table,
                                                int count,
                                                thrt_metadata_t* meta_base,
                                                uint8_t* ip) {
    int low = 0, high = count - 1;
    while (low <= high) {
        int mid = low + (high - low) / 2;
        thrt_ipv6_range_t* range = &table[mid];
        int cmp_start = memcmp(ip, range->ip_start, 16);
        int cmp_end = memcmp(ip, range->ip_end, 16);
        if (cmp_start < 0)
            high = mid - 1;
        else if (cmp_end > 0)
            low = mid + 1;
        else
            return &meta_base[range->meta_idx];
    }
    return NULL;
}

/* ============================================================================
 * PRIVATE IP DETECTION
 * Skip CTI/GeoIP lookups for RFC1918, loopback, link-local, CGNAT, etc.
 * These will never match public threat feeds or GeoIP databases.
 * Cost: ~3-5 integer comparisons (branch-predicted, near-zero overhead).
 * ============================================================================ */

/* IPv4: host byte order input (same as thrt_lookup_ip expects) */
static inline bool thrt_is_private_ipv4(uint32_t ip) {
    /* 10.0.0.0/8 */
    if ((ip >> 24) == 10) return true;
    /* 172.16.0.0/12 */
    if ((ip >> 20) == 0xAC1) return true; /* 172.16-31.x.x */
    /* 192.168.0.0/16 */
    if ((ip >> 16) == 0xC0A8) return true;
    /* 127.0.0.0/8 (loopback) */
    if ((ip >> 24) == 127) return true;
    /* 169.254.0.0/16 (link-local) */
    if ((ip >> 16) == 0xA9FE) return true;
    /* 100.64.0.0/10 (CGNAT - RFC 6598) */
    if ((ip >> 22) == (100 << 2 | 1)) return true; /* 100.64-127.x.x */
    /* 0.0.0.0/8 (current network) */
    if ((ip >> 24) == 0) return true;
    return false;
}

/* IPv6: network byte order input (16-byte array, same as in6_addr.s6_addr) */
static inline bool thrt_is_private_ipv6(const uint8_t* ip) {
    /* ::1 (loopback) */
    static const uint8_t loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (memcmp(ip, loopback, 16) == 0) return true;
    /* :: (unspecified) */
    static const uint8_t unspec[16] = {0};
    if (memcmp(ip, unspec, 16) == 0) return true;
    /* fe80::/10 (link-local) */
    if (ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80) return true;
    /* fc00::/7 (ULA - unique local address) */
    if ((ip[0] & 0xFE) == 0xFC) return true;
    return false;
}

// Hash Lookup for Strings (O(1))
static inline thrt_metadata_t* thrt_lookup_string(
    thrt_hash_entry_t* table, int slots, char* str_pool, thrt_metadata_t* meta_base, const char* key) {
    uint64_t hash = thrt_hash(key);
    uint32_t mask = slots - 1;
    uint32_t idx = (uint32_t)hash & mask;
    int probes = 0;

    // Limit probes to avoid infinite loops on corrupted DBs
    while (probes < 128) {
        thrt_hash_entry_t* entry = &table[idx];

        // 0xFFFFFFFF indicates an empty slot (End of Chain)
        if (entry->meta_idx == 0xFFFFFFFF) return NULL;

        if (entry->hash_key == hash) {
            // Hash Matches. Now Verify the actual string to avoid collisions.
            if (strcmp(key, str_pool + entry->string_offset) == 0) {
                return &meta_base[entry->meta_idx];
            }
        }
        // Linear Probe: Try next slot
        idx = (idx + 1) & mask;
        probes++;
    }
    return NULL;
}

#endif
