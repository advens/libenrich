/* thrt_cli.c
 * Standalone command-line tool to query and inspect a CTI database
 * (.thrt) and perform maintenance operations on it.
 *
 * Usage:   ./thrt_cli <db_file> <ip_or_domain>
 * Compile: cc -O3 thrt_cli.c -o thrt_cli
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include "thrt_format.h"
#include "thrt_logic.h"

/* --- Colors & Icons --- */
#define COL_RESET   "\033[0m"
#define COL_BOLD    "\033[1m"
#define COL_RED     "\033[1;31m"
#define COL_GREEN   "\033[1;32m"
#define COL_CYAN    "\033[0;36m"
#define COL_ORANGE  "\033[38;5;208m"
#define COL_YELLOW  "\033[1;33m"
#define COL_WHITE   "\033[1;37m"

#define ICON_OK     "[OK]"
#define ICON_WARN   "[WARN] "
#define ICON_FAIL   "[FAIL]"
#define ICON_DB     "[DB]"

/* --- V4 Feed Table --- */
static thrt_feed_entry_t *g_feeds = NULL;
static uint32_t g_feed_count = 0;

/* --- Category Mask Decoder --- */
typedef struct { uint16_t flag; const char *name; const char *color; } cat_entry_t;
static const cat_entry_t g_categories[] = {
    { THRT_CAT_ATTACK,     "Attack",     COL_RED },
    { THRT_CAT_MALWARE,    "Malware",    COL_RED },
    { THRT_CAT_PHISHING,   "Phishing",   COL_ORANGE },
    { THRT_CAT_BOTNET,     "Botnet",     COL_RED },
    { THRT_CAT_C2,         "C2",         COL_RED },
    { THRT_CAT_EXPLOIT,    "Exploit",    COL_ORANGE },
    { THRT_CAT_RANSOMWARE, "Ransomware", COL_RED },
    { THRT_CAT_SPAM,       "Spam",       COL_YELLOW },
    { THRT_CAT_SCANNER,    "Scanner",    COL_YELLOW },
    { THRT_CAT_TOR_EXIT,   "Tor Exit",   COL_ORANGE },
    { THRT_CAT_PROXY,      "Proxy",      COL_YELLOW },
    { 0, NULL, NULL }
};

void print_categories(uint16_t mask) {
    int first = 1;
    for (const cat_entry_t *c = g_categories; c->name; c++) {
        if (mask & c->flag) {
            printf("%s%s%s%s", first ? "" : ", ", c->color, c->name, COL_RESET);
            first = 0;
        }
    }
    if (first) printf("Unknown");
    printf(" (0x%04x)", mask);
}

void print_feeds(uint64_t mask) {
    int first = 1;
    for (uint32_t i = 0; i < g_feed_count && i < 64; i++) {
        if (mask & (1ULL << i)) {
            printf("%s%s", first ? "" : ", ", g_feeds[i].name);
            first = 0;
        }
    }
    if (first) printf("(none)");
}

void print_tlp(uint8_t mask) {
    int first = 1;
    if (mask & THRT_TLP_CLEAR) { printf("%s%sWHITE%s", first ? "" : ", ", COL_WHITE, COL_RESET); first = 0; }
    if (mask & THRT_TLP_GREEN) { printf("%s%sGREEN%s", first ? "" : ", ", COL_GREEN, COL_RESET); first = 0; }
    if (mask & THRT_TLP_AMBER) { printf("%s%sAMBER%s", first ? "" : ", ", COL_ORANGE, COL_RESET); first = 0; }
    if (mask & THRT_TLP_RED)   { printf("%s%sRED%s",   first ? "" : ", ", COL_RED, COL_RESET);   first = 0; }
    if (first) printf("UNK");
}

void print_type(uint8_t mask) {
    int first = 1;
    if (mask & THRT_TYPE_CTI)   { printf("%sCTI",   first ? "" : "+"); first = 0; }
    if (mask & THRT_TYPE_CTI_R) { printf("%sCTI_R", first ? "" : "+"); first = 0; }
    if (mask & THRT_TYPE_TAGS)  { printf("%sTAGS",  first ? "" : "+"); first = 0; }
    if (first) printf("(none)");
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <feed.thrt> <ioc_to_check>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    const char *key = argv[2];

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    struct stat sb;
    fstat(fd, &sb);
    void *map = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); return 1; }

    thrt_header_t *hdr = (thrt_header_t*)map;
    if (hdr->magic != THRT_MAGIC) { printf("Invalid Magic\n"); return 1; }
    if (hdr->version < THRT_VERSION) {
        printf("%s Database is v%d - v%d required. Rebuild with thrtutil.\n",
               ICON_FAIL, hdr->version, THRT_VERSION);
        return 1;
    }

    printf("%s %sDB Loaded:%s %s (v%d)\n", ICON_DB, COL_BOLD, COL_RESET, path, hdr->version);

    // Base Pointers
    thrt_metadata_t *meta_base = (thrt_metadata_t*)((char*)map + hdr->offset_metadata);
    thrt_ipv4_range_t *ip_table = (thrt_ipv4_range_t*)((char*)map + hdr->offset_ipv4);
    thrt_ipv6_range_t *ip6_table = (thrt_ipv6_range_t*)((char*)map + hdr->offset_ipv6);
    thrt_hash_entry_t *hash_table = (thrt_hash_entry_t*)((char*)map + hdr->offset_hashtable);
    char *str_pool = (char*)map + hdr->offset_strings;

    // V2 Pointers
    thrt_ip_accel_t *ip_accel = NULL;
    uint8_t *bloom_base = NULL;
    if (hdr->version >= 2) {
        ip_accel = (thrt_ip_accel_t*)((char*)map + hdr->offset_ip_accel);
        bloom_base = (uint8_t*)((char*)map + hdr->offset_bloom);
    }

    // Load V4 Feed Table
    if (hdr->version >= 4 && hdr->feed_count > 0 && hdr->offset_feeds > 0) {
        g_feeds = (thrt_feed_entry_t*)((char*)map + hdr->offset_feeds);
        g_feed_count = hdr->feed_count;
        printf("   Feeds Available: %u\n", g_feed_count);
    }

    // Logic
    thrt_metadata_t *res = NULL;
    struct in_addr addr;
    struct in6_addr addr6;

    printf("\nChecking: %s%s%s\n", COL_CYAN, key, COL_RESET);

    if (inet_pton(AF_INET, key, &addr)) {
        printf("[*] Type: IPv4\n");
        uint32_t ip = ntohl(addr.s_addr);

        if (ip_accel) {
            printf("[*] Using Acceleration Table\n");
            res = thrt_lookup_ip_accel(ip_table, ip_accel, meta_base, ip);
        } else {
            res = thrt_lookup_ip(ip_table, hdr->ipv4_range_count, meta_base, ip);
        }

    } else if (inet_pton(AF_INET6, key, &addr6)) {
        printf("[*] Type: IPv6\n");
        // Test Fast Parser logic implicitly via lookup
        res = thrt_lookup_ipv6(ip6_table, hdr->ipv6_range_count, meta_base, addr6.s6_addr);

    } else {
        printf("[*] Type: String\n");
        uint64_t hash = thrt_hash(key);
        //printf("[*] Hash: %" PRIx64 "\n", hash);

        if (bloom_base) {
            if (!thrt_bloom_check(bloom_base, hdr->bloom_size_bits, hash)) {
                printf("%s Bloom Filter: REJECTED%s\n", COL_RED, COL_RESET);
            } else {
                printf("%s Bloom Filter: PASSED%s\n", COL_GREEN, COL_RESET);
            }
        }

        res = thrt_lookup_string(hash_table, hdr->hash_slots, str_pool, meta_base, key);
    }

    if (res) {
        printf("\n%s>>> MATCH FOUND! <<<%s\n", ICON_WARN, COL_RESET);
        printf("   Confidence : %d%%\n", res->confidence);
        printf("   Type       : "); print_type(res->type_mask); printf("\n");
        printf("   TLP        : "); print_tlp(res->tlp_mask); printf("\n");
        printf("   Categories : "); print_categories(res->category_mask); printf("\n");
        printf("   Feeds      : "); print_feeds(res->feed_mask); printf("\n");

        if (res->tags_offset && res->tags_length && str_pool) {
            printf("   Tags       : %.*s\n", res->tags_length, str_pool + res->tags_offset);
        }
    } else {
        printf("\n%s NO MATCH.\n", ICON_OK);
    }

    return 0;
}
