/* thrt_cli.c
 * `enrich lookup`: look one indicator up in a .thrt through the library
 * lookup API, so the command prints what an enricher would emit.
 *
 * Usage:   enrich lookup <indicator>  (thrt_cli_main <db_file> <indicator>)
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
#include <string.h>
#include "enrich.h"

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

static void print_categories(uint16_t mask) {
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

static void print_feeds(const enrich_snap_t *s, uint64_t mask) {
    int first = 1;
    for (unsigned i = 0; i < 64; i++) {
        const char *name;
        if (!(mask & (1ULL << i))) continue;
        name = enrich_feed_name(s, i);
        if (name == NULL) continue;
        printf("%s%s", first ? "" : ", ", name);
        first = 0;
    }
    if (first) printf("(none)");
}

static void print_tlp(uint8_t mask) {
    int first = 1;
    if (mask & THRT_TLP_CLEAR) { printf("%s%sWHITE%s", first ? "" : ", ", COL_WHITE, COL_RESET); first = 0; }
    if (mask & THRT_TLP_GREEN) { printf("%s%sGREEN%s", first ? "" : ", ", COL_GREEN, COL_RESET); first = 0; }
    if (mask & THRT_TLP_AMBER) { printf("%s%sAMBER%s", first ? "" : ", ", COL_ORANGE, COL_RESET); first = 0; }
    if (mask & THRT_TLP_RED)   { printf("%s%sRED%s",   first ? "" : ", ", COL_RED, COL_RESET);   first = 0; }
    if (first) printf("UNK");
}

static void print_type(uint8_t mask) {
    int first = 1;
    if (mask & THRT_TYPE_CTI)   { printf("%sCTI",   first ? "" : "+"); first = 0; }
    if (mask & THRT_TYPE_CTI_R) { printf("%sCTI_R", first ? "" : "+"); first = 0; }
    if (mask & THRT_TYPE_TAGS)  { printf("%sTAGS",  first ? "" : "+"); first = 0; }
    if (first) printf("(none)");
}

int main(int argc, char **argv) {
    enrich_options_t opt;
    enrich_t *e = NULL;
    enrich_reader_t *r;
    const enrich_snap_t *snap;
    enrich_result_t res;
    enrich_info_t info;
    char err[512];
    const char *key;
    int rc;
    static const char *kinds[] = {"String", "IPv4", "IPv6"};

    if (argc < 3) {
        printf("Usage: %s <feed.thrt> <ioc_to_check>\n", argv[0]);
        return 1;
    }
    key = argv[2];

    memset(&opt, 0, sizeof opt);
    opt.size = sizeof opt;
    opt.thrt_path = argv[1];
    rc = enrich_open(&e, &opt, err, sizeof err);
    if (rc != ENRICH_OK) {
        printf("%s %s\n", ICON_FAIL, err[0] ? err : enrich_strerror(rc));
        return 1;
    }
    r = enrich_reader_new(e);
    if (r == NULL) {
        printf("%s out of memory\n", ICON_FAIL);
        enrich_close(e);
        return 1;
    }
    snap = enrich_reader_enter(r);
    enrich_snap_info(snap, &info);
    printf("%s %sDB Loaded:%s %s (v%u)\n", ICON_DB, COL_BOLD, COL_RESET, argv[1], info.thrt_version);
    if (info.thrt_feeds > 0) printf("   Feeds Available: %u\n", info.thrt_feeds);

    printf("\nChecking: %s%s%s\n", COL_CYAN, key, COL_RESET);
    rc = enrich_lookup(snap, 0, key, strlen(key), &res);
    if (rc < 0) {
        printf("%s %s\n", ICON_FAIL, enrich_strerror(rc));
        enrich_reader_free(r);
        enrich_close(e);
        return 1;
    }
    printf("[*] Type: %s\n", kinds[res.kind <= ENRICH_KIND_IPV6 ? res.kind : 0]);

    if (res.flags & ENRICH_R_THRT) {
        printf("\n%s>>> MATCH FOUND! <<<%s\n", ICON_WARN, COL_RESET);
        if (res.type_mask & THRT_TYPE_CTI) printf("   Confidence : %d%%\n", res.confidence);
        if (res.type_mask & THRT_TYPE_CTI_R) printf("   Restricted : confidence %d%%\n", res.confidence_r);
        printf("   Type       : "); print_type(res.type_mask); printf("\n");
        if (res.type_mask & THRT_TYPE_CTI) {
            printf("   TLP        : "); print_tlp(res.tlp_mask); printf("\n");
            printf("   Categories : "); print_categories(res.category_mask); printf("\n");
            printf("   Feeds      : "); print_feeds(snap, res.feed_mask); printf("\n");
        }
        if (res.labels != NULL) printf("   Labels     : %.*s\n", (int)res.labels_len, res.labels);
        if (res.tags != NULL) printf("   Tags       : %.*s\n", (int)res.tags_len, res.tags);
    } else {
        printf("\n%s NO MATCH.\n", ICON_OK);
    }

    enrich_reader_free(r);
    enrich_close(e);
    return 0;
}
