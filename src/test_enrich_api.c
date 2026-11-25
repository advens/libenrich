/* test_enrich_api.c
 * The lookup API against the fixtures in testdata/api, built by `make test`
 * into build/api: the lookup policy, the public and restricted split, the
 * overlay value check, reload and reclamation, and refusal of bad files.
 *
 * Usage: test_enrich_api <build/api directory>
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0. See LICENSE.
 */
#include "enrich.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_fail;
static int g_checks;

#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        g_checks++;                                                                                                    \
        if (!(cond)) {                                                                                                 \
            g_fail++;                                                                                                  \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                            \
        }                                                                                                              \
    } while (0)

static char g_dir[512];

static const char *path_of(const char *name) {
    static char buf[4][768];
    static int k;
    char *p = buf[k++ & 3];
    snprintf(p, sizeof buf[0], "%s/%s", g_dir, name);
    return p;
}

static int copy_file(const char *src, const char *dst) {
    char buf[65536];
    ssize_t n;
    int in = open(src, O_RDONLY), out;
    if (in < 0) return -1;
    out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) {
        close(in);
        return -1;
    }
    while ((n = read(in, buf, sizeof buf)) > 0)
        if (write(out, buf, (size_t)n) != n) n = -1;
    close(in);
    close(out);
    return n < 0 ? -1 : 0;
}

/* Copy src to a temporary name and rename it over dst, as the builders do. */
static int replace_file(const char *src, const char *dst) {
    char tmp[sizeof g_dir + 300];
    int n = snprintf(tmp, sizeof tmp, "%s.tmp", dst);
    if (n < 0 || (size_t)n >= sizeof tmp) return -1;
    if (copy_file(src, tmp) != 0) return -1;
    return rename(tmp, dst);
}

static int lookup(const enrich_snap_t *s, uint32_t flags, const char *v, enrich_result_t *r) {
    return enrich_lookup(s, flags, v, strlen(v), r);
}

/* mask names exactly the feeds in the comma-separated list. */
static int feeds_are(const enrich_snap_t *s, uint64_t mask, const char *list) {
    int seen = 0, want = 1;
    for (const char *c = list; *c; c++) want += *c == ',';
    for (unsigned i = 0; i < 64; i++) {
        const char *name, *p;
        size_t n;
        int found = 0;
        if (!(mask & (1ULL << i))) continue;
        name = enrich_feed_name(s, i);
        if (name == NULL) return 0;
        n = strlen(name);
        for (p = list; *p; p += strcspn(p, ",") + (p[strcspn(p, ",")] == ',')) {
            if (strcspn(p, ",") == n && strncmp(p, name, n) == 0) found = 1;
        }
        if (!found) return 0;
        seen++;
    }
    return seen == want;
}

static int has_text(const char *p, uint32_t len, const char *needle) {
    size_t n = strlen(needle);
    if (p == NULL) return 0;
    for (uint32_t i = 0; i + n <= len; i++)
        if (memcmp(p + i, needle, n) == 0) return 1;
    return 0;
}

/* ------------------------------------------------------------------------
 * A value with the same CRC32C as a target, built by appending four bytes.
 * The CRC is affine over GF(2) in those 32 bits, so the bytes solve a
 * 32x32 linear system.
 * ------------------------------------------------------------------------ */
static uint32_t crc_of(const char *s, size_t n) {
    return crc32c_platform(0xFFFFFFFFu, s, n) ^ 0xFFFFFFFFu;
}

static int forge(const char *prefix, uint32_t target, char *out, size_t out_sz) {
    size_t pl = strlen(prefix);
    uint32_t col[32], base, want, rows[32], sol = 0;
    int piv[32];
    char buf[256];
    if (pl + 5 > sizeof buf || pl + 5 > out_sz) return -1;
    memcpy(buf, prefix, pl);
    memset(buf + pl, 0, 4);
    base = crc_of(buf, pl + 4);
    for (int b = 0; b < 32; b++) {
        memset(buf + pl, 0, 4);
        buf[pl + b / 8] = (char)(1u << (b % 8));
        col[b] = crc_of(buf, pl + 4) ^ base;
    }
    want = target ^ base;
    /* Rows of A (bit i of every column) with the right-hand side in bit 32. */
    for (int i = 0; i < 32; i++) {
        rows[i] = 0;
        for (int b = 0; b < 32; b++)
            if (col[b] >> i & 1u) rows[i] |= 1u << b;
    }
    {
        uint64_t aug[32];
        for (int i = 0; i < 32; i++) aug[i] = rows[i] | ((uint64_t)(want >> i & 1u) << 32);
        for (int c = 0, r = 0; c < 32; c++, r++) {
            int p = -1;
            for (int k = r; k < 32; k++)
                if (aug[k] >> c & 1u) {
                    p = k;
                    break;
                }
            if (p < 0) return -1;
            uint64_t t = aug[p];
            aug[p] = aug[r];
            aug[r] = t;
            for (int k = 0; k < 32; k++)
                if (k != r && (aug[k] >> c & 1u)) aug[k] ^= aug[r];
            piv[r] = c;
        }
        for (int r = 0; r < 32; r++)
            if (aug[r] >> 32 & 1u) sol |= 1u << piv[r];
    }
    memcpy(buf + pl, &sol, 4);
    for (int k = 0; k < 4; k++)
        if (buf[pl + k] == '\0') return -1;
    memcpy(out, buf, pl + 4);
    out[pl + 4] = '\0';
    return crc_of(out, pl + 4) == target ? 0 : -1;
}

/* ------------------------------------------------------------------------
 * A printable domain with a chosen CRC32C: the prefix, 40 letters each 'a'
 * or 'b', then ".example". For a fixed length the CRC is affine over GF(2)
 * in the a/b choices, so they solve a 32x40 linear system.
 * ------------------------------------------------------------------------ */
#define AB_LEN 40
static int forge_ab(const char *prefix, uint32_t target, char *out, size_t out_sz) {
    static const char tail[] = ".example";
    size_t pl = strlen(prefix), n = pl + AB_LEN + sizeof tail - 1;
    uint64_t aug[32] = {0};
    uint32_t base;
    int piv[32], r = 0;
    if (n + 1 > out_sz) return -1;
    memcpy(out, prefix, pl);
    memset(out + pl, 'a', AB_LEN);
    memcpy(out + pl + AB_LEN, tail, sizeof tail);
    base = crc_of(out, n);
    for (int j = 0; j < AB_LEN; j++) {
        uint32_t col;
        out[pl + j] = 'b';
        col = crc_of(out, n) ^ base;
        out[pl + j] = 'a';
        for (int i = 0; i < 32; i++)
            if (col >> i & 1u) aug[i] |= 1ULL << j;
    }
    for (int i = 0; i < 32; i++) aug[i] |= (uint64_t)((target ^ base) >> i & 1u) << AB_LEN;
    for (int c = 0; c < AB_LEN && r < 32; c++) {
        int p = -1;
        for (int k = r; k < 32; k++)
            if (aug[k] >> c & 1u) {
                p = k;
                break;
            }
        if (p < 0) continue;
        uint64_t t = aug[p];
        aug[p] = aug[r];
        aug[r] = t;
        for (int k = 0; k < 32; k++)
            if (k != r && (aug[k] >> c & 1u)) aug[k] ^= aug[r];
        piv[r++] = c;
    }
    for (int k = r; k < 32; k++)
        if (aug[k] >> AB_LEN & 1u) return -1;
    for (int k = 0; k < r; k++)
        if (aug[k] >> AB_LEN & 1u) out[pl + piv[k]] = 'b';
    return crc_of(out, n) == target ? 0 : -1;
}

/* A feed of n domains sharing the CRC32C of victim.example, then that
 * domain from another feed, as CSV on stdout. */
static int write_collisions(int n) {
    uint32_t target = crc_of("victim.example", 14);
    char v[128], prefix[32];
    for (int k = 0, made = 0; made < n && k < 100000; k++) {
        snprintf(prefix, sizeof prefix, "c%05d-", k);
        if (forge_ab(prefix, target, v, sizeof v) != 0) continue;
        printf("domain,%s,50,malware,crafted,green\n", v);
        made++;
    }
    printf("domain,victim.example,90,phishing,honest,green\n");
    return 0;
}

/* ------------------------------------------------------------------------
 * A small .prev written field by field.
 * ------------------------------------------------------------------------ */
static int write_prev(const char *path) {
    struct {
        prev_header_t h;
        prev_entry_t e[8];
    } f;
    uint64_t h;
    uint32_t idx;
    int fd;
    memset(&f, 0, sizeof f);
    f.h.magic = PREV_MAGIC;
    f.h.version = PREV_VERSION;
    f.h.total_size = sizeof f;
    f.h.hash_slots = 8;
    f.h.entry_count = 1;
    f.h.epoch = 1700000000u;
    f.h.offset_entries = sizeof f.h;
    f.h.count_max = 500;
    f.h.reporting_edges = 4;
    f.h.sip_key[0] = 0x243f6a8885a308d3ULL;
    f.h.sip_key[1] = 0x13198a2e03707344ULL;
    h = prev_hash(f.h.sip_key, "common.example");
    idx = (uint32_t)h & 7u;
    f.e[idx].hash_key = h;
    f.e[idx].total_count = 500;
    f.e[idx].edge_count = 3;
    f.e[idx].source_count = 40;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    if (write(fd, &f, sizeof f) != (ssize_t)sizeof f) {
        close(fd);
        return -1;
    }
    return close(fd);
}

/* ------------------------------------------------------------------------ */

static void test_policy(void) {
    enrich_options_t o = {sizeof o, path_of("threat.thrt"), path_of("site.ovly"), NULL, 0};
    enrich_t *e = NULL;
    enrich_reader_t *r;
    const enrich_snap_t *s;
    enrich_result_t res, res2;
    enrich_event_t ev;
    char err[256], forged[64], big[ENRICH_VALUE_MAX + 2];
    int rc;

    rc = enrich_open(&e, &o, err, sizeof err);
    CHECK(rc == ENRICH_OK);
    if (rc != ENRICH_OK) {
        fprintf(stderr, "open: %s\n", err);
        return;
    }
    r = enrich_reader_new(e);
    s = enrich_reader_enter(r);

    /* Public, restricted and tags layers on one address, plus a /24. */
    CHECK(lookup(s, 0, "198.51.100.10", &res) == 1);
    CHECK(res.kind == ENRICH_KIND_IPV4);
    CHECK(res.flags == (ENRICH_R_MATCH | ENRICH_R_THRT));
    CHECK(res.type_mask == (THRT_TYPE_CTI | THRT_TYPE_CTI_R | THRT_TYPE_TAGS));
    CHECK(res.confidence == 80);
    CHECK(res.confidence_r == 95);
    CHECK(res.tlp_mask == (THRT_TLP_GREEN | THRT_TLP_CLEAR));
    CHECK(res.category_mask == (THRT_CAT_SCANNER | THRT_CAT_ATTACK));
    CHECK(feeds_are(s, res.feed_mask, "pubfeed,labels.misp"));
    CHECK(has_text(res.tags, res.tags_len, "crown-jewel") && has_text(res.tags, res.tags_len, "dmz-edge"));
    CHECK(res.tags_len == strlen("[\"crown-jewel\",\"dmz-edge\"]"));
    /* MISP labels stay apart from the inventory tags. */
    CHECK(has_text(res.labels, res.labels_len, "misp-event:campaign-x"));
    CHECK(!has_text(res.tags, res.tags_len, "misp-event") && !has_text(res.labels, res.labels_len, "crown-jewel"));

    /* Restricted only: no public field, no feed name. Inside the /24. */
    CHECK(lookup(s, 0, "198.51.100.20", &res) == 1);
    CHECK(res.type_mask == (THRT_TYPE_CTI | THRT_TYPE_CTI_R));
    CHECK(res.confidence == 50 && res.confidence_r == 85);
    CHECK(res.tlp_mask == THRT_TLP_CLEAR);
    CHECK((res.category_mask & THRT_CAT_RANSOMWARE) == 0);
    CHECK(feeds_are(s, res.feed_mask, "pubfeed"));

    /* The /24 alone, either side of the /32s it contains. */
    CHECK(lookup(s, 0, "198.51.100.9", &res) == 1 && res.confidence == 50 && res.type_mask == THRT_TYPE_CTI);
    CHECK(lookup(s, 0, "198.51.100.255", &res) == 1 && res.confidence == 50);
    CHECK(lookup(s, 0, "198.51.101.0", &res) == 0);

    /* IPv6 inside a /48 that contains a /128. */
    CHECK(lookup(s, 0, "2001:db8::5", &res) == 1 && res.kind == ENRICH_KIND_IPV6 && res.confidence == 75);
    CHECK(lookup(s, 0, "2001:db8::6", &res) == 1 && res.confidence == 40);
    CHECK(lookup(s, 0, "2001:db8:1::", &res) == 0);

    /* Private address. */
    CHECK(lookup(s, 0, "10.1.2.3", &res) == 1);
    CHECK((res.flags & ENRICH_R_PRIVATE) && (res.flags & ENRICH_R_MATCH) && res.confidence >= 60);
    CHECK(lookup(s, ENRICH_OPT_SKIP_PRIVATE, "10.1.2.3", &res) == 1);
    CHECK(res.flags == (ENRICH_R_PRIVATE | ENRICH_R_PRIVATE_SKIP | ENRICH_R_THRT));
    CHECK(res.type_mask == 0 && res.confidence == 0 && res.feed_mask == 0);
    CHECK(has_text(res.tags, res.tags_len, "dmz"));
    CHECK(res.labels == NULL);
    CHECK(lookup(s, 0, "10.1.2.3", &res) == 1 && has_text(res.labels, res.labels_len, "campaign-y"));
    CHECK(lookup(s, ENRICH_OPT_SKIP_PRIVATE, "10.9.9.9", &res) == 0 && res.flags == ENRICH_R_PRIVATE);

    /* Strings. */
    CHECK(lookup(s, 0, "evil.example", &res) == 1 && res.kind == ENRICH_KIND_STRING);
    CHECK(res.confidence == 70 && res.tlp_mask == THRT_TLP_AMBER && res.category_mask == THRT_CAT_MALWARE);
    CHECK(lookup(s, 0, "evil.exampl", &res) == 0);
    CHECK(lookup(s, 0, "evil.example.", &res) == 0);
    CHECK(enrich_lookup(s, 0, "evil.example-and-more", 12, &res) == 1);

    /* Overlay. */
    CHECK(lookup(s, 0, "wl.example", &res) == 1);
    CHECK(res.flags == (ENRICH_R_OVERLAY | ENRICH_R_SUPPRESSED) && res.type_mask == 0);
    CHECK(lookup(s, 0, "soft.example", &res) == 1);
    CHECK((res.flags & ENRICH_R_WHITELISTED) && (res.flags & ENRICH_R_MATCH) && res.confidence == 65);
    CHECK(lookup(s, 0, "add.example", &res) == 1);
    CHECK(res.flags == (ENRICH_R_OVERLAY | ENRICH_R_MATCH) && res.ovl_confidence == 70);
    CHECK(res.ovl_category_mask == THRT_CAT_MALWARE && res.type_mask == 0);
    CHECK(lookup(s, 0, "tag.example", &res) == 1);
    CHECK(has_text(res.overlay_tags, res.overlay_tags_len, "owner:it") && !(res.flags & ENRICH_R_MATCH));

    /* A different value with the same CRC32C as a whitelisted one misses. */
    rc = -1;
    for (int k = 0; k < 64 && rc != 0; k++) {
        char prefix[32];
        snprintf(prefix, sizeof prefix, "forged-%d-", k);
        rc = forge(prefix, crc_of("wl.example", 10), forged, sizeof forged);
    }
    CHECK(rc == 0);
    CHECK(thrt_hash(forged) == thrt_hash("wl.example"));
    CHECK(lookup(s, 0, forged, &res) == 0 && res.flags == 0);

    /* The address reading, the same as the builder's on every platform. */
    {
        static const struct {
            const char *v;
            int kind;
        } cases[] = {
            {"0.0.0.0", ENRICH_KIND_IPV4},       {"255.255.255.255", ENRICH_KIND_IPV4},
            {"1.2.3.4", ENRICH_KIND_IPV4},       {"01.2.3.4", ENRICH_KIND_STRING},
            {"1.2.3", ENRICH_KIND_STRING},       {"1.2.3.4.5", ENRICH_KIND_STRING},
            {"256.1.1.1", ENRICH_KIND_STRING},   {"1..2.3", ENRICH_KIND_STRING},
            {".1.2.3", ENRICH_KIND_STRING},      {"1.2.3.", ENRICH_KIND_STRING},
            {"1.2.3.4 ", ENRICH_KIND_STRING},    {"1.2.3.a", ENRICH_KIND_STRING},
            {"::1", ENRICH_KIND_IPV6},           {"::ffff:1.2.3.4", ENRICH_KIND_IPV6},
            {"2001:db8::5", ENRICH_KIND_IPV6},   {"2001:db8:::5", ENRICH_KIND_STRING},
            {"abcd", ENRICH_KIND_STRING},        {"fe80::1%en0", ENRICH_KIND_STRING},
            {"2001:DB8::5", ENRICH_KIND_IPV6},
        };
        int agree = 1;
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            parsed_ip_t ip;
            int built = parse_ip_or_cidr(cases[i].v, 1, &ip) ? (ip.family == 4 ? ENRICH_KIND_IPV4 : ENRICH_KIND_IPV6)
                                                             : ENRICH_KIND_STRING;
            lookup(s, 0, cases[i].v, &res);
            if (res.kind != cases[i].kind || built != cases[i].kind) {
                fprintf(stderr, "kind of '%s': lookup %d, builder %d, want %d\n", cases[i].v, res.kind, built,
                        cases[i].kind);
                agree = 0;
            }
        }
        CHECK(agree);
        CHECK(lookup(s, 0, "2001:DB8::5", &res) == 1 && res.confidence == 75);
    }

    /* Bounds. */
    memset(big, 'a', sizeof big);
    CHECK(enrich_lookup(s, 0, big, ENRICH_VALUE_MAX, &res) == 0);
    CHECK(enrich_lookup(s, 0, big, ENRICH_VALUE_MAX + 1, &res) == ENRICH_ETOOLONG);
    CHECK(enrich_lookup(s, 0, "evil\0.example", 13, &res) == ENRICH_EINVAL);
    CHECK(enrich_lookup(s, 0, "x", 0, &res) == ENRICH_EINVAL);
    CHECK(enrich_lookup(s, 0, NULL, 3, &res) == ENRICH_EINVAL);

    /* Batch gives the same answers as one by one. */
    {
        static const char *vals[] = {"198.51.100.10", "evil.example", "wl.example", "nothing.example",
                                     "10.1.2.3",      "2001:db8::5", "add.example", "tag.example"};
        enum { N = sizeof vals / sizeof vals[0] };
        enrich_value_t v[N];
        enrich_result_t out[N];
        int st[N];
        size_t hits, want = 0;
        int same = 1;
        for (int i = 0; i < N; i++) v[i] = (enrich_value_t){vals[i], strlen(vals[i])};
        hits = enrich_lookup_batch(s, ENRICH_OPT_SKIP_PRIVATE, v, N, out, st);
        for (int i = 0; i < N; i++) {
            int one = lookup(s, ENRICH_OPT_SKIP_PRIVATE, vals[i], &res2);
            if (one == 1) want++;
            if (one != st[i] || memcmp(&res2, &out[i], sizeof res2) != 0) same = 0;
        }
        CHECK(same);
        CHECK(hits == want && hits == 7);
    }

    /* Across chunks, with misses and refused values between the hits. */
    {
        static const char *hit[] = {"198.51.100.10", "evil.example", "wl.example", "10.1.2.3",
                                    "2001:db8::5",   "add.example",  "tag.example"};
        enum { N = 200 };
        static char miss[N][32];
        enrich_value_t v[N];
        enrich_result_t out[N];
        int st[N];
        size_t hits, want = 0;
        int same = 1;
        for (int i = 0; i < N; i++) {
            const char *h = hit[(i / 9) % 7];
            switch (i % 9) {
            case 0:
            case 3:
            case 5:
                v[i] = (enrich_value_t){h, strlen(h)};
                break;
            case 7:
                v[i] = i % 2 ? (enrich_value_t){big, ENRICH_VALUE_MAX + 1} : (enrich_value_t){"evil\0.example", 13};
                break;
            case 8:
                v[i] = (enrich_value_t){NULL, 3};
                break;
            default:
                snprintf(miss[i], sizeof miss[i], "miss-%d.example", i);
                v[i] = (enrich_value_t){miss[i], strlen(miss[i])};
            }
        }
        hits = enrich_lookup_batch(s, ENRICH_OPT_SKIP_PRIVATE, v, N, out, st);
        for (int i = 0; i < N; i++) {
            int one = enrich_lookup(s, ENRICH_OPT_SKIP_PRIVATE, v[i].value, v[i].len, &res2);
            if (one == 1) want++;
            if (one != st[i] || memcmp(&res2, &out[i], sizeof res2) != 0) {
                fprintf(stderr, "batch differs at %d: %d, one by one %d\n", i, st[i], one);
                same = 0;
            }
        }
        CHECK(same);
        CHECK(hits == want && hits > 60);
    }

    /* Event fold. */
    memset(&ev, 0, sizeof ev);
    lookup(s, 0, "198.51.100.10", &res);
    enrich_event_fold(&ev, &res);
    lookup(s, 0, "add.example", &res);
    enrich_event_fold(&ev, &res);
    CHECK(ev.match == 1 && ev.whitelisted == 0);
    CHECK(ev.confidence == 95);
    CHECK(ev.category_mask == (THRT_CAT_SCANNER | THRT_CAT_ATTACK | THRT_CAT_MALWARE));
    CHECK(feeds_are(s, ev.feed_mask, "pubfeed,labels.misp"));

    /* Names. */
    CHECK(strcmp(enrich_category_name(THRT_CAT_C2), "c2") == 0);
    CHECK(enrich_category_name(0x8000) == NULL);
    CHECK(strcmp(enrich_tlp_strictest(THRT_TLP_GREEN | THRT_TLP_AMBER), "amber") == 0);
    CHECK(enrich_feed_name(s, 63) == NULL);

    enrich_reader_free(r);
    enrich_close(e);
}

/* build/api/fold.thrt is the same feeds, then a fold that withdraws the
 * /24. The /32s inside it came from other rows and stay. */
static void test_fold_withdraw(void) {
    enrich_options_t o = {sizeof o, path_of("fold.thrt"), NULL, NULL, 0};
    enrich_t *e = NULL;
    enrich_reader_t *r;
    const enrich_snap_t *s;
    enrich_result_t res;
    char err[256];
    CHECK(enrich_open(&e, &o, err, sizeof err) == ENRICH_OK);
    if (e == NULL) return;
    r = enrich_reader_new(e);
    s = enrich_reader_enter(r);
    CHECK(lookup(s, 0, "198.51.100.9", &res) == 0);
    CHECK(lookup(s, 0, "198.51.100.255", &res) == 0);
    CHECK(lookup(s, 0, "198.51.100.10", &res) == 1 && res.confidence == 80 && res.confidence_r == 95);
    CHECK(res.tlp_mask == THRT_TLP_GREEN);
    CHECK(lookup(s, 0, "198.51.100.20", &res) == 1 && res.type_mask == THRT_TYPE_CTI_R && res.confidence == 0);
    CHECK(lookup(s, 0, "2001:db8::6", &res) == 1 && res.confidence == 40);
    enrich_reader_free(r);
    enrich_close(e);
}

static void test_prev_and_partial(void) {
    char prev[800], err[256];
    enrich_options_t o;
    enrich_t *e = NULL;
    enrich_reader_t *r;
    const enrich_snap_t *s;
    enrich_prev_t pv;
    enrich_info_t info;
    unsigned changed = 0;
    int rc;

    snprintf(prev, sizeof prev, "%s", path_of("site.prev"));
    unlink(prev);
    o = (enrich_options_t){sizeof o, path_of("threat.thrt"), NULL, prev, 0};

    /* Missing .prev: refused without PARTIAL, accepted with it. */
    CHECK(enrich_open(&e, &o, err, sizeof err) == ENRICH_ENOENT && e == NULL);
    o.flags = ENRICH_OPT_PARTIAL;
    rc = enrich_open(&e, &o, err, sizeof err);
    CHECK(rc == ENRICH_ENOENT && e != NULL);
    if (e == NULL) return;
    r = enrich_reader_new(e);
    s = enrich_reader_enter(r);
    CHECK(enrich_prevalence(s, "common.example", 14, &pv) == 0);
    enrich_snap_info(s, &info);
    CHECK(info.components == ENRICH_C_THRT && info.thrt_version == THRT_VERSION);

    CHECK(write_prev(prev) == 0);
    CHECK(enrich_reload(e, &changed, err, sizeof err) == ENRICH_OK && changed == ENRICH_C_PREV);
    s = enrich_reader_enter(r);
    CHECK(enrich_prevalence(s, "common.example", 14, &pv) == 1);
    CHECK(pv.count == 500 && pv.edges == 3 && pv.sources == 40);
    CHECK(enrich_prevalence(s, "rare.example", 12, &pv) == 1 && pv.count == 0);
    CHECK(enrich_prev_reporting_edges(s) == 4);
    /* Nothing changed: no new snapshot. */
    CHECK(enrich_reload(e, &changed, err, sizeof err) == ENRICH_OK && changed == 0);
    CHECK(enrich_reader_enter(r) == s);

    enrich_reader_free(r);
    enrich_close(e);

    /* A prevalence table alone, as a rule engine opens it. */
    o = (enrich_options_t){sizeof o, NULL, NULL, prev, 0};
    CHECK(enrich_open(&e, &o, err, sizeof err) == ENRICH_OK);
    if (e != NULL) {
        enrich_result_t res;
        r = enrich_reader_new(e);
        s = enrich_reader_enter(r);
        CHECK(enrich_prevalence(s, "common.example", 14, &pv) == 1 && pv.count == 500);
        CHECK(enrich_lookup(s, 0, "198.51.100.10", 13, &res) == 0);
        enrich_reader_free(r);
        enrich_close(e);
    }
    o = (enrich_options_t){sizeof o, NULL, NULL, NULL, 0};
    CHECK(enrich_open(&e, &o, err, sizeof err) == ENRICH_EINVAL);
    unlink(prev);
}

/* Write a copy of src with one change, recomputing the .thrt CRC when asked. */
static int corrupt_copy(const char *src, const char *dst, size_t off, uint32_t val, int fix_crc) {
    FILE *f;
    long n;
    unsigned char *b;
    if (copy_file(src, dst) != 0) return -1;
    f = fopen(dst, "r+b");
    if (f == NULL) return -1;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    b = malloc((size_t)n);
    fseek(f, 0, SEEK_SET);
    if (b == NULL || fread(b, 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        free(b);
        return -1;
    }
    memcpy(b + off, &val, 4);
    if (fix_crc) {
        thrt_header_t *h = (thrt_header_t *)(void *)b;
        uint32_t co = h->checksum_offset, crc;
        crc = crc32c_platform(0xFFFFFFFFu, b, co);
        crc = crc32c_platform(crc, b + co + 4, (size_t)n - co - 4) ^ 0xFFFFFFFFu;
        h->checksum = crc;
    }
    fseek(f, 0, SEEK_SET);
    fwrite(b, 1, (size_t)n, f);
    fclose(f);
    free(b);
    return 0;
}

static void test_bad_files(void) {
    char bad[800], err[256];
    enrich_options_t o;
    enrich_t *e = NULL;
    thrt_header_t h;
    FILE *f;

    snprintf(bad, sizeof bad, "%s", path_of("bad.thrt"));
    f = fopen(path_of("threat.thrt"), "rb");
    CHECK(f != NULL && fread(&h, sizeof h, 1, f) == 1);
    if (f) fclose(f);
    o = (enrich_options_t){sizeof o, bad, NULL, NULL, 0};

    /* A flipped byte in the middle. */
    CHECK(corrupt_copy(path_of("threat.thrt"), bad, (size_t)h.offset_strings + 8, 0x41414141u, 0) == 0);
    CHECK(enrich_open(&e, &o, err, sizeof err) == ENRICH_ECHECKSUM && e == NULL);
    /* An index out of its table, with a valid CRC. */
    CHECK(corrupt_copy(path_of("threat.thrt"), bad, (size_t)h.offset_ipv4 + 8, 0x7FFFFFFFu, 1) == 0);
    CHECK(enrich_open(&e, &o, err, sizeof err) == ENRICH_EFORMAT && e == NULL);
    /* A bloom filter size the readers cannot mask, with a valid CRC. */
    CHECK(corrupt_copy(path_of("threat.thrt"), bad, offsetof(thrt_header_t, bloom_size_bits), 3000000u, 1) == 0);
    CHECK(enrich_open(&e, &o, err, sizeof err) == ENRICH_EFORMAT && e == NULL);
    /* Another version. */
    CHECK(corrupt_copy(path_of("threat.thrt"), bad, 4, 4, 1) == 0);
    CHECK(enrich_open(&e, &o, err, sizeof err) == ENRICH_EVERSION && e == NULL);
    /* Truncated. */
    CHECK(copy_file(path_of("threat.thrt"), bad) == 0 && truncate(bad, (off_t)h.total_size - 100) == 0);
    CHECK(enrich_open(&e, &o, err, sizeof err) == ENRICH_EFORMAT && e == NULL);
    /* A version 1 overlay header. */
    {
        char ov[800];
        snprintf(ov, sizeof ov, "%s", path_of("bad.ovly"));
        CHECK(copy_file(path_of("site.ovly"), ov) == 0);
        f = fopen(ov, "r+b");
        if (f) {
            uint32_t v1 = 1;
            fseek(f, 4, SEEK_SET);
            fwrite(&v1, 4, 1, f);
            fclose(f);
        }
        o = (enrich_options_t){sizeof o, path_of("threat.thrt"), ov, NULL, 0};
        CHECK(enrich_open(&e, &o, err, sizeof err) == ENRICH_EVERSION && e == NULL);
        unlink(ov);
    }
    /* A .prev of another version is refused, and the message names it. */
    {
        char pv[800];
        prev_header_t ph;
        memset(&ph, 0, sizeof ph);
        ph.magic = PREV_MAGIC;
        ph.version = 2;
        snprintf(pv, sizeof pv, "%s", path_of("old.prev"));
        f = fopen(pv, "wb");
        if (f) {
            fwrite(&ph, sizeof ph, 1, f);
            fclose(f);
        }
        o = (enrich_options_t){sizeof o, NULL, NULL, pv, 0};
        CHECK(enrich_open(&e, &o, err, sizeof err) == ENRICH_EVERSION && e == NULL);
        CHECK(strstr(err, ".prev version 2") != NULL);
        unlink(pv);
    }
    unlink(bad);
}

/* ------------------------------------------------------------------------
 * Reload under load: reader threads look up while the main thread swaps
 * two databases. Under AddressSanitizer a snapshot freed too early is a
 * use-after-free.
 * ------------------------------------------------------------------------ */
typedef struct {
    enrich_t *e;
    atomic_int *stop;
    long lookups;
    int wrong;
} worker_t;

static void *worker(void *arg) {
    worker_t *w = (worker_t *)arg;
    enrich_reader_t *r = enrich_reader_new(w->e);
    enrich_result_t res;
    long n = 0;
    if (r == NULL) {
        w->wrong++;
        return NULL;
    }
    while (!atomic_load(w->stop)) {
        const enrich_snap_t *s = enrich_reader_enter(r);
        enrich_info_t info;
        int a, b;
        enrich_snap_info(s, &info);
        a = lookup(s, 0, "198.51.100.10", &res);
        b = lookup(s, 0, "203.0.113.30", &res);
        /* Exactly one of the two databases is visible in one snapshot. */
        if (a + b != 1) w->wrong++;
        if (++n % 64 == 0) enrich_reader_leave(r);
    }
    w->lookups = n;
    enrich_reader_free(r);
    return NULL;
}

static void test_reload_under_load(void) {
    char live[800], err[256];
    enrich_options_t o;
    enrich_t *e = NULL;
    enrich_reader_t *pin;
    const enrich_snap_t *old, *cur;
    enrich_result_t res;
    pthread_t th[4];
    worker_t w[4];
    atomic_int stop;
    unsigned changed;
    int swaps = 0;

    snprintf(live, sizeof live, "%s", path_of("live.thrt"));
    CHECK(replace_file(path_of("threat.thrt"), live) == 0);
    o = (enrich_options_t){sizeof o, live, NULL, NULL, 0};
    CHECK(enrich_open(&e, &o, err, sizeof err) == ENRICH_OK);
    if (e == NULL) return;

    /* A pinned reader keeps its snapshot through a reload and a reclaim. */
    pin = enrich_reader_new(e);
    old = enrich_reader_enter(pin);
    CHECK(replace_file(path_of("second.thrt"), live) == 0);
    CHECK(enrich_reload(e, &changed, err, sizeof err) == ENRICH_OK && changed == ENRICH_C_THRT);
    enrich_reclaim(e);
    CHECK(lookup(old, 0, "198.51.100.10", &res) == 1);
    {
        enrich_reader_t *other = enrich_reader_new(e);
        cur = enrich_reader_enter(other);
        CHECK(cur != old);
        CHECK(lookup(cur, 0, "198.51.100.10", &res) == 0 && lookup(cur, 0, "203.0.113.30", &res) == 1);
        enrich_reader_free(other);
    }
    enrich_reader_free(pin);

    atomic_init(&stop, 0);
    for (int i = 0; i < 4; i++) {
        w[i] = (worker_t){e, &stop, 0, 0};
        pthread_create(&th[i], NULL, worker, &w[i]);
    }
    for (int k = 0; k < 200; k++) {
        const char *src = (k & 1) ? path_of("second.thrt") : path_of("threat.thrt");
        if (replace_file(src, live) != 0) break;
        if (enrich_reload(e, &changed, err, sizeof err) == ENRICH_OK && changed) swaps++;
    }
    atomic_store(&stop, 1);
    for (int i = 0; i < 4; i++) {
        pthread_join(th[i], NULL);
        CHECK(w[i].wrong == 0);
        CHECK(w[i].lookups > 0);
    }
    CHECK(swaps == 200);
    enrich_close(e);
    unlink(live);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--collide") == 0) return write_collisions(atoi(argv[2]));
    if (argc < 2) {
        fprintf(stderr, "usage: %s <build/api directory> | --collide <n>\n", argv[0]);
        return 2;
    }
    snprintf(g_dir, sizeof g_dir, "%s", argv[1]);
    test_policy();
    test_fold_withdraw();
    test_prev_and_partial();
    test_bad_files();
    test_reload_under_load();
    printf("test_enrich_api: %d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
