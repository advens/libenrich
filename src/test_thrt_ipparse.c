/* test_thrt_ipparse.c — the CTI range parser must never widen an indicator.
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0.
 *
 * The regression this pins: 91 scheme-less URL indicators in a subscribed MISP
 * feed ("103.117.72.60/ptj" and friends) each produced a 0.0.0.0/0 range,
 * because the prefix was read with atoi() and any non-numeric suffix silently
 * became prefix 0. Every IPv4 address then matched CTI at confidence 70. The
 * sample values below are verbatim from that feed.
 *
 * Build: make -f Makefile.dev test-ipparse
 */

#include <stdio.h>
#include <string.h>

#include "thrt_ipparse.h"

static int failures;

static void check(int cond, const char* what) {
    if (!cond) {
        printf("  FAIL %s\n", what);
        failures++;
    }
}

/* A value must not parse as an address range at all. */
static void reject(const char* value, int allow_cidr) {
    parsed_ip_t ip;
    if (parse_ip_or_cidr(value, allow_cidr, &ip)) {
        unsigned long long span = (unsigned long long)ip.v4_end - ip.v4_start + 1;
        printf("  FAIL %-42s parsed as a range (family=%d, %llu addrs)\n", value, ip.family, span);
        failures++;
    }
}

/* A value must parse to exactly [start, end]. */
static void accept_v4(const char* value, uint32_t start, uint32_t end) {
    parsed_ip_t ip;
    if (!parse_ip_or_cidr(value, 1, &ip)) {
        printf("  FAIL %-42s rejected, expected a v4 range\n", value);
        failures++;
        return;
    }
    if (ip.family != 4 || ip.v4_start != start || ip.v4_end != end) {
        printf("  FAIL %-42s got %u-%u, want %u-%u\n", value, ip.v4_start, ip.v4_end, start, end);
        failures++;
    }
}

/* The parser before 1.1.2: a character filter, then the libc. The native
 * thrt_ipv6_strict must accept and reject exactly what it did and produce
 * the same 16 bytes. */
static int ref_ipv6(const char* s, size_t len, uint8_t out[16]) {
    char buf[46];
    struct in6_addr a6;
    int colon = 0;
    if (len == 0 || len >= sizeof buf) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == ':')
            colon = 1;
        else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.'))
            return 0;
    }
    if (!colon) return 0;
    memcpy(buf, s, len);
    buf[len] = '\0';
    if (inet_pton(AF_INET6, buf, &a6) != 1) return 0;
    memcpy(out, a6.s6_addr, 16);
    return 1;
}

/* An octet of the dotted part written with a leading zero ("01"). macOS
 * inet_pton takes it; glibc, FreeBSD and thrt_ipv4_strict do not. */
static int dotted_leading_zero(const char* s, size_t len) {
    const char* dot = memchr(s, '.', len);
    const char* p;
    if (dot == NULL) return 0;
    p = dot;
    while (p > s && p[-1] != ':') p--;
    for (; p < s + len; p++) {
        int start = (p == s || p[-1] == ':' || p[-1] == '.');
        if (start && p[0] == '0' && p + 1 < s + len && p[1] >= '0' && p[1] <= '9') return 1;
    }
    return 0;
}

/* A hex group of more than four digits ("014c3"). macOS inet_pton takes it
 * when the extra digits are leading zeros; glibc and FreeBSD do not. */
static int group_over_four(const char* s, size_t len) {
    int n = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            if (++n > 4) return 1;
        } else {
            n = 0;
        }
    }
    return 0;
}

static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;
static uint32_t rnd(uint32_t n) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state % n);
}

/* A valid IPv6 text: eight groups, a run of zero groups maybe written as
 * "::", maybe a dotted IPv4 in the last two, random case. */
static size_t gen_valid(char* out, size_t cap) {
    static const char hex[] = "0123456789abcdef";
    unsigned g[8];
    int dotted = rnd(4) == 0, ngroups = dotted ? 6 : 8, zs = -1, zl = 0;
    size_t n = 0;
    for (int i = 0; i < ngroups; i++) g[i] = rnd(3) == 0 ? 0 : rnd(0x10000) >> rnd(13);
    if (rnd(3) != 0) {
        zs = (int)rnd((uint32_t)ngroups);
        zl = 1 + (int)rnd((uint32_t)(ngroups - zs));
        for (int i = zs; i < zs + zl; i++) g[i] = 0;
    }
    for (int i = 0; i < ngroups; i++) {
        if (i == zs) {
            n += (size_t)snprintf(out + n, cap - n, i == 0 ? "::" : ":");
            i += zl - 1;
            continue;
        }
        if (i > 0 && !(zs >= 0 && i == zs + zl)) out[n++] = ':';
        {
            char tmp[8];
            int k = 0, lead = (int)rnd(2);
            unsigned v = g[i];
            do {
                tmp[k++] = hex[v & 15];
                v >>= 4;
            } while (v);
            while (lead-- > 0 && k < 4) tmp[k++] = '0';
            while (k > 0) {
                char c = tmp[--k];
                out[n++] = (rnd(2) && c >= 'a') ? (char)(c - 32) : c;
            }
        }
    }
    if (dotted) {
        if (!(zs >= 0 && zs + zl == ngroups)) out[n++] = ':';
        n += (size_t)snprintf(out + n, cap - n, "%u.%u.%u.%u", rnd(256), rnd(256), rnd(256), rnd(256));
    }
    out[n] = '\0';
    return n;
}

static void test_ipv6_differential(void) {
    static const char alpha[] = "0123456789abcdefABCDEF::::....%xg ";
    char s[96];
    long cases = 0, accepted = 0, tolerated = 0;
    for (int it = 0; it < 3000000; it++) {
        size_t len;
        uint8_t a[16], b[16];
        int ra, rb, kind = it % 3;
        if (kind == 2) {
            len = rnd(48);
            for (size_t i = 0; i < len; i++) s[i] = alpha[rnd(sizeof alpha - 1)];
            s[len] = '\0';
        } else {
            len = gen_valid(s, sizeof s);
            if (kind == 1) {
                int edits = 1 + (int)rnd(3);
                while (edits-- > 0) {
                    size_t at = len ? rnd((uint32_t)len) : 0;
                    switch (rnd(4)) {
                    case 0:
                        if (len + 1 < sizeof s) {
                            memmove(s + at + 1, s + at, len - at + 1);
                            s[at] = alpha[rnd(sizeof alpha - 1)];
                            len++;
                        }
                        break;
                    case 1:
                        if (len) {
                            memmove(s + at, s + at + 1, len - at);
                            len--;
                        }
                        break;
                    case 2:
                        if (len) s[at] = alpha[rnd(sizeof alpha - 1)];
                        break;
                    default:
                        if (len + 1 < sizeof s) {
                            memmove(s + at + 1, s + at, len - at + 1);
                            s[at] = ':';
                            len++;
                        }
                    }
                }
            }
        }
        cases++;
        ra = thrt_ipv6_strict(s, len, a);
        rb = ref_ipv6(s, len, b);
        accepted += ra;
        if (ra == rb && (!ra || memcmp(a, b, 16) == 0)) continue;
        if (!ra && rb && (dotted_leading_zero(s, len) || group_over_four(s, len))) {
            tolerated++;
            continue;
        }
        if (failures < 20)
            printf("  FAIL ipv6 \"%s\": native %d, libc %d%s\n", s, ra, rb,
                   ra && rb ? " (bytes differ)" : "");
        failures++;
    }
    printf("ipv6 differential: %ld cases, %ld accepted, %ld leading-zero forms refused only by the native parser\n",
           cases, accepted, tolerated);
}

#define V4(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))

int main(void) {
    test_ipv6_differential();
    const char* poison[] = {
        "103.117.72.60/ptj",
        "185.70.186.145/gate.php",
        "104.152.187.66/updates/",
        "178.62.227.13/wrgjwrgjwrg246356356356/hnios2",
        "129.226.15.142/pixel.gif",
        "123.51.185.75/jquery-3.3.1.slim.min.js",
        "162.241.127.180/j.ad",
        "146.0.72.180/3307/", /* digit-leading path, atoi() gave 3307 */
        "177.21.75.140/456/activex.exe",
        "1.2.3.4/", /* empty suffix, atoi() gave 0 */
        "1.2.3.4/ 8", /* leading space */
        "1.2.3.4/8bit.exe", /* atoi() gave 8 -> a /8 */
        "1.2.3.4/+8",
        "1.2.3.4/-1",
        "1.2.3.4/0x10",
        "1.2.3.4/33", /* out of range for v4 */
    };
    parsed_ip_t ip6;
    parsed_ip_t ip;
    printf("thrt_ipparse regression\n");

    /* 1. The exact feed values that poisoned the database. Every one of these
     *    previously became 0.0.0.0/0. */
    printf("scheme-less URL indicators must never become networks\n");
    for (size_t i = 0; i < sizeof(poison) / sizeof(*poison); i++) reject(poison[i], 1);

    /* 2. The wildcard guard: even a syntactically valid prefix must not blanket
     *    the address space. Defence in depth behind the strict parse. */
    printf("over-broad prefixes must be rejected\n");
    reject("0.0.0.0/0", 1);
    reject("1.2.3.4/0", 1);
    reject("10.0.0.0/1", 1);
    reject("10.0.0.0/7", 1);
    reject("::/0", 1);
    reject("2001:db8::/16", 1);

    /* 3. Real blocklist netblocks must still land, unchanged. */
    printf("legitimate netblocks must still parse\n");
    accept_v4("10.0.0.0/8", V4(10, 0, 0, 0), V4(10, 255, 255, 255));
    accept_v4("192.168.1.0/24", V4(192, 168, 1, 0), V4(192, 168, 1, 255));
    accept_v4("172.16.0.0/12", V4(172, 16, 0, 0), V4(172, 31, 255, 255));
    accept_v4("203.0.113.7", V4(203, 0, 113, 7), V4(203, 0, 113, 7));
    accept_v4("203.0.113.7/32", V4(203, 0, 113, 7), V4(203, 0, 113, 7));

    check(parse_ip_or_cidr("2001:db8::/32", 1, &ip6) && ip6.family == 6, "2001:db8::/32 accepted");
    check(parse_ip_or_cidr("2001:db8::1", 1, &ip6) && ip6.family == 6, "bare v6 accepted");

    /* 4. Type-aware routing: a declared non-address type never takes the slash
     *    path, but a bare address is still indexable whatever the type says. */
    printf("declared type gates the slash form\n");
    reject("192.168.1.0/24", 0);
    check(parse_ip_or_cidr("203.0.113.7", 0, &ip) && ip.family == 4, "bare address accepted with allow_cidr=0");

    check(ioc_type_is_ip("ip") && ioc_type_is_ip("cidr") && ioc_type_is_ip(NULL) && ioc_type_is_ip(""),
          "address types and unclassified are IP-ish");
    check(!ioc_type_is_ip("url") && !ioc_type_is_ip("domain") && !ioc_type_is_ip("md5") && !ioc_type_is_ip("email"),
          "url/domain/hash/email are not IP-ish");

    /* 5. Malformed and hostile input must not crash or parse. */
    printf("degenerate input\n");
    reject(NULL, 1);
    reject("", 1);
    reject("/24", 1);
    reject("not-an-ip/24", 1);
    reject("999.999.999.999/24", 1);
    reject(
        "1.2.3.4/"
        "1111111111111111111111111111111111111111111111111111111111111111111111",
        1);

    if (failures) {
        printf("\n%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}
