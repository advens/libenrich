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

#define V4(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))

int main(void) {
    printf("thrt_ipparse regression\n");

    /* 1. The exact feed values that poisoned the database. Every one of these
     *    previously became 0.0.0.0/0. */
    printf("scheme-less URL indicators must never become networks\n");
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

    parsed_ip_t ip6;
    check(parse_ip_or_cidr("2001:db8::/32", 1, &ip6) && ip6.family == 6, "2001:db8::/32 accepted");
    check(parse_ip_or_cidr("2001:db8::1", 1, &ip6) && ip6.family == 6, "bare v6 accepted");

    /* 4. Type-aware routing: a declared non-address type never takes the slash
     *    path, but a bare address is still indexable whatever the type says. */
    printf("declared type gates the slash form\n");
    reject("192.168.1.0/24", 0);
    parsed_ip_t ip;
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
