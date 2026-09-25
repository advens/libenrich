/* thrt_ipparse.h — validated IP / CIDR parsing for the CTI database builder.
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0.
 *
 * The single entry point every site uses to turn a feed value into an address
 * range. Keeping it in one place is the point: a second, laxer parse is how a
 * malformed indicator reaches the range table.
 *
 * A prefix length must be a complete decimal number inside the family's range.
 * atoi() cannot report failure and returns 0 for any non-numeric suffix, so a
 * scheme-less URL indicator such as "103.117.72.60/ptj" parsed as a network
 * yielded 0.0.0.0/0. One such entry makes every address in the world a CTI
 * hit, and public feeds do ship them.
 *
 * Header-only and dependency-free (libc + POSIX sockets), so tests and the
 * builder compile it identically.
 */

#ifndef THRT_IPPARSE_H
#define THRT_IPPARSE_H

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

/* Widest range a single indicator may cover. Public blocklists publish
 * netblocks down to roughly /9; anything broader is malformed input, never
 * intent. Second line of defence behind the strict prefix parse. */
#define THRT_MIN_IPV4_PREFIX 8
#define THRT_MIN_IPV6_PREFIX 32

typedef struct {
    int family; /* 4 or 6 */
    uint32_t v4_start;
    uint32_t v4_end;
    uint8_t v6_start[16];
    uint8_t v6_end[16];
} parsed_ip_t;

/* Parse a full decimal prefix length. Returns 1 and sets *out only when the
 * whole suffix is digits and the value is within [0, max]. Rejects an empty
 * suffix, a leading sign or space, trailing junk, and out-of-range values. */
static inline int parse_prefix_len(const char* s, int max, int* out) {
    if (!s || !isdigit((unsigned char)*s)) return 0;
    char* end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return 0;
    if (v < 0 || v > max) return 0;
    *out = (int)v;
    return 1;
}

/* Parse a bare address or a CIDR into an inclusive range.
 *
 * allow_cidr gates the slash form. It is honoured only when the caller knows
 * the value is meant to be an address (a declared address type, or no declared
 * type at all), so a value declared as url/domain/hash/email is never read as
 * a network. A bare address is always accepted regardless: that reading is
 * unambiguous and costs no coverage.
 *
 * Returns 1 on success. Ranges wider than THRT_MIN_*_PREFIX are rejected so a
 * malformed feed cannot blanket the address space. */
static inline int parse_ip_or_cidr(const char* value, int allow_cidr, parsed_ip_t* out) {
    struct in_addr a4;
    struct in6_addr a6;

    if (!value || !*value || !out) return 0;
    memset(out, 0, sizeof(*out));

    const char* slash = strchr(value, '/');
    if (slash) {
        if (!allow_cidr) return 0;
        char netbuf[64];
        size_t nlen = (size_t)(slash - value);
        if (nlen == 0 || nlen >= sizeof(netbuf)) return 0;
        memcpy(netbuf, value, nlen);
        netbuf[nlen] = '\0';

        int prefix = 0;
        if (inet_pton(AF_INET, netbuf, &a4) == 1) {
            if (!parse_prefix_len(slash + 1, 32, &prefix)) return 0;
            if (prefix < THRT_MIN_IPV4_PREFIX) return 0;
            uint32_t net = ntohl(a4.s_addr);
            uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
            out->family = 4;
            out->v4_start = net & mask;
            out->v4_end = out->v4_start | ~mask;
            return 1;
        }
        if (inet_pton(AF_INET6, netbuf, &a6) == 1) {
            if (!parse_prefix_len(slash + 1, 128, &prefix)) return 0;
            if (prefix < THRT_MIN_IPV6_PREFIX) return 0;
            out->family = 6;
            for (int b = 0; b < 16; b++) {
                int bits = prefix - b * 8;
                uint8_t m = (bits >= 8) ? 0xFF : (bits <= 0) ? 0x00 : (uint8_t)(0xFF << (8 - bits));
                out->v6_start[b] = (uint8_t)(a6.s6_addr[b] & m);
                out->v6_end[b] = (uint8_t)(out->v6_start[b] | (uint8_t)~m);
            }
            return 1;
        }
        return 0;
    }

    if (inet_pton(AF_INET, value, &a4) == 1) {
        out->family = 4;
        out->v4_start = out->v4_end = ntohl(a4.s_addr);
        return 1;
    }
    if (inet_pton(AF_INET6, value, &a6) == 1) {
        out->family = 6;
        memcpy(out->v6_start, a6.s6_addr, 16);
        memcpy(out->v6_end, a6.s6_addr, 16);
        return 1;
    }
    return 0;
}

/* Declared IOC types whose value is an address. An absent or empty type means
 * the producer did not classify the value, so shape detection decides. */
static inline int ioc_type_is_ip(const char* type) {
    if (!type || !*type) return 1;
    return strcasecmp(type, "ip") == 0 || strcasecmp(type, "cidr") == 0 || strcasecmp(type, "ipv4") == 0 ||
           strcasecmp(type, "ipv6") == 0 || strcasecmp(type, "ip-range") == 0 || strcasecmp(type, "net") == 0 ||
           strcasecmp(type, "network") == 0;
}

#endif /* THRT_IPPARSE_H */
