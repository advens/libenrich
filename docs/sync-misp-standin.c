/* Local stand-in for MISP /attributes/restSearch. Prints its port, then
 * answers POST pages. No Python: the macOS CI runner does not provide it.
 *
 * usage: sync-misp-standin T0 [withdrawn | fail-page]
 *
 * Every attribute has an event publish time relative to T0, and its
 * attribute timestamp is that publish time. "last" must be [lo, hi]: the
 * attributes published in that range, both ends included, as MISP reads
 * it. page and limit slice that list. Each request is logged on stderr
 * as "window LO HI PAGE LIMIT".
 *
 * Three attributes share one publish second (one event), so a slice that
 * holds them cannot be split.
 *
 * The default is the snapshot. "withdrawn" is the same MISP after
 * 203.0.113.201 was deleted: that row comes back deleted, published an
 * hour before T0. "fail-page" answers 500 from page 2 on.
 */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DAY 86400

struct row {
    long ago;        /* publish time is T0 - ago */
    const char *fmt; /* one %llu: the attribute timestamp */
};

static const struct row full_rows[] = {
    {3 * DAY,
     "{\"id\":\"1\",\"type\":\"ip-dst\",\"value\":\"203.0.113.201\","
     "\"to_ids\":true,\"timestamp\":\"%llu\",\"category\":\"Network activity\","
     "\"Tag\":[{\"name\":\"tlp:green\"}],"
     "\"Event\":{\"info\":\"sync-sample\",\"threat_level_id\":\"1\"}}"},
    {2 * DAY + 1,
     "{\"id\":\"4\",\"type\":\"ip-dst\",\"value\":\"203.0.113.204\","
     "\"to_ids\":true,\"timestamp\":%llu,\"category\":\"Network activity\"}"},
    {2 * DAY + 1,
     "{\"id\":\"5\",\"type\":\"ip-dst\",\"value\":\"203.0.113.205\","
     "\"to_ids\":true,\"timestamp\":%llu,\"category\":\"Network activity\"}"},
    {2 * DAY + 1,
     "{\"id\":\"6\",\"type\":\"ip-dst\",\"value\":\"203.0.113.206\","
     "\"to_ids\":true,\"timestamp\":%llu,\"category\":\"Network activity\"}"},
    {2 * DAY,
     "{\"id\":\"2\",\"type\":\"ip-dst\",\"value\":\"203.0.113.202\","
     "\"to_ids\":true,\"timestamp\":%llu,\"category\":\"Network activity\"}"},
    {DAY,
     "{\"id\":\"3\",\"type\":\"ip-dst\",\"value\":\"203.0.113.203\","
     "\"to_ids\":true,\"timestamp\":%llu,\"category\":\"Network activity\"}"},
};

static const struct row withdrawn_rows[] = {
    {2 * DAY + 1,
     "{\"id\":\"4\",\"type\":\"ip-dst\",\"value\":\"203.0.113.204\","
     "\"to_ids\":true,\"timestamp\":%llu,\"category\":\"Network activity\"}"},
    {2 * DAY,
     "{\"id\":\"2\",\"type\":\"ip-dst\",\"value\":\"203.0.113.202\","
     "\"to_ids\":true,\"timestamp\":%llu,\"category\":\"Network activity\"}"},
    {DAY,
     "{\"id\":\"3\",\"type\":\"ip-dst\",\"value\":\"203.0.113.203\","
     "\"to_ids\":true,\"timestamp\":%llu,\"category\":\"Network activity\"}"},
    {3600,
     "{\"id\":\"1\",\"type\":\"ip-dst\",\"value\":\"203.0.113.201\","
     "\"to_ids\":true,\"deleted\":true,\"timestamp\":%llu,"
     "\"category\":\"Network activity\"}"},
};

static unsigned long long g_t0;
static int g_fail_page;
static int g_withdrawn;

static int json_int(const char *body, const char *key, int fallback)
{
    char pat[32];
    const char *p;
    char *end;
    long v;

    snprintf(pat, sizeof pat, "\"%s\":", key);
    p = strstr(body, pat);
    if (p == NULL)
        return fallback;
    p += strlen(pat);
    errno = 0;
    v = strtol(p, &end, 10);
    if (errno != 0 || end == p || v < 1 || v > 100000)
        return fallback;
    return (int)v;
}

/* "last":[lo,hi] with two Unix times. */
static int json_range(const char *body, unsigned long long *lo, unsigned long long *hi)
{
    const char *p = strstr(body, "\"last\":[");
    char *end;

    if (p == NULL)
        return -1;
    p += 8;
    errno = 0;
    *lo = strtoull(p, &end, 10);
    if (errno != 0 || end == p || *end != ',')
        return -1;
    p = end + 1;
    *hi = strtoull(p, &end, 10);
    if (errno != 0 || end == p || *end != ']' || *lo > *hi)
        return -1;
    return 0;
}

static void reply_status(int client, const char *status)
{
    char msg[128];
    int nw = snprintf(msg, sizeof msg,
                      "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status);
    if (nw > 0)
        (void)write(client, msg, (size_t)nw);
}

static void answer(int client)
{
    char req[8192];
    size_t n = 0;
    const char *header_end;
    const char *body;
    const char *cl;
    long need = 0;
    int page, limit, count, i, start, matched, sent;
    const struct row *rows;
    unsigned long long lo, hi;
    char payload[8192];
    size_t used = 0;
    char hdr[256];
    int nw;

    memset(req, 0, sizeof req);
    while (n < sizeof req - 1) {
        ssize_t r = read(client, req + n, sizeof req - 1 - n);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        if (r == 0)
            break;
        n += (size_t)r;
        req[n] = '\0';
        header_end = strstr(req, "\r\n\r\n");
        if (header_end == NULL)
            continue;
        body = header_end + 4;
        cl = strstr(req, "Content-Length:");
        if (cl != NULL && cl < header_end)
            need = strtol(cl + 15, NULL, 10);
        if (need < 0 || need > 4096)
            need = 0;
        if ((size_t)(n - (size_t)(body - req)) >= (size_t)need)
            break;
    }

    header_end = strstr(req, "\r\n\r\n");
    body = header_end != NULL ? header_end + 4 : req;
    /* MISP refuses a request without the automation key. */
    if (strstr(req, "\r\nAuthorization: test-key\r\n") == NULL) {
        reply_status(client, "401 Unauthorized");
        return;
    }
    if (strncmp(req, "POST /attributes/restSearch ", 28) != 0) {
        reply_status(client, "404 Not Found");
        return;
    }
    if (json_range(body, &lo, &hi) != 0) {
        reply_status(client, "400 Bad Request");
        return;
    }
    if (g_withdrawn) {
        rows = withdrawn_rows;
        count = (int)(sizeof withdrawn_rows / sizeof withdrawn_rows[0]);
    } else {
        rows = full_rows;
        count = (int)(sizeof full_rows / sizeof full_rows[0]);
    }
    page = json_int(body, "page", 1);
    limit = json_int(body, "limit", 2000);
    fprintf(stderr, "window %llu %llu %d %d\n", lo, hi, page, limit);
    if (g_fail_page > 0 && page >= g_fail_page) {
        reply_status(client, "500 Error");
        return;
    }
    start = (page - 1) * limit;
    nw = snprintf(payload, sizeof payload, "{\"response\":{\"Attribute\":[");
    if (nw < 0 || (size_t)nw >= sizeof payload)
        return;
    used = (size_t)nw;
    matched = 0;
    sent = 0;
    for (i = 0; i < count && sent < limit; i++) {
        unsigned long long pub = g_t0 - (unsigned long long)rows[i].ago;
        if (pub < lo || pub > hi)
            continue;
        if (matched++ < start)
            continue;
        if (sent > 0) {
            if (used + 1 >= sizeof payload)
                return;
            payload[used++] = ',';
        }
        nw = snprintf(payload + used, sizeof payload - used, rows[i].fmt, pub);
        if (nw < 0 || (size_t)nw >= sizeof payload - used)
            return;
        used += (size_t)nw;
        sent++;
    }
    nw = snprintf(payload + used, sizeof payload - used, "]}}");
    if (nw < 0 || (size_t)nw >= sizeof payload - used)
        return;
    used += (size_t)nw;

    nw = snprintf(hdr, sizeof hdr,
                  "HTTP/1.1 200 OK\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: %zu\r\n"
                  "Connection: close\r\n"
                  "\r\n",
                  used);
    if (nw > 0)
        (void)write(client, hdr, (size_t)nw);
    (void)write(client, payload, used);
}

int main(int argc, char **argv)
{
    int srv, one = 1;
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;
    char *end;

    if (argc < 2) {
        fprintf(stderr, "usage: sync-misp-standin T0 [withdrawn | fail-page]\n");
        return 2;
    }
    errno = 0;
    g_t0 = strtoull(argv[1], &end, 10);
    if (errno != 0 || *end != '\0' || g_t0 < 4 * DAY) {
        fprintf(stderr, "sync-misp-standin: T0 is not a Unix time\n");
        return 2;
    }
    if (argc > 2 && strcmp(argv[2], "fail-page") == 0)
        g_fail_page = 2;
    if (argc > 2 && strcmp(argv[2], "withdrawn") == 0)
        g_withdrawn = 1;
    setvbuf(stderr, NULL, _IOLBF, 0);

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0)
        return 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7f000001);
    addr.sin_port = htons(0);
    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0)
        return 1;
    if (getsockname(srv, (struct sockaddr *)&addr, &len) != 0)
        return 1;
    if (listen(srv, 16) != 0)
        return 1;
    printf("%d\n", ntohs(addr.sin_port));
    fflush(stdout);

    for (;;) {
        int client = accept(srv, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR)
                continue;
            return 1;
        }
        answer(client);
        close(client);
    }
}
