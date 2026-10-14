/* Local stand-in for MISP /attributes/restSearch. Prints its port, then
 * answers POST pages. No Python: the macOS CI runner does not provide it.
 *
 * A numeric "last" returns the withdrawn attribute. Any other window
 * returns the two-attribute snapshot. page and limit slice that list.
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

static const char *full_rows[] = {
    "{\"id\":\"1\",\"type\":\"ip-dst\",\"value\":\"203.0.113.201\","
    "\"to_ids\":true,\"timestamp\":\"100\",\"category\":\"Network activity\","
    "\"Tag\":[{\"name\":\"tlp:green\"}],"
    "\"Event\":{\"info\":\"sync-sample\",\"threat_level_id\":\"1\"}}",
    "{\"id\":\"2\",\"type\":\"ip-dst\",\"value\":\"203.0.113.202\","
    "\"to_ids\":true,\"timestamp\":150,\"category\":\"Network activity\"}"
};

static const char *delta_rows[] = {
    "{\"id\":\"1\",\"type\":\"ip-dst\",\"value\":\"203.0.113.201\","
    "\"to_ids\":true,\"deleted\":true,\"timestamp\":300,"
    "\"category\":\"Network activity\"}"
};

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

static int last_is_timestamp(const char *body)
{
    const char *p = strstr(body, "\"last\":\"");
    if (p == NULL)
        return 0;
    p += 8;
    if (*p < '0' || *p > '9')
        return 0;
    while (*p >= '0' && *p <= '9')
        p++;
    return *p == '"';
}

static void answer(int client)
{
    char req[8192];
    size_t n = 0;
    const char *header_end;
    const char *body;
    const char *cl;
    long need = 0;
    int page, limit, count, i, start;
    const char **rows;
    char payload[4096];
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
    if (last_is_timestamp(body)) {
        rows = delta_rows;
        count = 1;
    } else {
        rows = full_rows;
        count = 2;
    }
    page = json_int(body, "page", 1);
    limit = json_int(body, "limit", 2000);
    start = (page - 1) * limit;
    used = 0;
    nw = snprintf(payload + used, sizeof payload - used,
                  "{\"response\":{\"Attribute\":[");
    if (nw < 0 || (size_t)nw >= sizeof payload - used)
        return;
    used += (size_t)nw;
    for (i = 0; i < limit && start + i < count; i++) {
        nw = snprintf(payload + used, sizeof payload - used, "%s%s",
                      i == 0 ? "" : ",", rows[start + i]);
        if (nw < 0 || (size_t)nw >= sizeof payload - used)
            return;
        used += (size_t)nw;
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

int main(void)
{
    int srv, one = 1;
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;

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
