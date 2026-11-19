/* overlay_tool.c
 * Build and query a CTI overlay (.ovly).
 *
 * Usage:
 *   overlay_tool lookup <file.ovly> <ioc>
 *   overlay_tool write  <out.ovly> [entries.json]
 *
 * write reads a JSON object with an "entries" array. Each entry needs "ioc"
 * (or "ioc_value") and "action" (ADD / WHITELIST / TAG, or + / - / T).
 * If the JSON path is omitted, write looks for allow.json next to the output
 * file (the lab layout).
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

#include "thrt_overlay.h"
#include "thrt_format.h"

#include <json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define OVERLAY_JSON_MAX (8 * 1024 * 1024)
#define OVERLAY_ENTRIES_MAX 65536u
#define OVERLAY_VALUE_MAX 4096
#define OVERLAY_POOL_MAX ((size_t)1 << 30)

static const char *action_name(uint8_t a) {
    switch (a) {
        case OVERLAY_ACTION_ADD:
            return "ADD";
        case OVERLAY_ACTION_WHITELIST:
            return "WHITELIST";
        case OVERLAY_ACTION_TAG:
            return "TAG";
        default:
            return "?";
    }
}

static uint8_t parse_action(const char *s) {
    if (s == NULL || s[0] == '\0') return OVERLAY_ACTION_ADD;
    if (strcmp(s, "WHITELIST") == 0 || strcmp(s, "whitelist") == 0 || strcmp(s, "-") == 0 || strcmp(s, "suppress") == 0)
        return OVERLAY_ACTION_WHITELIST;
    if (strcmp(s, "TAG") == 0 || strcmp(s, "tag") == 0 || strcmp(s, "T") == 0) return OVERLAY_ACTION_TAG;
    return OVERLAY_ACTION_ADD;
}

static uint16_t parse_category(const char *s) {
    if (s == NULL || s[0] == '\0') return 0;
    if (strcmp(s, "c2") == 0 || strcmp(s, "C2") == 0) return THRT_CAT_C2;
    if (strcmp(s, "malware") == 0) return THRT_CAT_MALWARE;
    if (strcmp(s, "phishing") == 0) return THRT_CAT_PHISHING;
    if (strcmp(s, "botnet") == 0) return THRT_CAT_BOTNET;
    if (strcmp(s, "attack") == 0) return THRT_CAT_ATTACK;
    if (strcmp(s, "exploit") == 0) return THRT_CAT_EXPLOIT;
    if (strcmp(s, "ransomware") == 0) return THRT_CAT_RANSOMWARE;
    if (strcmp(s, "spam") == 0) return THRT_CAT_SPAM;
    if (strcmp(s, "scanner") == 0) return THRT_CAT_SCANNER;
    if (strcmp(s, "tor_exit") == 0) return THRT_CAT_TOR_EXIT;
    if (strcmp(s, "proxy") == 0) return THRT_CAT_PROXY;
    return 0;
}

static int sibling_allow_json(const char *out_path, char *dst, size_t dstsz) {
    const char *slash;
    size_t dirlen;

    if (out_path == NULL || dst == NULL || dstsz < 11) return -1;
    slash = strrchr(out_path, '/');
    if (slash == NULL) {
        if (dstsz < 11) return -1;
        memcpy(dst, "allow.json", 11);
        return 0;
    }
    dirlen = (size_t)(slash - out_path);
    if (dirlen + 11 + 1 > dstsz) return -1;
    memcpy(dst, out_path, dirlen);
    memcpy(dst + dirlen, "/allow.json", 12);
    return 0;
}

static char *read_whole_file(const char *path, size_t *out_len) {
    FILE *f;
    long sz;
    char *buf;
    size_t n;

    f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return NULL;
    }
    sz = ftell(f);
    if (sz <= 0 || sz > OVERLAY_JSON_MAX) {
        fprintf(stderr, "%s: empty or larger than %d bytes\n", path, OVERLAY_JSON_MAX);
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        perror("fseek");
        fclose(f);
        return NULL;
    }
    buf = (char *)malloc((size_t)sz + 1);
    if (buf == NULL) {
        fprintf(stderr, "overlay_tool: out of memory\n");
        fclose(f);
        return NULL;
    }
    n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) {
        fprintf(stderr, "%s: short read\n", path);
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

/* Growable string pool. Offset 0 holds a NUL, so 0 means "no string". */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
} pool_t;

static int pool_add(pool_t *p, const char *s, size_t n, uint32_t *off) {
    if (n > OVERLAY_POOL_MAX || p->len > OVERLAY_POOL_MAX - n - 1) return -1;
    if (p->len + n + 1 > p->cap) {
        size_t cap = p->cap ? p->cap : 4096;
        char *d;
        while (cap < p->len + n + 1) cap *= 2;
        d = (char *)realloc(p->data, cap);
        if (d == NULL) return -1;
        p->data = d;
        p->cap = cap;
    }
    memcpy(p->data + p->len, s, n);
    p->data[p->len + n] = '\0';
    *off = (uint32_t)p->len;
    p->len += n + 1;
    return 0;
}

/* Index of an earlier entry with the same value, or -1. */
static long find_dup(const uint32_t *slots, uint32_t mask, const thrt_overlay_entry_t *ents, const pool_t *p,
                     uint64_t h, const char *v, size_t n, uint32_t *slot_out) {
    uint32_t slot = (uint32_t)h & mask;
    while (slots[slot] != THRT_OVERLAY_IDX_EMPTY) {
        const thrt_overlay_entry_t *e = &ents[slots[slot]];
        if (e->ioc_hash == h && e->value_length == n && memcmp(p->data + e->value_offset, v, n) == 0)
            return (long)slots[slot];
        slot = (slot + 1) & mask;
    }
    *slot_out = slot;
    return -1;
}

static int write_atomic(const char *out_path, const unsigned char *buf, size_t len) {
    char tmp[1100];
    FILE *f;
    int n = snprintf(tmp, sizeof tmp, "%s.tmp.%ld", out_path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof tmp) {
        fprintf(stderr, "overlay_tool: output path too long\n");
        return -1;
    }
    f = fopen(tmp, "wb");
    if (f == NULL) {
        perror(tmp);
        return -1;
    }
    if (fwrite(buf, 1, len, f) != len || fflush(f) != 0 || fsync(fileno(f)) != 0) {
        perror(tmp);
        fclose(f);
        unlink(tmp);
        return -1;
    }
    if (fclose(f) != 0 || rename(tmp, out_path) != 0) {
        perror(out_path);
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int cmd_write(const char *out_path, const char *json_path) {
    char sibling[1024];
    const char *src;
    char *text;
    struct json_object *root = NULL, *entries, *item, *jv;
    uint32_t n, i, tenant_id, cap, mask;
    uint32_t *slots = NULL;
    size_t off, need;
    unsigned char *buf = NULL;
    thrt_overlay_header_t hdr;
    thrt_overlay_entry_t *ents = NULL;
    pool_t pool = {0};
    uint32_t crc, zero_off;
    int rc = 1;

    src = json_path;
    if (src == NULL || src[0] == '\0') {
        if (sibling_allow_json(out_path, sibling, sizeof sibling) != 0) {
            fprintf(stderr, "overlay_tool: output path too long for allow.json fallback\n");
            return 1;
        }
        src = sibling;
    }

    text = read_whole_file(src, NULL);
    if (text == NULL) return 1;

    root = json_tokener_parse(text);
    free(text);
    if (root == NULL) {
        fprintf(stderr, "%s: invalid JSON\n", src);
        return 1;
    }
    if (!json_object_object_get_ex(root, "entries", &entries) || json_object_get_type(entries) != json_type_array) {
        fprintf(stderr, "%s: missing entries array\n", src);
        goto out;
    }

    n = (uint32_t)json_object_array_length(entries);
    if (n == 0 || n > OVERLAY_ENTRIES_MAX) {
        fprintf(stderr, "%s: entry count %u not in 1..%u\n", src, n, OVERLAY_ENTRIES_MAX);
        goto out;
    }

    tenant_id = 1;
    if (json_object_object_get_ex(root, "tenant_id", &jv)) tenant_id = (uint32_t)json_object_get_int(jv);

    memset(&hdr, 0, sizeof hdr);
    hdr.magic = THRT_OVERLAY_MAGIC;
    hdr.version = THRT_OVERLAY_VERSION;
    hdr.entry_count = n;
    hdr.tenant_id = tenant_id;
    hdr.timestamp = (uint64_t)time(NULL);

    ents = (thrt_overlay_entry_t *)calloc(n, sizeof(*ents));
    cap = overlay_next_pow2(n * 2);
    mask = cap - 1;
    slots = (uint32_t *)malloc((size_t)cap * sizeof(*slots));
    if (ents == NULL || slots == NULL || pool_add(&pool, "", 0, &zero_off) != 0) {
        fprintf(stderr, "overlay_tool: out of memory\n");
        goto out;
    }
    memset(slots, 0xFF, (size_t)cap * sizeof(*slots));

    for (i = 0; i < n; i++) {
        const char *ioc = NULL;
        const char *act = NULL;
        const char *cat = NULL;
        size_t ioc_len;
        uint8_t action;
        uint32_t slot = 0;
        long dup;
        int conf;

        item = json_object_array_get_idx(entries, (int)i);
        if (item == NULL) {
            fprintf(stderr, "%s: entry %u is not an object\n", src, i);
            goto out;
        }
        if (json_object_object_get_ex(item, "ioc", &jv))
            ioc = json_object_get_string(jv);
        else if (json_object_object_get_ex(item, "ioc_value", &jv))
            ioc = json_object_get_string(jv);
        if (ioc == NULL || ioc[0] == '\0') {
            fprintf(stderr, "%s: entry %u missing ioc\n", src, i);
            goto out;
        }
        ioc_len = strlen(ioc);
        if (ioc_len > OVERLAY_VALUE_MAX) {
            fprintf(stderr, "%s: entry %u ioc longer than %d bytes\n", src, i, OVERLAY_VALUE_MAX);
            goto out;
        }
        ents[i].ioc_hash = thrt_hash(ioc);
        dup = find_dup(slots, mask, ents, &pool, ents[i].ioc_hash, ioc, ioc_len, &slot);
        if (dup >= 0) {
            fprintf(stderr, "%s: entry %u repeats the ioc of entry %ld\n", src, i, dup);
            goto out;
        }
        if (pool_add(&pool, ioc, ioc_len, &ents[i].value_offset) != 0) {
            fprintf(stderr, "%s: string pool full\n", src);
            goto out;
        }
        ents[i].value_length = (uint32_t)ioc_len;
        slots[slot] = i;

        if (json_object_object_get_ex(item, "action", &jv)) act = json_object_get_string(jv);
        action = parse_action(act);
        ents[i].action = action;
        if (action == OVERLAY_ACTION_WHITELIST) {
            ents[i].suppress_mode = OVERLAY_SUPPRESS_FULL;
            ents[i].confidence = 100;
            ents[i].type_mask = THRT_TYPE_CTI;
        } else if (action == OVERLAY_ACTION_TAG) {
            ents[i].suppress_mode = OVERLAY_SUPPRESS_SCORE_ONLY;
            ents[i].confidence = 80;
            ents[i].type_mask = THRT_TYPE_TAGS;
        } else {
            ents[i].suppress_mode = OVERLAY_SUPPRESS_SCORE_ONLY;
            ents[i].confidence = 80;
            ents[i].type_mask = THRT_TYPE_CTI;
        }
        if (json_object_object_get_ex(item, "confidence", &jv)) {
            conf = json_object_get_int(jv);
            if (conf < 0) conf = 0;
            if (conf > 100) conf = 100;
            ents[i].confidence = (uint8_t)conf;
        }
        if (json_object_object_get_ex(item, "suppress_mode", &jv)) {
            const char *sm = json_object_get_string(jv);
            if (sm != NULL && (strcmp(sm, "full") == 0 || strcmp(sm, "FULL") == 0))
                ents[i].suppress_mode = OVERLAY_SUPPRESS_FULL;
            else
                ents[i].suppress_mode = OVERLAY_SUPPRESS_SCORE_ONLY;
        }
        if (json_object_object_get_ex(item, "category", &jv)) cat = json_object_get_string(jv);
        ents[i].category_mask = parse_category(cat);
        if (action == OVERLAY_ACTION_ADD && ents[i].category_mask == 0) ents[i].category_mask = THRT_CAT_C2;

        /* tags: an array of strings, stored as its JSON text. */
        if (json_object_object_get_ex(item, "tags", &jv)) {
            const char *tj;
            size_t k, tn;
            if (json_object_get_type(jv) != json_type_array) {
                fprintf(stderr, "%s: entry %u tags is not an array\n", src, i);
                goto out;
            }
            tn = json_object_array_length(jv);
            for (k = 0; k < tn; k++) {
                if (json_object_get_type(json_object_array_get_idx(jv, (int)k)) != json_type_string) {
                    fprintf(stderr, "%s: entry %u tags holds a non-string\n", src, i);
                    goto out;
                }
            }
            if (tn > 0) {
                tj = json_object_to_json_string_ext(jv, JSON_C_TO_STRING_PLAIN);
                if (tj == NULL || pool_add(&pool, tj, strlen(tj), &ents[i].tags_offset) != 0) {
                    fprintf(stderr, "%s: string pool full\n", src);
                    goto out;
                }
                ents[i].tags_length = (uint32_t)strlen(tj);
            }
        }
    }

    need = sizeof hdr + (size_t)n * sizeof(*ents) + pool.len + sizeof crc;
    buf = (unsigned char *)malloc(need);
    if (buf == NULL) {
        fprintf(stderr, "overlay_tool: out of memory\n");
        goto out;
    }
    off = 0;
    memcpy(buf + off, &hdr, sizeof hdr);
    off += sizeof hdr;
    memcpy(buf + off, ents, (size_t)n * sizeof(*ents));
    off += (size_t)n * sizeof(*ents);
    memcpy(buf + off, pool.data, pool.len);
    off += pool.len;
    crc = crc32c_platform(0xFFFFFFFFu, buf, off) ^ 0xFFFFFFFFu;
    memcpy(buf + off, &crc, sizeof crc);
    off += sizeof crc;

    if (write_atomic(out_path, buf, off) != 0) goto out;

    printf("wrote %s (%zu bytes, %u entries)\n", out_path, off, n);
    for (i = 0; i < n; i++)
        printf("  %-9s %s  hash=0x%llx  action='%c'\n", action_name(ents[i].action), pool.data + ents[i].value_offset,
               (unsigned long long)ents[i].ioc_hash, (char)ents[i].action);
    rc = 0;

out:
    free(buf);
    free(slots);
    free(ents);
    free(pool.data);
    json_object_put(root);
    return rc;
}

static const char *load_reason(int why) {
    switch (why) {
        case THRT_OVERLAY_ERR_VERSION:
            return "not a version 2 overlay, rebuild it";
        case THRT_OVERLAY_ERR_CHECKSUM:
            return "CRC32C mismatch";
        case THRT_OVERLAY_ERR_FORMAT:
            return "bad magic or an entry out of bounds";
        case THRT_OVERLAY_ERR_NOMEM:
            return "out of memory";
        default:
            return "cannot open or map";
    }
}

static int cmd_lookup(const char *path, const char *ioc) {
    thrt_overlay_t *ovl;
    uint64_t h;
    int why = 0;
    const thrt_overlay_entry_t *e;

    ovl = thrt_overlay_load_ex(path, &why);
    if (ovl == NULL) {
        fprintf(stderr, "failed to load overlay %s: %s\n", path, load_reason(why));
        return 1;
    }
    h = thrt_hash(ioc);
    e = thrt_overlay_find(ovl, h, ioc, strlen(ioc));
    if (e == NULL) {
        printf("MISS  ioc=%s  hash=0x%llx\n", ioc, (unsigned long long)h);
        thrt_overlay_free(ovl);
        return 0;
    }
    printf("HIT   ioc=%s  hash=0x%llx  action=%s  suppress=%u  confidence=%u\n", ioc, (unsigned long long)h,
           action_name(e->action), e->suppress_mode, e->confidence);
    thrt_overlay_free(ovl);
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s write <out.ovly> [entries.json]\n", argv0);
    fprintf(stderr, "       %s lookup <file.ovly> <ioc>\n", argv0);
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "write") == 0) return cmd_write(argv[2], argc >= 4 ? argv[3] : NULL);
    if (argc >= 4 && strcmp(argv[1], "lookup") == 0) return cmd_lookup(argv[2], argv[3]);
    usage(argv[0]);
    return 2;
}
