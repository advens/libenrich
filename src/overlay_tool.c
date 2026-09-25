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

#define OVERLAY_JSON_MAX (8 * 1024 * 1024)
#define OVERLAY_ENTRIES_MAX 65536u

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

static int cmd_write(const char *out_path, const char *json_path) {
    char sibling[1024];
    const char *src;
    char *text;
    struct json_object *root, *entries, *item, *jv;
    uint32_t n, i, tenant_id;
    size_t off, need;
    unsigned char *buf;
    thrt_overlay_header_t hdr;
    thrt_overlay_entry_t *ents;
    uint32_t crc;
    FILE *f;

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
        json_object_put(root);
        return 1;
    }

    n = (uint32_t)json_object_array_length(entries);
    if (n == 0 || n > OVERLAY_ENTRIES_MAX) {
        fprintf(stderr, "%s: entry count %u not in 1..%u\n", src, n, OVERLAY_ENTRIES_MAX);
        json_object_put(root);
        return 1;
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
    if (ents == NULL) {
        fprintf(stderr, "overlay_tool: out of memory\n");
        json_object_put(root);
        return 1;
    }

    for (i = 0; i < n; i++) {
        const char *ioc = NULL;
        const char *act = NULL;
        const char *cat = NULL;
        uint8_t action;
        int conf;

        item = json_object_array_get_idx(entries, (int)i);
        if (item == NULL) continue;
        if (json_object_object_get_ex(item, "ioc", &jv))
            ioc = json_object_get_string(jv);
        else if (json_object_object_get_ex(item, "ioc_value", &jv))
            ioc = json_object_get_string(jv);
        if (ioc == NULL || ioc[0] == '\0') {
            fprintf(stderr, "%s: entry %u missing ioc\n", src, i);
            free(ents);
            json_object_put(root);
            return 1;
        }
        if (json_object_object_get_ex(item, "action", &jv)) act = json_object_get_string(jv);
        action = parse_action(act);
        ents[i].ioc_hash = thrt_hash(ioc);
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
    }

    need = sizeof hdr + (size_t)n * sizeof(*ents) + sizeof crc;
    buf = (unsigned char *)malloc(need);
    if (buf == NULL) {
        fprintf(stderr, "overlay_tool: out of memory\n");
        free(ents);
        json_object_put(root);
        return 1;
    }
    off = 0;
    memcpy(buf + off, &hdr, sizeof hdr);
    off += sizeof hdr;
    memcpy(buf + off, ents, (size_t)n * sizeof(*ents));
    off += (size_t)n * sizeof(*ents);
    crc = crc32c_platform(0xFFFFFFFFu, buf, off) ^ 0xFFFFFFFFu;
    memcpy(buf + off, &crc, sizeof crc);
    off += sizeof crc;

    f = fopen(out_path, "wb");
    if (f == NULL) {
        perror(out_path);
        free(buf);
        free(ents);
        json_object_put(root);
        return 1;
    }
    if (fwrite(buf, 1, off, f) != off) {
        perror("fwrite");
        fclose(f);
        free(buf);
        free(ents);
        json_object_put(root);
        return 1;
    }
    fclose(f);

    printf("wrote %s (%zu bytes, %u entries)\n", out_path, off, n);
    for (i = 0; i < n; i++) {
        const char *ioc = NULL;
        item = json_object_array_get_idx(entries, (int)i);
        if (item != NULL) {
            if (json_object_object_get_ex(item, "ioc", &jv))
                ioc = json_object_get_string(jv);
            else if (json_object_object_get_ex(item, "ioc_value", &jv))
                ioc = json_object_get_string(jv);
        }
        printf("  %-9s %s  hash=0x%llx  action='%c'\n", action_name(ents[i].action), ioc ? ioc : "?",
               (unsigned long long)ents[i].ioc_hash, (char)ents[i].action);
    }

    free(buf);
    free(ents);
    json_object_put(root);
    return 0;
}

static int cmd_lookup(const char *path, const char *ioc) {
    thrt_overlay_t *ovl;
    uint64_t h;
    const thrt_overlay_entry_t *e;

    ovl = thrt_overlay_load(path);
    if (ovl == NULL) {
        fprintf(stderr, "failed to load overlay %s (magic/version/CRC)\n", path);
        return 1;
    }
    h = thrt_hash(ioc);
    e = thrt_overlay_lookup(ovl, h);
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
