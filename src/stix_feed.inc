/* STIX 2.1 bundle -> indicator rows.
 *
 * A bundle, a bare object, or an array of objects. spec_version 2.1, and
 * 2.0 objects that use the same indicator shape. pattern_type stix (or
 * omitted). Equality and IN become one row each. AND and OR are both
 * expanded: the database matches one value, so a conjunction is not kept.
 * FOLLOWEDBY is temporal and is left out. LIKE, MATCHES, inequalities,
 * ISSUBSET, and ISSUPERSET are left out.
 *
 * Revoked, already expired (valid_until), and not yet valid (valid_from)
 * are left out of a full build. During apply-delta, revoked and expired
 * rows are deletes. indicator_types of only "benign" are left out.
 * Cyber-observable objects are compiled only when the bundle has no
 * indicator. The feed layer (cti or cti_r) comes from the config, not
 * from the bundle.
 *
 * Included into thrtutil.c. Uses its JSON cursor and emit_normalized_ioc_v4.
 */

#define STIX_MARK_MAX 64
#define STIX_PAT_MAX (8 * 1024 * 1024)

typedef struct {
    char id[128];
    char tlp[32];
} stix_mark_t;

typedef struct {
    char type[48];
    char spec[8];
    char pattern_type[24];
    char *pattern;
    char name[128];
    char value[512];
    char login[128];
    char regkey[512];
    char hash_md5[80];
    char hash_sha1[48];
    char hash_sha256[72];
    char hash_sha512[136];
    char valid_from[40];
    char valid_until[40];
    char tlp_def[32];
    char id[128];
    int confidence;
    int revoked;
    int number;
    int has_number;
    char itypes[8][48];
    int ntypes;
    char labels[8][64];
    int nlabels;
    char marks[6][128];
    int nmarks;
} stix_obj_t;

typedef struct {
    uint8_t confidence;
    uint16_t category;
    uint8_t tlp;
    char action;
    const char *tags;
    size_t emitted;
    size_t skipped;
} stix_ctx_t;

static void stix_obj_init(stix_obj_t *o) {
    memset(o, 0, sizeof(*o));
    o->confidence = -1;
    o->revoked = -1;
}

static void stix_obj_free(stix_obj_t *o) {
    free(o->pattern);
    o->pattern = NULL;
}

static const char *stix_well_known_tlp(const char *id) {
    /* STIX 2.1 section 7.2.1.4 (TLP:WHITE/GREEN/AMBER/RED). */
    if (strcmp(id, "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9") == 0)
        return "clear";
    if (strcmp(id, "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da") == 0)
        return "green";
    if (strcmp(id, "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82") == 0)
        return "amber";
    if (strcmp(id, "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed") == 0)
        return "red";
    /* TLP 2.0 extension (extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d). */
    if (strcmp(id, "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487") == 0)
        return "clear";
    if (strcmp(id, "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb") == 0)
        return "green";
    if (strcmp(id, "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421") == 0)
        return "amber";
    if (strcmp(id, "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003") == 0)
        return "amber+strict";
    if (strcmp(id, "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1") == 0)
        return "red";
    return NULL;
}

static int stix_tlp_rank(const char *s) {
    if (!s || !s[0]) return 0;
    if (strcasestr(s, "red")) return 4;
    if (strcasestr(s, "strict")) return 3;
    if (strcasestr(s, "amber")) return 3;
    if (strcasestr(s, "green")) return 2;
    return 1;
}

static const char *stix_number(const char *p, const char *end, int *out) {
    p = extract_json_int(p, end, out);
    if (p < end && *p == '.') {
        p++;
        while (p < end && *p >= '0' && *p <= '9') p++;
    }
    if (p < end && (*p == 'e' || *p == 'E')) {
        p++;
        if (p < end && (*p == '+' || *p == '-')) p++;
        while (p < end && *p >= '0' && *p <= '9') p++;
    }
    return p;
}

static const char *stix_str_array(const char *p, const char *end,
                                  char *dst, int stride, int maxn, int *nout) {
    *nout = 0;
    p = skip_ws(p, end);
    if (p >= end || *p != '[') return skip_json_val(p, end);
    p++;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == ']') break;
        if (*p == ',') { p++; continue; }
        if (*p == '"') {
            if (*nout < maxn)
                p = extract_json_str(p, end, dst + (*nout) * stride, (size_t)stride);
            else
                p = skip_json_str(p, end);
            if (*nout < maxn) (*nout)++;
        } else {
            p = skip_json_val(p, end);
        }
    }
    if (p < end && *p == ']') p++;
    return p;
}

static char *stix_dup_str(const char *p, const char *end, const char **after) {
    size_t n = 0;
    const char *q;
    char *buf;

    if (p >= end || *p != '"') {
        *after = p;
        return NULL;
    }
    q = p + 1;
    while (q < end && *q != '"') {
        if (*q == '\\' && q + 1 < end) { q += 2; n++; }
        else { q++; n++; }
    }
    if (n > STIX_PAT_MAX) {
        *after = skip_json_str(p, end);
        return NULL;
    }
    buf = malloc(n + 1);
    if (!buf) {
        *after = skip_json_str(p, end);
        return NULL;
    }
    *after = extract_json_str(p, end, buf, n + 1);
    return buf;
}

static const char *stix_hashes(const char *p, const char *end, stix_obj_t *o) {
    p = skip_ws(p, end);
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++;
    while (p < end) {
        char key[32];
        char val[140];
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') { p = skip_json_val(p, end); continue; }
        p = extract_json_str(p, end, key, sizeof(key));
        p = skip_ws(p, end);
        if (p >= end || *p != ':') break;
        p++;
        p = skip_ws(p, end);
        if (p >= end || *p != '"') { p = skip_json_val(p, end); continue; }
        p = extract_json_str(p, end, val, sizeof(val));
        if (strcasecmp(key, "MD5") == 0)
            snprintf(o->hash_md5, sizeof(o->hash_md5), "%s", val);
        else if (strcasecmp(key, "SHA-1") == 0 || strcasecmp(key, "SHA1") == 0)
            snprintf(o->hash_sha1, sizeof(o->hash_sha1), "%s", val);
        else if (strcasecmp(key, "SHA-256") == 0 || strcasecmp(key, "SHA256") == 0)
            snprintf(o->hash_sha256, sizeof(o->hash_sha256), "%s", val);
        else if (strcasecmp(key, "SHA-512") == 0 || strcasecmp(key, "SHA512") == 0)
            snprintf(o->hash_sha512, sizeof(o->hash_sha512), "%s", val);
    }
    if (p < end && *p == '}') p++;
    return p;
}

static const char *stix_definition(const char *p, const char *end, char *tlp, size_t n) {
    p = skip_ws(p, end);
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++;
    while (p < end) {
        char key[32];
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') { p = skip_json_val(p, end); continue; }
        p = extract_json_str(p, end, key, sizeof(key));
        p = skip_ws(p, end);
        if (p >= end || *p != ':') break;
        p++;
        p = skip_ws(p, end);
        if (strcmp(key, "tlp") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, tlp, n);
        else
            p = skip_json_val(p, end);
    }
    if (p < end && *p == '}') p++;
    return p;
}

static const char *stix_one_extension(const char *p, const char *end, char *tlp, size_t n) {
    p = skip_ws(p, end);
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++;
    while (p < end) {
        char key[32];
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') { p = skip_json_val(p, end); continue; }
        p = extract_json_str(p, end, key, sizeof(key));
        p = skip_ws(p, end);
        if (p >= end || *p != ':') break;
        p++;
        p = skip_ws(p, end);
        if (strcmp(key, "tlp_2_0") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, tlp, n);
        else
            p = skip_json_val(p, end);
    }
    if (p < end && *p == '}') p++;
    return p;
}

static const char *stix_extensions(const char *p, const char *end, char *tlp, size_t n) {
    p = skip_ws(p, end);
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') { p = skip_json_val(p, end); continue; }
        p = skip_json_str(p, end);
        p = skip_ws(p, end);
        if (p >= end || *p != ':') break;
        p++;
        p = stix_one_extension(p, end, tlp, n);
    }
    if (p < end && *p == '}') p++;
    return p;
}

static const char *stix_fill(const char *p, const char *end, stix_obj_t *o) {
    p = skip_ws(p, end);
    if (p >= end || *p != '{') return skip_json_val(p, end);
    p++;
    while (p < end) {
        char key[64];
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') { p = skip_json_val(p, end); continue; }
        p = extract_json_str(p, end, key, sizeof(key));
        p = skip_ws(p, end);
        if (p >= end || *p != ':') break;
        p++;
        p = skip_ws(p, end);
        if (strcmp(key, "type") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, o->type, sizeof(o->type));
        else if (strcmp(key, "spec_version") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, o->spec, sizeof(o->spec));
        else if (strcmp(key, "id") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, o->id, sizeof(o->id));
        else if (strcmp(key, "pattern_type") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, o->pattern_type, sizeof(o->pattern_type));
        else if (strcmp(key, "pattern") == 0 && p < end && *p == '"') {
            const char *after = p;
            free(o->pattern);
            o->pattern = stix_dup_str(p, end, &after);
            p = after;
        } else if (strcmp(key, "name") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, o->name, sizeof(o->name));
        else if (strcmp(key, "value") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, o->value, sizeof(o->value));
        else if (strcmp(key, "user_id") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, o->value, sizeof(o->value));
        else if (strcmp(key, "account_login") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, o->login, sizeof(o->login));
        else if (strcmp(key, "key") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, o->regkey, sizeof(o->regkey));
        else if ((strcmp(key, "path") == 0 || strcmp(key, "serial_number") == 0) &&
                 p < end && *p == '"')
            p = extract_json_str(p, end, o->value, sizeof(o->value));
        else if (strcmp(key, "valid_from") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, o->valid_from, sizeof(o->valid_from));
        else if (strcmp(key, "valid_until") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, o->valid_until, sizeof(o->valid_until));
        else if (strcmp(key, "confidence") == 0)
            p = stix_number(p, end, &o->confidence);
        else if (strcmp(key, "number") == 0) {
            p = stix_number(p, end, &o->number);
            o->has_number = 1;
        } else if (strcmp(key, "revoked") == 0)
            p = extract_json_bool(p, end, &o->revoked);
        else if (strcmp(key, "indicator_types") == 0)
            p = stix_str_array(p, end, &o->itypes[0][0], 48, 8, &o->ntypes);
        else if (strcmp(key, "labels") == 0)
            p = stix_str_array(p, end, &o->labels[0][0], 64, 8, &o->nlabels);
        else if (strcmp(key, "object_marking_refs") == 0)
            p = stix_str_array(p, end, &o->marks[0][0], 128, 6, &o->nmarks);
        else if (strcmp(key, "hashes") == 0)
            p = stix_hashes(p, end, o);
        else if (strcmp(key, "definition") == 0)
            p = stix_definition(p, end, o->tlp_def, sizeof(o->tlp_def));
        else if (strcmp(key, "extensions") == 0)
            p = stix_extensions(p, end, o->tlp_def, sizeof(o->tlp_def));
        else
            p = skip_json_val(p, end);
    }
    if (p < end && *p == '}') p++;
    return p;
}

static int stix_index_type(const char *path, char *type, size_t n) {
    const char *colon = strchr(path, ':');
    char obj[64];
    const char *prop;
    size_t ol, pl;

    if (!colon) return 0;
    ol = (size_t)(colon - path);
    if (ol == 0 || ol >= sizeof(obj)) return 0;
    memcpy(obj, path, ol);
    obj[ol] = '\0';
    prop = colon + 1;
    pl = strlen(prop);
    if (pl >= 5 && strcmp(prop + pl - 5, "_refs") == 0) return 0;
    if (pl >= 4 && strcmp(prop + pl - 4, "_ref") == 0) return 0;

    if (strcmp(obj, "ipv4-addr") == 0 && strcmp(prop, "value") == 0) {
        snprintf(type, n, "ip"); return 1;
    }
    if (strcmp(obj, "ipv6-addr") == 0 && strcmp(prop, "value") == 0) {
        snprintf(type, n, "ip"); return 1;
    }
    if (strcmp(obj, "domain-name") == 0 && strcmp(prop, "value") == 0) {
        snprintf(type, n, "domain"); return 1;
    }
    if (strcmp(obj, "url") == 0 && strcmp(prop, "value") == 0) {
        snprintf(type, n, "url"); return 1;
    }
    if (strcmp(obj, "email-addr") == 0 && strcmp(prop, "value") == 0) {
        snprintf(type, n, "email"); return 1;
    }
    if (strcmp(obj, "mac-addr") == 0 && strcmp(prop, "value") == 0) {
        snprintf(type, n, "mac"); return 1;
    }
    if (strcmp(obj, "mutex") == 0 && strcmp(prop, "value") == 0) {
        snprintf(type, n, "mutex"); return 1;
    }
    if (strcmp(obj, "windows-registry-key") == 0 && strcmp(prop, "key") == 0) {
        snprintf(type, n, "registry"); return 1;
    }
    if (strcmp(obj, "autonomous-system") == 0 && strcmp(prop, "number") == 0) {
        snprintf(type, n, "asn"); return 1;
    }
    if (strcmp(obj, "user-account") == 0 &&
        (strcmp(prop, "user_id") == 0 || strcmp(prop, "account_login") == 0)) {
        snprintf(type, n, "user"); return 1;
    }
    if (strcmp(obj, "directory") == 0 && strcmp(prop, "path") == 0) {
        snprintf(type, n, "path"); return 1;
    }
    if ((strcmp(obj, "file") == 0 || strcmp(obj, "artifact") == 0) &&
        strcmp(prop, "name") == 0) {
        snprintf(type, n, "filename"); return 1;
    }
    if (strcmp(obj, "x509-certificate") == 0 && strcmp(prop, "serial_number") == 0) {
        snprintf(type, n, "x509"); return 1;
    }
    if ((strcmp(obj, "file") == 0 || strcmp(obj, "artifact") == 0 ||
         strcmp(obj, "x509-certificate") == 0) && strncmp(prop, "hashes.", 7) == 0) {
        const char *alg = prop + 7;
        char algbuf[32];
        if (*alg == '\'' || *alg == '"') {
            char q = *alg;
            const char *e;
            alg++;
            e = strchr(alg, q);
            if (!e || (size_t)(e - alg) >= sizeof(algbuf)) return 0;
            memcpy(algbuf, alg, (size_t)(e - alg));
            algbuf[e - alg] = '\0';
            alg = algbuf;
        }
        if (strcasecmp(alg, "MD5") == 0) { snprintf(type, n, "md5"); return 1; }
        if (strcasecmp(alg, "SHA-1") == 0 || strcasecmp(alg, "SHA1") == 0) {
            snprintf(type, n, "sha1"); return 1;
        }
        if (strcasecmp(alg, "SHA-256") == 0 || strcasecmp(alg, "SHA256") == 0) {
            snprintf(type, n, "sha256"); return 1;
        }
        if (strcasecmp(alg, "SHA-512") == 0 || strcasecmp(alg, "SHA512") == 0) {
            snprintf(type, n, "sha512"); return 1;
        }
        if (strcasecmp(alg, "SSDEEP") == 0) { snprintf(type, n, "ssdeep"); return 1; }
        snprintf(type, n, "hash");
        return 1;
    }
    return 0;
}

static int stix_hash_type(const char *type) {
    return strcmp(type, "md5") == 0 || strcmp(type, "sha1") == 0 ||
           strcmp(type, "sha256") == 0 || strcmp(type, "sha512") == 0 ||
           strcmp(type, "hash") == 0;
}

static void stix_emit(stix_ctx_t *ctx, const char *type, const char *value) {
    normalized_ioc_v4_t ioc;
    char *c;

    if (!ctx || !type || !type[0] || !value || !value[0]) {
        if (ctx) ctx->skipped++;
        return;
    }
    if (strlen(value) >= sizeof(ioc.value)) {
        ctx->skipped++;
        return;
    }
    memset(&ioc, 0, sizeof(ioc));
    snprintf(ioc.value, sizeof(ioc.value), "%s", value);
    snprintf(ioc.type, sizeof(ioc.type), "%s", type);
    if (stix_hash_type(type) || strcmp(type, "domain") == 0 || strcmp(type, "email") == 0) {
        for (c = ioc.value; *c; c++)
            *c = (char)tolower((unsigned char)*c);
    }
    ioc.confidence = ctx->confidence;
    ioc.category_mask = ctx->category;
    ioc.tlp_mask = ctx->tlp;
    ioc.action = ctx->action;
    snprintf(ioc.feed, sizeof(ioc.feed), "%s", g_default_source);
    if (ctx->tags && ctx->tags[0])
        snprintf(ioc.tags_json, sizeof(ioc.tags_json), "%s", ctx->tags);
    emit_normalized_ioc_v4(&ioc);
    ctx->emitted++;
}

static const char *stix_pat_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

static int stix_kw(const char *p, const char *end, const char *kw) {
    size_t n = strlen(kw);
    char c;
    if ((size_t)(end - p) < n || memcmp(p, kw, n) != 0) return 0;
    if (p + n >= end) return 1;
    c = p[n];
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' ||
        (c >= '0' && c <= '9'))
        return 0;
    return 1;
}

static int stix_temporal(const char *s) {
    const char *p = s;
    const char *end = s + strlen(s);
    while (p < end) {
        if (*p == '\'') {
            p++;
            while (p < end && *p != '\'') {
                if (*p == '\\' && p + 1 < end) p += 2;
                else p++;
            }
            if (p < end) p++;
            continue;
        }
        if (stix_kw(p, end, "FOLLOWEDBY")) return 1;
        p++;
    }
    return 0;
}

static const char *stix_sq(const char *p, const char *end, char *buf, size_t n) {
    size_t i = 0;
    buf[0] = '\0';
    if (p >= end || *p != '\'') return p;
    p++;
    while (p < end && *p != '\'') {
        char c = *p++;
        if (c == '\\' && p < end) {
            char e = *p++;
            switch (e) {
            case '\\': case '\'': case '/': c = e; break;
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'u':
                if (p + 4 <= end) {
                    int cp = 0, ok = 1, k;
                    for (k = 0; k < 4; k++) {
                        char h = p[k];
                        int v;
                        if (h >= '0' && h <= '9') v = h - '0';
                        else if (h >= 'a' && h <= 'f') v = h - 'a' + 10;
                        else if (h >= 'A' && h <= 'F') v = h - 'A' + 10;
                        else { ok = 0; break; }
                        cp = (cp << 4) | v;
                    }
                    p += 4;
                    c = (ok && cp >= 32 && cp < 127) ? (char)cp : '?';
                }
                break;
            default:
                c = e;
                break;
            }
        }
        if (i + 1 < n) buf[i++] = c;
    }
    buf[i] = '\0';
    if (p < end && *p == '\'') p++;
    return p;
}

static const char *stix_hexlit(const char *p, const char *end, char *buf, size_t n) {
    size_t i = 0;
    buf[0] = '\0';
    if (!(p + 2 <= end && (p[0] == 'h' || p[0] == 'H') && p[1] == '\'')) return p;
    p += 2;
    while (p < end && *p != '\'') {
        if (i + 1 < n) buf[i++] = *p;
        p++;
    }
    buf[i] = '\0';
    if (p < end && *p == '\'') p++;
    return p;
}

static const char *stix_read_path(const char *p, const char *end, char *buf, size_t n) {
    size_t i = 0;
    while (p < end) {
        char c = *p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
            c == ']' || c == ')' || c == '=' || c == '!' || c == '<' || c == '>')
            break;
        if (i + 1 >= n) {
            while (p < end && *p != ' ' && *p != '=' && *p != ']') p++;
            buf[0] = '\0';
            return p;
        }
        buf[i++] = c;
        p++;
    }
    buf[i] = '\0';
    return p;
}

static const char *stix_skip_qual(const char *p, const char *end) {
    p = stix_pat_ws(p, end);
    if (stix_kw(p, end, "WITHIN")) {
        p += 6;
        p = stix_pat_ws(p, end);
        while (p < end && *p >= '0' && *p <= '9') p++;
        p = stix_pat_ws(p, end);
        if (stix_kw(p, end, "SECONDS")) p += 7;
        return p;
    }
    if (stix_kw(p, end, "REPEATS")) {
        p += 7;
        p = stix_pat_ws(p, end);
        while (p < end && *p >= '0' && *p <= '9') p++;
        p = stix_pat_ws(p, end);
        if (stix_kw(p, end, "TIMES")) p += 5;
        return p;
    }
    if (stix_kw(p, end, "START")) {
        p += 5;
        p = stix_pat_ws(p, end);
        if (p < end && *p == '\'') {
            char dump[8];
            p = stix_sq(p, end, dump, sizeof(dump));
        }
        p = stix_pat_ws(p, end);
        if (stix_kw(p, end, "STOP")) {
            p += 4;
            p = stix_pat_ws(p, end);
            if (p < end && *p == '\'') {
                char dump[8];
                p = stix_sq(p, end, dump, sizeof(dump));
            }
        }
        return p;
    }
    return p;
}

static const char *stix_expr(const char *p, const char *end, stix_ctx_t *ctx, int depth);

static const char *stix_comparison(const char *p, const char *end, stix_ctx_t *ctx) {
    char path[160];
    char type[32];
    const char *start;
    int op = 0;
    int indexable;

    p = stix_pat_ws(p, end);
    start = p;
    p = stix_read_path(p, end, path, sizeof(path));
    if (p == start || path[0] == '\0') return start;
    p = stix_pat_ws(p, end);
    if (p < end && *p == '=' && !(p + 1 < end && p[1] == '=')) { op = 1; p++; }
    else if (p + 1 < end && p[0] == '!' && p[1] == '=') { op = 0; p += 2; }
    else if (p + 1 < end && p[0] == '>' && p[1] == '=') { op = 0; p += 2; }
    else if (p + 1 < end && p[0] == '<' && p[1] == '=') { op = 0; p += 2; }
    else if (p < end && (*p == '>' || *p == '<')) { op = 0; p++; }
    else if (stix_kw(p, end, "IN")) { op = 2; p += 2; }
    else if (stix_kw(p, end, "LIKE")) { op = 0; p += 4; }
    else if (stix_kw(p, end, "MATCHES")) { op = 0; p += 7; }
    else if (stix_kw(p, end, "ISSUBSET")) { op = 0; p += 8; }
    else if (stix_kw(p, end, "ISSUPERSET")) { op = 0; p += 10; }
    else return p;

    indexable = stix_index_type(path, type, sizeof(type));
    p = stix_pat_ws(p, end);

    if (op == 2 && p < end && *p == '(') {
        p++;
        while (p < end && *p != ')') {
            char val[512];
            p = stix_pat_ws(p, end);
            if (p < end && *p == ',') { p++; continue; }
            if (p >= end || *p == ')') break;
            val[0] = '\0';
            if (*p == '\'')
                p = stix_sq(p, end, val, sizeof(val));
            else if ((*p == 'h' || *p == 'H') && p + 1 < end && p[1] == '\'')
                p = stix_hexlit(p, end, val, sizeof(val));
            else if (*p == '-' || (*p >= '0' && *p <= '9')) {
                size_t i = 0;
                if (*p == '-') val[i++] = *p++;
                while (p < end && *p >= '0' && *p <= '9' && i + 1 < sizeof(val))
                    val[i++] = *p++;
                val[i] = '\0';
            } else {
                while (p < end && *p != ',' && *p != ')') p++;
            }
            if (indexable && val[0]) stix_emit(ctx, type, val);
            else ctx->skipped++;
        }
        if (p < end && *p == ')') p++;
        return p;
    }

    {
        char val[512];
        val[0] = '\0';
        if (p < end && *p == '\'')
            p = stix_sq(p, end, val, sizeof(val));
        else if (p < end && (*p == 'h' || *p == 'H') && p + 1 < end && p[1] == '\'')
            p = stix_hexlit(p, end, val, sizeof(val));
        else if (p < end && (*p == '-' || (*p >= '0' && *p <= '9'))) {
            size_t i = 0;
            if (*p == '-') val[i++] = *p++;
            while (p < end && *p >= '0' && *p <= '9' && i + 1 < sizeof(val))
                val[i++] = *p++;
            val[i] = '\0';
        } else {
            ctx->skipped++;
            return p;
        }
        if (op == 1 && indexable && val[0]) stix_emit(ctx, type, val);
        else ctx->skipped++;
    }
    return p;
}

static const char *stix_factor(const char *p, const char *end, stix_ctx_t *ctx, int depth) {
    if (depth > 32) return end;
    p = stix_pat_ws(p, end);
    if (p >= end) return p;
    if (*p == '(') {
        p++;
        p = stix_expr(p, end, ctx, depth + 1);
        p = stix_pat_ws(p, end);
        if (p < end && *p == ')') p++;
        return p;
    }
    if (*p == '[') {
        p++;
        p = stix_expr(p, end, ctx, depth + 1);
        p = stix_pat_ws(p, end);
        if (p < end && *p == ']') p++;
        for (;;) {
            const char *q = stix_pat_ws(p, end);
            const char *n = stix_skip_qual(q, end);
            if (n == q) break;
            p = n;
        }
        return p;
    }
    return stix_comparison(p, end, ctx);
}

static const char *stix_expr(const char *p, const char *end, stix_ctx_t *ctx, int depth) {
    const char *start;
    p = stix_pat_ws(p, end);
    start = p;
    p = stix_factor(p, end, ctx, depth);
    if (p == start) return p;
    for (;;) {
        const char *q = stix_pat_ws(p, end);
        const char *n;
        if (stix_kw(q, end, "AND")) q += 3;
        else if (stix_kw(q, end, "OR")) q += 2;
        else break;
        n = stix_factor(q, end, ctx, depth);
        if (n == q) break;
        p = n;
    }
    return p;
}

static int stix_parse_time(const char *s, time_t *out) {
    int Y, M, D, h, mi, se;
    int y, era;
    unsigned mo, yoe, doy, doe;
    long days;

    if (!s || !s[0]) return 0;
    if (sscanf(s, "%d-%d-%dT%d:%d:%d", &Y, &M, &D, &h, &mi, &se) != 6) return 0;
    if (M < 1 || M > 12 || D < 1 || D > 31 || h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 60)
        return 0;
    y = Y;
    mo = (unsigned)M;
    y -= mo <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned)(y - era * 400);
    doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + (unsigned)D - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    days = (long)era * 146097L + (long)doe - 719468L;
    *out = (time_t)days * 86400 + h * 3600 + mi * 60 + se;
    return 1;
}

static uint16_t stix_type_mask(const stix_obj_t *o) {
    uint16_t mask = 0;
    int i;
    for (i = 0; i < o->ntypes; i++) {
        if (strcasecmp(o->itypes[i], "benign") == 0) continue;
        if (strcasecmp(o->itypes[i], "anonymization") == 0) {
            mask |= THRT_CAT_PROXY;
            continue;
        }
        if (strcasecmp(o->itypes[i], "compromised") == 0 ||
            strcasecmp(o->itypes[i], "anomalous-activity") == 0 ||
            strcasecmp(o->itypes[i], "attribution") == 0) {
            mask |= THRT_CAT_ATTACK;
            continue;
        }
        mask |= parse_category_mask(o->itypes[i]);
    }
    if (mask) return mask;
    for (i = 0; i < o->nlabels; i++) {
        if (strncasecmp(o->labels[i], "tlp:", 4) == 0) continue;
        mask |= parse_category_mask(o->labels[i]);
    }
    return mask;
}

static int stix_only_benign(const stix_obj_t *o) {
    int i, any = 0;
    if (o->ntypes == 0) return 0;
    for (i = 0; i < o->ntypes; i++) {
        if (strcasecmp(o->itypes[i], "benign") != 0) return 0;
        any = 1;
    }
    return any;
}

static const char *stix_mark_lookup(const stix_mark_t *marks, int n, const char *id) {
    int i;
    const char *known = stix_well_known_tlp(id);
    if (known) return known;
    for (i = 0; i < n; i++)
        if (strcmp(marks[i].id, id) == 0) return marks[i].tlp;
    return NULL;
}

static const char *stix_pick_tlp(const stix_obj_t *o, const stix_mark_t *marks, int nmarks) {
    const char *best = NULL;
    int rank = 0;
    int i;
    for (i = 0; i < o->nmarks; i++) {
        const char *t = stix_mark_lookup(marks, nmarks, o->marks[i]);
        int r;
        if (!t) continue;
        r = stix_tlp_rank(t);
        if (r > rank || (r == rank && t && strcasestr(t, "strict") &&
                         !(best && strcasestr(best, "strict")))) {
            best = t;
            rank = r;
        }
    }
    for (i = 0; i < o->nlabels; i++) {
        const char *lab = o->labels[i];
        int r;
        if (strncasecmp(lab, "tlp:", 4) != 0) continue;
        r = stix_tlp_rank(lab + 4);
        if (r > rank) {
            best = lab + 4;
            rank = r;
        }
    }
    return best;
}

static void stix_build_tags(const stix_obj_t *o, const char *tlp_text, char *buf, size_t n) {
    int pos = 1;
    int i;
    buf[0] = '[';
    buf[1] = '\0';
    if (o->name[0] && !strchr(o->name, '"') && !strchr(o->name, '\\'))
        append_label(buf, &pos, (int)n, o->name);
    for (i = 0; i < o->ntypes; i++) {
        if (!strchr(o->itypes[i], '"'))
            append_label(buf, &pos, (int)n, o->itypes[i]);
    }
    if (tlp_text && strcasestr(tlp_text, "strict"))
        append_label(buf, &pos, (int)n, "tlp:amber+strict");
    if (pos > 1 && pos + 1 < (int)n) {
        buf[pos++] = ']';
        buf[pos] = '\0';
    } else {
        buf[0] = '\0';
    }
}

static int stix_spec_ok(const char *spec) {
    return spec[0] == '\0' || strcmp(spec, "2.1") == 0 || strcmp(spec, "2.0") == 0;
}

static int stix_keep(const stix_obj_t *o, char *action) {
    time_t now = time(NULL);
    time_t t;
    *action = '+';
    if (!stix_spec_ok(o->spec)) return 0;
    if (o->pattern_type[0] && strcmp(o->pattern_type, "stix") != 0) return 0;
    if (stix_only_benign(o)) return 0;
    if (o->valid_from[0] && stix_parse_time(o->valid_from, &t) && t > now) return 0;
    if (o->valid_until[0] && stix_parse_time(o->valid_until, &t) && t < now) {
        if (g_ioc_dedup_active) { *action = '-'; return 1; }
        return 0;
    }
    if (o->revoked == 1) {
        if (g_ioc_dedup_active) { *action = '-'; return 1; }
        return 0;
    }
    return 1;
}

static void stix_compile_indicator(const stix_obj_t *o, const stix_mark_t *marks, int nmarks,
                                   size_t *emitted, size_t *skipped) {
    stix_ctx_t ctx;
    const char *tlp_text;
    char tags[MAX_TAGS_JSON];
    char action = '+';

    memset(&ctx, 0, sizeof(ctx));
    if (!stix_keep(o, &action)) {
        (*skipped)++;
        return;
    }
    if (!o->pattern || !o->pattern[0] || stix_temporal(o->pattern)) {
        (*skipped)++;
        return;
    }
    tlp_text = stix_pick_tlp(o, marks, nmarks);
    stix_build_tags(o, tlp_text, tags, sizeof(tags));
    ctx.confidence = (o->confidence < 0) ? 50 : o->confidence;
    if (ctx.confidence > 100) ctx.confidence = 100;
    ctx.category = stix_type_mask(o);
    ctx.tlp = tlp_text ? parse_tlp_mask(tlp_text) : THRT_TLP_AMBER;
    ctx.action = action;
    ctx.tags = tags[0] ? tags : NULL;
    stix_expr(o->pattern, o->pattern + strlen(o->pattern), &ctx, 0);
    if (ctx.emitted == 0 && ctx.skipped == 0)
        ctx.skipped++;
    *emitted += ctx.emitted;
    *skipped += ctx.skipped;
}

static void stix_compile_sco(const stix_obj_t *o, const stix_mark_t *marks, int nmarks,
                             size_t *emitted, size_t *skipped) {
    stix_ctx_t ctx;
    const char *tlp_text;
    char tags[MAX_TAGS_JSON];
    const char *kind = o->type;

    memset(&ctx, 0, sizeof(ctx));
    if (!stix_spec_ok(o->spec)) {
        (*skipped)++;
        return;
    }
    tlp_text = stix_pick_tlp(o, marks, nmarks);
    stix_build_tags(o, tlp_text, tags, sizeof(tags));
    ctx.confidence = (o->confidence < 0) ? 50 : o->confidence;
    if (ctx.confidence > 100) ctx.confidence = 100;
    ctx.category = stix_type_mask(o);
    ctx.tlp = tlp_text ? parse_tlp_mask(tlp_text) : THRT_TLP_AMBER;
    ctx.action = '+';
    ctx.tags = tags[0] ? tags : NULL;

    if (strcmp(kind, "ipv4-addr") == 0 || strcmp(kind, "ipv6-addr") == 0)
        stix_emit(&ctx, "ip", o->value);
    else if (strcmp(kind, "domain-name") == 0)
        stix_emit(&ctx, "domain", o->value);
    else if (strcmp(kind, "url") == 0)
        stix_emit(&ctx, "url", o->value);
    else if (strcmp(kind, "email-addr") == 0)
        stix_emit(&ctx, "email", o->value);
    else if (strcmp(kind, "mac-addr") == 0)
        stix_emit(&ctx, "mac", o->value);
    else if (strcmp(kind, "mutex") == 0)
        stix_emit(&ctx, "mutex", o->value);
    else if (strcmp(kind, "windows-registry-key") == 0)
        stix_emit(&ctx, "registry", o->regkey);
    else if (strcmp(kind, "directory") == 0)
        stix_emit(&ctx, "path", o->value[0] ? o->value : o->name);
    else if (strcmp(kind, "user-account") == 0) {
        if (o->value[0]) stix_emit(&ctx, "user", o->value);
        if (o->login[0]) stix_emit(&ctx, "user", o->login);
    } else if (strcmp(kind, "autonomous-system") == 0 && o->has_number) {
        char num[16];
        snprintf(num, sizeof(num), "%d", o->number);
        stix_emit(&ctx, "asn", num);
    } else if (strcmp(kind, "file") == 0 || strcmp(kind, "artifact") == 0 ||
               strcmp(kind, "x509-certificate") == 0) {
        if (o->hash_md5[0]) stix_emit(&ctx, "md5", o->hash_md5);
        if (o->hash_sha1[0]) stix_emit(&ctx, "sha1", o->hash_sha1);
        if (o->hash_sha256[0]) stix_emit(&ctx, "sha256", o->hash_sha256);
        if (o->hash_sha512[0]) stix_emit(&ctx, "sha512", o->hash_sha512);
        if (strcmp(kind, "x509-certificate") == 0 && o->value[0])
            stix_emit(&ctx, "x509", o->value);
        else if (o->name[0])
            stix_emit(&ctx, "filename", o->name);
    } else {
        (*skipped)++;
        return;
    }
    *emitted += ctx.emitted;
    *skipped += ctx.skipped;
}

static int stix_is_sco(const char *type) {
    return strcmp(type, "ipv4-addr") == 0 || strcmp(type, "ipv6-addr") == 0 ||
           strcmp(type, "domain-name") == 0 || strcmp(type, "url") == 0 ||
           strcmp(type, "email-addr") == 0 || strcmp(type, "mac-addr") == 0 ||
           strcmp(type, "mutex") == 0 || strcmp(type, "windows-registry-key") == 0 ||
           strcmp(type, "directory") == 0 || strcmp(type, "user-account") == 0 ||
           strcmp(type, "autonomous-system") == 0 || strcmp(type, "file") == 0 ||
           strcmp(type, "artifact") == 0 || strcmp(type, "x509-certificate") == 0;
}

typedef struct {
    stix_mark_t marks[STIX_MARK_MAX];
    int nmarks;
    int indicators;
} stix_index_t;

static void stix_index_one(const char *obj, const char *objend, void *ud) {
    stix_index_t *ix = ud;
    stix_obj_t o;
    (void)objend;
    stix_obj_init(&o);
    stix_fill(obj, objend, &o);
    if (strcmp(o.type, "indicator") == 0) ix->indicators++;
    if (strcmp(o.type, "marking-definition") == 0 && o.id[0] && o.tlp_def[0] &&
        ix->nmarks < STIX_MARK_MAX) {
        snprintf(ix->marks[ix->nmarks].id, sizeof(ix->marks[0].id), "%s", o.id);
        snprintf(ix->marks[ix->nmarks].tlp, sizeof(ix->marks[0].tlp), "%s", o.tlp_def);
        ix->nmarks++;
    }
    if (o.tlp_def[0] == '\0' && o.name[0] && strncasecmp(o.name, "TLP:", 4) == 0 &&
        strcmp(o.type, "marking-definition") == 0 && ix->nmarks < STIX_MARK_MAX) {
        snprintf(ix->marks[ix->nmarks].id, sizeof(ix->marks[0].id), "%s", o.id);
        snprintf(ix->marks[ix->nmarks].tlp, sizeof(ix->marks[0].tlp), "%s", o.name + 4);
        ix->nmarks++;
    }
    stix_obj_free(&o);
}

typedef struct {
    const stix_index_t *ix;
    size_t emitted;
    size_t skipped;
} stix_compile_ud_t;

static void stix_compile_one(const char *obj, const char *objend, void *ud) {
    stix_compile_ud_t *c = ud;
    stix_obj_t o;
    (void)objend;
    stix_obj_init(&o);
    stix_fill(obj, objend, &o);
    if (strcmp(o.type, "indicator") == 0)
        stix_compile_indicator(&o, c->ix->marks, c->ix->nmarks, &c->emitted, &c->skipped);
    else if (c->ix->indicators == 0 && stix_is_sco(o.type))
        stix_compile_sco(&o, c->ix->marks, c->ix->nmarks, &c->emitted, &c->skipped);
    stix_obj_free(&o);
}

static void stix_each(const char *p, const char *end,
                      void (*fn)(const char *, const char *, void *), void *ud) {
    p = skip_ws(p, end);
    if (p < end && *p == '[') {
        p++;
        while (p < end) {
            const char *after;
            p = skip_ws(p, end);
            if (p >= end || *p == ']') break;
            if (*p == ',') { p++; continue; }
            if (*p != '{') { p = skip_json_val(p, end); continue; }
            after = skip_json_val(p, end);
            fn(p, after, ud);
            p = after;
        }
        return;
    }
    if (p < end && *p == '{') {
        const char *after = skip_json_val(p, end);
        fn(p, after, ud);
    }
}

static const char *stix_toplevel(const char *p, const char *end,
                                 char *type, size_t typesz,
                                 char *spec, size_t specsz,
                                 const char **objects_at) {
    *objects_at = NULL;
    type[0] = '\0';
    spec[0] = '\0';
    p = skip_ws(p, end);
    if (p >= end || *p != '{') return p;
    p++;
    while (p < end) {
        char key[32];
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') { p = skip_json_val(p, end); continue; }
        p = extract_json_str(p, end, key, sizeof(key));
        p = skip_ws(p, end);
        if (p >= end || *p != ':') break;
        p++;
        p = skip_ws(p, end);
        if (strcmp(key, "type") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, type, typesz);
        else if (strcmp(key, "spec_version") == 0 && p < end && *p == '"')
            p = extract_json_str(p, end, spec, specsz);
        else if (strcmp(key, "objects") == 0 && p < end && *p == '[') {
            *objects_at = p;
            p = skip_json_val(p, end);
        } else
            p = skip_json_val(p, end);
    }
    return p;
}

static void stix_compile_list(const char *p, const char *end, size_t *emitted, size_t *skipped) {
    stix_index_t ix;
    stix_compile_ud_t ud;
    memset(&ix, 0, sizeof(ix));
    stix_each(p, end, stix_index_one, &ix);
    memset(&ud, 0, sizeof(ud));
    ud.ix = &ix;
    stix_each(p, end, stix_compile_one, &ud);
    *emitted += ud.emitted;
    *skipped += ud.skipped;
}

static void process_stix_json(const char *filename) {
    int fd = open(filename, O_RDONLY);
    struct stat sb;
    const char *map, *end, *p;
    size_t emitted = 0, skipped = 0;

    if (fd < 0) {
        fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno));
        exit(1);
    }
    if (fstat(fd, &sb) < 0 || sb.st_size == 0) {
        fprintf(stderr, "%s Empty or unreadable file: %s\n", ICON_WARN, filename);
        close(fd);
        return;
    }
    map = (const char *)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "mmap failed for %s: %s\n", filename, strerror(errno));
        close(fd);
        exit(1);
    }
    end = map + sb.st_size;
    p = map;
    if ((size_t)(end - p) >= 3 && memcmp(p, "\xef\xbb\xbf", 3) == 0) p += 3;
    p = skip_ws(p, end);

    if (g_verbose)
        printf("%s %sProcessing %-14s: %s (%.2f MB)%s\n",
               ICON_INFO, "", "STIX", filename, sb.st_size / (1024.0 * 1024.0), "");

    if (p < end && *p == '[') {
        stix_compile_list(p, end, &emitted, &skipped);
    } else if (p < end && *p == '{') {
        char type[48];
        char spec[8];
        const char *objects = NULL;
        stix_toplevel(p, end, type, sizeof(type), spec, sizeof(spec), &objects);
        if (spec[0] && strcmp(spec, "2.1") != 0 && strcmp(spec, "2.0") != 0) {
            fprintf(stderr, "%s %s: spec_version %s is not 2.1 or 2.0\n",
                    ICON_WARN, filename, spec);
        } else if (objects)
            stix_compile_list(objects, end, &emitted, &skipped);
        else
            stix_compile_list(p, end, &emitted, &skipped);
    } else {
        fprintf(stderr, "%s %s is not a STIX bundle or object\n", ICON_WARN, filename);
    }

    if (g_verbose) {
        printf("   %s Loaded %zu IOCs from STIX", ICON_CHECK, emitted);
        if (skipped > 0)
            printf(" (%zu skipped)", skipped);
        printf("\n");
    }
    munmap((void *)map, (size_t)sb.st_size);
    close(fd);
}
