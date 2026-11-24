/* fuzz_enrichd.c
 * libFuzzer harness for what enrichd does with a request once the HTTP
 * layer has handed it over, and for its key file parser.
 *
 * The first input byte picks the target and the key; the rest is the
 * input:
 *   byte % 4 == 0   a lookup path value, still percent-encoded
 *   byte % 4 == 1   a POST /v1/lookup body
 *   byte % 4 == 2   a POST /attributes/restSearch body
 *   byte % 4 == 3   a key file
 *   byte & 4        the request uses the tlp:red, restricted, context key
 *                   instead of the tlp:clear one
 * Every response is serialized, so the result builders run to the end.
 *
 * FUZZ_THRT and FUZZ_OVERLAY name the database files (make test leaves
 * them in build/api). FUZZ_PREV adds a prevalence table. The seeds in
 * testdata/fuzz/enrichd hit each target once.
 *
 * Build: make fuzz-enrichd (needs a clang with libFuzzer, libfastjson and
 * libmicrohttpd).
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0. See LICENSE.
 */
#define main enrichd_main
#include "enrichd.c"
#undef main

static api_key_t g_clear, g_red;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    enrich_options_t eo;
    char err[512];
    int rc;
    (void)argc;
    (void)argv;
    memset(&g_cfg, 0, sizeof g_cfg);
    g_cfg.max_batch = 1000;
    g_cfg.max_body = 1024 * 1024;
    g_cfg.unmarked_tlp = TLP_AMBER;
    g_cfg.skip_private = 1;

    memset(&eo, 0, sizeof eo);
    eo.size = sizeof eo;
    eo.thrt_path = getenv("FUZZ_THRT");
    eo.overlay_path = getenv("FUZZ_OVERLAY");
    eo.prev_path = getenv("FUZZ_PREV");
    eo.flags = ENRICH_OPT_SKIP_PRIVATE;
    if (eo.thrt_path == NULL && eo.overlay_path == NULL && eo.prev_path == NULL) {
        fprintf(stderr, "fuzz_enrichd: set FUZZ_THRT, FUZZ_OVERLAY or FUZZ_PREV\n");
        exit(1);
    }
    err[0] = '\0';
    rc = enrich_open(&g_enrich, &eo, err, sizeof err);
    if (rc != ENRICH_OK) {
        fprintf(stderr, "fuzz_enrichd: open: %s\n", err[0] ? err : enrich_strerror(rc));
        exit(1);
    }
    g_lookup_flags = enrich_lookup_flags(g_enrich);

    snprintf(g_clear.name, sizeof g_clear.name, "clear");
    g_clear.tlp = TLP_CLEAR;
    snprintf(g_red.name, sizeof g_red.name, "red");
    g_red.tlp = TLP_RED;
    g_red.restricted = 1;
    g_red.context = 1;
    return 0;
}

static void consume(struct json_object *o) {
    const char *text;
    if (o == NULL) return;
    text = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
    if (text != NULL && text[0] != '{') abort();
    json_object_put(o);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const api_key_t *k;
    const char *err = NULL;
    unsigned status = 0;
    size_t nvalues = 0, len;
    char *buf;
    if (size == 0) return 0;
    k = (data[0] & 4) ? &g_red : &g_clear;
    len = size - 1;
    /* A copy with a NUL after it: the path and the key file are C strings,
     * and a body exactly len bytes long must not be read past. */
    buf = malloc(len + 1);
    if (buf == NULL) return 0;
    memcpy(buf, data + 1, len);
    buf[len] = '\0';
    switch (data[0] % 4) {
        case 0:
            if (memchr(buf, '\0', len) == NULL) consume(resp_lookup_one(k, buf, &status, &err));
            break;
        case 1:
            consume(resp_lookup_batch(k, buf, len, &status, &err, &nvalues));
            break;
        case 2:
            consume(resp_misp(k, buf, len, &status, &err, &nvalues));
            break;
        default: {
            char kerr[512];
            keyset_t *ks = keys_parse(buf, len, "fuzz", kerr, sizeof kerr);
            buf = NULL; /* keys_parse took it */
            keys_free(ks);
            break;
        }
    }
    if (status != 0 && status != 200 && status != 400 && status != 500 && status != 503) abort();
    free(buf);
    return 0;
}
