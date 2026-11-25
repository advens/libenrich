/* lmdb_build <sorted list file> <out>: each key maps to "70".
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0. See LICENSE.
 */
#define _GNU_SOURCE
#include <lmdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    MDB_env *env; MDB_txn *txn; MDB_dbi dbi; char *line = NULL; size_t cap = 0; ssize_t n; long cnt = 0;
    FILE *f = fopen(argv[1], "r");
    if (argc != 3 || f == NULL) return 1;
    if (mdb_env_create(&env) || mdb_env_set_mapsize(env, (size_t)4 << 30) ||
        mdb_env_open(env, argv[2], MDB_NOSUBDIR | MDB_WRITEMAP | MDB_NOSYNC, 0644) ||
        mdb_txn_begin(env, NULL, 0, &txn) || mdb_dbi_open(txn, NULL, 0, &dbi)) return 2;
    while ((n = getline(&line, &cap, f)) > 0) {
        MDB_val k, d = {2, "70"};
        if (line[n - 1] == '\n') line[--n] = 0;
        k.mv_size = (size_t)n; k.mv_data = line;
        int rc = mdb_put(txn, dbi, &k, &d, MDB_APPEND);
        if (rc) { fprintf(stderr, "put %s: %s\n", line, mdb_strerror(rc)); return 3; }
        cnt++;
    }
    if (mdb_txn_commit(txn)) return 4;
    mdb_env_sync(env, 1); mdb_env_close(env);
    printf("lmdb: %ld keys\n", cnt);
    return 0;
}
