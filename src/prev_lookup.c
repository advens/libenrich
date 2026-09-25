/* prev_lookup.c
 * mmap a prevalence .prev table and print the fleet count for a key.
 *
 * Usage:   prev_lookup <file.prev> <observable>
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

#include "prev_format.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int fd;
    struct stat st;
    void *map;
    uint32_t slots = 0;
    const prev_entry_t *table;
    uint16_t edges = 0, srcs = 0;
    uint32_t count;
    const prev_header_t *h;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <file.prev> <observable>\n", argv[0]);
        return 2;
    }
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror(argv[1]);
        return 1;
    }
    if (fstat(fd, &st) != 0) {
        perror("fstat");
        close(fd);
        return 1;
    }
    if (st.st_size <= 0) {
        fprintf(stderr, "%s: empty file\n", argv[1]);
        close(fd);
        return 1;
    }
    map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    table = prev_table_map(map, (size_t)st.st_size, &slots);
    if (table == NULL) {
        fprintf(stderr, "invalid .prev (magic/version/layout)\n");
        munmap(map, (size_t)st.st_size);
        return 1;
    }
    h = (const prev_header_t *)map;
    count = prev_lookup(table, slots, argv[2], &edges, &srcs);
    printf("db %s  v%u  slots=%u  entries=%u  epoch=%u\n", argv[1], h->version, slots, h->entry_count, h->epoch);
    printf("key=%s  count=%u  collectors=%u  sources=%u%s\n", argv[2], count, edges, srcs,
           count == 0 ? "  (absent = rare)" : "");
    munmap(map, (size_t)st.st_size);
    return 0;
}
