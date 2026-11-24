#!/bin/bash
# Run the store comparison inside ubuntu:24.04. See README.md.
# Copyright 2026 Advens. Licensed under the Apache License, Version 2.0.
#   /src   libenrich source tree (read-only)
#   /bench this directory (read-only)
#   /data  output of gen.py (read-only)
# THREADS defaults to the number of CPUs.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null
apt-get -qq install -y build-essential pkg-config libfastjson-dev libmaxminddb-dev liblmdb-dev \
    libcdb-dev tinycdb libglib2.0-dev libhiredis-dev redis-server golang-go ca-certificates >/dev/null 2>&1

T=${THREADS:-$(nproc)}
W=/work
D=/data
S=$W/stores
mkdir -p $W $S
case $(uname -m) in
    aarch64) ARCH=-march=armv8-a+crc ;;
    x86_64) ARCH="-march=x86-64-v2 -msse4.2" ;;
    *) ARCH= ;;
esac
since() { echo $(($(date +%s) - $1)); }

echo "host: $(uname -m), $(nproc) CPUs, $(gcc --version | head -1)"
cp -a /src $W/libenrich
(cd $W/libenrich && rm -rf build && make -s >/dev/null)

t0=$(date +%s)
printf '{"output":"%s","feeds":[{"name":"bench","type":"csv","layer":"cti","path":"%s"}]}\n' \
    $S/bench.thrt $D/feed.csv >$W/enrich.json
$W/libenrich/build/enrich -c $W/enrich.json build >/dev/null
echo "libenrich .thrt: built in $(since $t0) s, $(du -h $S/bench.thrt | cut -f1)"

mkdir -p $W/mmdbgen && cp /bench/mmdbgen.go $W/mmdbgen/main.go
(cd $W/mmdbgen && go mod init mmdbgen >/dev/null 2>&1 &&
    go get github.com/maxmind/mmdbwriter@v1.0.0 >/dev/null 2>&1 && go build -o mmdbgen .)
t0=$(date +%s)
$W/mmdbgen/mmdbgen $D/ip_nets.txt $S/bench.mmdb
echo "MaxMind DB: built in $(since $t0) s, $(du -h $S/bench.mmdb | cut -f1)"

t0=$(date +%s)
awk '{print $0" 70"}' $D/strings.txt | cdb -c -m $S/bench.cdb
echo "tinycdb: built in $(since $t0) s, $(du -h $S/bench.cdb | cut -f1)"

gcc -O2 -o $W/lmdb_build /bench/lmdb_build.c -llmdb
t0=$(date +%s)
$W/lmdb_build $D/strings.txt $S/bench.lmdb
echo "LMDB: built in $(since $t0) s, $(du -h $S/bench.lmdb | cut -f1)"

redis-server --port 0 --unixsocket $W/redis.sock --save "" --appendonly no --daemonize yes >/dev/null
until redis-cli -s $W/redis.sock ping >/dev/null 2>&1; do sleep 0.2; done
t0=$(date +%s)
awk '{printf "*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$2\r\n70\r\n", length($0), $0}' $D/strings.txt |
    redis-cli -s $W/redis.sock --pipe >/dev/null
echo "Redis: loaded in $(since $t0) s, $(redis-cli -s $W/redis.sock info memory |
    grep '^used_memory_human' | cut -d: -f2 | tr -d '\r')"

# libenrich links from its own make build; the other stores use the
# distribution's libraries.
gcc -O2 -std=c11 $ARCH -I$W/libenrich/src $(pkg-config --cflags glib-2.0) -o $W/compare /bench/compare.c \
    $W/libenrich/build/libenrich.a -lfastjson -lmaxminddb -llmdb -lcdb -lhiredis $(pkg-config --libs glib-2.0) -pthread

expect() { grep "^$1 " $D/expect.txt | cut -d' ' -f2; }
echo
echo "IP: 1M queries, longest-prefix match over 1M addresses and 50k networks"
for q in q_ip_0.001.txt q_ip_1.txt; do
    $W/compare enrich $S/bench.thrt $D/$q $T "$(expect $q)"
    $W/compare mmdb $S/bench.mmdb $D/$q $T "$(expect $q)"
    $W/compare mmdbstr $S/bench.mmdb $D/$q $T "$(expect $q)"
done
echo
echo "Strings: 1M queries, exact match over 2M domains, URLs and SHA-256 digests"
for q in q_str_0.001.txt q_str_1.txt; do
    $W/compare enrich $S/bench.thrt $D/$q $T "$(expect $q)"
    $W/compare cdb $S/bench.cdb $D/$q $T "$(expect $q)"
    $W/compare lmdb $S/bench.lmdb $D/$q $T "$(expect $q)"
    $W/compare ghash $D/strings.txt $D/$q $T "$(expect $q)"
    $W/compare redis $W/redis.sock $D/$q $T "$(expect $q)"
    $W/compare redisp $W/redis.sock $D/$q $T "$(expect $q)"
done
