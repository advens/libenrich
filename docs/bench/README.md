# Store comparison

How fast libenrich answers "is this value a known indicator" next to the
stores a log pipeline would otherwise use for the same question. Every
store gets the same indicators and the same query stream, and a run that
does not find exactly the expected number of hits fails.

## Workloads

`gen.py` writes a fixed set (seeded, so every run gets the same data):

- IP: 1,000,000 IPv4 addresses and 50,000 IPv4 networks from /16 to
  /28, all public. A query is a hit when the address is listed or falls
  in a listed network (longest-prefix match).
- Strings: 2,000,000 values, half domains, a quarter URLs, a quarter
  SHA-256 digests. A query is a hit on an exact match.

Each workload has two query streams of 1,000,000 values: 0.1% hits,
which is what a log stream looks like, and 100% hits, the worst case
for every store.

## Stores

| Engine | Workload | What a lookup does |
|--------|----------|--------------------|
| `enrich` | both | `enrich_lookup()` on a `.thrt`: classify the value, look it up, fill the full result (confidence, TLP, categories, feeds) under the policy |
| `mmdb` | IP | MaxMind DB: `inet_pton`, `MMDB_lookup_sockaddr`, read one field |
| `mmdbstr` | IP | MaxMind DB: `MMDB_lookup_string`, read one field |
| `cdb` | strings | tinycdb: `cdb_find`, read the value |
| `lmdb` | strings | LMDB: `mdb_get` in a read transaction |
| `ghash` | strings | GLib `GHashTable` built in memory at start; a lower bound with nothing on disk |
| `redis` | strings | Redis `GET` over a Unix socket, one round trip per value |
| `redisp` | strings | Redis, 100 `GET`s per round trip |

The file-backed stores are memory-mapped and warmed by one untimed pass,
so the timings are lookups, not disk reads. `open` is the time to open
the store; for `ghash` it is the time to build the table.

## Run

```
python3 docs/bench/gen.py /tmp/bench-data
docker run --rm -v "$PWD":/src:ro -v "$PWD"/docs/bench:/bench:ro \
    -v /tmp/bench-data:/data:ro ubuntu:24.04 /bench/run.sh
```

`run.sh` installs the other stores from Ubuntu 24.04, builds libenrich
with `make`, builds every store from the same files, then runs
`compare` for each engine and stream: one warm pass, five timed passes
on one thread (the median is reported), then one pass per CPU at once.

## Results

Both runs use gcc 13.3 in an Ubuntu 24.04 container, libenrich 1.2.0
plus main, and the same generated data.

### arm64

Apple M1 (4 performance and 4 efficiency cores), container with 8 CPUs.

IP, ns per lookup on one thread, and lookups per second on 8 threads:

| Engine | 0.1% hits | 100% hits | 8 threads, 0.1% hits |
|--------|----------:|----------:|---------------------:|
| `enrich` | 131 | 125 | 34.1 M/s |
| `mmdb` | 563 | 653 | 8.3 M/s |
| `mmdbstr` | 601 | 824 | 8.9 M/s |

Strings:

| Engine | 0.1% hits | 100% hits | 8 threads, 0.1% hits |
|--------|----------:|----------:|---------------------:|
| `enrich` | 50 | 188 | 76.5 M/s |
| `ghash` (in memory) | 87 | 205 | 50.4 M/s |
| `cdb` | 151 | 225 | 27.0 M/s |
| `lmdb` | 772 | 885 | 6.4 M/s |
| `redisp` | 1,132 | 1,313 | 1.1 M/s |
| `redis` | 4,548 | 4,804 | 0.2 M/s |

Build and size for the same data:

| Store | Build | Size | Open |
|-------|------:|-----:|-----:|
| libenrich `.thrt` (IP and strings) | 23 s | 173 MB | 0.14 to 0.66 s |
| MaxMind DB (IP) | 4 s | 72 MB | under 1 ms |
| tinycdb (strings) | under 1 s | 114 MB | 9 to 14 ms |
| LMDB (strings) | under 1 s | 90 MB | 2 to 12 ms |
| Redis (strings) | 3 s load | 164 MB in memory | |
| `GHashTable` (strings) | | in memory | 0.5 to 0.6 s per start |

### x86-64

Intel Core i5-11320H (4 cores, 8 threads), Linux 7.0 host. Other jobs
ran on the machine during the run (load average 1.7 to 2.9), so the
8 thread column is the least stable one.

IP:

| Engine | 0.1% hits | 100% hits | 8 threads, 0.1% hits |
|--------|----------:|----------:|---------------------:|
| `enrich` | 169 | 174 | 44.5 M/s |
| `mmdb` | 398 | 510 | 12.4 M/s |
| `mmdbstr` | 496 | 570 | 10.0 M/s |

Strings:

| Engine | 0.1% hits | 100% hits | 8 threads, 0.1% hits |
|--------|----------:|----------:|---------------------:|
| `enrich` | 70 | 240 | 63.3 M/s |
| `ghash` (in memory) | 101 | 209 | 49.4 M/s |
| `cdb` | 119 | 196 | 39.5 M/s |
| `lmdb` | 605 | 603 | 10.6 M/s |
| `redisp` | 1,043 | 1,185 | 2.1 M/s |
| `redis` | 9,015 | 9,328 | 0.2 M/s |

Sizes are the same as on arm64. The `.thrt` built in 19 s and opened
in 0.04 s; MaxMind DB built in 3 s, tinycdb and LMDB in about 1 s,
Redis loaded in 2 s, and the `GHashTable` took 0.37 s per start.

## Reading the numbers

- A miss is the common case in a log stream. libenrich answers a string
  miss from its bloom filter without touching the hash table, which is
  why it is faster than the in-memory hash table there, on both
  machines.
- On a hit libenrich does more than the others: it fills a result with
  confidence, TLP, categories and feeds after the policy. On the M1 it
  is still at or below tinycdb and the in-memory table; on x86-64 it is
  15 to 25% slower than both when every query hits.
- IP lookups are 2.4 to 5.2 times faster than MaxMind DB on one thread
  and 3.6 to 4.5 times faster on 8.
- The cost is at build and open. The builder merges every feed, cuts
  networks so each address answers with every row that covers it, and
  writes the indexes. `enrich_open()` checks the whole file (checksum,
  bounds, indexes) before the first lookup, where MaxMind DB, tinycdb and
  LMDB read a file as given. A reload maps the new file next to the old
  one, so lookups do not wait for it.
- One libenrich file holds both workloads; the others need a store per
  kind of value.

## Not measured

- Detection engines with their own indicator matching, such as Suricata
  datasets and IP reputation, or the Zeek Intel framework. Their lookup
  runs inside packet or event processing and cannot be timed on its own
  with the same query stream.
- A cold page cache. Every timed pass runs after a warm pass.
