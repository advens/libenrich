# Changelog

All notable changes to libenrich are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The shared
library SONAME is `libenrich.so.<MAJOR>`. `LIB_PATCH` in the Makefile
and `enrich_version()` are the published version.

The frozen surfaces are the C ABI and the on-disk `.thrt`, `.ovly`, and
`.prev` layouts. A change to either is called out explicitly.

## [Unreleased]

## [1.1.4] - 2026-11-20

PATCH: faster string lookups, a bloom filter sized to the database,
and a fuzz target for `.prev` files. The C ABI and the SONAME
(`libenrich.so.1`) are unchanged. The `.thrt` layout is unchanged; the
reader now also refuses a bloom filter size no builder ever wrote.

### Added

- The fuzz harness covers `.prev` files (`FUZZ_TARGET=prev`), and the
  `.thrt` target cuts the bloom filter out of its seed, so a run checks
  a few hundred KB instead of the whole file.

### Changed

- String lookups find the bloom filter bits with a mask instead of a
  division. On FreeBSD amd64 (i9-13900H, one pinned core, five
  alternated runs) a domain lookup drops from 57.4 to 55.7 ns and a
  SHA-256 lookup from 42.4 to 38.6 ns; an M1 shows no difference. The
  probes are the same bits, so existing files read the same.
- The builder sizes the bloom filter to the database: 32 bits per
  string, a power of two from 64 Kbit up to the former fixed 64 Mbit.
  A database of a few thousand strings shrinks from 8.9 MB to 550 KB.
  A database past about two million strings keeps 64 Mbit.
- The reader refuses a bloom filter whose size is not a power of two.
  Every builder release wrote 64 Mbit, so no existing file is refused.

## [1.1.3] - 2026-11-20

PATCH: the builder refuses a string table a lookup cannot walk, and the
IPv6 parser and two builder helpers build under -Winline. The C ABI,
the SONAME (`libenrich.so.1`), and the on-disk formats are unchanged.

### Security

- The builder refuses a string table where an entry sits 128 or more
  slots from its home slot, the distance a lookup walks before it gives
  up. The string hash is CRC32C, so a feed could ship values whose home
  slots pile up on the slot of a value another feed lists and make that
  value unfindable, with no error. The build now fails, names the feeds
  holding the run, and keeps the previous database. Natural tables stay
  far below the bound (14 slots at most on a 2.3 million string build).
  Lookups and the on-disk format are unchanged.

### Fixed

- 1.1.2's `thrt_ipv6_strict()` was `static inline` and too large for
  GCC to inline at -O2; rsyslog, which builds these sources with
  `-Winline -Werror`, stopped there. It is `static` and marked unused,
  as `parse_prefix_len()`, `ioc_type_is_ip()`, `prev_table_map()`,
  `prev_lookup()` and `prev_hash()` are now too. An IPv6
  lookup did not slow down: 177 ns against 262 ns for 1.1.2 on an M1.
- `-Winline` is part of the library's warning flags, so the tests,
  built with `-Werror` (`test_prev` too, now), catch a header function
  the compiler will not inline before a project that vendors the header
  does.

## [1.1.2] - 2026-11-19

PATCH: IPv6 lookups are parsed without the libc, and the builder no
longer wraps or overflows what it reads from feeds. The C ABI, the
SONAME (`libenrich.so.1`), and the on-disk formats are unchanged.

### Changed

- `thrt_ipv6_strict()` parses IPv6 text itself instead of filtering it
  and calling `inet_pton()`, which cost 180 to 300 ns per address. It
  accepts and rejects exactly what `inet_pton(AF_INET6)` does on glibc
  and FreeBSD, checked on 3 million generated, mutated and random
  inputs. macOS also takes a hex group of more than four digits when
  the extra digits are leading zeros, and an embedded IPv4 octet with a
  leading zero; those are refused now on every platform, as IPv4 already
  was. An IPv6 lookup on FreeBSD amd64 drops from 390 to 225 ns.

### Fixed

- A feed's `confidence` was read with `atoi()` into a `uint8_t`: 300
  became 44, and a number past `INT_MAX` was undefined behaviour. It is
  clamped to 0..100 now. The category number is read the same way.
- `--ttl-days` and `--generation` took any text: `--ttl-days -3` became
  4294967293 days. Anything but a whole number is refused.
- The tags CSV built its JSON array with `strcat()`. It was bounded by a
  check before, but rescanned the buffer for every tag; it writes at a
  tracked offset now.
- `enrich sync --hup` without `--hup-cmd` ran `pgrep` through a shell
  (`popen()`) off Linux. It runs `pgrep` directly.

## [1.1.1] - 2026-11-19

PATCH: the sources build with -Winline -Wmissing-prototypes -Werror, and
make install writes an enrich.pc for its PREFIX. The C ABI, the SONAME (`libenrich.so.1`),
and the on-disk formats are unchanged.

### Fixed

- `prev_siphash()` in `prev_format.h` was `static inline`. GCC does not
  inline it at -O2 in a module that calls it from several places, and a
  project that builds with `-Winline -Werror`, as rsyslog does from git,
  stopped there. It is `static` and marked unused now; the compiler
  still inlines it where that pays. `thrt_valid_err()`, which takes a
  variable argument list and can never be inlined, and `thrt_validate()`
  in `thrt_validate.h` get the same treatment.
- `thrtutil.c` defined `thrt_fold_begin()`, `thrt_fold_page()`,
  `thrt_fold_commit()` and `thrt_fold_abort()` with no prototype, which
  `-Wmissing-prototypes -Werror` refuses. Each now has one, as
  `thrt_misp_delta_mode()` already did.
- `make install PREFIX=...` copied the `enrich.pc` written at build time,
  so a build without `PREFIX` and an install with it left a pkg-config
  file that pointed at `/usr/local`. Install writes it for its own
  `PREFIX`.

## [1.1.0] - 2026-11-19

MINOR: `enrich sync` pulls a MISP window in slices it sizes itself, and
`--slice-rows` sets the size. The C ABI, the SONAME (`libenrich.so.1`),
and the on-disk formats are unchanged.

### Changed

- `enrich sync` cuts a MISP window into slices on the event publish
  time (`"last":[lo,hi]`). A slice is checked with one request for the
  attribute just past `--slice-rows` (ten pages by default) and cut in
  two while it holds more, so no page starts deeper than that. One
  second is never cut. MISP pages with an SQL offset, so a single window
  cost every earlier row on each page: on a MISP whose 180-day
  window holds 2.9 million attributes, 89% of them imported on one day,
  the full pull at 2000 rows a page was on course for over two hours.
  It now takes 23 minutes and pulls the same 3.6 GB.
- An incremental pull no longer starts before `since`: a cursor older
  than the window a full pull would cover is moved up to it.

## [1.0.4] - 2026-11-19

PATCH: credentials stay off the process list, and opening a `.prev` of
another version no longer crashes. The C ABI, the SONAME
(`libenrich.so.1`), and the on-disk formats are unchanged.

### Security

- `enrich` passed the MISP automation key (`-H Authorization: ...`) and
  the MaxMind account and license key (`-u ...`) to curl as arguments,
  which every local user can read in the process list. curl now reads
  them as a config on its standard input (`-K -`). Rotate a key that was
  in use on a host shared with other users.

### Fixed

- `enrich_open()` and `enrich_reload()` unmapped a `.prev` of another
  version, then read its version number for the error message. A host
  still holding a version 2 `.prev` crashed at configuration load.

## [1.0.3] - 2026-11-19

PATCH: the overlay header compiles under strict C11. The C ABI, the
SONAME (`libenrich.so.1`), and the on-disk formats are unchanged.

### Fixed

- `thrt_overlay.h` used `O_CLOEXEC`, which glibc hides under plain
  `-std=c11`, so a consumer that includes `enrich.h` without asking for
  POSIX failed to compile. It now opens without the flag in that case.

## [1.0.2] - 2026-11-19

The 1.0.2 tag was pushed before its version bump merged. Its tarball
has the strict C11 fix, but its files still say 1.0.1
(`libenrich.so.1.0.1`, `enrich_version()`). Use 1.0.3.

## [1.0.1] - 2026-11-19

The 1.0.1 tag points at the 1.0.0 tree: it was pushed before the fix
merged, and release tags are not moved. Its tarball is 1.0.0. Use 1.0.3.

## [1.0.0] - 2026-11-19

MAJOR: a compiled lookup API, and new `.thrt`, overlay and `.prev`
formats. Contract: abi (the SONAME is now `libenrich.so.1`) and format
(`.thrt` version 5, overlay version 2, `.prev` version 3; older files
are refused).

### Added

- `enrich.h` lookup API in `libenrich.so`: `enrich_open`,
  `enrich_reload`, per-thread readers with quiescent-state reclamation,
  `enrich_lookup`, `enrich_lookup_batch`, `enrich_event_fold`,
  `enrich_prevalence`, and name and snapshot helpers. Every file is
  validated (version, offsets, indices, CRC32C) before it is published.
  Values are counted, never truncated, and refused past 4096 bytes.
- `make sanitize` (ASan, UBSan, TSan) and `make fuzz` (libFuzzer).
- An overlay tag entry takes a `tags` array.
- `enrich_open()` takes any non-empty subset of the three files, so a
  rule engine can open a `.prev` alone.

### Changed

- `.thrt` version 5. Confidence, TLP, categories and feed names describe
  the public CTI layer only. A restricted source adds the CTI_R layer and
  `confidence_r`, never a feed name, a marking, a category or a label.
  The header lists the public feeds (`public_feed_mask`). A record keeps
  the labels of public CTI (MISP tags, STIX labels) apart from the
  context tags of the tags layer, and the result carries both. The
  network rows as declared are stored next to the disjoint lookup
  pieces, so a fold works on exact networks.
- `.prev` version 3. Rows are keyed by SipHash-1-3 under a random
  128-bit key stored in the header, instead of unkeyed FNV-1a.
  `prev_lookup()` takes the header.
- Overlay version 2 stores each value and a lookup compares it. Version
  1 matched on the 32-bit CRC alone. An `ioc` listed twice, or longer
  than 4096 bytes, is an error. The file is written through a temporary
  name and a rename.
- `enrich lookup` goes through the API, prints a restricted match as
  its score only, and prints labels and tags on separate lines.
- When two sources tag or label one indicator, the record keeps the
  union of their tags and of their labels instead of the first set.
- A fold validates the existing database like a reader does before it
  reads it, and a write that fails (a full disk) is not renamed over
  the live file.

### Fixed

- A restricted feed name, marking, category or score could be printed
  under the public CTI fields of an indicator that a public feed also
  listed.
- A full build kept one row per feed and layer for the same indicator,
  and a lookup returned one of them: a public match could read as a tag
  only. Rows now merge in full builds as they did in folds.
- Overlapping networks broke the binary search. Ranges are cut into
  disjoint pieces at write time, each with the merge of every row that
  covers it.
- A fold merged two different strings with the same 32-bit CRC into one
  row, and a withdrawal removed every indicator sharing the withdrawn
  value's CRC. Both now compare the exact range or string.
- The bloom filter's second hash was always zero, so its three probes
  hit one bit. It now uses a mixed second hash.
- A prevalence row was found by an unkeyed 64-bit FNV-1a hash, so a name
  could be chosen to collide with a common one and read as common.
- Addresses were read with `inet_pton()`, which takes `01.2.3.4` and a
  `%zone` on macOS but not on glibc or FreeBSD. One strict parser now
  serves the builder and the lookups on every platform.

## [0.1.7] - 2026-11-17

PATCH: a sync writes the threat database once. The C ABI, the SONAME
(`libenrich.so.0`), and the on-disk formats are unchanged.

### Fixed

- `enrich sync` writes the threat database once per pull. Each MISP
  page is still released before the next request. A later page adds
  to that feed instead of replacing it. A later window is one
  generation. The C ABI, the SONAME (`libenrich.so.0`), and the
  on-disk formats are unchanged.

## [0.1.6] - 2026-11-16

PATCH: each MISP page is folded and released. The C ABI, the SONAME
(`libenrich.so.0`), and the on-disk formats are unchanged.

### Fixed

- `enrich sync` no longer keeps every MISP page in memory. Each page
  is folded with `apply-delta` and released. The first page of a first
  pull or `--full` is a snapshot of that feed. Later pages of that
  pull add to it. `dest` is still one attribute-search body. The
  on-disk `.thrt` layout is unchanged.

## [0.1.5] - 2026-11-10

- `thrt_overlay_load` and `parse_ip_or_cidr` are no longer declared
  inline, and `thrt_hash`, `thrt_lookup_ip`, and `crc32c_platform` are
  always inlined, so the headers build without `-Winline` warnings.
  Lookup results are unchanged.

## [0.1.4] - 2026-11-10

- thrtutil, thrt_cli, and the shared headers build without warnings
  under rsyslog's warning flags.
- A STIX hash longer than its field is dropped instead of stored cut
  off. A TLP marking whose name does not fit its field is not
  registered, so an indicator that references it gets amber.
- thrtutil pads the string pool so the IPv4 accelerator table starts
  on an 8-byte boundary. A 0.1.3 reader loads the new files.
  `thrt_lookup_ip_accel` copies each slot, so a file written by 0.1.3
  loads without a misaligned access.

## [0.1.3] - 2026-10-14

- `enrich sync` pages one MISP feed into `dest` and a `.cursor` file.
  The first pull, and `--full`, compiles `output` through `build`.
  A later window is one `apply-delta` generation. `--segment` folds a
  file already on disk. `--follow` needs libzmq and exits 2 without it.
  The on-disk `.thrt` layout is unchanged.

## [0.1.2] - 2026-10-08

- `enrich` compiles a STIX 2.1 bundle, and a 2.0 indicator of the same
  shape, into the threat database. `fetch` GETs one bundle when the
  feed has a `url`. `apply-delta` accepts a `.stix` or `.stix.json`
  segment. The on-disk `.thrt` layout is unchanged.
- A full build keeps a leading NUL in the string pool, so the first
  tag list is stored at a non-zero offset and `lookup` prints it.
- `enrich` compiles the attribute search returned by
  `/attributes/restSearch` (`{"response":{"Attribute":[...]}}`),
  including a nested Event on each attribute. An empty GeoIP account
  id and license key skip the GeoIP download. `fetch` creates the
  directory that holds a download. The MISP POST sends
  `Accept: application/json` and `Content-Type: application/json`.

## [0.1.1] - 2026-10-04

- `enrich` opens its config once and reads that descriptor. The size
  check no longer races a second path lookup.
- Operator manual, run by `make test`.

## [0.1.0] - 2026-09-25

- Header-only `.thrt`, overlay, and prevalence formats.
- `enrich` builds a `.thrt` from a JSON config and can fetch GeoIP,
  MISP, and plain files. It does not distribute files to edges.

[Unreleased]: https://github.com/advens/libenrich/compare/1.0.4...HEAD
[1.0.4]: https://github.com/advens/libenrich/releases/tag/1.0.4
[1.0.3]: https://github.com/advens/libenrich/releases/tag/1.0.3
[1.0.2]: https://github.com/advens/libenrich/releases/tag/1.0.2
[1.0.1]: https://github.com/advens/libenrich/releases/tag/1.0.1
[1.0.0]: https://github.com/advens/libenrich/releases/tag/1.0.0
[0.1.7]: https://github.com/advens/libenrich/releases/tag/0.1.7
[0.1.6]: https://github.com/advens/libenrich/releases/tag/0.1.6
[0.1.5]: https://github.com/advens/libenrich/releases/tag/0.1.5
[0.1.4]: https://github.com/advens/libenrich/releases/tag/0.1.4
[0.1.3]: https://github.com/advens/libenrich/releases/tag/0.1.3
[0.1.2]: https://github.com/advens/libenrich/releases/tag/0.1.2
[0.1.1]: https://github.com/advens/libenrich/releases/tag/0.1.1
[0.1.0]: https://github.com/advens/libenrich/releases/tag/0.1.0
