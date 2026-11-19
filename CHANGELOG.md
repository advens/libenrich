# Changelog

All notable changes to libenrich are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The shared
library SONAME is `libenrich.so.<MAJOR>`. `LIB_PATCH` in the Makefile
and `enrich_version()` are the published version.

The frozen surfaces are the C ABI and the on-disk `.thrt`, `.ovly`, and
`.prev` layouts. A change to either is called out explicitly.

## [Unreleased]

## [1.0.2] - 2026-11-19

PATCH: the overlay header compiles under strict C11. The C ABI, the
SONAME (`libenrich.so.1`), and the on-disk formats are unchanged.

### Fixed

- `thrt_overlay.h` used `O_CLOEXEC`, which glibc hides under plain
  `-std=c11`, so a consumer that includes `enrich.h` without asking for
  POSIX failed to compile. It now opens without the flag in that case.

## [1.0.1] - 2026-11-19

The 1.0.1 tag points at the 1.0.0 tree: it was pushed before the fix
merged, and release tags are not moved. Its tarball is 1.0.0. Use 1.0.2.

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

[Unreleased]: https://github.com/advens/libenrich/compare/1.0.2...HEAD
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
