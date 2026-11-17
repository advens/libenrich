# Changelog

All notable changes to libenrich are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The shared
library SONAME is `libenrich.so.<MAJOR>`. `LIB_PATCH` in the Makefile
and `enrich_version()` are the published version.

The frozen surfaces are the C ABI and the on-disk `.thrt`, `.ovly`, and
`.prev` layouts. A change to either is called out explicitly.

## [Unreleased]

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

[Unreleased]: https://github.com/advens/libenrich/compare/0.1.6...HEAD
[0.1.6]: https://github.com/advens/libenrich/releases/tag/0.1.6
[0.1.5]: https://github.com/advens/libenrich/releases/tag/0.1.5
[0.1.4]: https://github.com/advens/libenrich/releases/tag/0.1.4
[0.1.3]: https://github.com/advens/libenrich/releases/tag/0.1.3
[0.1.2]: https://github.com/advens/libenrich/releases/tag/0.1.2
[0.1.1]: https://github.com/advens/libenrich/releases/tag/0.1.1
[0.1.0]: https://github.com/advens/libenrich/releases/tag/0.1.0
