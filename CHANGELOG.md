# Changelog

## [0.1.1]

- `enrich` opens its config once and reads that descriptor. The size
  check no longer races a second path lookup.
- Operator manual, run by `make test`.

## [0.1.0]

- Header-only `.thrt`, overlay, and prevalence formats.
- `enrich` builds a `.thrt` from a JSON config and can fetch GeoIP,
  MISP, and plain files. It does not distribute files to edges.
