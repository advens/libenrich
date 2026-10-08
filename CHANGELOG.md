# Changelog

## [Unreleased]

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

## [0.1.1]

- `enrich` opens its config once and reads that descriptor. The size
  check no longer races a second path lookup.
- Operator manual, run by `make test`.

## [0.1.0]

- Header-only `.thrt`, overlay, and prevalence formats.
- `enrich` builds a `.thrt` from a JSON config and can fetch GeoIP,
  MISP, and plain files. It does not distribute files to edges.
