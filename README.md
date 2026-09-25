# libenrich

Formats and builders for the files `mmenrich` reads. The central `enrich`
command builds those files. Copying them onto edges is a separate step.

The on-disk formats (`.thrt`, `.ovly`, `.prev`) and their lookup helpers
are header-only. `libenrich.so` exports `enrich_version()` so a package
can pin the SONAME. The builders are `thrtutil`, `thrt_cli`,
`overlay_tool` (needs libfastjson), and `prev_lookup`.

`enrich build` calls `thrtutil`. `enrich apply-delta` folds one segment.
`enrich fetch` downloads GeoIP (MaxMind) and any plain `files` entries
such as `ua.json` or `tld.json`. Those are not formats this library
builds. `mmenrich` keeps using libmaxminddb for the `.mmdb`.

```
make
make test
make install PREFIX=/usr/local
```

`overlay_tool` is `make overlay` when pkg-config finds libfastjson.

MarlinOS links this library from `mmenrich` the way `mmsigma` links
`libsigma`. An upstream rsyslog tree vendors the headers and builders
next to the module. Until that cut, the rsyslog port still carries its
own copy of these sources.
