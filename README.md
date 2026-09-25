# libenrich

Formats and builders for the files `mmenrich` reads. The central `enrich`
command builds those files. Copying them onto edges is a separate step.

The on-disk formats (`.thrt`, `.ovly`, `.prev`) and their lookup helpers
are header-only. `libenrich.so` exports `enrich_version()` so a package
can pin the SONAME. The builders are `thrtutil`, `thrt_cli`,
`overlay_tool` (needs libfastjson), and `prev_lookup`.

`enrich build` calls `thrtutil` for every local feed, and `overlay_tool`
when an overlay feed is set. `enrich fetch` downloads the remote ones.
`enrich run` fetches, then builds. `enrich apply-delta` folds one
segment into the `.thrt`.

| mmenrich parameter | CLI feed `type` | What it is |
|---|---|---|
| `file` | `csv`, `json`, `lookup`, `txt`, `ioc`, `misp` | Public or restricted CTI compiled into `threat.thrt`. `layer` is `cti` or `cti_r`. A `misp` feed with `url` is fetched from `/attributes/restSearch` first. |
| `file` | `tags` | Context: asset, CMDB, cartography. Same `.thrt`, layer `tags`. |
| `overlay_file` | `overlay` | `.ovly` whitelist / tag / add list. Needs `make overlay`. |
| `geoip_db`, `geoip_asn_db` | `geoip` | MaxMind `.mmdb` download. Not a format we build. |
| `ua_file` | `ua` | `ua.json` download. |
| `tld_file` | `tld` | `tld.json` download. |
| `prevalence_db` | none | `.prev` is written by `waked/prev_write.py` from fleet counts. It is not an upstream feed. |

`file` is one database. Several feeds of the types above are layers of that file.

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
