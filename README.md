# libenrich

Formats and builders for the files `mmenrich` reads. The central `enrich`
command builds those files. Copying them onto edges is a separate step.

The on-disk formats (`.thrt`, `.ovly`, `.prev`) and their lookup helpers
are header-only. `libenrich.so` exports `enrich_version()` so a package
can pin the SONAME. The only command is `enrich`.

`enrich build` writes `threat.thrt` and any overlay. `enrich fetch`
downloads GeoIP, MISP, `ua.json`, and `tld.json`. `enrich run` fetches,
then builds. `enrich lookup` queries the `.thrt`. `enrich apply-delta`
folds one segment.

| mmenrich parameter | CLI feed `type` | What it is |
|---|---|---|
| `file` | `csv`, `json`, `lookup`, `txt`, `ioc`, `misp` | Public or restricted CTI compiled into `threat.thrt`. `layer` is `cti` or `cti_r`. A `misp` feed with `url` is fetched from `/attributes/restSearch` first. |
| `file` | `tags` | Context: asset, CMDB, cartography. Same `.thrt`, layer `tags`. |
| `overlay_file` | `overlay` | `.ovly` whitelist / tag / add list. |
| `geoip_db`, `geoip_asn_db` | `geoip` | MaxMind `.mmdb` download. Not a format we build. |
| `ua_file` | `ua` | `ua.json` download. |
| `tld_file` | `tld` | `tld.json` download. |
| `prevalence_db` | none | `.prev` is written by `waked/prev_write.py` from fleet counts. It is not an upstream feed. |

`file` is one database. Several feeds of the types above are layers of that file.

```
make
make test
make install PREFIX=/usr/local
enrich -c /etc/enrich.json run
```

There is one command, `enrich`. It builds the `.thrt`, writes the overlay,
downloads GeoIP, MISP, `ua.json`, and `tld.json`, and looks an indicator up.
`libfastjson` is required.

Credentials and URLs are fields of that config file. `-c` selects it.
With no `-c`, `enrich` reads `./enrich.json`, then `/etc/enrich.json`.
Keep the file mode `0600`. `enrich.json.example` shows the fields.
`geoip.account_id`, `geoip.license_key`, each `misp` feed's `url` and
`key`, and each `ua` / `tld` feed's `url` are all in that file.

MarlinOS links this library from `mmenrich` the way `mmsigma` links
`libsigma`. An upstream rsyslog tree vendors the headers and builders
next to the module. Until that cut, the rsyslog port still carries its
own copy of these sources.
