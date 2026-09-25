# libenrich

Build the files a log enricher reads. The manual, with a worked
example that `make test` runs, is [docs/manual.md](docs/manual.md).

Feeds:

- MISP. `url`, `key`, and `since` pull `/attributes/restSearch`. The body is saved as `.misp.json` and compiled into the threat database.
- Local indicators. `csv`, `json`, `lookup`, `txt`, `ioc`, and a `.misp.json` you already have. `layer` is `cti` or `cti_r`.
- Context. `tags` for an asset, an inventory, or a cartography file. Same database, layer `tags`.
- Overlay. A whitelist, tag, or add list (`.ovly`).
- GeoIP. MaxMind City and ASN. The checksum skips an unchanged archive.
- User-agent table and public-suffix table. Plain downloads.

```
make
make test
make install PREFIX=/usr/local
```

`libfastjson` is required (`pkg-config libfastjson`).

## One command

```
enrich -c /etc/enrich.json fetch
enrich -c /etc/enrich.json build
enrich -c /etc/enrich.json run
enrich -c /etc/enrich.json lookup 203.0.113.7
enrich -c /etc/enrich.json apply-delta --segment /var/lib/enrich/delta.csv \
    --feed-key public --snapshot --ttl-days 30 --generation 2
```

`fetch` downloads GeoIP, every MISP feed that has a `url`, the
user-agent table, and the public-suffix table. `build` compiles
`threat.thrt` (including the saved MISP file and the context layer)
and the overlay. `run` is fetch, then build. `lookup` queries the
database named by `output`. `apply-delta` folds one segment into
that database.

MISP in the config, on its own:

```json
{
  "name": "misp",
  "type": "misp",
  "layer": "cti",
  "url": "https://misp.example",
  "key": "",
  "since": "7d",
  "dest": "/var/lib/enrich/misp.misp.json"
}
```

`url` is the server, with no path. `key` is the automation token.
`since` is the MISP `last` window (`7d`, `30d`). `dest` is where the
JSON is written. `enrich run` fetches it, then compiles `dest` into
`output`. A feed with `path` and no `url` compiles a `.misp.json` you
already downloaded.

With no `-c`, `enrich` reads `./enrich.json`, then `/etc/enrich.json`.
Keep the file mode `0600`. Account ids, license keys, and tokens are
fields in that file. They are not environment variables.

A GeoIP `fetch` downloads the edition checksum every time. The archive
is skipped when that checksum matches the local database.

## Config

```json
{
  "output": "/var/lib/enrich/threat.thrt",
  "geoip": {
    "account_id": "",
    "license_key": "",
    "dest_dir": "/var/lib/enrich",
    "editions": ["GeoLite2-City", "GeoLite2-ASN"]
  },
  "feeds": [
    {"name": "public-csv", "type": "csv", "layer": "cti", "path": "/var/lib/enrich/public.csv"},
    {"name": "public-json", "type": "json", "layer": "cti", "path": "/var/lib/enrich/cti.json"},
    {"name": "lookup", "type": "lookup", "layer": "cti", "path": "/var/lib/enrich/table.lookup"},
    {"name": "plain", "type": "txt", "layer": "cti", "path": "/var/lib/enrich/iocs.txt"},
    {"name": "ioc-list", "type": "ioc", "layer": "cti", "path": "/var/lib/enrich/iocs.ioc"},
    {"name": "restricted", "type": "csv", "layer": "cti_r", "path": "/var/lib/enrich/restricted.csv"},
    {"name": "misp", "type": "misp", "layer": "cti", "url": "https://misp.example", "key": "", "since": "7d", "dest": "/var/lib/enrich/misp.misp.json"},
    {"name": "cmdb", "type": "tags", "path": "/var/lib/enrich/cmdb.tags"},
    {"name": "cartography", "type": "tags", "path": "/var/lib/enrich/carto.tags.json"},
    {"name": "ua", "type": "ua", "url": "https://example.invalid/ua.json", "dest": "/var/lib/enrich/ua.json"},
    {"name": "tld", "type": "tld", "url": "https://example.invalid/tld.json", "dest": "/var/lib/enrich/tld.json"},
    {"name": "overlay", "type": "overlay", "path": "/var/lib/enrich/allow.json", "dest": "/var/lib/enrich/allow.ovly"}
  ]
}
```

| Output | Feed `type` | Role |
|---|---|---|
| `output` (`.thrt`) | `csv`, `json`, `lookup`, `txt`, `ioc`, `misp` | Threat indicators. `layer` is `cti` or `cti_r`. A `misp` feed with `url` is fetched from `/attributes/restSearch` into `dest` before the build. |
| same file | `tags` | Context: asset, inventory, cartography. A path ending in `.tags.json` is the JSON form. |
| `dest` of `overlay` | `overlay` | Whitelist, tag, or add list (`.ovly`). |
| `dest_dir`/`edition`.mmdb | `geoip` | MaxMind City and ASN databases. The checksum skips an unchanged archive. |
| `dest` of `ua` | `ua` | User-agent table (`ua.json`). |
| `dest` of `tld` | `tld` | Public-suffix table (`tld.json`). |

Prevalence tables are not built here. They come from the counts a
deployment already has.

## Library

Headers install under `include/enrich/`. `libenrich.so` exports
`enrich_version()`. The on-disk formats are header-only. Link with
`pkg-config enrich`.
