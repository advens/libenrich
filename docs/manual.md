# enrich

One command reads one JSON file and writes the files a log enricher
loads. This page is the manual. `docs/check.sh` runs the worked example
and fails if a lookup does not come back in the layer that file claims.
`make test` runs that script.

## Install

```
make
make install PREFIX=/usr/local
```

`pkg-config libfastjson` must succeed. The install puts `enrich` and
`thrtutil` on `PATH`. `thrtutil` is the same builder for a caller that
already passes `-o`, `-l`, and `--apply-delta`. New use is `enrich`.

## Config file

`-c` selects the file. With no `-c`, `enrich` reads `./enrich.json`,
then `/etc/enrich.json`.

Put the MaxMind account id, the license key, and every MISP token in
that file. Keep it mode `0600`. An empty license key does not warn. A
non-empty license key in a file that is readable by group or other
does.

`output` is the threat database (`.thrt`). Every local indicator feed
is a layer of that one file.

## Commands

```
enrich -c enrich.json fetch
enrich -c enrich.json build
enrich -c enrich.json run
enrich -c enrich.json lookup 203.0.113.50
enrich -c enrich.json apply-delta --segment delta.csv --feed-key delta
```

`fetch` downloads GeoIP, every MISP feed that has a `url`, and every
`ua` or `tld` feed. `build` compiles `output` and writes each overlay.
`run` is fetch, then build. `lookup` queries `output` only. It does
not query an overlay. `apply-delta` folds one CSV or MISP JSON segment
into `output`.

## MISP

Live pull. `url` is the server, with no path. `key` is the automation
token. `since` is the MISP `last` window. `dest` is the file that is
written, and the file `build` then compiles.

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

`enrich fetch` sends:

```
POST https://misp.example/attributes/restSearch
Authorization: <key>
Content-Type: application/json

{"returnFormat":"json","last":"7d","to_ids":1,"limit":10000}
```

The response body is stored at `dest` unchanged. `build` accepts that
body when it is a MISP event (`{"Event":{...}}`) or a search response
(`{"response":[...]}`). An attribute is kept when `to_ids` is true.

A feed with `path` and no `url` does not call the server. It compiles
the file you already have. `docs/examples/event.misp.json` is that
shape. `docs/check.sh` compiles it. The live POST is not run by the
check: it needs a server and a token.

## Local indicators

`layer` is `cti` (public) or `cti_r` (restricted). Omitted means `cti`,
except `tags`, which defaults to the context layer.

CSV, no header required. Columns are type, value, confidence, category,
feed, tlp:

```
ip,203.0.113.50,80,scanner,sample,green
```

Dictionary JSON. One object, indicator to record:

```json
{"203.0.113.51":{"tlp":"clear","feed":["sample"],"max_score":70,"type":"ip"}}
```

Lookup JSON. Each record has `index` and `value`. `value` is a JSON
object, stored as a string:

```json
{"index":"203.0.113.52","value":"{\"tlp\":\"clear\",\"max_score\":\"60\",\"type\":\"ip\",\"feed\":\"sample\"}"}
```

Plain text, extension `.txt` or `.ioc`. One indicator per line. Blank
lines and lines starting with `#` or `;` are skipped:

```
203.0.113.53
```

A saved MISP file must be named `.misp` or `.misp.json`.

## Context

Same database, layer `tags`.

CSV, extension `.tags`. The value, then the tags:

```
203.0.113.57,asset,lab
```

JSON, the name must contain `.tags.json`, one object per line:

```json
{"index":"203.0.113.58","tags":["lab","asset"]}
```

`lookup` prints `Type: TAGS` and a `Tags` line.

## Overlay

Not a layer of the threat database. `path` is the JSON. `dest` is the
`.ovly`.

```json
{"entries":[{"ioc":"203.0.113.59","action":"whitelist"}]}
```

`action` is `whitelist` (also `suppress` or `-`), `tag` (also `T`), or
anything else, which means add. `enrich build` writes `dest` and prints
the entry count. There is no `enrich` subcommand that queries an
overlay.

## GeoIP

Top-level object, not a row of `feeds`.

```json
"geoip": {
  "account_id": "",
  "license_key": "",
  "dest_dir": "/var/lib/enrich",
  "editions": ["GeoLite2-City", "GeoLite2-ASN"]
}
```

`fetch` asks MaxMind for each edition:

```
GET https://download.maxmind.com/geoip/databases/<edition>/download?suffix=tar.gz.sha256
```

Basic authentication is `account_id:license_key`. If that checksum
matches `<dest_dir>/<edition>.sha256` and `<dest_dir>/<edition>.mmdb`
is present, the archive is not downloaded. Otherwise the `.tar.gz` is
downloaded and the `.mmdb` member is extracted. How often you run
`fetch` is your cron. The config has no age field.

## User-agent and suffix tables

```json
{"name": "ua", "type": "ua", "url": "https://example.invalid/ua.json", "dest": "/var/lib/enrich/ua.json"}
{"name": "tld", "type": "tld", "url": "https://example.invalid/tld.json", "dest": "/var/lib/enrich/tld.json"}
```

`fetch` saves the response body at `dest`. This tool does not interpret
those files.

## Delta

`apply-delta` reads a CSV. With no header, column 0 is the indicator
and a leading `+` or `-` is the action (`+,203.0.113.60` adds,
`-,203.0.113.60` deletes). With a header, name the columns. This is
the file `docs/check.sh` folds:

```
action,type,indicator,confidence,category,feed,tlp
+,ip,203.0.113.60,70,scanner,delta,green
```

```
enrich -c enrich.json apply-delta --segment delta.csv --feed-key delta
```

`--snapshot` drops that feed's previous indicators before adding the
segment. `--ttl-days N` drops other feeds whose last fold is older
than N days. `--generation G` drops the segment when G is not greater
than the generation already stored for that feed. The generation file
is `<output>.gen`.

A segment named `.misp.json` is parsed as MISP. Any other `.json`
segment is also parsed as MISP, not as a dictionary. Use `.csv` for a
CSV delta.

## Worked example

From the repository root, after `make`:

```
sh docs/check.sh
```

That is `docs/examples/enrich.json` plus the files next to it. It
builds `build/docs/threat.thrt` and `build/docs/allow.ovly`, checks
nine lookups, folds `docs/examples/delta.csv`, and checks the tenth.

What `lookup` prints for the CSV row:

```
Checking: 203.0.113.50
[*] Type: IPv4

[WARN] >>> MATCH FOUND! <<<
   Confidence : 80%
   Type       : CTI
   TLP        : GREEN
   Categories : Scanner (0x0100)
   Feeds      : sample
```

The other rows, checked by the script:

| Indicator | File | Type |
|---|---|---|
| 203.0.113.50 | public.csv | CTI |
| 203.0.113.51 | dictionary.json | CTI |
| 203.0.113.52 | table.lookup | CTI |
| 203.0.113.53 | iocs.txt | CTI |
| 203.0.113.54 | iocs.ioc | CTI |
| 203.0.113.55 | event.misp.json | CTI |
| 203.0.113.56 | restricted.csv | CTI_R |
| 203.0.113.57 | cmdb.tags | TAGS, tags `["asset","lab"]` |
| 203.0.113.58 | carto.tags.json | TAGS, tags `["lab","asset"]` |
| 203.0.113.60 | delta.csv, after apply-delta | CTI |

The overlay write prints:

```
wrote build/docs/allow.ovly (68 bytes, 1 entries)
  WHITELIST 203.0.113.59  hash=0xa613971f  action='-'
```

## Not built here

A prevalence table (`.prev`) is not a feed. This tool does not download
one and does not compile one.
