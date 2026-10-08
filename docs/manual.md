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

`pkg-config libfastjson` must succeed. The install puts `enrich` on
`PATH`.

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
enrich -c enrich.json apply-delta --segment delta.stix.json --feed-key stix-delta
```

`fetch` downloads GeoIP, every MISP feed that has a `url`, every STIX
feed that has a `url`, and every `ua` or `tld` feed. `build` compiles
`output` and writes each overlay. `run` is fetch, then build. `lookup`
queries `output` only. It does not query an overlay. `apply-delta`
folds one CSV, MISP, or STIX segment into `output`.

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

The response body is stored at `dest` unchanged. `fetch` creates the
directory that holds `dest`. `build` compiles that body in any of
these shapes:

- a single event, `{"Event":{...}}`
- an event search, `{"response":[{"Event":{...}}]}`
- an attribute search, `{"response":{"Attribute":[...]}}`, which is what this POST returns
- an attribute list, `{"Attribute":[...]}`

A nested `Event` on an attribute supplies the event info, the threat
level, and the event tags. An attribute is kept when `to_ids` is true.
The request asks for at most 10000 attributes. `docs/check.sh` compiles
`docs/examples/event.misp.json` and `docs/examples/attributes.misp.json`.
The live POST is not run by the check: it needs a server and a token.

A feed with `path` and no `url` does not call the server. It compiles
the file you already have. An empty GeoIP account id and license key
in the same file skip the GeoIP download, so this fetch still runs.

## STIX 2.1

A feed of type `stix` compiles a STIX bundle into the same threat
database as MISP and CSV. `layer` is `cti` or `cti_r`. The bundle does
not choose the layer.

Live pull. `url` is the address of one bundle. `dest` is the file
`fetch` writes and `build` then compiles. The request is one GET, with
no body.

```json
{
  "name": "stix",
  "type": "stix",
  "layer": "cti",
  "url": "https://cti.example/bundle.json",
  "dest": "/var/lib/enrich/bundle.stix.json"
}
```

Name `dest` so it ends in `.stix` or `.stix.json`. A feed with `path`
and no `url` compiles a file you already have, with the same suffix.
`docs/examples/indicators.stix.json` is that shape. `docs/check.sh`
compiles it. The live GET is not run by the check.

The file may be a bundle (`{"type":"bundle","objects":[...]}`), one
object, or an array of objects. `spec_version` is `2.1`, `2.0`, or
omitted. A file whose `spec_version` is anything else produces no row.
An `indicator` with `pattern_type` `stix`, or with `pattern_type`
omitted, is compiled. `pattern_type` `snort`, `yara`, `pcre`, or
`sigma` produces no row.

Each `=` and each `IN` literal becomes one indicator. `AND` and `OR`
both do that: every indexable value is stored on its own, and a later
lookup hits any one of them. Parentheses group the expression. A
pattern that contains `FOLLOWEDBY` outside a quoted string produces no
row. `LIKE`, `MATCHES`, `!=`, `<`, `>`, `ISSUBSET`, and `ISSUPERSET`
produce no row for that comparison. `WITHIN`, `REPEATS`, `START`, and
`STOP` are ignored. A pattern longer than 8 MiB is dropped. Nesting
deeper than 32 stops that expression.

A string literal uses single quotes. `\\` in the pattern is one
backslash, so `'Global\\StixLab'` is stored as `Global\StixLab`. A hex
literal `h'HH'` is stored as that hex text. An integer literal is
stored as its decimal text. Domain names, email addresses, and the
hash types below are stored in lower case. A URL keeps its case.

| Pattern object | Stored as |
|---|---|
| `ipv4-addr:value`, `ipv6-addr:value` | `ip`. A CIDR is a range. |
| `domain-name:value` | `domain` |
| `url:value` | `url` |
| `email-addr:value` | `email` |
| `mac-addr:value` | `mac` |
| `mutex:value` | `mutex` |
| `windows-registry-key:key` | `registry` |
| `autonomous-system:number` | `asn` |
| `user-account:user_id`, `user-account:account_login` | `user` |
| `directory:path` | `path` |
| `file:name`, `artifact:name` | `filename` |
| `file`, `artifact`, or `x509-certificate` hashes `MD5`, `SHA-1`, `SHA-256`, `SHA-512` | `md5`, `sha1`, `sha256`, `sha512` |
| hash `SSDEEP` | `ssdeep`, case kept |
| any other hash algorithm | `hash` |
| `x509-certificate:serial_number` | `x509` |

A property whose name ends in `_ref` or `_refs` is skipped.
`software:name`, `process:name`, `process:pid`,
`email-message:subject`, and network-traffic ports are not indexed.

`confidence` is 0 to 100. Omitted means 50. A fractional part is
dropped, so `85.0` is 85. `indicator_types` use the same category
words as a CSV row: `malicious-activity` is attack,
`malicious-command-and-control` is C2, `anonymization` is proxy,
`compromised`, `anomalous-activity`, and `attribution` are attack, and
`malware`, `ransomware`, `exploit`, `phish`, `botnet`, `spam`, `scan`,
and `tor` use those names. An indicator whose types are only `benign`
produces no row. The name and the indicator types are stored as tags
when they contain no quote.

`valid_from` in the future produces no row. `valid_until` in the past,
and `revoked` true, produce no row on `build`. On `apply-delta` those
two delete that value.

When the bundle contains no `indicator`, cyber-observable objects of
the types in the table are compiled from their own fields. A bundle
that has at least one `indicator` leaves those objects unused.
`observed-data`, `relationship`, `malware`, `campaign`,
`threat-actor`, `report`, and `sighting` produce no row.

Markings. The most restrictive mark wins: red, then amber (including
amber+strict), then green, then clear. Clear prints as `WHITE`. An
indicator with no marking is amber. These ids are recognized with or
without a `marking-definition` object in the bundle.

STIX 2.1: white `613f2e26-407d-48c7-9eca-b8e91df99dc9`, green
`34098fce-860f-48ae-8e50-ebd3cc5e41da`, amber
`f88d31f6-486f-44da-b317-01333bde0b82`, red
`5e57c739-391a-4eb3-b6be-7d15ca92d5ed`.

TLP 2.0: clear `94868c89-83c2-464b-929b-a1a8aa3c8487`, green
`bab4a63c-aed9-4cf5-a766-dfca5abac2bb`, amber
`55d920b0-5e8b-4f79-9ee9-91f868d9b421`, amber+strict
`939a9414-2ddd-4d32-a0cd-375ea402b003`, red
`e828b379-4e03-4974-9ac4-e53a884c97c1`.

Amber+strict uses the amber bit. The tag `tlp:amber+strict` keeps the
distinction. A `marking-definition` in the bundle supplies any other
id, from `definition.tlp`, from an extension field `tlp_2_0`, or from
a name that starts with `TLP:`. Up to 64 of those definitions are kept.

The name `lookup` prints is the file stem. `indicators.stix.json` and
`indicators.stix` are both `indicators`. The `name` field in the
config is a label for you. `--feed-key` on `apply-delta` sets the stem
for that fold.

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

A saved MISP file must be named `.misp` or `.misp.json`. A STIX bundle
must be named `.stix` or `.stix.json`. On `build`, any other `.json`
file is the dictionary form above.

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

Basic authentication is `account_id:license_key`. Both fields empty
skips this download. One of them set and the other empty is an error.
If that checksum
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

A segment named `.stix` or `.stix.json` is STIX. A segment named
`.misp.json`, and every other `.json` segment, is MISP. A `.csv`
segment is CSV. The STIX test is applied first, so `delta.stix.json`
is a bundle and `delta.json` is MISP.

## Worked example

From the repository root, after `make`:

```
sh docs/check.sh
```

That is `docs/examples/enrich.json` plus the files next to it. It
builds `build/docs/threat.thrt` and `build/docs/allow.ovly`, checks
the rows below, folds `docs/examples/delta.csv` and
`docs/examples/delta.stix.json`, and checks the two added addresses.

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

What `lookup` prints for the STIX address `203.0.113.70`:

```
Checking: 203.0.113.70
[*] Type: IPv4

[WARN] >>> MATCH FOUND! <<<
   Confidence : 85%
   Type       : CTI
   TLP        : WHITE
   Categories : Attack (0x0001)
   Feeds      : indicators
   Tags       : ["lab ipv4","malicious-activity"]
```

The feed is `indicators` because the file is
`indicators.stix.json`. The config row that points at it is named
`stix`. That label is not the feed name.

The other rows, checked by the script:

| Indicator | File | Type |
|---|---|---|
| 203.0.113.50 | public.csv | CTI |
| 203.0.113.51 | dictionary.json | CTI |
| 203.0.113.52 | table.lookup | CTI |
| 203.0.113.53 | iocs.txt | CTI |
| 203.0.113.54 | iocs.ioc | CTI |
| 203.0.113.55 | event.misp.json | CTI, tag `misp-event:sample` |
| 203.0.113.61 | attributes.misp.json | CTI, TLP GREEN, confidence 90, tag `misp-event:search-sample`. Attribute search with a nested event. |
| 203.0.113.62 | attributes.misp.json | CTI, TLP WHITE. Attribute with no nested event. |
| 203.0.113.56 | restricted.csv | CTI_R |
| 203.0.113.57 | cmdb.tags | TAGS, tags `["asset","lab"]` |
| 203.0.113.58 | carto.tags.json | TAGS, tags `["lab","asset"]` |
| 203.0.113.70 | indicators.stix.json | CTI, TLP WHITE, confidence 85, feed `indicators` |
| 203.0.113.71 | indicators.stix.json | CTI, C2, TLP AMBER. The pattern is an OR. |
| or.example | indicators.stix.json | CTI. The pattern literal is `Or.Example`. |
| 203.0.113.72 | indicators.stix.json | CTI. `IN` list, with .73. |
| 203.0.113.73 | indicators.stix.json | CTI. Same `IN` list. |
| 2001:db8::70 | indicators.stix.json | CTI |
| http://evil.example/stix | indicators.stix.json | CTI. Case kept. |
| stix@example.com | indicators.stix.json | CTI, phishing. Pattern literal `Stix@Example.com`. |
| 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae | indicators.stix.json | CTI, malware. SHA-256. |
| bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb | indicators.stix.json | CTI. `AND` with `stixlab.exe`, both stored. |
| stixlab.exe | indicators.stix.json | CTI. Same `AND`. |
| Global\StixLab | indicators.stix.json | CTI. Mutex. |
| 64496 | indicators.stix.json | CTI. ASN, unquoted integer. |
| 203.0.113.100 | indicators.stix.json | CTI, proxy. Inside `203.0.113.96/28`. |
| 203.0.113.82 | indicators.stix.json | CTI, TLP RED |
| 203.0.113.83 | indicators.stix.json | CTI, TLP AMBER, tag `tlp:amber+strict` |
| 203.0.113.87 | indicators.stix.json | CTI, TLP GREEN. Custom marking in the bundle. |
| 203.0.113.78 | sco.stix.json | CTI, confidence 50, TLP AMBER, feed `sco` |
| 203.0.113.79 | private.stix.json | CTI_R, TLP RED, feed `private` |
| d41d8cd98f00b204e9800998ecf8427e | indicators.stix.json | CTI. Hex literal `h'd41d8cd9...'`, MD5. |

Rows the script requires to miss:

| Indicator | Why there is no row |
|---|---|
| 203.0.113.74 | `revoked` true |
| 203.0.113.75 | `valid_until` 2020-01-01 |
| 203.0.113.76 | `indicator_types` is only `benign` |
| 203.0.113.81 | comparison is `LIKE` |
| 203.0.113.84 | `valid_from` 2099-01-01 |
| 203.0.113.85 | pattern contains `FOLLOWEDBY` |
| 203.0.113.86 | `pattern_type` is `snort` |
| 203.0.113.95 | outside `203.0.113.96/28` |
| skip.example | `to_ids` is false in `attributes.misp.json` |

After the two folds:

| Indicator | File | Type |
|---|---|---|
| 203.0.113.60 | delta.csv | CTI, feed `delta` |
| 203.0.113.80 | delta.stix.json | CTI, feed `stix-delta` |

The overlay write prints:

```
wrote build/docs/allow.ovly (68 bytes, 1 entries)
  WHITELIST 203.0.113.59  hash=0xa613971f  action='-'
```

## Not built here

A prevalence table (`.prev`) is not a feed. This tool does not download
one and does not compile one.

TAXII is not a feed. A STIX `url` is one HTTP GET of a bundle. A
collector that speaks TAXII saves that bundle, and `path` compiles the
file.
