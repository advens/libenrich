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
enrich -c enrich.json sync
enrich -c enrich.json sync --apply --hup
enrich -c enrich.json sync --segment osint.csv --feed-key osint --apply --full --hup
```

`fetch` downloads GeoIP, every MISP feed that has a `url`, every STIX
feed that has a `url`, and every `ua` or `tld` feed. `build` compiles
`output` and writes each overlay. `run` is fetch, then build. `lookup`
queries `output` only. It does not query an overlay. `apply-delta`
folds one CSV, MISP, or STIX segment into `output`.

## MISP

Live pull, then a local compile. `url` is the server origin, with no
path and no trailing slash. `key` is the automation key. The `Authorization` value is that
key alone. `since` is
copied into the MISP field `last`. Omit it and the request uses `7d`.
`1d`, `12h`, and `30d` are the same kind of value. `dest` must end in
`.misp` or `.misp.json`. That suffix is what makes `build` treat the
file as MISP. Any other `.json` name is the dictionary form below.

```json
{
  "output": "/var/lib/enrich/threat.thrt",
  "feeds": [
    {
      "name": "misp",
      "type": "misp",
      "layer": "cti",
      "url": "https://misp.example",
      "key": "",
      "since": "7d",
      "dest": "/var/lib/enrich/misp.misp.json"
    }
  ]
}
```

`name` is a label in the config. `lookup` prints the file stem.
`misp.misp.json` is feed `misp`.

`enrich fetch` requires `curl` on `PATH`. It sends one request:

```
POST https://misp.example/attributes/restSearch
Authorization: <key>
Accept: application/json
Content-Type: application/json

{"returnFormat":"json","last":"7d","to_ids":1,"limit":10000}
```

`curl` follows redirects, stops at 120 seconds, and checks the server
certificate. A private CA has to be in the trust store already. The body is written to `dest.tmp`
and renamed onto `dest`. `fetch` creates the directory that holds
`dest`. A missing `url`, an empty `key`, a missing `dest`, a missing
`curl`, a TLS error, or an HTTP error exits 1 and leaves the previous
`dest` in place. The failure line is `misp download failed` or
`misp feed needs url, key, and dest in the config`.

The request is one page. `limit` is 10000 and there is no `page`
loop. Attributes past that page are not fetched and the command does
not say so. Narrow `since`, or count the attributes in `dest`, before
you treat the file as the whole window. Paging that window is
`enrich sync`, not `fetch`.

The response is stored unchanged. `build` compiles these shapes:

- a single event, `{"Event":{...}}`
- an event search, `{"response":[{"Event":{...}}]}`
- an attribute search, `{"response":{"Attribute":[...]}}`, which is what this POST returns
- an attribute list, `{"Attribute":[...]}`

A nested `Event` on an attribute supplies `info`, `threat_level_id`,
and the event tags. An event export also walks `Object[].Attribute`.
The attribute-search body does not. MISP already puts those object
attributes in the `Attribute` array.

An attribute is kept when `to_ids` is true. A missing `to_ids` is
kept. `to_ids` false is dropped. The request already asks for
`to_ids` 1. `deleted` and `published` are not read. If a deleted
attribute is in the body and `to_ids` is true, it becomes a row.

| MISP `type` | Stored as |
|---|---|
| `ip-src`, `ip-dst` | `ip` |
| `ip-src\|port`, `ip-dst\|port` | `ip`, text before the pipe |
| `domain`, `hostname` | `domain` |
| `domain\|ip` | one `domain` row and one `ip` row |
| `md5`, `sha1`, `sha256` | that hash type |
| `filename\|md5`, `filename\|sha1`, `filename\|sha256` | the hash, text after the pipe |
| `url` | `url` |
| `email-src`, `email-dst` | `email` |

Any other type is dropped. A value longer than 511 bytes is cut.

| MISP `category` | Lookup category |
|---|---|
| `Network activity`, `Attribution` | Attack |
| `Payload delivery`, `Payload installation`, `Persistence mechanism`, `Artifacts dropped`, `Antivirus detection` | Malware |
| `Targeting data`, `Financial fraud` | Phishing |
| anything else, or no category | Unknown |

`threat_level_id` may be a string or an integer. `1` is confidence
90, `2` is 70, `3` is 50, and any other value, including a missing
event, is 70.

A tag whose name starts with `tlp:` sets the mark. `red`, then
`amber` (so `amber+strict` is amber), then `green`, otherwise clear.
`lookup` prints clear as `WHITE`. An attribute tag wins over the
event tag. Other tag names are kept. The event `info` is stored as
`misp-event:<info>`.

`docs/check.sh` compiles `docs/examples/event.misp.json` and
`docs/examples/attributes.misp.json` without calling a server.
`203.0.113.55` is the saved event. `203.0.113.61` is an attribute
with a nested event (TLP green, confidence 90, tag
`misp-event:search-sample`). `203.0.113.62` has no nested event (TLP
white, confidence 70). `skip.example` is `to_ids` false and must not
match.

To test your own server, put the config above in a file of mode
`0600`, leave the GeoIP account id and license key empty or omit the
`geoip` object, and run:

```
enrich -c enrich.json fetch
enrich -c enrich.json build
enrich -c enrich.json lookup 203.0.113.61
```

Replace the last argument with an indicator you know is `to_ids` on
that server. A hit prints `CTI` and a TLP word. A value you know is
`to_ids` false, or whose type is not in the table, prints `NO MATCH.`
`run` is `fetch`, then `build`. A feed with `path` and no `url` does
not call the server. It compiles the file you already have.

## Sync

`sync` talks only to the MISP feed. It does not download GeoIP, a
STIX bundle, or a UA or suffix table. It does not copy a file, call
Fleet, or write a second database. `output` stays the database named
in the config.

```
POST {url}/attributes/restSearch
Authorization: <key>
Accept: application/json
Content-Type: application/json

{"returnFormat":"json","last":[<lo>,<hi>],"to_ids":1,"limit":2000,"page":1}
```

A pull covers the window from its start to the time the command
started. `last` is a range of event publish times, two Unix times, both
included: MISP selects the attributes of the events published in it.

MISP pages with an SQL offset and no `ORDER BY`. A page costs every row
before it, so one window of millions of attributes takes hours, and an
attribute added during the pull moves the rows after it to the next
page. The window is cut into slices instead. Before a slice is paged,
one request with `limit` 1 and `page` one past `--slice-rows` asks
whether the slice holds more attributes than that. If it does, the
slice is cut in two at its middle second and each half is checked the
same way, the older half first. Only the busy periods are cut, and no
page starts deeper than `--slice-rows`. One second is never cut: the
attributes of an event share its publish time, so a large event is
paged as one slice. `--slice-rows` defaults to ten pages.

`limit` defaults to 2000 (`--page-size`). Within a slice, the next page
is requested until a page is shorter than that limit. Each page is released before
the next request. The pages are still saved as one attribute-search
body at `dest`. A pull that returns no attributes leaves `dest`, the
cursor, and `output` unchanged. A server that keeps returning a full
page stops after 100000 pages of one slice, and a pull stops after a
million slices and checks.

The cursor is `<dest>.cursor`. It holds the newest attribute
`timestamp`, and the next pull starts there. The first pull, and any
`--full`, starts at the config `since` (or `7d`) instead of the
cursor. `since` is read as MISP reads `last`: a number followed by `d`,
`h`, or `m` counts back from now, and a plain number is a Unix time.
A cursor older than `since` is moved up to it.
A failed pull leaves the previous `dest` and cursor in place.

Without `--apply` the command stops after `dest` and the cursor. It
does not change `output` and it does not signal rsyslog. With
`--apply`, the first pull and any `--full` replace that MISP feed in
`output`. Every page of that pull is folded into one database, and
the database is written once. The feed is snapshotted once, before
the first page, so a later page adds to it instead of replacing it.
Indicators already stored under a different feed stay. Overlay feeds
are written the same way `build` writes them. A later window is one
generation of `apply-delta`. On that later window, `deleted` true
or `to_ids` false removes the indicator. A full pull does not treat
those attributes as withdrawals. A still-valid `to_ids` attribute is
added. Type, confidence, TLP, and category stay the rules `build`
already uses. A failed fold leaves the previous `dest`, cursor, and
`output`, and does not signal.

`--segment FILE` reads a file already on disk and needs no MISP key.
Without `--apply` it does not change `output`. With `--apply` it
folds that file. `--full` makes the fold a snapshot
(`apply-delta --snapshot`), which is how a CSV that is not a
configured feed replaces one feed key. `--feed-key` on a segment is
that feed key. On a pull, `--feed-key` selects the MISP feed `name`.
When it is omitted, a pull uses the first MISP feed that has a `dest`.

`--hup` runs only after a fold that succeeded. On Linux the command
is `systemctl kill -s HUP rsyslog`. Elsewhere it sends SIGHUP to
`rsyslogd`. `--hup-cmd` replaces that command. A signal that fails
does not undo the fold.

`--follow` subscribes to the MISP ZeroMQ topic `misp_json_attribute`
and folds one delta every `--flush-seconds` (default 300). `--zmq`
defaults to `tcp://<misp host>:50000`. The socket is libzmq linked
into this binary. A build without libzmq still runs every other flag,
and `--follow` exits 2. There is no Python and no pyzmq.

A test host runs `sync`, then `lookup`. The host that holds the key
runs `sync` from cron, or `sync --follow --apply --hup` when that
host runs rsyslog. A host with no key runs
`sync --segment <file> --apply --hup`.

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

One indicator is one record, whatever feeds and layers list it. The
same address, network or string from several files merges into one
row. A network that contains another indicator is cut so that each
address answers with the merge of every row that covers it. In that
record, confidence, TLP, categories and feed names describe the public
layer only. A restricted source adds its layer and its own score,
never a feed name, a marking, a category or a label. `lookup` prints
that score on a `Restricted` line. The labels a public source attaches
(MISP tags, STIX labels) print on a `Labels` line, apart from the
context `Tags`. Two sources that tag one indicator keep both sets.

An address is four decimal octets (no leading zero) or an IPv6
address without a `%zone`, read the same way on every platform.
Anything else is a string.

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
anything else, which means add. A whitelist hides the indicator
entirely; with `"suppress_mode":"score"` it is only flagged. A tag
entry carries `"tags":["...", "..."]`. An add entry takes `confidence`
and `category`. An `ioc` longer than 4096 bytes, or listed twice, is
an error. `enrich build` writes `dest` (temporary file, then rename)
and prints the entry count. There is no `enrich` subcommand that
queries an overlay.

The file stores each value, and a lookup compares it. An overlay
written before format version 2 matched on a 32-bit hash alone, so an
unrelated value with the same hash hit the entry. Those files are
refused; rebuild them.

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
| 203.0.113.79 | private.stix.json | CTI_R. `lookup` prints its score, not its TLP or feed. |
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
wrote build/docs/allow.ovly (90 bytes, 1 entries)
  WHITELIST 203.0.113.59  hash=0xa613971f  action='-'
```

## Library

`enrich.h` is the lookup API that `lookup` uses. A log enricher or a
lookup service opens the database, the overlay and a prevalence table
as one snapshot, and looks values up under the rules above.

```c
enrich_options_t o = {sizeof o, "/var/lib/enrich/threat.thrt",
                      "/var/lib/enrich/allow.ovly", NULL, ENRICH_OPT_SKIP_PRIVATE};
enrich_t *e;
char err[256];
if (enrich_open(&e, &o, err, sizeof err) != ENRICH_OK) { /* err names the file */ }

enrich_reader_t *r = enrich_reader_new(e);      /* one per thread */
const enrich_snap_t *s = enrich_reader_enter(r);
enrich_result_t res;
if (enrich_lookup(s, enrich_lookup_flags(e), "203.0.113.50", 12, &res) == 1) {
    /* res.flags, res.confidence, res.feed_mask, res.tags ... */
}
enrich_reader_leave(r);

enrich_reload(e, NULL, err, sizeof err);         /* after a rebuild */
```

Every file is validated before it is published: version, sizes, every
table offset and index, and the CRC32C. A file that fails keeps the
previous snapshot. `enrich_reload()` loads only the files whose inode,
size or mtime changed, and readers never wait for it. A reader holds
its snapshot until it leaves or enters again; a replaced snapshot is
unmapped once every reader has moved on. Replace files by rename, as
`enrich` does: a file rewritten in place under a live mapping can
fault.

The order of a lookup: the overlay first (a full whitelist ends it),
then the database. `ENRICH_OPT_SKIP_PRIVATE` drops the CTI parts of a
private, loopback, link-local, CGNAT or ULA address and keeps its
tags. Values are taken with their length, are never truncated, and
are refused past 4096 bytes. `enrich_lookup_batch()` takes many values
at once and prefetches the bloom filter. `enrich_event_fold()` sums the
fields of one event. `enrich_prevalence()` reads a `.prev`.

The library reads `.thrt` version 5, overlay version 2 and `.prev`
version 3, and refuses any other version. `enrich_open()` takes any
non-empty subset of the three paths; a rule engine can open the
`.prev` alone.

`make test` runs `src/test_enrich_api.c` against `testdata/api`.
`make sanitize` runs it under AddressSanitizer, UndefinedBehaviorSanitizer
and ThreadSanitizer. `make fuzz` builds the libFuzzer harness
`src/fuzz_enrich.c` for the three loaders, and `make fuzz-enrichd`
builds `src/fuzz_enrichd.c` for enrichd's request handling and key
file parser. Both need a clang with libFuzzer; the comment at the top
of each file says how to run it.

## Lookup service

`enrichd` answers lookups over HTTP from the same snapshot and policy as
the library. It is optional: `make enrichd` needs libmicrohttpd
(`pkg-config libmicrohttpd`), and `make install-enrichd` puts it in
`$(PREFIX)/sbin`. It runs in the foreground and logs to stderr; the
service manager starts it, keeps the log and runs it as an unprivileged
user.

```
enrichd -c /usr/local/etc/enrichd.json      # serve
enrichd -c /usr/local/etc/enrichd.json -t   # check config, keys, database
openssl rand -hex 32 | tee key | enrichd -k # digest for the key file
```

### Config

`docs/examples/enrichd.json` lists every key. An unknown key is an
error.

| Key | Default | |
|-----|---------|-|
| `listen` | `127.0.0.1` | numeric IPv4 or IPv6 address |
| `port` | 8470 | |
| `threads` | 4 | worker threads |
| `thrt`, `overlay`, `prev` | | at least one; as `enrich_open()` takes them |
| `skip_private` | true | `ENRICH_OPT_SKIP_PRIVATE` |
| `reload_seconds` | 30 | stat the files and reload what changed; 0 turns it off |
| `keys` | required | the API key file |
| `tls_cert`, `tls_key` | | PEM files; libmicrohttpd must be built with TLS |
| `allow_plaintext` | false | plain HTTP on an address that is not loopback |
| `unmarked_tlp` | `amber` | the TLP a match without a marking is treated as |
| `max_batch` | 1000 | values per request |
| `max_body` | 1 MiB | request body bytes |
| `max_connections` | 256 | |
| `per_ip_connections` | 32 | 0 is no limit |
| `timeout_seconds` | 10 | idle connection timeout |
| `access_log` | false | one line per request: client, key name, route, status, count |

Plain HTTP is refused off loopback unless `allow_plaintext` says a TLS
proxy sits in front. The TLS key file must not be readable by group or
other. The access log never holds a looked-up value. A database that
fails to load at start is retried at each reload, and `/v1/health`
answers 503 until it loads; `-t` fails instead.

SIGHUP reloads the key file and the database. SIGTERM stops.

### Keys

One key per line: a name, the SHA-256 of the key in hex (`enrichd -k`),
and optional grants, comma-separated.

```
# name        digest                                                            grants
soc-misp      9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  tlp:amber
soar          2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae  tlp:red,restricted,context
```

| Grant | Shows |
|-------|-------|
| `tlp:clear` (default), `tlp:green`, `tlp:amber`, `tlp:red` | public CTI whose strictest marking is at most this |
| `restricted` | the score of a restricted CTI match, never its feed, marking or labels |
| `context` | tags, overlay tags, overlay add entries, the whitelist disposition, prevalence |

A request sends `Authorization: Bearer <key>`, or `Authorization: <key>`
as MISP clients do. A key is 32 to 512 characters. The file holds
digests, not keys, and must not be writable by group or other. Every
digest is compared on each request, so the time does not depend on
which key matched.

What a key may not see is removed before the response is built. A
match it may not see is a miss: `matched` is false and nothing of it
is returned. A full whitelist in the overlay is a miss for every key.

### API

| Request | |
|---------|-|
| `GET /v1/health` | no key; 200 `{"status":"ok"}` once a database is loaded, else 503 |
| `GET /v1/db` | library version, snapshot generation, sizes and mtimes |
| `GET /v1/lookup/<value>` | one value, percent-encoded; `GET /v1/lookup?value=` is the same |
| `POST /v1/lookup` | `{"values": ["...", ...]}`, at most `max_batch` |
| `POST /attributes/restSearch` | MISP attribute search, below |

A value is used as given: no trimming, no case folding. `%00`, a bad
escape, and a value longer than 4096 bytes are refused with 400.

A result:

```json
{
  "value": "evil.example",
  "matched": true,
  "threat": {
    "indicator": {
      "type": "domain-name",
      "confidence": "High",
      "marking": {"tlp": "AMBER"},
      "provider": ["pubfeed"]
    },
    "feed": {"name": ["pubfeed"]}
  },
  "enrich": {
    "cti": {"confidence": 70, "categories": ["malware"], "tlp": ["amber"], "feeds": ["pubfeed"]}
  }
}
```

`threat` uses ECS names. `threat.indicator.type` comes from the value:
an address is `ipv4-addr` or `ipv6-addr`, 32, 40, 64 or 128 hex digits
are `file`, a value with `://` is `url`, one with `@` and no `/` is
`email-addr`, anything else is `domain-name`. `confidence` is the best
score the key may see, on the STIX 2.1 scale: 0 None, 1 to 29 Low, 30
to 69 Medium, 70 to 100 High. `marking` and `provider` describe public
CTI only.

`enrich` has the detail in the shape mmenrich writes per field
(`cti` with `confidence`, `categories`, `tlp`, `feeds`, `labels`), plus,
as the grants allow, `restricted.confidence`, `overlay` (an add entry:
`confidence`, `categories`), `tags`, `overlay_tags`,
`disposition: "allowed"` (a soft whitelist), `prevalence` (`count`,
`edges`, `sources`), and `private: true` for a private address.

A batch answers `{"generation": N, "results": [...]}` in request order.
A value the library refuses gives `{"error": "..."}` in its place.

### MISP search

`POST /attributes/restSearch` (or `/attributes/restSearch/json`) takes a
MISP search body, flat or under `"request"`. `value` is a string or a
list, matched exactly. A value that starts with `!` or starts or ends
with `%` is refused with 400: wildcards and negation are not supported,
and a silent miss would be worse. `returnFormat` must be `json` when
present. Other filters are ignored.

The answer is `{"response": {"Attribute": [...]}}` with one attribute
per value the key sees as a match. `type` is `ip-dst`, `domain`, `url`,
`email-src`, `md5`, `sha1`, `sha256` or `sha512`; `category` is
`Payload delivery` for a hash and `Network activity` otherwise;
`timestamp` is the database mtime; `id` and `event_id` are `"0"`. Tags
carry the rest: `tlp:<marking>`, `enrich:confidence="N"`,
`enrich:feed="<name>"`, `enrich:category="<name>"`, the labels the
source attached, and `enrich:restricted` or `enrich:overlay` when those
parts matched.

### Limits and numbers

Request bodies stop at `max_body` (413, before the body is read when
`Content-Length` says so), JSON bodies at a depth of 8, connections at
`max_connections` and `per_ip_connections`, idle connections at
`timeout_seconds`. Headers and the URL fit the libmicrohttpd connection
memory (32 KB).

On an M1, 4 threads, `ab -k -c 16` on the same host: 80 000 single
lookups per second, 32 000 batches of 100 values per second, no
failure. `ab` runs on one core, so these are floors.

`make test-enrichd` starts `enrichd` on `testdata/api` and checks each
grant, the bounds, the MISP search and a reload (`docs/check-enrichd.sh`,
needs curl and python3).

## Not built here

A prevalence table (`.prev`) is not a feed. This tool does not download
one and does not compile one. Its rows are 64-bit SipHash-1-3 values
under a random key stored in the file (`prev_format.h`), so a name
cannot be chosen to collide with a common one. A writer draws a new
key per table; readers take it from the file.

TAXII is not a feed. A STIX `url` is one HTTP GET of a bundle. A
collector that speaks TAXII saves that bundle, and `path` compiles the
file.
