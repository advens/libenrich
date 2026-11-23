#!/bin/sh
# Start enrichd on the API test database and check what each kind of key
# sees, the input bounds, the MISP search, and a reload. Needs curl and
# python3. Usage: sh docs/check-enrichd.sh [build dir]
set -eu
cd "$(dirname "$0")/.."
B=${1:-build}
D=$B/enrichd-check
test -x "$B/enrichd"
test -s "$B/api/threat.thrt"
rm -rf "$D"
mkdir -p "$D"
cp "$B/api/threat.thrt" "$D/threat.thrt"
cp "$B/api/site.ovly" "$D/site.ovly"

KEY_CLEAR=clear-key-0123456789abcdef0123456789abcdef
KEY_AMBER=amber-key-0123456789abcdef0123456789abcdef
KEY_FULL=full-key-0123456789abcdef0123456789abcdef00
PORT=$((20000 + $$ % 20000))
URL=http://127.0.0.1:$PORT
PID=

fail() {
    echo "check-enrichd: FAIL: $*" >&2
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    [ -f "$D/log" ] && sed 's/^/  log: /' "$D/log" >&2
    exit 1
}

digest() {
    printf '%s\n' "$1" | "$B/enrichd" -k
}

# -k is SHA-256 of the key.
want=$(python3 -I -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$KEY_FULL")
[ "$(digest "$KEY_FULL")" = "$want" ] || fail "enrichd -k is not SHA-256"
printf 'short\n' | "$B/enrichd" -k >/dev/null 2>&1 && fail "enrichd -k took a short key"

{
    echo "# name digest grants"
    echo "clear $(digest "$KEY_CLEAR")"
    echo "amber $(digest "$KEY_AMBER") tlp:amber"
    echo "full $(digest "$KEY_FULL") tlp:red,restricted,context"
} >"$D/keys"
chmod 600 "$D/keys"

cat >"$D/enrichd.json" <<EOF
{
  "listen": "127.0.0.1",
  "port": $PORT,
  "threads": 2,
  "thrt": "$D/threat.thrt",
  "overlay": "$D/site.ovly",
  "keys": "$D/keys",
  "reload_seconds": 1,
  "max_batch": 4,
  "max_body": 2048,
  "access_log": true
}
EOF

"$B/enrichd" -c "$D/enrichd.json" -t >/dev/null || fail "-t refused a good config"

chmod 620 "$D/keys"
"$B/enrichd" -c "$D/enrichd.json" -t >/dev/null 2>&1 && fail "a group-writable key file was accepted"
chmod 600 "$D/keys"

sed -e 's/"127.0.0.1"/"0.0.0.0"/' "$D/enrichd.json" >"$D/open.json"
"$B/enrichd" -c "$D/open.json" -t >/dev/null 2>&1 && fail "plain HTTP off loopback was accepted"

sed -e 's/"threads": 2,/"threads": 2, "bogus": 1,/' "$D/enrichd.json" >"$D/bogus.json"
"$B/enrichd" -c "$D/bogus.json" -t >/dev/null 2>&1 && fail "an unknown config key was accepted"

"$B/enrichd" -c "$D/enrichd.json" 2>"$D/log" &
PID=$!
i=0
until curl -fsS "$URL/v1/health" >/dev/null 2>&1; do
    i=$((i + 1))
    [ $i -lt 50 ] || fail "enrichd did not answer /v1/health"
    sleep 0.1
done

# status <expected> <curl args...>: the HTTP status, body in $D/body.
status() {
    want=$1
    shift
    got=$(curl -sS -o "$D/body" -w '%{http_code}' "$@") || fail "curl $*"
    [ "$got" = "$want" ] || fail "status $got, want $want: $* -> $(cat "$D/body")"
}

# js <python expression over j>: assert on the last body.
js() {
    python3 -I -c '
import json, sys
j = json.load(open(sys.argv[1]))
if not eval(sys.argv[2]):
    print(json.dumps(j), file=sys.stderr)
    sys.exit(1)
' "$D/body" "$1" || fail "assertion: $1"
}

get() {
    key=$1
    shift
    status 200 -H "Authorization: Bearer $key" "$URL/v1/lookup/$1"
}

# Keys.
status 401 "$URL/v1/lookup/evil.example"
status 401 -H "Authorization: Bearer not-a-key-0123456789abcdef0123456789" "$URL/v1/lookup/evil.example"
status 401 -H "Authorization: Bearer $KEY_FULL$KEY_FULL" "$URL/v1/lookup/evil.example"
status 200 -H "Authorization: $KEY_AMBER" "$URL/v1/lookup/evil.example"
js 'j["matched"] is True'

# TLP clearance. evil.example is amber.
get "$KEY_CLEAR" evil.example
js 'j["matched"] is False and "threat" not in j and "enrich" not in j'
get "$KEY_AMBER" evil.example
js 'j["matched"] and j["threat"]["indicator"]["type"] == "domain-name"'
js 'j["threat"]["indicator"]["marking"]["tlp"] == "AMBER" and j["threat"]["indicator"]["confidence"] == "High"'
js 'j["threat"]["feed"]["name"] == ["pubfeed"] and j["enrich"]["cti"]["categories"] == ["malware"]'

# 198.51.100.10: public CTI (clear, green), restricted CTI, context tags.
get "$KEY_AMBER" 198.51.100.10
js 'j["matched"] and j["threat"]["indicator"]["type"] == "ipv4-addr"'
js '"restricted" not in j["enrich"] and "tags" not in j["enrich"]'
js 'j["enrich"]["cti"]["labels"] == ["misp-event:campaign-x"]'
get "$KEY_FULL" 198.51.100.10
js 'j["enrich"]["restricted"]["confidence"] == 95 and "crown-jewel" in j["enrich"]["tags"]'
js '"secretfeed" not in json.dumps(j)'

# 198.51.100.20: restricted CTI (85) inside a public clear range (50).
get "$KEY_AMBER" 198.51.100.20
js 'j["threat"]["indicator"]["confidence"] == "Medium" and "restricted" not in j["enrich"]'
get "$KEY_FULL" 198.51.100.20
js 'j["threat"]["indicator"]["confidence"] == "High" and j["enrich"]["restricted"]["confidence"] == 85'

# Overlay: full whitelist, soft whitelist, add, tag.
get "$KEY_FULL" wl.example
js 'j["matched"] is False and "enrich" not in j'
get "$KEY_AMBER" soft.example
js 'j["matched"] and "disposition" not in j.get("enrich", {})'
get "$KEY_FULL" soft.example
js 'j["enrich"]["disposition"] == "allowed"'
get "$KEY_AMBER" add.example
js 'j["matched"] is False'
get "$KEY_FULL" add.example
js 'j["matched"] and j["enrich"]["overlay"]["confidence"] == 70'
get "$KEY_FULL" tag.example
js 'j["matched"] is False and j["enrich"]["overlay_tags"] == ["vip", "owner:it"]'

# Private address: CTI dropped, tags kept for a context key.
get "$KEY_FULL" 10.1.2.3
js 'j["matched"] is False and j["enrich"]["private"] is True and "dmz" in j["enrich"]["tags"]'

# A URL in the path, and the query form.
get "$KEY_AMBER" "http%3A%2F%2Fnothing.example%2Fa%3Fb%3Dc"
js 'j["value"] == "http://nothing.example/a?b=c" and j["matched"] is False'
status 200 -H "Authorization: Bearer $KEY_AMBER" "$URL/v1/lookup?value=evil.example"
js 'j["matched"]'

# Bounds and refusals.
status 400 -H "Authorization: Bearer $KEY_AMBER" "$URL/v1/lookup/a%00b"
status 400 -H "Authorization: Bearer $KEY_AMBER" "$URL/v1/lookup/a%zz"
status 400 -H "Authorization: Bearer $KEY_AMBER" "$URL/v1/lookup?value="
long=$(python3 -I -c 'print("a" * 4097)')
status 400 -H "Authorization: Bearer $KEY_AMBER" "$URL/v1/lookup/$long"
status 404 -H "Authorization: Bearer $KEY_AMBER" "$URL/v2/lookup"
status 405 -X DELETE -H "Authorization: Bearer $KEY_AMBER" "$URL/v1/lookup"
status 405 -X POST -H "Authorization: Bearer $KEY_AMBER" -d '{}' "$URL/v1/db"

# Batch.
status 200 -H "Authorization: Bearer $KEY_AMBER" -H 'Content-Type: application/json' \
    -d '{"values":["evil.example","198.51.100.10","nothing.example","2001:db8::5"]}' "$URL/v1/lookup"
js '[r["matched"] for r in j["results"]] == [True, True, False, True] and j["generation"] >= 1'
js 'j["results"][3]["threat"]["indicator"]["type"] == "ipv6-addr"'
status 400 -H "Authorization: Bearer $KEY_AMBER" -d '{"values":["a","b","c","d","e"]}' "$URL/v1/lookup"
status 400 -H "Authorization: Bearer $KEY_AMBER" -d '{"values":[1]}' "$URL/v1/lookup"
status 400 -H "Authorization: Bearer $KEY_AMBER" -d '{"values":["a"]} x' "$URL/v1/lookup"
status 400 -H "Authorization: Bearer $KEY_AMBER" -d '[[[[[[[[[[[[1]]]]]]]]]]]]' "$URL/v1/lookup"
status 400 -H "Authorization: Bearer $KEY_AMBER" -d 'not json' "$URL/v1/lookup"
big=$(python3 -I -c 'print("{\"values\":[\"" + "a" * 3000 + "\"]}")')
status 413 -H "Authorization: Bearer $KEY_AMBER" -d "$big" "$URL/v1/lookup"
printf '%s' "$big" >"$D/big.json"
status 413 -H "Authorization: Bearer $KEY_AMBER" -H 'Transfer-Encoding: chunked' --data-binary @"$D/big.json" \
    "$URL/v1/lookup"

# MISP attribute search.
status 200 -H "Authorization: $KEY_AMBER" -H 'Accept: application/json' -H 'Content-Type: application/json' \
    -d '{"returnFormat":"json","value":["evil.example","nothing.example","198.51.100.10"]}' \
    "$URL/attributes/restSearch"
js '[a["value"] for a in j["response"]["Attribute"]] == ["evil.example", "198.51.100.10"]'
js 'j["response"]["Attribute"][0]["type"] == "domain" and j["response"]["Attribute"][1]["type"] == "ip-dst"'
js '{"name": "tlp:amber"} in j["response"]["Attribute"][0]["Tag"]'
js '{"name": "misp-event:campaign-x"} in j["response"]["Attribute"][1]["Tag"]'
status 200 -H "Authorization: $KEY_AMBER" -d '{"request":{"value":"evil.example"}}' "$URL/attributes/restSearch"
js 'len(j["response"]["Attribute"]) == 1'
status 400 -H "Authorization: $KEY_AMBER" -d '{"value":"%.example"}' "$URL/attributes/restSearch"
status 400 -H "Authorization: $KEY_AMBER" -d '{"value":"evil.example","returnFormat":"csv"}' \
    "$URL/attributes/restSearch"

# Snapshot facts, and no key needed for health.
status 200 -H "Authorization: Bearer $KEY_AMBER" "$URL/v1/db"
js 'j["thrt"]["format"] == 5 and j["overlay"]["entries"] == 4'
gen=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["generation"])' "$D/body")

# Reload: replace the database by rename; the next lookup sees it.
get "$KEY_CLEAR" 203.0.113.30
js 'j["matched"] is False'
cp "$B/api/second.thrt" "$D/threat.thrt.new" 2>/dev/null || {
    "$B/enrich" -c testdata/api/second.json build >/dev/null
    cp "$B/api/second.thrt" "$D/threat.thrt.new"
}
mv "$D/threat.thrt.new" "$D/threat.thrt"
i=0
while :; do
    get "$KEY_CLEAR" 203.0.113.30
    python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["matched"] else 1)' "$D/body" && break
    i=$((i + 1))
    [ $i -lt 50 ] || fail "the replaced database was not reloaded"
    sleep 0.1
done
status 200 -H "Authorization: Bearer $KEY_AMBER" "$URL/v1/db"
js "j['generation'] > $gen"

# The access log names the route and the key, never a value.
grep -q ' amber GET /v1/lookup/ 200 1' "$D/log" || fail "no access log line"
grep -q 'evil.example' "$D/log" && fail "a looked-up value reached the log"

kill -TERM "$PID"
wait "$PID" || fail "enrichd did not exit cleanly"
PID=
echo "check-enrichd: ok"
