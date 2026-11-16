#!/bin/sh
# Offline checks for enrich sync. docs/sync-misp-standin.c stands in for MISP.
set -eu
cd "$(dirname "$0")/.."
test -x build/enrich

tmp=$(mktemp -d)
srv=0
srv2=0
cleanup() {
    if [ "$srv" != 0 ]; then
        kill "$srv" 2>/dev/null || true
        wait "$srv" 2>/dev/null || true
    fi
    if [ "$srv2" != 0 ]; then
        kill "$srv2" 2>/dev/null || true
        wait "$srv2" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT

# A segment without --apply does not create the database.
cat >"$tmp/idle.json" <<EOF
{"output": "$tmp/idle.thrt"}
EOF
printf '%s\n' 'action,type,indicator,confidence,category,tlp' \
    '+,ip,203.0.113.210,80,Attack,green' >"$tmp/one.csv"
./build/enrich -c "$tmp/idle.json" sync --segment "$tmp/one.csv" --feed-key labosint
test ! -e "$tmp/idle.thrt"

# --full on a segment is a snapshot of that feed key.
./build/enrich -c "$tmp/idle.json" sync --segment "$tmp/one.csv" \
    --feed-key labosint --apply --full
out=$(./build/enrich -c "$tmp/idle.json" lookup 203.0.113.210)
printf '%s\n' "$out" | grep -q CTI
printf '%s\n' 'action,type,indicator,confidence,category,tlp' \
    '+,ip,203.0.113.211,80,Attack,green' >"$tmp/two.csv"
./build/enrich -c "$tmp/idle.json" sync --segment "$tmp/two.csv" \
    --feed-key labosint --apply --full
out=$(./build/enrich -c "$tmp/idle.json" lookup 203.0.113.210)
printf '%s\n' "$out" | grep -q "NO MATCH"
out=$(./build/enrich -c "$tmp/idle.json" lookup 203.0.113.211)
printf '%s\n' "$out" | grep -q CTI

# The signal runs only after a fold that succeeded.
./build/enrich -c "$tmp/idle.json" sync --segment "$tmp/two.csv" \
    --feed-key labosint --apply --full --hup-cmd "touch $tmp/hup.ok"
test -f "$tmp/hup.ok"
printf '%s\n' 'not a segment' >"$tmp/bad.dat"
if ./build/enrich -c "$tmp/idle.json" sync --segment "$tmp/bad.dat" \
    --apply --hup-cmd "touch $tmp/hup.bad"; then
    echo "a bad segment must fail" >&2
    exit 1
fi
test ! -e "$tmp/hup.bad"

# A refused pull leaves dest and does not create a cursor.
printf 'ORIGINAL\n' >"$tmp/keep.misp.json"
cat >"$tmp/down.json" <<EOF
{
  "output": "$tmp/down.thrt",
  "feeds": [{
    "name": "lab-misp",
    "type": "misp",
    "url": "http://127.0.0.1:9",
    "key": "test-key",
    "since": "7d",
    "dest": "$tmp/keep.misp.json"
  }]
}
EOF
chmod 600 "$tmp/down.json"
if ./build/enrich -c "$tmp/down.json" sync --apply; then
    echo "a refused pull must fail" >&2
    exit 1
fi
grep -q ORIGINAL "$tmp/keep.misp.json"
test ! -e "$tmp/keep.misp.json.cursor"
test ! -e "$tmp/down.thrt"

# Without libzmq, --follow exits 2. With it, the process waits.
./build/enrich -c "$tmp/down.json" sync --follow >"$tmp/follow.out" 2>"$tmp/follow.err" &
fp=$!
sleep 1
if kill -0 "$fp" 2>/dev/null; then
    kill "$fp" 2>/dev/null || true
    wait "$fp" 2>/dev/null || true
else
    set +e
    wait "$fp"
    code=$?
    set -e
    test "$code" -eq 2
    grep -q "needs libzmq" "$tmp/follow.err"
fi

cc -std=c11 -O2 -o "$tmp/misp-standin" docs/sync-misp-standin.c
"$tmp/misp-standin" >"$tmp/port" 2>"$tmp/standin.err" &
srv=$!
i=0
while [ ! -s "$tmp/port" ]; do
    i=$((i + 1))
    if [ "$i" -gt 50 ]; then
        echo "misp stand-in did not start" >&2
        cat "$tmp/standin.err" >&2 || true
        exit 1
    fi
    sleep 0.1
done
port=$(cat "$tmp/port")

cat >"$tmp/live.json" <<EOF
{
  "output": "$tmp/live.thrt",
  "feeds": [{
    "name": "lab-misp",
    "type": "misp",
    "url": "http://127.0.0.1:$port",
    "key": "test-key",
    "since": "7d",
    "dest": "$tmp/live.misp.json"
  }]
}
EOF
chmod 600 "$tmp/live.json"

# Every page is saved. Without --apply the database is not created.
cat >"$tmp/cache.json" <<EOF
{
  "output": "$tmp/cache.thrt",
  "feeds": [{
    "name": "lab-misp",
    "type": "misp",
    "url": "http://127.0.0.1:$port",
    "key": "test-key",
    "since": "7d",
    "dest": "$tmp/cache.misp.json"
  }]
}
EOF
chmod 600 "$tmp/cache.json"
./build/enrich -c "$tmp/cache.json" sync --page-size 1
test ! -e "$tmp/cache.thrt"
grep -q "sync-sample" "$tmp/cache.misp.json"
grep -q "203.0.113.202" "$tmp/cache.misp.json"
grep -q "203.0.113.203" "$tmp/cache.misp.json"
grep -q '^180$' "$tmp/cache.misp.json.cursor"

./build/enrich -c "$tmp/live.json" sync --apply --page-size 1
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.201)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.202)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.203)
printf '%s\n' "$out" | grep -q CTI
grep -q '^180$' "$tmp/live.misp.json.cursor"
grep -q "sync-sample" "$tmp/live.misp.json"
grep -q "203.0.113.203" "$tmp/live.misp.json"

# A different feed key survives a full pull. The MISP feed key does not.
printf '%s\n' 'action,type,indicator,confidence,category,tlp' \
    '+,ip,203.0.113.244,80,Attack,green' >"$tmp/extra-other.csv"
printf '%s\n' 'action,type,indicator,confidence,category,tlp' \
    '+,ip,203.0.113.245,80,Attack,green' >"$tmp/extra-same.csv"
./build/enrich -c "$tmp/live.json" sync --segment "$tmp/extra-other.csv" \
    --feed-key other --apply
./build/enrich -c "$tmp/live.json" sync --segment "$tmp/extra-same.csv" \
    --feed-key live.misp --apply
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.244)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.245)
printf '%s\n' "$out" | grep -q CTI
./build/enrich -c "$tmp/live.json" sync --apply --full --page-size 1
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.244)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.245)
printf '%s\n' "$out" | grep -q "NO MATCH"
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.201)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.203)
printf '%s\n' "$out" | grep -q CTI
grep -q '^180$' "$tmp/live.misp.json.cursor"

./build/enrich -c "$tmp/live.json" sync --apply --page-size 1
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.201)
printf '%s\n' "$out" | grep -q "NO MATCH"
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.202)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.203)
printf '%s\n' "$out" | grep -q CTI
grep -q '^300$' "$tmp/live.misp.json.cursor"
grep -q '"deleted"' "$tmp/live.misp.json"

# The deleted indicator comes back when the feed is snapshotted again.
./build/enrich -c "$tmp/live.json" sync --apply --full --page-size 1
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.201)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.203)
printf '%s\n' "$out" | grep -q CTI
grep -q '^180$' "$tmp/live.misp.json.cursor"
grep -q "sync-sample" "$tmp/live.misp.json"

# A failed later page must not replace dest, the cursor, or output.
"$tmp/misp-standin" fail-page >"$tmp/port2" 2>"$tmp/standin2.err" &
srv2=$!
i=0
while [ ! -s "$tmp/port2" ]; do
    i=$((i + 1))
    if [ "$i" -gt 50 ]; then
        echo "failing stand-in did not start" >&2
        exit 1
    fi
    sleep 0.1
done
port2=$(cat "$tmp/port2")
cat >"$tmp/fail.json" <<EOF
{
  "output": "$tmp/live.thrt",
  "feeds": [{
    "name": "lab-misp",
    "type": "misp",
    "url": "http://127.0.0.1:$port2",
    "key": "test-key",
    "since": "7d",
    "dest": "$tmp/live.misp.json"
  }]
}
EOF
chmod 600 "$tmp/fail.json"
if ./build/enrich -c "$tmp/fail.json" sync --apply --full --page-size 1; then
    echo "a failed later page must fail" >&2
    exit 1
fi
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.201)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.203)
printf '%s\n' "$out" | grep -q CTI
grep -q '^180$' "$tmp/live.misp.json.cursor"
grep -q "sync-sample" "$tmp/live.misp.json"
if find "$tmp" \( -name '*.page.*.misp.json' -o -name '*.pull.*.misp.json' -o -name '*.work.*' \) | grep -q .; then
    echo "a failed pull left a page or work file" >&2
    exit 1
fi

echo "sync ok"
