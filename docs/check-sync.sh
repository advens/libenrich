#!/bin/sh
# Offline checks for enrich sync. docs/sync-misp-standin.c stands in for MISP.
set -eu
cd "$(dirname "$0")/.."
test -x build/enrich

tmp=$(mktemp -d)
srv=0
srv2=0
srv3=0
cleanup() {
    if [ "$srv" != 0 ]; then
        kill "$srv" 2>/dev/null || true
        wait "$srv" 2>/dev/null || true
    fi
    if [ "$srv2" != 0 ]; then
        kill "$srv2" 2>/dev/null || true
        wait "$srv2" 2>/dev/null || true
    fi
    if [ "$srv3" != 0 ]; then
        kill "$srv3" 2>/dev/null || true
        wait "$srv3" 2>/dev/null || true
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
# Publish times in the stand-in count back from t0, so a test with a
# Unix-time since knows every slice edge.
t0=$(date +%s)
day=86400
"$tmp/misp-standin" "$t0" >"$tmp/port" 2>"$tmp/standin.err" &
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

# The key reaches MISP (the stand-in answers 401 without it) but never
# curl's arguments, which every local user can read in the process list.
mkdir -p "$tmp/shim"
real_curl=$(command -v curl)
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >>"%s"\nexec "%s" "$@"\n' "$tmp/curl.argv" "$real_curl" >"$tmp/shim/curl"
chmod 755 "$tmp/shim/curl"
PATH="$tmp/shim:$PATH" ./build/enrich -c "$tmp/live.json" sync --full >/dev/null
test -s "$tmp/curl.argv"
if grep -q 'test-key' "$tmp/curl.argv"; then
    echo "the MISP key is on the curl command line" >&2
    exit 1
fi
rm -f "$tmp/live.misp.json" "$tmp/live.misp.json.cursor"

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
grep -q "^$((t0 - day))$" "$tmp/cache.misp.json.cursor"

./build/enrich -c "$tmp/live.json" sync --apply --page-size 1
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.201)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.202)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.203)
printf '%s\n' "$out" | grep -q CTI
grep -q "^$((t0 - day))$" "$tmp/live.misp.json.cursor"
grep -q "sync-sample" "$tmp/live.misp.json"
grep -q "203.0.113.203" "$tmp/live.misp.json"
# Three pages, one generation.
gen=$(awk -F '\t' '$1 == "live.misp" { print $2 }' "$tmp/live.thrt.gen")
test "$gen" = 1

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
grep -q "^$((t0 - day))$" "$tmp/live.misp.json.cursor"

# The same MISP after 203.0.113.201 was deleted. An incremental pull
# starts at the cursor and folds the withdrawal.
"$tmp/misp-standin" "$t0" withdrawn >"$tmp/port3" 2>"$tmp/standin3.err" &
srv3=$!
i=0
while [ ! -s "$tmp/port3" ]; do
    i=$((i + 1))
    if [ "$i" -gt 50 ]; then
        echo "withdrawn stand-in did not start" >&2
        exit 1
    fi
    sleep 0.1
done
port3=$(cat "$tmp/port3")
sed "s/127.0.0.1:$port\"/127.0.0.1:$port3\"/" "$tmp/live.json" >"$tmp/withdrawn.json"
chmod 600 "$tmp/withdrawn.json"
./build/enrich -c "$tmp/withdrawn.json" sync --apply --page-size 1
first=$(awk 'NR == 1 { print $2 }' "$tmp/standin3.err")
test "$first" = "$((t0 - day))"
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.201)
printf '%s\n' "$out" | grep -q "NO MATCH"
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.202)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.203)
printf '%s\n' "$out" | grep -q CTI
grep -q "^$((t0 - 3600))$" "$tmp/live.misp.json.cursor"
grep -q '"deleted"' "$tmp/live.misp.json"

# The deleted indicator comes back when the feed is snapshotted again.
./build/enrich -c "$tmp/live.json" sync --apply --full --page-size 1
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.201)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.203)
printf '%s\n' "$out" | grep -q CTI
grep -q "^$((t0 - day))$" "$tmp/live.misp.json.cursor"
grep -q "sync-sample" "$tmp/live.misp.json"

# A slice over --slice-rows is split in two until it fits; one second is
# never split. The stand-in logs "window LO HI PAGE LIMIT": a probe asks
# for one row, a page for --page-size rows. Its rows are published at
# t0 - 3d, three at t0 - 2d - 1s, t0 - 2d, and t0 - 1d.
cat >"$tmp/slice.json" <<EOF
{
  "output": "$tmp/slice.thrt",
  "feeds": [{
    "name": "lab-misp",
    "type": "misp",
    "url": "http://127.0.0.1:$port",
    "key": "test-key",
    "since": "$((t0 - 3 * day))",
    "dest": "$tmp/slice.misp.json"
  }]
}
EOF
chmod 600 "$tmp/slice.json"
mark=$(wc -l <"$tmp/standin.err")
./build/enrich -c "$tmp/slice.json" sync --apply --page-size 2 --slice-rows 2
tail -n +"$((mark + 1))" "$tmp/standin.err" >"$tmp/slice.windows"
awk -v start="$((t0 - 3 * day))" -v t0="$t0" -v day="$day" '
    BEGIN {
        pub[1] = t0 - 3 * day; pub[2] = t0 - 2 * day - 1; pub[3] = pub[2]
        pub[4] = pub[2]; pub[5] = t0 - 2 * day; pub[6] = t0 - day
    }
    $5 == 1 { probes++ }
    $5 == 2 && $4 == 1 {
        n++; lo[n] = $2; hi[n] = $3
        rows = 0
        for (k = 1; k <= 6; k++) if (pub[k] >= $2 && pub[k] <= $3) rows++
        if ($2 < $3 && rows > 2) { print "window " $2 "-" $3 " holds " rows; bad = 1 }
        if ($2 == $3 && $2 == pub[2]) single = 1
    }
    $5 == 2 && $4 == 2 && $2 == $3 && $2 == pub[2] { paged = 1 }
    END {
        if (probes == 0) { print "no probe"; bad = 1 }
        if (n == 0 || lo[1] != start) { print "the first page does not start the window"; bad = 1 }
        for (k = 2; k <= n; k++)
            if (lo[k] != hi[k - 1] + 1) { print "window " k " does not follow"; bad = 1 }
        if (hi[n] < t0) { print "the last page ends at " hi[n]; bad = 1 }
        if (!single || !paged) { print "the three-row second was not paged on its own"; bad = 1 }
        exit bad
    }
' "$tmp/slice.windows"
for ip in 203.0.113.201 203.0.113.202 203.0.113.203 203.0.113.204 203.0.113.205 203.0.113.206; do
    test "$(grep -o "\"$ip\"" "$tmp/slice.misp.json" | wc -l | tr -d ' ')" = 1
    ./build/enrich -c "$tmp/slice.json" lookup "$ip" | grep -q CTI
done

# A failed later page must not replace dest, the cursor, or output.
"$tmp/misp-standin" "$t0" fail-page >"$tmp/port2" 2>"$tmp/standin2.err" &
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
grep -q "^$((t0 - day))$" "$tmp/live.misp.json.cursor"
grep -q "sync-sample" "$tmp/live.misp.json"
if find "$tmp" \( -name '*.page.*.misp.json' -o -name '*.pull.*.misp.json' -o -name '*.work.*' \) | grep -q .; then
    echo "a failed pull left a page or work file" >&2
    exit 1
fi

echo "sync ok"
