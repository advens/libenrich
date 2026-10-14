#!/bin/sh
# Offline checks for enrich sync. A local POST server stands in for MISP.
set -eu
cd "$(dirname "$0")/.."
test -x build/enrich

tmp=$(mktemp -d)
srv=0
cleanup() {
    if [ "$srv" != 0 ]; then
        kill "$srv" 2>/dev/null || true
        wait "$srv" 2>/dev/null || true
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

cat >"$tmp/misp.py" <<'PY'
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FULL = [
    {
        "id": "1",
        "type": "ip-dst",
        "value": "203.0.113.201",
        "to_ids": True,
        "timestamp": "100",
        "category": "Network activity",
        "Tag": [{"name": "tlp:green"}],
        "Event": {"info": "sync-sample", "threat_level_id": "1"},
    },
    {
        "id": "2",
        "type": "ip-dst",
        "value": "203.0.113.202",
        "to_ids": True,
        "timestamp": 150,
        "category": "Network activity",
    },
]
DELTA = [
    {
        "id": "1",
        "type": "ip-dst",
        "value": "203.0.113.201",
        "to_ids": True,
        "deleted": True,
        "timestamp": 300,
        "category": "Network activity",
    }
]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(n).decode() or "{}")
        last = str(body.get("last", ""))
        page = int(body.get("page", 1))
        limit = int(body.get("limit", 2000))
        src = DELTA if last.isdigit() else FULL
        start = (page - 1) * limit
        chunk = src[start:start + limit]
        payload = json.dumps({"response": {"Attribute": chunk}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(httpd.server_address[1], flush=True)
httpd.serve_forever()
PY

python3 "$tmp/misp.py" >"$tmp/port" &
srv=$!
i=0
while [ ! -s "$tmp/port" ]; do
    i=$((i + 1))
    if [ "$i" -gt 50 ]; then
        echo "misp stand-in did not start" >&2
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

./build/enrich -c "$tmp/live.json" sync --apply --page-size 1
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.201)
printf '%s\n' "$out" | grep -q CTI
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.202)
printf '%s\n' "$out" | grep -q CTI
grep -q '^150$' "$tmp/live.misp.json.cursor"
grep -q "sync-sample" "$tmp/live.misp.json"

./build/enrich -c "$tmp/live.json" sync --apply --page-size 1
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.201)
printf '%s\n' "$out" | grep -q "NO MATCH"
out=$(./build/enrich -c "$tmp/live.json" lookup 203.0.113.202)
printf '%s\n' "$out" | grep -q CTI
grep -q '^300$' "$tmp/live.misp.json.cursor"
grep -q '"deleted"' "$tmp/live.misp.json"

echo "sync ok"
