#!/bin/sh
# Run the worked example in docs/manual.md. Exit non-zero if a lookup
# does not come back as the layer that example file claims.
set -eu
cd "$(dirname "$0")/.."
test -x build/enrich
rm -rf build/docs
mkdir -p build/docs
./build/enrich -c docs/examples/enrich.json build
test -s build/docs/threat.thrt
test -s build/docs/allow.ovly

expect() {
    ind=$1
    kind=$2
    out=$(./build/enrich -c docs/examples/enrich.json lookup "$ind")
    printf '%s\n' "$out"
    printf '%s\n' "$out" | grep -q "$kind"
}

expect 203.0.113.50 CTI
expect 203.0.113.51 CTI
expect 203.0.113.52 CTI
expect 203.0.113.53 CTI
expect 203.0.113.54 CTI
expect 203.0.113.55 CTI
expect 203.0.113.56 CTI_R
expect 203.0.113.57 TAGS
expect 203.0.113.58 TAGS

./build/enrich -c docs/examples/enrich.json apply-delta \
    --segment docs/examples/delta.csv --feed-key sample
expect 203.0.113.60 CTI
echo "docs/check.sh: ok"
