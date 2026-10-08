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
expect 203.0.113.61 CTI
expect 203.0.113.62 CTI
expect 203.0.113.56 CTI_R
expect 203.0.113.57 TAGS
expect 203.0.113.58 TAGS

expect 203.0.113.70 CTI
expect 203.0.113.71 CTI
expect or.example CTI
expect 203.0.113.72 CTI
expect 203.0.113.73 CTI
expect 2001:db8::70 CTI
expect http://evil.example/stix CTI
expect stix@example.com CTI
expect 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae CTI
expect bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb CTI
expect stixlab.exe CTI
expect 'Global\StixLab' CTI
expect 64496 CTI
expect 203.0.113.100 CTI
expect 203.0.113.82 CTI
expect 203.0.113.83 CTI
expect 203.0.113.87 CTI
expect 203.0.113.78 CTI
expect 203.0.113.79 CTI_R
expect d41d8cd98f00b204e9800998ecf8427e CTI

miss() {
    ind=$1
    out=$(./build/enrich -c docs/examples/enrich.json lookup "$ind")
    printf '%s\n' "$out"
    printf '%s\n' "$out" | grep -q "NO MATCH"
}

miss 203.0.113.74
miss 203.0.113.75
miss 203.0.113.76
miss 203.0.113.81
miss 203.0.113.84
miss 203.0.113.85
miss 203.0.113.86
miss 203.0.113.95
miss skip.example

color() {
    ind=$1
    kind=$2
    out=$(./build/enrich -c docs/examples/enrich.json lookup "$ind")
    printf '%s\n' "$out" | grep -q "$kind"
}
color 203.0.113.61 GREEN
color 203.0.113.61 'misp-event:search-sample'
color 203.0.113.61 '90%'
color 203.0.113.62 WHITE
color 203.0.113.70 WHITE
color 203.0.113.82 RED
color 203.0.113.83 AMBER
color 203.0.113.87 GREEN
color 203.0.113.83 'tlp:amber+strict'

./build/enrich -c docs/examples/enrich.json apply-delta \
    --segment docs/examples/delta.csv --feed-key sample
expect 203.0.113.60 CTI
./build/enrich -c docs/examples/enrich.json apply-delta \
    --segment docs/examples/delta.stix.json --feed-key stix-delta
expect 203.0.113.80 CTI
echo "docs/check.sh: ok"
