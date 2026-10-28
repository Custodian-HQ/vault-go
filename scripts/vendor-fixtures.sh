#!/bin/sh
# Copies the fixtures from a checkout of custodian-device-crypto and pins the manifest.
# Usage: scripts/vendor-fixtures.sh ../custodian-device-crypto
# Review the diff before committing: it shows exactly what the wire format changed.
set -eu
src=${1:?path to custodian-device-crypto}/fixtures/v1
root=$(cd "$(dirname "$0")/.." && pwd)
dest=$root/testdata/fixtures/v1
rm -rf "$dest"
mkdir -p "$dest"
cp "$src"/* "$dest"/
shasum -a 256 "$dest/MANIFEST.json" | cut -d' ' -f1 > "$root/testdata/fixtures.lock"
echo "vendored $(ls "$dest" | wc -l | tr -d ' ') files; pinned manifest $(cat "$root/testdata/fixtures.lock")"
