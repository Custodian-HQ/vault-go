#!/bin/sh
# Copies the fixtures from a checkout of the reference implementation and pins the manifest.
# Usage: scripts/vendor-fixtures.sh <path to source checkout>
# Review the diff before committing: it shows exactly what the wire format changed.
# PROVENANCE.md belongs to this repository: the copy keeps it.
set -eu
src=${1:?usage: scripts/vendor-fixtures.sh <path to source checkout>}/fixtures/v1
root=$(cd "$(dirname "$0")/.." && pwd)
dest=$root/testdata/fixtures/v1
keep=$(mktemp)
trap 'rm -f "$keep"' EXIT
cp "$dest/PROVENANCE.md" "$keep"
rm -rf "$dest"
mkdir -p "$dest"
cp "$src"/* "$dest"/
cp "$keep" "$dest/PROVENANCE.md"
shasum -a 256 "$dest/MANIFEST.json" | cut -d' ' -f1 > "$root/testdata/fixtures.lock"
echo "vendored $(ls "$dest" | wc -l | tr -d ' ') files; pinned manifest $(cat "$root/testdata/fixtures.lock")"
