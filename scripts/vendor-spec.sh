#!/bin/sh
# Copies the business API spec from a checkout of the API source and pins it. The tests check that the SDK calls exactly the
# operations the spec lists. Review the diff before committing: it shows what the API changed.
# Usage: scripts/vendor-spec.sh <path to source checkout>
set -eu
src=${1:?usage: scripts/vendor-spec.sh <path to source checkout>}/docs/openapi-vault.yaml
root=$(cd "$(dirname "$0")/.." && pwd)
cp "$src" "$root/testdata/openapi-vault.yaml"
shasum -a 256 "$root/testdata/openapi-vault.yaml" | cut -d' ' -f1 > "$root/testdata/openapi-vault.lock"
echo "vendored the spec; pinned $(cat "$root/testdata/openapi-vault.lock")"
