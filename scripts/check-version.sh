#!/usr/bin/env bash
# Fails unless the tag (for example v0.1.0) equals the version of the vendored API spec.
set -euo pipefail
cd "$(dirname "$0")/.."
tag="${1:?usage: check-version.sh <tag>}"
spec=$(awk '/^info:/{i=1} i && /^  version:/{print $2; exit}' testdata/openapi-vault.yaml)
[ -n "$spec" ] || { echo "no version in testdata/openapi-vault.yaml"; exit 1; }
[ "${tag#v}" = "$spec" ] || { echo "tag $tag does not match the API spec version $spec"; exit 1; }
echo "version $spec ok"
