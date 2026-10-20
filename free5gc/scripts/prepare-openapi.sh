#!/usr/bin/env bash
# Prepare a copy of github.com/free5gc/openapi with the Naanf_AKMA models and
# client added (patches/openapi/*.patch). The AAnF, and later the AUSF, use it
# through a "replace" directive in go.mod.
#
# Usage: free5gc/scripts/prepare-openapi.sh [destination] [version]
#   destination defaults to free5gc/build/openapi
#   version defaults to v1.2.4, the version pinned by the AUSF, UDM and NRF
#   of free5GC v4.2.3; the test bench of free5GC (~/free5gc/test) pins
#   v1.2.5-0.20260527003827-02dc71b4d94f and uses free5gc/build/openapi-test.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
dest="${1:-$here/build/openapi}"
OPENAPI_VERSION="${2:-v1.2.4}"

command -v go >/dev/null || { echo "go not found in PATH" >&2; exit 1; }

src="$(go mod download -json "github.com/free5gc/openapi@${OPENAPI_VERSION}" \
       | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"
[ -d "$src" ] || { echo "could not download free5gc/openapi ${OPENAPI_VERSION}" >&2; exit 1; }

# Only a previous copy of free5gc/openapi is replaced.
if [ -e "$dest" ]; then
    grep -q '^module github.com/free5gc/openapi$' "$dest/go.mod" 2>/dev/null \
        || { echo "$dest exists and is not a copy of free5gc/openapi; not touching it" >&2; exit 1; }
    rm -rf "$dest"
fi
mkdir -p "$(dirname "$dest")"
cp -r "$src" "$dest"
chmod -R u+w "$dest"

for p in "$here"/patches/openapi/*.patch; do
    echo "applying $(basename "$p")"
    patch -d "$dest" -p1 --forward --quiet < "$p"
done

echo "patched free5gc/openapi ${OPENAPI_VERSION} ready at $dest"
