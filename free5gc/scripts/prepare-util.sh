#!/usr/bin/env bash
# Prepare a copy of github.com/free5gc/util without the log of the TLS secrets
# (patches/util/*.patch). The NFs use it through a "replace" directive in go.mod.
#
# Usage: free5gc/scripts/prepare-util.sh [destination] [version]
#   destination defaults to free5gc/build/util
#   version defaults to v1.3.2, the version pinned by the NFs of free5GC v4.2.3
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
dest="${1:-$here/build/util}"
UTIL_VERSION="${2:-v1.3.2}"

command -v go >/dev/null || { echo "go not found in PATH" >&2; exit 1; }

src="$(go mod download -json "github.com/free5gc/util@${UTIL_VERSION}" \
       | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"
[ -d "$src" ] || { echo "could not download free5gc/util ${UTIL_VERSION}" >&2; exit 1; }

# Only a previous copy of free5gc/util is replaced.
if [ -e "$dest" ]; then
    grep -q '^module github.com/free5gc/util$' "$dest/go.mod" 2>/dev/null \
        || { echo "$dest exists and is not a copy of free5gc/util; not touching it" >&2; exit 1; }
    rm -rf "$dest"
fi
mkdir -p "$(dirname "$dest")"
cp -r "$src" "$dest"
chmod -R u+w "$dest"

for p in "$here"/patches/util/*.patch; do
    echo "applying $(basename "$p")"
    patch -d "$dest" -p1 --forward --quiet < "$p"
done

echo "patched free5gc/util ${UTIL_VERSION} ready at $dest"
