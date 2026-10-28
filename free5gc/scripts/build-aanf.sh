#!/usr/bin/env bash
# Build the AAnF and the seed test tool.
#
# Usage: free5gc/scripts/build-aanf.sh
#   Output: free5gc/build/bin/aanf and free5gc/build/bin/seed (static binaries).
#   Prepares the patched free5gc/openapi first when it is missing or lacks
#   one of the patches.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$here/.." && pwd)"

command -v go >/dev/null || { echo "go not found in PATH" >&2; exit 1; }

if [ ! -f "$here/build/openapi/aanf/AKMA/client.go" ] ||
    [ ! -f "$here/build/openapi/udm/UEContextManagement/api_trigger_the_primary_re_authentication.go" ]; then
    "$here/scripts/prepare-openapi.sh"
fi

version="$(git -C "$repo" describe --tags --always --dirty 2>/dev/null || echo unknown)"
commit="$(git -C "$repo" rev-parse --short=8 HEAD 2>/dev/null || echo unknown)"
commit_time="$(git -C "$repo" log -1 --format=%cd --date=format:%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
v="github.com/free5gc/util/version"
ldflags="-X $v.VERSION=$version -X $v.BUILD_TIME=$build_time -X $v.COMMIT_HASH=$commit -X $v.COMMIT_TIME=$commit_time"

mkdir -p "$here/build/bin"
cd "$here/aanf"
CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "$here/build/bin/aanf" ./cmd
CGO_ENABLED=0 go build -trimpath -o "$here/build/bin/seed" ./tools/seed
echo "built $here/build/bin/aanf and $here/build/bin/seed ($version)"
