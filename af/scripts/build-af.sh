#!/usr/bin/env bash
# Build the AF and the Ua* client.
#
# Usage: af/scripts/build-af.sh
#   Output: af/build/bin/af and af/build/bin/uaclient (static binaries).
#   Prepares the patched free5gc/openapi first when it is missing: the AF
#   uses its Naanf_AKMA client.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$here/.." && pwd)"

command -v go >/dev/null || { echo "go not found in PATH" >&2; exit 1; }

if [ ! -f "$repo/free5gc/build/openapi/aanf/AKMA/client.go" ]; then
    "$repo/free5gc/scripts/prepare-openapi.sh"
fi

mkdir -p "$here/build/bin"
cd "$here"
CGO_ENABLED=0 go build -trimpath -o "$here/build/bin/af" ./af/cmd/af
CGO_ENABLED=0 go build -trimpath -o "$here/build/bin/uaclient" ./ue/uaclient/cmd/uaclient
echo "built $here/build/bin/af and $here/build/bin/uaclient"
