#!/usr/bin/env bash
# Build the service of the certificate revocation lists.
#
# Usage: free5gc/scripts/build-crl.sh
#   Output: free5gc/build/bin/crl (static binary).
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"

command -v go >/dev/null || { echo "go not found in PATH" >&2; exit 1; }

mkdir -p "$here/build/bin"
cd "$here/crl"
CGO_ENABLED=0 go build -trimpath -o "$here/build/bin/crl" .
echo "built $here/build/bin/crl"
