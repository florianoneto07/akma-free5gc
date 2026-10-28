#!/usr/bin/env bash
# Build the AF and the Ua* client.
#
# Usage: af/scripts/build-af.sh
#   Output: af/build/bin/af and af/build/bin/uaclient (static binaries).
#   Prepares the patched free5gc/openapi first when it is missing: the AF
#   uses its Naanf_AKMA client.
#
#   With the wolfSSL library of af/scripts/build-wolfssl.sh, both binaries
#   have the PSK profiles (psk-tls13, psk-tls12, psk-dtls13, psk-dtls12) and,
#   linked with wolfSSL, are licensed under the GNU General Public License
#   v3.0. Without it, or with AF_WOLFSSL=no, they have the other profiles
#   only.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$here/.." && pwd)"
lib="$here/build/wolfssl/install/lib/libwolfssl.a"

command -v go >/dev/null || { echo "go not found in PATH" >&2; exit 1; }

if [ ! -f "$repo/free5gc/build/openapi/aanf/AKMA/client.go" ]; then
    "$repo/free5gc/scripts/prepare-openapi.sh"
fi

mkdir -p "$here/build/bin"
cd "$here"
if [ -f "$lib" ] && [ "${AF_WOLFSSL:-yes}" != no ]; then
    # The Go build cache does not see the library: its hash, compiled into
    # af/wolftls, makes a new library rebuild that package and link the
    # binaries again.
    export CGO_ENABLED=1 CGO_CFLAGS="-O2 -g -DWOLFTLS_LIB=0x$(sha256sum "$lib" | cut -c1-16)ULL"
    flags=(-tags 'wolfssl netgo osusergo' -ldflags '-linkmode external -extldflags -static')
    with="with wolfSSL (PSK profiles; GPLv3 binaries)"
else
    export CGO_ENABLED=0
    flags=()
    with="without wolfSSL (no PSK profiles)"
fi
go build -trimpath "${flags[@]}" -o "$here/build/bin/af" ./af/cmd/af
go build -trimpath "${flags[@]}" -o "$here/build/bin/uaclient" ./ue/uaclient/cmd/uaclient
echo "built $here/build/bin/af and $here/build/bin/uaclient $with"
