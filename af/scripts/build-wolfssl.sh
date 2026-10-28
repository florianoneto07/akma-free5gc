#!/usr/bin/env bash
# Build the wolfSSL static library used by af/wolftls (build tag wolfssl).
#
# Copyright 2026 Floriano Neto. Licensed under the GNU General Public
# License v3.0 or later, as wolfSSL itself; see af/wolftls/COPYING.
#
# Usage: af/scripts/build-wolfssl.sh
#   Downloads wolfSSL $version, checks the SHA-256 of the archive, builds a
#   static library with the TLS profile of TS 33.210 cl. 6.2 and installs it
#   in af/build/wolfssl. Then checks the macros of wolfssl/options.h.
#   WOLFSSL_ZIP=<file> uses a local copy of the archive.
#   Needs gcc, make and unzip.
set -euo pipefail

version=5.9.4
sha256=9cd0d69d208d025b16836c177658cc0deebc2a85c4b60898c9bc546bc6cbdf18
url="https://www.wolfssl.com/wolfssl-$version.zip"

here="$(cd "$(dirname "$0")/.." && pwd)"
build="$here/build/wolfssl"
prefix="$build/install"

for c in gcc make unzip sha256sum; do
    command -v "$c" >/dev/null || { echo "$c not found in PATH" >&2; exit 1; }
done

mkdir -p "$build"
zip="${WOLFSSL_ZIP:-$build/wolfssl-$version.zip}"
if [ ! -f "$zip" ]; then
    echo "downloading $url"
    wget -q -O "$zip.part" "$url" || curl -fsSL -o "$zip.part" "$url"
    mv "$zip.part" "$zip"
fi
echo "$sha256  $zip" | sha256sum -c --quiet - || {
    echo "$zip: SHA-256 differs from the pinned wolfSSL $version" >&2
    exit 1
}

src="$build/wolfssl-$version"
rm -rf "$src" "$prefix"
unzip -q "$zip" -d "$build"

# TS 33.210 cl. 6.2: TLS 1.2 and 1.3, nothing older (default); no finite
# field DH; SNI, Extended Master Secret and RFC 5746 (defaults); x25519 and
# P-256. PSK for the K.3 profiles of TS 24.109; session tickets for the
# resumption of TS 33.222 cl. 5.3.1.5 and 5.4.1.4. DTLS 1.2 and 1.3, with a
# settable MTU, and AES-CCM for the DTLS profiles of TS 33.535 Annex C. No
# early data (0-RTT). No RNG
# fork handlers: Go programs never use wolfSSL across fork(), and the
# handlers need dlopen, which a static binary does not have.
# With a DTLS MTU set, wolfSSL reads at most MTU + this many octets per
# datagram (500 by default): a ClientHello with post-quantum key shares, as
# OpenSSL 4.1 sends, is larger. The MTU still bounds what wolfSSL sends.
cd "$src"
./configure --prefix="$prefix" \
    --enable-static --disable-shared --disable-rng-autofork \
    --enable-psk --enable-session-ticket \
    --enable-dtls --enable-dtls13 --enable-dtls-mtu --enable-aesccm \
    --enable-curve25519 --disable-dh \
    --disable-earlydata --disable-oldtls \
    --disable-examples --disable-crypttests \
    CFLAGS="-O2 -fPIC -DWOLFSSL_DTLS_MTU_ADDITIONAL_READ_BUFFER=16384" >"$build/configure.log"
make -j"$(nproc)" >"$build/make.log" 2>&1
make install >>"$build/make.log" 2>&1

# The library must have what af/wolftls and the profiles need, and nothing
# that TS 33.210 cl. 6.2 forbids.
opts="$prefix/include/wolfssl/options.h"
fail=0
for m in WOLFSSL_TLS13 WOLFSSL_DTLS WOLFSSL_DTLS13 WOLFSSL_DTLS_MTU HAVE_AESGCM HAVE_AESCCM HAVE_ECC HAVE_CURVE25519 \
         HAVE_SNI HAVE_EXTENDED_MASTER HAVE_SERVER_RENEGOTIATION_INFO HAVE_SUPPORTED_CURVES \
         HAVE_SESSION_TICKET NO_DH NO_OLD_TLS; do
    grep -q "^#define $m\b" "$opts" || { echo "options.h: $m missing" >&2; fail=1; }
done
for m in NO_PSK WOLFSSL_EARLY_DATA WOLFSSL_ALLOW_TLSV10 WOLFSSL_ALLOW_SSLV3 HAVE_TRUNCATED_HMAC; do
    grep -q "^#define $m\b" "$opts" && { echo "options.h: $m must not be defined" >&2; fail=1; }
done
grep -q "LIBWOLFSSL_VERSION_STRING \"$version\"" "$prefix/include/wolfssl/version.h" ||
    { echo "version.h: not wolfSSL $version" >&2; fail=1; }
[ "$fail" = 0 ] || exit 1

echo "built wolfSSL $version in $prefix"
