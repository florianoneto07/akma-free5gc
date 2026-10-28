#!/usr/bin/env bash
# Make a test CA and the certificate of the AF for the digest-tls profile
# (TS 24.109 K.2: the AF is authenticated by its certificate).
#
# Usage: af/scripts/make-test-ca.sh [FQDN]
#   FQDN  of the AF, af1.akma.example when absent
#   Output in af/build/cert: ca.pem and ca.key (kept when they exist),
#   <FQDN>.pem and <FQDN>.key (made again). ECDSA P-256 with SHA-256; the
#   certificate of the AF names the FQDN in subjectAltName, which the UE
#   checks (TS 33.222 cl. 5.3.1.3, RFC 2818 cl. 3.1).
#
#   Test only: the private keys are not encrypted. The UE needs ca.pem
#   (uaclient -ca).
set -euo pipefail

fqdn="${1:-af1.akma.example}"
here="$(cd "$(dirname "$0")/.." && pwd)"
dir="$here/build/cert"
command -v openssl >/dev/null || { echo "openssl not found in PATH" >&2; exit 1; }
mkdir -p "$dir"
umask 077

if [ ! -f "$dir/ca.pem" ] || [ ! -f "$dir/ca.key" ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/ca.key"
    openssl req -x509 -new -key "$dir/ca.key" -sha256 -days 1825 -subj "/CN=AKMA test CA" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$dir/ca.pem"
    echo "made the test CA $dir/ca.pem"
fi

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/$fqdn.key"
openssl req -new -key "$dir/$fqdn.key" -subj "/CN=$fqdn" -out "$dir/$fqdn.csr"
openssl x509 -req -in "$dir/$fqdn.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" -CAcreateserial -sha256 \
    -days 365 -out "$dir/$fqdn.pem" -extfile <(printf '%s\n' \
        "basicConstraints=critical,CA:FALSE" \
        "keyUsage=critical,digitalSignature" \
        "extendedKeyUsage=serverAuth" \
        "subjectAltName=DNS:$fqdn") 2>/dev/null
rm -f "$dir/$fqdn.csr"
chmod 644 "$dir/ca.pem" "$dir/$fqdn.pem"
openssl verify -CAfile "$dir/ca.pem" "$dir/$fqdn.pem" >/dev/null
echo "made $dir/$fqdn.pem for $fqdn, signed by $dir/ca.pem"
