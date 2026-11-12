#!/usr/bin/env bash
# Make the keys and certificates of the CAPIF core function (CCF).
#
# Usage: free5gc/scripts/make-capif-certs.sh <directory> <CAPIF-1e IPv4>
#   directory      where the files go, usually the cert/ directory of free5GC
#   CAPIF-1e IPv4  address of the CCF for the API invokers; it goes in the
#                  subjectAltName of the server certificate
#
#   ccf-ca.pem, ccf-ca.key    CA of the CCF, ECDSA P-384: it signs the server
#                             certificate and the client certificates of the
#                             API invokers (TS 33.122 cl. 6.1 step 4); TLS
#                             client/server CA profile of TS 33.310 cl. 6.1.4a
#   ccf.pem, ccf.key          server certificate of CAPIF-1e, ECDSA P-256; TLS
#                             entity profile of TS 33.310 cl. 6.1.3a
#   ccf-token.key             ECDSA P-256, signs the access tokens (ES256,
#                             TS 33.210 cl. 6.3.3.1)
#   ccf-token.pub.pem         its public key, for the API exposing functions
#   ccf-credential.key        ECDSA P-256, signs the onboarding credentials
#
#   The subjects are O=AKMA test, CN=<name>, in UTF8String (TS 33.310
#   cl. 6.1.1). The server certificate has the CRL distribution point of the
#   CA of the CCF, at the CRL service on port 8030 of the address given; the
#   CCF itself signs that CRL.
#
#   Files that exist are kept when their key is of the type above, except the
#   server certificate, made again for the address given. Test only: the
#   private keys are not encrypted.
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <directory> <CAPIF-1e IPv4>" >&2; exit 2; }
dir="$1"
ip="$2"
command -v openssl >/dev/null || { echo "openssl not found in PATH" >&2; exit 1; }
[[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not an IPv4 address: $ip" >&2; exit 2; }
mkdir -p "$dir"
umask 077
org="AKMA test"

# is_ec_key <file> <curve>: the file holds an EC private key on the curve
# (OpenSSL name).
is_ec_key() {
    [ -f "$1" ] && openssl pkey -in "$1" -noout -text 2>/dev/null | grep -q "ASN1 OID: $2"
}

# The CA certificate gets only the extensions of this configuration: with the
# default configuration, OpenSSL 1.1.1 would add these to the ones of its
# v3_ca section, and a certificate with an extension twice is invalid
# (RFC 5280 cl. 4.2).
ca_config() {
    printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca' 'string_mask = utf8only' '[dn]' \
        '[ca]' 'basicConstraints = critical,CA:TRUE,pathlen:0' 'keyUsage = critical,keyCertSign,cRLSign' \
        'subjectKeyIdentifier = hash'
}

if [ ! -f "$dir/ccf-ca.pem" ] || ! is_ec_key "$dir/ccf-ca.key" secp384r1; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$dir/ccf-ca.key"
    openssl req -x509 -new -key "$dir/ccf-ca.key" -sha384 -days 1825 -utf8 -config <(ca_config) \
        -subj "/O=$org/CN=CAPIF core function test CA" -out "$dir/ccf-ca.pem"
    echo "made the CA of the CCF $dir/ccf-ca.pem"
fi

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/ccf.key"
openssl req -new -key "$dir/ccf.key" -utf8 -subj "/O=$org/CN=ccf" -out "$dir/ccf.csr"
openssl x509 -req -in "$dir/ccf.csr" -CA "$dir/ccf-ca.pem" -CAkey "$dir/ccf-ca.key" -CAcreateserial -sha384 \
    -days 365 -out "$dir/ccf.pem" -extfile <(printf '%s\n' \
        "keyUsage=critical,digitalSignature" \
        "extendedKeyUsage=serverAuth" \
        "crlDistributionPoints=URI:http://$ip:8030/ccf-ca.crl" \
        "subjectAltName=IP:$ip") 2>/dev/null
rm -f "$dir/ccf.csr"
echo "made the server certificate of CAPIF-1e $dir/ccf.pem for $ip"

for key in ccf-token ccf-credential; do
    if ! is_ec_key "$dir/$key.key" prime256v1; then
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/$key.key"
        echo "made $dir/$key.key"
    fi
done
openssl pkey -in "$dir/ccf-token.key" -pubout -out "$dir/ccf-token.pub.pem"
chmod 644 "$dir/ccf-ca.pem" "$dir/ccf.pem" "$dir/ccf-token.pub.pem"
