#!/usr/bin/env bash
# Make the test PKI of the operator for the service-based interfaces: the CA,
# the certificates of the NFs and of the test tools, and the CRL.
#
# Usage: free5gc/scripts/make-sba-certs.sh <directory> <entities> [all|crl|revoke <name>|check]
#   directory  where the files go, usually cert/sba of free5GC; the CRL goes in
#              the crl directory next to it (cert/crl)
#   entities   free5gc/config/sba-entities.conf
#
#   all     (default) the CA, each certificate that is missing, that expires
#           in less than 30 days or whose entity line changed, and the CRL
#   crl     sign the CRL again, with nextUpdate one week ahead
#   revoke  revoke the certificate of <name> and sign the CRL again
#   check   check every certificate against its profile
#
#   sba-ca.pem, sba-ca.key   CA of the operator, ECDSA P-384, signature with
#                            SHA-384; TLS client/server CA profile of
#                            TS 33.310 cl. 6.1.4a
#   <name>.pem, <name>.key   certificate of each entity, ECDSA P-256; NF profile
#                            of TS 33.310 table 6.1.3c.3-1, except nrf-token
#                            (table 6.1.3c.3-2) and ccf-internal (cl. 6.1.3a)
#   ../crl/sba-ca.crl        the CRL, v2, in DER (TS 33.310 cl. 6.1a;
#                            RFC 5280 cl. 4.2.1.13)
#
#   Test only: the private keys are not encrypted, and the key of the CA stays
#   on this machine.
set -euo pipefail

[ $# -ge 2 ] || { echo "usage: $0 <directory> <entities> [all|crl|revoke <name>|check]" >&2; exit 2; }
dir="$1"
entities="$2"
action="${3:-all}"
command -v openssl >/dev/null || { echo "openssl not found in PATH" >&2; exit 1; }
[ -f "$entities" ] || { echo "no file $entities" >&2; exit 1; }
mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"
crl_dir="$(dirname "$dir")/crl"
db="$dir/ca"
umask 077

setting() { awk -v k="$1" '$1 == k { print $2; exit }' "$entities"; }
country="$(setting country)"
domain="$(setting domain)"
crl_url="$(setting crl)"
[ -n "$country" ] && [ -n "$domain" ] && [ -n "$crl_url" ] \
    || { echo "$entities needs country, domain and crl" >&2; exit 1; }

# entity_lines: the lines of the entities, without the settings.
entity_lines() { grep -E '^(nf|client|revoked|no-crldp|other-ca|token|ccf) ' "$entities"; }

# is_ec_key <file> <curve>: the file holds an EC private key on the curve
# (OpenSSL name).
is_ec_key() {
    [ -f "$1" ] && openssl pkey -in "$1" -noout -text 2>/dev/null | grep -q "ASN1 OID: $2"
}

# new_key <file> <curve for genpkey> <curve for is_ec_key>
new_key() {
    is_ec_key "$1" "$3" || openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$2" -out "$1" 2>/dev/null
}

# ca_config <directory of the CA> <certificate> <key>: the configuration of
# "openssl ca". Own file, so that nothing comes from the default configuration
# of OpenSSL: the CA certificate has only its own extensions (RFC 5280 cl. 4.2).
ca_config() {
    printf '%s\n' \
        '[ca]' 'default_ca = this' \
        '[this]' \
        "dir = $1" \
        'database = $dir/index.txt' 'new_certs_dir = $dir/newcerts' 'serial = $dir/serial' 'crlnumber = $dir/crlnumber' \
        "certificate = $2" "private_key = $3" \
        'default_md = sha384' 'default_days = 365' 'default_crl_days = 7' \
        'policy = names' 'preserve = yes' 'email_in_dn = no' 'unique_subject = no' 'utf8 = yes' 'string_mask = utf8only' \
        'copy_extensions = none' 'crl_extensions = crl_ext' \
        '[names]' 'countryName = optional' 'organizationName = optional' 'commonName = supplied' \
        '[crl_ext]' 'authorityKeyIdentifier = keyid:always'
}

# prepare_ca <directory of the CA> <certificate> <key> <subject>: the CA and its
# database, when missing.
prepare_ca() {
    local cadir="$1" cert="$2" key="$3" subject="$4"
    mkdir -p "$cadir/newcerts"
    [ -f "$cadir/index.txt" ] || : >"$cadir/index.txt"
    [ -f "$cadir/index.txt.attr" ] || echo 'unique_subject = no' >"$cadir/index.txt.attr"
    [ -f "$cadir/crlnumber" ] || echo 01 >"$cadir/crlnumber"
    ca_config "$cadir" "$cert" "$key" >"$cadir/openssl.cnf"
    if [ ! -f "$cert" ] || ! is_ec_key "$key" secp384r1; then
        new_key "$key" P-384 secp384r1
        openssl req -x509 -new -key "$key" -sha384 -days 1825 -utf8 -subj "$subject" -out "$cert" -config <(printf '%s\n' \
            '[req]' 'distinguished_name = dn' 'x509_extensions = ca' 'string_mask = utf8only' '[dn]' \
            '[ca]' 'basicConstraints = critical,CA:TRUE,pathlen:0' 'keyUsage = critical,keyCertSign,cRLSign' \
            'subjectKeyIdentifier = hash')
        echo "made the CA $cert"
    fi
}

# nf_types_section <type>: the NFTypes extension (RFC 9310), that OpenSSL does
# not know, by its OID.
nf_types_section() {
    printf '%s\n' '1.3.6.1.5.5.7.1.34 = ASN1:SEQUENCE:nf_types' '[nf_types]' "t1 = IA5STRING:$1"
}

# extensions <role> <name> <type> <fqdn> <address> <port> <id>
extensions() {
    local role="$1" type="$3" fqdn="$4" address="$5" port="$6" id="$7"
    local san eku
    printf '%s\n' '[ext]' 'keyUsage = critical,digitalSignature' \
        'authorityKeyIdentifier = keyid:always' 'subjectKeyIdentifier = hash'
    case "$role" in
    nf)
        eku='clientAuth,serverAuth'
        san="URI:urn:uuid:$id,DNS:$fqdn,IP:$address,URI:https://$fqdn:$port"
        ;;
    token)
        eku='1.3.6.1.5.5.7.3.39'
        san="URI:urn:uuid:$id"
        ;;
    ccf)
        eku='serverAuth'
        san="DNS:$fqdn,IP:$address"
        ;;
    *)
        eku='clientAuth'
        san="URI:urn:uuid:$id,DNS:$fqdn"
        ;;
    esac
    printf '%s\n' "extendedKeyUsage = $eku" "subjectAltName = critical,$san"
    [ "$role" = no-crldp ] || echo "crlDistributionPoints = URI:$crl_url"
    [ "$role" = ccf ] || nf_types_section "$type"
}

subject_of() { # <role> <fqdn>
    local cn="$2"
    [ "$1" = token ] && cn='NRF access token signing'
    printf '/C=%s/O=%s/CN=%s' "$country" "$domain" "$cn"
}

# issue <line of the entity>: the certificate of the entity, when needed. Says
# on stdout whether it was issued, for the caller to revoke the test one.
issue() {
    local role name type fqdn address port id cadir cacert line_file
    read -r role name type fqdn address port id <<<"$1"
    cadir="$db"
    cacert="$dir/sba-ca.pem"
    if [ "$role" = other-ca ]; then
        cadir="$dir/other-ca-ca.d"
        cacert="$dir/other-ca-ca.pem"
    fi
    line_file="$db/issued/$name.line"
    mkdir -p "$db/issued"
    if [ -f "$dir/$name.pem" ] && openssl x509 -in "$dir/$name.pem" -noout -checkend 2592000 >/dev/null 2>&1 \
        && [ "$(cat "$line_file" 2>/dev/null)" = "$1" ]; then
        return 0
    fi
    new_key "$dir/$name.key" P-256 prime256v1
    openssl req -new -key "$dir/$name.key" -utf8 -subj "$(subject_of "$role" "$fqdn")" -out "$dir/$name.csr" \
        -config <(printf '%s\n' '[req]' 'distinguished_name = dn' 'string_mask = utf8only' '[dn]')
    # 16 random octets, positive: the serial number of the certificate
    # (TS 33.310 table 6.1.3c.3-1)
    openssl rand -hex 16 | sed 's/^./4/' >"$cadir/serial"
    openssl ca -batch -notext -config "$cadir/openssl.cnf" -in "$dir/$name.csr" -out "$dir/$name.pem" \
        -extfile <(extensions "$role" "$name" "$type" "$fqdn" "$address" "$port" "$id") -extensions ext 2>/dev/null
    rm -f "$dir/$name.csr"
    echo "$1" >"$line_file"
    echo "issued"
}

sign_crl() {
    mkdir -p "$crl_dir"
    openssl ca -config "$db/openssl.cnf" -gencrl -out "$db/crl.pem" 2>/dev/null
    openssl crl -in "$db/crl.pem" -outform DER -out "$crl_dir/sba-ca.crl"
    chmod 644 "$crl_dir/sba-ca.crl"
    chmod 755 "$crl_dir"
    echo "signed $crl_dir/sba-ca.crl"
}

revoke() { # <name>
    openssl ca -config "$db/openssl.cnf" -revoke "$dir/$1.pem" -crl_reason keyCompromise 2>/dev/null
    echo "revoked $1"
}

make_all() {
    local line state
    prepare_ca "$db" "$dir/sba-ca.pem" "$dir/sba-ca.key" "/C=$country/O=$domain/CN=SBA test CA"
    prepare_ca "$dir/other-ca-ca.d" "$dir/other-ca-ca.pem" "$dir/other-ca-ca.key" "/O=AKMA test/CN=Other test CA"
    while read -r line; do
        state="$(issue "$line")"
        if [ -n "$state" ]; then
            echo "made $(awk '{print $2}' <<<"$line")"
            if [ "${line%% *}" = revoked ]; then
                revoke "$(awk '{print $2}' <<<"$line")"
            fi
        fi
    done < <(entity_lines)
    sign_crl
    chmod 755 "$dir"
    chmod 644 "$dir"/*.pem
}

# ---------------------------------------------------------------- check
problems=0
problem() { echo "$1: $2"; problems=$((problems + 1)); }

# nf_types_hex <type>: the DER of NFTypes with one NFType, in upper case hex
nf_types_hex() {
    local hex len
    hex="$(printf '%s' "$1" | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')"
    len=${#1}
    printf '30%02X16%02X%s' $((len + 2)) "$len" "$hex"
}

check_one() {
    local role name type fqdn address port id f text not_before not_after serial subject san cn
    read -r role name type fqdn address port id <<<"$1"
    f="$dir/$name.pem"
    [ -f "$f" ] || { problem "$name" "no certificate"; return; }
    text="$(openssl x509 -in "$f" -noout -text)"
    grep -q 'Version: 3 ' <<<"$text" || problem "$name" "not version 3"
    serial="$(openssl x509 -in "$f" -noout -serial | cut -d= -f2)"
    { [ ${#serial} -le 40 ] && [[ "$serial" =~ ^[0-7] ]]; } || problem "$name" "serial number longer than 20 octets or not positive"
    subject="$(openssl x509 -in "$f" -noout -subject -nameopt RFC2253)"
    grep -q "C=$country" <<<"$subject" || problem "$name" "no C=$country in the Subject"
    grep -q "O=$domain" <<<"$subject" || problem "$name" "O of the Subject is not $domain"
    not_before="$(date -d "$(openssl x509 -in "$f" -noout -startdate | cut -d= -f2)" +%s)"
    not_after="$(date -d "$(openssl x509 -in "$f" -noout -enddate | cut -d= -f2)" +%s)"
    [ $((not_after - not_before)) -le $((3 * 366 * 86400)) ] || problem "$name" "valid for more than 3 years"
    openssl x509 -in "$f" -noout -checkend 0 >/dev/null || problem "$name" "expired"
    grep -Eq 'Signature Algorithm: ecdsa-with-SHA(256|384)' <<<"$text" || problem "$name" "signature is not ECDSA with SHA-256 or SHA-384"
    grep -A1 'X509v3 Key Usage: critical' <<<"$text" | grep -q 'Digital Signature' || problem "$name" "keyUsage not critical or without digitalSignature"
    local eku
    eku="$(grep -A1 'X509v3 Extended Key Usage' <<<"$text" | tail -1)"
    case "$role" in
    nf) grep -q 'TLS Web Client Authentication' <<<"$eku" && grep -q 'TLS Web Server Authentication' <<<"$eku" || problem "$name" "extendedKeyUsage without clientAuth and serverAuth" ;;
    token) grep -Eq '1\.3\.6\.1\.5\.5\.7\.3\.39|oauthAccessTokenSigning' <<<"$eku" || problem "$name" "extendedKeyUsage without id-kp-oauthAccessTokenSigning" ;;
    ccf) grep -q 'TLS Web Server Authentication' <<<"$eku" || problem "$name" "extendedKeyUsage without serverAuth" ;;
    *) grep -q 'TLS Web Client Authentication' <<<"$eku" || problem "$name" "extendedKeyUsage without clientAuth" ;;
    esac
    local aki ski
    aki="$(grep -A1 'X509v3 Authority Key Identifier' <<<"$text" | tail -1 | sed 's/keyid://; s/[[:space:]]//g')"
    ski="$(openssl x509 -in "$dir/sba-ca.pem" -noout -text | grep -A1 'X509v3 Subject Key Identifier' | tail -1 | tr -d ' ')"
    if [ "$role" != other-ca ]; then
        [ -n "$aki" ] && [ "$aki" = "$ski" ] || problem "$name" "authorityKeyIdentifier differs from the CA"
    fi
    grep -q 'X509v3 Subject Key Identifier' <<<"$text" || problem "$name" "no subjectKeyIdentifier"
    if [ "$role" = no-crldp ]; then
        grep -q 'CRL Distribution Points' <<<"$text" && problem "$name" "has a CRL distribution point"
    else
        grep -q "URI:$crl_url" <<<"$text" || problem "$name" "CRL distribution point is not $crl_url"
    fi
    grep -q 'X509v3 Subject Alternative Name: critical' <<<"$text" || problem "$name" "subjectAltName not critical"
    san="$(grep -A1 'X509v3 Subject Alternative Name' <<<"$text" | tail -1)"
    if [ "$role" != ccf ]; then
        [[ "$id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || problem "$name" "$id is not a UUID v4"
        grep -q "URI:urn:uuid:$id" <<<"$san" || problem "$name" "no urn:uuid:$id in the subjectAltName"
    fi
    case "$role" in
    nf | ccf)
        grep -q "DNS:$fqdn" <<<"$san" || problem "$name" "no DNS-ID $fqdn"
        grep -q "IP Address:$address" <<<"$san" || problem "$name" "no IP $address"
        ;;
    esac
    [ "$role" = nf ] && { grep -q "URI:https://$fqdn:$port" <<<"$san" || problem "$name" "no URI of the apiRoot"; }
    cn="$(sed -n 's/.*CN=\([^,]*\).*/\1/p' <<<"$subject")"
    [ "$role" = token ] || grep -q "DNS:$cn" <<<"$san" || problem "$name" "CN $cn is not in the subjectAltName"
    if [ "$role" != ccf ]; then
        local asn
        asn="$(openssl x509 -in "$f" -outform DER | openssl asn1parse -inform DER)"
        grep -A1 ':1.3.6.1.5.5.7.1.34' <<<"$asn" | grep -q "OCTET STRING.*\[HEX DUMP\]:$(nf_types_hex "$type")\$" \
            || problem "$name" "nfTypes missing, critical or not $type"
    fi
    if [ "$role" = revoked ]; then
        openssl crl -in "$crl_dir/sba-ca.crl" -inform DER -noout -text | grep -q "Serial Number: $serial" \
            || problem "$name" "not in the CRL"
    fi
    local critical
    critical="$(grep -E ': critical$' <<<"$text" | grep -Ev 'X509v3 (Key Usage|Subject Alternative Name): critical' || true)"
    [ -z "$critical" ] || problem "$name" "other critical extension: $critical"
}

check_all() {
    local line
    while read -r line; do
        check_one "$line"
    done < <(entity_lines)
    openssl crl -in "$crl_dir/sba-ca.crl" -inform DER -noout -CAfile "$dir/sba-ca.pem" 2>&1 | grep -q 'verify OK' \
        || problem CRL "signature does not verify with the CA"
    openssl crl -in "$crl_dir/sba-ca.crl" -inform DER -noout -text | grep -q 'Version 2' \
        || problem CRL "not a v2 CRL"
    if [ "$problems" -eq 0 ]; then
        echo "every certificate fits its profile"
    else
        echo "$problems problem(s)"
        exit 1
    fi
}

case "$action" in
all) make_all ;;
crl) sign_crl ;;
revoke)
    [ $# -eq 4 ] || { echo "usage: $0 <directory> <entities> revoke <name>" >&2; exit 2; }
    revoke "$4"
    sign_crl
    ;;
check) check_all ;;
*) echo "unknown action $action" >&2; exit 2 ;;
esac
