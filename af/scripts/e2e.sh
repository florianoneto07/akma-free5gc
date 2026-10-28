#!/usr/bin/env bash
# End-to-end run of AKMA: free5GC with the AAnF, UERANSIM with the AKMA ME,
# the AF and the Ua* client of the UE, plus the negative tests. Runs on the AF
# machine; drives the free5GC host by SSH and asks once, there, for the sudo
# password (af/scripts/e2e-remote.sh).
#
# Usage: af/scripts/e2e.sh [--keep] [user@host]
#   --keep     leave free5GC, the gNB and the UE running at the end
#   user@host  free5GC host; FREE5GC_HOST when absent
#
# Prerequisites: on the free5GC host, the repository at ~/akma-free5gc, the
# free5GC and UERANSIM patches applied, the AAnF installed and the seed tool
# at ~/akma-tools/seed; here, af/scripts/build-wolfssl.sh,
# af/scripts/build-af.sh, af/scripts/make-test-ca.sh and
# free5gc/scripts/build-aanf.sh run, and the AF configuration of
# af/config/afcfg.yaml.
#
# The AF runs the profiles of af/config/afcfg.yaml and, on port 8080, the
# digest-http test profile. The AAnF address is the aanfUri of
# af/config/afcfg.yaml, and the address of the extra AFs is the one of its
# first listen; the AAnF of the free5GC host must listen on that aanfUri
# (sbi.bindingIPv4 of ~/free5gc/config/aanfcfg.yaml).
#
# OPENSSL_DTLS13=<openssl binary with DTLS 1.3, such as OpenSSL 4.1> runs
# check D03, PSK DTLS 1.3 with a UE independent of wolfSSL; without it, D03 is
# reported as skipped.
#
# LIBCOAP_CLIENT=<coap-client of libcoap with OSCORE> runs checks O04 and O05,
# the OSCORE profile with a UE independent of the code of the AF
# (af/scripts/oscore-check.py); without it, they are reported as skipped.
#
# Output: af/build/e2e/<time>/ with report.md, the results and the logs of
# both machines. Exit code 0 when every check passes.
set -uo pipefail

keep=""
host="${FREE5GC_HOST:-}"
for a in "$@"; do
    case "$a" in
    --keep) keep=--keep ;;
    *) host="$a" ;;
    esac
done
[ -n "$host" ] || { echo "usage: $0 [--keep] user@host (or set FREE5GC_HOST)" >&2; exit 2; }

here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$here/.." && pwd)"
ts="$(date +%Y%m%d-%H%M%S)"
L="$here/build/e2e/$ts"
R="akma-e2e/$ts" # relative to the home directory on the free5GC host
afcfg="$here/config/afcfg.yaml"
afcfg_ext="$here/config/afcfg-external.yaml"
aanf="$(sed -n 's#^ *aanfUri: *https\{0,1\}://\([^/[:space:]]*\).*#\1#p' "$afcfg" | head -1)"
nef="$(sed -n 's#^ *nefUri: *https\{0,1\}://\([^/[:space:]]*\).*#\1#p' "$afcfg_ext" | head -1)"
af_ip="$(sed -n 's/^ *listen: *\([0-9.]*\):[0-9]*.*/\1/p' "$afcfg" | head -1)"
nrf="http://127.0.0.10:8000"
seed_local="$repo/free5gc/build/bin/seed"
uaclient="$here/build/bin/uaclient"
vectors="$repo/shared/akma/testdata/vectors.json"
ca="$here/build/cert/ca.pem"
fqdn="af1.akma.example"
af_id="$fqdn.FF00000001"
mkdir -p "$L"
results="$L/local-results.txt"
: >"$results"

ssh_b() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$host" "$@"; }
pass() { echo "PASS $1 $2" >>"$results"; }
fail() { echo "FAIL $1 $2" >>"$results"; }
skip() { echo "SKIP $1 $2" >>"$results"; }
expect() { # id description output pattern
    if grep -q -- "$4" <<<"$3"; then pass "$1" "$2"; else fail "$1" "$2 (got: $(head -c 200 <<<"$3" | tr '\n' ' '))"; fi
}
vec() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1])); x=[x for x in v["vectors"] if x["name"]==sys.argv[2]][0]; print(x[sys.argv[3]] if sys.argv[3]!="a_kid" else x["a_kid"]["base64"])' "$vectors" "$1" "$2"; }
state() { ssh_b "sed -n 's/^$1=//p' $R/state" | tail -1; }
# retrieve <A-KID> [AF_ID]: "200 <expiry>" or the error of the AAnF; K_AF is not printed
retrieve() {
    local out
    out="$("$seed_local" retrieve --aanf "http://$aanf" --af-id "${2:-$af_id}" --akid "$1" 2>&1)"
    if grep -q '^expiry:' <<<"$out"; then echo "200 $(sed -n 's/^expiry: //p' <<<"$out")"; else sed -n 's/^seed: AAnF answered //p' <<<"$out"; fi
}
# kaf_of <vector> <Ua* id>: the K_AF of the K_AKMA of a vector for the AF_ID
# af1.akma.example.<Ua* id> (TS 33.535 A.4), from the Python KDF
kaf_of() {
    python3 -I -c 'import hashlib, hmac, json, sys
v = [x for x in json.load(open(sys.argv[1]))["vectors"] if x["name"] == sys.argv[2]][0]
p0 = sys.argv[3].encode() + bytes.fromhex(sys.argv[4])
print(hmac.new(bytes.fromhex(v["k_akma"]), b"\x82" + p0 + len(p0).to_bytes(2, "big"), hashlib.sha256).hexdigest())' \
        "$vectors" "$1" "$fqdn" "$2"
}
# af_config <base> [digest-http listen]: the base configuration with absolute
# certificate paths and, when given, the digest-http test profile
af_config() {
    awk -v dir="$here/config" -v dh="${2:-}" '
        /^ *(certificate|key): / && $2 !~ /^\// { sub(/: /, ": " dir "/") }
        { print }
        /^  profiles:/ && dh != "" { print "    - type: digest-http"; print "      listen: " dh }' "$1"
}
# digest_http_only <base> <listen>: the base configuration with one
# digest-http server at <listen> in place of its profiles
digest_http_only() {
    awk -v listen="$2" '
        /^  profiles:/ { skip = 1; print "  listen: " listen; next }
        skip && /^(  [^ #-]|[^ #])/ { skip = 0 }
        skip { next }
        /^  listen:/ { print "  listen: " listen; next }
        { print }' "$1"
}
af_instance() { # name listen clockOffset -> pid of an extra AF
    digest_http_only "$afcfg" "$2" | awk -v off="$3" '
        { print }
        /^  aanfUri:/ && off != "" { print "  clockOffset: " off }' >"$L/afcfg-$1.yaml"
    "$here/build/bin/af" -c "$L/afcfg-$1.yaml" >"$L/af-$1.log" 2>&1 &
    echo $!
}

# af_variant <name> <base configuration> <listen> [line for the configuration]
# -> pid of an extra AF; the line replaces an "anonymous:" line of the base.
af_variant() {
    digest_http_only "$2" "$3" | awk -v extra="${4:-}" '
        /^  anonymous:/ { next }
        { print }
        /^  listen:/ && extra != "" { print "  " extra }' >"$L/afcfg-$1.yaml"
    "$here/build/bin/af" -c "$L/afcfg-$1.yaml" >"$L/af-$1.log" 2>&1 &
    echo $!
}

# psk_variant <name> <listen> ["key: value"]... -> pid of an extra AF with one
# server of the profile $PSK_TYPE, psk-tls13 when unset; each line replaces
# the key of the base or is added. The base is $PSK_BASE, af/config/afcfg.yaml
# when unset.
psk_variant() {
    local name="$1" listen="$2"
    shift 2
    digest_http_only "${PSK_BASE:-$afcfg}" "$listen" | awk -v listen="$listen" -v type="${PSK_TYPE:-psk-tls13}" \
        -v extra="$(printf '%s\n' "$@")" '
        BEGIN { n = split(extra, kv, "\n"); for (i = 1; i <= n; i++) if (kv[i] != "") { k = kv[i]; sub(/:.*/, "", k); over[k] = kv[i] } }
        /^  listen:/ { print "  profiles:"; print "    - type: " type; print "      listen: " listen; next }
        /^  [a-zA-Z]+:/ { k = $1; sub(/:$/, "", k); if (k in over) { print "  " over[k]; done[k] = 1; next } }
        { print }
        /^  aanfUri:/ { for (k in over) if (!(k in done)) { print "  " over[k]; done[k] = 1 } }' >"$L/afcfg-$name.yaml"
    "$here/build/bin/af" -c "$L/afcfg-$name.yaml" >"$L/af-$name.log" 2>&1 &
    echo $!
}
# psk_get <A-KID> <K_AF> <host:port>: GET of the session resource over TLS 1.3
# with an external PSK, by OpenSSL, independent of wolfSSL
psk_get() {
    printf 'GET /ua/v1/session HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n' "$fqdn" "${3##*:}" |
        timeout 15 openssl s_client -quiet -tls1_3 -connect "$3" -servername "$fqdn" \
            -psk_identity "3GPP-AKMA;$1" -psk "$2" 2>&1
}
# wait_log <file> <fixed string> [seconds]
wait_log() {
    local i
    for ((i = 0; i < ${3:-30}; i++)); do
        grep -aqF -- "$2" "$1" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}
extra_pids=()
tunnel=""
# stop_extra stops the AFs of the NEF group (they deregister from the NRF)
# and the tunnel to the NRF.
stop_extra() {
    [ "${#extra_pids[@]}" -gt 0 ] && kill -INT "${extra_pids[@]}" 2>/dev/null && sleep 2
    extra_pids=()
    [ -n "$tunnel" ] && kill "$tunnel" 2>/dev/null
    tunnel=""
}

# ---------------------------------------------------------------- local checks
group_A() { # system up, A_KID_1 registered
    local akid1 out k_ausf supi012 akid012 akid12 pid supi3 k_ausf3
    akid1="$(state A_KID_1)"
    echo "== A: AAnF API from the AF machine; A-KID $akid1"
    python3 -I "$here/scripts/negative/aanf_api.py" "$aanf" "$akid1" >>"$results" 2>&1

    # AkmaKeyInfo the AAnF must refuse (AUSF role, with an access token)
    k_ausf="$(vec rid-012 k_ausf)"
    out="$(ssh_b "~/akma-tools/seed register --nrf $nrf --aanf http://$aanf --supi imsi-208930000000099 --k-ausf $k_ausf --rid 0000 --mcc 208 --mnc 93 --gpsi msisdn-5511999990000" 2>&1)"
    expect N17 "AkmaKeyInfo with supi and gpsi: 400 OPTIONAL_IE_INCORRECT (TS 29.535 table 5.1.6.2.2-1)" "$out" "400 (OPTIONAL_IE_INCORRECT"
    out="$(ssh_b "~/akma-tools/seed register --nrf $nrf --aanf http://$aanf --supi imsi-208930000000099 --k-ausf $k_ausf --rid 0000 --mcc 208 --mnc 93 --k-akma 0123" 2>&1)"
    expect N18 "kAkma outside the pattern: 400 MANDATORY_IE_INCORRECT" "$out" "400 (MANDATORY_IE_INCORRECT"

    # RID "012" and "12" are different A-KIDs (TS 23.003 cl. 2.2B)
    supi012="$(vec rid-012 supi)"
    akid012="$(vec rid-012 a_kid)"
    out="$(ssh_b "~/akma-tools/seed register --nrf $nrf --aanf http://$aanf --supi $supi012 --k-ausf $k_ausf --rid 012 --mcc 345 --mnc 12" 2>&1)"
    expect N19 "context with RID 012 registered with the A-KID of the oracle" "$out" "a-kid: $akid012"
    expect N20 "retrieve with RID 012: 200" "$(retrieve "$akid012")" "^200 "
    akid12="${akid012/rid012./rid12.}"
    expect N21 "retrieve with RID 12, same A-TID: 403 K_AKMA_NOT_PRESENT" "$(retrieve "$akid12")" "^403 (K_AKMA_NOT_PRESENT)"

    # AF with a deliberately shifted clock (TS 33.535 cl. 4.4.0).
    # Context of the vector mnc-3-digits, whose K_AF is the one of
    # af1.akma.example and whose SUPI is not the one of the UE.
    supi3="$(vec mnc-3-digits supi)"
    k_ausf3="$(vec mnc-3-digits k_ausf)"
    out="$(ssh_b "~/akma-tools/seed register --nrf $nrf --aanf http://$aanf --supi $supi3 --k-ausf $k_ausf3 --rid 7 --mcc 310 --mnc 410" 2>&1)"
    expect N22a "context of the vector mnc-3-digits registered" "$out" "a-kid: $(vec mnc-3-digits a_kid)"
    pid="$(af_instance plus2h "$af_ip:8081" 2h)"
    sleep 1
    out="$("$uaclient" -vector mnc-3-digits -vectors "$vectors" -connect "$af_ip:8081" 2>&1)"
    expect N22 "AF clock 2 h ahead: a valid K_AF looks expired and is refused (503 AANF_UNAVAILABLE)" "$out" "503 AANF_UNAVAILABLE"
    kill "$pid" 2>/dev/null
    pid="$(af_instance minus2h "$af_ip:8082" -2h)"
    sleep 1
    out="$("$uaclient" -vector mnc-3-digits -vectors "$vectors" -connect "$af_ip:8082" 2>&1)"
    expect N23 "AF clock 2 h behind: K_AF accepted, and it would stay in use 2 h past its expiry" "$out" "session established"
    kill "$pid" 2>/dev/null

    # Ua* failures at the AF
    out="$("$uaclient" -akid "$akid1" -kaf "$(printf '%063d1' 0)" 2>&1)"
    expect N24 "Ua* with a wrong K_AF: 401" "$out" "AF answered 401"
    out="$("$uaclient" -vector mnc-3-digits -vectors "$vectors" -fqdn af2.akma.example 2>&1)"
    expect N25 "Ua* with the Host of another AF: 421" "$out" "421 MISDIRECTED_REQUEST"

    group_T "$akid1" "$akid12"
    group_D "$akid1" "$akid12"
    group_O "$akid1" "$akid12"

    out="$(ssh_b "~/akma-tools/seed remove --nrf $nrf --aanf http://$aanf --supi $supi012; ~/akma-tools/seed remove --nrf $nrf --aanf http://$aanf --supi $supi3" 2>&1)"
    expect N26 "test contexts removed" "$(grep -c '^removed' <<<"$out")" "^2$"

    group_nef "$akid1"
}

# The TLS profiles (TS 24.109 Annex K): what the AF saw of the sessions of
# the UE in R2t, and the negative cases, with the context of the vector
# mnc-3-digits (registered in group A).
group_T() {
    local akid1="$1" unknown="$2" akid3 kaf7 out pid n
    akid3="$(vec mnc-3-digits a_kid)"
    kaf7="$(kaf_of mnc-3-digits 0100000007)"
    echo "== T: TLS profiles"
    expect T01 "K.2 in TLS 1.3 from the UE: Digest with the AF_ID of the cipher suite (TS 33.220 H.3)" \
        "$(grep -aF "UE with A-KID $akid1 authenticated (AF_ID $fqdn.01000113" "$L/af.log")" "nc 00000002"
    expect T02 "K.2 in TLS 1.2 from the UE: AF_ID $fqdn.010001C02B" \
        "$(grep -aF "UE with A-KID $akid1 authenticated (AF_ID $fqdn.010001C02B" "$L/af.log")" "nc 00000001"
    expect T03 "PSK TLS 1.3 from the UE: AF_ID $fqdn.0100000007, the second connection resumed (TS 33.222 cl. 5.4.1.4)" \
        "$(grep -aF "TLS 1.3 PSK handshake with" "$L/af.log" | grep -aF "A-KID $akid1, AF_ID $fqdn.0100000007")" \
        "cipher suite 1301, resumed true"
    expect T04 "PSK TLS 1.2 from the UE: TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256, AF_ID $fqdn.010001D001, resumed" \
        "$(grep -aF "TLS 1.2 PSK handshake with" "$L/af.log" | grep -aF "A-KID $akid1, AF_ID $fqdn.010001D001")" \
        "cipher suite D001, resumed true"
    out="$(psk_get "$akid3" "$kaf7" "$af_ip:8444")"
    expect T05 "PSK TLS 1.3 with OpenSSL as the UE: 200 with the A-KID" "$out" "\"aKid\":\"$akid3\""
    out="$("$uaclient" -profile psk-tls12 -connect "$af_ip" -vector mnc-3-digits -vectors "$vectors" 2>&1)"
    expect T06 "PSK TLS 1.2 with the K_AF of another AF_ID: handshake fails" "$out" "wolftls: handshake"
    out="$("$uaclient" -profile psk-tls13 -connect "$af_ip" -akid "$unknown" -kaf "$kaf7" 2>&1)"
    expect T07 "PSK TLS 1.3 with an A-KID unknown to the AAnF: handshake refused" "$out" "wolftls: handshake"
    expect T07b "the AF logs K_AKMA_NOT_PRESENT of the AAnF" \
        "$(grep -aF "No K_AKMA at the AAnF for A-KID $unknown (AF_ID $fqdn.0100000007)" "$L/af.log")" "handshake refused"
    out="$("$uaclient" -profile psk-tls13 -psk-ke-only -connect "$af_ip" -akid "$akid3" -kaf "$kaf7" 2>&1)"
    expect T08 "PSK TLS 1.3 offering psk_ke only: refused (TS 33.210 cl. 6.2.2)" "$out" "wolftls: handshake"
    out="$("$uaclient" -profile digest-tls -ca "$ca" -connect "$af_ip" -fqdn af2.akma.example -vector mnc-3-digits -vectors "$vectors" 2>&1)"
    expect T09 "K.2 with the certificate of another FQDN: the UE ends the TLS (TS 33.222 cl. 5.3.1.3)" "$out" "not af2.akma.example"

    pid="$(psk_variant af3 "$af_ip:8446" "fqdn: af3.akma.example")"
    sleep 1
    out="$("$uaclient" -profile psk-tls13 -connect "$af_ip:8446" -fqdn af3.akma.example -akid "$akid3" -kaf "$kaf7" 2>&1)"
    expect T10 "AF_ID of a profile outside the policy of the AAnF: handshake refused" "$out" "wolftls: handshake"
    expect T10b "the AAnF refused the AF_ID" "$(grep -aF "not obtained" "$L/af-af3.log")" "AAnF answered 403"
    kill "$pid" 2>/dev/null

    # K_AF of 1 h seen 10 s before its expiry by an AF clock 3590 s ahead
    # (TS 33.535 cl. 6.4.2): the AF closes the TLS session at the expiry.
    # The AAnF keeps a K_AF until its own expiry and gives the same one back,
    # also when the same K_AUSF registers the context again. Removing the
    # context (TS 33.535 cl. 6.6) and registering it again (the seed tool, as
    # an AUSF) gives the AAnF a fresh K_AF, as a new primary authentication
    # would with a new A-KID.
    fresh_context() {
        ssh_b "~/akma-tools/seed remove --nrf $nrf --aanf http://$aanf --supi $(vec mnc-3-digits supi); ~/akma-tools/seed register --nrf $nrf --aanf http://$aanf --supi $(vec mnc-3-digits supi) --k-ausf $(vec mnc-3-digits k_ausf) --rid 7 --mcc 310 --mnc 410" >/dev/null 2>&1
    }
    pid="$(psk_variant refetch "$af_ip:8447" "clockOffset: 3590s" "kafExpiry: refetch")"
    fresh_context
    sleep 1
    psk_get "$akid3" "$kaf7" "$af_ip:8447" >"$L/t11-1.out"
    timeout 20 openssl s_client -quiet -tls1_3 -connect "$af_ip:8447" -servername "$fqdn" \
        -psk_identity "3GPP-AKMA;$akid3" -psk "$kaf7" </dev/null >"$L/t11-held.out" 2>&1
    expect T11 "K_AF expired: the AF closes the TLS session (close_notify)" \
        "$(wait_log "$L/af-refetch.log" "expired: TLS 1.3 session with" 5 && echo closed)" "closed"
    fresh_context
    out="$(psk_get "$akid3" "$kaf7" "$af_ip:8447")"
    expect T12 "after the expiry, policy refetch: the AF asks the AAnF again and a new handshake succeeds" \
        "$(grep -aF "requesting it again from the AAnF (policy refetch)" "$L/af-refetch.log")$out" "\"aKid\":\"$akid3\""
    expect T12b "after the expiry, policy refetch: a second K_AF from the AAnF" \
        "$(grep -acF "K_AF for A-KID $akid3 and AF_ID $fqdn.0100000007 obtained" "$L/af-refetch.log")" "^2$"
    kill "$pid" 2>/dev/null
    pid="$(psk_variant reject "$af_ip:8448" "clockOffset: 3590s" "kafExpiry: reject")"
    fresh_context
    sleep 1
    psk_get "$akid3" "$kaf7" "$af_ip:8448" >"$L/t13-1.out"
    sleep 11
    out="$(psk_get "$akid3" "$kaf7" "$af_ip:8448")"
    expect T13 "after the expiry, policy reject: the first handshake had a session, the second none" \
        "$(grep -c '"aKid"' "$L/t13-1.out")$(grep -c '"aKid"' <<<"$out")" "^10$"
    expect T13b "after the expiry, policy reject: the AF refuses the expired K_AF" \
        "$(grep -aF "K_AF for A-KID $akid3 expired" "$L/af-reject.log")" "access rejected (policy reject)"
    kill "$pid" 2>/dev/null
}

# The AF outside the operator network, through the NEF (TS 33.535 cl. 6.3),
# and anonymous access (cl. 6.2.2). The extra AFs stay up for the Ua* of the
# UE (R2n) and are stopped in group B. The NRF listens on a loopback address
# of the free5GC host: the AFs reach it through an SSH tunnel.
group_nef() {
    local akid1="$1" out
    echo "== A (NEF): AF outside the operator network and anonymous access"
    ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -L "${nrf#http://}:${nrf#http://}" "$host" &
    tunnel=$!
    sleep 2
    extra_pids+=("$(af_variant nef "$afcfg_ext" "$af_ip:8083")")
    extra_pids+=("$(af_variant nef-anon "$afcfg_ext" "$af_ip:8084" "anonymous: true")")
    extra_pids+=("$(af_variant anon "$afcfg" "$af_ip:8085" "anonymous: true")")
    extra_pids+=("$(PSK_BASE="$afcfg_ext" psk_variant nef-psk "$af_ip:8456")")
    sleep 3
    expect E00 "AFs outside the operator network registered at the NRF through the tunnel" \
        "$(cat "$L/af-nef.log" "$L/af-nef-anon.log" | grep -c 'registered at the NRF')" "^2$"
    python3 -I "$here/scripts/negative/nef_api.py" "${nrf#http://}" "$nef" "$aanf" "$af_ip" "$akid1" >>"$results" 2>&1
}

# The DTLS profiles (TS 33.535 Annex C): what the AF saw of the associations
# of the UE in R2d, a UE independent of wolfSSL, and the refusals.
group_D() {
    local akid1="$1" unknown="$2" akid3 kaf9 out
    akid3="$(vec mnc-3-digits a_kid)"
    kaf9="$(kaf_of mnc-3-digits 0100000009)"
    echo "== D: DTLS profiles"
    expect D01 "DTLS 1.3 from the UE: AF_ID $fqdn.0100000009, the second association resumed" \
        "$(grep -aF "DTLS 1.3 PSK handshake with" "$L/af.log" | grep -aF "A-KID $akid1, AF_ID $fqdn.0100000009")" \
        "cipher suite 1301, resumed true"
    expect D02 "DTLS 1.2 from the UE: TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256, AF_ID $fqdn.010001D001, resumed" \
        "$(grep -aF "DTLS 1.2 PSK handshake with" "$L/af.log" | grep -aF "A-KID $akid1, AF_ID $fqdn.010001D001")" \
        "cipher suite D001, resumed true"
    if [ -n "${OPENSSL_DTLS13:-}" ]; then
        # CoAP GET coaps://af1.akma.example/ua/v1/session (RFC 7252 cl. 3),
        # built by hand: CON, token "abcd", Uri-Host, Uri-Path.
        out="$(printf '\x44\x01\x12\x34abcd\x3d\x03af1.akma.example\x82ua\x02v1\x07session' |
            timeout 10 "$OPENSSL_DTLS13" s_client -quiet -dtls1_3 -connect "$af_ip:5684" -servername "$fqdn" \
                -psk_identity "3GPP-AKMA;$akid3" -psk "$kaf9" 2>&1 | tr -c '[:print:]' ' ')"
        expect D03 "PSK DTLS 1.3 with OpenSSL as the UE ($("$OPENSSL_DTLS13" version | cut -d' ' -f1,2)): CoAP 2.05 with the A-KID" \
            "$out" "\"aKid\":\"$akid3\""
    else
        skip D03 "PSK DTLS 1.3 with OpenSSL as the UE: no OPENSSL_DTLS13"
    fi
    out="$("$uaclient" -profile psk-dtls13 -connect "$af_ip" -akid "$unknown" -kaf "$kaf9" 2>&1)"
    expect D04 "DTLS 1.3 with an A-KID unknown to the AAnF: handshake refused" "$out" "wolftls: handshake"
    expect D04b "the AF logs K_AKMA_NOT_PRESENT of the AAnF" \
        "$(grep -aF "No K_AKMA at the AAnF for A-KID $unknown (AF_ID $fqdn.0100000009)" "$L/af.log")" "handshake refused"
    out="$("$uaclient" -profile psk-dtls13 -connect "$af_ip" -vector mnc-3-digits -vectors "$vectors" 2>&1)"
    expect D05 "DTLS 1.3 with the K_AF of another AF_ID: handshake fails" "$out" "wolftls: handshake"
}

# The OSCORE profile (TS 33.535 Annex D): what the AF saw of the requests of
# the UE in R2o, the independent check with libcoap, the negative cases, and
# the expiry of K_AF with the clock-shifted AFs of group T.
group_O() {
    local akid1="$1" unknown="$2" akid3 kaf8 out pid
    akid3="$(vec mnc-3-digits a_kid)"
    kaf8="$(kaf_of mnc-3-digits 0100000008)"
    echo "== O: OSCORE profile"
    expect O01 "OSCORE from the UE: four POST /akma, AF_ID $fqdn.0100000008, one K_AF from the AAnF" \
        "$(grep -acF "OSCORE context for A-KID $akid1, AF_ID $fqdn.0100000008" "$L/af.log")$(grep -acF "K_AF for A-KID $akid1 and AF_ID $fqdn.0100000008 obtained" "$L/af.log")" "^41$"
    expect O02 "six requests of the UE protected by OSCORE served (D.3.2 steps 5 and 6)" \
        "$(grep -acF "UE with A-KID $akid1 served over OSCORE (AF_ID $fqdn.0100000008)" "$L/af.log")" "^6$"
    expect O03 "the context renewed twice by RFC 8613 Appendix B.2 (D.3.4)" \
        "$(grep -aF "OSCORE context of A-KID $akid1, AF_ID $fqdn.0100000008 with UE-SID" "$L/af.log" |
            grep -acF "renewed (RFC 8613 Appendix B.2), ID Context")" "^2$"
    if [ -n "${LIBCOAP_CLIENT:-}" ]; then
        out="$(python3 -I "$here/scripts/oscore-check.py" --coap-client "$LIBCOAP_CLIENT" --af "$af_ip:5683" \
            --fqdn "$fqdn" --akid "$akid3" --kaf "$kaf8" --dir "$L/oscore-check" 2>&1)"
        expect O04 "OSCORE with coap-client of libcoap as the UE, context from oscore-check.py: 2.05 with the A-KID" \
            "$out" "\"aKid\":\"$akid3\""
        out="$(python3 -I "$here/scripts/oscore-check.py" --coap-client "$LIBCOAP_CLIENT" --af "$af_ip:5683" \
            --fqdn "$fqdn" --akid "$akid3" --kaf "$kaf8" --dir "$L/oscore-check" --osc-inp-alg 11 2>&1)"
        expect O05 "OSC-INP with another AEAD algorithm: 4.00 OSC_INP_NOT_SUPPORTED" "$out" "4.00.*OSC_INP_NOT_SUPPORTED"
    else
        skip O04 "OSCORE with coap-client of libcoap as the UE: no LIBCOAP_CLIENT"
        skip O05 "OSC-INP with another AEAD algorithm: no LIBCOAP_CLIENT"
    fi
    out="$("$uaclient" -profile oscore -connect "$af_ip" -akid "$unknown" -kaf "$kaf8" 2>&1)"
    expect O06 "OSCORE with an A-KID unknown to the AAnF: 4.03 AKMA_KEY_NOT_AVAILABLE" "$out" "4.03 AKMA_KEY_NOT_AVAILABLE"
    expect O06b "the AF logs K_AKMA_NOT_PRESENT of the AAnF" \
        "$(grep -aF "No K_AKMA at the AAnF for A-KID $unknown (AF_ID $fqdn.0100000008)" "$L/af.log")" "OSCORE context refused"
    out="$("$uaclient" -profile oscore -connect "$af_ip" -vector mnc-3-digits -vectors "$vectors" 2>&1)"
    expect O07 "OSCORE with the K_AF of another AF_ID: 4.00 Decryption failed (RFC 8613 cl. 8.2)" "$out" \
        '4.00 response "Decryption failed"'

    # K_AF of 1 h seen 10 s before its expiry by an AF clock 3590 s ahead
    # (TS 33.535 cl. 6.4.2), as in group T.
    pid="$(PSK_TYPE=oscore psk_variant oscore-refetch "$af_ip:5687" "clockOffset: 3590s" "kafExpiry: refetch")"
    fresh_context
    sleep 1
    "$uaclient" -profile oscore -connect "$af_ip:5687" -akid "$akid3" -kaf "$kaf8" >"$L/o-refetch-1.out" 2>&1
    expect O08 "K_AF expired: the AF removes the OSCORE context" \
        "$(grep -c "AF authenticated by the OSCORE context" "$L/o-refetch-1.out")$(wait_log "$L/af-oscore-refetch.log" "expired: OSCORE context with UE-SID" 25 && echo removed)" "^1removed$"
    fresh_context
    out="$("$uaclient" -profile oscore -connect "$af_ip:5687" -akid "$akid3" -kaf "$kaf8" 2>&1)"
    expect O09 "after the expiry, policy refetch: a new POST /akma, with a second K_AF from the AAnF" \
        "$(grep -c "AF authenticated by the OSCORE context" <<<"$out")$(grep -acF "K_AF for A-KID $akid3 and AF_ID $fqdn.0100000008 obtained" "$L/af-oscore-refetch.log")" "^12$"
    kill "$pid" 2>/dev/null
    pid="$(PSK_TYPE=oscore psk_variant oscore-reject "$af_ip:5688" "clockOffset: 3590s" "kafExpiry: reject")"
    fresh_context
    sleep 1
    "$uaclient" -profile oscore -connect "$af_ip:5688" -akid "$akid3" -kaf "$kaf8" >"$L/o-reject-1.out" 2>&1
    sleep 11
    out="$("$uaclient" -profile oscore -connect "$af_ip:5688" -akid "$akid3" -kaf "$kaf8" 2>&1)"
    expect O10 "after the expiry, policy reject: the first POST had a context, the second 4.03 KAF_EXPIRED" \
        "$(grep -c "AF authenticated by the OSCORE context" "$L/o-reject-1.out")$(tr '\n' ' ' <<<"$out")" \
        "^1.*4.03 KAF_EXPIRED"
    kill "$pid" 2>/dev/null
}

group_B() { # after the new authentication
    local akid1 akid2
    akid1="$(state A_KID_1)"
    akid2="$(state A_KID_2)"
    stop_extra
    expect E12 "AFs outside the operator network deregistered from the NRF" \
        "$(cat "$L/af-nef.log" "$L/af-nef-anon.log" | grep -c 'Deregistered from the NRF')" "^2$"
    echo "== B: A-KID after a new authentication"
    expect B1 "previous A-KID refused by the AAnF: 403 K_AKMA_NOT_PRESENT (TS 33.535 cl. 6.1 NOTE 1a)" "$(retrieve "$akid1")" "^403 (K_AKMA_NOT_PRESENT)"
    expect B2 "new A-KID: 200" "$(retrieve "$akid2")" "^200 "
}

group_C() { # after remove-context
    local akid5
    akid5="$(state A_KID_5)"
    echo "== C: retrieve after remove-context"
    expect C1 "retrieve after remove-context: 403 K_AKMA_NOT_PRESENT (TS 33.535 cl. 6.6)" "$(retrieve "$akid5")" "^403 (K_AKMA_NOT_PRESENT)"
}

worker() {
    local s i
    trap stop_extra EXIT
    for s in A B C; do
        for ((i = 0; i < 2400; i++)); do
            ssh_b "test -f $R/sync-$s.ready" && break
            ssh_b "test -f $R/.finished" && return
            sleep 3
        done
        "group_$s"
        ssh_b "touch $R/sync-$s.done"
    done
}

# ---------------------------------------------------------------- preflight
echo "== preflight"
for f in "$here/build/bin/af" "$uaclient" "$seed_local"; do
    [ -x "$f" ] || { echo "$f missing: run af/scripts/build-af.sh and free5gc/scripts/build-aanf.sh" >&2; exit 1; }
done
[ -f "$ca" ] || { echo "$ca missing: run af/scripts/make-test-ca.sh" >&2; exit 1; }
ssh_b true || { echo "cannot reach $host by SSH" >&2; exit 1; }
for f in akma-free5gc/af/scripts/e2e-remote.sh akma-free5gc/af/scripts/ue-netns.sh akma-free5gc/af/build/bin/uaclient \
    akma-tools/seed UERANSIM/build/nr-akma-selftest; do
    ssh_b "test -e $f" || { echo "$host:$f missing (see the prerequisites in $0)" >&2; exit 1; }
done
[ -n "$aanf" ] && [ -n "$af_ip" ] || { echo "aanfUri or listen missing in $afcfg" >&2; exit 1; }
bind="$(ssh_b "sed -n 's/^ *bindingIPv4: *\([0-9.]*\).*/\1/p' ~/free5gc/config/aanfcfg.yaml" | head -1)"
[ "${aanf%:*}" = "$bind" ] ||
    { echo "aanfUri of $afcfg ($aanf) is not the AAnF of $host (bindingIPv4 ${bind:-missing})" >&2; exit 1; }
{
    echo "commit $(git -C "$repo" describe --always --dirty 2>/dev/null)"
    for nf in nrf udm ausf amf config run; do ssh_b "~/akma-free5gc/free5gc/scripts/patch-nf.sh $nf status | head -1"; done
    ssh_b "~/akma-free5gc/af/scripts/patch-ueransim.sh status | head -1"
} | tee "$L/preflight.txt"
out="$(ssh_b "~/UERANSIM/build/nr-akma-selftest ~/akma-free5gc/shared/akma/testdata/vectors.json" 2>&1)"
echo "$out" >"$L/selftest.txt"
expect S1 "self-test of the ME against the shared vectors (TS 33.535 A.2-A.4)" "$out" "5 passed, 3 refused.*, 0 failed"

# ---------------------------------------------------------------- run
af_config "$afcfg" "$af_ip:8080" >"$L/afcfg.yaml"
"$here/build/bin/af" -c "$L/afcfg.yaml" -l "$L/af.log" >"$L/af.out" 2>&1 &
afpid=$!
sleep 1
kill -0 "$afpid" 2>/dev/null || { echo "the AF did not start; see $L/af.out" >&2; exit 1; }
grep -q "Built with wolfSSL" "$L/af.out" || { echo "the AF has no PSK profiles: run af/scripts/build-af.sh with wolfSSL" >&2; exit 1; }
ssh_b "mkdir -p $R" && scp -q -o BatchMode=yes "$ca" "$host:$R/ca.pem"

worker >"$L/worker.out" 2>&1 &
workerpid=$!

echo "== free5GC host: type the sudo password of $host when asked"
ssh -t "$host" "AF_IP=$af_ip CA=\$HOME/$R/ca.pem bash ~/akma-free5gc/af/scripts/e2e-remote.sh \$HOME/$R $keep" | tee "$L/remote.out"
ssh_b "touch $R/.finished"
wait "$workerpid"
kill "$afpid" 2>/dev/null
wait "$afpid" 2>/dev/null

mkdir -p "$L/remote"
scp -q -o BatchMode=yes "$host:$R/*" "$L/remote/" 2>/dev/null
if grep -aEq '[0-9a-fA-F]{64}' "$L/af.log" "$L"/af-*.log 2>/dev/null; then
    fail L1 "no 64-hexadecimal string in the AF logs"
else
    pass L1 "no 64-hexadecimal string in the AF logs"
fi

# ---------------------------------------------------------------- report
all="$(cat "$L/remote/remote-results.txt" "$results" 2>/dev/null)"
npass="$(grep -c '^PASS' <<<"$all")"
nfail="$(grep -c '^FAIL' <<<"$all")"
nskip="$(grep -c '^SKIP' <<<"$all")"
{
    echo "# AKMA end to end — $ts"
    echo
    echo "free5GC host \`$host\`; AF machine \`$(hostname)\`; $(head -1 "$L/preflight.txt")."
    echo
    echo "**$npass passed, $nfail failed, $nskip skipped.**"
    echo
    echo "## A-KIDs"
    echo
    echo '```'
    grep '^A_KID' "$L/remote/state" 2>/dev/null
    echo '```'
    echo
    echo "## Free5GC host (R) and AF machine (S, N, T, D, O, B, C, L)"
    echo
    echo "| | Check | Result |"
    echo "|---|---|---|"
    sed -E 's/^(PASS|FAIL|SKIP) ([^ ]+) (.*)$/| \2 | \3 | \1 |/' <<<"$all"
    echo
    echo "## Evidence"
    echo
    echo "AKMA entries of the free5GC log (\`remote/free5gc.log\`):"
    echo
    echo '```'
    grep -a 'CAT="AKMA"' "$L/remote/free5gc.log" 2>/dev/null |
        sed -E 's/^time="[0-9-]+T([0-9:.]+)[^"]*" level="([a-z]+)" msg="(.*)" CAT="AKMA" NF="([A-Z]+)"$/\1 [\2][\4] \3/'
    echo '```'
    echo
    echo "AKMA entries of the UE (\`remote/ue.log\`):"
    echo
    echo '```'
    grep -a 'AKMA' "$L/remote/ue.log" 2>/dev/null
    echo '```'
    echo
    echo "Ua* entries of the AF (\`af.log\`):"
    echo
    echo '```'
    grep -a 'CAT="UA"\|CAT="Consumer"' "$L/af.log" 2>/dev/null |
        sed -E 's/^time="[0-9-]+T([0-9:.]+)[^"]*" level="([a-z]+)" msg="(.*)" CAT="([A-Za-z]+)" NF="AF"$/\1 [\2][AF][\4] \3/'
    echo '```'
} >"$L/report.md"

echo
echo "report: $L/report.md"
echo "$npass passed, $nfail failed, $nskip skipped"
[ "$nfail" -eq 0 ]
