#!/usr/bin/env bash
# End-to-end run on the free5GC host, driven by af/scripts/e2e.sh on
# the AF machine through "ssh -t". Asks for the sudo password once.
#
# Usage: e2e-remote.sh <run directory> [--keep]
#   --keep  leave free5GC, the gNB and the UE running at the end
#
# Steps:
#   R1  free5GC (run.sh -aanf), gNB, UE in its namespace, subscriber provisioned
#   R2  registration; A-KID of the UE = AUSF = AAnF; Ua* from the UE
#   R2k AKMA key service of the ME: K_AF only to the application of the AF_ID
#   R2t Ua* from the UE over the TLS profiles: K.2 in TLS 1.3 and 1.2, PSK
#       TLS 1.3 and 1.2, each resumed on a second connection
#   R2d Ua* from the UE over the DTLS profiles, CoAP inside: DTLS 1.3 and
#       1.2, each resumed on a second association
#   R2o Ua* from the UE over OSCORE: POST /akma, requests protected with the
#       context, renewal (RFC 8613 Appendix B.2), a new POST per request
#       -> sync A (checks from the AF machine)
#   R3  new authentication: new A-KID; Ua* with it; Ua* with the previous
#       A-KID and K_AF, still valid at the AF until expiry
#       -> sync B
#   R4  AAnF down during a primary authentication: the authentication
#       succeeds and the registration in the AAnF fails (TS 33.535 cl. 6.1)
#   R5  subscriber without AKMA subscription, then restored
#   R6  remove-context
#   R6r refresh of K_AKMA by the AAnF (TS 33.535 cl. 6.4.4): the AAnF, with
#       kakmaRefresh 20s, asks the UDM for a new primary authentication on a
#       K_AF request; the AMF re-authenticates the registered UE; new A-KID
#       -> sync C
#   R7  no key in the logs; logs copied; stop
#
# Results: PASS/FAIL lines in <run>/remote-results.txt; A-KIDs in <run>/state.
set -uo pipefail

run="${1:?usage: e2e-remote.sh <run directory> [--keep]}"
keep="${2:-}"
repo="$HOME/akma-free5gc"
f5="$HOME/free5gc"
uer="$HOME/UERANSIM"
netns="$repo/af/scripts/ue-netns.sh"
seed="$HOME/akma-tools/seed"
nrf="http://127.0.0.10:8000"
supi="imsi-208930000000001"
fqdn="af1.akma.example"
af_ip="${AF_IP:-192.168.16.129}" # the AF machine; the extra AFs of the NEF group listen there
ca="${CA:-$repo/af/build/cert/ca.pem}" # the test CA of the certificate of the AF (digest-tls)
# Where the AAnF listens: sbi.bindingIPv4 and sbi.port of its configuration
aanf="$(sed -n 's/^ *bindingIPv4: *\([0-9.]*\).*/\1/p' "$f5/config/aanfcfg.yaml" | head -1):$(
    sed -n 's/^ *port: *\([0-9]*\).*/\1/p' "$f5/config/aanfcfg.yaml" | head -1)"

mkdir -p "$run"
results="$run/remote-results.txt"
state="$run/state"
: >"$results"
: >"$state"

pass() { echo "PASS $1 $2" | tee -a "$results"; }
fail() { echo "FAIL $1 $2" | tee -a "$results"; }
check() { # id description command...
    local id="$1" desc="$2"
    shift 2
    if "$@"; then pass "$id" "$desc"; else fail "$id" "$desc"; fi
}
setstate() { echo "$1=$2" >>"$state"; }
step() { echo; echo "== $*"; }

# wait_for <file> <fixed string> [seconds]
wait_for() {
    local i
    for ((i = 0; i < ${3:-60}; i++)); do
        grep -aqF -- "$2" "$1" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}
# count <file> <fixed string>
count() { grep -acF -- "$2" "$1" 2>/dev/null || true; }
# wait_more <file> <fixed string> <previous count> [seconds]
wait_more() {
    local i
    for ((i = 0; i < ${4:-60}; i++)); do
        [ "$(count "$1" "$2")" -gt "$3" ] && return 0
        sleep 1
    done
    return 1
}
sync_point() {
    local i
    touch "$run/sync-$1.ready"
    echo "-- waiting for the checks of the AF machine ($1)"
    for ((i = 0; i < 900; i++)); do
        [ -f "$run/sync-$1.done" ] && return 0
        sleep 1
    done
    fail "sync-$1" "the AF machine did not finish its checks in 15 min"
}

ue_akid() { grep -ao 'AKMA key material derived, A-KID\[[^]]*\]' "$run/ue.log" | tail -1 | sed 's/.*A-KID\[//; s/\]$//'; }
ua() { sudo "$netns" ua "$@"; }
deregister() { sudo "$netns" cli "$supi" -e "deregister normal" >/dev/null; }

# A new primary authentication: deregistration, then the automatic initial
# registration of UERANSIM, a new A-KID and a new PDU session.
reauthenticate() {
    local derived tun
    derived="$(count "$run/ue.log" "AKMA key material derived")"
    tun="$(count "$run/ue.log" "TUN interface[uesimtun0")"
    deregister
    wait_more "$run/ue.log" "AKMA key material derived" "$derived" 60 &&
        wait_more "$run/ue.log" "TUN interface[uesimtun0" "$tun" 30
}

stop_ue() {
    local pids
    pids="$(sudo ip netns pids ueransim-ue 2>/dev/null)"
    [ -n "$pids" ] && sudo kill $pids 2>/dev/null
    sleep 1
}

start_ue() {
    local try
    for try in 1 2 3; do
        sudo "$netns" ue >>"$run/ue.log" 2>&1 </dev/null &
        if wait_for "$run/ue.log" "TUN interface[uesimtun0" 30; then return 0; fi
        # UERANSIM sometimes stays in LIMITED-SERVICE on the first start ("no SI").
        echo "-- UE without PDU session (attempt $try); restarting it"
        stop_ue
    done
    return 1
}

# ---------------------------------------------------------------- sudo once
sudo -v || exit 1
(while true; do sudo -n -v 2>/dev/null; sleep 50; done) &
keepalive=$!
trap 'kill $keepalive 2>/dev/null' EXIT
# No job control (set -m): with it, Ctrl-C and the end of the SSH session
# reach only the command running at the time, and the script would go on
# alone, up to stopping free5GC under the next run.

# ---------------------------------------------------------------- R1
step "R1 setup"
cd "$f5" || exit 1
sudo ./force_kill.sh >/dev/null 2>&1
sudo "$repo/free5gc/scripts/n6-nat.sh" apply
sudo "$netns" down >/dev/null 2>&1
sudo "$netns" up
check R1.gnb-link "gNB radio link on the veth (linkIp: 10.100.0.1)" \
    grep -Eq '^linkIp: *10\.100\.0\.1( |$)' "$uer/config/free5gc-gnb.yaml"
"$repo/free5gc/scripts/provision-akma-subscriber.sh" "$supi" 0000 >"$run/provision.out" 2>&1
check R1.subscriber "AKMA subscription of $supi provisioned (akmaAllowed, routingId 0000)" \
    grep -q "routingId: '0000'" "$run/provision.out"

# free5GC in a process group of its own, which the stop at the end signals;
# in the same terminal, for the sudo of run.sh.
set -m
./run.sh -aanf >"$run/run.out" 2>&1 </dev/null &
runpid=$!
set +m
wait_for "$run/run.out" "log path:" 20
f5log="$f5/$(sed -n 's/^log path: \.\///p' "$run/run.out" | head -1)free5gc.log"
setstate FREE5GC_LOG "$f5log"
check R1.free5gc "free5GC up with the AAnF registered at the NRF" \
    wait_for "$f5log" "msg=\"Start SBI server (listen on $aanf)\" CAT=\"SBI\" NF=\"AANF\"" 90

"$uer/build/nr-gnb" -c "$uer/config/free5gc-gnb.yaml" >"$run/gnb.log" 2>&1 </dev/null &
check R1.gnb "gNB NG Setup" wait_for "$run/gnb.log" "NG Setup procedure is successful" 30
: >"$run/ue.log"
check R1.ue "UE registered with a PDU session, in its namespace" start_ue

# ---------------------------------------------------------------- R2
step "R2 registration and Ua* from the UE"
check R2.registration "Initial Registration is successful" wait_for "$run/ue.log" "Initial Registration is successful" 5
akid1="$(ue_akid)"
setstate A_KID_1 "$akid1"
wait_for "$f5log" "AKMA context of $supi registered, A-KID $akid1" 15
check R2.akid-ausf "A-KID of the UE = A-KID derived by the AUSF" \
    grep -aqF "K_AKMA and A-KID derived for $supi: A-KID $akid1" "$f5log"
check R2.akid-aanf "A-KID of the UE = A-KID registered at the AAnF" \
    grep -aqF "AKMA context of $supi registered, A-KID $akid1" "$f5log"
ua -n 3 >"$run/ua-1.out" 2>&1
check R2.ua "Ua* from the UE, through the user plane, with the K_AF of the ME (3 requests)" \
    grep -q "session established (nc 00000003)" "$run/ua-1.out"

# ---------------------------------------------------------------- R2k
# The AKMA key service of the ME (TS 33.535 cl. 4.4.3): uaclient got its K_AF
# from it in R2.ua; another AF_ID, another user and nr-cli are refused, and a
# configuration that gives one AF_ID to two applications does not start.
step "R2k AKMA key service of the ME"
check R2k.given "the ME gave uaclient the K_AF of its AF_ID" \
    grep -aqF "K_AF for AF_ID[af1.akma.example.FF00000001] given to application [uaclient]" "$run/ue.log"
# The user of uaclient asks for the K_AF of an AF_ID outside its list. The
# client itself asks the ME only after the AF has chosen AKMA, and the AF
# refuses another FQDN first.
python3 -c 'import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(b"KAF af2.akma.example FF00000001\n")
print(s.makefile().readline().strip())' "/run/ueransim/akma-$supi.sock" >"$run/ua-k-afid.out" 2>&1
check R2k.af-id "an AF_ID outside the list of uaclient is refused (cl. 4.4.3)" \
    bash -c 'grep -qx "ERR NOT_AUTHORIZED" "$1" &&
        grep -aqF "Application [uaclient] not authorized for AF_ID[af2.akma.example.FF00000001]" "$2"' _ \
    "$run/ua-k-afid.out" "$run/ue.log"
sudo -u nobody python3 -c 'import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(b"KAF af1.akma.example FF00000001\n")
print(s.makefile().readline().strip())' "/run/ueransim/akma-$supi.sock" >"$run/ua-k-uid.out" 2>&1
check R2k.uid "another user gets no K_AF (cl. 4.4.3)" grep -qx "ERR NOT_AUTHORIZED" "$run/ua-k-uid.out"
sudo "$netns" cli "$supi" -e "akma-kaf af1.akma.example" >"$run/ua-k-cli.out" 2>&1
check R2k.nr-cli "akma-kaf of nr-cli is disabled" grep -q "akma-kaf is disabled" "$run/ua-k-cli.out"
awk '{print} /^akmaKeyService:/ {svc=1} svc && /^  applications:/ {print "    - name: other\n      uid: 0\n      afIds:\n        - af1.akma.example.FF00000001"; svc=0}' \
    "$uer/config/free5gc-ue.yaml" >"$run/ue-duplicate.yaml"
timeout 5 "$uer/build/nr-ue" -c "$run/ue-duplicate.yaml" >"$run/ua-k-dup.out" 2>&1
check R2k.duplicate "a configuration that gives one AF_ID to two applications is refused" \
    grep -q "is given to more than one application" "$run/ua-k-dup.out"

# ---------------------------------------------------------------- R2t
# The TLS profiles of TS 24.109 Annex K, with the K_AF of the ME for the AF_ID
# of each profile and cipher suite (TS 33.220 H.3). -reconnect: the second
# request goes on a new connection that resumes the TLS session.
step "R2t Ua* over the TLS profiles"
ua -profile digest-tls -ca "$ca" -connect "$af_ip" -reconnect -n 2 >"$run/ua-t-k2.out" 2>&1
check R2t.k2-tls13 "K.2: Digest inside TLS 1.3, the AF authenticated by its certificate (TS 24.109 K.2)" \
    grep -q "session established (nc 00000002).*AF_ID $fqdn.01000113.*TLS 1.3" "$run/ua-t-k2.out"
check R2t.k2-resumed "K.2: the second connection resumed the TLS session (TS 33.222 cl. 5.3.1.5)" \
    grep -q "(nc 00000002).*resumed true" "$run/ua-t-k2.out"
ua -profile digest-tls -tls12 -ca "$ca" -connect "$af_ip" -n 1 >"$run/ua-t-k2-12.out" 2>&1
check R2t.k2-tls12 "K.2 inside TLS 1.2: AF_ID of TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" \
    grep -q "session established (nc 00000001).*AF_ID $fqdn.010001C02B.*TLS 1.2" "$run/ua-t-k2-12.out"
ua -profile psk-tls13 -connect "$af_ip" -reconnect -n 2 >"$run/ua-t-psk13.out" 2>&1
check R2t.psk13 "PSK TLS 1.3 with K_AF, AF_ID $fqdn.0100000007 (TS 24.109 K.3.3), two connections" \
    test "$(grep -c "AF authenticated by the TLS handshake with K_AF.*AF_ID $fqdn.0100000007; TLS 1.3, cipher suite 1301" "$run/ua-t-psk13.out")" -eq 2
ua -profile psk-tls12 -connect "$af_ip" -reconnect -n 2 >"$run/ua-t-psk12.out" 2>&1
check R2t.psk12 "PSK TLS 1.2 with K_AF, TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256, AF_ID $fqdn.010001D001 (K.3.2)" \
    grep -q "AF authenticated by the TLS handshake with K_AF.*AF_ID $fqdn.010001D001; TLS 1.2, cipher suite D001, resumed false" "$run/ua-t-psk12.out"
check R2t.psk12-resumed "PSK TLS 1.2: the second connection resumed the session (TS 33.222 cl. 5.4.1.4)" \
    grep -q "AF_ID $fqdn.010001D001; TLS 1.2, cipher suite D001, resumed true" "$run/ua-t-psk12.out"
check R2t.me "the ME gave uaclient the K_AF of each AF_ID of the TLS profiles" \
    bash -c 'for id in 01000113 010001C02B 0100000007 010001D001; do grep -aqF "K_AF for AF_ID[$2.$id" "$1" || exit 1; done' _ "$run/ue.log" "$fqdn"
ua -profile psk-tls13 -psk-ke-only -connect "$af_ip" -n 1 >"$run/ua-t-psk-ke.out" 2>&1
check R2t.psk-ke "a ClientHello with psk_ke only is refused (TS 33.210 cl. 6.2.2)" \
    grep -q "wolftls: handshake" "$run/ua-t-psk-ke.out"

# ---------------------------------------------------------------- R2d
# The DTLS profiles (TS 33.535 Annex C): a CoAP GET over UDP through the user
# plane, with the K_AF of 01 00 00 00 09 (DTLS 1.3) or of the cipher suite
# (DTLS 1.2).
step "R2d Ua* over the DTLS profiles"
ua -profile psk-dtls13 -connect "$af_ip" -reconnect -n 2 >"$run/ua-d-13.out" 2>&1
check R2d.dtls13 "DTLS 1.3 with K_AF, CoAP, AF_ID $fqdn.0100000009 (TS 33.535 Annex C), two associations" \
    test "$(grep -c "AF authenticated by the DTLS handshake with K_AF.*AF_ID $fqdn.0100000009; DTLS 1.3, cipher suite 1301" "$run/ua-d-13.out")" -eq 2
ua -profile psk-dtls12 -connect "$af_ip" -reconnect -n 2 >"$run/ua-d-12.out" 2>&1
check R2d.dtls12 "DTLS 1.2 with K_AF, TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256, AF_ID $fqdn.010001D001" \
    grep -q "AF_ID $fqdn.010001D001; DTLS 1.2, cipher suite D001, resumed false" "$run/ua-d-12.out"
check R2d.dtls12-resumed "DTLS 1.2: the second association resumed the session" \
    grep -q "AF_ID $fqdn.010001D001; DTLS 1.2, cipher suite D001, resumed true" "$run/ua-d-12.out"
check R2d.me "the ME gave uaclient the K_AF of the AF_ID of DTLS 1.3" \
    grep -aqF "K_AF for AF_ID[$fqdn.0100000009] given to application [uaclient]" "$run/ue.log"
ua -profile psk-dtls13 -psk-ke-only -connect "$af_ip" -n 1 >"$run/ua-d-psk-ke.out" 2>&1
check R2d.psk-ke "DTLS 1.3: a ClientHello with psk_ke only is refused (TS 33.210 cl. 6.2.2)" \
    grep -q "wolftls: handshake" "$run/ua-d-psk-ke.out"

# ---------------------------------------------------------------- R2o
# The OSCORE profile (TS 33.535 Annex D): POST /akma in CBOR over UDP through
# the user plane, then requests protected with the context from the K_AF of
# 01 00 00 00 08.
step "R2o Ua* over OSCORE"
ua -profile oscore -connect "$af_ip" -n 2 >"$run/ua-o.out" 2>&1
check R2o.oscore "OSCORE with a context from K_AF, AF_ID $fqdn.0100000008 (TS 33.535 Annex D), two requests in one context" \
    test "$(grep -c "AF authenticated by the OSCORE context from K_AF.*AF_ID $fqdn.0100000008" "$run/ua-o.out")" -eq 2
ua -profile oscore -connect "$af_ip" -rekey -n 2 >"$run/ua-o-rekey.out" 2>&1
check R2o.rekey "the context renewed before each request by RFC 8613 Appendix B.2 (D.3.4)" \
    test "$(grep -c "AF_ID $fqdn.0100000008; context renewed, ID Context [0-9a-f]\{32\}" "$run/ua-o-rekey.out")" -eq 2
ua -profile oscore -connect "$af_ip" -reconnect -n 2 >"$run/ua-o-reconnect.out" 2>&1
check R2o.reconnect "a new POST /akma for each request, with new N1 and N2 (D.3.4)" \
    test "$(grep -c "AF authenticated by the OSCORE context from K_AF.*AF_ID $fqdn.0100000008" "$run/ua-o-reconnect.out")" -eq 2
check R2o.me "the ME gave uaclient the K_AF of the AF_ID of OSCORE" \
    grep -aqF "K_AF for AF_ID[$fqdn.0100000008] given to application [uaclient]" "$run/ue.log"
sync_point A

# ---------------------------------------------------------------- R2n
# The AF machine has started, in group A, an AF outside the operator network
# (8083), the same AF with anonymous access (8084), an anonymous AF inside
# the operator network (8085) and an AF outside the operator network with the
# PSK TLS 1.3 profile (8456).
step "R2n AF outside the operator network (NEF) and anonymous access"
ua -connect "$af_ip:8083" -n 1 >"$run/ua-nef.out" 2>&1
check R2n.ua-nef "Ua* with the AF outside the operator network, K_AF through the NEF (TS 33.535 cl. 6.3)" \
    grep -q "session established (nc 00000001)" "$run/ua-nef.out"
ua -connect "$af_ip:8084" -n 1 >"$run/ua-nef-anon.out" 2>&1
check R2n.ua-nef-anon "Ua* with the AF outside the operator network, anonymous access (cl. 6.2.2)" \
    grep -q "session established (nc 00000001)" "$run/ua-nef-anon.out"
ua -connect "$af_ip:8085" -n 1 >"$run/ua-anon.out" 2>&1
check R2n.ua-anon "Ua* with an anonymous AF inside the operator network (cl. 6.2.2)" \
    grep -q "session established (nc 00000001)" "$run/ua-anon.out"
check R2n.aanf-via-nef "the AAnF provides K_AF through the NEF (cl. 6.3 step 4)" \
    bash -c 'grep -aF "for A-KID $1, expires" "$2" | grep -qF "through the NEF at"' _ "$akid1" "$f5log"
check R2n.nef-relayed "the NEF relays K_AF to the AF" \
    grep -aqF "K_AF for A-KID $akid1 relayed to AF_ID $fqdn." "$f5log"
ua -profile psk-tls13 -connect "$af_ip:8456" -n 1 >"$run/ua-nef-psk.out" 2>&1
check R2n.ua-nef-psk "PSK TLS 1.3 with the AF outside the operator network, K_AF through the NEF" \
    grep -q "AF authenticated by the TLS handshake with K_AF.*AF_ID $fqdn.0100000007" "$run/ua-nef-psk.out"
check R2n.nef-psk-relayed "the NEF relays the K_AF of the AF_ID of the PSK profile" \
    grep -aqF "K_AF for A-KID $akid1 relayed to AF_ID $fqdn.0100000007" "$f5log"
check R2n.nef-no-supi "no SUPI in the AKMA lines of the NEF (cl. 6.3 step 5)" \
    bash -c '! grep -a "CAT=\"AKMA\" NF=\"NEF\"" "$1" | grep -q "imsi-"' _ "$f5log"

# ---------------------------------------------------------------- R3
step "R3 new primary authentication"
kaffile="$(umask 077 && mktemp "$run/.kaf.XXXXXX")"
# The application keeps the K_AF it got before the new authentication: the
# test asks the AKMA key service of the ME for it, as the user of uaclient,
# and keeps it in a file only that user reads.
python3 -c 'import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(("KAF " + sys.argv[2] + " FF00000001\n").encode())
answer = s.makefile().readline().split()
print(dict(f.split("=", 1) for f in answer[1:]).get("k-af", "") if answer[:1] == ["OK"] else "")' \
    "/run/ueransim/akma-$supi.sock" "$fqdn" >"$kaffile"
check R3.reauth "deregistration and new registration with a new authentication" reauthenticate
akid2="$(ue_akid)"
setstate A_KID_2 "$akid2"
check R3.new-akid "the new authentication gives a new A-KID" test "$akid2" != "$akid1"
wait_for "$f5log" "A-KID $akid2 (previous context replaced)" 15
check R3.replaced "the AAnF replaces the context (TS 33.535 cl. 6.1 NOTE 1a)" \
    grep -aqF "AKMA context of $supi registered, A-KID $akid2 (previous context replaced)" "$f5log"
ua -n 1 >"$run/ua-2.out" 2>&1
check R3.ua-new "Ua* with the new A-KID" grep -q "session established (nc 00000001)" "$run/ua-2.out"
ua -akid "$akid1" -kaf-file "$kaffile" >"$run/ua-2-old.out" 2>&1
rm -f "$kaffile"
check R3.ua-old "Ua* with the previous A-KID and K_AF: still accepted by the AF until expiry (cl. 6.4.2, 5.2)" \
    grep -q "session established" "$run/ua-2-old.out"
sync_point B

# ---------------------------------------------------------------- R4
step "R4 AAnF down during a primary authentication"
failed_before="$(count "$f5log" "Naanf_AKMA_AnchorKey_Register for $supi failed")"
pkill -INT -x aanf
for ((i = 0; i < 15; i++)); do pgrep -x aanf >/dev/null || break; sleep 1; done
check R4.aanf-stopped "AAnF stopped" bash -c '! pgrep -x aanf >/dev/null'
check R4.registration "registration and PDU session without the AAnF" reauthenticate
akid3="$(ue_akid)"
setstate A_KID_3 "$akid3"
check R4.ausf-error "the AUSF logs the failed AnchorKey_Register and the authentication goes on" \
    wait_more "$f5log" "Naanf_AKMA_AnchorKey_Register for $supi failed" "$failed_before" 15
ua -n 1 >"$run/ua-3.out" 2>&1
check R4.ua "Ua*: the AF cannot obtain K_AF (503 AANF_UNAVAILABLE)" grep -q "503 AANF_UNAVAILABLE" "$run/ua-3.out"
./bin/aanf -c ./config/aanfcfg.yaml -l "$f5log" >"$run/aanf-restart.out" 2>&1 </dev/null &
check R4.aanf-restarted "AAnF started again" \
    bash -c 'for i in $(seq 20); do ss -ltn | grep -qF "$1" && exit 0; sleep 1; done; exit 1' _ "$aanf"

# ---------------------------------------------------------------- R5
step "R5 subscriber without AKMA subscription"
"$repo/free5gc/scripts/provision-akma-subscriber.sh" "$supi" --revoke >"$run/revoke.out" 2>&1
indications="$(count "$f5log" "AKMA indication sent to the AUSF for $supi")"
check R5.reauth "registration of the subscriber without AKMA subscription" reauthenticate
akid4="$(ue_akid)"
setstate A_KID_4 "$akid4"
check R5.no-indication "the UDM sends no AKMA indication" \
    test "$(count "$f5log" "AKMA indication sent to the AUSF for $supi")" -eq "$indications"
check R5.no-context "the AAnF has no context for the A-KID the UE derived" \
    bash -c "! grep -aqF 'A-KID $akid4' '$f5log'"
ua -n 1 >"$run/ua-4.out" 2>&1
check R5.ua "Ua*: 403 AKMA_KEY_NOT_AVAILABLE" grep -q "403 AKMA_KEY_NOT_AVAILABLE" "$run/ua-4.out"
"$repo/free5gc/scripts/provision-akma-subscriber.sh" "$supi" 0000 >/dev/null 2>&1
check R5.restored "subscription restored and a new authentication" reauthenticate
akid5="$(ue_akid)"
setstate A_KID_5 "$akid5"
wait_for "$f5log" "AKMA context of $supi registered, A-KID $akid5" 15
ua -n 1 >"$run/ua-5.out" 2>&1
check R5.ua-restored "Ua* again with the restored subscription" grep -q "session established" "$run/ua-5.out"

# ---------------------------------------------------------------- R6
step "R6 remove-context"
"$seed" remove --nrf "$nrf" --aanf "http://$aanf" --supi "$supi" >"$run/remove-1.out" 2>&1
check R6.removed "Naanf_AKMA_ContextRemove: removed (204)" grep -q "^removed" "$run/remove-1.out"
"$seed" remove --nrf "$nrf" --aanf "http://$aanf" --supi "$supi" >"$run/remove-2.out" 2>&1
check R6.not-found "remove-context again: 404 AKMA_CONTEXT_NOT_FOUND" \
    grep -q "404 (AKMA_CONTEXT_NOT_FOUND)" "$run/remove-2.out"

# ---------------------------------------------------------------- R6r
# The local authentication policy of the AAnF (TS 33.535 cl. 6.4.4): a copy
# of its configuration with kakmaRefresh 20s; the installed one is untouched
# and runs again at the end of the step.
step "R6r refresh of K_AKMA by the AAnF"
restart_aanf() { # configuration
    pkill -INT -x aanf
    for ((i = 0; i < 15; i++)); do pgrep -x aanf >/dev/null || break; sleep 1; done
    ./bin/aanf -c "$1" -l "$f5log" >>"$run/aanf-restart.out" 2>&1 </dev/null &
    for ((i = 0; i < 20; i++)); do ss -ltn | grep -qF "$aanf" && return 0; sleep 1; done
    return 1
}
sed 's/^\( *kakmaRefresh:\).*/\1 20s/' ./config/aanfcfg.yaml >"$run/aanfcfg-refresh.yaml"
restart_aanf "$run/aanfcfg-refresh.yaml"
check R6r.policy "AAnF started with kakmaRefresh 20s" \
    wait_for "$f5log" "older than 20s (TS 33.535 cl. 6.4.4)" 20
check R6r.registration "new registration: a K_AKMA registered at the AAnF" reauthenticate
akid6="$(ue_akid)"
setstate A_KID_6 "$akid6"
wait_for "$f5log" "AKMA context of $supi registered, A-KID $akid6" 15
requested="refresh requested from the UDM (TS 33.535 cl. 6.4.4)"
ua -n 1 >"$run/ua-6.out" 2>&1
check R6r.young "K_AF of a K_AKMA younger than 20s: no refresh" \
    bash -c 'grep -q "session established" "$1" && ! grep -aF "K_AKMA of $3 registered" "$2" | grep -qF "$4"' _ \
    "$run/ua-6.out" "$f5log" "$supi" "$requested"
sleep 21
derived="$(count "$run/ue.log" "AKMA key material derived")"
tun="$(count "$run/ue.log" "TUN interface[uesimtun0")"
# Another AF_ID: the AF keeps the K_AF of the first one until it expires
# (TS 33.535 cl. 6.4.2) and would not ask the AAnF again.
ua -profile psk-tls13 -connect "$af_ip" -n 1 >"$run/ua-7.out" 2>&1
check R6r.ua "K_AF of a K_AKMA older than 20s, for another AF_ID: provided to the AF" \
    grep -q "AF authenticated by the TLS handshake with K_AF.*AF_ID $fqdn.0100000007" "$run/ua-7.out"
check R6r.aanf "the AAnF asks the UDM for the refresh (Nudm_UECM_AuthTrigger)" \
    wait_for "$f5log" "Refresh of K_AKMA of $supi accepted by the UDM" 15
check R6r.udm "the UDM notifies the AMF (Nudm_UECM_Re-AuthenticationNotification, TS 33.501 cl. 6.1.5)" \
    bash -c 'grep -aF "AuthTrigger for $2 from AANF at" "$1" | grep -qF "re-authentication notified to the AMF"' _ \
    "$f5log" "$supi"
check R6r.amf "the AMF starts the primary authentication of the registered UE" \
    grep -aqF "Re-authentication of $supi requested by the UDM: started" "$f5log"
check R6r.smc "the AMF takes the new KAMF into use with a NAS SMC (TS 33.501 cl. 6.9.4.2)" \
    wait_for "$f5log" "Re-authentication of $supi requested by the UDM: completed" 15
check R6r.ue "the UE derives a new A-KID at the NAS SMC" \
    wait_more "$run/ue.log" "AKMA key material derived" "$derived" 15
akid7="$(ue_akid)"
setstate A_KID_7 "$akid7"
check R6r.new-akid "the new A-KID differs from the previous one" test "$akid7" != "$akid6"
check R6r.akid-ausf "A-KID of the UE = A-KID derived by the AUSF" \
    wait_for "$f5log" "K_AKMA and A-KID derived for $supi: A-KID $akid7" 15
check R6r.akid-aanf "the AAnF replaces the context with the new A-KID (TS 33.535 cl. 6.1 NOTE 1a)" \
    wait_for "$f5log" "AKMA context of $supi registered, A-KID $akid7 (previous context replaced)" 15
check R6r.pdu "the PDU session goes on: no new TUN interface" \
    test "$(count "$run/ue.log" "TUN interface[uesimtun0")" -eq "$tun"
ua -n 1 >"$run/ua-8.out" 2>&1
check R6r.ua-new "Ua* through the same PDU session, with the new A-KID" \
    bash -c 'grep -q "session established" "$1" && grep -aqF "for A-KID $3, expires" "$2"' _ \
    "$run/ua-8.out" "$f5log" "$akid7"
check R6r.once "one refresh: none for the new K_AKMA" \
    test "$(grep -aF "K_AKMA of $supi registered" "$f5log" | grep -cF "$requested")" -eq 1
"$seed" trigger-auth --nrf "$nrf" --supi "$supi" >"$run/trigger-1.out" 2>&1
check R6r.udm-interval "another AuthTrigger within 60 s: 403 REAUTHENTICATION_NOT_ALLOWED" \
    grep -q "UDM answered 403 (REAUTHENTICATION_NOT_ALLOWED" "$run/trigger-1.out"
"$seed" trigger-auth --nrf "$nrf" --supi "$supi" --method GET >"$run/trigger-2.out" 2>&1
check R6r.udm-get "trigger-auth with GET: 405, Allow: POST (TS 29.503 table 6.2.3.13.4.1-1)" \
    bash -c 'grep -q "^405 " "$1" && grep -qx "allow: POST" "$1"' _ "$run/trigger-2.out"
"$seed" trigger-auth --nrf "$nrf" --supi "$supi" --body '{}' >"$run/trigger-3.out" 2>&1
check R6r.udm-no-supi "trigger-auth without supi: 400 MANDATORY_IE_MISSING" \
    grep -q '^400 .*"cause":"MANDATORY_IE_MISSING"' "$run/trigger-3.out"
"$seed" trigger-auth --nrf "$nrf" --supi imsi-208930000000099 >"$run/trigger-4.out" 2>&1
check R6r.udm-unknown "trigger-auth for an unknown SUPI: 404 USER_NOT_FOUND" \
    grep -q "UDM answered 404 (USER_NOT_FOUND" "$run/trigger-4.out"
check R6r.restored "AAnF back to the installed configuration" restart_aanf ./config/aanfcfg.yaml
sync_point C

# ---------------------------------------------------------------- R7
step "R7 logs"
cp "$f5log" "$run/free5gc.log"
for f in free5gc.log ue.log gnb.log; do
    check "R7.no-key-$f" "no 64-hexadecimal string in $f" bash -c "! grep -aEq '[0-9a-fA-F]{64}' '$run/$f'"
done

if [ "$keep" != --keep ]; then
    step "stop"
    stop_ue
    pkill -INT -x nr-gnb
    sudo kill -INT -- "-$runpid" 2>/dev/null
    for ((i = 0; i < 30; i++)); do kill -0 "$runpid" 2>/dev/null || break; sleep 1; done
    pkill -INT -x aanf
    sleep 2
    sudo ./force_kill.sh >/dev/null 2>&1
    echo "free5GC, gNB and UE stopped; the UE namespace and the N6 rules are kept"
fi

echo
echo "remote: $(grep -c ^PASS "$results") passed, $(grep -c ^FAIL "$results") failed"
! grep -q ^FAIL "$results"
