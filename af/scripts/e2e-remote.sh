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
#       -> sync A (checks from the AF machine)
#   R3  new authentication: new A-KID; Ua* with it; Ua* with the previous
#       A-KID and K_AF, still valid at the AF until expiry
#       -> sync B
#   R4  AAnF down during a primary authentication: the authentication
#       succeeds and the registration in the AAnF fails (TS 33.535 cl. 6.1)
#   R5  subscriber without AKMA subscription, then restored
#   R6  remove-context
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
set -m # background jobs in their own process groups

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

./run.sh -aanf >"$run/run.out" 2>&1 </dev/null &
runpid=$!
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
sync_point A

# ---------------------------------------------------------------- R2n
# The AF machine has started, in group A, an AF outside the operator network
# (8083), the same AF with anonymous access (8084) and an anonymous AF inside
# the operator network (8085).
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
check R2n.nef-no-supi "no SUPI in the AKMA lines of the NEF (cl. 6.3 step 5)" \
    bash -c '! grep -a "CAT=\"AKMA\" NF=\"NEF\"" "$1" | grep -q "imsi-"' _ "$f5log"

# ---------------------------------------------------------------- R3
step "R3 new primary authentication"
kaffile="$(umask 077 && mktemp "$run/.kaf.XXXXXX")"
sudo "$netns" cli "$supi" -e "akma-kaf $fqdn" | sed -n 's/^k-af: //p' >"$kaffile"
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
