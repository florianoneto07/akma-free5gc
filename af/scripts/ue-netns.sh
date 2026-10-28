#!/usr/bin/env bash
# The UE of UERANSIM in a network namespace of its own. On the host where
# free5GC runs it is required: in the host namespace the address of the PDU
# session (10.60.0.1) would be local to the host, and the kernel would drop
# the packets that the UPF delivers from upfgtp; in its own namespace the UE
# reaches the data network through the user plane: uesimtun0 -> gNB -> UPF ->
# N6 (free5gc/scripts/n6-nat.sh). Needs root.
#
# Usage: sudo ue-netns.sh up|down|status
#        sudo ue-netns.sh ue [nr-ue config]       run nr-ue in the namespace
#        sudo ue-netns.sh cli <nr-cli arguments>  run nr-cli in the namespace
#        sudo ue-netns.sh ua [uaclient options]   run the Ua* client in the
#             namespace, as the invoking user, with A-KID and K_AF from the
#             AKMA key service of the ME and the address of the PDU session as
#             source
#
#   UE_NETNS      namespace (default: ueransim-ue)
#   UERANSIM_DIR  UERANSIM directory (default: ~/UERANSIM of the invoking user)
#   UE_CONFIG     nr-ue configuration (default: config/free5gc-ue.yaml)
#   UACLIENT      Ua* client (default: af/build/bin/uaclient of this repository)
#   AKMA_SOCKET   AKMA key service of the ME (default: /run/ueransim/akma-<SUPI>.sock)
#
# The namespace reaches the gNB through a veth pair: 10.100.0.1 on the host,
# 10.100.0.2 in the namespace. The gNB must listen there (linkIp: 10.100.0.1
# in free5gc-gnb.yaml) and the UE must search it there (gnbSearchList).
set -euo pipefail

ns="${UE_NETNS:-ueransim-ue}"
host_if=veth-ue-host
ns_if=veth-ue-ns
host_ip=10.100.0.1
ns_ip=10.100.0.2
here="$(cd "$(dirname "$0")/.." && pwd)"
user="${SUDO_USER:-$(id -un)}"
user_home="$(getent passwd "$user" | cut -d: -f6)"
ueransim="${UERANSIM_DIR:-$user_home/UERANSIM}"
ue_config="${UE_CONFIG:-$ueransim/config/free5gc-ue.yaml}"
uaclient="${UACLIENT:-$here/build/bin/uaclient}"

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }

exists() { ip netns list | awk '{print $1}' | grep -qx "$ns"; }
need() { exists || { echo "namespace $ns does not exist: run '$0 up'" >&2; exit 1; }; }
pdu_addr() { ip netns exec "$ns" ip -4 -o addr show dev uesimtun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1; }

case "${1:-}" in
up)
    if exists; then
        echo "namespace $ns already exists"
    else
        ip netns add "$ns"
        ip link add "$host_if" type veth peer name "$ns_if"
        ip link set "$ns_if" netns "$ns"
        ip addr add "$host_ip/24" dev "$host_if"
        ip link set "$host_if" up
        ip netns exec "$ns" ip link set lo up
        ip netns exec "$ns" ip addr add "$ns_ip/24" dev "$ns_if"
        ip netns exec "$ns" ip link set "$ns_if" up
        ip netns exec "$ns" ip route add default via "$host_ip"
        echo "namespace $ns: host $host_ip <-> UE $ns_ip"
    fi
    gnb="$ueransim/config/free5gc-gnb.yaml"
    if [ -f "$gnb" ] && ! grep -Eq "^linkIp: *$host_ip( |$)" "$gnb"; then
        echo "note: $gnb does not have 'linkIp: $host_ip'; the UE in $ns will not find the gNB"
    fi
    ;;
down)
    if exists; then
        for pid in $(ip netns pids "$ns"); do kill "$pid" 2>/dev/null || true; done
        ip netns del "$ns"
        echo "namespace $ns deleted"
    fi
    ip link del "$host_if" 2>/dev/null || true
    ;;
status)
    if ! exists; then echo "namespace $ns: absent"; exit 3; fi
    echo "namespace $ns: present"
    ip -br addr show "$host_if" 2>/dev/null || true
    ip netns exec "$ns" ip -br addr
    addr="$(pdu_addr)"
    echo "PDU session address: ${addr:-none}"
    ;;
ue)
    need
    shift
    exec ip netns exec "$ns" "$ueransim/build/nr-ue" -c "${1:-$ue_config}"
    ;;
cli)
    need
    shift
    exec ip netns exec "$ns" runuser -u "$user" -- "$ueransim/build/nr-cli" "$@"
    ;;
ua)
    need
    shift
    addr="$(pdu_addr)"
    [ -n "$addr" ] || { echo "no PDU session (uesimtun0) in $ns" >&2; exit 1; }
    supi="$(awk -F"'" '/^supi:/ {print $2}' "$ue_config")"
    [ -n "$supi" ] || { echo "no supi in $ue_config" >&2; exit 1; }
    [ -x "$uaclient" ] || { echo "$uaclient not found: run af/scripts/build-af.sh" >&2; exit 1; }
    exec ip netns exec "$ns" runuser -u "$user" -- "$uaclient" \
        -me-socket "${AKMA_SOCKET:-/run/ueransim/akma-$supi.sock}" -bind "$addr" "$@"
    ;;
*)
    echo "usage: sudo $0 up|down|status|ue [config]|cli <args>|ua [uaclient options]" >&2
    exit 2
    ;;
esac
