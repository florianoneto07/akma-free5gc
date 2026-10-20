#!/usr/bin/env bash
# Forwarding and NAT on N6 for the UE subnet, on the free5GC host, so that
# traffic from the PDU sessions leaves the UPF towards the data network (the
# AF machine, the Internet) and the answers come back. Needs root.
#
# Usage: sudo n6-nat.sh apply|remove|status
#   UE_SUBNET  UE address pool of the UPF (default: 10.60.0.0/16, upfcfg.yaml)
#   N6_IFACE   interface towards the data network (default: the one of the
#              default route)
#
# apply   net.ipv4.ip_forward=1; MASQUERADE of the UE subnet on N6_IFACE;
#         FORWARD accepted to and from the UE subnet; TCP MSS set to 1400 on
#         forwarded SYNs (GTP-U overhead), as in the free5GC installation guide.
#         Each rule is added once. Nothing is made persistent.
# remove  deletes the rules added by apply (ip_forward is left as it is).
# status  shows ip_forward and the rules of the UE subnet.
set -euo pipefail

subnet="${UE_SUBNET:-10.60.0.0/16}"
iface="${N6_IFACE:-$(ip route show default | awk '{print $5; exit}')}"
[ -n "$iface" ] || { echo "no default route: set N6_IFACE" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }

rules=(
    "nat POSTROUTING -s $subnet -o $iface -j MASQUERADE"
    "filter FORWARD -s $subnet -j ACCEPT"
    "filter FORWARD -d $subnet -j ACCEPT"
    "mangle FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400"
)

case "${1:-}" in
apply)
    sysctl -q -w net.ipv4.ip_forward=1
    for r in "${rules[@]}"; do
        read -r table chain spec <<<"$r"
        # shellcheck disable=SC2086
        if iptables -t "$table" -C "$chain" $spec 2>/dev/null; then
            echo "present: -t $table $chain $spec"
        else
            # shellcheck disable=SC2086
            iptables -t "$table" -I "$chain" 1 $spec
            echo "added:   -t $table $chain $spec"
        fi
    done
    ;;
remove)
    for r in "${rules[@]}"; do
        read -r table chain spec <<<"$r"
        # shellcheck disable=SC2086
        while iptables -t "$table" -C "$chain" $spec 2>/dev/null; do
            iptables -t "$table" -D "$chain" $spec
            echo "removed: -t $table $chain $spec"
        done
    done
    ;;
status)
    echo "UE subnet $subnet, N6 interface $iface"
    echo "net.ipv4.ip_forward = $(sysctl -n net.ipv4.ip_forward)"
    echo "FORWARD policy: $(iptables -S FORWARD | head -1)"
    for r in "${rules[@]}"; do
        read -r table chain spec <<<"$r"
        # shellcheck disable=SC2086
        if iptables -t "$table" -C "$chain" $spec 2>/dev/null; then s=present; else s=absent; fi
        echo "$s: -t $table $chain $spec"
    done
    if command -v ufw >/dev/null; then ufw status | head -1; fi
    ;;
*)
    echo "usage: sudo $0 apply|remove|status" >&2
    exit 2
    ;;
esac
