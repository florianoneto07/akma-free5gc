#!/usr/bin/env bash
# Copy the AAnF and the seed tool to the free5GC host. Only new files: no
# file of free5GC is modified.
#
# Usage: free5gc/scripts/deploy.sh [user@host] [--force-config]
#   user@host       free5GC host; FREE5GC_HOST when absent
#   --force-config  replace an existing ~/free5gc/config/aanfcfg.yaml (its
#                   differences are shown first)
#
# Files written on the host:
#   ~/free5gc/bin/aanf                 AAnF binary (replaced on each deploy)
#   ~/free5gc/config/aanfcfg.yaml      AAnF configuration (kept if present)
#   ~/akma-tools/seed                  test tool (outside the free5GC tree)
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
target="${FREE5GC_HOST:-}"
force_config=no
for a in "$@"; do
    case "$a" in
    --force-config) force_config=yes ;;
    -*) echo "unknown option $a" >&2; exit 2 ;;
    *) target="$a" ;;
    esac
done
[ -n "$target" ] || { echo "usage: $0 user@host [--force-config] (or set FREE5GC_HOST)" >&2; exit 2; }
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)

for f in "$here/build/bin/aanf" "$here/build/bin/seed"; do
    [ -x "$f" ] || { echo "$f missing: run free5gc/scripts/build-aanf.sh" >&2; exit 1; }
done

ssh "${ssh_opts[@]}" "$target" 'test -d ~/free5gc/bin && test -d ~/free5gc/config' \
    || { echo "~/free5gc not found on $target" >&2; exit 1; }
if ssh "${ssh_opts[@]}" "$target" 'test -f ~/free5gc/log/aanf/aanf.pid && kill -0 "$(cat ~/free5gc/log/aanf/aanf.pid)" 2>/dev/null'; then
    echo "the AAnF is running on $target: stop it first (run-aanf.sh stop)" >&2
    exit 1
fi

scp "${ssh_opts[@]}" -q "$here/build/bin/aanf" "$target:free5gc/bin/aanf.new"
ssh "${ssh_opts[@]}" "$target" 'mv ~/free5gc/bin/aanf.new ~/free5gc/bin/aanf && mkdir -p ~/akma-tools'
scp "${ssh_opts[@]}" -q "$here/build/bin/seed" "$target:akma-tools/seed"
echo "copied bin/aanf and akma-tools/seed to $target"

if ssh "${ssh_opts[@]}" "$target" 'test -f ~/free5gc/config/aanfcfg.yaml'; then
    if ssh "${ssh_opts[@]}" "$target" 'cat ~/free5gc/config/aanfcfg.yaml' | diff -u - "$here/config/aanfcfg.yaml"; then
        echo "config/aanfcfg.yaml on $target is up to date"
    elif [ "$force_config" = yes ]; then
        scp "${ssh_opts[@]}" -q "$here/config/aanfcfg.yaml" "$target:free5gc/config/aanfcfg.yaml"
        echo "config/aanfcfg.yaml replaced on $target"
    else
        echo "config/aanfcfg.yaml on $target differs (above); kept. Use --force-config to replace it."
    fi
else
    scp "${ssh_opts[@]}" -q "$here/config/aanfcfg.yaml" "$target:free5gc/config/aanfcfg.yaml"
    echo "copied config/aanfcfg.yaml to $target"
fi
