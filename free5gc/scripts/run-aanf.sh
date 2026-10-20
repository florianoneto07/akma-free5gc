#!/usr/bin/env bash
# Start, stop or query the AAnF on the free5GC host.
#
# Usage: run-aanf.sh start|stop|status|foreground
#   FREE5GC_DIR  free5GC directory (default: ~/free5gc); the AAnF runs from it,
#                like the other NFs, so that relative paths such as
#                cert/nrf.pem resolve as in their configurations.
#
# From another machine: ssh <host> bash -s -- start < free5gc/scripts/run-aanf.sh
set -euo pipefail

dir="${FREE5GC_DIR:-$HOME/free5gc}"
logdir="$dir/log/aanf"
pidfile="$logdir/aanf.pid"
export GIN_MODE=release   # as run.sh: no gin debug lines on the console
cmd=(./bin/aanf -c ./config/aanfcfg.yaml -l "$logdir/aanf.log")

running() {
    [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

cd "$dir"
[ -x ./bin/aanf ] || { echo "$dir/bin/aanf not found" >&2; exit 1; }
[ -f ./config/aanfcfg.yaml ] || { echo "$dir/config/aanfcfg.yaml not found" >&2; exit 1; }
mkdir -p "$logdir"

case "${1:-}" in
start)
    if running; then echo "AAnF already running (pid $(cat "$pidfile"))"; exit 0; fi
    nohup "${cmd[@]}" >"$logdir/aanf.out" 2>&1 &
    echo $! >"$pidfile"
    sleep 2
    if running; then
        echo "AAnF started (pid $(cat "$pidfile")); log: $logdir/aanf.log"
    else
        echo "AAnF exited; see $logdir/aanf.out" >&2
        tail -20 "$logdir/aanf.out" >&2
        exit 1
    fi
    ;;
stop)
    if ! running; then echo "AAnF not running"; rm -f "$pidfile"; exit 0; fi
    pid="$(cat "$pidfile")"
    kill -TERM "$pid"   # the AAnF deregisters from the NRF on SIGTERM
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    if kill -0 "$pid" 2>/dev/null; then echo "AAnF did not stop (pid $pid)" >&2; exit 1; fi
    rm -f "$pidfile"
    echo "AAnF stopped"
    ;;
status)
    if running; then echo "AAnF running (pid $(cat "$pidfile"))"; else echo "AAnF not running"; exit 3; fi
    ;;
foreground)
    exec "${cmd[@]}"
    ;;
*)
    echo "usage: $0 start|stop|status|foreground" >&2
    exit 2
    ;;
esac
