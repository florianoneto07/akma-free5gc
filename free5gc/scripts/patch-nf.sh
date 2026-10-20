#!/usr/bin/env bash
# Apply or revert the AKMA patches on a network function of free5GC, and
# rebuild it. Runs on the free5GC host.
#
# Usage: patch-nf.sh <nf> apply|revert|status [patch-dir]
#   <nf>        directory under $FREE5GC_DIR/NFs (e.g. nrf, ausf, udm),
#               "test" for the Go test bench in $FREE5GC_DIR/test,
#               "config" for the configuration files in $FREE5GC_DIR/config, or
#               "run" for run.sh and force_kill.sh in $FREE5GC_DIR
#   patch-dir   default: the patches/<nf> directory next to this script's
#               parent (free5gc/patches/<nf> in the repository)
#   FREE5GC_DIR free5GC directory (default: ~/free5gc)
#
# apply   checks every patch, applies them in order with git apply, keeps a
#         copy of the original binary as bin/<nf>.orig (once) and runs
#         "make <nf>" (nothing is built for "test", "config" and "run").
# revert  reverses the patches in the opposite order and restores
#         bin/<nf> from bin/<nf>.orig.
# status  tells whether the patches are applied.
set -euo pipefail

nf="${1:?usage: patch-nf.sh <nf> apply|revert|status [patch-dir]}"
action="${2:?usage: patch-nf.sh <nf> apply|revert|status [patch-dir]}"
here="$(cd "$(dirname "$0")/.." && pwd)"
patch_dir="${3:-$here/patches/$nf}"
dir="${FREE5GC_DIR:-$HOME/free5gc}"
case "$nf" in
test | config) src="$dir/$nf"; build=false ;;
run) src="$dir"; build=false ;;
*) src="$dir/NFs/$nf"; build=true ;;
esac
bin="$dir/bin/$nf"

if ! command -v go >/dev/null && [ -x /usr/local/go/bin/go ]; then
    export PATH="/usr/local/go/bin:$PATH"
fi

# The NFs are git submodules; the test bench is a directory of the free5GC
# repository. Patches are relative to $src and applied from the top level.
root="$(git -C "$src" rev-parse --show-toplevel 2>/dev/null)" || { echo "$src is not in a git checkout" >&2; exit 1; }
prefix="$(git -C "$src" rev-parse --show-prefix)"
gitapply() { git -C "$root" apply ${prefix:+--directory="$prefix"} "$@"; }
mapfile -t patches < <(find "$patch_dir" -maxdepth 1 -name '*.patch' | sort)
[ "${#patches[@]}" -gt 0 ] || { echo "no patch in $patch_dir" >&2; exit 1; }
# Files touched by the patches, relative to the top level; only they are
# checked for local changes.
mapfile -t files < <(for p in "${patches[@]}"; do gitapply --numstat "$p"; done | cut -f3 | sort -u)
gitstatus() { git -C "$root" status --porcelain "$@" -- "${files[@]}"; }

applied() {
    local p
    for p in "${patches[@]}"; do
        gitapply --reverse --check "$p" 2>/dev/null || return 1
    done
}

case "$action" in
status)
    if applied; then echo "$nf: patches applied"; else echo "$nf: patches not applied"; fi
    gitstatus
    ;;
apply)
    if applied; then
        echo "$nf: patches already applied"
    else
        if [ -n "$(gitstatus --untracked-files=no)" ]; then
            echo "$src has local changes; not applying" >&2
            gitstatus --untracked-files=no >&2
            exit 1
        fi
        for p in "${patches[@]}"; do gitapply --check "$p"; done
        for p in "${patches[@]}"; do gitapply "$p"; echo "applied $(basename "$p")"; done
    fi
    if [ "$build" = false ]; then
        echo "$nf patched; nothing to build"
        exit 0
    fi
    if [ -f "$bin" ] && [ ! -f "$bin.orig" ]; then
        cp -p "$bin" "$bin.orig"
        echo "original binary kept as bin/$nf.orig"
    fi
    make -C "$dir" "$nf"
    echo "$nf rebuilt: $bin"
    ;;
revert)
    if applied; then
        for ((i=${#patches[@]}-1; i>=0; i--)); do
            gitapply --reverse "${patches[$i]}"
            echo "reverted $(basename "${patches[$i]}")"
        done
    else
        echo "$nf: patches not applied; nothing to reverse in the source"
    fi
    if [ -f "$bin.orig" ]; then
        cp -p "$bin.orig" "$bin"
        echo "bin/$nf restored from bin/$nf.orig"
    fi
    ;;
*)
    echo "unknown action $action" >&2
    exit 2
    ;;
esac
