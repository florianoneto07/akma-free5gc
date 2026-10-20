#!/usr/bin/env bash
# Apply or revert the AKMA patches on UERANSIM, and rebuild nr-ue. Runs on
# the host where UERANSIM is built: the free5GC host or a separate host.
#
# Usage: patch-ueransim.sh apply|revert|status [patch-dir]
#   patch-dir     default: af/ue/ueransim/patches in the repository
#   UERANSIM_DIR  UERANSIM directory (default: ~/UERANSIM)
#
# apply   checks every patch, applies them in order with git apply, keeps a
#         copy of the original binary as build/nr-ue.orig (once) and rebuilds
#         nr-ue and nr-akma-selftest only, incrementally, in
#         cmake-build-release, with the cmake that configured it.
# revert  reverses the patches in the opposite order, restores build/nr-ue
#         from build/nr-ue.orig and removes build/nr-akma-selftest.
# status  tells whether the patches are applied.
#
# To move to a newer set of patches, revert with the old set first.
set -euo pipefail

action="${1:?usage: patch-ueransim.sh apply|revert|status [patch-dir]}"
here="$(cd "$(dirname "$0")/.." && pwd)"
patch_dir="$(cd "${2:-$here/ue/ueransim/patches}" && pwd)"
dir="${UERANSIM_DIR:-$HOME/UERANSIM}"
bin="$dir/build/nr-ue"

git -C "$dir" rev-parse --show-toplevel >/dev/null 2>&1 || { echo "$dir is not a git checkout" >&2; exit 1; }
gitapply() { git -C "$dir" apply "$@"; }
mapfile -t patches < <(find "$patch_dir" -maxdepth 1 -name '*.patch' | sort)
[ "${#patches[@]}" -gt 0 ] || { echo "no patch in $patch_dir" >&2; exit 1; }
# Only the files touched by the patches are checked for local changes, so
# that an edited gNB configuration does not block the UE patches.
mapfile -t files < <(for p in "${patches[@]}"; do gitapply --numstat "$p"; done | cut -f3 | sort -u)
gitstatus() { git -C "$dir" status --porcelain "$@" -- "${files[@]}"; }

# series_ok forward|reverse: dry run of the whole series, in order (or in
# the opposite order when reversing), on a scratch copy of the files it
# touches. Later patches of the series depend on earlier ones, so they cannot
# be checked one by one against the tree.
series_ok() {
    local tmp f p rc=0 list=("${patches[@]}") opt=()
    if [ "$1" = reverse ]; then
        opt=(--reverse)
        list=()
        for ((i=${#patches[@]}-1; i>=0; i--)); do list+=("${patches[$i]}"); done
    fi
    tmp="$(mktemp -d)"
    for f in "${files[@]}"; do
        if [ -e "$dir/$f" ]; then
            mkdir -p "$tmp/$(dirname "$f")"
            cp -p "$dir/$f" "$tmp/$f"
        fi
    done
    for p in "${list[@]}"; do
        (cd "$tmp" && git apply "${opt[@]}" "$p") >/dev/null 2>&1 || { rc=1; break; }
    done
    rm -rf "$tmp"
    return "$rc"
}

applied() { series_ok reverse; }

build() {
    local cache="$dir/cmake-build-release/CMakeCache.txt" cmake_bin=cmake t targets=(nr-ue)
    grep -q "nr-akma-selftest" "$dir/CMakeLists.txt" && targets+=(nr-akma-selftest)
    if [ -f "$cache" ]; then
        # The cmake that configured the tree (UERANSIM needs 3.17 or later).
        cmake_bin="$(sed -n 's/^CMAKE_COMMAND:INTERNAL=//p' "$cache")"
        # One target per run: a changed CMakeLists.txt regenerates the
        # makefiles during the first one.
        for t in "${targets[@]}"; do
            "$cmake_bin" --build "$dir/cmake-build-release" --target "$t"
        done
    else
        make -C "$dir"
    fi
    # Rename into place: works while an nr-ue is running.
    for t in "${targets[@]}"; do
        cp -p "$dir/cmake-build-release/$t" "$dir/build/$t.new"
        mv "$dir/build/$t.new" "$dir/build/$t"
    done
    echo "rebuilt: ${targets[*]} in $dir/build"
}

case "$action" in
status)
    if applied; then echo "UERANSIM: patches applied"; else echo "UERANSIM: patches not applied"; fi
    gitstatus
    ;;
apply)
    if applied; then
        echo "UERANSIM: patches already applied"
    else
        if [ -n "$(gitstatus --untracked-files=no)" ]; then
            echo "$dir has local changes; not applying" >&2
            gitstatus --untracked-files=no >&2
            exit 1
        fi
        series_ok forward || { echo "the patches do not apply to $dir" >&2; exit 1; }
        for p in "${patches[@]}"; do gitapply "$p"; echo "applied $(basename "$p")"; done
    fi
    if [ -f "$bin" ] && [ ! -f "$bin.orig" ]; then
        cp -p "$bin" "$bin.orig"
        echo "original binary kept as build/nr-ue.orig"
    fi
    build
    ;;
revert)
    if applied; then
        for ((i=${#patches[@]}-1; i>=0; i--)); do
            gitapply --reverse "${patches[$i]}"
            echo "reverted $(basename "${patches[$i]}")"
        done
    else
        echo "UERANSIM: patches not applied; nothing to reverse in the source"
    fi
    if [ -f "$bin.orig" ]; then
        cp -p "$bin.orig" "$bin.new"
        mv "$bin.new" "$bin"
        echo "build/nr-ue restored from build/nr-ue.orig"
    fi
    rm -f "$dir/build/nr-akma-selftest"
    ;;
*)
    echo "unknown action $action" >&2
    exit 2
    ;;
esac
