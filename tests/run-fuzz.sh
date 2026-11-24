#!/usr/bin/env bash
# Host-side randomised tests of guest-facing parsers (virtqueues, the
# uplink channel to the NIC drivers, netd's offload, the mlx5 driver's
# receive completions, steering and L3 filter, usbd's records, blkd's windows).  Debug build: it checks overflow, as
# shipped (release) host builds also do (overflow-checks, DESIGN.md §10,
# "Integer arithmetic"), and pointer preconditions, which release builds
# do not.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
iters=${1:-200000}
out=$root/build/usbtest
mkdir -p "$out"
pids=() names=()
trap 'for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true' EXIT
spawn() {
    local name=$1; shift
    ( "$@" ) >"$out/fuzz-$name.log" 2>&1 &
    pids+=($!)
    names+=("$name")
}
# Independent CPU-bound fuzzers and unit tests run in parallel across cores.
spawn fuzz-uplink bash -euo pipefail -c 'cd "$1/tests/fuzz-uplink" && cargo +stable run -q -- "$2"' _ "$root" "$iters"
spawn fuzz-virtq bash -euo pipefail -c 'cd "$1/tests/fuzz-virtq" && cargo +stable test -q && cargo +stable run -q -- "$2"' _ "$root" "$iters"
spawn fuzz-steer bash -euo pipefail -c 'cd "$1/tests/fuzz-steer" && cargo +stable test -q && cargo +stable run -q -- "$2"' _ "$root" "$iters"
spawn fuzz-ipfilter bash -euo pipefail -c 'cd "$1/tests/fuzz-ipfilter" && cargo +stable test -q && cargo +stable run -q -- "$2"' _ "$root" "$iters"
spawn fuzz-usbreq bash -euo pipefail -c 'cd "$1/tests/fuzz-usbreq" && cargo +stable run -q -- "$2"' _ "$root" "$iters"
spawn unit-tests bash -euo pipefail -c '
    root=$1 out=$2
    cargo +stable test -q --manifest-path "$root/host/l4h-netcore/Cargo.toml"
    cargo +stable test -q --manifest-path "$root/tests/mlx5-vfio/Cargo.toml"
    rustc +stable --edition=2024 --crate-type rlib --crate-name l4h_abi "$root/host/l4h-abi/src/lib.rs" -o "$out/libl4h_abi.rlib"
    rustc +stable --edition=2024 --crate-type rlib --crate-name l4h_host "$root/host/l4h-host/src/lib.rs" --extern l4h_abi="$out/libl4h_abi.rlib" -o "$out/libl4h_host.rlib"
    rustc +stable --edition=2024 --test "$root/tests/usb.rs" --extern l4h_abi="$out/libl4h_abi.rlib" --extern l4h_host="$out/libl4h_host.rlib" -L "$out" -o "$out/unit-tests"
    "$out/unit-tests" -q
    rustc +stable --edition=2024 --test "$root/tests/blk-windows.rs" --extern l4h_host="$out/libl4h_host.rlib" -L "$out" -o "$out/blk-window-tests"
    "$out/blk-window-tests" -q
' _ "$root" "$out"
fail=0
for i in "${!pids[@]}"; do
    if ! wait "${pids[$i]}"; then
        fail=1
    fi
    cat "$out/fuzz-${names[$i]}.log"
done
trap - EXIT
exit "$fail"
