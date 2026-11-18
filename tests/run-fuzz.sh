#!/usr/bin/env bash
# Host-side randomised tests of guest-facing parsers (virtqueues, the
# uplink channel to the NIC drivers, netd's offload, the mlx5 driver's
# receive completions, steering and L3 filter, usbd's records, blkd's windows).  Debug build: it checks overflow, as
# shipped (release) host builds also do (overflow-checks, DESIGN.md §10,
# "Integer arithmetic"), and pointer preconditions, which release builds
# do not.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
# netd's offload checks (l4h-netcore's unit tests), and the mlx5 driver's
# receive completions (built for Linux by its VFIO harness).
cargo +stable test -q --manifest-path "$root/host/l4h-netcore/Cargo.toml"
cargo +stable test -q --manifest-path "$root/tests/mlx5-vfio/Cargo.toml"
(cd "$root/tests/fuzz-virtq" && cargo +stable test -q && cargo +stable run -q -- "${1:-200000}")
(cd "$root/tests/fuzz-steer" && cargo +stable test -q && cargo +stable run -q -- "${1:-200000}")
(cd "$root/tests/fuzz-ipfilter" && cargo +stable test -q && cargo +stable run -q -- "${1:-200000}")
(cd "$root/tests/fuzz-uplink" && cargo +stable run -q -- "${1:-200000}")
# usbd's record checks and TRB layout: unit tests, then random records.
out=$root/build/usbtest
mkdir -p "$out"
rustc +stable --edition=2024 --crate-type rlib --crate-name l4h_abi "$root/host/l4h-abi/src/lib.rs" -o "$out/libl4h_abi.rlib"
rustc +stable --edition=2024 --crate-type rlib --crate-name l4h_host "$root/host/l4h-host/src/lib.rs" --extern l4h_abi="$out/libl4h_abi.rlib" -o "$out/libl4h_host.rlib"
rustc +stable --edition=2024 --test "$root/tests/usb.rs" --extern l4h_abi="$out/libl4h_abi.rlib" --extern l4h_host="$out/libl4h_host.rlib" -L "$out" -o "$out/unit-tests"
"$out/unit-tests" -q
# blkd's disk windows and extent volumes (l4h_host::blk).
rustc +stable --edition=2024 --test "$root/tests/blk-windows.rs" --extern l4h_host="$out/libl4h_host.rlib" -L "$out" -o "$out/blk-window-tests"
"$out/blk-window-tests" -q
(cd "$root/tests/fuzz-usbreq" && cargo +stable run -q -- "${1:-200000}")
