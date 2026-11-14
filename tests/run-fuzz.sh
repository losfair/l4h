#!/usr/bin/env bash
# Host-side randomised tests of guest-facing parsers (virtqueues, the
# uplink channel to the NIC drivers, netd's offload, steering and L3 filter, usbd's records, blkd's windows).  Debug build: it checks overflow and
# pointer preconditions, which shipped (release) host builds do not
# (DESIGN.md §10, "Integer arithmetic").
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
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
