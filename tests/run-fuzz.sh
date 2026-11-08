#!/usr/bin/env bash
# Host-side randomised tests of guest-facing parsers (virtqueues, netd's
# offload and steering, usbd's records).  Debug build: like the host components, it checks
# overflow and pointer preconditions.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
(cd "$root/tests/fuzz-virtq" && cargo +stable test -q && cargo +stable run -q -- "${1:-200000}")
(cd "$root/tests/fuzz-steer" && cargo +stable test -q && cargo +stable run -q -- "${1:-200000}")
# usbd's record checks and TRB layout: unit tests, then random records.
out=$root/build/usbtest
mkdir -p "$out"
rustc +stable --edition=2024 --crate-type rlib --crate-name l4h_abi "$root/host/l4h-abi/src/lib.rs" -o "$out/libl4h_abi.rlib"
rustc +stable --edition=2024 --test "$root/tests/usb.rs" --extern l4h_abi="$out/libl4h_abi.rlib" -o "$out/unit-tests"
"$out/unit-tests" -q
(cd "$root/tests/fuzz-usbreq" && cargo +stable run -q -- "${1:-200000}")
