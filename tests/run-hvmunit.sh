#!/usr/bin/env bash
# l4h-hvm's platform models and image loading on the build host
# (tests/hvm.rs): no seL4, no QEMU.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/hvmunit
mkdir -p "$out"
rustc +stable --edition=2024 --crate-name l4h_abi --crate-type rlib \
    "$root/host/l4h-abi/src/lib.rs" -o "$out/libl4h_abi.rlib"
rustc +stable --edition=2024 --crate-name l4h_host --crate-type rlib -L dependency="$out" \
    --extern l4h_abi="$out/libl4h_abi.rlib" "$root/host/l4h-host/src/lib.rs" -o "$out/libl4h_host.rlib"
rustc +stable --edition=2024 --test -D warnings -L dependency="$out" \
    --extern l4h_abi="$out/libl4h_abi.rlib" --extern l4h_host="$out/libl4h_host.rlib" \
    "$root/tests/hvm.rs" -o "$out/unit-tests"
"$out/unit-tests" "$@"
