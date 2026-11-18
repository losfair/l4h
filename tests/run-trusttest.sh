#!/usr/bin/env bash
# Fixed-size flags service invariants, signed verifier policy checks and
# trustd's check of another partition's key.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/trusttest
mkdir -p "$out"
rustc +stable --edition=2024 --crate-type lib --crate-name l4h_abi "$root/host/l4h-abi/src/lib.rs" -o "$out/libl4h_abi.rlib"
rustc +stable --edition=2024 --crate-type lib --crate-name l4h_host "$root/host/l4h-host/src/lib.rs" \
    --extern l4h_abi="$out/libl4h_abi.rlib" -o "$out/libl4h_host.rlib"
rustc +stable --edition=2024 --test "$root/tests/trust.rs" -L dependency="$out" \
    --extern l4h_host="$out/libl4h_host.rlib" -o "$out/trust-tests"
"$out/trust-tests"
python3 "$root/tests/attest-verifier.py"
cargo +stable test -q --manifest-path "$root/tests/trustd-key/Cargo.toml"
