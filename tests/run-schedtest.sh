#!/usr/bin/env bash
# Pure host-side tests of CPU topology, placement, migration policy and CPU
# budgets, then the closed-loop scheduling simulation (tests/dst-sched.rs).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$root/build"
cd "$root/host"
rustc --edition=2024 --test "$root/tests/sched.rs" -o "$root/build/schedtest"
"$root/build/schedtest"
libs="$root/build/sched-libs"
mkdir -p "$libs"
rustc --edition=2024 --crate-name l4h_abi --crate-type rlib l4h-abi/src/lib.rs -o "$libs/libl4h_abi.rlib"
rustc --edition=2024 --crate-name l4h_host --crate-type rlib l4h-host/src/lib.rs \
    --extern l4h_abi="$libs/libl4h_abi.rlib" -o "$libs/libl4h_host.rlib"
rustc --edition=2024 -L dependency="$libs" --extern l4h_host="$libs/libl4h_host.rlib" \
    --extern l4h_abi="$libs/libl4h_abi.rlib" -O --test "$root/tests/dst-sched.rs" -o "$root/build/dst-schedtest"
"$root/build/dst-schedtest" "$@"
