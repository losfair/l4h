#!/usr/bin/env bash
# Host-side checks of the partitions' message rings (tests/ring.rs).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/ringtest
mkdir -p "$out"
rustc +stable --edition=2024 -O --test "$root/tests/ring.rs" -o "$out/unit-tests"
"$out/unit-tests" --nocapture
rustc +stable --edition=2024 -O --test "$root/tests/link.rs" -o "$out/link-tests"
"$out/link-tests" --nocapture
