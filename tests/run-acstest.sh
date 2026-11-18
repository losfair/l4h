#!/usr/bin/env bash
# Host-side checks of root's PCIe ACS setup (host/l4h-root/src/acs.rs)
# and BAR sizing (host/l4h-root/src/barsize.rs) against a model of
# configuration space.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/acstest
mkdir -p "$out"
rustc +stable --edition=2024 --test "$root/tests/acs.rs" -o "$out/unit-tests"
"$out/unit-tests"
rustc +stable --edition=2024 --test "$root/tests/barsize.rs" -o "$out/barsize-tests"
"$out/barsize-tests"
