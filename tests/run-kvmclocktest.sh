#!/usr/bin/env bash
# The actual kernel and multikernel pvclock readers, with modeled CPUID/MSRs.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
"$root/tools/prepare-kernel.sh"
out=$root/build/kvmclocktest
mkdir -p "$out"
gcc -std=gnu11 -O2 -Wall -Wextra -Werror -I"$root/build/seL4-src/include/plat/pc99" \
    "$root/tests/kvm-clock.c" -o "$out/kernel"
"$out/kernel"
rustc +stable --edition=2024 --test "$root/tests/kvm-clock.rs" -o "$out/shim"
"$out/shim"
