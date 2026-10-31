#!/usr/bin/env bash
# Guest RAM blocks converting between frame mode and seL4 object mode
# (DESIGN.md §8.3): page-table pressure, smp_mm_stress during
# conversions, guest OOM when no 2 MiB block is left.
# Usage: run-objtest.sh [vcpus]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
"$l4h_cc" -O2 -static -o "$out/objtest" "$root/tests/guest/objtest.c"
"$l4h_cc" -O2 -static -pthread -o "$out/selftest" "$root/tests/guest/selftest.c"
"$root/tools/mkinitramfs.sh" "$out/objtest.cpio.gz" "$root/tests/guest/init-objtest" \
    "$out/objtest" "$out/selftest" >/dev/null
L4H_DOM0_VCPUS=${1:-4} L4H_DOM0_MEM_MB=${OBJTEST_MEM_MB:-256} \
    "$root/tools/run-dom0.sh" "$out/objtest.cpio.gz" "console=hvc0" ${OBJTEST_TIMEOUT:-600} \
    | grep -aE "OBJTEST|l4h: |Out of memory|Killed process|panic|BUG|SELFTEST: FAIL" || true
grep -aq "OBJTEST: PASS" "$root/build/qemu.log"
