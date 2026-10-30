#!/usr/bin/env bash
# Paired THP/base-page benchmarks. Trial 0 is warmup; trials 1-5 are measured.
# Usage: run-thpbench.sh [vcpus=1]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/thpbench
mkdir -p "$out/page-aging"
"$l4h_cc" -O2 -Wall -Wextra -static -o "$out/thpbench" "$root/tests/guest/thpbench.c"
cp "$root"/tests/guest/page-aging/* "$out/page-aging/"
"$root/tools/build-linux.sh" vmlinux modules >"$out/build.log" 2>&1 \
    || { tail -80 "$out/build.log"; exit 1; }
"$root/tools/build-linux.sh" M="$out/page-aging" modules >"$out/module.log" 2>&1 \
    || { cat "$out/module.log"; exit 1; }
"$root/tools/mkinitramfs.sh" "$out/initrd.cpio.gz" "$root/tests/guest/init-thpbench" "$out/thpbench" "$out/page-aging/l4h_page_aging.ko" >/dev/null
L4H_DOM0_VCPUS=${1:-1} L4H_DOM0_MEM_MB=512 L4H_TEST_FAIL_PATTERN='THPBENCH: FAIL|Kernel panic' \
    "$root/tools/run-dom0.sh" "$out/initrd.cpio.gz" 'console=hvc0' "${L4H_TEST_TIMEOUT:-900}" \
    | tee "$out/run-${1:-1}.log"
grep -q 'THPBENCH: PASS' "$root/build/qemu.log"
! grep -q 'THPBENCH: FAIL\|WARNING:\|BUG:\|Kernel panic' "$root/build/qemu.log"
