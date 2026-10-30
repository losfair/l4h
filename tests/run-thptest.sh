#!/usr/bin/env bash
# PMD THP correctness, including the 512 underlying seL4 mappings.
# Usage: run-thptest.sh [vcpus=4]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/thptest
mkdir -p "$out/page-aging"
"$l4h_cc" -O2 -g -Wall -Wextra -static -pthread -o "$out/thptest" "$root/tests/guest/thptest.c"
cp "$root"/tests/guest/page-aging/* "$out/page-aging/"
"$root/tools/build-linux.sh" vmlinux modules >"$out/build.log" 2>&1 \
    || { tail -80 "$out/build.log"; exit 1; }
"$root/tools/build-linux.sh" M="$out/page-aging" modules >"$out/module.log" 2>&1 \
    || { cat "$out/module.log"; exit 1; }
"$root/tools/mkinitramfs.sh" "$out/initrd.cpio.gz" "$root/tests/guest/init-thptest" \
    "$out/thptest" "$out/page-aging/l4h_page_aging.ko" >/dev/null
disk=$(mktemp "$out/swap.XXXXXX")
trap 'rm -f "$disk"' EXIT
truncate -s 128M "$disk"
L4H_DOM0_VCPUS=${1:-4} L4H_DOM0_MEM_MB=512 L4H_TEST_FAIL_PATTERN='THPTEST: FAIL|Kernel panic' \
L4H_QEMU_ARGS="-drive file=$disk,if=none,id=swap,format=raw,cache=none -device virtio-blk-pci,drive=swap,disable-legacy=on" \
    "$root/tools/run-dom0.sh" "$out/initrd.cpio.gz" 'console=hvc0' "${L4H_TEST_TIMEOUT:-600}" \
    | tee "$out/run.log"
grep -q 'THPTEST: PASS' "$root/build/qemu.log"
grep -q 'THPTEST: fallback PASS' "$root/build/qemu.log"
! grep -q 'THPTEST: FAIL\|WARNING:\|BUG:\|Kernel panic' "$root/build/qemu.log"
