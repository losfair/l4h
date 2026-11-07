#!/usr/bin/env bash
# Usage: run-reclaimtest.sh [seconds=120]
# RECLAIM_SWAP_DIR=/dev/shm uses host RAM. The default is the workspace
# disk; both use a virtio-blk image and QEMU cache=none. Output includes
# operation/fault counts and system swap-in/out counters.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/reclaimtest
mkdir -p "$out"
"$l4h_cc" -O2 -static -pthread -o "$out/reclaim-stress" "$root/tests/guest/reclaim-stress.c"
"$root/tools/mkinitramfs.sh" "$out/reclaimtest.cpio.gz" "$root/tests/guest/init-reclaimtest" \
    "$out/reclaim-stress" >/dev/null
disk=$(mktemp "${RECLAIM_SWAP_DIR:-$out}/l4h-swap.XXXXXX")
trap 'rm -f "$disk"' EXIT
truncate -s 512M "$disk"
seconds=${1:-120}
L4H_DOM0_MEM_MB=256 L4H_DOM0_VCPUS=1 \
L4H_QEMU_ARGS="-drive file=$disk,if=none,id=swap,format=raw,cache=none -device virtio-blk-pci,drive=swap,disable-legacy=on" \
    "$root/tools/run-dom0.sh" "$out/reclaimtest.cpio.gz" "console=hvc0 reclaim_seconds=$seconds" \
    "$((seconds + 180))" | tee "$out/run.log"
grep -q 'RECLAIM: PASS' "$root/build/qemu.log"
! grep -q 'RECLAIM: FAIL' "$root/build/qemu.log" || exit 1
