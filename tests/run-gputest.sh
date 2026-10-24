#!/usr/bin/env bash
# dom0 creates a VM with a virtio-gpu (l4h-vmm's gpu.rs), which draws on
# it with DRM; the display, read with l4hctl screenshot, must show each
# image the VM shows, pixel for pixel, and nothing once it turns it off.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest/gpu
mkdir -p "$out"
"$root/tools/build-l4hctl.sh"
"$l4h_cc" -O2 -static -Wall -o "$out/gpudraw" "$root/tests/guest/gpudraw.c"
"$l4h_cc" -O2 -static -Wall -o "$out/gpucheck" "$root/tests/guest/gpucheck.c"
"$root/tools/mkinitramfs.sh" "$out/gpuvm.cpio.gz" "$root/tests/guest/init-gpuvm" "$out/gpudraw" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/gputest.cpio.gz" "$root/tests/guest/init-gputest" \
    "$l4h_ctl" "$out/gpucheck" "$out/gpuvm.cpio.gz" >/dev/null
L4H_KMODS=1 L4H_DOM0_MEM_MB=512 "$root/tools/run-dom0.sh" "$out/gputest.cpio.gz" \
    "console=hvc0 L4H_TEST_SLOW=$l4h_test_slow" "${L4H_TEST_TIMEOUT:-$((300 * l4h_test_slow))}" \
    | grep -aE "GPUTEST|GPUVM|GPUCHECK|vm [0-9]|panic|l4h-vmm" || true
grep -q "GPUTEST: PASS" "$root/build/qemu.log"
! grep -q "WARNING:\|BUG:" "$root/build/qemu.log"
