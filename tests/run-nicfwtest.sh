#!/usr/bin/env bash
# Firmware dom0 loads for NIC drivers (DESIGN.md §9.8), on QEMU's e1000e
# in a host built with L4H_TEST_INJECT=1, whose e1000e driver then names
# a test firmware (tests/guest/init-nicfwtest).  With
# L4H_QEMU_IOMMU=intel|amd the driver is confined: dom0 loads the blob,
# and the restarted driver must report exactly its bytes.  Without, root
# refuses the load and the driver runs without firmware.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/nicfwtest.cpio.gz" "$root/tests/guest/init-nicfwtest" \
    "$l4h_ctl" "$root/tests/guest/udhcpc.script" >/dev/null
L4H_TEST_INJECT=1 L4H_DOM0_MEM_MB=256 \
L4H_QEMU_ARGS="-netdev user,id=n0 -device e1000e,netdev=n0" \
    "$root/tools/run-dom0.sh" "$out/nicfwtest.cpio.gz" "console=hvc0 L4H_TEST_SLOW=$l4h_test_slow" $((180 * l4h_test_slow)) \
    | grep -aE "NICFWTEST|nicd|nic [0-9]|firmware|panic" || true
log=$root/build/qemu.log
grep -aq "NICFWTEST: PASS" "$log"
fw="test firmware l4h-test/e1000e.fw"
if [ -n "${L4H_QEMU_IOMMU:-}" ]; then
    # First without it, then with exactly what dom0 loaded.
    grep -aq "$fw: 0 bytes" "$log"
    grep -aq "$fw: 4096 bytes, byte sum 368640" "$log" || { echo "nicfw: the driver did not get the blob"; exit 1; }
    grep -aq "firmware l4h-test/e1000e.fw (loaded by dom0, 4096 bytes)" "$log"
else
    grep -aq "$fw: 0 bytes" "$log"
    if grep -aq "$fw: 4096 bytes" "$log"; then echo "nicfw: an unconfined driver got dom0's firmware"; exit 1; fi
fi
echo "nicfw: PASS"
