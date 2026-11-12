#!/usr/bin/env bash
# NIC drivers outside netd (DESIGN.md §9.8): two virtio-net NICs, each
# with its own nicd, in a host built with L4H_TEST_INJECT=1.  NIC 1's
# driver panics, then hangs; root restarts it each time while dom0's
# uplink on NIC 0 keeps working; NIC 1 is unbound and bound again, and
# NIC 0's driver restarted.  L4H_QEMU_IOMMU=intel|amd runs it with an
# IOMMU (DMA regions mapped and remapped across restarts).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/nictest.cpio.gz" "$root/tests/guest/init-nictest" \
    "$l4h_ctl" "$root/tests/guest/udhcpc.script" >/dev/null
L4H_TEST_INJECT=1 L4H_DOM0_MEM_MB=256 \
L4H_QEMU_ARGS="-netdev user,id=n0 -device virtio-net-pci,netdev=n0,disable-legacy=on -netdev user,id=n1 -device virtio-net-pci,netdev=n1,disable-legacy=on" \
    "$root/tools/run-dom0.sh" "$out/nictest.cpio.gz" "console=hvc0 L4H_TEST_SLOW=$l4h_test_slow" $((300 * l4h_test_slow)) \
    | grep -E "NICTEST|nicd|nic [0-9]|driver|panic" || true
grep -q "NICTEST: PASS" "$root/build/qemu.log"
# A virtio NIC's driver is never confined (DESIGN.md §9.8): its own
# feature choice could take the device past the IOMMU.
grep -q "driver virtio-net, trusted (not confined)" "$root/build/qemu.log"
