#!/usr/bin/env bash
# Host-side VT-d firmware parser and hardware format checks.
# --qemu also runs the existing DMA, lifecycle, NIC and serial tests.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/vtdtest
mkdir -p "$out"
rustc +stable --edition=2024 --test "$root/tests/vtd.rs" -o "$out/unit-tests"
"$out/unit-tests"
if [ "${1:-}" = --qemu ]; then
    [ "${L4H_ARCH:-x86_64}" = x86_64 ] || { echo "VT-d QEMU tests require x86_64" >&2; exit 1; }
    export L4H_QEMU_IOMMU=intel
    "$root/tests/run-blktest.sh"
    cp "$root/build/qemu.log" "$out/virtio-blk.log"
    BLKTEST_DEV=nvme "$root/tests/run-blktest.sh"
    cp "$root/build/qemu.log" "$out/nvme.log"
    "$root/tests/run-ctltest.sh"
    cp "$root/build/qemu.log" "$out/ctl.log"
    "$root/tests/run-nettest.sh"
    cp "$root/build/qemu.log" "$out/net.log"
    python3 "$root/tests/vtd-net-qemu.py"
    "$root/tests/run-monitor.sh"
    cp "$root/build/qemu-monitor.log" "$out/monitor.log"
    python3 "$root/tests/vtd-qemu.py"
    python3 "$root/tests/vtd-qemu.py" --bridge pci
    python3 "$root/tests/vtd-qemu.py" --bridge pcie-pci
    for setting in iommu_intremap=0 iommu=0; do
        printf '%s\n' "$setting" > "$out/disabled.conf"
        L4H_CONFIG="$out/disabled.conf" "$root/tests/run-blktest.sh"
        cp "$root/build/qemu.log" "$out/$setting.log"
        if [ "$setting" = iommu_intremap=0 ]; then
            grep -aq 'VT-d at .*enabled, .*interrupts not remapped' "$root/build/qemu.log"
        else
            grep -aq 'iommu=0: DMA is not confined' "$root/build/qemu.log"
        fi
    done
fi
