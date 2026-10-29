#!/usr/bin/env bash
# UEFI host kexec with NVMe and virtio-net, usually behind PCIe root ports.
# A second build has a different host_version; the new host checks it, DHCP and ESP
# data from the old one, including preserved bridge routing.
# KEXEC_UEFI_BUILT=1 reuses the kernel, Linux and module tree.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/kexec-uefitest
mkdir -p "$out"
if [ "${KEXEC_UEFI_BUILT:-0}" != 1 ]; then
    L4H_KERNEL_VARIANT=kexec "$root/tools/build-kernel.sh" >"$out/kernel-build.log" 2>&1
    "$root/tools/build-linux.sh" vmlinux >"$out/linux-build.log" 2>&1
    "$root/tools/build-kmods.sh" >/dev/null
fi
export SEL4_PREFIX="$root/build/sel4-kexec"
L4H_VERSION=kexec-test-1 "$root/tools/build-host.sh" >"$out/host-build-1.log" 2>&1
"$root/tools/mkefi.sh" "$out/cold.efi" \
    "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" \
    "$root/build/sel4-kexec/bin/kernel.elf" "$root/build/kernel-kexec" >"$out/efi-build-1.log"
L4H_VERSION=kexec-test-2 "$root/tools/build-host.sh" >"$out/host-build-2.log" 2>&1
"$root/tools/mkefi.sh" "$out/next.efi" \
    "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" \
    "$root/build/sel4-kexec/bin/kernel.elf" "$root/build/kernel-kexec" >"$out/efi-build-2.log"
(cd "$root/tools/l4hctl" && cargo +stable build -q --release)
"$root/tools/mkinitramfs.sh" "$out/initrd" "$root/tests/guest/init-kexec-uefi" \
    "$root/tools/l4hctl/target/release/l4hctl" "$root/tests/guest/udhcpc.script" >/dev/null
printf 'dom0_disks=1\ndom0_cmdline="console=hvc0 kexec_first"\n' >"$out/first.conf"
printf 'dom0_disks=1\ndom0_cmdline="console=hvc0 kexec_done"\n' >"$out/next.conf"
L4H_ESP_FILES="/l4h/next.efi=$out/next.efi /l4h/next.conf=$out/next.conf" \
    "$root/tools/mkimage.sh" -e "$out/cold.efi" -i "$out/initrd" -c "$out/first.conf" "$out/l4h.raw" >"$out/image-build.log"
[ "${KEXEC_UEFI_BUILD_ONLY:-0}" != 1 ] || exit 0
# Two controllers exercise their independent flush pages during both boots
# and the sequential asynchronous flushes during handoff.
truncate -s 1M "$out/extra.img"
iommu=()
case "${KEXEC_UEFI_IOMMU:-}" in
    intel) iommu=(-machine q35,kernel-irqchip=split -device intel-iommu,intremap=on,caching-mode=on
        -global virtio-blk-pci.iommu_platform=on -global virtio-scsi-pci.iommu_platform=on -global virtio-net-pci.iommu_platform=on) ;;
    amd) iommu=(-machine q35,kernel-irqchip=split -device amd-iommu,intremap=on
        -global virtio-blk-pci.iommu_platform=on -global virtio-scsi-pci.iommu_platform=on -global virtio-net-pci.iommu_platform=on) ;;
    '') ;;
    *) echo "KEXEC_UEFI_IOMMU must be intel or amd" >&2; exit 2 ;;
esac
if [ ${#iommu[@]} -ne 0 ]; then
    export L4H_BALLOON=0
fi
log=$out/qemu.log
# AMD's test keeps its established bus-0 topology; other runs cover bridges.
bridge=${KEXEC_UEFI_BRIDGE:-}
if [ -z "$bridge" ]; then
    case "${KEXEC_UEFI_IOMMU:-}" in
        amd) bridge=0 ;;
        *) bridge=1 ;;
    esac
fi
export L4H_UEFI_BRIDGE="$bridge"
extra_topology=()
extra_bus=
if [ "$bridge" = 1 ]; then
    # Keep the blank controller after the boot disk in enumeration order.
    extra_topology=(-device pcie-root-port,id=extra-port,chassis=3,slot=3)
    extra_bus=,bus=extra-port
fi
timeout "${KEXEC_UEFI_TIMEOUT:-240}" "$root/tools/run-uefi.sh" "$out/l4h.raw" \
    "${extra_topology[@]}" \
    -drive file="$out/extra.img",format=raw,if=none,id=extra \
    -device "nvme,drive=extra,serial=extra$extra_bus" \
    "${iommu[@]}" </dev/null >"$log" 2>&1 &
qemu=$!
while kill -0 "$qemu" 2>/dev/null; do
    grep -aq "KEXECUEFI: done\|KEXECUEFI: FAIL" "$log" && { sleep 1; kill "$qemu" 2>/dev/null || true; break; }
    sleep 1
done
wait "$qemu" 2>/dev/null || true
grep -aE "KEXECUEFI|kexec|panic|Boot failed" "$log" || true
grep -aq "KEXECUEFI: done" "$log"
! grep -aq "KEXECUEFI: FAIL\|panic" "$log"
[ "$(grep -ac 'KEXECUEFI: network ok' "$log")" -ge 2 ]
