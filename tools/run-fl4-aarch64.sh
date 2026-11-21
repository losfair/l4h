#!/usr/bin/env bash
# Boot an FL4 AArch64 UEFI image (tools/mkfl4-efi-aarch64.sh) on QEMU's virt
# machine under TCG, from a FAT ESP directory.  By default the firmware
# enters FL4 at EL2 with GICv3 (FL4 is then a VHE hypervisor host):
#   L4H_QEMU_GIC_VERSION     2 or 3 (default 3)
#   L4H_QEMU_VIRTUALIZATION  on (EL2) or off (EL1 only; default on)
#   L4H_QEMU_CPU             default max (cortex-a57 has no VHE)
#   L4H_SMP, L4H_MEM_MB      vCPUs (2) and RAM in MiB (2048)
#   L4H_QEMU_EFI             the AArch64 UEFI firmware (QEMU_EFI.fd)
# l4h-root finds PCI at QEMU virt's low ECAM and MMIO windows
# (highmem-ecam=off, highmem-mmio=off), as with tools/run-image-aarch64.sh.
# The ESP is a virtio-mmio disk: the firmware boots from it, and the host
# does not take it for one of its PCI disks.
# Usage: run-fl4-aarch64.sh <l4h-fl4-aarch64.efi> [extra qemu args...]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
efi=$1; shift
efi_fw=
for f in "${L4H_QEMU_EFI:-}" /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd \
    "$root/build/QEMU_EFI.fd"; do
    if [ -n "$f" ] && [ -f "$f" ]; then
        efi_fw=$f
        break
    fi
done
if [ -z "$efi_fw" ]; then
    echo "no AArch64 UEFI firmware: install qemu-efi-aarch64 or set L4H_QEMU_EFI" >&2
    exit 1
fi
esp=$(mktemp -d)
trap 'rm -rf "$esp"' EXIT
mkdir -p "$esp/EFI/BOOT"
cp "$efi" "$esp/EFI/BOOT/BOOTAA64.EFI"
qemu-system-aarch64 -accel tcg \
    -machine "virt,acpi=off,gic-version=${L4H_QEMU_GIC_VERSION:-3},virtualization=${L4H_QEMU_VIRTUALIZATION:-on},highmem-ecam=off,highmem-mmio=off" \
    -cpu "${L4H_QEMU_CPU:-max}" -smp "${L4H_SMP:-2}" -m "${L4H_MEM_MB:-2048}" \
    -nographic -serial mon:stdio -no-reboot \
    -bios "$efi_fw" -drive "if=none,id=esp,format=raw,file=fat:rw:$esp" -device virtio-blk-device,drive=esp "$@"
