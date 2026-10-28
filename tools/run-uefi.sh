#!/usr/bin/env bash
# Boot a disk image from tools/mkimage.sh with OVMF, like a GCE VM: the
# boot disk is NVMe, the NIC virtio-net.
# Usage: run-uefi.sh <disk.raw> [extra qemu args...]
set -euo pipefail
disk=$1; shift
# l4h reports its free memory to QEMU, which then drops it
# (L4H_BALLOON=0 leaves the device out).
balloon=()
[ "${L4H_BALLOON:-1}" = 1 ] && balloon=(-device virtio-balloon-pci,free-page-reporting=on,disable-legacy=on)
exec qemu-system-x86_64 \
    -enable-kvm -cpu "${L4H_QEMU_CPU:-host,-vmx,+invtsc}" \
    -smp "${L4H_SMP:-4}" -m "${L4H_MEM:-4G}" \
    -machine q35 -bios /usr/share/ovmf/OVMF.fd \
    -nographic -serial mon:stdio -no-reboot \
    -drive file="$disk",format=raw,if=none,id=boot -device nvme,drive=boot,serial=boot \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0,disable-legacy=on "${balloon[@]}" "$@"
