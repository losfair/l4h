#!/usr/bin/env bash
# Boot a disk image from tools/mkimage.sh with SeaBIOS, like a BIOS-only
# cloud VM (DigitalOcean): i440fx, the boot disk virtio-blk and the NIC
# virtio-net, both transitional (legacy and modern) devices.
# Usage: run-bios.sh <disk.raw> [extra qemu args...]
set -euo pipefail
disk=$1; shift
# l4h reports its free memory to QEMU, which then drops it
# (L4H_BALLOON=0 leaves the device out).
balloon=()
[ "${L4H_BALLOON:-1}" = 1 ] && balloon=(-device virtio-balloon-pci,free-page-reporting=on,disable-legacy=on)
exec qemu-system-x86_64 \
    -enable-kvm -cpu host,-vmx,+invtsc \
    -smp "${L4H_SMP:-4}" -m "${L4H_MEM:-4G}" \
    -machine pc \
    -nographic -serial mon:stdio -no-reboot \
    -drive file="$disk",format=raw,if=none,id=boot -device virtio-blk-pci,drive=boot \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 "${balloon[@]}" "$@"
