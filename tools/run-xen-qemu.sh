#!/usr/bin/env bash
# Boot Xen and the dom0 from tools/build-xen-dom0.sh in QEMU/KVM: a stand-in
# for a large machine partitioned into l4h HVM guests (DESIGN.md §11.2).
# Unlike tools/run-qemu.sh, VMX is exposed, for Xen.  The machine has an
# Intel IOMMU, which Xen needs to pass devices through; devices given to
# guests must translate through it (iommu_platform=on for virtio).
# Usage: run-xen-qemu.sh [extra qemu args...]
# L4H_XEN_ARGS and L4H_XEN_DOM0_ARGS add to Xen's and dom0's command lines
# (xen-pciback.hide=(BB:DD.F)... in dom0's hides the devices to pass through).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
x=$root/build/xen
exec qemu-system-x86_64 \
    -enable-kvm -cpu host,+invtsc \
    -smp "${L4H_SMP:-4}" -m "${L4H_MEM:-6G}" \
    -machine q35,kernel-irqchip=split -device intel-iommu,intremap=on,caching-mode=on \
    -nographic -serial mon:stdio -no-reboot \
    -kernel "$x/xen" \
    -append "console=com1 com1=115200 dom0_mem=1024M,max:1024M loglvl=all guest_loglvl=all ${L4H_XEN_ARGS:-}" \
    -initrd "$x/vmlinuz console=hvc0 ${L4H_XEN_DOM0_ARGS:-},$x/dom0.cpio.gz" "$@"
