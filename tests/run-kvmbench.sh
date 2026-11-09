#!/usr/bin/env bash
# KVM performance in a guest against Linux KVM in the same place (DESIGN.md
# §5.10): tests/guest/kvmbench.c's exit, fault and compute timings, and the
# time to boot the host's kernel under QEMU, Firecracker and
# cloud-hypervisor (tests/kvm-vmms.sh), with L1 either l4h's dom0 or the
# host's Linux kernel in QEMU, both with two vCPUs, on nested KVM.
# Usage: run-kvmbench.sh l4h|linux
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
mode=${1:?usage: run-kvmbench.sh l4h|linux}
out=$root/build/guest
mkdir -p "$out"
source "$root/tests/kvm-vmms.sh"
gcc -O2 -static -o "$out/kvmbench" "$root/tests/guest/kvmbench.c"
"$root/tools/mkinitramfs.sh" "$out/kvmbench.cpio.gz" "$root/tests/guest/init-kvmbench" \
    "$out/kvmbench" "$root/tests/guest/run-nested" >/dev/null
kvm_vmms_append "$out/kvmbench.cpio.gz" qemu firecracker cloud-hypervisor
log=$root/build/kvmbench-$mode.log
case $mode in
l4h)
    L4H_QEMU_CPU=${L4H_QEMU_CPU:-host,+invtsc} L4H_DOM0_MEM_MB=1536 L4H_DOM0_VCPUS=2 \
        "$root/tools/run-dom0.sh" "$out/kvmbench.cpio.gz" "console=hvc0 ${KVMBENCH_CMDLINE:-}" "${KVMBENCH_TIMEOUT:-600}" >/dev/null
    cp "$root/build/qemu.log" "$log" ;;
linux)
    kernel=${KVMTEST_KERNEL:-/boot/vmlinuz-$(uname -r)}
    mods=$(mktemp -d)
    trap 'rm -rf "$mods"' EXIT
    mkdir -p "$mods/lib/kvm"
    # kvm-amd needs ccp (SEV's firmware interface).
    vendor=arch/x86/kvm/kvm-intel
    grep -qw svm /proc/cpuinfo && vendor="drivers/crypto/ccp/ccp arch/x86/kvm/kvm-amd"
    for m in virt/lib/irqbypass arch/x86/kvm/kvm $vendor; do
        xz -dc "/lib/modules/$(uname -r)/kernel/$m.ko.xz" >"$mods/lib/kvm/$(basename "$m").ko"
    done
    (cd "$mods" && find . | cpio -o -H newc --quiet | gzip -1) >>"$out/kvmbench.cpio.gz"
    timeout "${KVMBENCH_TIMEOUT:-600}" qemu-system-x86_64 -accel kvm -cpu host,+invtsc \
        -smp 2 -m 1536M -display none -vga none -nic none -no-reboot -monitor none \
        -serial "file:$log" -kernel "$kernel" -initrd "$out/kvmbench.cpio.gz" \
        -append "console=ttyS0 quiet panic=-1" </dev/null || true ;;
*) echo "usage: run-kvmbench.sh l4h|linux" >&2; exit 2 ;;
esac
tr -d '\r' <"$log" | grep -a 'KVMBENCH' | grep -v 'KVMBENCH: done'
grep -aq "KVMBENCH: finished" "$log"
