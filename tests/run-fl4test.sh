#!/usr/bin/env bash
# Boot the complete l4h stack on the pinned FL4 revision, or on a frozen
# worktree selected by L4H_FL4_SOURCE.
# Exercise SMP, device memory, networking, free-page reporting and KVM.
# KVM runs when the host exposes VMX/SVM and KVM nesting is enabled, and
# FL4 found the speculation mitigations it requires for VM exits (IBPB
# and the like; a nested host may hide them, and FL4 then leaves
# virtualization off).  L4H_FL4_KVM=1 requires it; =0 skips it; the
# default is auto-detection.
# L4H_RELEASE=1 also runs the ABI/SDK test: FL4's debug profile
# intentionally has no l4h debug-syscall MCP filter.
set -euo pipefail
# e2fsprogs installs mkfs.ext4 and debugfs outside an ordinary user's PATH.
export PATH="$PATH:/usr/sbin:/sbin"
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_ARCH=x86_64
export L4H_KERNEL_VARIANT=fl4 SEL4_PREFIX=$root/build/sel4-fl4
case "${L4H_FL4_KVM:-auto}" in
    auto)
        nested=absent
        if grep -qw svm /proc/cpuinfo; then
            nested=$(cat /sys/module/kvm_amd/parameters/nested 2>/dev/null || echo absent)
        elif grep -qw vmx /proc/cpuinfo; then
            nested=$(cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || echo absent)
        fi
        kvm=0
        if [[ $nested == [Y1] ]]; then kvm=1; fi
        ;;
    0|1) kvm=$L4H_FL4_KVM ;;
    *) echo 'L4H_FL4_KVM must be auto, 0 or 1' >&2; exit 2 ;;
esac
"$root/tools/build-fl4.sh"
if ! grep -q '^#define CONFIG_VTX  *1$' "$SEL4_PREFIX/libsel4/include/kernel/gen_config.h"; then
    echo 'FL4TEST: FAIL (kernel ABI has no VT-x/AMD-V support)' >&2
    exit 1
fi
if [ "${L4H_RELEASE:-0}" != 1 ]; then
    L4H_QEMU_CPU=host,-vmx,-svm,+invtsc "$root/tests/run-vtxtest.sh" off
fi
for vcpus in 1 4; do
    L4H_QEMU_CPU=host,-vmx,-svm,+invtsc "$root/tests/run-selftest.sh" "$vcpus"
    grep -aq 'FL4: seL4 17.0 (MCS) API kernel' "$root/build/qemu.log"
    grep -aq 'FL4: virtualization unavailable' "$root/build/qemu.log"
    grep -aq 'no VT-x or AMD-V on this host' "$root/build/qemu.log"
done
"$root/tests/run-blktest.sh" 4
"$root/tests/run-nettest.sh"
"$root/tests/run-balloontest.sh"
if [ "${L4H_RELEASE:-0}" = 1 ]; then
    "$root/tests/run-abitest.sh"
fi
# The boots above logged what FL4 found: without the mitigations it
# requires, no VM-exit path is enabled, whatever the CPU flags say.
if [ "${L4H_FL4_KVM:-auto}" = auto ] && grep -aq 'FL4: speculation mitigations: incomplete:' "$root/build/qemu.log"; then
    kvm=0
fi
if [ "$kvm" = 1 ]; then
    if [ "${L4H_RELEASE:-0}" != 1 ]; then
        "$root/tests/run-vtxtest.sh" on
    fi
    for vcpus in 1 4; do
        "$root/tests/run-kvmtest.sh" "$vcpus"
        grep -aq 'FL4: virtualization \(VT-x\|AMD-V\)' "$root/build/qemu.log"
        cp "$root/build/qemu.log" "$root/build/fl4-kvm-$vcpus.log"
    done
else
    echo 'FL4TEST: KVM SKIP (nesting or speculation mitigations unavailable, or L4H_FL4_KVM=0)'
fi
echo 'FL4TEST: PASS'
