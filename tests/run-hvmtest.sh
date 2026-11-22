#!/usr/bin/env bash
# HVM guests (DESIGN.md §5.11): dom0 runs an unmodified x86-64 Linux
# (tools/build-linux-hvm.sh) in VT-x or AMD-V guest mode, with 2 vCPUs, a
# virtio-blk disk (written, then read back by a second guest), a virtio-net
# NIC (pinging a PV guest on its switch), its 16550 console (output and
# input), the ACPI power button (l4hctl shutdown), destroy while running,
# and all its memory back after each.
# It needs KVM that nests (VT-x or AMD-V in /proc/cpuinfo, /dev/kvm
# usable): QEMU gives the host the CPU's own.  QEMU's TCG cannot stand in:
# its SVM has no next-RIP saving, which seL4 requires.  Without VT-x or
# AMD-V the host refuses HVM guests (-ENODEV), which is checked, and the
# test is skipped.  Where the build host has them (VT-x or AMD-V in
# /proc/cpuinfo, /dev/kvm usable), a skip fails unless HVMTEST_ALLOW_SKIP=1
# (a run that hides them on purpose); elsewhere HVMTEST_REQUIRE_HW=1 makes
# it fail.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
[ "${L4H_ARCH:-x86_64}" = x86_64 ] || { echo "HVMTEST: x86_64 only"; exit 0; }
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$root/tools/build-l4hctl.sh"
# vmmgr's HVM monitor must be built in (an empty one is no HVM support,
# which would pass as a skip).
hvm_elf=$root/host/target/x86_64-sel4/$l4h_profile/stripped/l4h-hvm.elf
bzimage=$("$root/tools/build-linux-hvm.sh" 2>"$root/build/linux-hvm-build.log") \
    || { tail -20 "$root/build/linux-hvm-build.log"; exit 1; }
cp "$bzimage" "$out/bzImage"
"$root/tools/mkinitramfs.sh" "$out/hvmvm.cpio.gz" "$root/tests/guest/init-hvmvm" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/netvm.cpio.gz" "$root/tests/guest/init-netvm" \
    "$root/tests/guest/udhcpc.script" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/hvmtest.cpio.gz" "$root/tests/guest/init-hvmtest" \
    "$l4h_ctl" "$out/bzImage" "$out/hvmvm.cpio.gz" "$out/netvm.cpio.gz" >/dev/null
rm -f "$out/hvm.img"
truncate -s 64M "$out/hvm.img"
slow=$l4h_test_slow
require_hw=${HVMTEST_REQUIRE_HW:-0}
if grep -qwE 'vmx|svm' /proc/cpuinfo && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    # The host CPU with its VT-x or AMD-V, unless the caller chose one.
    export L4H_QEMU_CPU=${L4H_QEMU_CPU:-host,+invtsc}
    [ "${HVMTEST_ALLOW_SKIP:-0}" = 1 ] || require_hw=1
fi
echo "HVMTEST: -cpu ${L4H_QEMU_CPU:-(run-qemu.sh default)}"
L4H_DOM0_DISKS=0 L4H_DOM0_MEM_MB=512 L4H_SMP=${L4H_SMP:-4} \
L4H_TEST_FAIL_PATTERN='HVMTEST: FAIL:' \
L4H_QEMU_ARGS="-drive file=$out/hvm.img,if=none,id=d0,format=raw -device virtio-blk-pci,drive=d0,disable-legacy=on" \
    "$root/tools/run-dom0.sh" "$out/hvmtest.cpio.gz" "console=hvc0 L4H_TEST_SLOW=$slow" ${HVMTEST_TIMEOUT:-$((900 * slow))} \
    | grep -aE "HVMTEST|HVMVM|NETVM|l4hctl|vm [0-9]|l4h-hvm|panic|l4h-vmmgr: guest|svm|vmx" || true
[ -s "$hvm_elf" ] || { echo "HVMTEST: FAIL: no l4h-hvm built into vmmgr ($hvm_elf)"; exit 1; }
if grep -aq "HVMTEST: no VT-x or AMD-V" "$root/build/qemu.log"; then
    if [ "$require_hw" = 1 ]; then
        echo "HVMTEST: FAIL: VT-x or AMD-V is there, but HVM guests were refused"
        exit 1
    fi
    echo "HVMTEST: SKIP (the host has no VT-x or AMD-V)"
    exit 0
fi
grep -aq "HVMTEST: PASS" "$root/build/qemu.log"
