#!/usr/bin/env bash
# HVM guests on AArch64 (DESIGN.md §5.11): dom0, on FL4 at EL2 under QEMU's
# TCG, runs an unmodified arm64 Linux (tools/build-linux-hvm.sh) with two
# vCPUs, a virtio-blk disk (written, then read back by a second guest), a
# virtio-net NIC (pinging a PV guest on its switch), its PL011 console
# (output and input), the power button (PL061, gpio-keys, then PSCI's
# SYSTEM_OFF), destroy while running, and all its memory back after each.
#   L4H_QEMU_GIC_VERSION     3 (default) or 2
#   L4H_QEMU_VIRTUALIZATION  on (default), or off: FL4 at EL1, which has no
#                            VCPUs, so HVM guests are refused (-ENODEV)
#   L4H_QEMU_CPU, L4H_SMP, L4H_MEM_MB, as for tools/run-fl4-aarch64.sh
# Needs tools/ci-setup.sh aarch64; L4H_FL4_SOURCE as for build-fl4-aarch64.sh.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_ARCH=aarch64
source "$root/tools/guest-env.sh"
gic=${L4H_QEMU_GIC_VERSION:-3}
virt=${L4H_QEMU_VIRTUALIZATION:-on}
export L4H_QEMU_GIC_VERSION=$gic L4H_QEMU_VIRTUALIZATION=$virt
out=$root/build/guest-hvm-arm64
mkdir -p "$out"
"$root/tools/build-fl4-aarch64.sh" >"$out/fl4-build.log" 2>&1 || { tail -20 "$out/fl4-build.log"; exit 1; }
SEL4_PREFIX=$root/build/sel4-fl4-aarch64 "$root/tools/build-host-aarch64.sh" >"$out/host-build.log" 2>&1 \
    || { tail -20 "$out/host-build.log"; exit 1; }
# vmmgr's HVM monitor must be built in (an empty one is no HVM support,
# which the EL1 run would pass with).
[ -s "$root/host/target/aarch64-sel4/$l4h_profile/stripped/l4h-hvm.elf" ] \
    || { echo "HVMTEST: FAIL: no l4h-hvm built into vmmgr"; exit 1; }
"$root/tools/build-linux.sh" vmlinux >"$out/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$out/linux-build.log"; exit 1; }
"$root/tools/build-l4hctl.sh"
image=$("$root/tools/build-linux-hvm.sh" 2>"$out/linux-hvm-build.log") \
    || { tail -20 "$out/linux-hvm-build.log"; exit 1; }
cp "$image" "$out/Image"
"$root/tools/mkinitramfs.sh" "$out/hvmvm.cpio.gz" "$root/tests/guest/init-hvmvm" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/netvm.cpio.gz" "$root/tests/guest/init-netvm" \
    "$root/tests/guest/udhcpc.script" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/hvmtest.cpio.gz" "$root/tests/guest/init-hvmtest" \
    "$l4h_ctl" "$out/Image" "$out/hvmvm.cpio.gz" "$out/netvm.cpio.gz" >/dev/null
rm -f "$out/hvm.img"
truncate -s 64M "$out/hvm.img"
aarch64-linux-gnu-objcopy --strip-debug "$l4h_linux_out/vmlinux" "$out/vmlinux"
# TCG runs a guest in a guest: everything takes many times as long.
slow=${HVMTEST_SLOW:-8}
printf 'dom0_mem_mb=%s\ndom0_vcpus=2\ndom0_disks=0\ndom0_cmdline=console=hvc0 L4H_TEST_SLOW=%s\n' \
    "${L4H_DOM0_MEM_MB:-640}" "$slow" >"$out/l4h.conf"
L4H_GUEST_KERNEL=$out/vmlinux L4H_DOM0_INITRD=$out/hvmtest.cpio.gz L4H_CONFIG=$out/l4h.conf \
    "$root/tools/mkfl4-efi-aarch64.sh" "$out/hvmtest.efi" \
    "$root/host/target/aarch64-sel4-roottask/$l4h_profile/l4h-root.elf" \
    "$root/build/sel4-fl4-aarch64/bin/kernel.elf"
log=$out/qemu-gicv$gic-virt$virt.log
export L4H_SMP=${L4H_SMP:-4} L4H_MEM_MB=${L4H_MEM_MB:-2048}
# Empty before the watch below reads it: a last run's end is not this one's.
: >"$log"
timeout --foreground "${HVMTEST_TIMEOUT:-3000}" "$root/tools/run-fl4-aarch64.sh" "$out/hvmtest.efi" \
    -drive "file=$out/hvm.img,if=none,id=d0,format=raw" -device virtio-blk-pci,drive=d0,disable-legacy=on \
    </dev/null >"$log" 2>&1 &
qemu=$!
kill_tree() {
    local c
    for c in $(pgrep -P "$1"); do
        kill_tree "$c"
    done
    kill "$1" 2>/dev/null || true
}
# The machine never powers off by itself: stop it once dom0 has stopped,
# or a test said how it ended.
while kill -0 "$qemu" 2>/dev/null; do
    if grep -aqE "l4h-vmmgr: all guests stopped|HVMTEST: (PASS|FAIL)" "$log"; then
        sleep 2
        kill_tree "$qemu"
        break
    fi
    sleep 2
done
wait "$qemu" 2>/dev/null || true
sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$log" | grep -aE "HVMTEST|HVMVM|NETVM|l4h-hvm|panic|FL4: EL|l4h-vmmgr: guest" || true
if [ "$virt" = off ]; then
    # FL4 at EL1 has no VCPUs: refused with -ENODEV ("unsupported device"),
    # and nothing left behind.
    grep -aq "HVMTEST: no hardware virtualization" "$log" \
        || { echo "HVMTEST: FAIL: an HVM guest was not refused at EL1"; exit 1; }
    echo "HVMTEST: refused at EL1 (-ENODEV)"
    exit 0
fi
grep -aq "HVMTEST: PASS" "$log"
