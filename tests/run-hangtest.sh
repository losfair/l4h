#!/usr/bin/env bash
# A driver that stops answering, as a compromised one might (DESIGN.md
# §10, "Root never waits on a driver"): the serial monitor has disk 1's
# blkd hang, and netd's, in a host built with L4H_TEST_INJECT=1.  dom0
# checks that a request to that blkd stays pending and can be given up,
# and that root, vmmgr and the other disk go on; then root still serves
# the monitor once netd hangs too.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$l4h_linux_out/vmlinux.stripped"
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/vm.cpio.gz" "$root/tests/guest/init-vm" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/hangtest.cpio.gz" "$root/tests/guest/init-hangtest" \
    "$l4h_ctl" "$out/vm.cpio.gz" >/dev/null
for i in 0 1; do
    rm -f "$out/hang$i.img"
    mkfs.ext4 -q -F "$out/hang$i.img" 32M
done
export L4H_GUEST_KERNEL="$l4h_linux_out/vmlinux.stripped" L4H_DOM0_INITRD="$out/hangtest.cpio.gz"
L4H_TEST_INJECT=1 L4H_DOM0_DISKS=0 L4H_DOM0_MEM_MB=512 \
    L4H_DOM0_CMDLINE="console=hvc0 L4H_TEST_SLOW=$l4h_test_slow" "$l4h_host_build"
log=$root/build/qemu-hang.log
fifo=$(mktemp -u)
mkfifo "$fifo"
qemu=
trap 'rm -f "$fifo"; [ -z "$qemu" ] || kill "$qemu" 2>/dev/null || true' EXIT
"$l4h_qemu" "$root/host/target/$l4h_target/$l4h_profile/l4h-root.elf" \
    -drive file="$out/hang0.img",if=none,id=d0,format=raw -device virtio-blk-pci,drive=d0,disable-legacy=on \
    -drive file="$out/hang1.img",if=none,id=d1,format=raw -device virtio-blk-pci,drive=d1,disable-legacy=on \
    <"$fifo" >"$log" 2>&1 &
qemu=$!
exec 3>"$fifo"
wait_for() { # pattern timeout
    local end=$((SECONDS + $2))
    until grep -aq "$1" "$log"; do
        ! grep -aq "HANGTEST: FAIL" "$log" || { grep -a "HANGTEST" "$log"; exit 1; }
        [ "$SECONDS" -lt "$end" ] || { echo "hang: timeout waiting for: $1"; tail -5 "$log"; exit 1; }
        sleep 0.5
    done
}
wait_for "HANGTEST: ready" $((180 * l4h_test_slow))
printf 'inject blkd-hang 1\r' >&3
wait_for "HANGTEST: PASS" $((300 * l4h_test_slow))
grep -a "HANGTEST" "$log"
# netd too: root goes on serving the monitor.
printf 'inject netd-hang\r' >&3
wait_for "component 0x200 hangs" 30
printf 'help\r' >&3
wait_for "monitor: help" 30
echo "hang: PASS"
