#!/usr/bin/env bash
# Boot Android as dom0: an x86_64 Cuttlefish build of Android 17
# (aosp_cf_x86_64_only_phone-userdebug, from ci.android.com), its images
# unpacked into $ANDROID_IMG (default build/cf17/img), made into an
# initramfs and a disk by tools/mkandroid.sh.  The boot passes once
# Android reports it complete (sys.boot_completed).  Android's errors are
# on the console with the kernel's messages (logcat on hvc1).
# Usage: run-android.sh [vcpus]
# ANDROID_TIMEOUT is in seconds; DATA=0 starts from a new disk.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
img=${ANDROID_IMG:-$root/build/cf17/img}
[ -f "$img/super.img" ] || {
    echo "no $img/super.img: unpack aosp_cf_x86_64_only_phone-img-<build>.zip there" >&2
    exit 1
}
out=$root/build/android
"$root/tools/build-linux.sh" vmlinux modules >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
rm -rf "$out/modules"
"$root/tools/build-linux.sh" modules_install INSTALL_MOD_PATH="$out/modules" INSTALL_MOD_STRIP=1 >/dev/null
release=$(cat "$root/build/linux-l4h/include/config/kernel.release")
"$root/tools/mkandroid.sh" "$img" "$out/modules/lib/modules/$release" "$out"
objcopy --strip-debug "$root/build/linux-l4h/vmlinux" "$root/build/linux-l4h/vmlinux.stripped"
export L4H_GUEST_KERNEL="$root/build/linux-l4h/vmlinux.stripped" L4H_DOM0_INITRD="$out/initrd.img"
L4H_DOM0_MEM_MB=${L4H_DOM0_MEM_MB:-3072} L4H_DOM0_VCPUS=${1:-4} \
    L4H_DOM0_CMDLINE="console=hvc0 lsm=selinux psi=1 bootconfig printk.devkmsg=on loop.max_part=7" \
    "$root/tools/build-host.sh"
log=$root/build/qemu-android.log
L4H_MEM=${L4H_MEM:-5G} "$root/tools/run-qemu.sh" "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" \
    -drive file="$out/disk.img",if=none,id=d0,format=raw,cache=none \
    -device virtio-blk-pci,drive=d0,disable-legacy=on \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0,disable-legacy=on \
    </dev/null >"$log" 2>&1 &
qemu=$!
# Android reboots when it cannot go on, and l4h-root boots dom0 again:
# the first boot is the one to look at.
end=$((SECONDS + ${ANDROID_TIMEOUT:-900}))
while kill -0 "$qemu" 2>/dev/null; do
    grep -aq "processing action (sys.boot_completed=1\|l4h-root: all guests stopped\|Kernel panic\|reboot: Restarting" "$log" && { sleep 1; kill "$qemu"; break; }
    [ "$SECONDS" -lt "$end" ] || { kill "$qemu"; break; }
    sleep 1
done
wait "$qemu" 2>/dev/null || true
grep -a "init: \(starting service\|Service .* exited\|.*boot_completed\)\|Kernel panic\|reboot: \|l4h-root: guest" "$log" | tail -40 || true
grep -aq "processing action (sys.boot_completed=1" "$log"
