#!/usr/bin/env bash
# Boot Android in a VM: an x86_64 Cuttlefish build of Android 17
# (aosp_cf_x86_64_only_phone-userdebug, from ci.android.com), its images
# unpacked into $ANDROID_IMG (default build/cf17/img), made into an
# initramfs and a disk by tools/mkandroid.sh.  dom0 (tests/guest/init-android)
# creates the VM with that disk and a virtio-gpu display, waits for Android
# to complete its boot (sys.boot_completed), and takes a screenshot, which
# must show something: it is build/android/screen.png.  Android's errors
# are on the VM's console ([vm1] lines).
# Usage: run-android.sh [vcpus]
# ANDROID_MEM_MB (3072), ANDROID_GPU (720x1200); DATA=0 starts from a new
# disk.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
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
release=$(cat "$l4h_linux_out/include/config/kernel.release")
"$root/tools/mkandroid.sh" "$img" "$out/modules/lib/modules/$release" "$out"
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-android" \
    "$l4h_ctl" "$out/initrd.img" >/dev/null
# Host disk 0, dom0's, takes the screenshot; disk 1 is Android's.
rm -f "$out/screen.img" && truncate -s 16M "$out/screen.img"
gpu=${ANDROID_GPU:-720x1200}
L4H_DOM0_DISKS=1 L4H_DOM0_MEM_MB=256 L4H_MEM=${L4H_MEM:-6G} \
L4H_QEMU_ARGS="-drive file=$out/screen.img,if=none,id=d0,format=raw -device virtio-blk-pci,drive=d0,disable-legacy=on \
    -drive file=$out/disk.img,if=none,id=d1,format=raw,cache=none -device virtio-blk-pci,drive=d1,disable-legacy=on" \
    "$root/tools/run-dom0.sh" "$out/dom0.cpio.gz" \
    "console=hvc0 L4H_TEST_SLOW=$l4h_test_slow android_mem=${ANDROID_MEM_MB:-3072} android_vcpus=${1:-4} android_gpu=$gpu" \
    "${ANDROID_TIMEOUT:-$((1200 * l4h_test_slow))}" >/dev/null
cp "$root/build/qemu.log" "$root/build/qemu-android.log"
grep -a "ANDROIDVM\|\[vm1\] init: \(Service .* exited\|.*boot_completed\)\|Kernel panic\|l4h-root: guest" \
    "$root/build/qemu-android.log" | tail -30 || true
grep -aq "ANDROIDVM: PASS" "$root/build/qemu-android.log"
# The screenshot (PPM) as a PNG, which must not be blank.
python3 - "$out/screen.img" "$out/screen.png" <<'PY'
import re, struct, sys, zlib
d = open(sys.argv[1], 'rb').read()
m = re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s', d)
if not m:
    sys.exit('android: no screenshot')
w, h = int(m[1]), int(m[2])
px = d[m.end():m.end() + w * h * 3]
rows = b''.join(b'\0' + px[y * w * 3:(y + 1) * w * 3] for y in range(h))
chunk = lambda t, b: struct.pack('>I', len(b)) + t + b + struct.pack('>I', zlib.crc32(t + b))
open(sys.argv[2], 'wb').write(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
                              + chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b''))
lit = sum(1 for i in range(0, len(px), 3) if px[i] | px[i + 1] | px[i + 2])
print(f'android: screenshot {w}x{h}, {100 * lit // (w * h)}% lit: {sys.argv[2]}')
sys.exit(0 if lit > w * h // 100 else 'android: the screen is blank')
PY
