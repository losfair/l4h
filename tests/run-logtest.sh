#!/usr/bin/env bash
# Fault/panic/shutdown diagnostics through l4hctl, including quiet builds.
set -euo pipefail
# e2fsprogs installs mkfs.ext4 and debugfs outside an ordinary user's PATH.
export PATH="$PATH:/usr/sbin:/sbin"
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/logtest
mkdir -p "$out/mod"
cp "$root"/tests/guest/log-fault/* "$out/mod/"
"$root/tools/build-linux.sh" vmlinux >"$out/kernel-build.log" 2>&1
"$root/tools/build-linux.sh" M="$out/mod" modules >"$out/module-build.log" 2>&1
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/logvm.cpio.gz" "$root/tests/guest/init-logvm" \
    "$out/mod/l4h_log_fault.ko" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/logtest.cpio.gz" "$root/tests/guest/init-logtest" \
    "$l4h_ctl" "$out/logvm.cpio.gz" >/dev/null
rm -f "$out/result.img"
mkfs.ext4 -q -F "$out/result.img" 32M
L4H_DOM0_DISKS=1 L4H_TEST_FAIL_PATTERN='LOGTEST: FAIL:' \
L4H_QEMU_ARGS="-drive file=$out/result.img,if=none,id=logdisk,format=raw -device virtio-blk-pci,drive=logdisk,disable-legacy=on" \
    "$root/tools/run-dom0.sh" "$out/logtest.cpio.gz" console=hvc0 "$((90 * l4h_test_slow))" >"$out/output.log" 2>&1
debugfs -R 'cat /result' "$out/result.img" 2>/dev/null >"$out/result"
cat "$out/result"
grep -qx 'LOGTEST: PASS' "$out/result"
