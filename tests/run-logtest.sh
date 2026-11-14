#!/usr/bin/env bash
# Fault/panic/shutdown diagnostics through l4hctl, and serial output in every build.
set -euo pipefail
# e2fsprogs installs mkfs.ext4 and debugfs outside an ordinary user's PATH.
export PATH="$PATH:/usr/sbin:/sbin"
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/logtest
fail() {
    echo "LOGTEST: FAIL: $*" >&2
    cat "$out/output.log" >&2
    exit 1
}
mkdir -p "$out/mod"
cp "$root"/tests/guest/log-fault/* "$out/mod/"
# External modules need Module.symvers, produced by the modules target.
"$root/tools/build-linux.sh" vmlinux modules >"$out/kernel-build.log" 2>&1 \
    || { cat "$out/kernel-build.log"; exit 1; }
"$root/tools/build-linux.sh" M="$out/mod" modules >"$out/module-build.log" 2>&1 \
    || { cat "$out/module-build.log"; exit 1; }
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/logvm.cpio.gz" "$root/tests/guest/init-logvm" \
    "$out/mod/l4h_log_fault.ko" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/logtest.cpio.gz" "$root/tests/guest/init-logtest" \
    "$l4h_ctl" "$out/logvm.cpio.gz" >/dev/null
rm -f "$out/result.img"
mkfs.ext4 -q -F "$out/result.img" 32M
L4H_DOM0_DISKS=1 L4H_TEST_FAIL_PATTERN='LOGTEST: FAIL:' \
L4H_QEMU_ARGS="-drive file=$out/result.img,if=none,id=logdisk,format=raw -device virtio-blk-pci,drive=logdisk,disable-legacy=on" \
    "$root/tools/run-dom0.sh" "$out/logtest.cpio.gz" console=hvc0 "$((90 * l4h_test_slow))" >"$out/output.log" 2>&1 \
    || fail "run dom0"
debugfs -R 'cat /result' "$out/result.img" >"$out/result" || fail "read result disk"
cat "$out/result"
grep -qx 'LOGTEST: PASS' "$out/result" || fail "guest result"
# Informational host messages and both dom0's and other guests' consoles
# reach logd even with L4H_RELEASE=1 (as this test runs in CI).
grep -aq 'l4h-root: .*core(s)' "$out/output.log" || fail "root serial output"
grep -aEq '\[vmmgr\] l4h-vmmgr: guest [0-9]+ power request' "$out/output.log" || fail "vmmgr serial output"
grep -aq 'LOGTEST: PASS' "$out/output.log" || fail "dom0 serial output"
grep -aEq '\[vm[0-9]+\] LOGVM: ready' "$out/output.log" || fail "guest serial output"
