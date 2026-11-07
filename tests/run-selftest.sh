#!/usr/bin/env bash
# Boot a Linux guest that runs tests/guest/selftest.c and check the result.
# Usage: run-selftest.sh [vcpus]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/guest
mkdir -p "$out"
cc=gcc
test_timeout=120
if [ "${L4H_ARCH:-x86_64}" = aarch64 ]; then
    cc=aarch64-linux-gnu-gcc
    test_timeout=600
fi
"$cc" -O2 -static -pthread -o "$out/selftest" "$root/tests/guest/selftest.c"
mod=$out/page-aging
mkdir -p "$mod"
cp "$root"/tests/guest/page-aging/* "$mod/"
"$root/tools/build-linux.sh" vmlinux modules >"$root/build/linux-build.log" 2>&1 \
    || { tail -80 "$root/build/linux-build.log"; exit 1; }
"$root/tools/build-linux.sh" M="$mod" modules >"$root/build/page-aging-module.log" 2>&1 \
    || { cat "$root/build/page-aging-module.log"; exit 1; }
"$root/tools/mkinitramfs.sh" "$out/selftest.cpio.gz" "$root/tests/guest/init-selftest" \
    "$out/selftest" "$mod/l4h_page_aging.ko" >/dev/null
L4H_DOM0_VCPUS=${1:-1} "$root/tools/run-dom0.sh" "$out/selftest.cpio.gz" "console=hvc0" "${L4H_TEST_TIMEOUT:-${SELFTEST_TIMEOUT:-$test_timeout}}" \
    | sed -n '/SELFTEST: start/,/SELFTEST: \(PASS\|FAIL\)/p'
grep -q "SELFTEST: PASS" "$root/build/qemu.log"
! grep -q 'hardware sampling skipped' "$root/build/qemu.log" || exit 1
! grep -q 'deschedule .* SC failed\|SchedContext UnbindObject: object not bound' "$root/build/qemu.log" || exit 1
