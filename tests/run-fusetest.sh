#!/usr/bin/env bash
# Boot a Linux guest that runs tests/guest/fusetest.c (a FUSE file system
# with SQLite's WAL access pattern: shared mappings, byte range locks,
# fsync and rename) and check the result.
# Usage: run-fusetest.sh [vcpus]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/guest
mkdir -p "$out"
cc=gcc
linux=$root/build/linux-l4h
test_timeout=180
if [ "${L4H_ARCH:-x86_64}" = aarch64 ]; then
    cc=aarch64-linux-gnu-gcc
    linux=$root/build/linux-l4h-aarch64
    test_timeout=900
fi
"$cc" -O2 -static -pthread -Wall -Wextra -Werror -o "$out/fusetest" "$root/tests/guest/fusetest.c"
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { tail -80 "$root/build/linux-build.log"; exit 1; }
grep -qx 'CONFIG_FUSE_FS=y' "$linux/.config" \
    || { echo "guest kernel built without CONFIG_FUSE_FS=y" >&2; exit 1; }
"$root/tools/mkinitramfs.sh" "$out/fusetest.cpio.gz" "$root/tests/guest/init-fusetest" \
    "$out/fusetest" >/dev/null
L4H_DOM0_VCPUS=${1:-1} L4H_TEST_FAIL_PATTERN='FUSETEST: FAIL' \
    "$root/tools/run-dom0.sh" "$out/fusetest.cpio.gz" "console=hvc0" "${L4H_TEST_TIMEOUT:-$test_timeout}" \
    | sed -n '/FUSETEST: start/,/FUSETEST: \(PASS\|FAIL\)/p'
grep -q "FUSETEST: PASS" "$root/build/qemu.log"
