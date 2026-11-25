#!/usr/bin/env bash
# Host-side CMOS calendar, mode, bounds and error-path tests.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/rtctest-${L4H_ARCH:-x86_64}
mkdir -p "$out"
if [ "${1:-}" != --qemu-only ]; then
    rustc +stable --edition=2024 --test "$root/tests/rtc.rs" -o "$out/unit-tests"
    "$out/unit-tests"
fi
if [ "${1:-}" = --qemu ] || [ "${1:-}" = --qemu-only ]; then
    source "$root/tools/guest-env.sh"
    if [ -z "${L4H_GUEST_KERNEL:-}" ]; then
        "$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1
        "$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$l4h_linux_out/vmlinux.stripped"
        export L4H_GUEST_KERNEL=$l4h_linux_out/vmlinux.stripped
    fi
    "$root/tools/build-l4hctl.sh"
    "$root/tools/mkinitramfs.sh" "$out/rtc-denied.cpio.gz" "$root/tests/guest/init-rtc-denied" "$l4h_ctl"
    export L4H_DOM0_INITRD=$out/rtctest.cpio.gz
    "$root/tools/mkinitramfs.sh" "$L4H_DOM0_INITRD" "$root/tests/guest/init-rtctest" "$l4h_ctl" "$out/rtc-denied.cpio.gz"
    "$l4h_host_build"
    python3 "$root/tests/rtc-qemu.py"
fi
