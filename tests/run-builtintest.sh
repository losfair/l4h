#!/usr/bin/env bash
# Shipped drivers need no module image; external modules still obey lockdown.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
source "$root/tools/guest-env.sh"
out=$root/build/guest/builtin
mkdir -p "$out"
"$root/tools/build-linux.sh" vmlinux modules >"$root/build/linux-build.log" 2>&1
if grep '^CONFIG_.*=m$' "$l4h_linux_out/.config"; then
    echo 'BUILTINTEST: FAIL: the default kernel still ships loadable modules' >&2
    exit 1
fi
test ! -s "$l4h_linux_out/modules.order"
grep -qx '# CONFIG_MODULE_SIG_ALL is not set' "$l4h_linux_out/.config"
grep -qx 'CONFIG_MODULE_SIG_KEY=""' "$l4h_linux_out/.config"
cp "$root/tests/guest/module/Makefile" "$root/tests/guest/module/l4h_modtest.c" "$out/"
"$root/tools/build-linux.sh" M="$out" modules >"$root/build/builtin-module-build.log" 2>&1
"$root/tools/mkinitramfs.sh" "$out/builtintest.cpio.gz" \
    "$root/tests/guest/init-builtintest" "$out/l4h_modtest.ko" >/dev/null
for mode in normal integrity; do
    cmdline=console=hvc0
    if [ "$mode" = integrity ]; then cmdline+=' lockdown=integrity'; fi
    L4H_KMODS=0 "$root/tools/run-dom0.sh" "$out/builtintest.cpio.gz" "$cmdline" \
        "${L4H_TEST_TIMEOUT:-$((120 * l4h_test_slow))}" | grep BUILTINTEST || true
    cp "$root/build/qemu.log" "$root/build/builtintest-$mode.log"
    grep -q "BUILTINTEST: PASS $mode" "$root/build/qemu.log"
    if grep -q 'WARNING:\|BUG:' "$root/build/qemu.log"; then exit 1; fi
done
