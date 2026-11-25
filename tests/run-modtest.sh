#!/usr/bin/env bash
# Load and unload an external module, exercising the ISA's ELF relocations.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest/module
mkdir -p "$out"
if [[ ${L4H_PREBUILT:-0} != 1 && ${L4H_PREBUILT:-0} != guest ]] || [ ! -f "$out/l4h_modtest.ko" ]; then
    cp "$root/tests/guest/module/Makefile" "$root/tests/guest/module/l4h_modtest.c" "$out/"
    "$root/tools/build-linux.sh" vmlinux modules >"$root/build/linux-build.log" 2>&1
    "$root/tools/build-linux.sh" M="$out" modules >"$root/build/module-build.log" 2>&1
fi
"$root/tools/mkinitramfs.sh" "$out/modtest.cpio.gz" "$root/tests/guest/init-modtest" "$out/l4h_modtest.ko" >/dev/null
"$root/tools/run-dom0.sh" "$out/modtest.cpio.gz" console=hvc0 120 | grep MODTEST || true
grep -q 'MODTEST: PASS' "$root/build/qemu.log"
