#!/usr/bin/env bash
# Host-side checks of root's PCIe ACS setup (host/l4h-root/src/acs.rs)
# and BAR sizing (host/l4h-root/src/barsize.rs) against a model of
# configuration space, which MADT entries l4h-mkshim gives each
# partition (boot/l4h-mkshim/src/madt.rs), and root's device tree walk
# (host/l4h-root/src/fdt.rs).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/acstest
mkdir -p "$out"
rustc +stable --edition=2024 --test "$root/tests/acs.rs" -o "$out/unit-tests"
"$out/unit-tests"
rustc +stable --edition=2024 --test "$root/tests/barsize.rs" -o "$out/barsize-tests"
"$out/barsize-tests"
rustc +stable --edition=2024 --test "$root/tests/mkshim-madt.rs" -o "$out/mkshim-madt-tests"
"$out/mkshim-madt-tests"
# The device tree walk that tells root whether QEMU virt's GICv2m is
# there (host/l4h-root/src/fdt.rs), also on QEMU's own trees if it is
# installed.
rustc +stable --edition=2024 --test "$root/tests/fdt.rs" -o "$out/fdt-tests"
if command -v qemu-system-aarch64 >/dev/null; then
    for v in 2 3; do
        qemu-system-aarch64 -machine "virt,gic-version=$v,dumpdtb=$out/qemu-virt-gicv$v.dtb" -nographic >/dev/null 2>&1
    done
    export L4H_TEST_QEMU_DTB_V2=$out/qemu-virt-gicv2.dtb L4H_TEST_QEMU_DTB_V3=$out/qemu-virt-gicv3.dtb
fi
"$out/fdt-tests"
