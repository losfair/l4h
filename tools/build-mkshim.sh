#!/usr/bin/env bash
# Build the multikernel boot shim and the seL4 kernels it loads, one per
# slot (DESIGN.md §11.4): build/mkshim/l4h-mkshim.elf (32-bit, for QEMU's
# -kernel and GRUB alike) and build/mkshim/kernel-sK.elf for slots
# 0..N-1 (default 8), each built in build/kernel[-VARIANT]-sK.
# L4H_KERNEL_VARIANT, L4H_LAPIC_MODE, L4H_PCID, L4H_SKIM_WINDOW and
# L4H_RELEASE select the kernel configuration, as for build-kernel.sh.
# Usage: build-mkshim.sh [N]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
n=${1:-8}
out=$root/build/mkshim${L4H_KERNEL_VARIANT:+-$L4H_KERNEL_VARIANT}
if [ "${L4H_PREBUILT:-0}" = 1 ] && [ -f "$out/l4h-mkshim.elf" ]; then
    prebuilt_ok=1
    for k in $(seq 0 $((n - 1))); do
        [ -f "$out/kernel-s$k.elf" ] || { prebuilt_ok=0; break; }
    done
    [ "$prebuilt_ok" != 1 ] || exit 0
fi
mkdir -p "$out"
base=${L4H_KERNEL_VARIANT:-}
for k in $(seq 0 $((n - 1))); do
    variant=${base:+$base-}s$k
    L4H_KERNEL_VARIANT=$variant L4H_KERNEL_SLOT=$k "$root/tools/build-kernel.sh" >"$out/kernel-s$k.log" 2>&1 \
        || { tail -20 "$out/kernel-s$k.log"; exit 1; }
    cp "$root/build/sel4${variant:+-$variant}/bin/kernel.elf" "$out/kernel-s$k.elf"
done
cd "$root/boot/l4h-mkshim"
profile=release
"$root/tools/cargo.sh" build "${l4h_cargo[@]}" -q --release
objcopy -O elf32-i386 "target/x86_64-unknown-none/$profile/l4h-mkshim" "$out/l4h-mkshim.elf"
echo "$out: l4h-mkshim.elf, kernel-s0..s$((n - 1)).elf"
