#!/usr/bin/env bash
# Build an unmodified x86-64 Linux bzImage for HVM guests (DESIGN.md
# §5.11): the release build/dl holds (tools/ci-setup.sh) extracted, without
# l4h's patches, into build/linux-hvm-src; x86_64_defconfig,
# kvm_guest.config and tests/hvm/linux.config.  Prints the bzImage's path.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
src=$root/build/linux-hvm-src
out=$root/build/linux-hvm
if [ ! -f "$src/Makefile" ]; then
    tarball=$(ls "$root"/build/dl/linux-6.18.*.tar.xz 2>/dev/null | sort -V | tail -1)
    [ -n "$tarball" ] || { echo "no build/dl/linux-6.18.*.tar.xz: run tools/ci-setup.sh" >&2; exit 1; }
    tmp=$(mktemp -d "$root/build/linux-hvm-src.XXXXXX")
    tar -C "$tmp" -xJf "$tarball"
    mv "$tmp"/linux-* "$src"
    rmdir "$tmp"
fi
mkdir -p "$out"
frag=$root/tests/hvm/linux.config
if [ ! -f "$out/.config" ] || [ "$frag" -nt "$out/.config" ]; then
    make -C "$src" O="$out" -s x86_64_defconfig
    make -C "$src" O="$out" -s kvm_guest.config
    "$src/scripts/kconfig/merge_config.sh" -m -O "$out" "$out/.config" "$frag" >/dev/null
    make -C "$src" O="$out" -s olddefconfig
fi
make -C "$src" O="$out" -s -j"$(nproc)" bzImage >&2
echo "$out/arch/x86/boot/bzImage"
