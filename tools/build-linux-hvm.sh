#!/usr/bin/env bash
# Build an unmodified Linux for HVM guests (DESIGN.md §5.11): the release
# build/dl holds (tools/ci-setup.sh) extracted, without l4h's patches, into
# build/linux-hvm-src.  With L4H_ARCH=x86_64 (the default) a bzImage from
# x86_64_defconfig, kvm_guest.config and tests/hvm/linux.config; with
# L4H_ARCH=aarch64 an arm64 Image from allnoconfig and
# tests/hvm/linux-arm64.config.  Prints the image's path.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
src=$root/build/linux-hvm-src
arch=${L4H_ARCH:-x86_64}
[ "$arch" = x86_64 ] || [ "$arch" = aarch64 ] || { echo "L4H_ARCH=$arch: x86_64 or aarch64" >&2; exit 1; }
out=$root/build/linux-hvm
[ "$arch" = x86_64 ] || out=$root/build/linux-hvm-$arch
if [[ ${L4H_PREBUILT:-0} == 1 || ${L4H_PREBUILT:-0} == guest ]]; then
    prebuilt=$out/arch/x86/boot/bzImage
    [ "$arch" = x86_64 ] || prebuilt=$out/arch/arm64/boot/Image
    if [ -f "$prebuilt" ]; then
        echo "$prebuilt"
        exit 0
    fi
fi
cc_args=()
if [ -n "${L4H_LINUX_CC:-}" ]; then
    cc_args+=(CC="$root/tools/linux-cc.sh")
    if [ "$arch" = x86_64 ] && [ "$(uname -m)" = x86_64 ]; then
        cc_args+=(HOSTCC="${HOSTCC:-$root/tools/linux-cc.sh}")
    fi
fi
if [ ! -f "$src/Makefile" ]; then
    tarball=$(ls "$root"/build/dl/linux-6.18.*.tar.xz 2>/dev/null | sort -V | tail -1)
    [ -n "$tarball" ] || { echo "no build/dl/linux-6.18.*.tar.xz: run tools/ci-setup.sh" >&2; exit 1; }
    tmp=$(mktemp -d "$root/build/linux-hvm-src.XXXXXX")
    tar -C "$tmp" -xJf "$tarball"
    mv "$tmp"/linux-* "$src"
    rmdir "$tmp"
fi
mkdir -p "$out"
if [ "$arch" = aarch64 ]; then
    frag=$root/tests/hvm/linux-arm64.config
    mk=(make -C "$src" O="$out" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- "${cc_args[@]}" -s)
    if [ ! -f "$out/.config" ] || [ "$frag" -nt "$out/.config" ]; then
        "${mk[@]}" allnoconfig
        ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
            "$src/scripts/kconfig/merge_config.sh" -m -O "$out" "$out/.config" "$frag" >/dev/null
        "${mk[@]}" olddefconfig
    fi
    "${mk[@]}" -j"$(nproc)" Image >&2
    echo "$out/arch/arm64/boot/Image"
    exit 0
fi
frag=$root/tests/hvm/linux.config
mk=(make -C "$src" O="$out" "${cc_args[@]}" -s)
if [ ! -f "$out/.config" ] || [ "$frag" -nt "$out/.config" ]; then
    "${mk[@]}" x86_64_defconfig
    "${mk[@]}" kvm_guest.config
    "$src/scripts/kconfig/merge_config.sh" -m -O "$out" "$out/.config" "$frag" >/dev/null
    "${mk[@]}" olddefconfig
fi
"${mk[@]}" -j"$(nproc)" bzImage >&2
echo "$out/arch/x86/boot/bzImage"
