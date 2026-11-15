#!/usr/bin/env bash
# Build the guest kernel's module tree, which every guest gets read-only as
# /dev/l4hkmod (DESIGN.md §5.6): an EROFS image of its /lib/modules,
#   <release>/        its modules and depmod's files
#   <release>/build/  the tree to build external modules against: kbuild,
#                     the headers, .config and Module.symvers, and l4h/abi
#                     (l4h/abi.h and the provider ABI), so that
#                     "make -C /lib/modules/$(uname -r)/build M=$PWD" works
#                     in a guest without further arguments
# Usage: build-kmods.sh [out.erofs]   (default: kmods.erofs in the kernel
# build directory, next to vmlinux).  Builds the kernel first.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
arch=${L4H_ARCH:-x86_64}
case "$arch" in
    x86_64) host_dir=arch/x86 ;;
    aarch64) host_dir=arch/arm64 ;;
esac
out=$(realpath -m "${1:-$l4h_linux_out/kmods.erofs}")
src=$root/build/linux-6.18
"$root/tools/build-linux.sh" vmlinux modules >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
"$root/tools/build-linux.sh" modules_install INSTALL_MOD_PATH="$stage" INSTALL_MOD_STRIP=1 >/dev/null
release=$(cat "$l4h_linux_out/include/config/kernel.release")
tree=$stage/lib/modules/$release/build
rm -f "$tree"
"$root/tools/build-linux.sh" run-command \
    KBUILD_RUN_COMMAND="\$(srctree)/scripts/package/install-extmod-build $tree" >/dev/null
# What install-extmod-build leaves out for ARCH=l4h: the headers and
# makefiles outside arch/l4h/include, and those of the ISA's own
# architecture, which l4h's include.
(cd "$src" && find -L arch/l4h \( -name 'Makefile*' -o -name '*.h' -o -name '*.lds' \) -print \
    | tar -chf - -T - "$host_dir/include") | tar -xf - -C "$tree"
(cd "$l4h_linux_out" && tar -cf - "$host_dir/include/generated" .config) | tar -xf - -C "$tree"
mkdir -p "$tree/l4h"
cp -r "$root/include" "$tree/l4h/abi"
# Build for ARCH=l4h without saying so: SUBARCH would otherwise come from
# uname -m, which names arm64 differently.
{
    echo "# l4h: external modules for the $arch ARCH=l4h kernel (tools/build-kmods.sh)"
    echo "ARCH ?= l4h"
    echo "override SUBARCH := $arch"
    cat "$tree/Makefile"
} >"$tree/Makefile.new"
mv "$tree/Makefile.new" "$tree/Makefile"
# Reproducible: the image is part of the measured UEFI application.
mkfs.erofs --quiet -zlzma,level=6 -C1048576 -Eall-fragments,ztailpacking -T0 --all-root \
    -U 6c346800-6b6d-6f64-0000-000000000000 "$out.new" "$stage/lib/modules"
mv "$out.new" "$out"
echo "$out: $release, $(( $(stat -c %s "$out") >> 10 )) KiB"
