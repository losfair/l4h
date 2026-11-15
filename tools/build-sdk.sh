#!/usr/bin/env bash
# Build the guest kernel SDK, shared read-only as /dev/l4hsdk.
# The EROFS image contains Kbuild, headers, .config, Module.symvers and
# l4h/abi, so modules can be built without the kernel source tree.
# Usage: build-sdk.sh [out.erofs] (default: sdk.erofs next to vmlinux).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
source "$root/tools/guest-env.sh"
arch=${L4H_ARCH:-x86_64}
case "$arch" in
    x86_64) host_dir=arch/x86 ;;
    aarch64) host_dir=arch/arm64 ;;
esac
out=$(realpath -m "${1:-$l4h_linux_out/sdk.erofs}")
src=$root/build/linux-6.18
"$root/tools/build-linux.sh" vmlinux modules >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
release=$(cat "$l4h_linux_out/include/config/kernel.release")
tree=$stage/tree
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
    echo "# l4h: external modules for the $arch ARCH=l4h kernel (tools/build-sdk.sh)"
    echo "ARCH ?= l4h"
    echo "override SUBARCH := $arch"
    cat "$tree/Makefile"
} >"$tree/Makefile.new"
mv "$tree/Makefile.new" "$tree/Makefile"
# The extra headers copied above bring back kbuild's local command records.
# The generated assembly is an intermediate for devicetable-offsets.h.
find "$tree" -name '.*.cmd' -delete
rm -f "$tree/scripts/mod/devicetable-offsets.s"
# Reproducible: the image is part of the measured UEFI application.
# Shared fragment/tail packing can corrupt files with the pinned
# erofs-utils. Use independent file extents and verify the complete SDK.
# EROFS treats SOURCE_DATE_EPOCH as an mtime clamp, so use zero here too.
SOURCE_DATE_EPOCH=0 mkfs.erofs --quiet --workers=1 -zlzma,level=6 -C1048576 -T0 --all-root \
    -U 6c346800-7364-6b00-0000-000000000000 "$out.new" "$tree"
fsck.erofs --extract="$stage/verify" "$out.new" >/dev/null
diff -qr --no-dereference "$tree" "$stage/verify"
mv "$out.new" "$out"
echo "$out: $release, $(( $(stat -c %s "$out") >> 10 )) KiB"
