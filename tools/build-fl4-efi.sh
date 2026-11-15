#!/usr/bin/env bash
# Build the FL4 x86_64 UEFI application and its matching debug archive.
# L4H_RELEASE=1 builds optimised host components and FL4's release profile.
# The host and ABI provider use FL4's libsel4; Linux and modules are shared
# with seL4. This application has no multikernel shim.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/efi
mkdir -p "$out"
source "$root/tools/host-profile.sh"
export L4H_ARCH=x86_64 L4H_KERNEL_VARIANT=fl4 SEL4_PREFIX=$root/build/sel4-fl4
"$root/tools/build-fl4.sh" >"$out/kernel-fl4.log" 2>&1 \
    || { tail -n 40 "$out/kernel-fl4.log"; exit 1; }
"$root/tools/build-host.sh"
if [ "${L4H_GUEST_BUILT:-0}" != 1 ]; then
    "$root/tools/build-kmods.sh" >/dev/null
fi
export L4H_GUEST_KERNEL=$root/build/linux-l4h/vmlinux
export L4H_GUEST_KMODS=$root/build/linux-l4h/kmods.erofs
L4H_MKSHIM= "$root/tools/mkefi.sh" "$out/l4h-fl4.efi" \
    "$root/host/target/x86_64-sel4-roottask/$l4h_profile/l4h-root.elf" \
    "$SEL4_PREFIX/bin/kernel.elf"

debug=$(mktemp -d)
trap 'rm -rf "$debug"' EXIT
symbols=$debug/l4h-debug-fl4-x86_64
mkdir -p "$symbols"
cp "$root/host/target/x86_64-sel4-roottask/$l4h_profile/l4h-root.elf" \
    "$root"/host/target/x86_64-sel4/$l4h_profile/l4h-{vmmgr,vmm,blkd,netd,trustd,memd,logd,usbd,nicd-*}.elf \
    "$L4H_GUEST_KERNEL" "$symbols/"
cp "$SEL4_PREFIX/bin/kernel.elf" "$SEL4_PREFIX/fl4-revision" "$symbols/"
cp "$SEL4_PREFIX/guest-provider/provider.bin" "$symbols/guest-provider.bin"
cp "$SEL4_PREFIX/guest-provider/provider.elf" "$symbols/guest-provider.elf"
tar -C "$debug" -cJf "$out/l4h-debug-fl4-x86_64.tar.xz" l4h-debug-fl4-x86_64
echo "$out/l4h-debug-fl4-x86_64.tar.xz: $(( $(stat -c %s "$out/l4h-debug-fl4-x86_64.tar.xz") >> 10 )) KiB"
