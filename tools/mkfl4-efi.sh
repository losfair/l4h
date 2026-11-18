#!/usr/bin/env bash
# Build an x86_64 application using FL4's native UEFI loader for SEV-SNP.
# Usage: mkfl4-efi.sh <out.efi> <l4h-root.elf> <FL4 kernel.elf>
# L4H_GUEST_KERNEL, L4H_GUEST_SDK, L4H_DOM0_INITRD and L4H_CONFIG are
# embedded in the root task by dom0-modules.sh.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/prepare-fl4.sh"
out=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
objcopy --strip-debug "$2" "$work/root.elf"
objcopy --strip-debug "$3" "$work/kernel.elf"
if [ -n "${L4H_GUEST_KERNEL:-}" ]; then
    objcopy --strip-debug "$L4H_GUEST_KERNEL" "$work/vmlinux"
    export L4H_GUEST_KERNEL=$work/vmlinux
fi
rootserver=$("$root/tools/dom0-modules.sh" "$work/root.elf")
(
    cd "$src"
    FL4_KERNEL_ELF="$work/kernel.elf" FL4_ROOTSERVER_ELF="$rootserver" \
        cargo build --locked --release -p fl4-efi --target x86_64-unknown-uefi --target-dir "$work/target"
)
cp "$work/target/x86_64-unknown-uefi/release/fl4-efi.efi" "$out"
