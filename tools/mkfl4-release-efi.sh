#!/usr/bin/env bash
# Package the native FL4 release EFI. The FL4 kernel, root, guest kernel and
# SDK are embedded. The selected filesystem supplies dom0's initrd and config.
# Usage: mkfl4-release-efi.sh OUT.efi [l4h-root.elf] [FL4 kernel.elf]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
source "$root/tools/host-profile.sh"
source "$root/tools/prepare-fl4.sh"
out=$(realpath -m "$1")
rootelf=${2:-$root/host/target/x86_64-sel4-roottask/$l4h_profile/l4h-root.elf}
kernel=${3:-$root/build/sel4-fl4/bin/kernel.elf}
revision=$(dirname "$kernel")/../fl4-revision
if [ -f "$revision" ] && [ "$(cat "$revision")" != "$base" ]; then
    echo "FL4 kernel and EFI handoff library have different revisions" >&2
    exit 1
fi
guest=${L4H_GUEST_KERNEL:-$root/build/linux-l4h/vmlinux}
sdk=${L4H_GUEST_SDK-$(dirname "$guest")/sdk.erofs}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
loader=$root/boot/l4h-fl4-efi
library=$work/fl4
mkdir -p "$library"
# The loader links the EFI library of the pinned FL4 revision, the same one
# the kernel is built from, extracted as is: l4h applies no patch to FL4.
git -C "$src" archive "$base" -- crates/fl4-efi crates/fl4-bootinfo | tar -xC "$library"
cp -R "$loader"/{Cargo.toml,Cargo.lock,src} "$work/"
objcopy --strip-debug "$kernel" "$work/kernel.elf"
objcopy --strip-debug "$rootelf" "$work/root.elf"
objcopy --strip-debug "$guest" "$work/vmlinux"
if [ -n "$sdk" ]; then
    cp "$sdk" "$work/sdk.erofs"
else
    : > "$work/sdk.erofs"
fi
export L4H_EFI_KERNEL=$work/kernel.elf L4H_EFI_ROOT_TASK=$work/root.elf L4H_EFI_GUEST_KERNEL=$work/vmlinux
export L4H_EFI_SDK=$work/sdk.erofs L4H_EFI_FB_CONSOLE=${L4H_FB_CONSOLE:-0}
# Map even the random private staging directory in every crate, and ask
# the PE linker for reproducible output without a PDB path.
(
    cd "$root/kernel/fl4"
    stage_map=$(python3 -c 'import json, sys; print(json.dumps(["--remap-path-prefix=" + sys.argv[1] + "=/l4h/efi"]))' "$work")
    cargo rustc "${l4h_cargo[@]}" --config "build.rustflags=$stage_map" \
        --manifest-path "$work/Cargo.toml" -p l4h-fl4-efi --target-dir "$work/target" \
        --target x86_64-unknown-uefi --release \
        -- -C link-arg=/Brepro -C link-arg=/DEBUG:NONE
)
cp "$work/target/x86_64-unknown-uefi/release/l4h-fl4-efi.efi" "$out"
