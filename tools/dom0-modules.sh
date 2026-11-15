#!/usr/bin/env bash
# Append the guest kernel, dom0's initramfs and the host settings to a copy
# of a built l4h-root ELF (tools/add-modules.py) and print the copy's path,
# for the QEMU scripts.
#   L4H_GUEST_KERNEL  the kernel dom0 and the VMs run (an ARCH=l4h ELF)
#   L4H_GUEST_SDK   its build SDK (tools/build-sdk.sh; optional)
#   L4H_DOM0_INITRD   dom0's initramfs (optional)
#   L4H_CONFIG        an l4h.conf (optional)
# With none of them set, prints the ELF unchanged.
# Usage: dom0-modules.sh <l4h-root.elf>
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
elf=$1
mods=()
[ -n "${L4H_GUEST_KERNEL:-}" ] && mods+=("guest-kernel=$L4H_GUEST_KERNEL")
[ -n "${L4H_GUEST_SDK:-}" ] && mods+=("guest-sdk=$L4H_GUEST_SDK")
[ -n "${L4H_DOM0_INITRD:-}" ] && mods+=("dom0-initrd=$L4H_DOM0_INITRD")
[ -n "${L4H_CONFIG:-}" ] && mods+=("l4h-config=$L4H_CONFIG")
if [ ${#mods[@]} -eq 0 ]; then
    echo "$elf"
    exit 0
fi
out=${elf%.elf}-dom0.elf
"$root/tools/add-modules.py" "$elf" "$out" "${mods[@]}" >&2
echo "$out"
