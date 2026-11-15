#!/usr/bin/env bash
# Boot l4h on QEMU's aarch64 virt machine (TCG: no KVM for arm64 here).
# Starts directly at EL1 with virtualization disabled. Set
# L4H_QEMU_VIRTUALIZATION=on to test the loader's EL2-to-EL1 path.
# Usage: run-qemu-aarch64.sh <l4h-root.elf> [extra qemu args...]
# The guest kernel and its build SDK (L4H_GUEST_KERNEL, L4H_GUEST_SDK),
# dom0's initramfs (L4H_DOM0_INITRD) and an l4h.conf (L4H_CONFIG) are
# appended to a copy of the root ELF (tools/dom0-modules.sh).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
rootserver=$("$root/tools/dom0-modules.sh" "$1"); shift
source "$root/tools/aarch64-memory.sh"
if [ "$(cat "$l4h_memory_stamp" 2>/dev/null || echo 2048)" != "$l4h_memory_mb" ]; then
    echo "Rebuild the AArch64 kernel and loader with L4H_MEM=$l4h_memory_mb before booting" >&2
    exit 1
fi
prefix=$root/build/sel4-aarch64
loader=$root/build/loader-target/aarch64-unknown-none/release/sel4-kernel-loader
"$root/build/loader-target/release/sel4-kernel-loader-add-payload" \
    --sel4-prefix "$prefix" --loader "$loader" --app "$rootserver" -o "$root/build/l4h-aarch64.img"
exec "$root/tools/run-image-aarch64.sh" "$root/build/l4h-aarch64.img" "$@"
