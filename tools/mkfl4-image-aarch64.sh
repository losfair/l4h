#!/usr/bin/env bash
# Build an ARM64 Linux `Image` wrapping the FL4 AArch64 kernel and l4h-root
# using the reusable position-independent stub (boot/l4h-fl4-image) and
# tools/pack-fl4-image.py.
# Boots directly under `qemu-system-aarch64 -kernel` and Apple
# Virtualization.framework `VZLinuxBootLoader`.
# Usage: mkfl4-image-aarch64.sh <out.Image> <l4h-root.elf> <FL4 kernel.elf>
# L4H_GUEST_KERNEL, L4H_GUEST_SDK, L4H_DOM0_INITRD and L4H_CONFIG are
# embedded in the root task by dom0-modules.sh.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
out=$1
stub=${L4H_FL4_IMAGE_STUB:-$root/build/l4h-fl4-image.bin}

if [ ! -f "$stub" ]; then
    "$root/tools/build-fl4-image-loader.sh" "$stub"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

aarch64-linux-gnu-objcopy --strip-debug "$2" "$work/root.elf"
aarch64-linux-gnu-objcopy --strip-debug "$3" "$work/kernel.elf"
if [ -n "${L4H_GUEST_KERNEL:-}" ]; then
    aarch64-linux-gnu-objcopy --strip-debug "$L4H_GUEST_KERNEL" "$work/vmlinux"
    export L4H_GUEST_KERNEL=$work/vmlinux
fi
rootserver=$("$root/tools/dom0-modules.sh" "$work/root.elf")

python3 "$root/tools/pack-fl4-image.py" "$stub" "$work/kernel.elf" "$rootserver" "$out"

# When dom0-modules.sh embedded modules, verify L4HMODS1 appears exactly once.
if [ "$rootserver" != "$work/root.elf" ]; then
    python3 - "$out" <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
n = d.count(b'L4HMODS1')
assert n == 1, f'expected exactly 1 L4HMODS1 marker in {sys.argv[1]}, found {n}'
PY
fi
