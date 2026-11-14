#!/usr/bin/env bash
# Boot the complete l4h stack on the pinned FL4 revision, or on a frozen
# worktree selected by L4H_FL4_SOURCE.
# Exercise SMP, device memory, networking and free-page reporting together.
# L4H_RELEASE=1 also runs the ABI/module-tree test: FL4's debug profile
# intentionally has no l4h debug-syscall MCP filter.
set -euo pipefail
# e2fsprogs installs mkfs.ext4 and debugfs outside an ordinary user's PATH.
export PATH="$PATH:/usr/sbin:/sbin"
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_ARCH=x86_64
export L4H_KERNEL_VARIANT=fl4 SEL4_PREFIX=$root/build/sel4-fl4
"$root/tools/build-fl4.sh"
for vcpus in 1 4; do
    "$root/tests/run-selftest.sh" "$vcpus"
    grep -aq 'FL4: seL4 17.0 (MCS) API kernel' "$root/build/qemu.log"
done
"$root/tests/run-blktest.sh" 4
"$root/tests/run-nettest.sh"
"$root/tests/run-balloontest.sh"
if [ "${L4H_RELEASE:-0}" = 1 ]; then
    "$root/tests/run-abitest.sh"
fi
echo 'FL4TEST: PASS'
