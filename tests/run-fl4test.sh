#!/usr/bin/env bash
# Boot the complete l4h stack on FL4 from L4H_FL4_SOURCE, a frozen worktree.
# L4H_RELEASE=1 also runs the ABI/module-tree test: FL4's debug profile
# intentionally has no l4h debug-syscall MCP filter.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_ARCH=x86_64
export L4H_KERNEL_VARIANT=fl4 SEL4_PREFIX=$root/build/sel4-fl4
"$root/tools/build-fl4.sh"
for vcpus in 1 4; do
    "$root/tests/run-selftest.sh" "$vcpus"
    grep -aq 'FL4: seL4 17.0 (MCS) API kernel' "$root/build/qemu.log"
done
if [ "${L4H_RELEASE:-0}" = 1 ]; then
    "$root/tests/run-abitest.sh"
fi
echo 'FL4TEST: PASS'
