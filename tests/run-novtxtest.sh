#!/usr/bin/env bash
# Build and boot the userspace stack against a kernel without VT-x/AMD-V.
# This is a development build, separate from the shipped kernel variants.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_ARCH=x86_64 L4H_RELEASE=0 L4H_VTX=OFF
export L4H_KERNEL_VARIANT=no-vtx SEL4_PREFIX=$root/build/sel4-no-vtx
"$root/tools/build-kernel.sh"
if grep -q '^#define CONFIG_VTX ' "$SEL4_PREFIX/libsel4/include/kernel/gen_config.h"; then
    echo 'NOVTXTEST: FAIL (kernel still has VT-x/AMD-V)' >&2
    exit 1
fi
for vcpus in 1 4; do
    "$root/tests/run-selftest.sh" "$vcpus"
    if grep -q '^CONFIG_KVM=y$' "$root/build/linux-l4h/.config"; then
        echo 'NOVTXTEST: FAIL (Linux KVM enabled without KernelVTX)' >&2
        exit 1
    fi
    if grep -aq 'Untyped Retype: VT-x is not available' "$root/build/qemu.log"; then
        echo 'NOVTXTEST: FAIL (root probed a VCPU without KernelVTX)' >&2
        exit 1
    fi
done
echo 'NOVTXTEST: PASS'
