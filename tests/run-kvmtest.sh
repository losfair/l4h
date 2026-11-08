#!/usr/bin/env bash
# KVM in a guest (DESIGN.md §5.10): dom0 runs tests/guest/kvmtest.c, small
# VMs on /dev/kvm.  With "vmm" it then boots the host's Linux kernel with two
# vCPUs under each of QEMU (the host's), Firecracker and cloud-hypervisor
# (their static release binaries, downloaded and checked into build/dl);
# KVMTEST_VMMS picks a subset.  Needs a CPU with VMX in QEMU (-cpu host on
# an Intel host with nested KVM); L4H_QEMU_CPU overrides it.
# Usage: run-kvmtest.sh [vmm] [vcpus]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/guest
mkdir -p "$out"
vmm=0
if [ "${1:-}" = vmm ]; then
    vmm=1
    shift
fi
vmms=${KVMTEST_VMMS:-qemu firecracker cloud-hypervisor}
source "$root/tests/kvm-vmms.sh"
gcc -O2 -static -pthread -o "$out/kvmtest" "$root/tests/guest/kvmtest.c"
"$root/tools/mkinitramfs.sh" "$out/kvmtest.cpio.gz" "$root/tests/guest/init-kvmtest" \
    "$out/kvmtest" "$root/tests/guest/run-nested" >/dev/null
mem=512
if [ "$vmm" = 1 ]; then
    mem=1536
    # shellcheck disable=SC2086
    kvm_vmms_append "$out/kvmtest.cpio.gz" $vmms
fi
export L4H_QEMU_CPU=${L4H_QEMU_CPU:-host,+invtsc}
L4H_DOM0_MEM_MB=${L4H_DOM0_MEM_MB:-$mem} L4H_DOM0_VCPUS=${1:-2} \
    L4H_TEST_FAIL_PATTERN='KVMTEST: FAIL|kernel fault|restarting dom0' \
    "$root/tools/run-dom0.sh" "$out/kvmtest.cpio.gz" "console=hvc0" "${KVMTEST_TIMEOUT:-300}" \
    | sed -n '/KVMTEST: start/,/KVMTEST: \(PASS\|FAIL\)/p;/kernel fault/p;/KVMTEST: VMM /,/KVMTEST: VMMs done/p'
grep -aq "KVMTEST: PASS" "$root/build/qemu.log"
if [ "$vmm" = 1 ]; then
    for v in $vmms; do
        grep -aq "^$v: NESTED: done" "$root/build/qemu.log" || { echo "KVMTEST: $v failed" >&2; exit 1; }
    done
fi
