#!/usr/bin/env bash
# x86 boot-time discovery, placement, the guest's SMT topology and
# migration with two SMT cores.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
[ "${L4H_ARCH:-x86_64}" = x86_64 ] || { echo "SMTTEST requires x86_64" >&2; exit 1; }
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/densvm.cpio.gz" "$root/tests/guest/init-densvm" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/smttest.cpio.gz" "$root/tests/guest/init-smttest" \
    "$l4h_ctl" "$out/densvm.cpio.gz" >/dev/null
L4H_SMP=4,sockets=1,cores=2,threads=2 L4H_DOM0_VCPUS=1 \
    "$root/tools/run-dom0.sh" "$out/smttest.cpio.gz" "console=hvc0" "${SMTTEST_TIMEOUT:-180}" \
    | grep -E 'SMTTEST|CPU physical|initial CPUs|balancer|panic' || true
grep -Fq 'CPU physical cores [0, 0, 2, 2]' "$root/build/qemu.log"
grep -Fq "guest 1 'spread' initial CPUs [2, 1, 3, 0]" "$root/build/qemu.log"
grep -Fq 'SMTTEST: guest SMT siblings 0,2 and 1,3' "$root/build/qemu.log"
grep -q 'SMTTEST: PASS' "$root/build/qemu.log"
