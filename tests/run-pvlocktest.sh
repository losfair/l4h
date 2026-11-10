#!/usr/bin/env bash
# Paravirtual spinlocks (DESIGN.md §6): contended spinlocks stay exclusive
# and their waiters block, in a 4-vCPU dom0 and in a 4-vCPU guest capped at
# 25%, whose vCPUs run out of budget holding locks; guests with one vCPU
# or "nopvspin" keep the plain locks.  Usage: run-pvlocktest.sh
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
mod=$out/pvlock
mkdir -p "$mod"
cp "$root"/tests/guest/pvlock/* "$mod/"
"$root/tools/build-linux.sh" vmlinux modules >"$root/build/linux-build.log" 2>&1 \
    || { tail -80 "$root/build/linux-build.log"; exit 1; }
"$root/tools/build-linux.sh" M="$mod" modules >"$root/build/pvlock-module.log" 2>&1 \
    || { cat "$root/build/pvlock-module.log"; exit 1; }
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/pvlockvm.cpio.gz" "$root/tests/guest/init-pvlockvm" \
    "$mod/l4h_pvlock.ko" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/pvlocktest.cpio.gz" "$root/tests/guest/init-pvlocktest" \
    "$l4h_ctl" "$out/pvlockvm.cpio.gz" "$mod/l4h_pvlock.ko" >/dev/null
tmo=$((60 * l4h_test_slow))
L4H_DOM0_VCPUS=4 "$root/tools/run-dom0.sh" "$out/pvlocktest.cpio.gz" \
    "console=hvc0 pvlock_timeout=$tmo" "${PVLOCKTEST_TIMEOUT:-$((5 * tmo))}" \
    | grep -E "PVLOCKTEST|panic" || true
grep -q "PVLOCKTEST: PASS" "$root/build/qemu.log"
