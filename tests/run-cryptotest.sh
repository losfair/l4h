#!/usr/bin/env bash
# Boot a Linux guest that runs tests/guest/cryptotest.c: dm-crypt with
# kernel-mode SIMD (AES-NI on x86_64, the ARMv8 Crypto Extensions on
# aarch64), checked against the generic C cipher, generic vs accelerated
# throughput, and a user SIMD-state stress while the kernel encrypts on
# every vCPU.
# Usage: run-cryptotest.sh [vcpus] [stress-seconds] [bench-MiB]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
secs=${2:-10}
mib=${3:-256}
"$l4h_cc" -O2 -static -pthread -o "$out/cryptotest" "$root/tests/guest/cryptotest.c"
"$root/tools/mkinitramfs.sh" "$out/cryptotest.cpio.gz" "$root/tests/guest/init-cryptotest" \
    "$out/cryptotest" >/dev/null
L4H_DOM0_VCPUS=${1:-2} "$root/tools/run-dom0.sh" "$out/cryptotest.cpio.gz" \
    "console=hvc0 cryptotest=$secs,$mib" "${L4H_TEST_TIMEOUT:-$(((secs * 4 + 180) * l4h_test_slow))}" \
    | sed -n '/CRYPTOTEST: start/,/CRYPTOTEST: \(PASS\|FAIL\)/p'
grep -q "CRYPTOTEST: PASS" "$root/build/qemu.log"
! grep -q "WARNING:\|BUG:" "$root/build/qemu.log" || exit 1
