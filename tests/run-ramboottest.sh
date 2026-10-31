#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Deferred boot RAM: early allocations, background conversion, usable pages.
# Usage: RAMBOOT_MEM_MB=1024 RAMBOOT_PAD_MB=64 run-ramboottest.sh [vcpus=2]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/ramboottest
mkdir -p "$out"
"$l4h_cc" -O2 -Wall -Wextra -static -o "$out/ramboottest" "$root/tests/guest/ramboottest.c"
# A compressed initramfs that needs real RAM when unpacked during boot.
truncate -s "${RAMBOOT_PAD_MB:-64}M" "$out/ramboot-pad"
"$root/tools/mkinitramfs.sh" "$out/initrd.cpio.gz" "$root/tests/guest/init-ramboottest" \
    "$out/ramboottest" "$out/ramboot-pad" >/dev/null
mem=${RAMBOOT_MEM_MB:-1024}
L4H_MEM=${L4H_MEM:-$((mem / 1024 + 2))G} L4H_DOM0_MEM_MB=$mem L4H_DOM0_VCPUS=${1:-2} \
L4H_TEST_FAIL_PATTERN='RAMBOOT: FAIL|Kernel panic|BUG:' \
    "$root/tools/run-dom0.sh" "$out/initrd.cpio.gz" "console=hvc0" "${RAMBOOT_TIMEOUT:-$((180 * l4h_test_slow))}" \
    | tee "$out/run.log"
grep -aq 'RAMBOOT: PASS' "$root/build/qemu.log"
! grep -aq 'RAMBOOT: FAIL' "$root/build/qemu.log"
