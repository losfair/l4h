#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Disable background conversion to test reclaim, OOM fallback, and initramfs.
# Usage: run-rampressuretest.sh [vcpus=2] [all|shrinker|oom|initramfs]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/rampressuretest
mkdir -p "$out"
"$l4h_cc" -O2 -Wall -Wextra -Werror -static -pthread -o "$out/rampressuretest" \
    "$root/tests/guest/rampressuretest.c"
mem=${RAMPRESSURE_MEM_MB:-1024}
modes=("${2:-all}")
if [ "${modes[0]}" = all ]; then modes=(shrinker oom initramfs); fi
for mode in "${modes[@]}"; do
    blacklist=objmem_init
    pad=0
    case "$mode" in
        shrinker) ;;
        oom) blacklist+=,objmem_shrinker_init ;;
        initramfs) pad=$((mem * 3 / 5)) ;;
        *) echo "unknown pressure test: $mode" >&2; exit 1 ;;
    esac
    printf '%s %s %s\n' "$mode" "$mem" "$pad" > "$out/pressure-config"
    truncate -s "${pad}M" "$out/pressure-pad"
    "$root/tools/mkinitramfs.sh" "$out/initrd.cpio.gz" "$root/tests/guest/init-rampressuretest" \
        "$out/rampressuretest" "$out/pressure-config" "$out/pressure-pad" >/dev/null
    # ramfs has no tmpfs size limit derived from the initial MemTotal.
    cmdline="console=hvc0 rootfstype=ramfs initramfs_async=0 initcall_blacklist=$blacklist"
    L4H_MEM=${L4H_MEM:-$((mem / 1024 + 2))G} L4H_DOM0_MEM_MB=$mem L4H_DOM0_VCPUS=${1:-2} \
    L4H_TEST_FAIL_PATTERN='RAMPRESSURE: FAIL|Kernel panic|BUG:|Out of memory: Killed process' \
        "$root/tools/run-dom0.sh" "$out/initrd.cpio.gz" "$cmdline" \
        "${RAMPRESSURE_TIMEOUT:-$((180 * l4h_test_slow))}" | tee "$out/$mode.log"
    grep -aq "RAMPRESSURE: PASS: $mode," "$out/$mode.log"
    if grep -aEq 'RAMPRESSURE: FAIL|Kernel panic|BUG:|Out of memory: Killed process' "$out/$mode.log"; then
        exit 1
    fi
done
