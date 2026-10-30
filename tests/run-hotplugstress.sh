#!/usr/bin/env bash
# Memory hotplug under stress (DESIGN.md §17): three 2-vCPU VMs under
# memory load (tests/guest/hpstress.c, smp_mm_stress, tmpfs) resized to
# random targets every few seconds, oversubscribing the host, with VMs
# destroyed in the middle of a resize (tests/guest/init-hotplugstress).
# Usage: run-hotplugstress.sh [rounds]
# HPSTRESS_THP=1 enables THP throughout the workload guests.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
rounds=${1:-90}
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$l4h_linux_out/vmlinux.stripped"
"$root/tools/build-l4hctl.sh"
"$l4h_cc" -O2 -static -pthread -o "$out/hpstress" "$root/tests/guest/hpstress.c"
"$l4h_cc" -O2 -static -pthread -o "$out/selftest" "$root/tests/guest/selftest.c"
"$root/tools/mkinitramfs.sh" "$out/hpstressvm.cpio.gz" "$root/tests/guest/init-hpstressvm" \
    "$out/hpstress" "$out/selftest" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/hotplugstress.cpio.gz" "$root/tests/guest/init-hotplugstress" \
    "$l4h_ctl" "$out/hpstressvm.cpio.gz" >/dev/null
L4H_DOM0_MEM_MB=256 L4H_MEM=${L4H_MEM:-4G} \
    "$root/tools/run-dom0.sh" "$out/hotplugstress.cpio.gz" "console=hvc0 HS_ROUNDS=$rounds HS_THP=${HPSTRESS_THP:-0}" \
    $(((300 + 6 * rounds) * l4h_test_slow)) \
    | grep -aE "HOTPLUGSTRESS|HPSTRESS|HPVM: (status|TMPFS|SELFTEST|HPSTRESS)|panic|BUG|WARNING|kernel fault" || true
grep -aq "HOTPLUGSTRESS: PASS" "$root/build/qemu.log"
