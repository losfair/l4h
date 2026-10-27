#!/usr/bin/env bash
# Free page reporting: QEMU drops the memory l4h does not use.  dom0 goes
# through phases (tests/guest/init-balloontest): idle, a guest filling
# 768 MiB, that guest destroyed, twice.  In each phase this script reads
# QEMU's resident memory, which must stay low while idle, rise with the
# guest and fall again once the guest is gone.
# BALLOONTEST_BASELINE=1 runs without the balloon device and only reports.
# BALLOONTEST_LEGACY=1 makes the balloon a legacy-only device.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
hold=12
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$l4h_linux_out/vmlinux.stripped"
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/balloonvm.cpio.gz" "$root/tests/guest/init-balloonvm" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/balloontest.cpio.gz" "$root/tests/guest/init-balloontest" \
    "$l4h_ctl" "$out/balloonvm.cpio.gz" >/dev/null
export L4H_GUEST_KERNEL="$l4h_linux_out/vmlinux.stripped" L4H_DOM0_INITRD="$out/balloontest.cpio.gz"
L4H_DOM0_MEM_MB=256 L4H_DOM0_VCPUS=1 L4H_WATCHDOG_SECS=0 \
    L4H_DOM0_CMDLINE="console=hvc0 BT_HOLD=$((hold * l4h_test_slow))" "$l4h_host_build"

baseline=${BALLOONTEST_BASELINE:-0}
log=$root/build/qemu.log
rm -f "$log"
balloon=$((1 - baseline))
[ "${BALLOONTEST_LEGACY:-0}" = 1 ] && [ "$baseline" = 0 ] && balloon=legacy
L4H_BALLOON=$balloon L4H_MEM=${L4H_MEM:-4G} \
    "$l4h_qemu" "$root/host/target/$l4h_target/debug/l4h-root.elf" </dev/null >"$log" 2>&1 &
qemu=$!
trap 'kill $qemu 2>/dev/null || true' EXIT
rss() { awk '/^VmRSS:/ { print int($2 / 1024) }' "/proc/$qemu/status"; }

declare -A mib
end=$((SECONDS + 300 * l4h_test_slow))
for phase in idle filled1 destroyed1 filled2 destroyed2; do
    until grep -aq "BALLOONTEST: phase $phase\$" <(tr -d '\r' < "$log"); do
        if grep -aq "BALLOONTEST: FAIL\|panic" "$log" || ! kill -0 $qemu 2>/dev/null || [ $SECONDS -ge $end ]; then
            sed -n '/l4h-root:/,$p' "$log" | grep -aE "BALLOON|balloon|panic|fault" || true
            echo "balloontest: FAIL (no phase $phase)"
            exit 1
        fi
        sleep 0.5
    done
    # Blocks are reported after two seconds free; leave time for QEMU to
    # drop them, but measure before dom0 moves on.
    sleep $((hold * l4h_test_slow - 3))
    mib[$phase]=$(rss)
    echo "balloontest: $phase: QEMU uses ${mib[$phase]} MiB"
done
grep -a "balloon:" "$log" | tr -d '\r' | sed -n '1p;$p'
fail=0
check() { if ! eval "$1"; then echo "balloontest: FAIL: $2"; fail=1; fi; }
if [ "$baseline" = 0 ]; then
    if [ "$balloon" = legacy ]; then
        check "grep -aq 'balloon: free page reporting on legacy queue' '$log'" "no legacy balloon device"
    else
        check "grep -aq 'balloon: free page reporting on queue' '$log'" "no balloon device"
    fi
    check "[ ${mib[idle]} -lt 1024 ]" "idle uses ${mib[idle]} MiB"
    for r in 1 2; do
        check "[ ${mib[filled$r]} -ge $((mib[idle] + 600)) ]" "the guest's data is not resident in round $r"
        check "[ ${mib[destroyed$r]} -le $((mib[idle] + 128)) ]" \
            "round $r: ${mib[destroyed$r]} MiB after destroy, ${mib[idle]} MiB idle"
    done
fi
[ $fail = 0 ] && echo "balloontest: PASS"
exit $fail
