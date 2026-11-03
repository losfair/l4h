#!/usr/bin/env bash
# Host (blkd) AES-XTS vs guest dm-crypt: 3.5 MiB O_DIRECT sequential and
# 4 KiB QD1 random I/O, plus guest CPU use, on one virtio-blk window.
# Kinds: plain, blkd (key-file attach), dmcrypt, dmcrypt-nowq (dm-crypt with
# no_read_workqueue/no_write_workqueue). Prints per-run results and medians.
# CRYPTBENCH_REPS (default 3), CRYPTBENCH_KINDS and CRYPTBENCH_VCPUS
# (space-separated) select the runs.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=tools/guest-env.sh
source "$root/tools/guest-env.sh"
reps=${CRYPTBENCH_REPS:-3}
kinds=${CRYPTBENCH_KINDS:-plain blkd dmcrypt dmcrypt-nowq}
vcpus=${CRYPTBENCH_VCPUS:-1 4}
out=$root/build/cryptbench-${L4H_ARCH:-x86_64}
mkdir -p "$out"
"$root/tools/build-l4hctl.sh"
"$l4h_cc" -O2 -static "$root/tests/guest/cryptbench.c" -o "$out/cryptbench"
"$l4h_cc" -O2 -static "$root/tests/guest/dmcrypt-setup.c" -o "$out/dmcrypt-setup"
"$root/tools/mkinitramfs.sh" "$out/cryptbenchvm.cpio.gz" "$root/tests/guest/init-cryptbenchvm" \
    "$out/cryptbench" "$out/dmcrypt-setup" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-cryptbench" \
    "$l4h_ctl" "$out/cryptbenchvm.cpio.gz" >/dev/null
export L4H_GUEST_KERNEL=${L4H_TEST_KERNEL:-$l4h_linux_out/vmlinux.stripped} L4H_DOM0_INITRD="$out/dom0.cpio.gz" L4H_GUEST_KMODS=
L4H_DOM0_DISKS=0 L4H_DOM0_MEM_MB=256 L4H_WATCHDOG_SECS=0 "$l4h_host_build" > "$out/build.log" 2>&1
rm -f "$out/disk.raw" && truncate -s 64M "$out/disk.raw"
printf 'dom0_disks=0\ndom0_mem_mb=256\nwatchdog_secs=0\ndom0_cmdline="console=hvc0 reps=%s kinds=%s cpus=%s"\n' \
    "$reps" "${kinds// /+}" "${vcpus// /+}" > "$out/config"
L4H_CONFIG="$out/config" "$l4h_qemu" "$root/host/target/$l4h_target/debug/l4h-root.elf" \
    -drive "file=$out/disk.raw,if=none,id=d0,format=raw,cache=none,aio=native" \
    -device virtio-blk-pci,drive=d0,disable-legacy=on > "$out/run.log" 2>&1 &
qemu=$!
trap 'kill "$qemu" 2>/dev/null || true' EXIT
end=$((SECONDS + 300 * reps * l4h_test_slow))
while kill -0 "$qemu" 2>/dev/null && [ "$SECONDS" -lt "$end" ]; do
    grep -aqE 'DOM0: ALL DONE|panicked at' "$out/run.log" && break
    sleep 2
done
sleep 2
kill "$qemu" 2>/dev/null || true; wait "$qemu" 2>/dev/null || true
# Guest lines appear both on the VM console and in dom0's copy; keep dom0's.
grep -a '^RESULT' "$out/run.log" > "$out/results" || true
cat "$out/results"
echo "medians over $reps run(s):"
sort -k2,2 -k3,3 -k4,4n "$out/results" | awk '
    function flush() { if (n) printf "  %-22s %-13s %10.1f %s\n", key, test, v[int((n + 1) / 2)], unit; n = 0 }
    { if ($2 != key || $3 != test) { flush(); key = $2; test = $3; unit = $5 } v[++n] = $4 }
    END { flush() }'
! grep -aqE 'FAIL|MISMATCH' "$out/run.log"
grep -aq 'DOM0: ALL DONE' "$out/run.log"
