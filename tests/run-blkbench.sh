#!/usr/bin/env bash
# Plain/bounced and encrypted sequential read/write. Optionally supply an
# already-built pre-bounce root ELF as L4H_BENCH_BASELINE_ROOT for "before".
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=tools/guest-env.sh
source "$root/tools/guest-env.sh"
out=$root/build/blkbench-${L4H_ARCH:-x86_64}
mkdir -p "$out"
"$root/tools/build-l4hctl.sh"
"$l4h_cc" -O2 -static "$root/tests/guest/cryptblk.c" -o "$out/cryptblk"
"$root/tools/mkinitramfs.sh" "$out/cryptblkvm.cpio.gz" "$root/tests/guest/init-cryptblkvm" "$out/cryptblk" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-blkbench" "$l4h_ctl" "$out/cryptblkvm.cpio.gz" >/dev/null
export L4H_GUEST_KERNEL=${L4H_TEST_KERNEL:-$l4h_linux_out/vmlinux.stripped} L4H_DOM0_INITRD="$out/dom0.cpio.gz" L4H_GUEST_KMODS=
L4H_DOM0_DISKS=0 L4H_DOM0_MEM_MB=256 L4H_WATCHDOG_SECS=0 "$l4h_host_build" > "$out/build.log" 2>&1
truncate -s 64M "$out/disk.raw"
# Copy a supplied ELF before adding boot modules: no changes to its build.
phases=(after)
if [ -n "${L4H_BENCH_BASELINE_ROOT:-}" ]; then
    cp "$L4H_BENCH_BASELINE_ROOT" "$out/before.elf"
    phases=(before after)
fi
cp "$root/host/target/$l4h_target/debug/l4h-root.elf" "$out/after.elf"
qemu=
trap 'if [ -n "$qemu" ]; then kill "$qemu" 2>/dev/null || true; wait "$qemu" 2>/dev/null || true; fi' EXIT
for phase in "${phases[@]}"; do
    [ -f "$out/$phase.elf" ] || continue
    printf 'dom0_disks=0\ndom0_mem_mb=256\nwatchdog_secs=0\ndom0_cmdline="console=hvc0 baseline=%s"\n' "$([ "$phase" = before ] && echo 1 || echo 0)" > "$out/config"
    L4H_CONFIG="$out/config" "$l4h_qemu" "$out/$phase.elf" \
        -drive "file=$out/disk.raw,if=none,id=d0,format=raw,cache=none,aio=native" \
        -device virtio-blk-pci,drive=d0,disable-legacy=on > "$out/$phase.log" 2>&1 &
    qemu=$!
    end=$((SECONDS + 300 * l4h_test_slow))
    while kill -0 "$qemu" 2>/dev/null && [ "$SECONDS" -lt "$end" ]; do
        if grep -aqE 'BLKBENCH: (PASS|FAIL)|panicked at' "$out/$phase.log"; then break; fi
        sleep 1
    done
    kill "$qemu" 2>/dev/null || true; wait "$qemu" 2>/dev/null || true; qemu=
    grep -a 'BENCH:' "$out/$phase.log" | sed "s/BENCH: disk/BENCH: $phase disk/"
    grep -aq 'BLKBENCH: PASS' "$out/$phase.log"
done
