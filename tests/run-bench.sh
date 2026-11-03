#!/usr/bin/env bash
# Micro-benchmarks: syscalls, faults, fork, pipes, block and network I/O.
# Usage: run-bench.sh [vcpus]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$l4h_linux_out/vmlinux.stripped"
"$root/tools/build-l4hctl.sh"
"$l4h_cc" -O2 -static -o "$out/bench" "$root/tests/guest/bench.c"
"$l4h_cc" -O2 -static -o "$out/netbench" "$root/tests/guest/netbench.c"
"$root/tools/mkinitramfs.sh" "$out/benchvm.cpio.gz" "$root/tests/guest/init-benchvm" "$out/netbench" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/benchsrc.cpio.gz" "$root/tests/guest/init-benchsrc" "$out/netbench" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/bench.cpio.gz" "$root/tests/guest/init-bench" \
    "$out/bench" "$l4h_ctl" \
    "$out/benchvm.cpio.gz" "$out/benchsrc.cpio.gz" >/dev/null
rm -f "$out/bench.img" && truncate -s 1G "$out/bench.img"
L4H_DOM0_VCPUS=${1:-1} L4H_DOM0_MEM_MB=512 \
L4H_QEMU_ARGS="-drive file=$out/bench.img,if=none,id=d0,format=raw,cache=none,aio=native -device virtio-blk-pci,drive=d0,disable-legacy=on" \
    "$root/tools/run-dom0.sh" "$out/bench.cpio.gz" "console=hvc0" 600 | grep -a "BENCH" || true
grep -aq "BENCH: done" "$root/build/qemu.log"
# Disk throughput, including host encryption; set L4H_BENCH_BASELINE_ROOT
# to an ELF from before bounce writes for a same-run plain-write baseline.
"$root/tests/run-blkbench.sh"
