#!/usr/bin/env bash
# Boot a Linux guest that runs the kernel's BPF test vectors (lib/test_bpf.c,
# built as an external module) and tests/guest/bpftest.c through the BPF
# JIT: verified XDP and tc programs, direct tail calls patched in and out,
# and XDP (generic) and tcx programs on lo.  On x86_64 the guest has
# 2 GiB, so that vmalloc is out of rel32 reach of the kernel image
# (arch/l4h/x86/bpf_jit.c).  On aarch64, L4H_QEMU_CPU=max gives a CPU with
# LSE atomics, which the JIT then uses instead of LL/SC.
# Usage: run-bpftest.sh [vcpus]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest/bpf
mkdir -p "$out"
echo 'obj-m += test_bpf.o' >"$out/Makefile"
cp "$root/build/linux-6.18/lib/test_bpf.c" "$out/"
"$root/tools/build-linux.sh" vmlinux modules >"$root/build/linux-build.log" 2>&1
"$root/tools/build-linux.sh" M="$out" modules >"$root/build/bpf-build.log" 2>&1
"$l4h_cc" -O2 -static -o "$out/bpftest" "$root/tests/guest/bpftest.c"
"$root/tools/mkinitramfs.sh" "$out/bpftest.cpio.gz" "$root/tests/guest/init-bpftest" \
    "$out/test_bpf.ko" "$out/bpftest" >/dev/null
mem=2048
[ "${L4H_ARCH:-x86_64}" = aarch64 ] && mem=512
L4H_DOM0_MEM_MB=$mem L4H_DOM0_VCPUS=${1:-2} "$root/tools/run-dom0.sh" "$out/bpftest.cpio.gz" \
    console=hvc0 "${L4H_TEST_TIMEOUT:-$((300 * l4h_test_slow))}" \
    | grep -a "test_bpf: .*Summary\|BPFTEST" || true
grep -q "BPFTEST: PASS" "$root/build/qemu.log"
! grep -q "WARNING:\|BUG:" "$root/build/qemu.log" || exit 1
! grep -a "test_bpf: .*Summary" "$root/build/qemu.log" | grep -qv " 0 FAILED" || exit 1
# Every test_bpf program was JIT-compiled.
! grep -ao "\[[0-9]*/[0-9]* JIT'ed\]" "$root/build/qemu.log" | awk -F'[][/ ]' '$2 != $3' | grep -q . || exit 1
