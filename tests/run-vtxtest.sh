#!/usr/bin/env bash
# VT-x in the kernel (patch 0038, DESIGN.md §4.1), below l4h-root: boot
# seL4 with tests/vtxprobe.c as the root task on 4 cores and check which
# VT-x objects it can create.
# Usage: run-vtxtest.sh off|on|skim
#   off   a CPU without VMX (-cpu host,-vmx): the kernel boots without VT-x
#         and refuses VCPU and EPT objects.
#   on    a CPU with VMX (-cpu host; needs nested KVM on an Intel host):
#         every core enters VMX operation, the objects are created and the
#         VCPU binds to a TCB.
#   skim  the SKIM variant (L4H_KERNEL_VARIANT, default skim-xapic-nopcid)
#         keeps VT-x off whatever the CPU has.
# L4H_QEMU_CPU overrides the CPU model, L4H_KERNEL_VARIANT the kernel
# (build/sel4-VARIANT) and L4H_QEMU_ACCEL the accelerator (tcg to try it
# without KVM, on an xAPIC/no-PCID variant).  Needs tools/build-kernel.sh.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
mode=${1:?usage: run-vtxtest.sh off|on|skim}
variant=${L4H_KERNEL_VARIANT:-}
case "$mode" in
    off) cpu=host,-vmx,+invtsc ;;
    on) cpu=host,+invtsc ;;
    skim) variant=${variant:-skim-xapic-nopcid}
        cpu=host,vendor=GenuineIntel,-vmx,+invtsc,-arch-capabilities,-pcid,-invpcid,-x2apic ;;
    *) echo "usage: run-vtxtest.sh off|on|skim" >&2; exit 2 ;;
esac
cpu=${L4H_QEMU_CPU:-$cpu}
# The probe's object numbering must match the default libsel4 build, as
# l4h-root's does on every variant.
inc=$root/build/sel4/libsel4/include
kernel=$root/build/sel4${variant:+-$variant}/bin/kernel.elf
out=$root/build/vtxtest${variant:+-$variant}
mkdir -p "$out"
gcc -O2 -static -nostdlib -ffreestanding -fno-pic -no-pie -fno-stack-protector \
    -fcf-protection=none -mno-red-zone -mfsgsbase -I"$inc" -I"$inc/sel4" \
    -Wl,-z,max-page-size=4096 -Wl,-e,_start -Wl,--build-id=none \
    -o "$out/vtxprobe.elf" "$root/tests/vtxprobe.c"
objcopy -O elf32-i386 "$kernel" "$out/kernel32.elf"
log=$out/serial-$mode.log
rm -f "$log"
qemu-system-x86_64 -accel "${L4H_QEMU_ACCEL:-kvm}" -cpu "$cpu" -smp 4 -m 512M \
    -display none -monitor none -serial "file:$log" -no-reboot \
    -kernel "$out/kernel32.elf" -initrd "$out/vtxprobe.elf" 2>"$out/qemu-$mode.err" &
qemu=$!
trap 'kill $qemu 2>/dev/null || true' EXIT
for _ in $(seq 120); do
    grep -q 'vtxprobe: done' "$log" 2>/dev/null && break
    kill -0 $qemu 2>/dev/null || break
    sleep 0.5
done
kill $qemu 2>/dev/null || true
wait $qemu 2>/dev/null || true
trap - EXIT
fail() {
    echo "VTXTEST($mode): FAIL: $*" >&2
    tr -d '\r' <"$log" | grep -a -E 'vt-x|vtxprobe|fail|halting' >&2 || true
    exit 1
}
grep -aq 'vtxprobe: done' "$log" || fail "the probe did not finish"
# seL4_InvalidArgument is 1.
case "$mode" in
    off) grep -aq 'vt-x: unavailable; booting without it' "$log" || fail "VT-x was not reported unavailable" ;;
    skim) grep -aq 'vt-x: off with the SKIM window' "$log" || fail "SKIM did not turn VT-x off" ;;
    on) ! grep -aq 'vt-x: unavailable\|vt-x: off' "$log" || fail "VT-x is off" ;;
esac
for object in vcpu ept_pml4 ept_pt; do
    if [ "$mode" = on ]; then
        grep -aq "vtxprobe: $object ok" "$log" || fail "$object was not created"
    else
        grep -aq "vtxprobe: $object err=1" "$log" || fail "$object was not refused"
    fi
done
grep -aq 'vtxprobe: tcb ok' "$log" || fail "a TCB was not created"
if [ "$mode" = on ]; then
    grep -aq 'vtxprobe: vcpu_set_tcb ok' "$log" || fail "the VCPU did not bind to a TCB"
fi
echo "VTXTEST($mode): PASS"
