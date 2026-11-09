#!/usr/bin/env bash
# VT-x and AMD-V in the kernel (patches 0038 and 0040, DESIGN.md §4.1), below
# l4h-root: boot seL4 with tests/vtxprobe.c as the root task on 4 cores and
# check which VCPU and EPT objects it can create.  The host's CPU decides
# which: VT-x on Intel, SVM on AMD.
# Usage: run-vtxtest.sh off|on|skim
#   off   a CPU without VMX or SVM (-cpu host,-vmx,-svm): the kernel boots
#         without them and refuses VCPU and EPT objects.
#   on    a CPU with VMX or SVM (-cpu host; needs nested KVM): every core
#         enters VMX operation or enables SVM, the objects are created and
#         the VCPU binds to a TCB.  On AMD the probe also runs a real-mode
#         guest to an I/O exit, a nested page fault and a HLT, and checks
#         that seL4 keeps its intercepts and VMCB fields.
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
    off) cpu=host,-vmx,-svm,+invtsc ;;
    on) cpu=host,+invtsc ;;
    skim) variant=${variant:-skim-xapic-nopcid}
        cpu=host,vendor=GenuineIntel,-vmx,+invtsc,-arch-capabilities,-pcid,-invpcid,-x2apic ;;
    *) echo "usage: run-vtxtest.sh off|on|skim" >&2; exit 2 ;;
esac
cpu=${L4H_QEMU_CPU:-$cpu}
# The kernel's messages say "vt-x" or "svm", by the vendor it sees.
virt=vt-x
if [ "$mode" != skim ] && grep -q '^vendor_id.*AuthenticAMD' /proc/cpuinfo; then
    virt=svm
fi
# The probe's object numbering must match the default libsel4 build, as
# l4h-root's does on every variant.
inc=$root/build/sel4/libsel4/include
kernel=$root/build/sel4${variant:+-$variant}/bin/kernel.elf
out=$root/build/vtxtest${variant:+-$variant}
mkdir -p "$out"
gcc -O2 -static -nostdlib -ffreestanding -fno-pic -no-pie -fno-stack-protector \
    -fcf-protection=none -mno-red-zone -I"$inc" -I"$inc/sel4" \
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
    tr -d '\r' <"$log" | grep -a -E 'vt-x|svm|vtxprobe|fail|halting' >&2 || true
    exit 1
}
grep -aq 'vtxprobe: done' "$log" || fail "the probe did not finish"
# seL4_InvalidArgument is 1.
case "$mode" in
    off) grep -aq "$virt: unavailable; booting without it" "$log" || fail "$virt was not reported unavailable" ;;
    skim) grep -aq 'vt-x: off with the SKIM window' "$log" || fail "SKIM did not turn VT-x off" ;;
    on) ! grep -aq "$virt: unavailable\|$virt: off" "$log" || fail "$virt is off" ;;
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
    # Patch 0039: seL4 loads KERNEL_GS_BASE with WRMSR before VM entry.
    grep -aq 'vtxprobe: kgs_canonical ok' "$log" || fail "a canonical KERNEL_GS_BASE was refused"
    grep -aq 'vtxprobe: kgs_noncanonical err=1' "$log" || fail "a noncanonical KERNEL_GS_BASE was accepted"
    grep -aq 'vtxprobe: flush_tlb ok' "$log" || fail "VCPU_FlushTLB failed"
fi
if [ "$mode" = on ] && [ "$virt" = vt-x ]; then
    # Patch 0042: the CR4 bits outside the allowlist stay in the CR4 mask
    # and out of GUEST_CR4.
    grep -aq 'vtxprobe: vmx_cr4_mask ok' "$log" || fail "a CR4 bit outside the allowlist left the CR4 guest/host mask"
    grep -aq 'vtxprobe: vmx_guest_cr4 ok' "$log" || fail "a CR4 bit outside the allowlist was written to GUEST_CR4"
    # Patches 0039 and 0043: MOV-DR and CR8 accesses always exit.
    grep -aq 'vtxprobe: vmx_ppc_forced ok' "$log" || fail "MOV-DR or CR8-load/store exiting was cleared"
    # Patch 0039: WBINVD always exits.
    grep -aq 'vtxprobe: vmx_spc_forced ok' "$log" || fail "EPT or WBINVD exiting was cleared"
fi
if [ "$mode" = on ] && [ "$virt" = svm ]; then
    # Patch 0040.  seL4_IllegalOperation is 3.
    grep -aq 'vtxprobe: svm_forced_intercepts ok' "$log" || fail "an intercept seL4 needs was cleared"
    grep -aq 'vtxprobe: svm_forced_invd ok' "$log" || fail "the INVD intercept was cleared"
    grep -aq 'vtxprobe: svm_owned_field err=3' "$log" || fail "a kernel-owned VMCB field was written"
    # Patch 0040: CR4 writes always exit and CR4 keeps only the allowed bits.
    grep -aq 'vtxprobe: svm_forced_cr4_write ok' "$log" || fail "the CR4 write intercept was cleared"
    grep -aq 'vtxprobe: svm_cr4_allowed ok' "$log" || fail "a CR4 bit outside the allowlist was written"
    for step in asid map bind io npf invd hlt tls_base invalid dirty_kept cr4_exit pkru_ud inject_exit; do
        grep -aq "vtxprobe: svm_$step ok" "$log" || fail "the guest failed at svm_$step"
    done
fi
echo "VTXTEST($mode): PASS"
