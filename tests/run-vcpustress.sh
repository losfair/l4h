#!/usr/bin/env bash
# SMP stress of the VCPU interface (patches 0039 and 0040, DESIGN.md §5.10),
# below l4h-root: boot seL4 with tests/vcpustress.c as the root task on 4
# cores.  Two threads keep a guest in seL4_VMEnter while two others invoke,
# signal, stall, rebind and finally delete what they run on; the kernel must
# survive, and every VMEnter must return what the guest did.  Three runs:
#   smp       the guests on cores 1 and 2, the attackers on cores 0 and 3
#   step      the same with RFLAGS.TF set in the guests: every instruction
#             is a #DB exit, so a dropped exit or a discarded VMEnter result
#             shows as an instruction the guest passed without one
#   onecore   every thread on core 0: the guests are preempted in guest mode
# Usage: run-vcpustress.sh [rounds]     (default 40, of 500 operations each)
# Needs tools/build-kernel.sh, and VT-x or AMD-V in the VM (-cpu host under
# nested KVM): without them the kernel creates no VCPU and the test says it
# was skipped.  QEMU's TCG emulates AMD-V without next-RIP saving, which
# patch 0040 requires, so it is skipped there too.
# L4H_QEMU_CPU overrides the CPU model, L4H_KERNEL_VARIANT the kernel
# (build/sel4-VARIANT) and L4H_QEMU_ACCEL the accelerator.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
rounds=${1:-40}
variant=${L4H_KERNEL_VARIANT:-}
cpu=${L4H_QEMU_CPU:-host,+invtsc}
# The numbering of objects and invocations must match the default libsel4
# build, as l4h-root's does on every variant.
inc=$root/build/sel4/libsel4/include
kernel=$root/build/sel4${variant:+-$variant}/bin/kernel.elf
out=$root/build/vcpustress${variant:+-$variant}
mkdir -p "$out"
objcopy -O elf32-i386 "$kernel" "$out/kernel32.elf"

run() {
    local mode=$1 log=$out/serial-$1.log
    shift
    # No FPU registers: the attackers turn the runners' FPU off and on.
    gcc -O2 -static -nostdlib -ffreestanding -fno-pic -no-pie -fno-stack-protector \
        -fcf-protection=none -mno-red-zone -mgeneral-regs-only -I"$inc" -I"$inc/sel4" \
        -DROUNDS="$rounds" "$@" \
        -Wl,-z,max-page-size=4096 -Wl,-e,_start -Wl,--build-id=none \
        -o "$out/vcpustress-$mode.elf" "$root/tests/vcpustress.c"
    rm -f "$log"
    qemu-system-x86_64 -accel "${L4H_QEMU_ACCEL:-kvm}" -cpu "$cpu" -smp 4 -m 512M \
        -display none -monitor none -serial "file:$log" -no-reboot \
        -kernel "$out/kernel32.elf" -initrd "$out/vcpustress-$mode.elf" 2>"$out/qemu-$mode.err" &
    local qemu=$!
    trap 'kill $qemu 2>/dev/null || true' EXIT
    for _ in $(seq 600); do
        grep -aq 'vcpustress: done\|vcpustress: FAIL\|vcpustress: .*skipped\|KERNEL EXCEPTION\|halting\.\.\.' \
            "$log" 2>/dev/null && break
        kill -0 $qemu 2>/dev/null || break
        sleep 0.5
    done
    kill $qemu 2>/dev/null || true
    wait $qemu 2>/dev/null || true
    trap - EXIT
    if grep -aq 'vcpustress: .*skipped' "$log"; then
        echo "VCPUSTRESS($mode): SKIP: no VT-x or AMD-V in the VM"
        return 0
    fi
    if ! grep -aq 'vcpustress: done' "$log" || grep -aq 'vcpustress: FAIL\|KERNEL EXCEPTION' "$log"; then
        echo "VCPUSTRESS($mode): FAIL" >&2
        tr -d '\r' <"$log" | sed 's/\x1b\[[0-9;]*m//g' |
            grep -a -E 'vcpustress|KERNEL EXCEPTION|^(Vector|IP):|halting|assert' | tail -30 >&2 || true
        exit 1
    fi
    echo "VCPUSTRESS($mode): PASS"
}

run smp
run step -DTFSTEP
run onecore -DONECORE
