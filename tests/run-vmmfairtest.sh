#!/usr/bin/env bash
# The real kernel must share CPU after VMM demotion and reject self-boosts.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/vmmfairtest
inc=$root/build/sel4/libsel4/include
mkdir -p "$out"
rustc +stable --edition=2024 --crate-name l4h_abi --crate-type rlib \
    "$root/host/l4h-abi/src/lib.rs" -o "$out/libl4h_abi.rlib"
rustc +stable --edition=2024 --crate-name l4h_host --crate-type rlib \
    --extern l4h_abi="$out/libl4h_abi.rlib" "$root/host/l4h-host/src/lib.rs" -o "$out/libl4h_host.rlib"
cat >"$out/priorities.rs" <<'RS'
#[allow(dead_code)]
#[path = "../../host/l4h-vmmgr/src/sched/budget.rs"] mod budget;
fn main() {
    let p = budget::background(budget::plan(5000, 0, 0, 500, Some(250)), 1);
    println!("#define VMM_PRIO {}\n#define VMM_FAIR {}\n#define GUEST_USER {}\n#define GUEST_KERNEL {}\n#define BG_BUDGET {}\n#define BG_PERIOD {}\n#define SC_BITS {}\n#define SC_REFILLS {}",
        l4h_host::PRIO_VMM, l4h_host::PRIO_VMM_FAIR, l4h_abi::PRIO_USER, l4h_abi::PRIO_KERNEL,
        p.vmm, p.vmm_period, l4h_host::GUEST_SC_BITS, l4h_host::GUEST_EXTRA_REFILLS);
}
RS
rustc +stable --edition=2024 -L dependency="$out" --extern l4h_host="$out/libl4h_host.rlib" --extern l4h_abi="$out/libl4h_abi.rlib" \
    "$out/priorities.rs" -o "$out/priorities"
"$out/priorities" >"$out/vmm-priorities.h"
gcc -O2 -Wall -Wextra -Werror -static -nostdlib -ffreestanding -fno-pic -no-pie -fno-stack-protector \
    -fcf-protection=none -mno-red-zone -I"$inc" -I"$inc/sel4" -I"$out" \
    -Wl,-z,max-page-size=4096 -Wl,-e,_start -Wl,--build-id=none \
    -o "$out/vmm-fair.elf" "$root/tests/vmm-fair.c"
objcopy -O elf32-i386 "$root/build/sel4${L4H_KERNEL_VARIANT:+-$L4H_KERNEL_VARIANT}/bin/kernel.elf" "$out/kernel32.elf"
log=$out/serial.log
rm -f "$log"
qemu-system-x86_64 -enable-kvm -cpu host,-vmx,-svm,+invtsc -smp 2 -m 512M \
    -display none -monitor none -serial "file:$log" -no-reboot \
    -kernel "$out/kernel32.elf" -initrd "$out/vmm-fair.elf" >"$out/qemu.log" 2>&1 &
qemu=$!
trap 'kill "$qemu" 2>/dev/null || true' EXIT
for _ in $(seq 60); do
    grep -aq 'VMMFAIR: \(PASS\|FAIL\)' "$log" 2>/dev/null && break
    kill -0 "$qemu" 2>/dev/null || break
    sleep 0.5
done
kill "$qemu" 2>/dev/null || true
wait "$qemu" 2>/dev/null || true
trap - EXIT
grep -aq 'VMMFAIR: PASS' "$log" || { cat "$log" >&2; exit 1; }
grep -a 'VMMFAIR:' "$log"
