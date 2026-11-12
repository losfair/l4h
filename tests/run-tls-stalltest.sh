#!/usr/bin/env bash
# x86 SMP must preserve userspace FS/GS changes across remote TCB stalls.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/tls-stall
sel4=$root/build/sel4${L4H_KERNEL_VARIANT:+-$L4H_KERNEL_VARIANT}
inc=$root/build/sel4/libsel4/include
mkdir -p "$out"
gcc -O2 -Wall -Wextra -Werror -static -nostdlib -ffreestanding -fno-pic -no-pie -fno-stack-protector \
    -fcf-protection=none -mno-red-zone -I"$inc" -I"$inc/sel4" \
    -Wl,-z,max-page-size=4096 -Wl,-e,_start -Wl,--build-id=none \
    -o "$out/tls-stall.elf" "$root/tests/tls-stall.c"
objcopy -O elf32-i386 "$sel4/bin/kernel.elf" "$out/kernel32.elf"
variant=${L4H_KERNEL_VARIANT:-debug}
log=$out/serial-$variant.log
rm -f "$log"
qemu-system-x86_64 -enable-kvm -cpu host,-vmx,-svm,+invtsc -smp 2 -m 512M \
    -display none -monitor none -serial "file:$log" -no-reboot \
    -kernel "$out/kernel32.elf" -initrd "$out/tls-stall.elf" >"$out/qemu-$variant.log" 2>&1 &
qemu=$!
trap 'kill "$qemu" 2>/dev/null || true' EXIT
for _ in $(seq 120); do
    grep -aq 'TLSSTALL: \(PASS\|FAIL\)' "$log" 2>/dev/null && break
    kill -0 "$qemu" 2>/dev/null || break
    sleep 0.5
done
kill "$qemu" 2>/dev/null || true
wait "$qemu" 2>/dev/null || true
trap - EXIT
grep -aq 'TLSSTALL: PASS' "$log" || { tail -n 35 "$log" >&2; exit 1; }
grep -a 'TLSSTALL:' "$log"
