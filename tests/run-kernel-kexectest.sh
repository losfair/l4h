#!/usr/bin/env bash
# Test an already built patch-0026 kernel, without preparing/committing sources.
# Usage: tests/run-kernel-kexectest.sh [build/kernel]
# Run against both x2APIC/PCID and xAPIC/no-PCID builds. KVM is the default;
# KEXEC_TEST_ACCEL=tcg works for xAPIC/no-PCID. KEXEC_TEST_CPUS defaults to "1 4".
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
kernel=$(realpath "${1:-$root/build/kernel}")
src=$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$kernel/CMakeCache.txt")
out=$root/build/kernel-kexectest-$(basename "$kernel")
mkdir -p "$out"
includes=("$kernel/libsel4/autoconf" "$kernel/gen_config" "$kernel/libsel4/gen_config"
          "$kernel/libsel4/include" "$kernel/libsel4/arch_include/x86"
          "$kernel/libsel4/sel4_arch_include/x86_64" "$src/libsel4/include"
          "$src/libsel4/arch_include/x86" "$src/libsel4/sel4_arch_include/x86_64"
          "$src/libsel4/sel4_plat_include/pc99" "$src/libsel4/mode_include/64")
cflags=()
for dir in "${includes[@]}"; do cflags+=(-I "$dir"); done
gcc -O2 -g -Wall -Wextra -Werror -Wno-unused-parameter -ffreestanding -fno-builtin \
    -fno-stack-protector -fno-pie -no-pie -mno-red-zone -mgeneral-regs-only -nostdlib \
    "${cflags[@]}" -Wl,-T,"$root/tests/sel4-kexec/linker.ld" -Wl,--build-id=none \
    "$root/tests/sel4-kexec/root.c" "$root/tests/sel4-kexec/entry.S" \
    "$src/libsel4/src/arch/x86_64/kexec.S" -o "$out/root.elf"
# QEMU's multiboot1 loader requires an ELF32 container for seL4's physical entry.
objcopy -O elf32-i386 "$kernel/kernel.elf" "$out/kernel32.elf"
accel=${KEXEC_TEST_ACCEL:-kvm}
cpu=host
if [ "$accel" = tcg ]; then cpu=max; fi
for cpus in ${KEXEC_TEST_CPUS:-1 4}; do
    status=0
    timeout 30 qemu-system-x86_64 -machine q35,accel="$accel" -cpu "$cpu" \
        -m 512 -smp "$cpus" -display none -monitor none -no-reboot \
        -serial "file:$out/serial-$cpus.log" -debugcon "file:$out/result-$cpus.log" \
        -device isa-debug-exit,iobase=0xf4,iosize=4 \
        -kernel "$out/kernel32.elf" -initrd "$out/root.elf" \
        >"$out/qemu-$cpus.log" 2>&1 || status=$?
    cat "$out/result-$cpus.log"
    if [ "$status" != 33 ] || ! grep -q 'KEXEC: PASS' "$out/result-$cpus.log"; then
        cat "$out/serial-$cpus.log" "$out/qemu-$cpus.log"
        echo "kexec test failed ($cpus CPUs, QEMU status $status)" >&2
        exit 1
    fi
done
