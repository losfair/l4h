#!/usr/bin/env bash
# Build the guest ABI provider against the selected libsel4. Linux and its
# modules never see these headers. vmmgr's build.rs embeds the raw image.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
arch=${L4H_ARCH:-x86_64}
case "$arch" in
    x86_64) cross=; prefix=$root/build/sel4
        isa=(-mcmodel=large -m64 -mno-red-zone -mno-sse -mno-mmx -mno-sse2 -mno-avx) ;;
    aarch64) cross=${CROSS_COMPILE:-aarch64-linux-gnu-}; prefix=$root/build/sel4-aarch64
        isa=(-mcmodel=large -mgeneral-regs-only -mno-outline-atomics) ;;
    *) echo "unsupported L4H_ARCH: $arch" >&2; exit 1 ;;
esac
prefix=${SEL4_PREFIX:-$prefix}
out=$prefix/guest-provider
mkdir -p "$out"
exec 9>"$out/.lock"
flock 9
flags=(-O2 -g -std=gnu11 -ffreestanding -fno-common -fno-builtin -fno-strict-aliasing
    -fno-stack-protector -fno-pic -fno-pie -ftls-model=local-exec
    -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-delete-null-pointer-checks
    -ffile-prefix-map="$root"=. -ffunction-sections -fdata-sections -Wall -Wextra -Wno-unused-parameter
    -Wno-unused-function -nostdinc -isystem "$("${cross}gcc" -print-file-name=include)"
    -I"$prefix/libsel4/include" -I"$root/include" -I"$root/guest/provider")
# FL4's X86PML4FrameBatch, if this libsel4 has it (seL4's has not).
if grep -qs '\bX86PML4FrameBatch\b' "$prefix/libsel4/include/sel4/arch/invocation.h"; then
    flags+=(-DL4H_HAVE_FRAME_BATCH)
fi
objects=()
for name in sys events user kvm cpu table; do
    "${cross}gcc" "${flags[@]}" "${isa[@]}" -c "$root/guest/provider/$name.c" -o "$out/$name.o"
    objects+=("$out/$name.o")
done
"${cross}ld" --gc-sections --no-undefined -T "$root/guest/provider/provider.lds" \
    -o "$out/provider.elf" "${objects[@]}"
"${cross}objcopy" -O binary "$out/provider.elf" "$out/provider.bin.new"
cmp -s "$out/provider.bin.new" "$out/provider.bin" && rm "$out/provider.bin.new" \
    || mv "$out/provider.bin.new" "$out/provider.bin"
