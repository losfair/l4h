#!/usr/bin/env bash
# Build the pinned FL4 kernel and its libsel4 in build/sel4-fl4.
# L4H_FL4_SOURCE overrides the pin with a frozen worktree for development.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
source "$root/tools/prepare-fl4.sh"
out=$root/build/kernel-fl4
prefix=$root/build/sel4-fl4
export PATH=$root/.venv/bin:$PATH
debug=ON
[ "${L4H_RELEASE:-0}" = 1 ] && debug=OFF
cmake -DCMAKE_C_FLAGS="$l4h_prefix_map" -DCMAKE_ASM_FLAGS="$l4h_prefix_map" -G Ninja -S "$root/kernel/fl4" -B "$out" \
    -DFL4_SOURCE="$src" \
    -DCARGO="$root/tools/cargo-fl4.sh" \
    -C "$root/kernel/configs/l4h-x86_64.cmake" \
    -DKernelVTX=ON -DKernelX86_64VTX64BitGuests=ON -DKernelDebugBuild="$debug" \
    -DKernelRetypeFanOutLimit=256 \
    -DLibSel4PrintInvocationErrors=0
ninja -C "$out"
mkdir -p "$prefix/bin" "$prefix/libsel4/include"
cp "$out/kernel/kernel.elf" "$prefix/bin/kernel.elf"
# Resolve FL4's relative interface/header symlinks into the installed tree.
for d in \
    "$src/libsel4/include" \
    "$src/libsel4/arch_include/x86" \
    "$src/libsel4/sel4_arch_include/x86_64" \
    "$src/libsel4/sel4_plat_include/pc99" \
    "$src/libsel4/mode_include/64" \
    "$out/libsel4/include" \
    "$out/libsel4/arch_include/x86" \
    "$out/libsel4/sel4_arch_include/x86_64" \
    "$out/kernel/gen_config" \
    "$out/libsel4/gen_config" \
    "$out/libsel4/autoconf"; do
    cp -rL "$d/." "$prefix/libsel4/include/"
done
# rust-sel4 generates its invocations from interfaces/object-api*.xml
# alone: install the architecture interface with FL4's extensions
# (seL4_Untyped_RetypeShared) appended, as FL4's own invocation.h has them.
cp "$out/libsel4/arch-invocation-labels.xml" "$prefix/libsel4/include/interfaces/object-api-arch.xml"
printf '%s\n' "$base" >"$prefix/fl4-revision"
echo "FL4 installed to $prefix (debug build: $debug)"
