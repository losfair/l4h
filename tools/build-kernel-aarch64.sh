#!/usr/bin/env bash
# Build the patched seL4 kernel for aarch64 (QEMU virt) into build/sel4-aarch64.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
src=$root/build/seL4-src
out=$root/build/kernel-aarch64
prefix=$root/build/sel4-aarch64
source "$root/tools/aarch64-memory.sh"
export PATH=$root/.venv/bin:$PATH
source "$root/tools/prepare-kernel.sh"
debug=ON
[ "${L4H_RELEASE:-0}" = 1 ] && debug=OFF
config=$root/kernel/configs/l4h-aarch64.cmake
[ "$config" -nt "$out/CMakeCache.txt" ] && rm -rf "$out"
cmake -DCMAKE_C_FLAGS="$l4h_prefix_map" -DCMAKE_ASM_FLAGS="$l4h_prefix_map" -G Ninja -S "$src" -B "$out" \
    -C "$config" \
    -DKernelDebugBuild=$debug \
    -DQEMU_MEMORY="$l4h_memory_mb" \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCROSS_COMPILER_PREFIX=aarch64-linux-gnu- >/dev/null
ninja -C "$out" all
ninja -C "$out" install >/dev/null
echo "$l4h_memory_mb" > "$l4h_memory_stamp"
echo "kernel installed to $prefix"
