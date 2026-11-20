#!/usr/bin/env bash
# Build the pinned FL4 kernel for AArch64 (any UEFI machine, built as QEMU
# virt) and its libsel4 in build/sel4-fl4-aarch64.  FL4 detects EL2 at
# boot: on it the kernel is a VHE hypervisor host, otherwise it runs at
# EL1 without virtualization.  L4H_FL4_SOURCE overrides the pin with a
# frozen worktree for development, as for tools/build-fl4.sh.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
source "$root/tools/prepare-fl4.sh"
out=$root/build/kernel-fl4-aarch64
prefix=$root/build/sel4-fl4-aarch64
export PATH=$root/.venv/bin:$PATH
debug=ON
[ "${L4H_RELEASE:-0}" = 1 ] && debug=OFF
config=$root/kernel/configs/l4h-aarch64.cmake
# NoKernelPrinting: FL4 on AArch64 gives the PL011's MMIO page to the root
# task (for l4h-logd) only with KernelPrinting off.  It still prints its
# whole boot log before it starts the root task, and then releases the
# UART (serial::release()).  Debug builds keep their other checks.
[ "$config" -nt "$out/CMakeCache.txt" ] && rm -rf "$out"
cmake -DCMAKE_C_FLAGS="$l4h_prefix_map" -DCMAKE_ASM_FLAGS="$l4h_prefix_map" -G Ninja -S "$root/kernel/fl4" -B "$out" \
    -DFL4_SOURCE="$src" \
    -DCARGO="$root/tools/cargo-fl4.sh" \
    -C "$config" \
    -DCROSS_COMPILER_PREFIX=aarch64-linux-gnu- \
    -DKernelDebugBuild="$debug" \
    -DNoKernelPrinting=ON \
    -DKernelRetypeFanOutLimit=256 \
    -DLibSel4PrintInvocationErrors=0
ninja -C "$out"
rm -rf "$prefix"
mkdir -p "$prefix/bin" "$prefix/libsel4/include"
cp "$out/kernel/kernel.elf" "$prefix/bin/kernel.elf"
# Resolve FL4's relative interface/header symlinks into the installed tree.
for d in \
    "$src/libsel4/include" \
    "$src/libsel4/arch_include/arm" \
    "$src/libsel4/sel4_arch_include/aarch64" \
    "$src/libsel4/sel4_plat_include/qemu-arm-virt" \
    "$src/libsel4/mode_include/64" \
    "$out/libsel4/include" \
    "$out/libsel4/arch_include/arm" \
    "$out/libsel4/sel4_arch_include/aarch64" \
    "$out/kernel/gen_config" \
    "$out/libsel4/gen_config" \
    "$out/libsel4/autoconf"; do
    cp -rL "$d/." "$prefix/libsel4/include/"
done
# rust-sel4 generates its invocations from interfaces/object-api*.xml
# alone: install the architecture interface with FL4's extensions
# (seL4_Untyped_RetypeShared) appended, as FL4's own invocation.h has them.
cp "$out/libsel4/arch-invocation-labels.xml" "$prefix/libsel4/include/interfaces/object-api-arch.xml"
# FL4 has the EL2 faults (VGICMaintenance, VCPUFault, VPPIEvent) on every
# AArch64 kernel, but its configuration says no hypervisor support, the
# condition under which rust-sel4 knows them.  rust-sel4 alone reads the
# preprocessed bitfields (.pbf): leave the three tags out of its copy, so
# that it builds unpatched.  Host components never run a VCPU, so they
# never get these faults; the C headers (and the guest provider, which
# decodes them) keep them.
pbf=$prefix/libsel4/include/sel4/sel4_arch/types.pbf
for tag in 'VGICMaintenance 7' 'VCPUFault 8' 'VPPIEvent 9'; do
    grep -qx "    tag $tag" "$pbf" || { echo "$pbf: no 'tag $tag'; recheck the rust-sel4 view" >&2; exit 1; }
done
sed -i -e '/^    tag VGICMaintenance 7$/d' -e '/^    tag VCPUFault 8$/d' -e '/^    tag VPPIEvent 9$/d' "$pbf"
printf '%s\n' "$base" >"$prefix/fl4-revision"
echo "FL4 (AArch64) installed to $prefix (debug build: $debug)"
