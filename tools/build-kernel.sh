#!/usr/bin/env bash
# Build the patched seL4 kernel and install libsel4 + kernel into build/sel4.
# L4H_RELEASE=1 builds without kernel assertions and debug syscalls.
# L4H_LAPIC_MODE=XAPIC builds for machines whose firmware leaves x2APIC off
# (default X2APIC, faster under virtualization).  L4H_PCID=OFF builds for
# CPUs without process-context identifiers (CPUID.1:ECX.PCID), such as the
# AMD EPYC 4004 series; seL4 otherwise stops in its first boot checks.
# L4H_SKIM_WINDOW=ON isolates kernel mappings on Meltdown-affected CPUs.
# L4H_KERNEL_VARIANT=NAME builds in build/kernel-NAME and installs to
# build/sel4-NAME instead, leaving the default build alone
# (tools/build-efi.sh builds the shipped variants so).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
src=$root/build/seL4-src
variant=${L4H_KERNEL_VARIANT:+-$L4H_KERNEL_VARIANT}
out=$root/build/kernel$variant
prefix=$root/build/sel4$variant
export PATH=$root/.venv/bin:$PATH

source "$root/tools/prepare-kernel.sh"

debug=ON
[ "${L4H_RELEASE:-0}" = 1 ] && debug=OFF
config=$root/kernel/configs/l4h-x86_64.cmake
# The config only seeds the cache: start afresh when it changed.
[ "$config" -nt "$out/CMakeCache.txt" ] && rm -rf "$out"
cmake -G Ninja -S "$src" -B "$out" \
    -C "$config" \
    -DKernelDebugBuild=$debug \
    -DKernelLAPICMode="${L4H_LAPIC_MODE:-X2APIC}" \
    -DKernelSupportPCID="${L4H_PCID:-ON}" \
    -DKernelSkimWindow="${L4H_SKIM_WINDOW:-OFF}" \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCROSS_COMPILER_PREFIX= >/dev/null
ninja -C "$out" all
ninja -C "$out" install >/dev/null
echo "kernel installed to $prefix (debug build: $debug)"
