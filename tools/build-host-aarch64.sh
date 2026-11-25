#!/usr/bin/env bash
# Build the host components and l4h-root for aarch64 (QEMU virt), the
# components without their debug information, as in tools/build-host.sh.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
export L4H_VERSION=$("$root/tools/version.sh")
cd "$root/host"
export SEL4_PREFIX=${SEL4_PREFIX:-$root/build/sel4-aarch64}
export CC_aarch64_sel4=aarch64-linux-gnu-gcc CC_aarch64_sel4_roottask=aarch64-linux-gnu-gcc
# The cargo profile, as for tools/build-host.sh.
source "$root/tools/host-profile.sh"
if [ "${L4H_PREBUILT:-0}" = 1 ] && [ "$#" -eq 0 ] && [ -z "${L4H_EXTRA_DRIVERS:-}" ] &&
   [ "${L4H_TEST_VMM_BUSY:-0}" != 1 ] &&
   { [ "${L4H_TEST_INJECT:-0}" != 1 ] || [ "${L4H_PREBUILT_INJECT:-0}" = 1 ]; } &&
   [ -f "$root/host/target/aarch64-sel4-roottask/$l4h_profile/l4h-root.elf" ]; then
    exit 0
fi
out=$root/host/target/aarch64-sel4/$l4h_profile
mkdir -p "$out/stripped"
strip() {
    for c in "$@"; do
        aarch64-linux-gnu-objcopy --strip-debug "$out/l4h-$c.elf" "$out/stripped/l4h-$c.elf.new"
        cmp -s "$out/stripped/l4h-$c.elf.new" "$out/stripped/l4h-$c.elf" \
            && rm "$out/stripped/l4h-$c.elf.new" || mv "$out/stripped/l4h-$c.elf.new" "$out/stripped/l4h-$c.elf"
        export "L4H_$(echo "$c" | tr a-z- A-Z_)_ELF=$out/stripped/l4h-$c.elf"
    done
}
# The NIC drivers, built into root as on x86_64 (tools/build-host.sh).
nicds=(virtio gvnic ena ixgbe e1000e mlx5 r8125)
nicd_pkgs=()
for d in "${nicds[@]}"; do nicd_pkgs+=(-p "l4h-nicd-$d"); done
"$root/tools/cargo.sh" build "${l4h_cargo[@]}" -q "${l4h_cargo_profile[@]}" --target aarch64-sel4 -p l4h-vmm -p l4h-blkd -p l4h-netd -p l4h-trustd -p l4h-memd -p l4h-logd -p l4h-usbd \
    "${nicd_pkgs[@]}"
strip vmm blkd netd trustd memd logd usbd "${nicds[@]/#/nicd-}"
drivers=()
for d in "${nicds[@]}"; do drivers+=("$out/stripped/l4h-nicd-$d.elf"); done
# shellcheck disable=SC2206
drivers+=(${L4H_EXTRA_DRIVERS:-})
python3 "$root/tools/mkdrivers.py" "$out/stripped/l4h-drivers.bin.new" "${drivers[@]}"
cmp -s "$out/stripped/l4h-drivers.bin.new" "$out/stripped/l4h-drivers.bin" \
    && rm "$out/stripped/l4h-drivers.bin.new" || mv "$out/stripped/l4h-drivers.bin.new" "$out/stripped/l4h-drivers.bin"
export L4H_DRIVERS_BIN=$out/stripped/l4h-drivers.bin
# HVM guests' monitor, built into vmmgr for a kernel with FL4's VCPUs and
# Stage-2 roots (a C seL4 without them has no HVM guests).
if grep -q seL4_ARM_Stage2VSpaceObject "$SEL4_PREFIX/libsel4/include/sel4/arch/objecttype.h" 2>/dev/null; then
    "$root/tools/cargo.sh" build "${l4h_cargo[@]}" -q "${l4h_cargo_profile[@]}" --target aarch64-sel4 -p l4h-hvm
    strip hvm
fi
"$root/tools/cargo.sh" build "${l4h_cargo[@]}" -q "${l4h_cargo_profile[@]}" --target aarch64-sel4 -p l4h-vmmgr
strip vmmgr
"$root/tools/cargo.sh" build "${l4h_cargo[@]}" -q "${l4h_cargo_profile[@]}" --target aarch64-sel4-roottask -p l4h-root "$@"
