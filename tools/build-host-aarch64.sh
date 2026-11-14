#!/usr/bin/env bash
# Build the host components and l4h-root for aarch64 (QEMU virt), the
# components without their debug information, as in tools/build-host.sh.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_VERSION=$("$root/tools/version.sh")
cd "$root/host"
export SEL4_PREFIX=$root/build/sel4-aarch64
export CC_aarch64_sel4=aarch64-linux-gnu-gcc CC_aarch64_sel4_roottask=aarch64-linux-gnu-gcc
# The cargo profile, as for tools/build-host.sh.
source "$root/tools/host-profile.sh"
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
cargo build -q "${l4h_cargo_profile[@]}" --target aarch64-sel4 -p l4h-vmm -p l4h-blkd -p l4h-netd -p l4h-trustd -p l4h-memd -p l4h-logd -p l4h-usbd \
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
cargo build -q "${l4h_cargo_profile[@]}" --target aarch64-sel4 -p l4h-vmmgr
strip vmmgr
cargo build -q "${l4h_cargo_profile[@]}" --target aarch64-sel4-roottask -p l4h-root "$@"
