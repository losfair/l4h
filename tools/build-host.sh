#!/usr/bin/env bash
# Build the host components and the root task that embeds them, without
# their debug information, which only takes memory there; the unstripped
# ELFs stay in host/target/x86_64-sel4/{debug,release}.  dom0 is not
# built in (see host/l4h-root/build.rs).  Extra arguments go to the root
# task's cargo build.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_VERSION=$("$root/tools/version.sh")
cd "$root/host"
# L4H_RELEASE=1 builds the shipped, optimised components (the cargo release
# profile); otherwise the dev profile (tools/host-profile.sh).
source "$root/tools/host-profile.sh"
out=$root/host/target/x86_64-sel4/$l4h_profile
mkdir -p "$out/stripped"
strip() {
    for c in "$@"; do
        # Replace the copy only when it changes: whatever embeds it rebuilds
        # when it does.
        objcopy --strip-debug "$out/l4h-$c.elf" "$out/stripped/l4h-$c.elf.new"
        cmp -s "$out/stripped/l4h-$c.elf.new" "$out/stripped/l4h-$c.elf" \
            && rm "$out/stripped/l4h-$c.elf.new" || mv "$out/stripped/l4h-$c.elf.new" "$out/stripped/l4h-$c.elf"
        export "L4H_$(echo "$c" | tr a-z- A-Z_)_ELF=$out/stripped/l4h-$c.elf"
    done
}
nicds=(virtio gvnic ena ixgbe e1000e mlx5)
nicd_pkgs=()
for d in "${nicds[@]}"; do nicd_pkgs+=(-p "l4h-nicd-$d"); done
cargo build -q "${l4h_cargo_profile[@]}" --target x86_64-sel4 -p l4h-vmm -p l4h-blkd -p l4h-netd -p l4h-trustd -p l4h-memd -p l4h-logd -p l4h-usbd \
    "${nicd_pkgs[@]}"
strip vmm blkd netd trustd memd logd usbd "${nicds[@]/#/nicd-}"
# The NIC drivers, as the bundle root has built in (the l4h-drivers boot
# module replaces it).  Extra images: $L4H_EXTRA_DRIVERS (test drivers).
drivers=()
for d in "${nicds[@]}"; do drivers+=("$out/stripped/l4h-nicd-$d.elf"); done
# shellcheck disable=SC2206
drivers+=(${L4H_EXTRA_DRIVERS:-})
python3 "$root/tools/mkdrivers.py" "$out/stripped/l4h-drivers.bin.new" "${drivers[@]}"
cmp -s "$out/stripped/l4h-drivers.bin.new" "$out/stripped/l4h-drivers.bin" \
    && rm "$out/stripped/l4h-drivers.bin.new" || mv "$out/stripped/l4h-drivers.bin.new" "$out/stripped/l4h-drivers.bin"
export L4H_DRIVERS_BIN=$out/stripped/l4h-drivers.bin
# vmmgr embeds l4h-vmm, root embeds vmmgr.
cargo build -q "${l4h_cargo_profile[@]}" --target x86_64-sel4 -p l4h-vmmgr
strip vmmgr
cargo build -q "${l4h_cargo_profile[@]}" -p l4h-root "$@"
