#!/usr/bin/env bash
# FL4's CMake project invokes Cargo independently of the host workspace.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
cargo=$(cd "$root/kernel/fl4" && rustup which cargo)
export RUSTC=$(cd "$root/kernel/fl4" && rustup which rustc)
# FL4 sets target-specific flags, which take priority over build.rustflags.
# Extend that array so its code model and frame-pointer settings survive.
# The AArch64 kernel's target has no flags of FL4's: give it the same maps.
maps=${l4h_cargo[2]/build.rustflags/target.x86_64-unknown-none.rustflags}
maps_a64=${l4h_cargo[2]/build.rustflags/target.aarch64-unknown-none-softfloat.rustflags}
exec "$cargo" "$@" --locked --config "$maps" --config "$maps_a64"
