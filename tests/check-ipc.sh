#!/usr/bin/env bash
# IPC has one way of each kind (DESIGN.md §10, "Wiring declarations"):
# capabilities are minted from their edges (l4h_task::edge), endpoints are
# called, served and received on through l4h-ipc.  clippy's
# disallowed-methods (host/clippy.toml) refuses the seL4 calls that would
# go around them anywhere else.  For the architecture L4H_ARCH names
# (x86_64 if unset), whose code alone is compiled; needs its seL4 headers
# (tools/build-kernel.sh, tools/build-kernel-aarch64.sh).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_VERSION=$("$root/tools/version.sh")
cd "$root/host"
arch=${L4H_ARCH:-x86_64}
if [ "$arch" = aarch64 ]; then
    export SEL4_PREFIX=$root/build/sel4-aarch64
    export CC_aarch64_sel4=aarch64-linux-gnu-gcc CC_aarch64_sel4_roottask=aarch64-linux-gnu-gcc
fi
lint=(-A clippy::all -D clippy::disallowed_methods)
cargo clippy -q --target "$arch-sel4" -p l4h-ipc -p l4h-task -p l4h-rt -p l4h-vmm -p l4h-blkd -p l4h-netd \
    -p l4h-trustd -p l4h-memd -p l4h-logd -p l4h-usbd -p l4h-vmmgr -- "${lint[@]}"
cargo clippy -q --target "$arch-sel4-roottask" -p l4h-root -- "${lint[@]}"
