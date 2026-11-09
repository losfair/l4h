#!/usr/bin/env bash
# IPC has one way of each kind (DESIGN.md §10, "Wiring declarations"):
# capabilities are minted from their edges (l4h_task::edge), endpoints are
# called, served and received on through l4h-ipc.  clippy's
# disallowed-methods (host/clippy.toml) refuses the seL4 calls that would
# go around them anywhere else.  Needs tools/build-kernel.sh (the seL4
# headers).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_VERSION=$("$root/tools/version.sh")
cd "$root/host"
lint=(-A clippy::all -D clippy::disallowed_methods)
cargo clippy -q --target x86_64-sel4 -p l4h-ipc -p l4h-task -p l4h-rt -p l4h-vmm -p l4h-blkd -p l4h-netd \
    -p l4h-trustd -p l4h-memd -p l4h-logd -p l4h-usbd -p l4h-vmmgr -- "${lint[@]}"
cargo clippy -q -p l4h-root -- "${lint[@]}"
