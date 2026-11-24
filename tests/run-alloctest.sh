#!/usr/bin/env bash
# Host-side allocator fragmentation, reclaim and container panic checks,
# the I/O pool sizing rules (host/l4h-host/src/iopool.rs), l4h-host's rings, and the
# virtio-gpu display's size arithmetic and copies (host/l4h-host/src/gpu.rs),
# memd's grant validation and capability revocation, the carving of
# device memory (host/l4h-root/src/devmem/span.rs), and that the paths
# dom0 drives make their CNodes with allocations that can fail
# (tests/check-fallible-alloc.sh).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
bash "$root/tests/check-fallible-alloc.sh"
mkdir -p "$root/build/alloctest"
rustc +stable --edition=2024 --test "$root/tests/alloc.rs" -o "$root/build/alloctest/unit-tests"
"$root/build/alloctest/unit-tests"
rustc +stable --edition=2024 --test "$root/tests/memd.rs" -o "$root/build/alloctest/memd-tests"
"$root/build/alloctest/memd-tests"
rustc +stable --edition=2024 --test "$root/tests/devmem.rs" -o "$root/build/alloctest/devmem-tests"
"$root/build/alloctest/devmem-tests"
rustc +stable --edition=2024 --test "$root/host/l4h-root/src/fdt.rs" -o "$root/build/alloctest/fdt-tests"
"$root/build/alloctest/fdt-tests"
rustc +stable --edition=2024 --test "$root/host/l4h-host/src/iopool.rs" -o "$root/build/alloctest/iopool-tests"
"$root/build/alloctest/iopool-tests"
rustc +stable --edition=2024 --test "$root/host/l4h-host/src/gpu.rs" -o "$root/build/alloctest/gpu-tests"
"$root/build/alloctest/gpu-tests"
# The host and serial rings, and the reader logd runs (host/l4h-host/src).
rustc +stable --edition=2024 --crate-name l4h_abi --crate-type rlib \
    "$root/host/l4h-abi/src/lib.rs" -o "$root/build/alloctest/libl4h_abi.rlib"
rustc +stable --edition=2024 --test --crate-name l4h_host -L dependency="$root/build/alloctest" \
    --extern l4h_abi="$root/build/alloctest/libl4h_abi.rlib" \
    "$root/host/l4h-host/src/lib.rs" -o "$root/build/alloctest/host-tests"
"$root/build/alloctest/host-tests"
