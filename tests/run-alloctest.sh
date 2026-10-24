#!/usr/bin/env bash
# Host-side allocator fragmentation, reclaim and container panic checks,
# the I/O pool sizing rules (host/l4h-host/src/iopool.rs), and the
# virtio-gpu display's size arithmetic and copies (host/l4h-host/src/gpu.rs).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$root/build/alloctest"
rustc +stable --edition=2024 --test "$root/tests/alloc.rs" -o "$root/build/alloctest/unit-tests"
"$root/build/alloctest/unit-tests"
rustc +stable --edition=2024 --test "$root/host/l4h-host/src/iopool.rs" -o "$root/build/alloctest/iopool-tests"
"$root/build/alloctest/iopool-tests"
rustc +stable --edition=2024 --test "$root/host/l4h-host/src/gpu.rs" -o "$root/build/alloctest/gpu-tests"
"$root/build/alloctest/gpu-tests"
