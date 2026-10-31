#!/usr/bin/env bash
# Hardware AES vectors, scatter/gather and bounce allocator tests.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/blkcrypt-tests
mkdir -p "$out"
rustc +stable --edition=2024 --test "$root/tests/blk-crypt.rs" -O -o "$out/native"
"$out/native" --nocapture
if [ "${L4H_ARCH:-x86_64}" = aarch64 ]; then
    rustc +stable --edition=2024 --test "$root/tests/blk-crypt.rs" -O \
        --target aarch64-unknown-linux-gnu -C linker=aarch64-linux-gnu-gcc \
        -C target-feature=+crt-static -o "$out/arm"
    qemu-aarch64 -cpu max "$out/arm" --nocapture
fi
