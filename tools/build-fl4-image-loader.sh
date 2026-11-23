#!/usr/bin/env bash
# Build the reusable position-independent FL4 ARM64 `Image` boot stub
# (boot/l4h-fl4-image) into build/l4h-fl4-image.bin (or the path given as $1).
# Pack kernel.elf and root-dom0.elf onto it with tools/pack-fl4-image.py.
# Usage: build-fl4-image-loader.sh [out.bin]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
source "$root/tools/prepare-fl4.sh"
out=${1:-$root/build/l4h-fl4-image.bin}
mkdir -p "$(dirname "$out")"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

stage=$work/loader
mkdir -p "$stage"
cp -r "$root/boot/l4h-fl4-image/." "$stage/"
cp -r "$src/crates/fl4-bootinfo" "$stage/fl4-bootinfo"

(
    cd "$stage"
    cargo +stable build --release --offline --target aarch64-unknown-none-softfloat --target-dir "$work/target"
)

elf=$work/target/aarch64-unknown-none-softfloat/release/l4h-fl4-image

# Verify only R_AARCH64_RELATIVE relocations are present (no unresolved dynamic refs).
if aarch64-linux-gnu-readelf -rW "$elf" | grep -E '^[0-9a-f]+[[:space:]]+[0-9a-f]+[[:space:]]+R_AARCH64_' | grep -vq 'R_AARCH64_RELATIVE'; then
    echo "build-fl4-image-loader: unexpected non-RELATIVE relocation in $elf" >&2
    aarch64-linux-gnu-readelf -rW "$elf" >&2
    exit 1
fi

aarch64-linux-gnu-objcopy -O binary "$elf" "$out.new"
size=$(stat -c %s "$out.new")
if [ $((size % 4096)) -ne 0 ]; then
    echo "build-fl4-image-loader: stub size $size is not 4096-byte aligned" >&2
    rm -f "$out.new"
    exit 1
fi
mv "$out.new" "$out"
echo "l4h-fl4-image stub: $out ($size bytes)"
