#!/usr/bin/env bash
# Build rust-sel4's kernel loader for aarch64 (with l4h's patches: entering
# EL1 kernels) and its payload tool.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
rs=$root/build/rust-sel4-src
patches=("$root"/third_party/patches/rust-sel4/*.patch)
base=$(git -C "$root/third_party/rust-sel4" rev-parse HEAD)
want=$(cat "${patches[@]}" | sha256sum | cut -d' ' -f1)-$base
[ -d "$rs/.git" ] || git clone -q "$root/third_party/rust-sel4" "$rs"
stamp=$rs/.git/l4h-patches
if [ "$(cat "$stamp" 2>/dev/null)" != "$want" ]; then
    if [ -n "$(git -C "$rs" status --porcelain --untracked-files=no)" ]; then
        echo "$rs has uncommitted changes; cannot update loader patches" >&2
        exit 1
    fi
    git -C "$rs" checkout -q -B l4h "$base"
    for patch in "${patches[@]}"; do
        git -C "$rs" apply "$patch"
    done
    git -C "$rs" add -u
    git -C "$rs" -c user.name=l4h -c user.email=l4h@localhost commit -q -m 'Apply l4h loader patches'
    echo "$want" > "$stamp"
fi
cd "$rs"
CC=aarch64-linux-gnu-gcc SEL4_PREFIX=$root/build/sel4-aarch64 "$root/tools/cargo.sh" build "${l4h_cargo[@]}" -q \
    -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem \
    --target aarch64-unknown-none --release -p sel4-kernel-loader --target-dir "$root/build/loader-target"
"$root/tools/cargo.sh" build "${l4h_cargo[@]}" -q --release -p sel4-kernel-loader-add-payload --target-dir "$root/build/loader-target"
