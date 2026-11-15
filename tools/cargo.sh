#!/usr/bin/env bash
# A pinned Cargo with the external path dependency hashing fix. Keep rustc
# selected by the caller's rust-toolchain.toml, independently of Cargo.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/source-pins.sh"
out=$root/build/cargo-$L4H_CARGO_DATE
if [ ! -x "$out/cargo" ]; then
    mkdir -p "$out" "$root/build/dl"
    archive=$root/build/dl/cargo-$L4H_CARGO_DATE.tar.xz
    [ -f "$archive" ] || curl -sSfL -o "$archive" \
        "https://static.rust-lang.org/dist/$L4H_CARGO_DATE/cargo-nightly-x86_64-unknown-linux-gnu.tar.xz"
    echo "$L4H_CARGO_SHA256  $archive" | sha256sum -c --quiet
    tar -xJf "$archive" -C "$out" --strip-components=3 \
        cargo-nightly-x86_64-unknown-linux-gnu/cargo/bin/cargo
fi
export RUSTC=${RUSTC:-$(rustup which rustc)}
export RUSTDOC=${RUSTDOC:-$(rustup which rustdoc)}
exec "$out/cargo" -Ztrim-paths --config 'profile.dev.trim-paths="all"' \
    --config 'profile.release.trim-paths="all"' "$@"
