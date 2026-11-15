#!/usr/bin/env bash
# Cargo's OUT_DIR includes a cache hash of external dependency paths. Give
# generated source files a stable name after Cargo adds its own path maps.
set -euo pipefail
compiler=$1
shift
flags=() wrapper=()
if [ -n "${OUT_DIR:-}" ]; then
    flags+=("--remap-path-prefix=$OUT_DIR=/cargo/out/$CARGO_PKG_NAME-$CARGO_PKG_VERSION")
fi
[ -n "${L4H_RUSTC_WRAPPER:-}" ] && wrapper=("$L4H_RUSTC_WRAPPER")
exec "${wrapper[@]}" "$compiler" "$@" "${flags[@]}"
