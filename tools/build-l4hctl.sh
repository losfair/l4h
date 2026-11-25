#!/usr/bin/env bash
# Build the static dom0 CLI for the selected Linux guest architecture.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
if [[ ${L4H_PREBUILT:-0} == 1 || ${L4H_PREBUILT:-0} == guest ]]; then
    case "${L4H_ARCH:-x86_64}" in
        x86_64) [ ! -x "$root/tools/l4hctl/target/release/l4hctl" ] || exit 0 ;;
        aarch64) [ ! -x "$root/tools/l4hctl/target/aarch64-unknown-linux-gnu/release/l4hctl" ] || exit 0 ;;
    esac
fi
source "$root/tools/reproducible-env.sh"
cd "$root/tools/l4hctl"
case "${L4H_ARCH:-x86_64}" in
    x86_64) cargo build "${l4h_cargo[@]}" -q --release ;;
    aarch64)
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
            cargo build "${l4h_cargo[@]}" -q --release --target aarch64-unknown-linux-gnu
        ;;
    *) echo "unsupported L4H_ARCH: $L4H_ARCH" >&2; exit 1 ;;
esac
