#!/usr/bin/env bash
# Host-side l4h EFI parsing and multiboot2 information construction checks.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/kexecimagetest
mkdir -p "$out"
rustc +stable --edition=2024 --test "$root/tests/kexec-image.rs" -o "$out/unit-tests"
"$out/unit-tests"
