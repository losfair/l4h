#!/usr/bin/env bash
# Guest-only release/reproduction entry point: no host or documentation build.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
export L4H_GUEST_VERSION=${L4H_GUEST_VERSION:-$("$root/tools/version.sh")}
"$root/tools/build-guest.sh"
arch=${L4H_ARCH:-x86_64}
(cd "$root/build/efi" && sha256sum "l4h-guest-$arch.tar.xz" "l4h-guest-debug-$arch.tar.xz" > SHA256SUMS)
cat "$root/build/efi/SHA256SUMS"
