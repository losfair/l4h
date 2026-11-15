#!/usr/bin/env bash
# The complete set of published x86_64 artifacts, also used for replay.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
export L4H_RELEASE=1
export L4H_VERSION=$("$root/tools/version.sh")
make -C "$root/docs/manual"
"$root/tools/build-efi.sh"
"$root/tools/build-dom0.sh"
cp "$root/tools/l4h-attest.py" "$root/docs/manual/l4h-manual.pdf" "$root/build/efi/"
(cd "$root/build/efi" && sha256sum l4h-*.efi l4h-*.tar.xz l4h-attest.py l4h-manual.pdf > SHA256SUMS)
cat "$root/build/efi/SHA256SUMS"
