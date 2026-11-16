#!/usr/bin/env bash
# The complete set of published x86_64 artifacts, also used for replay.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
export L4H_RELEASE=1
export L4H_VERSION=$("$root/tools/version.sh")
# Full releases include a default guest. A host-only release can pin an
# already published guest with L4H_GUEST_RELEASE, without building Linux.
if [ -z "${L4H_GUEST_RELEASE:-}" ]; then
    if [ "${L4H_GUEST_VERSION:-$L4H_VERSION}" != "$L4H_VERSION" ]; then
        echo 'A bundled guest must use the release tag; publish independent versions with build-guest-release.sh' >&2
        exit 1
    fi
    export L4H_GUEST_VERSION=$L4H_VERSION L4H_GUEST_RELEASE=$L4H_VERSION
    "$root/tools/build-guest.sh"
else
    rm -f "$root/build/efi/l4h-guest-x86_64.tar.xz" "$root/build/efi/l4h-guest-debug-x86_64.tar.xz"
fi
make -C "$root/docs/manual"
"$root/tools/build-efi.sh"
"$root/tools/build-dom0.sh"
cp "$root/tools/l4h-attest.py" "$root/docs/manual/l4h-manual.pdf" "$root/build/efi/"
(cd "$root/build/efi" && sha256sum l4h-*.efi l4h-*.tar.xz l4h-host-*.json l4h-attest.py l4h-manual.pdf > SHA256SUMS)
cat "$root/build/efi/SHA256SUMS"
