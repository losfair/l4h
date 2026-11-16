#!/usr/bin/env bash
# Build the independently versioned guest Linux image, SDK and debug symbols.
# No microkernel headers or host build are needed. L4H_GUEST_VERSION overrides
# the source version; the package manifest records its exact ABI requirements.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
source "$root/tools/guest-env.sh"
arch=${L4H_ARCH:-x86_64}
out=$root/build/efi
mkdir -p "$out"
"$root/tools/build-sdk.sh" >/dev/null
version=${L4H_GUEST_VERSION:-$("$root/tools/version.sh")}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
guest=$stage/l4h-guest-$arch
debug=$stage/l4h-guest-debug-$arch
mkdir -p "$guest" "$debug"
"$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$guest/vmlinux"
cp "$l4h_linux_out/sdk.erofs" "$l4h_linux_out/include/config/kernel.release" "$guest/"
python3 "$root/tools/install/artifacts.py" guest "$guest" --release "$version"
cp "$l4h_linux_out/vmlinux" "$debug/"
cp "$guest/guest.json" "$debug/"
l4h_tar -C "$stage" -cJf "$out/l4h-guest-$arch.tar.xz" "l4h-guest-$arch"
l4h_tar -C "$stage" -cJf "$out/l4h-guest-debug-$arch.tar.xz" "l4h-guest-debug-$arch"
echo "Guest $version: $out/l4h-guest-$arch.tar.xz"
