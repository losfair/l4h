#!/usr/bin/env bash
# Prepare a fresh Debian 13 (trixie) system, run as root, to build and test
# l4h: packages, Rust toolchains, the seL4 Python environment and the Linux
# source.  Used by .github/workflows/test.yml; also works in a container.
# Usage: ci-setup.sh [x86_64|aarch64|debian]...   (default: x86_64)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
# Downloads are pinned by checksum.
LINUX_VERSION=6.18.60
LINUX_SHA256=3c2f44ef6acc021a7ad444d9a2e6ec1ef488ff09368793d0004a6080f69d621e
RUSTUP_VERSION=1.29.1
RUSTUP_SHA256=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
want=" ${*:-x86_64} "

pkgs=(git ca-certificates curl xz-utils bzip2 wget sudo procps kmod
    build-essential gcc g++ make cmake ninja-build python3 python3-venv
    libxml2-utils device-tree-compiler clang libclang-dev
    flex bison bc libelf-dev libssl-dev pahole cpio rsync ccache
    busybox-static e2fsprogs erofs-utils
    qemu-system-x86 qemu-utils gdb ovmf grub-efi-amd64-bin grub-pc-bin mtools fdisk
    gcc-aarch64-linux-gnu libc6-dev-arm64-cross
    swtpm swtpm-tools python3-cryptography acpica-tools)
[[ $want == *" aarch64 "* ]] && pkgs+=(qemu-system-arm gdb-multiarch)
[[ $want == *" debian "* ]] && pkgs+=(debootstrap debian-archive-keyring)
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends "${pkgs[@]}"

# Rust: stable for the dom0 tools and tests, the pinned nightly for the host
# (host/rust-toolchain.toml).
if ! command -v rustup >/dev/null; then
    # rustup-init acts on its file name.
    init=$(mktemp -d)/rustup-init
    curl -sSfL -o "$init" \
        "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/x86_64-unknown-linux-gnu/rustup-init"
    echo "$RUSTUP_SHA256  $init" | sha256sum -c --quiet
    chmod +x "$init"
    "$init" -y --profile minimal --default-toolchain stable
    rm -rf "$(dirname "$init")"
fi
export PATH=$HOME/.cargo/bin:$PATH
rustup toolchain install stable --profile minimal
rustup component add rust-src --toolchain stable
# Rust-for-Linux bindings for kemu in the x86_64 guest kernel.
cargo +stable install --locked bindgen-cli --version 0.71.1
(cd "$root/host" && rustup toolchain install)

if [[ $want == *" aarch64 "* ]]; then
    rustup target add --toolchain stable aarch64-unknown-linux-gnu
    # Extract the foreign BusyBox without replacing the build host's binary.
    dpkg --add-architecture arm64
    apt-get update -q
    busybox_pkg=$(mktemp -d)
    (cd "$busybox_pkg" && apt-get download busybox-static:arm64)
    mkdir -p "$root/build/busybox-aarch64"
    dpkg-deb -x "$busybox_pkg"/busybox-static_*_arm64.deb "$root/build/busybox-aarch64"
    rm -rf "$busybox_pkg"
fi

# seL4's build tools.
[ -x "$root/.venv/bin/python" ] || python3 -m venv "$root/.venv"
"$root/.venv/bin/pip" install -q "$root/kernel/seL4/tools/python-deps"

# Linux, unless already there.
if [ ! -f "$root/build/linux-6.18/Makefile" ]; then
    mkdir -p "$root/build/dl"
    tarball=$root/build/dl/linux-$LINUX_VERSION.tar.xz
    [ -f "$tarball" ] || curl -sSfL -o "$tarball" \
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$LINUX_VERSION.tar.xz"
    echo "$LINUX_SHA256  $tarball" | sha256sum -c --quiet
    tar -C "$root/build" -xJf "$tarball"
    mv "$root/build/linux-$LINUX_VERSION" "$root/build/linux-6.18"
fi

if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$HOME/.cargo/bin" >> "$GITHUB_PATH"
fi
