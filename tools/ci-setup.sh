#!/usr/bin/env bash
# Prepare a fresh Debian 13 (trixie) system, run as root, to build and test
# l4h: packages, Rust toolchains, the seL4 Python environment and the Linux
# source.  Used by .github/workflows/test.yml; also works in a container.
# Usage: ci-setup.sh [x86_64|x86_64-run|x86_64-host|x86_64-fl4|aarch64|aarch64-run|debian]...
#   (default: x86_64)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export TMPDIR=${TMPDIR:-$root/build/tmp}
mkdir -p "$TMPDIR"
# Container runners can mount a checkout owned by the runner's host UID.
# Trust these exact inputs before reading their Git metadata.
for path in "$root" "$root/kernel/seL4" "$root/third_party/"{rust-sel4,sddf,kemu}; do
    git config --global --add safe.directory "$path"
done
source "$root/tools/source-pins.sh"
want=" ${*:-x86_64} "

need_x86_linux=0
need_arm_linux=0
need_host_rust=0
need_fl4_rust=0
need_sel4_venv=0
need_x86_runtime=0
need_arm_runtime=0

[[ $want == *" x86_64 "* ]] && {
    need_x86_linux=1; need_host_rust=1; need_fl4_rust=1; need_sel4_venv=1; need_x86_runtime=1
}
[[ $want == *" x86_64-run "* ]] && { need_x86_runtime=1; }
[[ $want == *" x86_64-host "* ]] && { need_host_rust=1; need_sel4_venv=1; need_x86_runtime=1; }
[[ $want == *" x86_64-fl4 "* ]] && { need_host_rust=1; need_fl4_rust=1; need_sel4_venv=1; need_x86_runtime=1; }
[[ $want == *" aarch64 "* ]] && {
    need_arm_linux=1; need_host_rust=1; need_sel4_venv=1; need_arm_runtime=1
}
[[ $want == *" aarch64-run "* ]] && { need_arm_runtime=1; }

pkgs=(git ca-certificates curl xz-utils bzip2 wget sudo procps kmod
    build-essential gcc g++ make python3
    libelf-dev cpio rsync busybox-static e2fsprogs erofs-utils
    gcc-aarch64-linux-gnu libc6-dev-arm64-cross)
if [ "$need_x86_runtime" = 1 ]; then
    pkgs+=(qemu-system-x86 qemu-utils gdb ovmf grub-efi-amd64-bin grub-pc-bin mtools fdisk
        swtpm swtpm-tools python3-cryptography acpica-tools)
fi
if [ "$need_arm_runtime" = 1 ]; then
    # qemu-system-arm only Recommends ipxe-qemu, which --no-install-recommends
    # omits; virtio-net-pci needs efi-virtio.rom from it even when dumping DTBs.
    pkgs+=(qemu-system-arm ipxe-qemu qemu-utils gdb-multiarch)
fi
if [ "$need_sel4_venv" = 1 ]; then
    pkgs+=(cmake ninja-build python3-venv libxml2-utils device-tree-compiler)
fi
if [ "$need_x86_linux" = 1 ] || [ "$need_arm_linux" = 1 ]; then
    pkgs+=(flex bison bc libssl-dev pahole ccache)
fi
if [ "$need_x86_linux" = 1 ]; then
    pkgs+=(clang libclang-dev)
fi
[[ $want == *" debian "* ]] && pkgs+=(debootstrap debian-archive-keyring)
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends "${pkgs[@]}"
source "$root/tools/reproducible-env.sh"

# Rust toolchains, installed only for modes that compile Rust.
if [ "$need_host_rust" = 1 ] || [ "$need_x86_linux" = 1 ] || [ "$need_fl4_rust" = 1 ]; then
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
    if [ "$need_x86_linux" = 1 ] || [ "$need_arm_linux" = 1 ]; then
        (cd "$root" && rustup toolchain install)
    fi
    if [ "$need_x86_linux" = 1 ]; then
        rustup component add rust-src --toolchain stable
        # Rust-for-Linux bindings for kemu in the x86_64 guest kernel.
        if ! command -v bindgen >/dev/null || [ "$(bindgen --version 2>/dev/null)" != "bindgen 0.71.1" ]; then
            (cd "$root" && cargo install --locked bindgen-cli --version 0.71.1)
        fi
    fi
    if [ "$need_host_rust" = 1 ]; then
        if [ "$need_x86_runtime" = 1 ]; then
            rustup target add --toolchain stable x86_64-unknown-none
        fi
        if [ "$need_arm_runtime" = 1 ]; then
            rustup target add --toolchain stable aarch64-unknown-linux-gnu
            if [ "$need_arm_linux" = 1 ]; then
                (cd "$root" && rustup target add aarch64-unknown-linux-gnu)
            fi
        fi
        (cd "$root/host" && rustup toolchain install)
    fi
    if [ "$need_fl4_rust" = 1 ]; then
        (cd "$root/kernel/fl4" && rustup toolchain install)
    fi
    "$root/tools/cargo.sh" --version
fi

if [ "$need_arm_runtime" = 1 ]; then
    # Extract the foreign BusyBox without replacing the build host's binary.
    dpkg --add-architecture arm64
    apt-get update -q
    if [ "$need_arm_linux" = 1 ]; then
        # SDK helpers run natively on the guest.
        apt-get install -y -q --no-install-recommends libssl-dev:arm64
    fi
    busybox_pkg=$(mktemp -d)
    (cd "$busybox_pkg" && apt-get download busybox-static:arm64)
    mkdir -p "$root/build/busybox-aarch64"
    dpkg-deb -x "$busybox_pkg"/busybox-static_*_arm64.deb "$root/build/busybox-aarch64"
    rm -rf "$busybox_pkg"
fi

# seL4's build tools.
if [ "$need_sel4_venv" = 1 ]; then
    [ -x "$root/.venv/bin/python" ] || python3 -m venv "$root/.venv"
    "$root/.venv/bin/pip" install -q -r "$root/tools/sel4-requirements.txt"
fi

# Linux, unless already there or not needed by this mode.
if { [ "$need_x86_linux" = 1 ] || [ "$need_arm_linux" = 1 ]; } && [ ! -f "$root/build/linux-6.18/Makefile" ]; then
    mkdir -p "$root/build/dl"
    tarball=$root/build/dl/linux-$LINUX_VERSION.tar.xz
    [ -f "$tarball" ] || curl -sSfL -o "$tarball" \
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$LINUX_VERSION.tar.xz"
    echo "$LINUX_SHA256  $tarball" | sha256sum -c --quiet
    tar -C "$root/build" -xJf "$tarball"
    mv "$root/build/linux-$LINUX_VERSION" "$root/build/linux-6.18"
fi

if [ -n "${GITHUB_PATH:-}" ] && [ -d "$HOME/.cargo/bin" ]; then
    echo "$HOME/.cargo/bin" >> "$GITHUB_PATH"
fi
