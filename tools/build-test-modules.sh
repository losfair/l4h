#!/usr/bin/env bash
# Prebuild the external guest kernel modules used by integration tests so
# CI test shards can reuse them without the full Linux source tree.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
arch=${L4H_ARCH:-x86_64}

"$root/tools/build-linux.sh" vmlinux modules >"$root/build/linux-build.log" 2>&1 \
    || { tail -80 "$root/build/linux-build.log"; exit 1; }

build_mod() {
    local dst=$1 src_dir=$2
    mkdir -p "$dst"
    cp "$src_dir"/* "$dst/"
    "$root/tools/build-linux.sh" M="$dst" modules >"$dst/build.log" 2>&1 \
        || { cat "$dst/build.log"; exit 1; }
}

build_mod "$root/build/guest/page-aging" "$root/tests/guest/page-aging"
build_mod "$root/build/guest/pvlock" "$root/tests/guest/pvlock"

bpf=$root/build/guest/bpf
mkdir -p "$bpf"
echo 'obj-m += test_bpf.o' >"$bpf/Makefile"
cp "$root/build/linux-6.18/lib/test_bpf.c" "$bpf/"
"$root/tools/build-linux.sh" M="$bpf" modules >"$bpf/build.log" 2>&1 \
    || { cat "$bpf/build.log"; exit 1; }

if [ "$arch" = aarch64 ]; then
    build_mod "$root/build/guest/module" "$root/tests/guest/module"
else
    build_mod "$root/build/usbtest/mod" "$root/tests/guest/usbabuse"
    build_mod "$root/build/logtest/mod" "$root/tests/guest/log-fault"
fi
