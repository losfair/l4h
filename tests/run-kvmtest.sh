#!/usr/bin/env bash
# KVM in a guest (DESIGN.md §5.10): dom0 runs tests/guest/kvmtest.c, small
# VMs on /dev/kvm, and with "qemu" the host's QEMU booting the host's
# Linux kernel on it as well.  Needs a CPU with VMX in QEMU (-cpu host on
# an Intel host with nested KVM); L4H_QEMU_CPU overrides it.
# Usage: run-kvmtest.sh [qemu] [vcpus]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/guest
mkdir -p "$out"
qemu=0
if [ "${1:-}" = qemu ]; then
    qemu=1
    shift
fi
gcc -O2 -static -pthread -o "$out/kvmtest" "$root/tests/guest/kvmtest.c"
"$root/tools/mkinitramfs.sh" "$out/kvmtest.cpio.gz" "$root/tests/guest/init-kvmtest" \
    "$out/kvmtest" >/dev/null
mem=512
if [ "$qemu" = 1 ]; then
    # QEMU and its libraries, its firmware, a kernel and an initramfs for
    # the VM, as a second archive after the first.
    mem=1536
    "$root/tools/mkinitramfs.sh" "$out/nested.cpio.gz" "$root/tests/guest/init-nested" >/dev/null
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    bin=$(command -v qemu-system-x86_64)
    mkdir -p "$dir/usr/bin" "$dir/nested" "$dir/usr/share"
    cp "$bin" "$dir/usr/bin/"
    ldd "$bin" | grep -o '/[^ ]*' | while read -r lib; do
        mkdir -p "$dir$(dirname "$lib")"
        cp -L "$lib" "$dir$lib"
    done
    cp -a /usr/share/seabios "$dir/usr/share/"
    mkdir -p "$dir/usr/share/qemu"
    cp -L /usr/share/qemu/{linuxboot_dma.bin,kvmvapic.bin} "$dir/usr/share/qemu/"
    cp "${KVMTEST_KERNEL:-/boot/vmlinuz-$(uname -r)}" "$dir/nested/vmlinuz"
    cp "$out/nested.cpio.gz" "$dir/nested/initrd.cpio.gz"
    (cd "$dir" && find . | cpio -o -H newc --quiet | gzip -1) >>"$out/kvmtest.cpio.gz"
fi
export L4H_QEMU_CPU=${L4H_QEMU_CPU:-host,+invtsc}
L4H_DOM0_MEM_MB=${L4H_DOM0_MEM_MB:-$mem} L4H_DOM0_VCPUS=${1:-2} \
    L4H_TEST_FAIL_PATTERN='KVMTEST: FAIL|kernel fault|restarting dom0' \
    "$root/tools/run-dom0.sh" "$out/kvmtest.cpio.gz" "console=hvc0" "${KVMTEST_TIMEOUT:-300}" \
    | sed -n '/KVMTEST: start/,/KVMTEST: \(PASS\|FAIL\)/p;/kernel fault/p;/KVMTEST: QEMU start/,/KVMTEST: QEMU done/p'
grep -aq "KVMTEST: PASS" "$root/build/qemu.log"
if [ "$qemu" = 1 ]; then
    grep -aq "nested: NESTED: done" "$root/build/qemu.log"
fi
