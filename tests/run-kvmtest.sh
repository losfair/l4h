#!/usr/bin/env bash
# KVM in a guest (DESIGN.md §5.10): dom0 runs tests/guest/kvmtest.c, small
# VMs on /dev/kvm.  With "vmm" it then boots the host's Linux kernel with two
# vCPUs under each of QEMU (the host's), Firecracker and cloud-hypervisor
# (their static release binaries, downloaded and checked into build/dl);
# KVMTEST_VMMS picks a subset.  Needs a CPU with VMX in QEMU (-cpu host on
# an Intel host with nested KVM); L4H_QEMU_CPU overrides it.
# Usage: run-kvmtest.sh [vmm] [vcpus]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/guest
mkdir -p "$out"
vmm=0
if [ "${1:-}" = vmm ]; then
    vmm=1
    shift
fi
vmms=${KVMTEST_VMMS:-qemu firecracker cloud-hypervisor}
FC_VERSION=v1.17.0
FC_SHA256=06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558
CH_VERSION=v54.0
CH_SHA256=4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b
fetch() { # url file sha256
    local f=$root/build/dl/$2
    mkdir -p "$root/build/dl"
    [ -f "$f" ] || curl -sSfL -o "$f.part" "$1"
    [ -f "$f" ] || mv "$f.part" "$f"
    echo "$3  $f" | sha256sum -c --quiet
}
gcc -O2 -static -pthread -o "$out/kvmtest" "$root/tests/guest/kvmtest.c"
"$root/tools/mkinitramfs.sh" "$out/kvmtest.cpio.gz" "$root/tests/guest/init-kvmtest" \
    "$out/kvmtest" >/dev/null
mem=512
if [ "$vmm" = 1 ]; then
    # The VMMs, QEMU's libraries and firmware, a kernel and an initramfs
    # for the VMs, as a second archive after the first.
    mem=1536
    "$root/tools/mkinitramfs.sh" "$out/nested.cpio.gz" "$root/tests/guest/init-nested" >/dev/null
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    mkdir -p "$dir/usr/bin" "$dir/nested" "$dir/usr/share"
    kernel=${KVMTEST_KERNEL:-/boot/vmlinuz-$(uname -r)}
    cp "$kernel" "$dir/nested/vmlinuz"
    # Firecracker and cloud-hypervisor load an ELF kernel.
    "$root/build/linux-6.18/scripts/extract-vmlinux" "$kernel" >"$dir/nested/vmlinux"
    cp "$out/nested.cpio.gz" "$dir/nested/initrd.cpio.gz"
    for v in $vmms; do
        case $v in
        qemu)
            bin=$(command -v qemu-system-x86_64)
            cp "$bin" "$dir/usr/bin/"
            ldd "$bin" | grep -o '/[^ ]*' | while read -r lib; do
                mkdir -p "$dir$(dirname "$lib")"
                cp -L "$lib" "$dir$lib"
            done
            cp -a /usr/share/seabios "$dir/usr/share/"
            mkdir -p "$dir/usr/share/qemu"
            cp -L /usr/share/qemu/{linuxboot_dma.bin,kvmvapic.bin} "$dir/usr/share/qemu/" ;;
        firecracker)
            fetch "https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-x86_64.tgz" \
                "firecracker-$FC_VERSION-x86_64.tgz" "$FC_SHA256"
            tar -xzf "$root/build/dl/firecracker-$FC_VERSION-x86_64.tgz" -C "$dir" \
                "release-$FC_VERSION-x86_64/firecracker-$FC_VERSION-x86_64"
            mv "$dir/release-$FC_VERSION-x86_64/firecracker-$FC_VERSION-x86_64" "$dir/usr/bin/firecracker"
            rm -r "$dir/release-$FC_VERSION-x86_64" ;;
        cloud-hypervisor)
            fetch "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$CH_VERSION/cloud-hypervisor-static" \
                "cloud-hypervisor-static-$CH_VERSION" "$CH_SHA256"
            install -m 755 "$root/build/dl/cloud-hypervisor-static-$CH_VERSION" "$dir/usr/bin/cloud-hypervisor" ;;
        *) echo "unknown VMM $v" >&2; exit 2 ;;
        esac
    done
    (cd "$dir" && find . | cpio -o -H newc --quiet | gzip -1) >>"$out/kvmtest.cpio.gz"
fi
export L4H_QEMU_CPU=${L4H_QEMU_CPU:-host,+invtsc}
L4H_DOM0_MEM_MB=${L4H_DOM0_MEM_MB:-$mem} L4H_DOM0_VCPUS=${1:-2} \
    L4H_TEST_FAIL_PATTERN='KVMTEST: FAIL|kernel fault|restarting dom0' \
    "$root/tools/run-dom0.sh" "$out/kvmtest.cpio.gz" "console=hvc0" "${KVMTEST_TIMEOUT:-300}" \
    | sed -n '/KVMTEST: start/,/KVMTEST: \(PASS\|FAIL\)/p;/kernel fault/p;/KVMTEST: VMM /,/KVMTEST: VMMs done/p'
grep -aq "KVMTEST: PASS" "$root/build/qemu.log"
if [ "$vmm" = 1 ]; then
    for v in $vmms; do
        grep -aq "^$v: NESTED: done" "$root/build/qemu.log" || { echo "KVMTEST: $v failed" >&2; exit 1; }
    done
fi
