# SPDX-License-Identifier: GPL-2.0-only
# shellcheck shell=bash
# Source after setting root.  kvm_vmms_append ARCHIVE VMM...: append to the
# initramfs ARCHIVE the VMMs named (qemu firecracker cloud-hypervisor),
# QEMU's libraries and firmware, and a kernel (KVMTEST_KERNEL, default the
# host's) and initramfs (tests/guest/init-nested) for their VMs under
# /nested.  Firecracker and cloud-hypervisor are their static releases,
# downloaded into build/dl and checked against pinned SHA-256s.
# Used by tests/run-kvmtest.sh and tests/run-kvmbench.sh.
FC_VERSION=v1.17.0
FC_SHA256=06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558
CH_VERSION=v54.0
CH_SHA256=4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b

kvm_fetch() { # url file sha256
    local f=$root/build/dl/$2
    mkdir -p "$root/build/dl"
    [ -f "$f" ] || curl -sSfL -o "$f.part" "$1"
    [ -f "$f" ] || mv "$f.part" "$f"
    echo "$3  $f" | sha256sum -c --quiet
}

kvm_vmms_append() {
    local archive=$1 dir kernel v bin lib
    shift
    dir=$(mktemp -d)
    "$root/tools/mkinitramfs.sh" "$dir.nested.cpio.gz" "$root/tests/guest/init-nested" >/dev/null
    mkdir -p "$dir/usr/bin" "$dir/nested" "$dir/usr/share"
    kernel=${KVMTEST_KERNEL:-/boot/vmlinuz-$(uname -r)}
    cp "$kernel" "$dir/nested/vmlinuz"
    # Firecracker and cloud-hypervisor load an ELF kernel.
    "$root/build/linux-6.18/scripts/extract-vmlinux" "$kernel" >"$dir/nested/vmlinux" 2>/dev/null
    mv "$dir.nested.cpio.gz" "$dir/nested/initrd.cpio.gz"
    for v in "$@"; do
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
            kvm_fetch "https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-x86_64.tgz" \
                "firecracker-$FC_VERSION-x86_64.tgz" "$FC_SHA256"
            tar -xzf "$root/build/dl/firecracker-$FC_VERSION-x86_64.tgz" -C "$dir" \
                "release-$FC_VERSION-x86_64/firecracker-$FC_VERSION-x86_64"
            mv "$dir/release-$FC_VERSION-x86_64/firecracker-$FC_VERSION-x86_64" "$dir/usr/bin/firecracker"
            rm -r "$dir/release-$FC_VERSION-x86_64" ;;
        cloud-hypervisor)
            kvm_fetch "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$CH_VERSION/cloud-hypervisor-static" \
                "cloud-hypervisor-static-$CH_VERSION" "$CH_SHA256"
            install -m 755 "$root/build/dl/cloud-hypervisor-static-$CH_VERSION" "$dir/usr/bin/cloud-hypervisor" ;;
        *) echo "unknown VMM $v" >&2; rm -rf "$dir"; return 2 ;;
        esac
    done
    (cd "$dir" && find . | cpio -o -H newc --quiet | gzip -1) >>"$archive"
    rm -rf "$dir"
}
