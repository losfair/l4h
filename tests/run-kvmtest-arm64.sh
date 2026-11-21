#!/usr/bin/env bash
# KVM in an AArch64 guest on FL4 at EL2 (DESIGN.md §5.10): dom0 runs
# tests/guest/kvmtest-arm64.c, small VMs on /dev/kvm, then boots an arm64
# Linux (tests/guest/nested-arm64.config) with two vCPUs under Firecracker
# and, on GICv3, cloud-hypervisor (their static releases, checked against
# pinned SHA-256s).  The FL4 image (tools/mkfl4-efi-aarch64.sh) boots on
# QEMU's virt machine (tools/run-fl4-aarch64.sh) with
# L4H_QEMU_GIC_VERSION (3 or 2).  Needs build/sel4-fl4-aarch64
# (tools/build-fl4-aarch64.sh) and the AArch64 host
# (SEL4_PREFIX=build/sel4-fl4-aarch64 tools/build-host-aarch64.sh), and
# L4H_FL4_SOURCE as for those.
# Usage: run-kvmtest-arm64.sh [vmm]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_ARCH=aarch64
out=$root/build/guest-arm64
mkdir -p "$out"
gic=${L4H_QEMU_GIC_VERSION:-3}
FC_VERSION=v1.17.0
FC_SHA256=e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256
CH_VERSION=v54.0
CH_SHA256=e8a6d9786ea678e739f1a386682846e93742dcb9c7b6e3e0c62e3bda6cff0ef3
fetch() { # url file sha256
    local f=$root/build/dl/$2
    mkdir -p "$root/build/dl"
    [ -f "$f" ] || curl -sSfL -o "$f.part" "$1"
    [ -f "$f" ] || mv "$f.part" "$f"
    echo "$3  $f" | sha256sum -c --quiet
}

vmms=
if [ "${1:-}" = vmm ]; then
    vmms=firecracker
    [ "$gic" = 3 ] && vmms="firecracker cloud-hypervisor"
fi
aarch64-linux-gnu-gcc -O2 -static -pthread -o "$out/kvmtest" "$root/tests/guest/kvmtest-arm64.c"
cat >"$out/init" <<EOF
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t tmpfs tmp /tmp
/bin/kvmtest
for v in $vmms; do
	echo "KVMTEST: VMM \$v"
	/bin/run-nested-arm64 \$v 2>&1 | sed "s/^/\$v: /"
done
echo "KVMTEST: VMMs done"
poweroff -f
EOF
"$root/tools/mkinitramfs.sh" "$out/kvmtest.cpio.gz" "$out/init" "$out/kvmtest" \
    "$root/tests/guest/run-nested-arm64" >/dev/null
if [ -n "$vmms" ]; then
    nested=$root/build/linux-nested-arm64
    mk=(make -C "$root/build/linux-6.18" O="$nested" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-)
    if [ ! -f "$nested/.config" ] || [ "$root/tests/guest/nested-arm64.config" -nt "$nested/.config" ]; then
        KCONFIG_ALLCONFIG=$root/tests/guest/nested-arm64.config "${mk[@]}" allnoconfig >/dev/null
    fi
    "${mk[@]}" -j"${L4H_JOBS:-$(nproc)}" Image >"$out/nested-build.log" 2>&1 \
        || { tail -40 "$out/nested-build.log"; exit 1; }
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    mkdir -p "$dir/nested" "$dir/usr/bin"
    cp "$nested/arch/arm64/boot/Image" "$dir/nested/Image"
    "$root/tools/mkinitramfs.sh" "$dir/nested/initrd.cpio.gz" "$root/tests/guest/init-nested" >/dev/null
    fetch "https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-aarch64.tgz" \
        "firecracker-$FC_VERSION-aarch64.tgz" "$FC_SHA256"
    tar -xzf "$root/build/dl/firecracker-$FC_VERSION-aarch64.tgz" -C "$dir" \
        "release-$FC_VERSION-aarch64/firecracker-$FC_VERSION-aarch64"
    mv "$dir/release-$FC_VERSION-aarch64/firecracker-$FC_VERSION-aarch64" "$dir/usr/bin/firecracker"
    rmdir "$dir/release-$FC_VERSION-aarch64"
    fetch "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$CH_VERSION/cloud-hypervisor-static-aarch64" \
        "cloud-hypervisor-static-aarch64-$CH_VERSION" "$CH_SHA256"
    install -m 755 "$root/build/dl/cloud-hypervisor-static-aarch64-$CH_VERSION" "$dir/usr/bin/cloud-hypervisor"
    (cd "$dir" && find . | cpio -o -H newc --quiet | gzip -1) >>"$out/kvmtest.cpio.gz"
fi

"$root/tools/build-linux.sh" vmlinux >"$out/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$out/linux-build.log"; exit 1; }
aarch64-linux-gnu-objcopy --strip-debug "$root/build/linux-l4h-aarch64/vmlinux" "$out/vmlinux"
printf 'dom0_mem_mb=%s\ndom0_vcpus=2\n' "${L4H_DOM0_MEM_MB:-768}" >"$out/l4h.conf"
L4H_GUEST_KERNEL=$out/vmlinux L4H_DOM0_INITRD=$out/kvmtest.cpio.gz L4H_CONFIG=$out/l4h.conf \
    "$root/tools/mkfl4-efi-aarch64.sh" "$out/kvmtest.efi" \
    "$root/host/target/aarch64-sel4-roottask/debug/l4h-root.elf" \
    "$root/build/sel4-fl4-aarch64/bin/kernel.elf"
log=$out/qemu-gicv$gic.log
timeout "${KVMTEST_TIMEOUT:-1200}" "$root/tools/run-fl4-aarch64.sh" "$out/kvmtest.efi" </dev/null >"$log" 2>&1 &
qemu=$!
kill_tree() {
    local c
    for c in $(pgrep -P "$1"); do
        kill_tree "$c"
    done
    kill "$1" 2>/dev/null || true
}
# The machine never powers off by itself: stop it once dom0 has stopped.
while kill -0 "$qemu" 2>/dev/null; do
    if grep -aq "l4h-vmmgr: all guests stopped" "$log"; then
        sleep 1
        kill_tree "$qemu"
        break
    fi
    sleep 2
done
wait "$qemu" 2>/dev/null || true
sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$log" | grep -a 'KVMTEST\|NESTED\|FL4: EL'
grep -aq "KVMTEST: PASS" "$log"
for v in $vmms; do
    grep -aq "^$v: NESTED: done" "$log" || { echo "KVMTEST: $v failed" >&2; exit 1; }
done
