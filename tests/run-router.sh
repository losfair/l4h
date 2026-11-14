#!/usr/bin/env bash
# M5 gate: a router VM (Debian, nftables masquerade) connects an internal
# switch to the uplink.  Needs build/debian.img (tests/mkdebian.sh).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$l4h_linux_out/vmlinux.stripped"
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/netvm.cpio.gz" "$root/tests/guest/init-netvm" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/router.cpio.gz" "$root/tests/guest/init-router" \
    "$l4h_ctl" "$out/netvm.cpio.gz" >/dev/null
cp --sparse=always "$root/build/debian.img" "$root/build/debian-run.img"
L4H_DOM0_DISKS=0 L4H_DOM0_MEM_MB=256 \
L4H_QEMU_ARGS="-drive file=$root/build/debian-run.img,if=none,id=d0,format=raw,cache=none -device virtio-blk-pci,drive=d0,disable-legacy=on -netdev user,id=n0 -device virtio-net-pci,netdev=n0,disable-legacy=on" \
    "$root/tools/run-dom0.sh" "$out/router.cpio.gz" "console=hvc0" 600 \
    | grep -aE "ROUTERTEST|ROUTER:|NETVM|^ +[0-9]+ |switch|panic" || true
grep -aq "ROUTERTEST: PASS" "$root/build/qemu.log"
