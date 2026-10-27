#!/usr/bin/env bash
# Boot l4h the way GCE does: UEFI firmware, GRUB multiboot2 from the image
# built by tools/mkimage.sh, NVMe boot disk, virtio-net.  The application
# holds the guest kernel and its module tree; GRUB loads dom0's initramfs
# and l4h.conf from the EFI partition.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$root/tools/build-kmods.sh" >/dev/null
(cd "$root/tools/l4hctl" && cargo +stable build -q --release)
"$root/tools/mkinitramfs.sh" "$out/uefi.cpio.gz" "$root/tests/guest/init-image" \
    "$root/tools/l4hctl/target/release/l4hctl" "$root/tests/guest/udhcpc.script" >/dev/null
env -u L4H_DOM0_DISKS -u L4H_DOM0_CMDLINE "$root/tools/build-host.sh"
# The boot disk is a host disk too: keep it away from dom0.
cat > "$out/uefi.conf" <<'CONF'
# tests/run-uefitest.sh
dom0_disks=0
dom0_cmdline="console=hvc0 imagetest=esp"
CONF
"$root/tools/mkimage.sh" -i "$out/uefi.cpio.gz" \
    -c "$out/uefi.conf" "$root/build/l4h.raw"
log=$root/build/qemu-uefi.log
timeout "${UEFITEST_TIMEOUT:-120}" "$root/tools/run-uefi.sh" "$root/build/l4h.raw" </dev/null >"$log" 2>&1 &
qemu=$!
while kill -0 "$qemu" 2>/dev/null; do
    grep -aq "IMAGETEST: done\|l4h-root: all guests stopped" "$log" && { sleep 1; kill "$qemu"; break; }
    sleep 1
done
wait "$qemu" 2>/dev/null || true
grep -aE "IMAGETEST|module '|l4h-kmod|disk [0-9]|nic [0-9]|memory:|cores:|l4h-root: [0-9]+ core|panic|Boot" "$log" || true
grep -aq "l4h-kmod: module tree" "$log"
grep -aq "IMAGETEST: cmdline .*imagetest=esp" "$log"
grep -aq "IMAGETEST: network ok" "$log"
