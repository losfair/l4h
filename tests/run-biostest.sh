#!/usr/bin/env bash
# Boot l4h the way a BIOS-only cloud does (DigitalOcean): SeaBIOS, BIOS GRUB
# from the image built by tools/mkimage.sh (the same image boots under
# UEFI, tests/run-uefitest.sh), virtio-blk boot disk, virtio-net.  GRUB
# loads l4h's files, dom0's initramfs and l4h.conf from the EFI partition,
# and multiboot2 sets up a framebuffer through VBE for the dashboard.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$root/tools/build-kmods.sh" >/dev/null
(cd "$root/tools/l4hctl" && cargo +stable build -q --release)
"$root/tools/mkinitramfs.sh" "$out/bios.cpio.gz" "$root/tests/guest/init-image" \
    "$root/tools/l4hctl/target/release/l4hctl" "$root/tests/guest/udhcpc.script" >/dev/null
env -u L4H_DOM0_DISKS -u L4H_DOM0_CMDLINE "$root/tools/build-host.sh"
# The boot disk is a host disk too: keep it away from dom0.
cat > "$out/bios.conf" <<'CONF'
# tests/run-biostest.sh
dom0_disks=0
dom0_cmdline="console=hvc0 imagetest=bios"
CONF
"$root/tools/mkimage.sh" -i "$out/bios.cpio.gz" \
    -c "$out/bios.conf" "$root/build/l4h-bios.raw"
log=$root/build/qemu-bios.log
timeout "${BIOSTEST_TIMEOUT:-120}" "$root/tools/run-bios.sh" "$root/build/l4h-bios.raw" </dev/null >"$log" 2>&1 &
qemu=$!
while kill -0 "$qemu" 2>/dev/null; do
    grep -aq "IMAGETEST: done\|l4h-root: all guests stopped" "$log" && { sleep 1; kill "$qemu"; break; }
    sleep 1
done
wait "$qemu" 2>/dev/null || true
grep -aE "IMAGETEST|module '|l4h-kmod|dashboard|disk [0-9]|nic [0-9]|memory:|cores:|l4h-root: [0-9]+ core|panic" "$log" || true
grep -aq "l4h-kmod: module tree" "$log"
grep -aq "l4h-root: dashboard on 1024x768 framebuffer" "$log"
grep -aq "IMAGETEST: cmdline .*imagetest=bios" "$log"
grep -aq "IMAGETEST: network ok" "$log"
