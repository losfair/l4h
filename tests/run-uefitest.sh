#!/usr/bin/env bash
# Boot l4h the way GCE does: UEFI firmware, GRUB multiboot2 from the image
# built by tools/mkimage.sh, NVMe boot disk, virtio-net.  The application
# holds the guest kernel and its build SDK; GRUB loads dom0's initramfs
# and l4h.conf from the EFI partition.
# UEFI_EFI=app.efi tests a prebuilt application without rebuilding its stack.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/guest
mkdir -p "$out"
efi=${UEFI_EFI:-}
image_args=()
if [ -n "$efi" ]; then
    [ -f "$efi" ] || { echo "$efi: missing" >&2; exit 1; }
    image_args=(-e "$efi")
else
    "$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
        || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
    "$root/tools/build-sdk.sh" >/dev/null
    env -u L4H_DOM0_DISKS -u L4H_DOM0_CMDLINE "$root/tools/build-host.sh"
fi
(cd "$root/tools/l4hctl" && cargo +stable build -q --release)
"$root/tools/mkinitramfs.sh" "$out/uefi.cpio.gz" "$root/tests/guest/init-image" \
    "$root/tools/l4hctl/target/release/l4hctl" "$root/tests/guest/udhcpc.script" >/dev/null
# The boot disk is a host disk too: keep it away from dom0.  fb_console=1:
# GRUB passes it to seL4 as a word of its own (DESIGN.md, "Settings").
cat > "$out/uefi.conf" <<'CONF'
# tests/run-uefitest.sh
dom0_disks=0
fb_console=1
dom0_cmdline="console=hvc0 imagetest=esp"
CONF
"$root/tools/mkimage.sh" "${image_args[@]}" -i "$out/uefi.cpio.gz" \
    -c "$out/uefi.conf" "$root/build/l4h.raw"
log=$root/build/qemu-uefi.log
timeout "${UEFITEST_TIMEOUT:-120}" "$root/tools/run-uefi.sh" "$root/build/l4h.raw" </dev/null >"$log" 2>&1 &
qemu=$!
while kill -0 "$qemu" 2>/dev/null; do
    grep -aq "IMAGETEST: done\|l4h-vmmgr: all guests stopped" "$log" && { sleep 1; kill "$qemu"; break; }
    sleep 1
done
wait "$qemu" 2>/dev/null || true
grep -aE "IMAGETEST|module '|disk [0-9]|nic [0-9]|memory:|cores:|l4h-root: [0-9]+ core|panic|Boot" "$log" || true
grep -aq "IMAGETEST: cmdline .*imagetest=esp" "$log"
# seL4 from GRUB's command line: debug_port the serial port alone (not with
# fb_console glued on, "debug_port=0x3f8fb_console"), and fb_console taken.
# Its "parsing cmdline" line comes before its console is up and never shows.
# Only a kernel that prints (not a release or FL4 application, UEFI_EFI)
# says its "Boot config".
if [ -z "$efi" ] || grep -aq "Boot config: debug_port" "$log"; then
    grep -aq "Boot config: debug_port = 0x3f8\s*$" "$log"
    grep -aEq "Boot config: (console copied to the framebuffer|framebuffer not usable as a console)" "$log"
fi
grep -aq "IMAGETEST: network ok" "$log"
kernel=seL4
if grep -aq 'FL4: seL4 17.0 (MCS) API kernel' "$log"; then kernel=FL4; fi
grep -aEq "IMAGETEST: version .+ \\($kernel\\)" "$log"
