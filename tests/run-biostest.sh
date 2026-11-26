#!/usr/bin/env bash
# Boot l4h the way a BIOS-only cloud does (DigitalOcean): SeaBIOS, BIOS GRUB
# from the image built by tools/mkimage.sh (the same image boots under
# UEFI, tests/run-uefitest.sh), virtio-blk boot disk, virtio-net.  GRUB
# loads l4h's files, dom0's initramfs and l4h.conf from the EFI partition,
# and multiboot2 sets up a framebuffer through VBE for the dashboard, whose
# title dom0 sets (tests/dashboard-qemu.py).
# BIOS_FILES=dir UEFI_EFI=app.efi tests prebuilt BIOS files (tools/mkbios.sh)
# without rebuilding their stack; the image carries that application for
# UEFI.  This is how FL4 is booted here (L4H_KERNEL_VARIANT=fl4 mkbios.sh).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/guest
mkdir -p "$out"
bios=${BIOS_FILES:-}
image_args=()
if [ -n "$bios" ]; then
    efi=${UEFI_EFI:?BIOS_FILES needs UEFI_EFI, the UEFI application of the image}
    [ -f "$bios/grub.cfg" ] || { echo "$bios/grub.cfg: missing" >&2; exit 1; }
    [ -f "$efi" ] || { echo "$efi: missing" >&2; exit 1; }
    image_args=(-b "$bios" -e "$efi")
else
    "$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
        || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
    "$root/tools/build-sdk.sh" >/dev/null
fi
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/bios.cpio.gz" "$root/tests/guest/init-image" \
    "$root/tools/l4hctl/target/release/l4hctl" "$root/tests/guest/udhcpc.script" >/dev/null
[ -n "$bios" ] || env -u L4H_DOM0_DISKS -u L4H_DOM0_CMDLINE "$root/tools/build-host.sh"
# The boot disk is a host disk too: keep it away from dom0.
cat > "$out/bios.conf" <<'CONF'
# tests/run-biostest.sh
dom0_disks=0
dom0_cmdline="console=hvc0 imagetest=bios"
CONF
"$root/tools/mkimage.sh" "${image_args[@]}" -i "$out/bios.cpio.gz" \
    -c "$out/bios.conf" "$root/build/l4h-bios.raw"
log=$root/build/qemu-bios.log
qmp=$root/build/bios-qmp.sock
rm -f "$qmp" "$log"
timeout "${BIOSTEST_TIMEOUT:-180}" "$root/tools/run-bios.sh" "$root/build/l4h-bios.raw" \
    -qmp "unix:$qmp,server=on,wait=off" </dev/null >"$log" 2>&1 &
qemu=$!
# dom0 gives the dashboard a title and takes it back: on the screen.
python3 "$root/tests/dashboard-qemu.py" "$log" "$qmp" &
screen=$!
while kill -0 "$qemu" 2>/dev/null; do
    grep -aq "IMAGETEST: done\|l4h-vmmgr: all guests stopped" "$log" && { sleep 0.2; kill "$qemu"; break; }
    sleep 0.2
done
wait "$qemu" 2>/dev/null || true
rm -f "$qmp"
grep -aE "IMAGETEST|module '|dashboard|disk [0-9]|nic [0-9]|memory:|cores:|l4h-root: [0-9]+ core|panic" "$log" || true
# seL4 asks GRUB for 1024x768 (patch 0011); FL4 names no size and gets the
# display's preferred mode.  tests/dashboard-qemu.py follows either.
grep -aEq "l4h-root: dashboard on [0-9]+x[0-9]+ framebuffer" "$log"
grep -aq "IMAGETEST: cmdline .*imagetest=bios" "$log"
grep -aq "IMAGETEST: network ok" "$log"
wait "$screen"
