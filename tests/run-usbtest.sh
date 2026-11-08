#!/usr/bin/env bash
# A whole xHCI controller for a guest (DESIGN.md §9.7): QEMU's xHCI with
# a keyboard, a tablet, a USB storage disk, a hub with a second disk
# behind it, and a UAS disk.  dom0 checks that the controller is left to
# the firmware until a guest gets it; the guest enumerates everything,
# reads both disks' digests, writes one, reloads its driver (usbd resets
# the controller); a guest destroyed during I/O hands it to the next; a
# hostile driver (tests/guest/usbabuse) has usbd refuse its requests.
# USBTEST_HC=nec uses an NEC xHCI with plain MSI instead of MSI-X.
# L4H_QEMU_IOMMU=intel|amd (tools/run-qemu.sh) adds an IOMMU.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/usbtest
mkdir -p "$out"
"$root/tools/build-l4hctl.sh"
for i in 1 2 3; do
    head -c 8M /dev/urandom > "$out/usb$i.img"
done
sha1=$(sha256sum "$out/usb1.img" | cut -d' ' -f1)
sha2=$(sha256sum "$out/usb2.img" | cut -d' ' -f1)
sha3=$(sha256sum "$out/usb3.img" | cut -d' ' -f1)
case "${USBTEST_HC:-qemu}" in
    nec) hc="nec-usb-xhci,msix=off,id=xhci,addr=0x8" ;;
    *) hc="qemu-xhci,id=xhci,addr=0x8" ;;
esac
# 6 devices on QEMU's 4 ports (each USB 2 and USB 3): keyboard, disk,
# UAS disk (SuperSpeed), a hub with the second disk and the tablet.
devs="${USBTEST_QEMU_EXTRA:-} -device $hc -device usb-kbd,bus=xhci.0,port=1
    -drive file=$out/usb1.img,if=none,id=u1,format=raw -device usb-storage,bus=xhci.0,port=2,drive=u1
    -device usb-hub,bus=xhci.0,id=hub,port=4
    -drive file=$out/usb2.img,if=none,id=u2,format=raw -device usb-storage,bus=xhci.0,port=4.1,drive=u2 -device usb-tablet,bus=xhci.0,port=4.2
    -drive file=$out/usb3.img,if=none,id=u3,format=raw -device usb-uas,bus=xhci.0,port=3,id=uas
    -device scsi-hd,bus=uas.0,scsi-id=0,lun=0,drive=u3"
# The hostile driver, built against the module tree as a guest would.
"$root/tools/build-linux.sh" vmlinux modules >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$root/tools/build-kmods.sh" >/dev/null
rm -rf "$out/tree" "$out/mod" && mkdir -p "$out/tree" "$out/mod"
fsck.erofs --extract="$out/tree" "$l4h_linux_out/kmods.erofs" >/dev/null
kbuild=$out/tree/$(cat "$l4h_linux_out/include/config/kernel.release")/build
cp "$root"/tests/guest/usbabuse/* "$out/mod/"
make -s -C "$kbuild" M="$out/mod" modules >"$out/build.log" 2>&1 || { cat "$out/build.log"; exit 1; }
"$root/tools/mkinitramfs.sh" "$out/usbvm.cpio.gz" "$root/tests/guest/init-usbvm" "$out/mod/usbabuse.ko" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/usbtest.cpio.gz" "$root/tests/guest/init-usbtest" \
    "$l4h_ctl" "$out/usbvm.cpio.gz" >/dev/null
L4H_DOM0_DISKS=0 L4H_DOM0_MEM_MB=512 \
L4H_TEST_FAIL_PATTERN='USBTEST: FAIL:' \
L4H_QEMU_ARGS="$devs" \
    "$root/tools/run-dom0.sh" "$out/usbtest.cpio.gz" \
    "console=hvc0 L4H_TEST_SLOW=$l4h_test_slow usbbdf=00:08.0 usbdevs=6 usbsha=$sha1 usbsha2=$sha2 usbsha3=$sha3" \
    $((600 * l4h_test_slow)) | grep -E "USBTEST|USBVM|usbd|xHCI|panic|fault" || true
grep -q "USBTEST: PASS" "$root/build/qemu.log"
