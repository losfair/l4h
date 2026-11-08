#!/usr/bin/env bash
# USB stress test and benchmark (DESIGN.md §9.7): QEMU's xHCI with a UAS
# disk (SuperSpeed), a BOT disk on a root port and a full-speed BOT disk behind
# a hub.  A guest measures each disk (sequential 1 MiB direct reads and
# writes, 4 KiB reads, all three at once); another runs writers, readers
# and verifiers on all of them for STRESS_SECS (default 120) while one disk
# is pulled out and put back (URB cancels under load); STRESS_CYCLES
# (default 5) guests are destroyed while every disk is busy; a last guest
# checks the stress guest's data survived.  USBSTRESS_NATIVE=1 also runs
# the benchmark natively in QEMU, with the build host's kernel and
# xhci-pci, for comparison.  L4H_QEMU_IOMMU and USBTEST_HC as for
# run-usbtest.sh.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/usbstress
mkdir -p "$out"
secs=${STRESS_SECS:-120}
cycles=${STRESS_CYCLES:-5}
"$root/tools/build-l4hctl.sh"
for d in uas:256 bot:256 fs:32; do
    rm -f "$out/${d%:*}.img"
    truncate -s "${d#*:}M" "$out/${d%:*}.img"
done
case "${USBTEST_HC:-qemu}" in
    nec) hc="nec-usb-xhci,msix=off,id=xhci,addr=0x8" ;;
    *) hc="qemu-xhci,id=xhci,addr=0x8" ;;
esac
devs="${USBSTRESS_QEMU_EXTRA:-} -device $hc
    -drive file=$out/uas.img,if=none,id=u1,format=raw,cache=none,aio=native -device usb-uas,bus=xhci.0,port=3,id=uas
    -device scsi-hd,bus=uas.0,scsi-id=0,lun=0,drive=u1
    -drive file=$out/bot.img,if=none,id=u2,format=raw,cache=none,aio=native -device usb-storage,bus=xhci.0,port=2,drive=u2
    -device usb-hub,bus=xhci.0,id=hub,port=4
    -drive file=$out/fs.img,if=none,id=u3,format=raw,cache=none,aio=native -device usb-storage,bus=xhci.0,port=4.1,drive=u3"
"$root/tools/mkinitramfs.sh" "$out/usbstressvm.cpio.gz" "$root/tests/guest/init-usbstressvm" >/dev/null
if [ "${USBSTRESS_NATIVE:-0}" = 1 ]; then
    # The same guest script on the build host's kernel, its stock xHCI
    # driver on the same emulated devices.
    nat=$out/native
    rm -rf "$nat" && mkdir -p "$nat/lib/native"
    kver=$(uname -r)
    for m in xhci_pci usb_storage uas sd_mod; do modprobe -S "$kver" --show-depends "$m"; done \
        | awk '$1 == "insmod" { print $2 }' | awk '!seen[$0]++' > "$nat/list"
    : > "$nat/lib/native/order"
    while read -r ko; do
        b=$(basename "$ko"); b=${b%.xz}
        case "$ko" in *.xz) xz -dc "$ko" > "$nat/lib/native/$b" ;; *) cp "$ko" "$nat/lib/native/$b" ;; esac
        echo "$b" >> "$nat/lib/native/order"
    done < "$nat/list"
    "$root/tools/mkinitramfs.sh" "$nat/base.cpio.gz" "$root/tests/guest/init-usbstressvm" >/dev/null
    (cd "$nat" && find lib | cpio -o -H newc --quiet | gzip -9) > "$nat/mods.cpio.gz"
    cat "$nat/base.cpio.gz" "$nat/mods.cpio.gz" > "$nat/native.cpio.gz"
    # shellcheck disable=SC2086
    timeout 600 qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 1G -nographic -no-reboot \
        -kernel "/boot/vmlinuz-$kver" -initrd "$nat/native.cpio.gz" \
        -append "console=ttyS0 quiet usbbench=1" $devs </dev/null > "$nat/qemu.log" 2>&1 || true
    grep -a 'USBSTRESS: bench\|USBSTRESS: FAIL\|USBSTRESS: disk' "$nat/qemu.log" | sed 's/^/native: /'
fi
"$root/tools/mkinitramfs.sh" "$out/usbstress.cpio.gz" "$root/tests/guest/init-usbstress" \
    "$l4h_ctl" "$out/usbstressvm.cpio.gz" >/dev/null
L4H_KMODS=1 L4H_DOM0_DISKS=0 L4H_DOM0_MEM_MB=512 \
L4H_TEST_FAIL_PATTERN='USBSTRESS: FAIL:' \
L4H_QEMU_ARGS="$devs" \
    "$root/tools/run-dom0.sh" "$out/usbstress.cpio.gz" \
    "console=hvc0 usbbdf=00:08.0 stresssecs=$secs stresscycles=$cycles" \
    $(((secs + 1500) * l4h_test_slow)) | grep -a -E "^USBSTRESS|usbd|panic|fault|quarantin" | grep -v default || true
grep -q "USBSTRESS: PASS" "$root/build/qemu.log"
