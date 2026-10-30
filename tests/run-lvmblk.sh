#!/usr/bin/env bash
# LVM-compatible volumes: a guest disk made of the extents of a linear LV
# whose guest order is not its disk order, as l4hctl lv-extents reads them
# from lvm. The build host edits the VG as dom0 would, through the PV's
# head and tools/l4h-lvm-pv. The guest writes a pattern across the extent
# boundaries and reads it back; dom0 checks that the volume's sectors are
# taken. Then Linux's own dm-linear must read the same bytes from
# /dev/VG/LV. Needs lvm2, and root (sudo -n) for the loop device.
# L4H_TEST_KERNEL may name an already-built compatible guest kernel.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export PATH="/usr/sbin:$PATH"
out=$root/build/lvmblk
mkdir -p "$out"
vg=l4hlvm$$
loop=
cleanup() {
    sudo -n lvm vgchange -q -an "$vg" >/dev/null 2>&1 || true
    sudo -n dmsetup remove "$vg-pv" 2>/dev/null || true
    if [ -n "$loop" ]; then sudo -n losetup -d "$loop" 2>/dev/null || true; fi
}
trap cleanup EXIT
"$root/tools/build-l4hctl.sh"
l4hctl=$root/tools/l4hctl/target/release/l4hctl

# A 256 MiB PV of 4 MiB extents.
rm -f "$out/disk.raw"
truncate -s 256M "$out/disk.raw"
loop=$(sudo -n losetup --show -f "$out/disk.raw")
sudo -n lvm pvcreate -q "$loop"
sudo -n lvm vgcreate -q -s 4m "$vg" "$loop"
ps=$(sudo -n lvm pvs --noheadings --nosuffix --units s -o pe_start "$loop" | tr -d ' ')
sudo -n lvm vgchange -q -an "$vg" >/dev/null
sudo -n losetup -d "$loop"
# From here on, as dom0 does: only the PV's head, made to look like the
# whole PV, and dom0's lvm.conf (the manual's "LVM logical volumes").
loop=$(sudo -n losetup --show -f --sizelimit $((ps * 512)) "$out/disk.raw")
pv=$(sudo -n "$root/tools/l4h-lvm-pv" "$loop" "$vg-pv")
mkdir -p "$out/lvm"
cat > "$out/lvm/lvm.conf" <<EOF
devices { global_filter = [ "a|^$pv\$|", "r|.*|" ] use_devicesfile = 0 }
activation { auto_activation_volume_list = [] }
EOF
dom0lvm() { sudo -n env LVM_SYSTEM_DIR="$out/lvm" "$@"; }
# The LV is PEs 10-11, then 2-4, then 7.
dom0lvm lvm lvcreate -q -an -Zn -Wn -l 2 -n lv "$vg" "$pv:10-11"
dom0lvm lvm lvextend -q -l +3 "$vg/lv" "$pv:2-4"
dom0lvm lvm lvextend -q -l +1 "$vg/lv" "$pv:7"
extents=$(dom0lvm "$l4hctl" lv-extents 0 "$vg/lv" --pv-start 0)
want="$((ps + 10 * 8192)):16384+$((ps + 2 * 8192)):24576+$((ps + 7 * 8192)):8192"
if [ "$extents" != "$want" ]; then
    echo "LVMBLK: FAIL: lv-extents gave $extents, want $want"
    exit 1
fi
sudo -n dmsetup remove "$pv"
sudo -n losetup -d "$loop"
loop=
echo "$extents" > "$out/extents"
# 24 MiB: each sector holds its number.
python3 -c 'import sys; sys.stdout.buffer.write(b"".join(b"%08d" % s * 64 for s in range(49152)))' > "$out/pattern"

if [ -n "${L4H_TEST_KERNEL:-}" ]; then
    objcopy --strip-debug "$L4H_TEST_KERNEL" "$out/vmlinux"
else
    "$root/tools/build-linux.sh" vmlinux > "$out/linux-build.log" 2>&1
    objcopy --strip-debug "$root/build/linux-l4h/vmlinux" "$out/vmlinux"
fi
"$root/tools/mkinitramfs.sh" "$out/lvmvm.cpio.gz" "$root/tests/guest/init-lvmblkvm" "$out/pattern" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-lvmblk" \
    "$l4hctl" "$out/lvmvm.cpio.gz" "$out/extents" >/dev/null
export L4H_GUEST_KERNEL="$out/vmlinux" L4H_DOM0_INITRD="$out/dom0.cpio.gz"
env L4H_DOM0_DISKS=0 L4H_DOM0_MEM_MB=256 L4H_WATCHDOG_SECS=0 "$root/tools/build-host.sh" > "$out/host-build.log" 2>&1
"$root/tools/run-qemu.sh" "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" \
    -drive "file=$out/disk.raw,if=none,id=d0,format=raw" -device virtio-blk-pci,drive=d0,disable-legacy=on \
    > "$out/qemu.log" 2>&1 &
qemu=$!
trap 'kill "$qemu" 2>/dev/null || true; wait "$qemu" 2>/dev/null || true; cleanup' EXIT
end=$((SECONDS + 300))
while kill -0 "$qemu" 2>/dev/null && [ "$SECONDS" -lt "$end" ]; do
    if grep -aqE 'LVMBLK: (PASS|FAIL)|panicked at|Caught cap fault' "$out/qemu.log"; then break; fi
    sleep 1
done
sed -n '/l4h-root:/,$p' "$out/qemu.log"
grep -aq 'LVMBLK: PASS' "$out/qemu.log"
! grep -aqE 'LVMVM: FAIL|LVMBLK: FAIL' "$out/qemu.log"
kill "$qemu" 2>/dev/null || true
wait "$qemu" 2>/dev/null || true

loop=$(sudo -n losetup --show -f "$out/disk.raw")
sudo -n lvm pvscan -q --cache "$loop" >/dev/null 2>&1 || true
sudo -n lvm vgchange -q -ay "$vg" >/dev/null
sudo -n cmp "/dev/$vg/lv" "$out/pattern"
echo "LVMBLK: PASS (dm-linear reads what the guest wrote)"
