#!/usr/bin/env bash
# Pass a virtio-blk PCI disk through to dom0 and check reads and writes.
# Usage: run-blktest.sh [vcpus]
# BLKTEST_DEV=nvme uses an NVMe controller, BLKTEST_DEV=scsi a virtio-scsi
# controller (scsi-legacy: a legacy-only one, as on GCE), instead of
# virtio-blk (virtio-legacy: a legacy-only one, as under hypervisors whose
# virtio predates 1.0); BLKTEST_LBA=4096 gives either 4 KiB blocks.  scsi-luns adds
# a second disk as another LUN of the same target, behind a CD-ROM.
# ahci and ahci-disks use SATA ports (the latter has two disks and an ATAPI
# device); their temporary disk images are removed when the test ends.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/guest
mkdir -p "$out"
diskout=$out
case "${BLKTEST_DEV:-}" in
    ahci|ahci-disks)
        diskout=$(mktemp -d "$out/ahci.XXXXXXXX")
        trap 'rm -rf "$diskout"' EXIT ;;
esac
mkdir -p "$diskout/blkroot"
echo "hello from the host" > "$diskout/blkroot/hello.txt"
rm -f "$diskout/blk.img"
mkfs.ext4 -q -F -b 4096 -d "$diskout/blkroot" "$diskout/blk.img" 64M
case "${BLKTEST_DEV:-virtio}" in
ahci|ahci-disks)
      lba=${BLKTEST_LBA:-512}
      dev="-device ich9-ahci,id=sata0 -device ide-cd,bus=sata0.0
           -device ide-hd,drive=d0,bus=sata0.1,logical_block_size=$lba,physical_block_size=$lba"
      if [ "$BLKTEST_DEV" = ahci-disks ]; then
          truncate -s 16M "$diskout/blk2.img"
          dev+=" -drive file=$diskout/blk2.img,if=none,id=d1,format=raw
                 -device ide-hd,drive=d1,bus=sata0.4,logical_block_size=$lba,physical_block_size=$lba"
      fi ;;
nvme) lba=${BLKTEST_LBA:-512}
      dev="-device nvme,drive=d0,serial=l4h0,logical_block_size=$lba,physical_block_size=$lba" ;;
scsi-luns)
      lba=${BLKTEST_LBA:-512}
      truncate -s 0 "$diskout/blk2.img"; truncate -s 16M "$diskout/blk2.img"
      dev="-device virtio-scsi-pci,id=s0,disable-legacy=on -device scsi-cd,bus=s0.0,scsi-id=0
           -device scsi-hd,drive=d0,bus=s0.0,scsi-id=1,lun=0,logical_block_size=$lba,physical_block_size=$lba
           -drive file=$diskout/blk2.img,if=none,id=d1,format=raw
           -device scsi-hd,drive=d1,bus=s0.0,scsi-id=1,lun=3,logical_block_size=$lba,physical_block_size=$lba" ;;
scsi|scsi-legacy)
      lba=${BLKTEST_LBA:-512}
      # Target 1, as GCE places its boot disk.
      if [ "$BLKTEST_DEV" = scsi ]; then mode=disable-legacy=on; else mode=disable-modern=on; fi
      dev="-device virtio-scsi-pci,id=s0,$mode -device scsi-hd,drive=d0,bus=s0.0,scsi-id=1,logical_block_size=$lba,physical_block_size=$lba" ;;
virtio-legacy)
      dev="-device virtio-blk-pci,drive=d0,disable-modern=on" ;;
*)    dev="-device virtio-blk-pci,drive=d0,disable-legacy=on" ;;
esac
"$root/tools/mkinitramfs.sh" "$out/blktest.cpio.gz" "$root/tests/guest/init-blktest" >/dev/null
L4H_QEMU_ARGS="-drive file=$diskout/blk.img,if=none,id=d0,format=raw $dev" \
L4H_DOM0_VCPUS=${1:-1} "$root/tools/run-dom0.sh" "$out/blktest.cpio.gz" "console=hvc0" 120 \
    | grep -E "BLKTEST|blkd|ahci|virtio|l4h-root|vda" || true
grep -q "BLKTEST: PASS" "$root/build/qemu.log"
if [[ ${BLKTEST_DEV:-} = scsi-luns || ${BLKTEST_DEV:-} = ahci-disks ]]; then
    grep -q "BLKTEST: second disk independent: ok" "$root/build/qemu.log"
fi
debugfs -R "cat /guest.txt" "$diskout/blk.img" 2>/dev/null | grep -q "written by the l4h guest"
echo "host sees /guest.txt: ok"
