#!/usr/bin/env bash
# Build a disk image that boots under UEFI and BIOS (DESIGN.md §10): GPT
# with an EFI system partition and a BIOS boot partition.  The ESP holds
# l4h as one UEFI application (tools/mkefi.sh), with the guest kernel in
# it, l4h's BIOS files in /l4h/bios (tools/mkbios.sh) and, optionally,
# dom0's initramfs and the host settings in /l4h, which both boot paths
# load.  On BIOS, the MBR holds GRUB's boot sector and the BIOS boot
# partition its core image, which finds the ESP by its volume serial.
# This is the image format GCE imports (tar -Sczf image.tar.gz disk.raw;
# gcloud compute images create ... --guest-os-features=UEFI_COMPATIBLE),
# and what BIOS-only clouds (DigitalOcean custom images, or written to the
# disk from a rescue system) boot.
# Usage: mkimage.sh [-e l4h.efi] [-b biosdir] [-i initrd] [-c l4h.conf]
#                   <out.raw> [l4h-root.elf]
#   -e  use this application instead of building one from l4h-root.elf;
#       without -b, the image then boots only under UEFI
#   -b  use this directory from tools/mkbios.sh instead of building one
#   -i, -c  dom0's initramfs and the settings, copied to /l4h/dom0/initrd
#       and /l4h/l4h.conf
# L4H_SERIAL_PORT, L4H_FB_CONSOLE=1, L4H_GUEST_KERNEL and L4H_GUEST_KMODS
# go to tools/mkefi.sh and tools/mkbios.sh.  L4H_ESP_MB
# sizes the partition (default: the payload plus 64 MiB, room for larger
# dom0 images later).
set -euo pipefail
# sfdisk is commonly installed outside an unprivileged user's PATH.
export PATH="$PATH:/usr/sbin:/sbin"
for tool in mformat mmd mcopy sfdisk; do command -v "$tool" >/dev/null; done
root=$(cd "$(dirname "$0")/.." && pwd)
efi= bios= dom0_initrd= config=
while getopts e:b:i:c: o; do
    case $o in
        e) efi=$OPTARG ;;
        b) bios=$OPTARG ;;
        i) dom0_initrd=$OPTARG ;;
        c) config=$OPTARG ;;
        *) exit 2 ;;
    esac
done
shift $((OPTIND - 1))
out=$1
rootserver=${2:-$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ -z "$bios" ] && [ -z "$efi" ]; then
    bios=$work/bios
    "$root/tools/mkbios.sh" "$bios" "$rootserver" >/dev/null
fi
if [ -z "$efi" ]; then
    efi=$work/BOOTX64.EFI
    "$root/tools/mkefi.sh" "$efi" "$rootserver" >/dev/null
fi
grub_pc=/usr/lib/grub/i386-pc
if [ -n "$bios" ]; then
    for f in grub.cfg kernel.elf l4h-root.elf vmlinux; do
        [ -f "$bios/$f" ] || { echo "$bios/$f: missing (tools/mkbios.sh)" >&2; exit 1; }
    done
    [ -f "$grub_pc/boot.img" ] || { echo "$grub_pc: BIOS GRUB is not installed (grub-pc-bin)" >&2; exit 1; }
fi

# EFI system partition: FAT32, sized for the payload.
payload=0
for f in "$efi" $dom0_initrd $config ${bios:+"$bios"/*}; do
    payload=$(( payload + $(stat -c %s "$f") ))
done
esp_mb=${L4H_ESP_MB:-$(( payload / 1048576 + 64 ))}
# The volume serial, for the BIOS core image's search.
serial=$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')
dd if=/dev/zero of="$work/esp.img" bs=1M count="$esp_mb" status=none
mformat -i "$work/esp.img" -F -N "$serial" -v L4HEFI ::
mmd -i "$work/esp.img" ::/EFI ::/EFI/BOOT ::/l4h ::/l4h/dom0
mcopy -i "$work/esp.img" "$efi" ::/EFI/BOOT/BOOTX64.EFI
if [ -n "$bios" ]; then
    mmd -i "$work/esp.img" ::/l4h/bios
    mcopy -i "$work/esp.img" "$bios"/* ::/l4h/bios/
fi
[ -n "$dom0_initrd" ] && mcopy -i "$work/esp.img" "$dom0_initrd" ::/l4h/dom0/initrd
[ -n "$config" ] && mcopy -i "$work/esp.img" "$config" ::/l4h/l4h.conf

# GPT disk: ESP from 1 MiB, then a 1 MiB BIOS boot partition; GCE wants
# a whole number of GiB.
disk_gb=$(( (esp_mb + 3 + 1023) / 1024 ))
rm -f "$out"
truncate -s "${disk_gb}G" "$out"
{
    printf 'label: gpt\nstart=2048, size=%sMiB, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI"\n' "$esp_mb"
    [ -z "$bios" ] || printf 'size=1MiB, type=21686148-6449-6E6F-744E-656564454649, name="BIOS"\n'
} | sfdisk -q "$out"
dd if="$work/esp.img" of="$out" bs=1M seek=1 conv=notrunc status=none

if [ -n "$bios" ]; then
    # GRUB's core image with every module grub.cfg needs: it finds the ESP
    # and reads grub.cfg from it in normal mode.
    fs_uuid=${serial:0:4}-${serial:4:4}
    cat > "$work/early.cfg" <<CFG
search --no-floppy --fs-uuid --set=root $fs_uuid
set prefix=(\$root)/l4h/bios
set l4h=(\$root)/l4h
CFG
    grub-mkimage -O i386-pc -o "$work/core.img" -p /l4h/bios -c "$work/early.cfg" \
        biosdisk part_gpt fat search search_fs_uuid normal configfile test echo \
        multiboot2 serial terminal video video_fb vbe
    # What grub-bios-setup does for a BIOS boot partition, on a file: boot.img
    # in the MBR (keeping the partition table), with the core image's LBA;
    # the core image's first sector, diskboot.img, with the LBA and length
    # of the rest.
    python3 - "$out" "$grub_pc/boot.img" "$work/core.img" $(( 2048 + esp_mb * 2048 )) <<'PY'
import struct
import sys

disk, boot, core, lba = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
boot = bytearray(open(boot, "rb").read())
core = bytearray(open(core, "rb").read())
if len(boot) != 512 or len(core) > 2048 * 512:
    sys.exit("mkimage.sh: unexpected GRUB image sizes")
core += bytes(-len(core) % 512)
struct.pack_into("<Q", boot, 0x5c, lba)        # GRUB_BOOT_MACHINE_KERNEL_SECTOR
boot[0x64] = 0xff                              # boot drive: the BIOS's
boot[0x66:0x68] = b"\x90\x90"                  # hard disk: skip the drive check
struct.pack_into("<QHH", core, 0x200 - 12, lba + 1, len(core) // 512 - 1, 0x820)
with open(disk, "r+b") as f:
    f.seek(0)
    mbr = bytearray(f.read(512))
    mbr[:0x1b8] = boot[:0x1b8]
    f.seek(0)
    f.write(mbr)
    f.seek(lba * 512)
    f.write(core)
PY
fi
echo "$out: ${disk_gb} GiB, ESP ${esp_mb} MiB${bios:+, BIOS and UEFI}"
