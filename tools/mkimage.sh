#!/usr/bin/env bash
# Build a UEFI-bootable disk image: GPT with an EFI system partition that
# holds l4h as one UEFI application (tools/mkefi.sh), with the guest kernel
# in it, and, optionally, dom0's initramfs and the host settings in /l4h
# (DESIGN.md §10).
# This is the image format GCE imports (tar -Sczf image.tar.gz disk.raw;
# gcloud compute images create ... --guest-os-features=UEFI_COMPATIBLE).
# Usage: mkimage.sh [-e l4h.efi] [-i initrd] [-c l4h.conf]
#                   <out.raw> [l4h-root.elf]
#   -e  use this application instead of building one from l4h-root.elf
#   -i, -c  dom0's initramfs and the settings, copied to /l4h/dom0/initrd
#       and /l4h/l4h.conf
# L4H_SERIAL_PORT, L4H_FB_CONSOLE=1, L4H_GUEST_KERNEL and L4H_GUEST_KMODS
# go to tools/mkefi.sh.  L4H_ESP_MB
# sizes the partition (default: the payload plus 64 MiB, room for larger
# dom0 images later).
set -euo pipefail
# sfdisk is commonly installed outside an unprivileged user's PATH.
export PATH="$PATH:/usr/sbin:/sbin"
for tool in mformat mmd mcopy sfdisk; do command -v "$tool" >/dev/null; done
root=$(cd "$(dirname "$0")/.." && pwd)
efi= dom0_initrd= config=
while getopts e:i:c: o; do
    case $o in
        e) efi=$OPTARG ;;
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

if [ -z "$efi" ]; then
    efi=$work/BOOTX64.EFI
    "$root/tools/mkefi.sh" "$efi" "$rootserver" >/dev/null
fi

# EFI system partition: FAT32, sized for the payload.
payload=0
for f in "$efi" $dom0_initrd $config; do
    payload=$(( payload + $(stat -c %s "$f") ))
done
esp_mb=${L4H_ESP_MB:-$(( payload / 1048576 + 64 ))}
dd if=/dev/zero of="$work/esp.img" bs=1M count="$esp_mb" status=none
mformat -i "$work/esp.img" -F -v L4HEFI ::
mmd -i "$work/esp.img" ::/EFI ::/EFI/BOOT ::/l4h ::/l4h/dom0
mcopy -i "$work/esp.img" "$efi" ::/EFI/BOOT/BOOTX64.EFI
[ -n "$dom0_initrd" ] && mcopy -i "$work/esp.img" "$dom0_initrd" ::/l4h/dom0/initrd
[ -n "$config" ] && mcopy -i "$work/esp.img" "$config" ::/l4h/l4h.conf

# GPT disk: ESP from 1 MiB; GCE wants a whole number of GiB.
disk_gb=$(( (esp_mb + 2 + 1023) / 1024 ))
rm -f "$out"
truncate -s "${disk_gb}G" "$out"
printf 'label: gpt\nstart=2048, size=%sMiB, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI"\n' "$esp_mb" \
    | sfdisk -q "$out"
dd if="$work/esp.img" of="$out" bs=1M seek=1 conv=notrunc status=none
echo "$out: ${disk_gb} GiB, ESP ${esp_mb} MiB"
