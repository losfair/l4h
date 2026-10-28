#!/usr/bin/env bash
# Build l4h as one UEFI application: a standalone GRUB whose memdisk holds
# the seL4 kernel, l4h-root, the guest kernel that dom0 and every VM run
# and its module tree (DESIGN.md §5.6).  dom0's initramfs and the settings
# come from the EFI system partition the application was loaded from
# (DESIGN.md §10):
#   /l4h/dom0/initrd    dom0's initramfs (optional)
#   /l4h/l4h.conf       host and dom0 settings (optional; see the manual)
# GRUB passes these to l4h-root as boot modules.  The partition is the
# one the application was loaded from or, when GRUB cannot tell, the first
# with /l4h/dom0/initrd (or /l4h/l4h.conf).
# Measured boot: the firmware measures this application, with everything
# in it, into PCR 4; GRUB's tpm module measures what it reads (the files
# above) into PCR 9 and its commands into PCR 8 (DESIGN.md §9.2).
# L4H_KERNEL_VARIANT selects a built seL4 variant when kernel.elf is omitted.
# Usage: mkefi.sh <out.efi> [l4h-root.elf] [kernel.elf]
# L4H_GUEST_KERNEL is the guest kernel (default: build/linux-l4h/vmlinux)
# and L4H_GUEST_KMODS its module tree (default: kmods.erofs next to it,
# from tools/build-kmods.sh; empty for none).
# L4H_SERIAL_PORT (default 0x3f8) and L4H_FB_CONSOLE=1 set the defaults of
# the serial_port and fb_console settings, which l4h.conf overrides.
# L4H_ACPI_TABLES (.aml files) has GRUB give l4h these ACPI tables too, and
# L4H_ACPI_EXCLUDE (a comma-separated list of signatures) none of the
# firmware's with those: to work around broken firmware tables, or to test
# TPM interfaces QEMU has none of (tests/run-attesttest.sh).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$1
rootserver=${2:-$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf}
kernel=${3:-$root/build/sel4${L4H_KERNEL_VARIANT:+-$L4H_KERNEL_VARIANT}/bin/kernel.elf}
guest_kernel=${L4H_GUEST_KERNEL:-$root/build/linux-l4h/vmlinux}
guest_kmods=${L4H_GUEST_KMODS-$(dirname "$guest_kernel")/kmods.erofs}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

acpi_cmd= acpi_files=()
if [ -n "${L4H_ACPI_TABLES:-}" ]; then
    acpi_cmd="acpi${L4H_ACPI_EXCLUDE:+ --exclude=$L4H_ACPI_EXCLUDE}"
    i=0
    for t in $L4H_ACPI_TABLES; do
        acpi_cmd+=" (memdisk)/boot/acpi/$i.aml"
        acpi_files+=("boot/acpi/$i.aml=$t")
        i=$((i + 1))
    done
fi

# l4h.conf is key=value lines, which GRUB sources as variable assignments:
# it reads serial_port and fb_console itself.
cat > "$work/grub.cfg" <<CFG
set timeout=0
serial_port=${L4H_SERIAL_PORT:-0x3f8}
fb_console=${L4H_FB_CONSOLE:-0}
# The partition this application was loaded from, when GRUB knows it
# (\$cmdpath is empty under OVMF), else the first one with l4h's files.
esp=
regexp --set=1:esp '^\(([^)]*)\)' "\$cmdpath"
if [ -z "\$esp" ]; then search --no-floppy --set=esp --file /l4h/dom0/initrd; fi
if [ -z "\$esp" ]; then search --no-floppy --set=esp --file /l4h/l4h.conf; fi
if [ -n "\$esp" ]; then
    if [ -f "(\$esp)/l4h/l4h.conf" ]; then source "(\$esp)/l4h/l4h.conf"; fi
fi
serial --port=\$serial_port --speed=115200
terminal_input serial
fbcon=
if [ "\$fb_console" = 1 ]; then
    terminal_output serial console
    fbcon=" fb_console"
else
    terminal_output serial
fi
$acpi_cmd
# GRUB 2.12 grows its heap through the firmware's boot services, even after
# multiboot2 has exited them: booting then faults if the relocator's last
# allocations no longer fit (it did under OvmfXen).  Have GRUB grow the
# heap now by reading a large file whole, which load_env does before it
# rejects the file and frees the buffer.
if load_env --file (memdisk)/boot/vmlinux; then true; fi
multiboot2 (memdisk)/boot/kernel.elf console_port=\$serial_port debug_port=\$serial_port\$fbcon
module2 (memdisk)/boot/l4h-root.elf
module2 (memdisk)/boot/vmlinux guest-kernel
${guest_kmods:+module2 (memdisk)/boot/kmods.erofs guest-kmods}
if [ -n "\$esp" ]; then
    if [ -f "(\$esp)/l4h/dom0/initrd" ]; then module2 "(\$esp)/l4h/dom0/initrd" dom0-initrd; fi
    if [ -f "(\$esp)/l4h/l4h.conf" ]; then module2 "(\$esp)/l4h/l4h.conf" l4h-config; fi
fi
boot
echo "l4h: boot failed"
CFG
# seL4 and root load only the segments: drop the debug information.
objcopy --strip-debug "$rootserver" "$work/l4h-root.elf"
objcopy --strip-debug "$guest_kernel" "$work/vmlinux"
memdisk=("boot/vmlinux=$work/vmlinux")
[ -n "$guest_kmods" ] && memdisk+=("boot/kmods.erofs=$guest_kmods")
grub-mkstandalone -O x86_64-efi -o "$out" --compress=xz \
    --modules="part_gpt fat search search_fs_file multiboot2 serial terminal normal configfile test regexp echo loadenv efi_gop video video_fb tpm${acpi_cmd:+ acpi}" \
    --locales= --fonts= --themes= \
    "boot/grub/grub.cfg=$work/grub.cfg" \
    "boot/kernel.elf=$kernel" \
    "boot/l4h-root.elf=$work/l4h-root.elf" "${memdisk[@]}" "${acpi_files[@]}"
echo "$out: $(( $(stat -c %s "$out") >> 10 )) KiB"
