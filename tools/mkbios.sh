#!/usr/bin/env bash
# Build l4h's files for BIOS (non-UEFI) machines: the seL4 kernel,
# l4h-root (with the service ELFs), the guest kernel and its module tree,
# and grub.cfg, the GRUB script that boots them with multiboot2 (DESIGN.md
# §11).  BIOS GRUB cannot carry these in its core image as the UEFI
# application does in its memdisk (tools/mkefi.sh): the core image must fit
# in a few hundred KiB.  They live on a filesystem GRUB reads instead, in
# one directory $l4h:
#   $l4h/bios/          the files built here
#   $l4h/dom0/initrd    dom0's initramfs (optional)
#   $l4h/l4h.conf       host and dom0 settings (optional; see the manual)
# The GRUB that runs grub.cfg sets $l4h first: the core image of
# tools/mkimage.sh, or the menu entry of the Linux installer
# (tools/install) in the distribution's GRUB.
# There is no measured boot: GRUB's tpm module works only on UEFI.
# L4H_KERNEL_VARIANT selects a built seL4 variant when kernel.elf is omitted.
# Usage: mkbios.sh <outdir> [l4h-root.elf] [kernel.elf]
# L4H_GUEST_KERNEL, L4H_GUEST_KMODS, L4H_SERIAL_PORT and L4H_FB_CONSOLE are
# as for tools/mkefi.sh.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$1
rootserver=${2:-$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf}
kernel=${3:-$root/build/sel4${L4H_KERNEL_VARIANT:+-$L4H_KERNEL_VARIANT}/bin/kernel.elf}
guest_kernel=${L4H_GUEST_KERNEL:-$root/build/linux-l4h/vmlinux}
guest_kmods=${L4H_GUEST_KMODS-$(dirname "$guest_kernel")/kmods.erofs}
mkdir -p "$out"
rm -f "$out/kmods.erofs"

# Like tools/mkefi.sh's, but every path is under $l4h.  The insmods are
# for the distribution's GRUB; the core image has these modules built in.
# vbe lets multiboot2 set up the framebuffer the kernel asks for, for the
# dashboard and fb_console (patches 0011 and 0020).
cat > "$out/grub.cfg" <<CFG
# l4h on BIOS (tools/mkbios.sh).  \$l4h is the directory that holds bios/,
# dom0/initrd and l4h.conf.
insmod multiboot2
insmod serial
insmod vbe
serial_port=${L4H_SERIAL_PORT:-0x3f8}
fb_console=${L4H_FB_CONSOLE:-0}
if [ -f "\$l4h/l4h.conf" ]; then source "\$l4h/l4h.conf"; fi
serial --port=\$serial_port --speed=115200
terminal_input serial
fbcon=
if [ "\$fb_console" = 1 ]; then
    terminal_output serial console
    fbcon=" fb_console"
else
    terminal_output serial
fi
multiboot2 "\$l4h/bios/kernel.elf" console_port=\$serial_port debug_port=\$serial_port\$fbcon
module2 "\$l4h/bios/l4h-root.elf"
module2 "\$l4h/bios/vmlinux" guest-kernel
if [ -f "\$l4h/bios/kmods.erofs" ]; then module2 "\$l4h/bios/kmods.erofs" guest-kmods; fi
if [ -f "\$l4h/dom0/initrd" ]; then module2 "\$l4h/dom0/initrd" dom0-initrd; fi
if [ -f "\$l4h/l4h.conf" ]; then module2 "\$l4h/l4h.conf" l4h-config; fi
boot
echo "l4h: boot failed"
CFG
cp "$kernel" "$out/kernel.elf"
# seL4 and root load only the segments: drop the debug information.
objcopy --strip-debug "$rootserver" "$out/l4h-root.elf"
objcopy --strip-debug "$guest_kernel" "$out/vmlinux"
[ -n "$guest_kmods" ] && cp "$guest_kmods" "$out/kmods.erofs"
echo "$out: $(( $(du -sk "$out" | cut -f1) )) KiB"
