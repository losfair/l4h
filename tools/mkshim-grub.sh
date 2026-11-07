# SPDX-License-Identifier: GPL-2.0-only
# shellcheck shell=bash
# Sourced by tools/mkefi.sh and tools/mkbios.sh: the GRUB lines that boot
# l4h as several partitions (DESIGN.md §11.4) when the boot partition has
# l4h-mk.conf, before the single-kernel lines.  The shim and its slot
# kernels (tools/build-mkshim.sh) come from GRUB path $1; root, the guest
# kernel and its module tree are $2, $3 and $4 (empty: none); l4h-mk.conf
# and each partition's dom0 initramfs and l4h.conf come from $5:
#   $5/l4h-mk.conf          the split (enables multikernel boot)
#   $5/pN/dom0/initrd       partition N's dom0 initramfs
#   $5/pN/l4h.conf          partition N's settings
#   $5/dom0/initrd, $5/l4h.conf   for partitions without their own
# GRUB's own settings (serial port, fb_console) come from $5/l4h.conf, as
# for one kernel; partition 0 owns the serial port and framebuffer.
# Usage: mkshim_grub <shim dir> <root> <vmlinux> <kmods> <config dir>
mkshim_grub() {
    local files=$1 rootserver=$2 vmlinux=$3 kmods=$4 conf=$5
    cat <<CFG
if [ -f "$conf/l4h-mk.conf" ]; then
    multiboot2 "$files/l4h-mkshim.elf" console_port=\$serial_port debug_port=\$serial_port\$fbcon
    for k in 0 1 2 3 4 5 6 7; do
        if [ -f "$files/kernel-s\$k.elf" ]; then module2 "$files/kernel-s\$k.elf" kernel-s\$k; fi
        if [ -f "$conf/p\$k/dom0/initrd" ]; then module2 "$conf/p\$k/dom0/initrd" p\$k:dom0-initrd; fi
        if [ -f "$conf/p\$k/l4h.conf" ]; then module2 "$conf/p\$k/l4h.conf" p\$k:l4h-config; fi
    done
    module2 "$rootserver" l4h-root
    module2 "$vmlinux" guest-kernel
CFG
    [ -n "$kmods" ] && echo "    if [ -f \"$kmods\" ]; then module2 \"$kmods\" guest-kmods; fi"
    cat <<CFG
    module2 "$conf/l4h-mk.conf" l4h-mk.conf
    if [ -f "$conf/dom0/initrd" ]; then module2 "$conf/dom0/initrd" dom0-initrd; fi
    if [ -f "$conf/l4h.conf" ]; then module2 "$conf/l4h.conf" l4h-config; fi
    boot
    echo "l4h: multikernel boot failed"
fi
CFG
}
