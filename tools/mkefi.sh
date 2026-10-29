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
# Usage: mkefi.sh <out.efi> [l4h-root.elf] [kernel.elf] [kernel-build]
# kernel-build is the CMake build directory for kernel.elf (default: the
# variant's build/kernel); its APIC and PCID settings go into a kexec
# variant note.
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
variant=${L4H_KERNEL_VARIANT:+-$L4H_KERNEL_VARIANT}
kernel=${3:-$root/build/sel4$variant/bin/kernel.elf}
kernel_build=${4:-${L4H_KERNEL_BUILD:-$root/build/kernel$variant}}
guest_kernel=${L4H_GUEST_KERNEL:-$root/build/linux-l4h/vmlinux}
guest_kmods=${L4H_GUEST_KMODS-$(dirname "$guest_kernel")/kmods.erofs}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

lapic=$(sed -n 's/^KernelLAPICMode:STRING=//p' "$kernel_build/CMakeCache.txt")
pcid=$(sed -n 's/^KernelSupportPCID:BOOL=//p' "$kernel_build/CMakeCache.txt")
case $lapic in X2APIC) flags=1 ;; XAPIC) flags=0 ;; *) echo "$kernel_build: unknown LAPIC mode '$lapic'" >&2; exit 1 ;; esac
case $pcid in ON) flags=$((flags | 2)) ;; OFF) ;; *) echo "$kernel_build: unknown PCID setting '$pcid'" >&2; exit 1 ;; esac
# A standard ELF note: name "l4h", type 1, one u64 of VARIANT_* flags.
printf '\x04\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00l4h\x00' >"$work/variant-note"
printf '%b' "\\x0$flags\\x00\\x00\\x00\\x00\\x00\\x00\\x00" >>"$work/variant-note"
objcopy --add-section ".note.l4h-kexec=$work/variant-note" \
    --set-section-flags .note.l4h-kexec=readonly \
    "$kernel" "$work/kernel.elf"

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
# it reads serial_port and fb_console itself. The fixed command sequence is
# shared with root's kexec parser; only these two optional lines expand here.
cat > "$work/grub.cfg" <<CFG
# l4h-boot 1
set timeout=0
serial_port=${L4H_SERIAL_PORT:-0x3f8}
fb_console=${L4H_FB_CONSOLE:-0}
CFG
while IFS= read -r line; do
    case $line in
        @ACPI@) [ -z "$acpi_cmd" ] || printf '%s\n' "$acpi_cmd" ;;
        @KMODS@) [ -z "$guest_kmods" ] || printf '%s\n' 'module2 (memdisk)/boot/kmods.erofs guest-kmods' ;;
        *) printf '%s\n' "$line" ;;
    esac
done >> "$work/grub.cfg" < "$root/tools/l4h-grub-fixed.cfg"
# seL4 and root load only the segments: drop the debug information.
objcopy --strip-debug "$rootserver" "$work/l4h-root.elf"
objcopy --strip-debug "$guest_kernel" "$work/vmlinux"
memdisk=("boot/vmlinux=$work/vmlinux")
[ -n "$guest_kmods" ] && memdisk+=("boot/kmods.erofs=$guest_kmods")
grub-mkstandalone -O x86_64-efi -o "$out" --compress=xz \
    --modules="part_gpt fat search search_fs_file multiboot2 serial terminal normal configfile test regexp echo loadenv efi_gop video video_fb tpm${acpi_cmd:+ acpi}" \
    --locales= --fonts= --themes= \
    "boot/grub/grub.cfg=$work/grub.cfg" \
    "boot/kernel.elf=$work/kernel.elf" \
    "boot/l4h-root.elf=$work/l4h-root.elf" "${memdisk[@]}" "${acpi_files[@]}"
echo "$out: $(( $(stat -c %s "$out") >> 10 )) KiB"
