# SPDX-License-Identifier: GPL-2.0-only
# shellcheck shell=bash
# Sourced by mkefi.sh. Choose the external files' partition before reading
# any l4h.conf, so an A/B boot never sources the other slot's settings.

efi_boot_partition() {
    cat <<'CFG'
esp=
l4h_boot_ok=1
l4h_boot_env=
# regexp supplies GRUB's device globbing. Check every device before
# loading anything: search --set would silently pick the first match.
for l4h_device in (*); do
    if [ -f "$l4h_device/EFI/L4H/grubenv" ]; then
        if [ -n "$l4h_boot_env" ]; then l4h_boot_ok=0; fi
        l4h_boot_env="$l4h_device/EFI/L4H/grubenv"
    fi
done
# No selector anywhere: retain the single-partition boot behaviour.
if [ -z "$l4h_boot_env" ]; then
# Prefer the loading partition; OVMF can leave cmdpath empty.
regexp --set=1:esp '^\(([^)]*)\)' "$cmdpath"
if [ -z "$esp" ]; then search --no-floppy --set=esp --file /l4h/dom0/initrd; fi
if [ -z "$esp" ]; then search --no-floppy --set=esp --file /l4h/l4h.conf; fi
fi
if [ -n "$l4h_boot_env" ]; then
# Only these two variables may be imported from the shared boot selector.
l4h_esp_uuid=
l4h_esp_label=
if [ "$l4h_boot_ok" = 1 ]; then
    if load_env --file "$l4h_boot_env" l4h_esp_uuid l4h_esp_label; then
        esp=
        if [ -n "$l4h_esp_uuid" -a -z "$l4h_esp_label" ]; then
            if search --no-floppy --set=esp --fs-uuid -- "$l4h_esp_uuid"; then true; else l4h_boot_ok=0; fi
        elif [ -n "$l4h_esp_label" -a -z "$l4h_esp_uuid" ]; then
            if search --no-floppy --set=esp --label -- "$l4h_esp_label"; then true; else l4h_boot_ok=0; fi
        else
            l4h_boot_ok=0
        fi
    else
        l4h_boot_ok=0
    fi
fi
fi
CFG
}
