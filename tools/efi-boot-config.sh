# SPDX-License-Identifier: GPL-2.0-only
# shellcheck shell=bash
# Sourced by mkefi.sh. Choose the external files' partition before reading
# any l4h.conf, so an A/B boot never sources the other slot's settings.

# A literal in a GRUB double-quoted string (also inside a device path).
grub_escape() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//\$/\\\$}
    printf '%s' "$value"
}

efi_boot_partition() {
    local uuid=${L4H_ESP_UUID:-} label=${L4H_ESP_LABEL:-} envfile=${L4H_BOOT_ENV:-}
    if [ -n "$uuid" ] && [ -n "$label" ]; then
        echo 'mkefi: choose L4H_ESP_UUID or L4H_ESP_LABEL' >&2
        return 1
    fi
    if [ -n "$envfile" ]; then
        if [[ "$envfile" != /* || "$envfile" == *')'* || "$envfile" == *'('* ]]; then
            echo 'mkefi: L4H_BOOT_ENV must be an absolute path within the selected partition' >&2
            return 1
        fi
        if [ -z "$uuid$label" ]; then
            echo 'mkefi: L4H_BOOT_ENV needs L4H_ESP_UUID or L4H_ESP_LABEL to locate its partition' >&2
            return 1
        fi
    fi
    if [[ "$uuid$label$envfile" == *$'\n'* || "$uuid$label$envfile" == *$'\r'* ]]; then
        echo 'mkefi: partition selectors and L4H_BOOT_ENV must be single-line values' >&2
        return 1
    fi
    echo 'esp='
    echo 'l4h_boot_ok=1'
    echo 'l4h_boot_env='
    if [ -n "$uuid$label" ]; then
        local flag=--fs-uuid value=$uuid
        if [ -n "$label" ]; then flag=--label; value=$label; fi
        printf 'if search --no-floppy --set=esp %s -- "%s"; then true; else l4h_boot_ok=0; fi\n' "$flag" "$(grub_escape "$value")"
        if [ -n "$envfile" ]; then
            printf 'l4h_boot_env="($esp)%s"\n' "$(grub_escape "$envfile")"
        fi
    else
        cat <<'CFG'
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
CFG
    fi
    cat <<'CFG'
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
