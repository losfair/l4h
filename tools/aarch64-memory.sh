# SPDX-License-Identifier: GPL-2.0-only
# shellcheck shell=bash
# Source after setting root. seL4's ARM RAM map must match QEMU's RAM size.
l4h_memory_stamp=$root/build/sel4-aarch64/.l4h-memory-mb
l4h_memory=${L4H_MEM:-$(cat "$l4h_memory_stamp" 2>/dev/null || echo 2048)}
if [[ ! $l4h_memory =~ ^([1-9][0-9]*)([mMgG]?)$ ]]; then
    echo "invalid L4H_MEM: $l4h_memory (use MiB, M or G)" >&2
    exit 1
fi
l4h_memory_mb=${BASH_REMATCH[1]}
case ${BASH_REMATCH[2]} in g|G) l4h_memory_mb=$((l4h_memory_mb * 1024));; esac
