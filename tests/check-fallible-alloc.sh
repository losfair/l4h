#!/usr/bin/env bash
# The paths dom0 can drive into low or fragmented memory make their
# CNodes with allocations that can fail (Arena::try_object, or the
# Alloc::dma_frames arena): Arena::object(_cap) and Alloc::object panic,
# and a panic of root is the whole host's, one of vmmgr its control
# plane's.  Each function named here, as l4h-root's nicd start
# (alloc_channel, alloc_dma) and netd mapping (map_uplink), its USB
# controller claim and attachment (usb.rs claim, attach) and disk
# attachment (blkd.rs prepare, attach), and vmmgr's guest creation
# (create, share_block) and SDK mapping (Sdk::map), must not use them.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
fail=0
# The body of fn NAME in FILE: from its line to the closing brace at its
# indentation.
body() {
    awk -v name="$2" '
        !found && $0 ~ "fn " name "[(<]" { found = 1; match($0, /^ */); indent = RLENGTH; print; next }
        found { print; if ($0 ~ "^ {" indent "}}$") exit }
    ' "$1"
}
check() {
    local file=$root/$1 fn=$2 b
    b=$(body "$file" "$fn")
    if [ -z "$b" ]; then
        echo "check-fallible-alloc: no fn $fn in $1" >&2
        fail=1
        return
    fi
    if grep -nE 'object_cap::<cap_type::CNode>|\.object\((alloc, )?ObjectBlueprint::CNode|\.expect\("guest CNode"\)' <<<"$b"; then
        echo "check-fallible-alloc: $1: $fn makes a CNode with an allocation that panics" >&2
        fail=1
    fi
}
check host/l4h-root/src/nicd.rs alloc_channel
check host/l4h-root/src/nicd.rs alloc_dma
check host/l4h-root/src/netd.rs map_uplink
check host/l4h-root/src/usb.rs claim
check host/l4h-root/src/usb.rs attach
check host/l4h-root/src/blkd.rs prepare
check host/l4h-root/src/blkd.rs attach
check host/l4h-vmmgr/src/guest.rs create
check host/l4h-vmmgr/src/guest.rs share_block
check host/l4h-vmmgr/src/kimage.rs map
# The nicd's and usbd's own CSpace CNodes are made before
# component::create, which would make them with one.  (The body is read
# whole first: grep -q stopping early would fail the pipe under pipefail.)
for at in nicd.rs:spawn usb.rs:claim; do
    b=$(body "$root/host/l4h-root/src/${at%%:*}" "${at#*:}")
    if ! grep -q 'cnode: Some(' <<<"$b"; then
        echo "check-fallible-alloc: ${at%%:*} ${at#*:} leaves its CNode to component::create" >&2
        fail=1
    fi
done
[ "$fail" = 0 ] && echo "check-fallible-alloc: ok"
exit "$fail"
