#!/usr/bin/env bash
# Boot Debian (systemd) as dom0 from a passed-through virtio-blk disk, with
# networking through the QEMU user-mode uplink.  The image comes from
# tests/mkdebian.sh (build/debian.img).
# Usage: run-debian.sh [vcpus]
# DEBIAN_ROLE adds l4h.role=<role> to the kernel command line;
# DEBIAN_KEEP=1 boots the image left by the previous run instead of a fresh
# copy.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/host-profile.sh"
img=$root/build/debian.img
[ -f "$img" ] || { echo "no $img: run tests/mkdebian.sh" >&2; exit 1; }
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
objcopy --strip-debug "$root/build/linux-l4h/vmlinux" "$root/build/linux-l4h/vmlinux.stripped"
export L4H_GUEST_KERNEL="$root/build/linux-l4h/vmlinux.stripped" L4H_DOM0_INITRD=
L4H_DOM0_MEM_MB=${L4H_DOM0_MEM_MB:-1024} L4H_DOM0_VCPUS=${1:-2} \
    L4H_DOM0_CMDLINE="console=hvc0 root=/dev/vda rw${DEBIAN_ROLE:+ l4h.role=$DEBIAN_ROLE}" "$root/tools/build-host.sh"
log=$root/build/qemu-debian.log
[ "${DEBIAN_KEEP:-0}" = 1 ] || cp --sparse=always "$img" "$root/build/debian-run.img"
"$root/tools/run-qemu.sh" "$root/host/target/x86_64-sel4-roottask/$l4h_profile/l4h-root.elf" \
    -drive file="$root/build/debian-run.img",if=none,id=d0,format=raw,cache=none \
    -device virtio-blk-pci,drive=d0,disable-legacy=on \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0,disable-legacy=on \
    </dev/null >"$log" 2>&1 &
qemu=$!
end=$((SECONDS + ${DEBIAN_TIMEOUT:-300}))
while kill -0 "$qemu" 2>/dev/null; do
    grep -aq "l4h-vmmgr: all guests stopped\|Kernel panic" "$log" && { sleep 1; kill "$qemu"; break; }
    [ "$SECONDS" -lt "$end" ] || { kill "$qemu"; break; }
    sleep 1
done
wait "$qemu" 2>/dev/null || true
grep -a "DEBIAN:\|WORKLOAD:\|Kernel panic\|Failed to start\|l4h-vmmgr: guest" "$log" || true
if [ -n "${DEBIAN_ROLE:-}" ]; then
    grep -aq "WORKLOAD: done" "$log"
else
    grep -aq "DEBIAN: system running" "$log"
fi
