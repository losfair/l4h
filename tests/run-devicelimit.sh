#!/usr/bin/env bash
# Fill dom0 and normal VMs to 64 devices, crossing the former channel and
# capability boundaries; exercise high event bits, sharing and restart.
# L4H_TEST_KERNEL may name an already-built compatible guest kernel.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/devicelimit
mkdir -p "$out"
if [ -n "${L4H_TEST_KERNEL:-}" ]; then
    objcopy --strip-debug "$L4H_TEST_KERNEL" "$out/vmlinux"
else
    "$root/tools/build-linux.sh" vmlinux > "$out/linux-build.log" 2>&1
    objcopy --strip-debug "$root/build/linux-l4h/vmlinux" "$out/vmlinux"
fi
"$root/tools/build-l4hctl.sh"
"$root/tools/build-host.sh" > "$out/host-build.log" 2>&1
"$root/tools/mkinitramfs.sh" "$out/devicelimitvm.cpio.gz" "$root/tests/guest/init-devicelimit" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-devicelimit" \
    "$root/tools/l4hctl/target/release/l4hctl" "$out/devicelimitvm.cpio.gz" >/dev/null
python3 - "$out" <<'PY'
from pathlib import Path
import sys

out = Path(sys.argv[1])
base = ('dom0_mem_mb=256\ndom0_vcpus=2\ndom0_disks=1\ndom0_disk0_mb=0\n'
        'dom0_nics=1\ndom0_internal_switches=0\nwatchdog_secs=0\n'
        'dom0_cmdline="console=hvc0 quiet"\n')
for name, count in [('fits', 59), ('overflow', 60)]:
    windows = ','.join(f'{8 + 16 * i}:8' for i in range(count))
    (out / f'{name}.conf').write_text(base + f'dom0_disk0_windows={windows}\n')
with (out / 'disk.raw').open('wb') as disk:
    disk.truncate(64 << 20)
PY
export L4H_GUEST_KERNEL="$out/vmlinux" L4H_GUEST_KMODS="" L4H_DOM0_INITRD="$out/dom0.cpio.gz"
export L4H_MEM="${L4H_MEM:-2G}" L4H_SMP="${L4H_SMP:-2}"
qemu=
trap 'if [ -n "$qemu" ]; then kill "$qemu" 2>/dev/null || true; wait "$qemu" 2>/dev/null || true; fi' EXIT
for case in fits overflow; do
    log=$out/$case.log
    L4H_CONFIG="$out/$case.conf" "$root/tools/run-qemu.sh" \
        "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" \
        -drive "file=$out/disk.raw,if=none,id=d0,format=raw" -device virtio-blk-pci,drive=d0,disable-legacy=on \
        -netdev user,id=n0 -device virtio-net-pci,netdev=n0,disable-legacy=on > "$log" 2>&1 </dev/null &
    qemu=$!
    end=$((SECONDS + 180))
    while kill -0 "$qemu" 2>/dev/null && [ "$SECONDS" -lt "$end" ]; do
        if grep -aqE 'DEVICELIMIT: (PASS|FAIL)|panicked at|Caught cap fault' "$log"; then break; fi
        sleep 1
    done
    kill "$qemu" 2>/dev/null || true
    wait "$qemu" 2>/dev/null || true
    qemu=
    grep -aE 'DEVICELIMIT|panicked at|dom0 device plan needs|Caught cap fault' "$log" || true
    if [ "$case" = fits ]; then
        grep -aq 'DEVICELIMIT: PASS' "$log"
        ! grep -aqE 'DEVICELIMIT: FAIL|panicked at|Caught cap fault' "$log" || exit 1
    else
        grep -aq 'dom0 device plan needs 65 slots' "$log"
        ! grep -aq "guest 0 'dom0' started" "$log" || exit 1
    fi
done
echo 'DEVICELIMIT: PASS (QEMU, 64 accepted and 65 rejected)'
