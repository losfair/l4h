#!/usr/bin/env bash
# AES-XTS and bounce writes through virtio-blk, NVMe (512/4Kn) or SCSI.
# CRYPTBLK_DEV=virtio|nvme|scsi, CRYPTBLK_LBA=512|4096; both architectures.
# L4H_TEST_KERNEL may supply an already-built compatible guest kernel.
# CRYPTBLK_NOAES=1 checks EOPNOTSUPP on a CPU with AES masked out.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=tools/guest-env.sh
source "$root/tools/guest-env.sh"
out=$root/build/cryptblk-${L4H_ARCH:-x86_64}-${CRYPTBLK_DEV:-virtio}-${CRYPTBLK_LBA:-512}${CRYPTBLK_NOAES:+-noaes}
mkdir -p "$out"
if [ -n "${L4H_TEST_KERNEL:-}" ]; then
    "$l4h_objcopy" --strip-debug "$L4H_TEST_KERNEL" "$out/vmlinux"
else
    "$root/tools/build-linux.sh" vmlinux > "$out/linux-build.log" 2>&1
    "$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$out/vmlinux"
fi
"$root/tools/build-l4hctl.sh"
"$l4h_cc" -O2 -static -Wall -Wextra -Werror "$root/tests/guest/cryptblk.c" -o "$out/cryptblk"
python3 - "$out" <<'PY'
from pathlib import Path
import sys
out = Path(sys.argv[1])
(out / 'cryptblk.key').write_bytes(bytes(range(64)))
(out / 'cryptblk-wrong.key').write_bytes(bytes(range(1, 65)))
PY
"$root/tools/mkinitramfs.sh" "$out/cryptblkvm.cpio.gz" "$root/tests/guest/init-cryptblkvm" "$out/cryptblk" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-cryptblk" \
    "$l4h_ctl" "$out/cryptblkvm.cpio.gz" "$out/cryptblk.key" "$out/cryptblk-wrong.key" >/dev/null
export L4H_GUEST_KERNEL="$out/vmlinux" L4H_DOM0_INITRD="$out/dom0.cpio.gz" L4H_GUEST_KMODS=
cmdline='console=hvc0'
if [ "${CRYPTBLK_NOAES:-0}" = 1 ]; then
    cmdline+=' noaes=1'
    if [ "${L4H_ARCH:-x86_64}" = x86_64 ]; then export L4H_QEMU_CPU=host,-vmx,+invtsc,-aes; fi
elif [ "${L4H_ARCH:-x86_64}" = aarch64 ]; then
    export L4H_QEMU_CPU=${L4H_QEMU_CPU:-max}
fi
L4H_DOM0_DISKS=0 L4H_DOM0_MEM_MB=256 L4H_WATCHDOG_SECS=0 L4H_DOM0_CMDLINE="$cmdline" \
    "$l4h_host_build" > "$out/host-build.log" 2>&1
truncate -s 0 "$out/disk.raw"; truncate -s 64M "$out/disk.raw"
lba=${CRYPTBLK_LBA:-512}
case "${CRYPTBLK_DEV:-virtio}" in
    nvme) dev=(-device "nvme,drive=d0,serial=crypt,logical_block_size=$lba,physical_block_size=$lba") ;;
    scsi) dev=(-device "virtio-scsi-pci,id=s0,disable-legacy=on"
               -device "scsi-hd,drive=d0,bus=s0.0,logical_block_size=$lba,physical_block_size=$lba") ;;
    virtio) dev=(-device "virtio-blk-pci,drive=d0,disable-legacy=on,logical_block_size=$lba,physical_block_size=$lba") ;;
    *) echo 'unsupported CRYPTBLK_DEV' >&2; exit 1 ;;
esac
"$l4h_qemu" "$root/host/target/$l4h_target/debug/l4h-root.elf" \
    -drive "file=$out/disk.raw,if=none,id=d0,format=raw" "${dev[@]}" > "$out/qemu.log" 2>&1 &
qemu=$!
trap 'kill "$qemu" 2>/dev/null || true; wait "$qemu" 2>/dev/null || true' EXIT
end=$((SECONDS + ${CRYPTBLK_TIMEOUT:-$((300 * l4h_test_slow))}))
while kill -0 "$qemu" 2>/dev/null && [ "$SECONDS" -lt "$end" ]; do
    if grep -aqE 'CRYPTBLK: (PASS|FAIL|NOAES PASS)|panicked at|Caught cap fault' "$out/qemu.log"; then break; fi
    sleep 1
done
kill "$qemu" 2>/dev/null || true
wait "$qemu" 2>/dev/null || true
trap - EXIT
sed -n '/l4h-root:/,$p' "$out/qemu.log"
if [ "${CRYPTBLK_NOAES:-0}" = 1 ]; then
    grep -aq 'CRYPTBLK: NOAES PASS' "$out/qemu.log"
else
    grep -aq 'CRYPTBLK: PASS' "$out/qemu.log"
    backend=aes-ni; [ "${L4H_ARCH:-x86_64}" != aarch64 ] || backend=armv8-ce
    grep -aq "aes-256-xts ($backend)" "$out/qemu.log"
    python3 "$root/tests/cryptblk-verify.py" "$out/disk.raw"
fi
