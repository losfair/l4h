#!/usr/bin/env bash
# Boot an l4h EFI under OVMF and commit the same image twice from dom0.
# This covers chunked LOAD and replacement; EXEC has its own later test.
# KEXEC_LOADTEST_BUILT=1 reuses already built kernel/Linux/host/kmods.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/kexec-loadtest
mkdir -p "$out"
if [ "${KEXEC_LOADTEST_BUILT:-0}" != 1 ]; then
    L4H_KERNEL_VARIANT=kexec "$root/tools/build-kernel.sh" >"$out/kernel-build.log" 2>&1
    "$root/tools/build-linux.sh" vmlinux >"$out/linux-build.log" 2>&1
    "$root/tools/build-kmods.sh" >/dev/null
fi
export SEL4_PREFIX="$root/build/sel4-kexec"
if [ "${KEXEC_LOADTEST_BUILT:-0}" != 1 ]; then
    "$root/tools/build-host.sh" >"$out/host-build.log" 2>&1
fi
(cd "$root/tools/l4hctl" && cargo +stable build -q --release)
"$root/tools/mkinitramfs.sh" "$out/initrd" "$root/tests/guest/init-kexec-load" \
    "$root/tools/l4hctl/target/release/l4hctl" "$root/tests/guest/udhcpc.script" >/dev/null
cat >"$out/l4h.conf" <<'CONF'
dom0_disks=1
dom0_cmdline="console=hvc0 kexec_loadtest=esp"
CONF
"$root/tools/mkefi.sh" "$out/l4h.efi" \
    "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" \
    "$root/build/sel4-kexec/bin/kernel.elf" "$root/build/kernel-kexec" >"$out/efi-build.log"
"$root/tools/mkimage.sh" -e "$out/l4h.efi" -i "$out/initrd" -c "$out/l4h.conf" "$out/l4h.raw" >"$out/image-build.log"
[ "${KEXEC_LOADTEST_BUILD_ONLY:-0}" != 1 ] || exit 0
log=$out/qemu.log
timeout "${KEXEC_LOADTEST_TIMEOUT:-180}" "$root/tools/run-uefi.sh" "$out/l4h.raw" </dev/null >"$log" 2>&1 &
qemu=$!
while kill -0 "$qemu" 2>/dev/null; do
    grep -aq "KEXECTEST: load ok\|KEXECTEST: FAIL\|l4h-root: all guests stopped" "$log" && { sleep 1; kill "$qemu" 2>/dev/null || true; break; }
    sleep 1
done
wait "$qemu" 2>/dev/null || true
grep -aE "KEXECTEST|kexec|panic|Boot failed" "$log" || true
grep -aq "KEXECTEST: load ok" "$log"
! grep -aq "KEXECTEST: FAIL\|panic" "$log"
[ "$(grep -ac 'l4h-root: kexec image staged' "$log")" -ge 2 ]
