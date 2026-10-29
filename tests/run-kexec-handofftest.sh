#!/usr/bin/env bash
# End-to-end handoff with no disks, NICs, IOMMU or TPM. The first host
# kexecs the EFI in its initramfs; the staged config changes dom0's command
# line, which the second host checks. Device/TPM teardown is tested later.
# KEXEC_HANDOFFTEST_BUILT=1 reuses already built kernel/Linux/host/kmods.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/kexec-handofftest
mkdir -p "$out"
if [ "${KEXEC_HANDOFFTEST_BUILT:-0}" != 1 ]; then
    L4H_KERNEL_VARIANT=kexec "$root/tools/build-kernel.sh" >"$out/kernel-build.log" 2>&1
    "$root/tools/build-linux.sh" vmlinux >"$out/linux-build.log" 2>&1
    "$root/tools/build-kmods.sh" >/dev/null
fi
export SEL4_PREFIX="$root/build/sel4-kexec"
if [ "${KEXEC_HANDOFFTEST_BUILT:-0}" != 1 ]; then
    "$root/tools/build-host.sh" >"$out/host-build.log" 2>&1
fi
(cd "$root/tools/l4hctl" && cargo +stable build -q --release)
"$root/tools/mkinitramfs.sh" "$out/target-initrd" "$root/tests/guest/init-kexec-handoff" \
    "$root/tools/l4hctl/target/release/l4hctl" >/dev/null
"$root/tools/mkefi.sh" "$out/target.efi" \
    "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" \
    "$root/build/sel4-kexec/bin/kernel.elf" "$root/build/kernel-kexec" >"$out/efi-build.log"
printf 'dom0_disks=0\ndom0_cmdline="console=hvc0 kexec_boot=done"\n' >"$out/target.conf"
printf 'dom0_disks=0\ndom0_cmdline="console=hvc0 kexec_boot=first"\n' >"$out/first.conf"
"$root/tools/mkinitramfs.sh" "$out/first-initrd" "$root/tests/guest/init-kexec-handoff" \
    "$root/tools/l4hctl/target/release/l4hctl" "$out/target.efi" "$out/target-initrd" "$out/target.conf" >/dev/null
[ "${KEXEC_HANDOFFTEST_BUILD_ONLY:-0}" != 1 ] || exit 0
log=$out/qemu.log
export L4H_KERNEL="$root/build/sel4-kexec/bin/kernel.elf"
export L4H_DOM0_INITRD="$out/first-initrd" L4H_CONFIG="$out/first.conf"
export L4H_GUEST_KERNEL="$root/build/linux-l4h/vmlinux" L4H_GUEST_KMODS="$root/build/linux-l4h/kmods.erofs"
export L4H_BALLOON=0 L4H_MEM=1G L4H_SMP=4
timeout "${KEXEC_HANDOFFTEST_TIMEOUT:-180}" "$root/tools/run-qemu.sh" \
    "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" </dev/null >"$log" 2>&1 &
qemu=$!
while kill -0 "$qemu" 2>/dev/null; do
    grep -aq "KEXECTEST: handoff ok\|KEXECTEST: FAIL" "$log" && { sleep 1; kill "$qemu" 2>/dev/null || true; break; }
    sleep 1
done
wait "$qemu" 2>/dev/null || true
grep -aE "KEXECTEST|kexec|panic|Boot failed" "$log" || true
grep -aq "KEXECTEST: handoff ok" "$log"
! grep -aq "KEXECTEST: FAIL\|panic" "$log"
