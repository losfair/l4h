#!/usr/bin/env bash
# FL4 AArch64's per-thread PAC keys, ArmHighVSpace and EL0 extensions as
# l4h hands them to guests (L4H_BOOT_HIGH_VSPACE, L4H_PROVIDER_ARM_PAC,
# L4H_PROVIDER_ARM_HIGH_VSPACE): dom0, with two vCPUs, loads
# tests/guest/highpac, then tests/guest/module, and runs
# tests/guest/selftest.c, on FL4 (DESIGN.md §5.10).
# Needs build/sel4-fl4-aarch64 (tools/build-fl4-aarch64.sh) and the
# AArch64 host (SEL4_PREFIX=build/sel4-fl4-aarch64
# tools/build-host-aarch64.sh), with L4H_FL4_SOURCE as for those.
#   L4H_HIGHPAC_BUILD_ONLY=1  only build build/highpac/highpac.efi, e.g. to
#     boot it on an Apple Silicon Mac: L4H_QEMU_ACCEL=hvf L4H_QEMU_CPU=host
#     L4H_QEMU_VIRTUALIZATION=off tools/run-fl4-aarch64.sh highpac.efi
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_ARCH=aarch64
source "$root/tools/guest-env.sh"
out=$root/build/highpac
rm -rf "$out" && mkdir -p "$out/highpac" "$out/module"
"$root/tools/build-linux.sh" vmlinux modules >"$out/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$out/linux-build.log"; exit 1; }
for m in highpac module; do
    cp "$root"/tests/guest/$m/* "$out/$m/"
    "$root/tools/build-linux.sh" M="$out/$m" modules >"$out/$m-build.log" 2>&1 \
        || { cat "$out/$m-build.log"; exit 1; }
done
aarch64-linux-gnu-gcc -O2 -static -pthread -o "$out/selftest" "$root/tests/guest/selftest.c"
cat >"$out/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t tmpfs tmp /tmp
ok=1
insmod /bin/l4h_highpac.ko || { echo 'HIGHPAC: FAIL load'; ok=0; }
rmmod l4h_highpac || { echo 'HIGHPAC: FAIL unload'; ok=0; }
if insmod /bin/l4h_modtest.ko && rmmod l4h_modtest; then
	echo 'MODTEST: PASS'
else
	echo 'MODTEST: FAIL'
	ok=0
fi
/bin/selftest || ok=0
[ "$ok" = 1 ] && echo 'HIGHPACTEST: DONE'
poweroff -f
INIT
"$root/tools/mkinitramfs.sh" "$out/highpac.cpio.gz" "$out/init" "$out/highpac/l4h_highpac.ko" \
    "$out/module/l4h_modtest.ko" "$out/selftest" >/dev/null
aarch64-linux-gnu-objcopy --strip-debug "$l4h_linux_out/vmlinux" "$out/vmlinux"
printf 'dom0_mem_mb=%s\ndom0_vcpus=%s\n' "${L4H_DOM0_MEM_MB:-512}" "${L4H_DOM0_VCPUS:-2}" >"$out/l4h.conf"
L4H_GUEST_KERNEL=$out/vmlinux L4H_DOM0_INITRD=$out/highpac.cpio.gz \
    L4H_CONFIG=$out/l4h.conf "$root/tools/mkfl4-efi-aarch64.sh" "$out/highpac.efi" \
    "$root/host/target/aarch64-sel4-roottask/$l4h_profile/l4h-root.elf" \
    "$root/build/sel4-fl4-aarch64/bin/kernel.elf"
[ "${L4H_HIGHPAC_BUILD_ONLY:-0}" = 1 ] && exit 0
log=$out/qemu.log
L4H_QEMU_VIRTUALIZATION=${L4H_QEMU_VIRTUALIZATION:-off} timeout "${L4H_TEST_TIMEOUT:-1200}" \
    "$root/tools/run-fl4-aarch64.sh" "$out/highpac.efi" </dev/null >"$log" 2>&1 &
qemu=$!
stopped=0
kill_tree() {
    local c
    for c in $(pgrep -P "$1"); do
        kill_tree "$c"
    done
    kill "$1" 2>/dev/null || true
}
# The machine never powers off by itself: stop it once dom0 has stopped.
while kill -0 "$qemu" 2>/dev/null; do
    if grep -aq "l4h-vmmgr: all guests stopped" "$log"; then
        stopped=1
        sleep 1
        kill_tree "$qemu"
        break
    fi
    sleep 2
done
wait "$qemu" 2>/dev/null || true
sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$log" | grep -a 'HIGHPAC\|MODTEST\|SELFTEST: \(PASS\|FAIL\)\|FL4: EL'
# Every test passed, module unloads included, and dom0 powered off (not
# the timeout).
for t in 'HIGHPAC: PASS' 'MODTEST: PASS' 'SELFTEST: PASS' 'HIGHPACTEST: DONE'; do
    grep -aq "$t" "$log" || { echo "no '$t'" >&2; exit 1; }
done
if grep -aq 'FAIL' "$log"; then
    echo 'a test failed' >&2
    exit 1
fi
[ "$stopped" = 1 ] || { echo 'dom0 did not stop' >&2; exit 1; }
