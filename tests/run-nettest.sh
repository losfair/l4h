#!/usr/bin/env bash
# M5 gate: L2 switches with an uplink, guest-to-guest traffic, multiple
# vNICs, switch isolation, isolated ports, MAC lock, and ports that outlive
# a dom0 restart.
# NETTEST_LEGACY=1 makes the uplink a legacy-only virtio-net device, as on
# GCE N2.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$l4h_linux_out/vmlinux.stripped"
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/netvm.cpio.gz" "$root/tests/guest/init-netvm" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/nettest.cpio.gz" "$root/tests/guest/init-nettest" \
    "$l4h_ctl" "$out/netvm.cpio.gz" \
    "$root/tests/guest/udhcpc.script" >/dev/null
mode=disable-legacy=on
[ "${NETTEST_LEGACY:-0}" = 1 ] && mode=disable-modern=on
L4H_DOM0_MEM_MB=384 \
L4H_QEMU_ARGS="-netdev user,id=n0 -device virtio-net-pci,netdev=n0,$mode" \
    "$root/tools/run-dom0.sh" "$out/nettest.cpio.gz" "console=hvc0 L4H_TEST_SLOW=$l4h_test_slow" ${NETTEST_TIMEOUT:-$((300 * l4h_test_slow))} \
    | grep -E "NETTEST|NETVM|netd|nic|switch|^ +[0-9]+ |panic|l4h-(root|vmmgr): (guest|comp)" || true
grep -q "NETTEST: PASS" "$root/build/qemu.log"
if [ "${NETTEST_LEGACY:-0}" = 1 ]; then
    grep -q "virtio-net legacy" "$root/build/qemu.log"
fi
