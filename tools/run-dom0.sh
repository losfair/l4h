#!/usr/bin/env bash
# Build the guest kernel + root task with a given dom0 initramfs/cmdline and
# boot it in QEMU.  Usage: run-dom0.sh <initrd> [cmdline] [timeout]
# L4H_KMODS=1 builds and adds the kernel's module tree (/dev/l4hkmod).
# L4H_TEST_FAIL_PATTERN stops on a test's explicit failure marker (ERE).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
initrd=$(realpath "$1")
cmdline=${2:-console=hvc0}
tmo=${3:-60}
source "$root/tools/guest-env.sh"
if [ "${L4H_ARCH:-x86_64}" = aarch64 ]; then
    source "$root/tools/aarch64-memory.sh"
    if [ "$(cat "$l4h_memory_stamp" 2>/dev/null || echo 2048)" != "$l4h_memory_mb" ]; then
        "$root/tools/build-kernel-aarch64.sh"
        "$root/tools/build-loader-aarch64.sh"
    fi
fi
log=$root/build/qemu.log
# Never let a failed build leave the previous run's log to be checked.
rm -f "$log"
if [ -n "${L4H_TEST_KERNEL:-}" ]; then
    mkdir -p "$l4h_linux_out"
    "$l4h_objcopy" --strip-debug "$L4H_TEST_KERNEL" "$l4h_linux_out/vmlinux.stripped"
else
    "$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
        || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
    "$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$l4h_linux_out/vmlinux.stripped"
fi
export L4H_GUEST_KERNEL="$l4h_linux_out/vmlinux.stripped" L4H_DOM0_INITRD="$initrd" L4H_GUEST_KMODS=
if [ "${L4H_KMODS:-0}" = 1 ]; then
    "$root/tools/build-kmods.sh" >/dev/null
    L4H_GUEST_KMODS=$l4h_linux_out/kmods.erofs
fi
L4H_DOM0_MEM_MB=${L4H_DOM0_MEM_MB:-256} \
    L4H_DOM0_VCPUS=${L4H_DOM0_VCPUS:-1} L4H_WATCHDOG_SECS=${L4H_WATCHDOG_SECS:-0} L4H_DOM0_CMDLINE="$cmdline" \
    "$l4h_host_build"
"$l4h_qemu" "$root/host/target/$l4h_target/debug/l4h-root.elf" \
    ${L4H_QEMU_ARGS:-} </dev/null >"$log" 2>&1 &
qemu=$!
# The machine never powers off by itself: stop it once every guest has
# stopped, or at the timeout.
end=$((SECONDS + tmo))
while kill -0 "$qemu" 2>/dev/null; do
    if grep -aq "l4h-vmmgr: all guests stopped" "$log" ||
       { [ -n "${L4H_TEST_FAIL_PATTERN:-}" ] && grep -aEq -- "$L4H_TEST_FAIL_PATTERN" "$log"; } ||
       [ "$SECONDS" -ge "$end" ]; then
        sleep 0.5
        kill "$qemu" 2>/dev/null || true
        break
    fi
    sleep 1
done
wait "$qemu" 2>/dev/null || true
sed -n '/l4h-root:/,$p' "$root/build/qemu.log"
