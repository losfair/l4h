#!/usr/bin/env bash
# Build the guest kernel + root task with a given dom0 initramfs/cmdline and
# boot it in QEMU.  Usage: run-dom0.sh <initrd> [cmdline] [timeout]
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
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
if [ ! -f "$l4h_linux_out/vmlinux.stripped" ] || [ "$l4h_linux_out/vmlinux" -nt "$l4h_linux_out/vmlinux.stripped" ]; then
    "$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$l4h_linux_out/vmlinux.stripped"
fi
export L4H_GUEST_KERNEL="$l4h_linux_out/vmlinux.stripped" L4H_DOM0_INITRD="$initrd"
# Pass per-run dom0 settings in l4h.conf (the l4h-config boot module) so
# l4h-root builds once with default settings instead of relinking per test.
mkdir -p "$root/build/tmp"
cfg=$(mktemp "$root/build/tmp/run-dom0-conf.XXXXXX")
trap 'rm -f "$cfg"' EXIT
{
    printf 'dom0_mem_mb=%s\n' "${L4H_DOM0_MEM_MB:-256}"
    printf 'dom0_vcpus=%s\n' "${L4H_DOM0_VCPUS:-1}"
    printf 'watchdog_secs=%s\n' "${L4H_WATCHDOG_SECS:-0}"
    printf 'dom0_cmdline="%s"\n' "$cmdline"
    [ -z "${L4H_DOM0_DISKS:-}" ] || printf 'dom0_disks=%s\n' "$L4H_DOM0_DISKS"
    [ -z "${L4H_DOM0_DISK0_MB:-}" ] || printf 'dom0_disk0_mb=%s\n' "$L4H_DOM0_DISK0_MB"
    [ -z "${L4H_DOM0_DISK0_WINDOWS:-}" ] || printf 'dom0_disk0_windows=%s\n' "$L4H_DOM0_DISK0_WINDOWS"
    [ -z "${L4H_DOM0_IO_POOL_MB:-}" ] || printf 'dom0_io_pool_mb=%s\n' "$L4H_DOM0_IO_POOL_MB"
    [ -z "${L4H_DOM0_VSPACES:-}" ] || printf 'dom0_vspaces=%s\n' "$L4H_DOM0_VSPACES"
    [ -z "${L4H_DOM0_NICS:-}" ] || printf 'dom0_nics=%s\n' "$L4H_DOM0_NICS"
    [ -z "${L4H_DOM0_INTERNAL_SWITCHES:-}" ] || printf 'dom0_internal_switches=%s\n' "$L4H_DOM0_INTERNAL_SWITCHES"
    [ -z "${L4H_UPLINK_NIC:-}" ] || printf 'uplink_nic=%s\n' "$L4H_UPLINK_NIC"
    [ -z "${L4H_UPLINK2_NIC:-}" ] || printf 'uplink2_nic=%s\n' "$L4H_UPLINK2_NIC"
    [ -z "${L4H_BOOT_DISK:-}" ] || printf 'boot_disk=%s\n' "$L4H_BOOT_DISK"
    [ -z "${L4H_SERIAL_PORT:-}" ] || printf 'serial_port=%s\n' "$L4H_SERIAL_PORT"
    [ -z "${L4H_SERIAL_IRQ:-}" ] || printf 'serial_irq=%s\n' "$L4H_SERIAL_IRQ"
    [ -z "${L4H_FB_CONSOLE:-}" ] || printf 'fb_console=%s\n' "$L4H_FB_CONSOLE"
    [ -z "${L4H_IOMMU:-}" ] || printf 'iommu=%s\n' "$L4H_IOMMU"
    [ -z "${L4H_IOMMU_INTREMAP:-}" ] || printf 'iommu_intremap=%s\n' "$L4H_IOMMU_INTREMAP"
    [ -z "${L4H_PCIE_ACS:-}" ] || printf 'pcie_acs=%s\n' "$L4H_PCIE_ACS"
    [ -z "${L4H_NIC_AUTO:-}" ] || printf 'nic_auto=%s\n' "$L4H_NIC_AUTO"
    [ -z "${L4H_NIC_MAX_RESTARTS:-}" ] || printf 'nic_max_restarts=%s\n' "$L4H_NIC_MAX_RESTARTS"
    [ -z "${L4H_CONFIG:-}" ] || cat "$L4H_CONFIG"
} >"$cfg"
env -u L4H_DOM0_CMDLINE -u L4H_DOM0_MEM_MB -u L4H_DOM0_VCPUS -u L4H_DOM0_IO_POOL_MB \
    -u L4H_DOM0_VSPACES -u L4H_DOM0_DISKS -u L4H_DOM0_DISK0_MB -u L4H_DOM0_DISK0_WINDOWS \
    -u L4H_DOM0_NICS -u L4H_DOM0_INTERNAL_SWITCHES -u L4H_WATCHDOG_SECS \
    -u L4H_UPLINK_NIC -u L4H_UPLINK2_NIC -u L4H_BOOT_DISK \
    -u L4H_SERIAL_PORT -u L4H_SERIAL_IRQ -u L4H_FB_CONSOLE \
    -u L4H_IOMMU -u L4H_IOMMU_INTREMAP -u L4H_PCIE_ACS \
    -u L4H_NIC_AUTO -u L4H_NIC_MAX_RESTARTS \
    "$l4h_host_build"
L4H_CONFIG="$cfg" "$l4h_qemu" "$root/host/target/$l4h_target/$l4h_profile/l4h-root.elf" \
    ${L4H_QEMU_ARGS:-} </dev/null >"$log" 2>&1 &
qemu=$!
# The machine never powers off by itself: stop it once every guest has
# stopped, or at the timeout.
end=$((SECONDS + tmo))
while kill -0 "$qemu" 2>/dev/null; do
    if grep -aq "l4h-vmmgr: all guests stopped" "$log" ||
       { [ -n "${L4H_TEST_FAIL_PATTERN:-}" ] && grep -aEq -- "$L4H_TEST_FAIL_PATTERN" "$log"; } ||
       [ "$SECONDS" -ge "$end" ]; then
        sleep 0.2
        kill "$qemu" 2>/dev/null || true
        break
    fi
    sleep 0.2
done
wait "$qemu" 2>/dev/null || true
sed -n '/l4h-root:/,$p' "$root/build/qemu.log"
