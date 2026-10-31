#!/usr/bin/env bash
# Memory hotplug (DESIGN.md §8.5): dom0 grows a 256 MiB VM to 2 GiB, fills
# it, shrinks it (short of the target while the data is there, without
# losing it), empties and shrinks it, grows it again and destroys it,
# checking the VM's memory and the host's after each step
# (tests/guest/init-hotplugtest).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$l4h_linux_out/vmlinux.stripped"
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/hotplugvm.cpio.gz" "$root/tests/guest/init-hotplugvm" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/hotplugtest.cpio.gz" "$root/tests/guest/init-hotplugtest" \
    "$l4h_ctl" "$out/hotplugvm.cpio.gz" >/dev/null
L4H_DOM0_MEM_MB=256 L4H_MEM=${L4H_MEM:-4G} \
    "$root/tools/run-dom0.sh" "$out/hotplugtest.cpio.gz" "console=hvc0" $((600 * l4h_test_slow)) \
    | grep -aE "HOTPLUGTEST|l4h-memhp|memd|panic|BUG|WARNING" || true
grep -aq "HOTPLUGTEST: PASS" "$root/build/qemu.log"
