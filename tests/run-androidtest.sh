#!/usr/bin/env bash
# Boot a Linux guest that runs tests/guest/androidtest.c twice: with the
# command line of an Android guest (lsm=selinux psi=1 bootconfig) and a
# bootconfig appended to its initramfs, as Android's boot images do; then
# with androidtest=default, which checks that a guest that asks for none
# of it gets none of it.  Both have the kernel's module tree, for vkms.
# Usage: run-androidtest.sh [vcpus]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest/android
mkdir -p "$out"
"$l4h_cc" -O2 -static -pthread -o "$out/androidtest" "$root/tests/guest/androidtest.c"
"$root/tools/mkinitramfs.sh" "$out/androidtest.cpio.gz" "$root/tests/guest/init-androidtest" \
    "$out/androidtest" >/dev/null
# The bootconfig text, its size and checksum (little-endian), then the
# magic, at the end of the initramfs.
python3 - "$out/androidtest.cpio.gz" "$out/androidtest-bootconfig.cpio.gz" <<'PY'
import struct, sys
bc = b'androidboot.l4htest = "ok"\n\0'
bc += b'\0' * (-len(bc) % 4)
with open(sys.argv[2], 'wb') as f:
    f.write(open(sys.argv[1], 'rb').read() + bc +
            struct.pack('<II', len(bc), sum(bc)) + b'#BOOTCONFIG\n')
PY
tmo=${L4H_TEST_TIMEOUT:-$((180 * l4h_test_slow))}
for mode in android default; do
    if [ "$mode" = android ]; then
        initrd=$out/androidtest-bootconfig.cpio.gz
        cmdline="console=hvc0 lsm=selinux psi=1 bootconfig"
    else
        initrd=$out/androidtest.cpio.gz
        cmdline="console=hvc0 androidtest=default"
    fi
    L4H_KMODS=1 L4H_DOM0_VCPUS=${1:-2} "$root/tools/run-dom0.sh" "$initrd" "$cmdline" "$tmo" \
        | sed -n '/ANDROIDTEST: start/,/ANDROIDTEST: \(PASS\|FAIL\)/p'
    cp "$root/build/qemu.log" "$root/build/androidtest-$mode.log"
    grep -q "ANDROIDTEST: PASS" "$root/build/qemu.log"
    ! grep -q "WARNING:\|BUG:" "$root/build/qemu.log"
done
