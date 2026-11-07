#!/usr/bin/env bash
# Focused no-TPM boot, on either architecture. Also included in ctltest.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/flagstest-${L4H_ARCH:-x86_64}
"$root/tools/build-l4hctl.sh"
"$root/tests/build-flagstest.sh" "$out"
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-flags" \
    "$l4h_ctl" "$out/flags-test" "$out/flagsvm.cpio.gz" >/dev/null
L4H_DOM0_DISKS=0 "$root/tools/run-dom0.sh" "$out/dom0.cpio.gz" console=hvc0 "${FLAGSTEST_TIMEOUT:-180}" > "$out/run.log"
grep -aE 'FLAG|l4h-attest|panic|no TPM' "$out/run.log"
grep -aq 'FLAGSTEST: PASS' "$out/run.log"
grep -aq 'FLAGVM: PASS no TPM' "$out/run.log"
grep -aq 'l4h-attest: no TPM: flags only' "$out/run.log"
! grep -aq 'FAIL' "$out/run.log" || exit 1
