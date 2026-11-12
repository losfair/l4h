#!/usr/bin/env bash
# Run a hostile VMM on the victim's core, through the production manager.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/vmmguardtest
mkdir -p "$out"
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/densvm.cpio.gz" "$root/tests/guest/init-densvm" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-vmmguard" \
    "$root/tools/l4hctl/target/release/l4hctl" "$out/densvm.cpio.gz" >/dev/null
L4H_TEST_INJECT=1 L4H_TEST_VMM_BUSY=1 L4H_DOM0_MEM_MB=256 L4H_SMP=4 \
    "$root/tools/run-dom0.sh" "$out/dom0.cpio.gz" console=hvc0 60 >"$out/output.log" 2>&1
grep -aq 'VMMGUARDTEST: PASS' "$root/build/qemu.log" || { tail -n 60 "$out/output.log" >&2; exit 1; }
grep -a 'VMMGUARD' "$out/output.log"
