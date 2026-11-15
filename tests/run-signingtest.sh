#!/usr/bin/env bash
# Verify the module signature policy with the actual kernel and EROFS tree.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/reproducible-env.sh"
source "$root/tools/guest-env.sh"
"$root/tools/build-kmods.sh" >/dev/null
out=$root/build/signingtest
mkdir -p "$out"
"$root/tools/mkinitramfs.sh" "$out/initrd" "$root/tests/guest/init-signingtest" \
    "$l4h_linux_out/net/ipv4/tcp_bic.ko" >/dev/null
L4H_KMODS=1 L4H_TEST_FAIL_PATTERN='SIGNINGTEST: FAIL' \
    "$root/tools/run-dom0.sh" "$out/initrd" \
    'console=hvc0 lockdown=integrity module.sig_enforce=1' "$((60 * l4h_test_slow))" >"$out/boot.log"
grep -a 'SIGNINGTEST:' "$out/boot.log"
grep -aq 'SIGNINGTEST: PASS' "$out/boot.log"
