#!/usr/bin/env bash
# Production console rings, memory-hotplug scheduling and control failure
# replies, and block-service replies across nested invocations. --qemu
# also checks hypercalls under sustained console kicks.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/devicetest
mkdir -p "$out"
# Compile the actual C functions against narrow mocks of their environment.
# Keep extraction explicit so a source reorganization fails this test instead
# of silently testing an obsolete copy of the implementation.
python3 - "$root" "$out" <<'PY'
import pathlib
import sys

root, out = map(pathlib.Path, sys.argv[1:])
writer = (root / 'guest/linux/arch/l4h/os-sel4/sys.c').read_text()
writer = writer.split('static unsigned int console_seq;', 1)[1].split('void l4h_power(int how)', 1)[0]
(out / 'console-writer.inc').write_text('static unsigned int console_seq;' + writer)
driver = (root / 'guest/linux/arch/l4h/drivers/memhp.c').read_text()
parts = []
for signature in ['static long mem_call(', 'static void memhp_work_fn(struct work_struct *w)\n{', 'static irqreturn_t memhp_interrupt(']:
    start = driver.index(signature)
    end = driver.index('\n}', start) + 2
    parts.append(driver[start:end])
(out / 'memhp-driver.inc').write_text('\n\n'.join(parts) + '\n')
# Use the complete block-service loop and handlers with mock hardware and
# IPC. Only the bare-metal entry attributes and driver declarations differ.
blkd = (root / 'host/l4h-blkd/src/main.rs').read_text()
start = blkd.index('use core::ops::{Deref, DerefMut};')
(out / 'blkd-main.inc').write_text(blkd[start:])
PY
cc -std=c11 -O2 -Wall -Wextra -Werror -I "$root/include" -I "$out" \
    -c "$root/tests/console-guest.c" -o "$out/console-guest.o"
cc -std=c11 -O2 -Wall -Wextra -Werror -Wno-unused-parameter -I "$root/include" -I "$out" \
    "$root/tests/memhp-events.c" -o "$out/memhp-events"
"$out/memhp-events"
rustc +stable --edition=2024 --crate-name l4h_abi --crate-type rlib \
    "$root/host/l4h-abi/src/lib.rs" -o "$out/libl4h_abi.rlib"
rustc +stable --edition=2024 --crate-name l4h_host --crate-type rlib \
    --extern l4h_abi="$out/libl4h_abi.rlib" \
    "$root/host/l4h-host/src/lib.rs" -o "$out/libl4h_host.rlib"
rustc +stable --edition=2024 --test -L dependency="$out" \
    --extern l4h_abi="$out/libl4h_abi.rlib" --extern l4h_host="$out/libl4h_host.rlib" \
    -C link-arg="$out/console-guest.o" "$root/tests/console.rs" -o "$out/console-tests"
"$out/console-tests"
rustc +stable --edition=2024 --test -L dependency="$out" \
    --extern l4h_abi="$out/libl4h_abi.rlib" --extern l4h_host="$out/libl4h_host.rlib" \
    "$root/tests/control-failure.rs" -o "$out/control-failure-tests"
"$out/control-failure-tests"
L4H_BLKD_TEST_SRC="$out/blkd-main.inc" rustc +stable --edition=2024 --test -L dependency="$out" \
    --extern l4h_host="$out/libl4h_host.rlib" \
    "$root/tests/blk-ipc.rs" -o "$out/blk-ipc-tests"
"$out/blk-ipc-tests"
if [ "${1:-}" = --qemu ]; then
    # shellcheck source=tools/guest-env.sh
    source "$root/tools/guest-env.sh"
    "$l4h_cc" -O2 -Wall -Wextra -Werror -static "$root/tests/guest/console-stress.c" -o "$out/console-stress"
    "$root/tools/mkinitramfs.sh" "$out/console.cpio.gz" "$root/tests/guest/init-consoletest" "$out/console-stress" >/dev/null
    L4H_DOM0_VCPUS=4 "$root/tools/run-dom0.sh" "$out/console.cpio.gz" console=hvc0 $((90 * l4h_test_slow)) >"$out/qemu-output.log" 2>&1
    grep -aq 'CONSOLETEST: PASS' "$root/build/qemu.log"
    if grep -aq 'CONSOLETEST: FAIL' "$root/build/qemu.log"; then
        exit 1
    fi
    echo 'CONSOLETEST: PASS (QEMU, continuous console output and RTC hypercalls)'
fi
