#!/usr/bin/env bash
# l4h-logd and failures (DESIGN.md §10.4): logd prints the last output of a
# component or of root that panics, and if logd itself faults, serial output
# stops and the host goes on. The serial monitor injects them, in a host
# built with L4H_TEST_INJECT=1.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$l4h_linux_out/vmlinux.stripped"
"$root/tools/mkinitramfs.sh" "$out/vm.cpio.gz" "$root/tests/guest/init-vm" >/dev/null
export L4H_GUEST_KERNEL="$l4h_linux_out/vmlinux.stripped" L4H_DOM0_INITRD="$out/vm.cpio.gz"
L4H_TEST_INJECT=1 L4H_DOM0_CMDLINE=console=hvc0 "$l4h_host_build"
log=$root/build/qemu-logd.log
fifo=$(mktemp -u)
mkfifo "$fifo"
qemu=
trap 'rm -f "$fifo"; [ -z "$qemu" ] || kill "$qemu" 2>/dev/null || true' EXIT
boot() {
    "$l4h_qemu" "$root/host/target/$l4h_target/debug/l4h-root.elf" <"$fifo" >"$log" 2>&1 &
    qemu=$!
    exec 3>"$fifo"
    wait_for "GUEST: ready" 120
}
stop() {
    kill "$qemu" 2>/dev/null || true
    wait "$qemu" 2>/dev/null || true
    qemu=
    exec 3>&-
}
wait_for() { # pattern timeout
    local end=$((SECONDS + $2))
    until grep -aq "$1" "$log"; do
        [ "$SECONDS" -lt "$end" ] || { echo "logd: timeout waiting for: $1"; tail -5 "$log"; exit 1; }
        sleep 0.5
    done
}

boot
# A component's panic: the text is in the ring, and logd prints it.
printf 'inject netd\r' >&3
wait_for "injected panic" 30
wait_for "l4h-rt: component 0x200 aborted" 30
printf 'help\r' >&3
wait_for "monitor: help" 30
# logd faults: serial output stops, and the host goes on: a reset does not
# wait for logd for ever. QEMU runs with -no-reboot, so the reset ends it.
printf 'inject logd\r' >&3
sleep 1
printf 'info\r' >&3
sleep 2
! grep -aq "monitor: 4 cores" "$log" || { echo "logd: output after logd faulted"; exit 1; }
printf 'reboot\r' >&3
end=$((SECONDS + 30))
while kill -0 "$qemu" 2>/dev/null; do
    [ "$SECONDS" -lt "$end" ] || { echo "logd: the host did not reset"; exit 1; }
    sleep 0.5
done
stop

boot
# Root panics: it stops, and logd, a task of its own, prints its last words.
printf 'info\r' >&3
wait_for "monitor: 4 cores" 30
printf 'inject root\r' >&3
wait_for "injected panic" 30
stop

# Root panics early in its boot, before it starts anything but logd and memd.
config=$out/logd-early.conf
echo 'test_early_panic=1' > "$config"
L4H_CONFIG="$config" "$l4h_qemu" "$root/host/target/$l4h_target/debug/l4h-root.elf" </dev/null >"$log" 2>&1 &
qemu=$!
wait_for "injected early panic" 60
kill "$qemu" 2>/dev/null || true
wait "$qemu" 2>/dev/null || true
qemu=
echo "logd: PASS"
