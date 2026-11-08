#!/usr/bin/env bash
# USB Ethernet benchmark (DESIGN.md §9.7): QEMU's usb-net (RNDIS / CDC
# Ethernet) on QEMU's xHCI, on QEMU's user network, given to a guest
# whole; it receives and sends NETBENCH_MB MB (default 256) to and from
# tests/usbnet-peer.py on the build host, NETBENCH_RUNS times (default 3),
# and pings it.  USBSTRESS_NATIVE=1 runs the same guest natively in QEMU
# with the build host's kernel and xhci-pci, on the same devices.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/usbnetbench
mkdir -p "$out"
mb=${NETBENCH_MB:-256}
runs=${NETBENCH_RUNS:-3}
"$root/tools/build-l4hctl.sh"
# Free ports for the peer.
read -r rxport txport < <(python3 -c 'import socket
s=[socket.socket() for _ in range(2)]
[x.bind(("127.0.0.1",0)) for x in s]
print(*[x.getsockname()[1] for x in s])')
python3 "$root/tests/usbnet-peer.py" "$rxport" "$txport" $((mb << 20)) > "$out/peer.log" 2>&1 &
peer=$!
trap 'kill $peer 2>/dev/null || true' EXIT
devs="-device qemu-xhci,id=xhci,addr=0x8 -netdev user,id=n0 -device usb-net,bus=xhci.0,port=1,netdev=n0"
args="netmb=$mb netruns=$runs rxport=$rxport txport=$txport"
"$root/tools/mkinitramfs.sh" "$out/usbnetvm.cpio.gz" "$root/tests/guest/init-usbnetvm" >/dev/null
if [ "${USBSTRESS_NATIVE:-0}" = 1 ]; then
    nat=$out/native
    rm -rf "$nat" && mkdir -p "$nat/lib/native"
    kver=$(uname -r)
    for m in xhci_pci usbnet cdc_ether rndis_host; do modprobe -S "$kver" --show-depends "$m"; done \
        | awk '$1 == "insmod" { print $2 }' | awk '!seen[$0]++' > "$nat/list"
    : > "$nat/lib/native/order"
    while read -r ko; do
        b=$(basename "$ko"); b=${b%.xz}
        case "$ko" in *.xz) xz -dc "$ko" > "$nat/lib/native/$b" ;; *) cp "$ko" "$nat/lib/native/$b" ;; esac
        echo "$b" >> "$nat/lib/native/order"
    done < "$nat/list"
    (cd "$nat" && find lib | cpio -o -H newc --quiet | gzip -9) > "$nat/mods.cpio.gz"
    cat "$out/usbnetvm.cpio.gz" "$nat/mods.cpio.gz" > "$nat/native.cpio.gz"
    # shellcheck disable=SC2086
    timeout 900 qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 1G -nographic -no-reboot \
        -kernel "/boot/vmlinuz-$kver" -initrd "$nat/native.cpio.gz" \
        -append "console=ttyS0 quiet $args" $devs </dev/null > "$nat/qemu.log" 2>&1 || true
    grep -a 'USBNET:' "$nat/qemu.log" | sed 's/^/native: /'
fi
"$root/tools/mkinitramfs.sh" "$out/usbnetbench.cpio.gz" "$root/tests/guest/init-usbnetbench" \
    "$l4h_ctl" "$out/usbnetvm.cpio.gz" >/dev/null
L4H_KMODS=1 L4H_DOM0_DISKS=0 L4H_DOM0_MEM_MB=512 \
L4H_TEST_FAIL_PATTERN='USBNET: FAIL' \
L4H_QEMU_ARGS="$devs" \
    "$root/tools/run-dom0.sh" "$out/usbnetbench.cpio.gz" "console=hvc0 usbbdf=00:08.0 $args" \
    $((1200 * l4h_test_slow)) | grep -a -E "^USBNET|usbd|panic" || true
grep -a 'usbnet-peer' "$out/peer.log" | sed 's/^/peer: /' || true
grep -q "USBNET: PASS" "$root/build/qemu.log"
