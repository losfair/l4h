#!/usr/bin/env bash
# The Intel 82574L driver (l4h-nicd-e1000e) as dom0's uplink, on QEMU's
# e1000e: DHCP, ping and checked TCP transfers each way (tests/nic-peer.py
# on this host), before and after the driver restarts.  With
# L4H_QEMU_IOMMU=intel|amd its nicd must be confined (DMA through its own
# IOMMU domain, interrupts remapped) and QEMU must see no translation
# fault; without, it runs trusted.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
"$root/tools/build-l4hctl.sh"
"$root/tools/mkinitramfs.sh" "$out/e1000etest.cpio.gz" "$root/tests/guest/init-e1000etest" \
    "$l4h_ctl" "$root/tests/guest/udhcpc.script" >/dev/null
bytes=$((8 << 20))
rx_port=$((20000 + RANDOM % 20000)); tx_port=$((rx_port + 1))
peer_log=$root/build/e1000e-peer.log
rm -f "$peer_log"
python3 "$root/tests/nic-peer.py" "$rx_port" "$tx_port" "$bytes" "$peer_log" &
peer=$!
trap 'kill $peer 2>/dev/null || true' EXIT
L4H_DOM0_MEM_MB=256 \
L4H_QEMU_ARGS="-netdev user,id=n0 -device e1000e,netdev=n0" \
    "$root/tools/run-dom0.sh" "$out/e1000etest.cpio.gz" \
    "console=hvc0 L4H_TEST_SLOW=$l4h_test_slow E1000E_RX_PORT=$rx_port E1000E_TX_PORT=$tx_port E1000E_BYTES=$bytes" \
    $((240 * l4h_test_slow)) \
    | grep -aE "E1000ETEST|nicd|nic [0-9]|panic" || true
log=$root/build/qemu.log
grep -aq "E1000ETEST: done" "$log"
if [ -n "${L4H_QEMU_IOMMU:-}" ]; then
    grep -aq "driver e1000e, confined" "$log" || { echo "e1000e: not confined behind the IOMMU"; exit 1; }
else
    grep -aq "driver e1000e, trusted (not confined)" "$log"
fi
if grep -aiE "translation fail|iommu.*fault|dmar.*fault|amdvi.*(fault|error)" "$log"; then
    echo "e1000e: IOMMU faults"; exit 1
fi
# Every transfer arrived whole: the hashes dom0 printed are the peer's.
for label in first restarted; do
    for dir in rx tx; do
        line=$(grep -a "E1000ETEST: $label $dir " "$log" | tr -d '\r')
        set -- $line
        [ "$4" = "$bytes" ] || { echo "e1000e: $label $dir: $4 bytes, not $bytes"; exit 1; }
        grep -q "^$dir $5\$" "$peer_log" || { echo "e1000e: $label $dir: data differs"; cat "$peer_log"; exit 1; }
    done
done
echo "e1000e: PASS${L4H_QEMU_IOMMU:+ (IOMMU $L4H_QEMU_IOMMU)}"
