#!/usr/bin/env bash
# A dedicated secondary ENI only: preserve management connectivity.
# Usage (root): run-on-host.sh PCI-ADDRESS OUR-IP PEER-IP [test options]
# Build ena-vfio locally, copy it beside this script, and start peer.py on
# PEER-IP. The peer must have MTU 9001; allow ICMP and TCP/UDP 9000-9001.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
bdf=${1:?PCI address}; ip=${2:?ENI IPv4 address}; peer=${3:?peer IPv4 address}
shift 3
[[ $bdf =~ ^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]$ ]] || exit 2
[ "$(id -u)" = 0 ] || { echo 'run as root' >&2; exit 2; }
dev=/sys/bus/pci/devices/$bdf
[ "$(basename "$(readlink "$dev/driver")")" = ena ] || { echo 'device must start bound to ena' >&2; exit 2; }
iface=$(basename "$dev"/net/*)
if ip -4 route show default | grep -qw "$iface" || ip -6 route show default | grep -qw "$iface"; then
    echo "refusing the default-route interface $iface" >&2; exit 2
fi
if [ -n "${SSH_CONNECTION:-}" ]; then
    client=${SSH_CONNECTION%% *}
    if ip route get "$client" | grep -qw "$iface"; then
        echo "refusing the SSH interface $iface" >&2; exit 2
    fi
fi
bin=${ENA_BIN:-$here/ena-vfio}
[ -x "$bin" ] || { echo "missing executable $bin" >&2; exit 2; }
old_huge=$(cat /proc/sys/vm/nr_hugepages)
modprobe vfio-pci
no_iommu=0
old_noiommu=$(cat /sys/module/vfio/parameters/enable_unsafe_noiommu_mode)
[ -e "$dev/iommu_group" ] || no_iommu=1
restore() {
    status=$?
    trap - EXIT INT TERM
    set +e
    if [ "$(basename "$(readlink "$dev/driver")")" = vfio-pci ]; then
        echo "$bdf" > /sys/bus/pci/drivers/vfio-pci/unbind
    fi
    echo > "$dev/driver_override"
    echo "$bdf" > /sys/bus/pci/drivers_probe
    echo "$old_noiommu" > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
    echo "$old_huge" > /proc/sys/vm/nr_hugepages
    # udev/networkd reconfigures this ENI after reprobe.
    udevadm settle
    driver=$(basename "$(readlink "$dev/driver")")
    echo "restored $bdf to $driver"
    [ "$driver" = ena ] || status=1
    exit "$status"
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$no_iommu" = 1 ]; then
    echo Y > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
    echo $((old_huge + 1)) > /proc/sys/vm/nr_hugepages
fi
ulimit -l unlimited
ip link set "$iface" down
echo vfio-pci > "$dev/driver_override"
echo "$bdf" > /sys/bus/pci/drivers/ena/unbind
echo "$bdf" > /sys/bus/pci/drivers_probe
timeout --signal=TERM --kill-after=5 180 "$bin" "$bdf" "$ip" "$peer" "$@"
