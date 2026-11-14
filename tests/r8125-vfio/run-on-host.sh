#!/usr/bin/env bash
# Run r8125-vfio on a Linux host against its RTL8125B port (root).  The
# port leaves r8169 for the run, so run this detached when it is the port
# you are logged in through:
#   systemd-run --unit=r8125-vfio ./run-on-host.sh 0000:05:00.0 IP GW [FIRMWARE]
# FIRMWARE is the PHY patch, uncompressed (rtl_nic/rtl8125b-2.fw; Debian
# ships it zstd-compressed in firmware-realtek).  The log is in
# /root/r8125-vfio.log; the port returns to r8169 after.
set -u
bdf=$1; ip=$2; gw=$3; fw=${4:-}
here=$(cd "$(dirname "$0")" && pwd)
log=/root/r8125-vfio.log
modprobe vfio-pci
echo "$bdf" > /sys/bus/pci/drivers/r8169/unbind
echo vfio-pci > "/sys/bus/pci/devices/$bdf/driver_override"
echo "$bdf" > /sys/bus/pci/drivers_probe
{
    echo "== without offloads, without the PHY patch"
    timeout 60 "$here/r8125-vfio" "$bdf" "$ip" "$gw"; echo "exit $?"
    echo "== with offloads${fw:+ and the PHY patch}"
    timeout 90 "$here/r8125-vfio" "$bdf" "$ip" "$gw" --offload ${fw:+--firmware "$fw"}; echo "exit $?"
} > "$log" 2>&1
echo "$bdf" > /sys/bus/pci/drivers/vfio-pci/unbind
echo > "/sys/bus/pci/devices/$bdf/driver_override"
echo "$bdf" > /sys/bus/pci/drivers/r8169/bind
sleep 5
systemctl restart systemd-networkd
