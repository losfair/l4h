#!/usr/bin/env bash
# Build build/debian.img: a minimal Debian (systemd) root filesystem for
# tests/run-debian.sh, with a boot-check unit that reports and powers off.
# Needs sudo and debootstrap.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
R=$root/build/debian-root
sudo rm -rf "$R"
sudo debootstrap --variant=minbase \
    --include=systemd-sysv,udev,iproute2,procps,kmod,dbus,ifupdown,isc-dhcp-client,nftables,iputils-ping,build-essential,fio,bzip2,wget \
    trixie "$R" http://deb.debian.org/debian
sudo sh -c "
echo l4h-debian > $R/etc/hostname
echo '/dev/vda / ext4 defaults 0 1' > $R/etc/fstab
printf 'auto lo\niface lo inet loopback\nauto eth0\niface eth0 inet dhcp\n' > $R/etc/network/interfaces
chroot $R passwd -d root >/dev/null
mkdir -p $R/etc/systemd/system/getty.target.wants $R/etc/systemd/system/multi-user.target.wants
ln -sf /lib/systemd/system/serial-getty@.service $R/etc/systemd/system/getty.target.wants/serial-getty@hvc0.service
install -m 755 $root/tests/guest/debian-l4h-test $R/usr/local/sbin/l4h-test
install -m 644 $root/tests/guest/debian-l4h-test.service $R/etc/systemd/system/l4h-test.service
ln -sf /etc/systemd/system/l4h-test.service $R/etc/systemd/system/multi-user.target.wants/l4h-test.service
"
# Source for the build workload (tests/run-workload.sh).
bb=$root/build/busybox-1.36.1.tar.bz2
[ -f "$bb" ] || wget -q -O "$bb" https://busybox.net/downloads/busybox-1.36.1.tar.bz2
sudo cp "$bb" "$R/root/busybox.tar.bz2"
sudo rm -f "$root/build/debian.img"
sudo mkfs.ext4 -q -F -d "$R" "$root/build/debian.img" 4G
sudo chown "$(id -u)" "$root/build/debian.img"
echo "$root/build/debian.img"
