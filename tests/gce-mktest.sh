#!/usr/bin/env bash
# Multikernel partitions (DESIGN.md §11.4) on a Google Compute Engine VM:
# an n2-standard-8 (i440FX, no MCFG: the partitions share the PCI
# configuration ports under a lock) split in two.  Partition 0 keeps the
# boot disk (virtio-scsi) and the first NIC; partition 1 gets the NVMe
# local SSD and a second NIC, on the VPC network NETWORK (default
# l4h-mk-test, created with a subnet if missing: a VM's NICs must be on
# different networks).  Each dom0 gets its address by DHCP over its own
# NIC and downloads over it, runs a VM, and the two ping each other over
# a link and flood it (tests/guest/init-mktest); partition 1 is refused
# host-reboot and its rtc-set reaches partition 0, which then resets the
# machine.  GCE_STRESS=S adds S seconds of MK_STRESS (tests/run-mktest.sh).
# Creates, then deletes, an image, an instance and a bucket object
# (KEEP=1 keeps the instance and image); the network stays.
# Usage: gce-mktest.sh PROJECT [ZONE] [MACHINE_TYPE]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
project=$1
zone=${2:-us-west1-b}
machine=${3:-n2-standard-8}
region=${zone%-*}
network=${NETWORK:-l4h-mk-test}
name=l4h-mktest-$(date +%Y%m%d-%H%M%S)
bucket=gs://$project-l4h-test
out=$root/build/gce-mk; mkdir -p "$out"
log=$out/$name.serial.log
url=http://deb.debian.org/debian/dists/trixie/Release

# ---- image: n2-standard-8 with one NVMe local SSD and two NICs is
# 00:03.0 virtio-scsi (boot disk), 00:04.0 NVMe, 00:05.0 and 00:06.0
# virtio-net, 00:07.0 virtio-rng.
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
objcopy --strip-debug "$l4h_linux_out/vmlinux" "$out/vmlinux"
"$root/tools/build-l4hctl.sh" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/vm.cpio.gz" "$root/tests/guest/init-mkvm" "$l4h_ctl" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-mktest" \
    "$l4h_ctl" "$out/vm.cpio.gz" "$root/tests/guest/udhcpc.script" >/dev/null
"$root/tools/build-mkshim.sh" 2 >/dev/null
"$root/tools/build-host.sh"
objcopy --strip-debug "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" "$out/l4h-root.elf"
rm -rf "$out/esp" && mkdir -p "$out/esp/p0" "$out/esp/p1"
printf 'partitions = 2\np1.pci = 00:04.0, 00:06.0\nlink.p0-p1 = 1\n' > "$out/esp/l4h-mk.conf"
stress=${GCE_STRESS:+ MKSTRESS=$GCE_STRESS}
printf 'dom0_cmdline="console=hvc0 MKP=0 MKPEER=1 MKURL=%s%s"\ndom0_mem_mb=512\nuplink_nic=00:05.0\n' \
    "$url" "$stress" > "$out/esp/p0/l4h.conf"
# GCE's DHCP names a gateway and the metadata server (its resolver) for a
# VM's first NIC only: the second's gateway is its subnet's first address.
printf 'dom0_cmdline="console=hvc0 MKP=1 MKPEER=0 MKGW=10.200.0.1 MKDNS=8.8.8.8 MKURL=%s%s"\ndom0_mem_mb=512\nuplink_nic=00:06.0\n' \
    "$url" "$stress" > "$out/esp/p1/l4h.conf"
L4H_GUEST_KMODS= L4H_GUEST_KERNEL="$out/vmlinux" "$root/tools/mkimage.sh" -i "$out/dom0.cpio.gz" -m "$out/esp" \
    "$out/$name.raw" "$out/l4h-root.elf" >/dev/null
"$root/tools/gce-image.sh" "$out/$name.raw" "$name" >/dev/null
rm -f "$out/$name.raw"

# ---- cloud resources
cleanup() {
    [ "${KEEP:-0}" = 1 ] && { echo "kept instance and image $name"; return; }
    gcloud compute instances delete "$name" --project="$project" --zone="$zone" --quiet >/dev/null 2>&1 || true
    gcloud compute images delete "$name" --project="$project" --quiet >/dev/null 2>&1 || true
    gcloud storage rm "$bucket/$name.tar.gz" --project="$project" >/dev/null 2>&1 || true
}
trap cleanup EXIT
if ! gcloud compute networks describe "$network" --project="$project" >/dev/null 2>&1; then
    gcloud compute networks create "$network" --project="$project" --subnet-mode=custom --quiet
    gcloud compute networks subnets create "$network" --project="$project" --network="$network" \
        --region="$region" --range=10.200.0.0/24 --quiet
fi
gcloud storage buckets describe "$bucket" --project="$project" >/dev/null 2>&1 \
    || gcloud storage buckets create "$bucket" --project="$project" --location="$region" --quiet
gcloud storage cp "$out/$name.tar.gz" "$bucket/" --project="$project" --quiet
rm -f "$out/$name.tar.gz"
gcloud compute images create "$name" --project="$project" \
    --source-uri="$bucket/$name.tar.gz" --guest-os-features=UEFI_COMPATIBLE,GVNIC --quiet
gcloud compute instances create "$name" --project="$project" --zone="$zone" \
    --machine-type="$machine" --image="$name" --local-ssd=interface=NVME \
    --network-interface=nic-type=VIRTIO_NET,network=default \
    --network-interface=nic-type=VIRTIO_NET,subnet="$network" \
    --metadata=serial-port-enable=TRUE --no-shielded-secure-boot --quiet

# ---- results from the serial port: until partition 0 resets the machine
end=$((SECONDS + ${GCE_TIMEOUT:-900} + ${GCE_STRESS:-0}))
while [ $SECONDS -lt $end ]; do
    sleep 20
    gcloud compute instances get-serial-port-output "$name" --project="$project" --zone="$zone" \
        2>/dev/null | tr -d '\r' >"$log" || continue
    grep -aq "MKTEST p[0-9]: FAIL\|l4h-root: host reboot (dom0)$\|panic\|cannot boot" "$log" && break
done
grep -aE "l4h-mkshim|MKTEST|no ECAM|partition [0-9]|RTC set|host reboot|nvme|panic|fault" "$log" | grep -v "MKVM" | awk 'NR <= 80' || true
ok=1
check() { grep -aq "$1" "$log" || { echo "missing: $2"; ok=0; }; }
check "MKTEST p0: done" "partition 0 finished"
check "\[p1\] MKTEST p1: done" "partition 1 finished"
check "MKTEST p0: downloaded" "partition 0's download over its NIC"
check "\[p1\] MKTEST p1: downloaded" "partition 1's download over its NIC"
check "MKTEST p0: link ok" "partition 0's ping over the link"
check "\[p1\] MKTEST p1: link ok" "partition 1's ping over the link"
check "\[p1\] MKTEST p1: host-reboot refused" "partition 1 refused host-reboot"
check "l4h-root: RTC set for partition 1" "partition 1's rtc-set reached partition 0"
check "l4h-root: host reboot (dom0)" "partition 0 reset the machine"
[ "$(grep -ac "l4h-root: no ECAM: PCI configuration through ports" "$log")" -ge 2 ] \
    || { echo "missing: both partitions on the shared PCI ports"; ok=0; }
if [ -n "${GCE_STRESS:-}" ]; then
    check "MKTEST p0: stress ok" "partition 0's stress"
    check "\[p1\] MKTEST p1: stress ok" "partition 1's stress"
else
    check "\[p1\] MKTEST p1: flood ok" "partition 1's flood"
fi
! grep -aq "stopped: no heartbeat" "$log" || { echo "heartbeats lost"; ok=0; }
echo "serial log: $log"
[ "$ok" = 1 ] && echo "GCE MKTEST: PASS" || { echo "GCE MKTEST: FAIL"; exit 1; }
