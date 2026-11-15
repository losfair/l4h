#!/usr/bin/env bash
# Run l4h on a Google Compute Engine VM: build the UEFI image with the test
# dom0 (tests/guest/init-gce), import it, boot an instance with an NVMe
# local SSD and a virtio-net NIC, and collect the results
# from the serial port.  Creates, then deletes, an image, an instance and a
# bucket object (KEEP=1 keeps the instance and image).  N2 attaches the
# boot disk with virtio-scsi (BOOT_DISK_INTERFACE=NVME on C3, N4, ...): it
# is a host disk, only read by the test since it has a GPT.
# SCSI_DISK_GB=n adds a blank persistent disk of n GB on the same SCSI
# controller, deleted with the instance, which the test writes.
# NIC_TYPE=GVNIC gives the instance a gVNIC, which C3, N4 and C4 require.
# "-lssd" machine types come with their local SSDs; LOCAL_SSD=0 asks for
# none on others (N4 has none).
# Usage: gce-test.sh PROJECT [ZONE] [MACHINE_TYPE]
# e.g.   BOOT_DISK_INTERFACE=NVME NIC_TYPE=GVNIC gce-test.sh PROJECT us-west1-b c3-standard-4-lssd
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
project=$1
zone=${2:-us-west1-b}
machine=${3:-n2-standard-4}
region=${zone%-*}
nic=${NIC_TYPE:-VIRTIO_NET}
ssd=--local-ssd=interface=NVME
case "$machine" in *-lssd) ssd= ;; esac
[ "${LOCAL_SSD:-1}" = 0 ] && ssd=
name=l4h-test-$(date +%Y%m%d-%H%M%S)
bucket=gs://$project-l4h-test
out=$root/build/gce; mkdir -p "$out"
log=$out/$name.serial.log

# ---- image
"$root/tools/build-kernel.sh" >"$root/build/kernel-build.log" 2>&1 \
    || { tail -20 "$root/build/kernel-build.log"; exit 1; }
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
objcopy --strip-debug "$root/build/linux-l4h/vmlinux" "$out/vmlinux"
(cd "$root/tools/l4hctl" && cargo +stable build -q --release)
gcc -O2 -static -pthread -o "$out/selftest" "$root/tests/guest/selftest.c"
"$root/tools/mkinitramfs.sh" "$out/selftest.cpio.gz" "$root/tests/guest/init-selftest" "$out/selftest" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/disk.cpio.gz" "$root/tests/guest/init-gcedisk" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/vm.cpio.gz" "$root/tests/guest/init-vm" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-gce" \
    "$root/tools/l4hctl/target/release/l4hctl" "$root/tests/guest/udhcpc.script" \
    "$out/selftest.cpio.gz" "$out/disk.cpio.gz" "$out/vm.cpio.gz" >/dev/null
L4H_DOM0_DISKS=0 L4H_DOM0_MEM_MB=1024 L4H_DOM0_CMDLINE=console=hvc0 L4H_WATCHDOG_SECS=${L4H_WATCHDOG_SECS:-0} \
    "$root/tools/build-host.sh"
L4H_GUEST_KERNEL=$out/vmlinux L4H_GUEST_SDK= \
    "$root/tools/mkimage.sh" -i "$out/dom0.cpio.gz" "$out/$name.raw" >/dev/null
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
gcloud storage buckets describe "$bucket" --project="$project" >/dev/null 2>&1 \
    || gcloud storage buckets create "$bucket" --project="$project" --location="$region" --quiet
gcloud storage cp "$out/$name.tar.gz" "$bucket/" --project="$project" --quiet
rm -f "$out/$name.tar.gz"
gcloud compute images create "$name" --project="$project" \
    --source-uri="$bucket/$name.tar.gz" --guest-os-features=UEFI_COMPATIBLE,GVNIC --quiet
gcloud compute instances create "$name" --project="$project" --zone="$zone" \
    --machine-type="$machine" --image="$name" ${BOOT_DISK_INTERFACE:+--boot-disk-interface=$BOOT_DISK_INTERFACE} \
    $ssd --network-interface=nic-type="$nic" \
    ${SCSI_DISK_GB:+--create-disk=size=${SCSI_DISK_GB}GB,type=pd-balanced,interface=SCSI,auto-delete=yes} \
    --metadata=serial-port-enable=TRUE --no-shielded-secure-boot --quiet

# ---- results from the serial port
end=$((SECONDS + ${GCE_TIMEOUT:-1200}))
while [ $SECONDS -lt $end ]; do
    sleep 20
    gcloud compute instances get-serial-port-output "$name" --project="$project" --zone="$zone" \
        >"$log" 2>/dev/null || continue
    # Serial lines end in CR LF.
    tr -d '\r' <"$log" | grep -aq "GCETEST: \(PASS\|FAIL\)$" && break
done
grep -a "GCETEST\|Got framebuffer\|l4h-root: [0-9]* core\|panic\|fault" "$log" || true
echo "serial log: $log"
grep -aq "GCETEST: PASS" "$log"
