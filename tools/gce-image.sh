#!/usr/bin/env bash
# Package a disk image from tools/mkimage.sh for Google Compute Engine and
# print the commands that import it and start a VM.  Nothing is uploaded.
# Usage: gce-image.sh [--sev] <disk.raw> [image-name]
#
# Supported machine shapes: N2/N2D/C2 etc. with
#   --network-interface=nic-type=VIRTIO_NET, and C3/N4/C4 etc. with
#   --network-interface=nic-type=GVNIC (DQO queue format)
#   any boot disk interface; l4h passes virtio-scsi (N2 boot and persistent
#   disks) and NVMe disks (local SSDs, NVMe persistent disks on C3/N4) through
# Hardware virtualization is neither needed nor used.
#
# --sev: for an image that boots l4h-fl4.efi (FL4, which shares DMA memory
# with the hypervisor) on an AMD SEV Confidential VM: the image is marked
# SEV_CAPABLE and the instance is an N2D with SEV, on gVNIC.
set -euo pipefail
sev=0
if [ "${1:-}" = --sev ]; then
    sev=1
    shift
fi
disk=$1
name=${2:-l4h-$(date +%Y%m%d-%H%M)}
dir=$(dirname "$disk")
tarball=$dir/$name.tar.gz
# GCE requires the member to be named disk.raw.
ln -f "$disk" "$dir/disk.raw" 2>/dev/null || cp --sparse=always "$disk" "$dir/disk.raw"
tar -C "$dir" -Sczf "$tarball" disk.raw
rm -f "$dir/disk.raw"
features=UEFI_COMPATIBLE,GVNIC
machine="--machine-type=n2-standard-4"
nic=VIRTIO_NET
if [ "$sev" = 1 ]; then
    features=UEFI_COMPATIBLE,GVNIC,SEV_CAPABLE
    machine="--machine-type=n2d-standard-4 --confidential-compute-type=SEV --maintenance-policy=TERMINATE"
    nic=GVNIC
fi
cat <<CMDS
$tarball: $(du -h "$tarball" | cut -f1)

To deploy (replace BUCKET, PROJECT and ZONE):
  gsutil cp $tarball gs://BUCKET/
  gcloud compute images create $name --project=PROJECT \\
      --source-uri=gs://BUCKET/$name.tar.gz \\
      --guest-os-features=$features
  gcloud compute instances create $name --project=PROJECT --zone=ZONE \\
      $machine --image=$name \\
      --network-interface=nic-type=$nic \\
      --metadata=serial-port-enable=TRUE
  gcloud compute connect-to-serial-port $name --zone=ZONE
CMDS
