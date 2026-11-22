#!/usr/bin/env bash
# Package a disk image from tools/mkimage.sh for Google Compute Engine and
# print the commands that import it and start a VM.  Nothing is uploaded.
# Usage: gce-image.sh [--sev|--sev-snp|--tdx [--no-vtpm]] <disk.raw> [image-name]
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
# --sev-snp: for an image built with tools/mkfl4-efi.sh, deployed in
# an SEV-SNP zone as an N2D with SEV_SNP and the SEV_SNP_CAPABLE image tag.
# --tdx: for an image that boots l4h-fl4.efi built with FL4's Intel TDX
# support, deployed in a zone with Intel TDX (C3) as a C3 with TDX and the
# TDX_CAPABLE image tag, on gVNIC with an NVMe boot disk.  trustd then
# binds its key to a DCAP quote (l4hctl attest tdx-evidence) and, when the
# instance has Google's Shielded VM vTPM (the default here, with
# --shielded-vtpm), to the vTPM's quote as well: both roots of trust, one
# key (l4h-attest.py verify takes either or both).  With --no-vtpm the
# instance has no vTPM (--no-shielded-vtpm, and so
# --no-shielded-integrity-monitoring, which needs it): TDX alone, whose
# trust does not rest on the host's vTPM.
set -euo pipefail
confidential=
vtpm=1
case "${1:-}" in
    --sev) confidential=SEV; shift ;;
    --sev-snp) confidential=SEV_SNP; shift ;;
    --tdx) confidential=TDX; shift
        if [ "${1:-}" = --no-vtpm ]; then vtpm=0; shift; fi ;;
esac
disk=$1
name=${2:-l4h-$(date +%Y%m%d-%H%M)}
dir=$(dirname -- "$disk")
tarball=$dir/$name.tar.gz
# GCE requires the member to be named disk.raw.
tar -C "$dir" -hSczf "$tarball" --transform='s|^.*$|disk.raw|' -- "$(basename -- "$disk")"
features=UEFI_COMPATIBLE,GVNIC
machine="--machine-type=n2-standard-4"
nic=VIRTIO_NET
image_args=
if [ "$confidential" = TDX ]; then
    features+=,TDX_CAPABLE
    machine="--machine-type=c3-standard-4 --confidential-compute-type=TDX --maintenance-policy=TERMINATE"
    nic=GVNIC
    # Integrity monitoring, on by default for UEFI images, needs the vTPM.
    if [ "$vtpm" = 1 ]; then shielded=--shielded-vtpm; else shielded="--no-shielded-vtpm --no-shielded-integrity-monitoring"; fi
    image_args=" --boot-disk-interface=NVME --no-shielded-secure-boot $shielded --no-service-account --no-scopes"
elif [ -n "$confidential" ]; then
    features+=,${confidential}_CAPABLE
    machine="--machine-type=n2d-standard-4 --min-cpu-platform=\"AMD Milan\" --confidential-compute-type=$confidential --maintenance-policy=TERMINATE"
    nic=GVNIC
    image_args=" --boot-disk-interface=NVME --no-shielded-secure-boot --no-service-account --no-scopes"
fi
cat <<CMDS
$tarball: $(du -h "$tarball" | cut -f1)

To deploy (replace BUCKET, PROJECT and ZONE):
  gsutil cp $tarball gs://BUCKET/
  gcloud compute images create $name --project=PROJECT \\
      --source-uri=gs://BUCKET/$name.tar.gz \\
      --guest-os-features=$features
  gcloud compute instances create $name --project=PROJECT --zone=ZONE \\
      $machine --image=$name$image_args \\
      --network-interface=nic-type=$nic \\
      --metadata=serial-port-enable=TRUE
  gcloud compute connect-to-serial-port $name --project=PROJECT --zone=ZONE
CMDS
