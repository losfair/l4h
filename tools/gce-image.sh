#!/usr/bin/env bash
# Package a disk image from tools/mkimage.sh for Google Compute Engine and
# print the commands that import it and start a VM.  Nothing is uploaded.
# Usage: gce-image.sh [--sev|--sev-snp|--tdx [--no-vtpm]|--aarch64]
#                     [--extra-disk SPEC]... <disk.raw> [image-name]
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
# --sev-snp: for an image booting the released l4h-fl4.efi, deployed in
# an SEV-SNP zone as an N2D with SEV_SNP and the SEV_SNP_CAPABLE image tag.
# --tdx: for an image that boots l4h-fl4.efi built with FL4's Intel TDX
# support, deployed in a zone with Intel TDX (C3) as a C3 with TDX and the
# TDX_CAPABLE image tag, on gVNIC with an NVMe boot disk.  On a TDX guest,
# l4h-fl4.efi, l4h-root and l4h-trustd ignore any cloud vTPM completely and
# attest through TDX alone (l4hctl attest tdx-evidence / tdx-quote).  With
# --no-vtpm the instance also omits GCE's Shielded VM vTPM
# (--no-shielded-vtpm --no-shielded-integrity-monitoring).
# --aarch64: for an image that boots FL4's AArch64 l4h (tools/mkimage.sh
# with L4H_ARCH=aarch64): an ARM64 image, deployed as an Arm C4A (Google
# Axion) on gVNIC with a hyperdisk boot disk.
# --extra-disk SPEC (repeatable): a blank disk for the instance,
# --create-disk=SPEC (e.g. size=10GB,type=hyperdisk-balanced,auto-delete=yes).
# --machine-type TYPE and --nic-type TYPE replace the mode's machine type
# (its other flags kept) and NIC type; --local-ssd adds an NVMe local SSD.
# Options go anywhere; arguments after -- are never options.  The image
# name must be a GCE resource name.
set -euo pipefail
confidential=
vtpm=1
arm=
extra_disks=()
machine_type=
nic_type=
local_ssd=
pos=()
usage() {
    echo "Usage: gce-image.sh [--sev|--sev-snp|--tdx [--no-vtpm]|--aarch64] [--extra-disk SPEC]..." >&2
    echo "                    [--machine-type TYPE] [--nic-type TYPE] [--local-ssd] <disk.raw> [image-name]" >&2
    exit 2
}
mode() {
    [ -z "$confidential$arm" ] || { echo "gce-image.sh: one of --sev, --sev-snp, --tdx and --aarch64" >&2; exit 2; }
}
# An option's value: not empty, not another option.
value() {
    case $2 in
        ''|-*) echo "gce-image.sh: $1 needs a value, not '$2'" >&2; exit 2 ;;
    esac
}
while [ $# -gt 0 ]; do
    case $1 in
        --sev) mode; confidential=SEV ;;
        --sev-snp) mode; confidential=SEV_SNP ;;
        --tdx) mode; confidential=TDX ;;
        --aarch64) mode; arm=1 ;;
        --no-vtpm) vtpm=0 ;;
        --local-ssd) local_ssd=1 ;;
        --extra-disk|--machine-type|--nic-type)
            value "$1" "${2:-}"
            case $1 in
                --extra-disk) extra_disks+=("$2") ;;
                --machine-type) machine_type=$2 ;;
                --nic-type) nic_type=$2 ;;
            esac
            shift ;;
        --extra-disk=*) value --extra-disk "${1#*=}"; extra_disks+=("${1#*=}") ;;
        --machine-type=*) value --machine-type "${1#*=}"; machine_type=${1#*=} ;;
        --nic-type=*) value --nic-type "${1#*=}"; nic_type=${1#*=} ;;
        --) shift; pos+=("$@"); break ;;
        -*) echo "gce-image.sh: unknown option $1" >&2; usage ;;
        *) pos+=("$1") ;;
    esac
    shift
done
[ "$vtpm" = 1 ] || [ "$confidential" = TDX ] || { echo "gce-image.sh: --no-vtpm is for --tdx" >&2; exit 2; }
{ [ ${#pos[@]} -ge 1 ] && [ ${#pos[@]} -le 2 ]; } || usage
disk=${pos[0]}
name=${pos[1]:-l4h-$(date +%Y%m%d-%H%M)}
if ! [[ $name =~ ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ ]]; then
    echo "gce-image.sh: '$name' is not a GCE image name (lowercase letters, digits and -, at most 63)" >&2
    exit 2
fi
[ -f "$disk" ] || { echo "gce-image.sh: $disk: no such file" >&2; exit 2; }
dir=$(dirname -- "$disk")
tarball=$dir/$name.tar.gz
# GCE requires the member to be named disk.raw.
tar -C "$dir" -hSczf "$tarball" --transform='s|^.*$|disk.raw|' -- "$(basename -- "$disk")"
features=UEFI_COMPATIBLE,GVNIC
machine=n2-standard-4
# The mode's flags beside the machine type.
machine_args=
nic=VIRTIO_NET
image_args=
image_create_args=
if [ -n "$arm" ]; then
    image_create_args=" \\
      --architecture=ARM64"
    machine=c4a-standard-4
    nic=GVNIC
    image_args=" --boot-disk-type=hyperdisk-balanced --boot-disk-size=10GB --no-shielded-secure-boot --no-service-account --no-scopes"
elif [ "$confidential" = TDX ]; then
    features+=,TDX_CAPABLE
    machine=c3-standard-4
    machine_args=" --confidential-compute-type=TDX --maintenance-policy=TERMINATE"
    nic=GVNIC
    # Integrity monitoring, on by default for UEFI images, needs the vTPM.
    if [ "$vtpm" = 1 ]; then shielded=--shielded-vtpm; else shielded="--no-shielded-vtpm --no-shielded-integrity-monitoring"; fi
    image_args=" --boot-disk-interface=NVME --no-shielded-secure-boot $shielded --no-service-account --no-scopes"
elif [ -n "$confidential" ]; then
    features+=,${confidential}_CAPABLE
    machine=n2d-standard-4
    machine_args=" --min-cpu-platform=\"AMD Milan\" --confidential-compute-type=$confidential --maintenance-policy=TERMINATE"
    nic=GVNIC
    image_args=" --boot-disk-interface=NVME --no-shielded-secure-boot --no-service-account --no-scopes"
fi
# Shell-quoted for the printed commands, when it needs to be.
quote() {
    case $1 in
        *[!A-Za-z0-9=,._:/@+-]*) printf '%q' "$1" ;;
        *) printf '%s' "$1" ;;
    esac
}
machine=${machine_type:-$machine}
nic=${nic_type:-$nic}
# SEV on C3D: Genoa, not N2D's Milan.
if [ "$confidential" = SEV ] && [[ $machine == c3d-* ]]; then
    machine_args=${machine_args/AMD Milan/AMD Genoa}
fi
[ -z "$local_ssd" ] || image_args+=" --local-ssd=interface=NVME"
for spec in ${extra_disks[@]+"${extra_disks[@]}"}; do
    image_args+=" --create-disk=$(quote "$spec")"
done
q_tarball=$(quote "$tarball")
cat <<CMDS
$tarball: $(du -h "$tarball" | cut -f1)

To deploy (replace BUCKET, PROJECT and ZONE):
  gsutil cp $q_tarball gs://BUCKET/
  gcloud compute images create $name --project=PROJECT \\
      --source-uri=gs://BUCKET/$name.tar.gz \\
      --guest-os-features=$features$image_create_args
  gcloud compute instances create $name --project=PROJECT --zone=ZONE \\
      --machine-type=$(quote "$machine")$machine_args --image=$name$image_args \\
      --network-interface=nic-type=$(quote "$nic") \\
      --metadata=serial-port-enable=TRUE
  gcloud compute connect-to-serial-port $name --project=PROJECT --zone=ZONE
CMDS
