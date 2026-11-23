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
# --sev and --sev-snp build FL4 and test AMD confidential VMs with
# gVNIC and NVMe persistent disks. Both require the selected technology,
# shared DMA and a disk write/readback.
# --tdx does the same on an Intel TDX C3 VM (FL4's UEFI loader, as for
# SEV-SNP), with Google's vTPM unless NO_VTPM=1, and requires TDX
# attestation to be ready and its evidence in the serial log (dom0 prints
# every attestation blob there, in hex, for tools/l4h-attest.py).
# --aarch64 tests L4H on FL4 for AArch64 on an Arm C4A (Google Axion,
# default c4a-standard-4 in us-central1-b): FL4 at EL1 with MSIs through
# the GICv3 ITS, gVNIC, a hyperdisk boot disk and a blank NVMe hyperdisk.
# FL4's AArch64 UEFI application carries dom0's initramfs and settings.
# UEFI_EFI=app.efi boots that exact release application with the test dom0
# and settings on its ESP, without rebuilding its kernel, host or SDK.
# IMAGE_ONLY=1 stops once the image's .tar.gz is built, prints its path
# and the deployment commands (tools/gce-image.sh), and uses no cloud
# resources (PROJECT is then only a placeholder).
# Usage: gce-test.sh [--sev|--sev-snp|--tdx|--aarch64] PROJECT [ZONE] [MACHINE_TYPE]
# e.g.   BOOT_DISK_INTERFACE=NVME NIC_TYPE=GVNIC gce-test.sh PROJECT us-west1-b c3-standard-4-lssd
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/host-profile.sh"
confidential=
arch=x86_64
default_zone=us-west1-b
default_machine=n2-standard-4
case "${1:-}" in
    --aarch64) arch=aarch64; default_zone=us-central1-b; default_machine=c4a-standard-4; shift ;;
    --sev) confidential=SEV; shift ;;
    --sev-snp) confidential=SEV_SNP; default_zone=us-central1-a; shift ;;
    --tdx) confidential=TDX; default_zone=us-central1-a; shift ;;
esac
project=$1
zone=${2:-$default_zone}
machine=${3:-$default_machine}
region=${zone%-*}
nic=${NIC_TYPE:-VIRTIO_NET}
ssd=--local-ssd=interface=NVME
case "$machine" in *-lssd) ssd= ;; esac
[ "${LOCAL_SSD:-1}" = 0 ] && ssd=
gce_args=()
disk_args=()
if [ -n "${SCSI_DISK_GB:-}" ]; then
    disk_args=(--create-disk="size=${SCSI_DISK_GB}GB,type=pd-balanced,interface=SCSI,auto-delete=yes")
fi
features=UEFI_COMPATIBLE,GVNIC
image_arch=()
if [ "$arch" = aarch64 ]; then
    # C4A: gVNIC, NVMe hyperdisks, no local SSD unless the type has them.
    nic=GVNIC
    case "$machine" in *-lssd) ;; *) ssd= ;; esac
    disk_args=(--boot-disk-type=hyperdisk-balanced --boot-disk-size=10GB
        --create-disk=size=10GB,type=hyperdisk-balanced,auto-delete=yes)
    image_arch=(--architecture=ARM64)
    export L4H_ARCH=aarch64 SEL4_PREFIX="$root/build/sel4-fl4-aarch64"
fi
if [ -n "$confidential" ]; then
    machine=${3:-n2d-standard-4}
    [ "$confidential" = TDX ] && machine=${3:-c3-standard-4}
    case "$confidential:$machine" in
        SEV:n2d-*|SEV:c2d-*|SEV_SNP:n2d-*) cpu="AMD Milan" ;;
        SEV:c3d-*) cpu="AMD Genoa" ;;
        TDX:c3-*) cpu= ;;
        *) echo "Unsupported $confidential machine type: $machine" >&2; exit 2 ;;
    esac
    nic=GVNIC
    ssd=
    BOOT_DISK_INTERFACE=NVME
    disk_args=(--create-disk=size=10GB,type=pd-balanced,interface=NVME,auto-delete=yes)
    features+=,${confidential}_CAPABLE
    gce_args=(--confidential-compute-type="$confidential" ${cpu:+--min-cpu-platform="$cpu"} --maintenance-policy=TERMINATE
        --no-service-account --no-scopes)
    if [ "$confidential" = TDX ]; then
        # Integrity monitoring, on by default for UEFI images, needs the vTPM.
        if [ "${NO_VTPM:-0}" = 1 ]; then
            gce_args+=(--no-shielded-vtpm --no-shielded-integrity-monitoring)
        else
            gce_args+=(--shielded-vtpm)
        fi
    fi
    export SEL4_PREFIX="$root/build/sel4-fl4" L4H_KERNEL_VARIANT=fl4
fi
name=l4h-test-$(date +%Y%m%d-%H%M%S)-$RANDOM
bucket=gs://$project-l4h-test
out=$root/build/gce; mkdir -p "$out"
log=$out/$name.serial.log

# ---- image
efi=${UEFI_EFI:-}
if [ "$arch" = aarch64 ]; then
    [ -z "$efi" ] || { echo "UEFI_EFI: not with --aarch64 (its application carries dom0)" >&2; exit 1; }
    "$root/tools/build-fl4-aarch64.sh" >"$root/build/kernel-build.log" 2>&1 \
        || { tail -20 "$root/build/kernel-build.log"; exit 1; }
    "$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
        || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
    aarch64-linux-gnu-objcopy --strip-debug "$root/build/linux-l4h-aarch64/vmlinux" "$out/vmlinux"
elif [ -n "$efi" ]; then
    [ -f "$efi" ] || { echo "$efi: missing EFI application" >&2; exit 1; }
else
    kernel_build=build-kernel.sh
    [ -n "$confidential" ] && kernel_build=build-fl4.sh
    "$root/tools/$kernel_build" >"$root/build/kernel-build.log" 2>&1 \
        || { tail -20 "$root/build/kernel-build.log"; exit 1; }
    "$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
        || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
    objcopy --strip-debug "$root/build/linux-l4h/vmlinux" "$out/vmlinux"
fi
cc=gcc
l4hctl=$root/tools/l4hctl/target/release/l4hctl
if [ "$arch" = aarch64 ]; then
    "$root/tools/build-l4hctl.sh"
    cc=aarch64-linux-gnu-gcc
    l4hctl=$root/tools/l4hctl/target/aarch64-unknown-linux-gnu/release/l4hctl
else
    (cd "$root/tools/l4hctl" && cargo +stable build -q --release)
fi
"$cc" -O2 -static -pthread -o "$out/selftest" "$root/tests/guest/selftest.c"
"$root/tools/mkinitramfs.sh" "$out/selftest.cpio.gz" "$root/tests/guest/init-selftest" "$out/selftest" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/disk.cpio.gz" "$root/tests/guest/init-gcedisk" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/vm.cpio.gz" "$root/tests/guest/init-vm" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-gce" \
    "$l4hctl" "$root/tests/guest/udhcpc.script" \
    "$out/selftest.cpio.gz" "$out/disk.cpio.gz" "$out/vm.cpio.gz" >/dev/null
cat > "$out/$name.conf" <<CONF
dom0_disks=0
dom0_mem_mb=1024
dom0_cmdline="console=hvc0"
watchdog_secs=${L4H_WATCHDOG_SECS:-0}
CONF
image_args=(-i "$out/dom0.cpio.gz" -c "$out/$name.conf")
if [ "$arch" = aarch64 ]; then
    "$root/tools/build-host-aarch64.sh"
    efi=$out/$name.efi
    L4H_GUEST_KERNEL=$out/vmlinux L4H_DOM0_INITRD=$out/dom0.cpio.gz L4H_CONFIG=$out/$name.conf \
        "$root/tools/mkfl4-efi-aarch64.sh" "$efi" \
        "$root/host/target/aarch64-sel4-roottask/$l4h_profile/l4h-root.elf" "$SEL4_PREFIX/bin/kernel.elf" >/dev/null
    image_args=()
elif [ -z "$efi" ]; then
    "$root/tools/build-host.sh"
    export L4H_GUEST_KERNEL=$out/vmlinux L4H_GUEST_SDK=
    if [ -n "$confidential" ]; then
        efi=$out/$name.efi
        "$root/tools/mkfl4-release-efi.sh" "$efi" \
            "$root/host/target/x86_64-sel4-roottask/$l4h_profile/l4h-root.elf" "$SEL4_PREFIX/bin/kernel.elf"
    fi
fi
[ -z "$efi" ] || image_args+=(-e "$efi")
"$root/tools/mkimage.sh" "${image_args[@]}" "$out/$name.raw" >/dev/null
if [ "${IMAGE_ONLY:-0}" = 1 ]; then
    image_flag=()
    case "$confidential" in
        SEV) image_flag=(--sev) ;;
        SEV_SNP) image_flag=(--sev-snp) ;;
        TDX) image_flag=(--tdx); [ "${NO_VTPM:-0}" = 1 ] && image_flag+=(--no-vtpm) ;;
    esac
    "$root/tools/gce-image.sh" "${image_flag[@]}" "$out/$name.raw" "$name"
    rm -f "$out/$name.raw"
    echo "image: $out/$name.tar.gz"
    exit 0
fi
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
    --source-uri="$bucket/$name.tar.gz" --guest-os-features="$features" "${image_arch[@]}" --quiet
gcloud compute instances create "$name" --project="$project" --zone="$zone" \
    "${gce_args[@]}" --machine-type="$machine" --image="$name" ${BOOT_DISK_INTERFACE:+--boot-disk-interface=$BOOT_DISK_INTERFACE} \
    $ssd --network-interface=nic-type="$nic" \
    "${disk_args[@]}" \
    --metadata=serial-port-enable=TRUE --no-shielded-secure-boot --quiet
if [ -n "$confidential" ]; then
    actual=$(gcloud compute instances describe "$name" --project="$project" --zone="$zone" \
        --format='value(confidentialInstanceConfig.confidentialInstanceType)')
    if [ "$actual" != "$confidential" ]; then
        echo "$name: expected confidential compute type $confidential, got '$actual'" >&2
        exit 1
    fi
fi

# ---- results from the serial port
end=$((SECONDS + ${GCE_TIMEOUT:-1200}))
while [ $SECONDS -lt $end ]; do
    sleep 20
    gcloud compute instances get-serial-port-output "$name" --project="$project" --zone="$zone" \
        >"$log" 2>/dev/null || continue
    # Serial lines end in CR LF.
    grep -aqE 'GCETEST: (PASS|FAIL)[[:space:]]*$' "$log" && break
done
grep -aE 'GCETEST|Got framebuffer|AMD SEV(-SNP)? guest|Intel TDX guest|DMA memory shared|l4h-trustd|l4h-root: [0-9]+ core|panic|fault' "$log" \
    | grep -av 'GCETEST: blob ' || true
echo "serial log: $log"
grep -aqE 'GCETEST: PASS[[:space:]]*$' "$log"
if [ -n "$confidential" ]; then
    technology=${confidential/_/-}
    markers=("FL4: AMD $technology guest, C-bit [0-9]+")
    [ "$confidential" = TDX ] && markers=("FL4: Intel TDX guest, GPAW [0-9]+" "l4h-trustd: TDX attestation ready" "GCETEST: ok: TDX evidence")
    for marker in "${markers[@]}" "l4h-root: DMA memory shared with the hypervisor" "GCETEST: ok: disk [0-9]+ pass-through"; do
        grep -aqE "$marker" "$log" || { echo "Missing serial marker: $marker" >&2; exit 1; }
    done
    if [ "$confidential" = SEV_SNP ]; then
        expected_cores=$(gcloud compute machine-types describe "$machine" --project="$project" --zone="$zone" --format='value(guestCpus)')
        if [[ ! $expected_cores =~ ^[0-9]+$ ]] ||
           ! grep -aqF "SELFTEST: start ($expected_cores CPUs online)" "$log"; then
            echo "$name: guest self-test did not report the instance's $expected_cores vCPUs online" >&2
            exit 1
        fi
    fi
    echo "GCE FL4 $technology: PASS"
fi
