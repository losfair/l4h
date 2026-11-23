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
# and the exact commands the test would run with it (the same bucket,
# image and instance arguments), and uses no cloud resources.
# Usage: gce-test.sh [--sev|--sev-snp|--tdx|--aarch64] PROJECT [ZONE] [MACHINE_TYPE]
# e.g.   BOOT_DISK_INTERFACE=NVME NIC_TYPE=GVNIC gce-test.sh PROJECT us-west1-b c3-standard-4-lssd
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/host-profile.sh"
usage() {
    echo "Usage: gce-test.sh [--sev|--sev-snp|--tdx|--aarch64] PROJECT [ZONE] [MACHINE_TYPE]" >&2
    exit 2
}
# Options anywhere; after --, arguments only.
mode=
pos=()
while [ $# -gt 0 ]; do
    case $1 in
        --aarch64|--sev|--sev-snp|--tdx)
            [ -z "$mode" ] || { echo "gce-test.sh: $mode and $1 cannot be combined" >&2; exit 2; }
            mode=$1 ;;
        --) shift; pos+=("$@"); break ;;
        -*) echo "gce-test.sh: unknown option $1" >&2; usage ;;
        *) pos+=("$1") ;;
    esac
    shift
done
{ [ ${#pos[@]} -ge 1 ] && [ ${#pos[@]} -le 3 ]; } || usage
set -- "${pos[@]}"
confidential=
arch=x86_64
default_zone=us-west1-b
default_machine=n2-standard-4
case "$mode" in
    --aarch64) arch=aarch64; default_zone=us-central1-b; default_machine=c4a-standard-4 ;;
    --sev) confidential=SEV ;;
    --sev-snp) confidential=SEV_SNP; default_zone=us-central1-a ;;
    --tdx) confidential=TDX; default_zone=us-central1-a ;;
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
    # C4A: gVNIC and NVMe hyperdisks.  Its -lssd shapes come with their
    # local SSDs and the others take no --local-ssd; hyperdisk-balanced
    # takes no --boot-disk-interface (an inherited NVME would fail).
    nic=GVNIC
    ssd=
    BOOT_DISK_INTERFACE=
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
bucket=gs://$project-l4h-test
out=$root/build/gce
mkdir -p "$out"
# This run's intermediate files, apart from any other run's: only the
# serial log, the image and its .tar.gz (named after the run) are in $out.
# Its directory is reserved by a plain mkdir, which fails if another run
# has the name; the name (GCE's, too) comes from it.
name=
for _ in 1 2 3 4 5 6 7 8; do
    try=$(printf 'l4h-test-%s-%x-%04x' "$(date +%Y%m%d-%H%M%S)" "$$" "$RANDOM")
    if mkdir "$out/$try" 2>/dev/null; then name=$try; break; fi
done
[ -n "$name" ] || { echo "gce-test.sh: no free run directory in $out" >&2; exit 1; }
work=$out/$name
# The raw image too, left by a step that failed after it was made.
remove_work() { [ "${KEEP:-0}" = 1 ] || rm -rf "$work" "$out/$name.raw"; }
trap remove_work EXIT
log=$out/$name.serial.log
# A failed build step: the end of its log, and the log kept beside the
# serial log ($work goes).
fail_log() {
    local saved
    saved=$out/$name.$(basename "$1")
    tail -30 "$1" >&2
    cp "$1" "$saved"
    echo "build log: $saved" >&2
    exit 1
}
# Run a build step with its output in $work/STEP.log.
build_step() {
    local f=$work/$1.log
    shift
    "$@" >"$f" 2>&1 || fail_log "$f"
}

# ---- image
# One run builds and packages at a time: the kernel, Linux and host
# outputs in build/ and host/target are shared.  Released once the
# image is packaged; the cloud part of runs goes on concurrently.
exec 7>"$root/build/.image-build.lock"
flock -n 7 || { echo "waiting for another run's image build" >&2; flock 7; }
efi=${UEFI_EFI:-}
if [ "$arch" = aarch64 ]; then
    [ -z "$efi" ] || { echo "UEFI_EFI: not with --aarch64 (its application carries dom0)" >&2; exit 1; }
    build_step kernel-build "$root/tools/build-fl4-aarch64.sh"
    build_step linux-build "$root/tools/build-linux.sh" vmlinux
    aarch64-linux-gnu-objcopy --strip-debug "$root/build/linux-l4h-aarch64/vmlinux" "$work/vmlinux"
elif [ -n "$efi" ]; then
    [ -f "$efi" ] || { echo "$efi: missing EFI application" >&2; exit 1; }
else
    kernel_build=build-kernel.sh
    [ -n "$confidential" ] && kernel_build=build-fl4.sh
    build_step kernel-build "$root/tools/$kernel_build"
    build_step linux-build "$root/tools/build-linux.sh" vmlinux
    objcopy --strip-debug "$root/build/linux-l4h/vmlinux" "$work/vmlinux"
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
"$cc" -O2 -static -pthread -o "$work/selftest" "$root/tests/guest/selftest.c"
"$root/tools/mkinitramfs.sh" "$work/selftest.cpio.gz" "$root/tests/guest/init-selftest" "$work/selftest" >/dev/null
"$root/tools/mkinitramfs.sh" "$work/disk.cpio.gz" "$root/tests/guest/init-gcedisk" >/dev/null
"$root/tools/mkinitramfs.sh" "$work/vm.cpio.gz" "$root/tests/guest/init-vm" >/dev/null
"$root/tools/mkinitramfs.sh" "$work/dom0.cpio.gz" "$root/tests/guest/init-gce" \
    "$l4hctl" "$root/tests/guest/udhcpc.script" \
    "$work/selftest.cpio.gz" "$work/disk.cpio.gz" "$work/vm.cpio.gz" >/dev/null
cat > "$work/$name.conf" <<CONF
dom0_disks=0
dom0_mem_mb=1024
dom0_cmdline="console=hvc0"
watchdog_secs=${L4H_WATCHDOG_SECS:-0}
CONF
image_args=(-i "$work/dom0.cpio.gz" -c "$work/$name.conf")
if [ "$arch" = aarch64 ]; then
    build_step host-build "$root/tools/build-host-aarch64.sh"
    efi=$work/$name.efi
    build_step efi-build env L4H_GUEST_KERNEL="$work/vmlinux" L4H_DOM0_INITRD="$work/dom0.cpio.gz" L4H_CONFIG="$work/$name.conf" \
        "$root/tools/mkfl4-efi-aarch64.sh" "$efi" \
        "$root/host/target/aarch64-sel4-roottask/$l4h_profile/l4h-root.elf" "$SEL4_PREFIX/bin/kernel.elf"
    image_args=()
elif [ -z "$efi" ]; then
    build_step host-build "$root/tools/build-host.sh"
    export L4H_GUEST_KERNEL=$work/vmlinux L4H_GUEST_SDK=
    if [ -n "$confidential" ]; then
        efi=$work/$name.efi
        build_step efi-build "$root/tools/mkfl4-release-efi.sh" "$efi" \
            "$root/host/target/x86_64-sel4-roottask/$l4h_profile/l4h-root.elf" "$SEL4_PREFIX/bin/kernel.elf"
    fi
fi
[ -z "$efi" ] || image_args+=(-e "$efi")
build_step image-build "$root/tools/mkimage.sh" ${image_args[@]+"${image_args[@]}"} "$out/$name.raw"
build_step gce-image "$root/tools/gce-image.sh" "$out/$name.raw" "$name"
rm -f "$out/$name.raw"
# The instance, as below and as IMAGE_ONLY=1 prints it.
instance_args=(
    ${gce_args[@]+"${gce_args[@]}"}
    --machine-type="$machine"
    --image="$name"
    ${BOOT_DISK_INTERFACE:+--boot-disk-interface="$BOOT_DISK_INTERFACE"}
    ${ssd:+"$ssd"}
    --network-interface=nic-type="$nic"
    ${disk_args[@]+"${disk_args[@]}"}
    --metadata=serial-port-enable=TRUE
    --no-shielded-secure-boot
)
if [ "${IMAGE_ONLY:-0}" = 1 ]; then
    # Shell-quoted, when it needs to be.
    quote() {
        case $1 in
            *[!A-Za-z0-9=,._:/@+-]*) printf '%q' "$1" ;;
            *) printf '%s' "$1" ;;
        esac
    }
    quote_all() {
        local a q=
        for a; do q+=" $(quote "$a")"; done
        printf '%s' "${q# }"
    }
    cat <<CMDS
$out/$name.tar.gz: $(du -h "$out/$name.tar.gz" | cut -f1)

To deploy as this test does (PROJECT as given, the bucket its):
  gcloud storage buckets describe $(quote "$bucket") --project=$(quote "$project") >/dev/null 2>&1 \\
      || gcloud storage buckets create $(quote "$bucket") --project=$(quote "$project") --location=$(quote "$region")
  gcloud storage cp $(quote "$out/$name.tar.gz") $(quote "$bucket/") --project=$(quote "$project")
  gcloud compute images create $name --project=$(quote "$project") \\
      --source-uri=$(quote "$bucket/$name.tar.gz") --guest-os-features=$features${image_arch[@]+ $(quote_all "${image_arch[@]}")}
  gcloud compute instances create $name --project=$(quote "$project") --zone=$(quote "$zone") \\
      $(quote_all "${instance_args[@]}")
  gcloud compute connect-to-serial-port $name --project=$(quote "$project") --zone=$(quote "$zone")
CMDS
    echo "image: $out/$name.tar.gz"
    exit 0
fi
flock -u 7
exec 7>&-

# ---- cloud resources
cleanup() {
    remove_work
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
gcloud compute instances create "$name" --project="$project" --zone="$zone" "${instance_args[@]}" --quiet
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
grep -aE 'GCETEST|Got framebuffer|AMD SEV(-SNP)? guest|Intel TDX guest|DMA memory shared|l4h-trustd|l4h-root: [0-9]+ core|FL4: ITS|l4h-root: MSIs through|no MSIs|panic|fault' "$log" \
    | grep -av 'GCETEST: blob ' || true
echo "serial log: $log"
grep -aqE 'GCETEST: PASS[[:space:]]*$' "$log"
if [ "$arch" = aarch64 ]; then
    # C4A's MSIs go through FL4's ITS: never a silent fall back to GICv2m.
    for marker in "FL4: ITS at 0x[0-9a-f]+: [0-9]+ LPIs" "l4h-root: MSIs through the ITS" "GCETEST: ok: disk [0-9]+ pass-through"; do
        grep -aqE "$marker" "$log" || { echo "Missing serial marker: $marker" >&2; exit 1; }
    done
    echo "GCE FL4 AArch64: PASS"
fi
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
