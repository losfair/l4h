#!/usr/bin/env bash
# Guest syscall latency on a Google Compute Engine VM under FL4: build a
# release FL4 image whose dom0 runs tests/guest/syscallbench (getpid on
# 1..N pinned threads), boot it with an NVMe boot disk and a gVNIC (what
# N4, C3 and C4 require), and print the results and FL4's mitigation
# status from the serial port.  Creates, then deletes, an image, an
# instance and a bucket object (KEEP=1 keeps the instance and image).
# VCPUS=n gives dom0 n vCPUs (default 2).
# L4H_FL4_SOURCE=<detached FL4 worktree> builds that FL4 instead of the pin.
# --sev-snp boots an AMD SEV-SNP confidential VM (default n2d-standard-4
# on AMD Milan) from FL4's native UEFI loader, with dom0 on the ESP, as
# tests/gce-test.sh --sev-snp does.
# --scale measures many-core scaling instead: syscallbench, then smpbench
# at 1, 2, 4, ... and all dom0 vCPUs (tests/guest/init-smpscale), with dom0
# on every host CPU (VCPUS defaults to the machine's) and 8 GiB of RAM.
# --probe is a quick scaling check instead (about 10 s of benchmark):
# getpid on one process per CPU for 1, 16, 32, ... and all dom0 vCPUs
# (tests/guest/init-getpidscale; PROBE_RANGES="0 0-31 ..." picks others),
# with dom0 on every host CPU as for --scale.
# --aarch64 benchmarks L4H on FL4 for AArch64 on an Arm C4A (default
# c4a-standard-4 in us-central1-b), dom0 in FL4's UEFI application.
# Usage: gce-bench.sh [--sev-snp|--aarch64] [--scale|--probe] PROJECT [ZONE] [MACHINE_TYPE]
# e.g.   gce-bench.sh PROJECT us-central1-a n4-standard-4
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_RELEASE=1 L4H_ARCH=x86_64 L4H_KERNEL_VARIANT=fl4 SEL4_PREFIX=$root/build/sel4-fl4
source "$root/tools/host-profile.sh"
usage() {
    echo "Usage: gce-bench.sh [--sev-snp|--aarch64] [--scale|--probe] PROJECT [ZONE] [MACHINE_TYPE]" >&2
    exit 2
}
# Options anywhere; after --, arguments only.
snp= scale= arm= probe=
pos=()
while [ $# -gt 0 ]; do
    case $1 in
        --sev-snp) snp=1 ;;
        --aarch64) arm=1 ;;
        --scale) scale=1 ;;
        --probe) probe=1 ;;
        --) shift; pos+=("$@"); break ;;
        -*) echo "gce-bench.sh: unknown option $1" >&2; usage ;;
        *) pos+=("$1") ;;
    esac
    shift
done
if [ -n "$scale" ] && [ -n "$probe" ]; then
    echo "gce-bench.sh: --scale and --probe cannot be combined" >&2
    exit 2
fi
if [ -n "$arm" ] && [ -n "$snp" ]; then
    echo "gce-bench.sh: --aarch64 and --sev-snp cannot be combined" >&2
    exit 2
fi
{ [ ${#pos[@]} -ge 1 ] && [ ${#pos[@]} -le 3 ]; } || usage
set -- "${pos[@]}"
project=$1
zone=${2:-us-central1-a}
machine=${3:-n4-standard-4}
features=UEFI_COMPATIBLE,GVNIC
gce_args=(--boot-disk-size=10GB)
image_arch=()
iface=(--boot-disk-interface=NVME)
cc=gcc
if [ -n "$arm" ]; then
    zone=${2:-us-central1-b}
    machine=${3:-c4a-standard-4}
    gce_args+=(--boot-disk-type=hyperdisk-balanced)
    image_arch=(--architecture=ARM64)
    iface=()
    cc=aarch64-linux-gnu-gcc
    export L4H_ARCH=aarch64 SEL4_PREFIX=$root/build/sel4-fl4-aarch64
fi
if [ -n "$snp" ]; then
    machine=${3:-n2d-standard-4}
    features+=,SEV_SNP_CAPABLE
    gce_args+=(--confidential-compute-type=SEV_SNP --min-cpu-platform="AMD Milan"
        --maintenance-policy=TERMINATE)
fi
region=${zone%-*}
bucket=gs://$project-l4h-test
out=$root/build/gce-bench
mkdir -p "$out"
# This run's intermediate files, apart from any other run's: only the
# serial log, the image and its .tar.gz (named after the run) are in $out.
# Its directory is reserved by a plain mkdir, which fails if another run
# has the name; the name (GCE's, too) comes from it.
name=
for _ in 1 2 3 4 5 6 7 8; do
    try=$(printf 'l4h-bench-%s-%x-%04x' "$(date +%Y%m%d-%H%M%S)" "$$" "$RANDOM")
    if mkdir "$out/$try" 2>/dev/null; then name=$try; break; fi
done
[ -n "$name" ] || { echo "gce-bench.sh: no free run directory in $out" >&2; exit 1; }
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
# outputs in build/ and host/target are shared (VCPUS goes into
# l4h-root.elf).  Released once the image is packaged; the cloud part of
# runs goes on concurrently.
exec 7>"$root/build/.image-build.lock"
flock -n 7 || { echo "waiting for another run's image build" >&2; flock 7; }
if [ -n "$arm" ]; then
    build_step kernel-build "$root/tools/build-fl4-aarch64.sh"
else
    build_step kernel-build "$root/tools/build-fl4.sh"
fi
build_step linux-build "$root/tools/build-linux.sh" vmlinux
if [ -n "$arm" ]; then
    aarch64-linux-gnu-objcopy --strip-debug "$root/build/linux-l4h-aarch64/vmlinux" "$work/vmlinux"
else
    objcopy --strip-debug "$root/build/linux-l4h/vmlinux" "$work/vmlinux"
fi
"$cc" -O2 -static -Wall -Wextra -Werror -o "$work/syscallbench" "$root/tests/guest/syscallbench.c"
cmdline="console=hvc0 quiet"
if [ -n "$probe" ]; then
    "$cc" -O2 -static -Wall -Wextra -Werror -o "$work/getpidscale" "$root/tests/guest/getpidscale.c"
    "$root/tools/mkinitramfs.sh" "$work/dom0.cpio.gz" "$root/tests/guest/init-getpidscale" \
        "$work/getpidscale" >/dev/null
    marker=PROBE
    [ -n "${PROBE_RANGES:-}" ] && cmdline+=" probe_ranges=$(echo "$PROBE_RANGES" | tr ' ' ,)"
    vcpus=${VCPUS:-$(gcloud compute machine-types describe "$machine" --project="$project" \
        --zone="$zone" --format='value(guestCpus)')}
    mem_mb=4096
elif [ -n "$scale" ]; then
    "$cc" -O2 -static -Wall -Wextra -Werror -o "$work/smpbench" "$root/tests/guest/smpbench.c"
    "$root/tools/mkinitramfs.sh" "$work/dom0.cpio.gz" "$root/tests/guest/init-smpscale" \
        "$work/syscallbench" "$work/smpbench" >/dev/null
    marker=SCALEBENCH
    vcpus=${VCPUS:-$(gcloud compute machine-types describe "$machine" --project="$project" \
        --zone="$zone" --format='value(guestCpus)')}
    mem_mb=8192
else
    "$root/tools/mkinitramfs.sh" "$work/dom0.cpio.gz" "$root/tests/guest/init-syscallbench" \
        "$work/syscallbench" >/dev/null
    marker=SYSCALLBENCH
    vcpus=${VCPUS:-2}
    mem_mb=1024
fi
host_build=build-host.sh
[ -n "$arm" ] && host_build=build-host-aarch64.sh
build_step host-build env L4H_DOM0_DISKS=0 L4H_DOM0_VCPUS="$vcpus" L4H_DOM0_MEM_MB="$mem_mb" \
    L4H_DOM0_CMDLINE="$cmdline" L4H_WATCHDOG_SECS=0 "$root/tools/$host_build"
export L4H_GUEST_KERNEL=$work/vmlinux L4H_GUEST_SDK=
if [ -n "$arm" ]; then
    # dom0's initramfs goes in the application.
    rootelf=$root/host/target/aarch64-sel4-roottask/$l4h_profile/l4h-root.elf
    build_step efi-build env L4H_DOM0_INITRD="$work/dom0.cpio.gz" "$root/tools/mkfl4-efi-aarch64.sh" "$work/$name.efi" "$rootelf" \
        "$SEL4_PREFIX/bin/kernel.elf"
    build_step image-build "$root/tools/mkimage.sh" -e "$work/$name.efi" "$out/$name.raw"
else
    rootelf=$root/host/target/x86_64-sel4-roottask/$l4h_profile/l4h-root.elf
    build_step efi-build "$root/tools/mkfl4-release-efi.sh" "$work/$name.efi" "$rootelf" "$SEL4_PREFIX/bin/kernel.elf"
    build_step image-build "$root/tools/mkimage.sh" -e "$work/$name.efi" -i "$work/dom0.cpio.gz" "$out/$name.raw"
fi
rm -f "$work/$name.efi"
build_step gce-image "$root/tools/gce-image.sh" "$out/$name.raw" "$name"
rm -f "$out/$name.raw"
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
gcloud compute instances create "$name" --project="$project" --zone="$zone" \
    "${gce_args[@]}" --machine-type="$machine" --image="$name" "${iface[@]}" \
    --network-interface=nic-type=GVNIC --no-service-account --no-scopes \
    --metadata=serial-port-enable=TRUE --no-shielded-secure-boot --quiet

# ---- results from the serial port
end=$((SECONDS + ${GCE_TIMEOUT:-600}))
while [ $SECONDS -lt $end ]; do
    sleep 15
    gcloud compute instances get-serial-port-output "$name" --project="$project" --zone="$zone" \
        >"$log" 2>/dev/null || continue
    grep -aqE "$marker: (PASS|FAIL)" "$log" && break
done
grep -aE "$marker|SYSCALLBENCH|SMPBENCH|GETPIDSCALE|FL4: speculation|FL4: AMD SEV|FL4: ITS|l4h-root: MSIs through|no MSIs|FL4: [0-9]+ core|l4h-root: [0-9]+ core|panic|fault" "$log" || true
echo "serial log: $log"
grep -aqE "$marker: PASS" "$log"
