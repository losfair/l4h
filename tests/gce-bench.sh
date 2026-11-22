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
# on AMD Milan) from FL4's native UEFI loader, with dom0 embedded, as
# tests/gce-test.sh --sev-snp does.
# --scale measures many-core scaling instead: syscallbench, then smpbench
# at 1, 2, 4, ... and all dom0 vCPUs (tests/guest/init-smpscale), with dom0
# on every host CPU (VCPUS defaults to the machine's) and 8 GiB of RAM.
# Usage: gce-bench.sh [--sev-snp] [--scale] PROJECT [ZONE] [MACHINE_TYPE]
# e.g.   gce-bench.sh PROJECT us-central1-a n4-standard-4
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export L4H_RELEASE=1 L4H_ARCH=x86_64 L4H_KERNEL_VARIANT=fl4 SEL4_PREFIX=$root/build/sel4-fl4
source "$root/tools/host-profile.sh"
snp= scale=
while :; do
    case "${1:-}" in
        --sev-snp) snp=1 ;;
        --scale) scale=1 ;;
        *) break ;;
    esac
    shift
done
project=$1
zone=${2:-us-central1-a}
machine=${3:-n4-standard-4}
features=UEFI_COMPATIBLE,GVNIC
gce_args=(--boot-disk-size=10GB)
if [ -n "$snp" ]; then
    machine=${3:-n2d-standard-4}
    features+=,SEV_SNP_CAPABLE
    gce_args+=(--confidential-compute-type=SEV_SNP --min-cpu-platform="AMD Milan"
        --maintenance-policy=TERMINATE)
fi
region=${zone%-*}
name=l4h-bench-$(date +%Y%m%d-%H%M%S)
bucket=gs://$project-l4h-test
out=$root/build/gce-bench; mkdir -p "$out"
log=$out/$name.serial.log

# ---- image
"$root/tools/build-fl4.sh" >"$out/kernel-build.log" 2>&1 \
    || { tail -20 "$out/kernel-build.log"; exit 1; }
"$root/tools/build-linux.sh" vmlinux >"$out/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$out/linux-build.log"; exit 1; }
objcopy --strip-debug "$root/build/linux-l4h/vmlinux" "$out/vmlinux"
gcc -O2 -static -Wall -Wextra -Werror -o "$out/syscallbench" "$root/tests/guest/syscallbench.c"
if [ -n "$scale" ]; then
    gcc -O2 -static -Wall -Wextra -Werror -o "$out/smpbench" "$root/tests/guest/smpbench.c"
    "$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-smpscale" \
        "$out/syscallbench" "$out/smpbench" >/dev/null
    marker=SCALEBENCH
    vcpus=${VCPUS:-$(gcloud compute machine-types describe "$machine" --project="$project" \
        --zone="$zone" --format='value(guestCpus)')}
    mem_mb=8192
else
    "$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-syscallbench" \
        "$out/syscallbench" >/dev/null
    marker=SYSCALLBENCH
    vcpus=${VCPUS:-2}
    mem_mb=1024
fi
L4H_DOM0_DISKS=0 L4H_DOM0_VCPUS=$vcpus L4H_DOM0_MEM_MB=$mem_mb L4H_DOM0_CMDLINE="console=hvc0 quiet" L4H_WATCHDOG_SECS=0 \
    "$root/tools/build-host.sh" >"$out/host-build.log" 2>&1 \
    || { tail -20 "$out/host-build.log"; exit 1; }
export L4H_GUEST_KERNEL=$out/vmlinux L4H_GUEST_SDK=
rootelf=$root/host/target/x86_64-sel4-roottask/$l4h_profile/l4h-root.elf
if [ -n "$snp" ]; then
    L4H_DOM0_INITRD="$out/dom0.cpio.gz" "$root/tools/mkfl4-efi.sh" "$out/$name.efi" \
        "$rootelf" "$SEL4_PREFIX/bin/kernel.elf" >"$out/efi-build.log" 2>&1 \
        || { tail -20 "$out/efi-build.log"; exit 1; }
    "$root/tools/mkimage.sh" -e "$out/$name.efi" "$out/$name.raw" >/dev/null
else
    L4H_MKSHIM='' "$root/tools/mkefi.sh" "$out/$name.efi" "$rootelf" "$SEL4_PREFIX/bin/kernel.elf" >/dev/null
    "$root/tools/mkimage.sh" -e "$out/$name.efi" -i "$out/dom0.cpio.gz" "$out/$name.raw" >/dev/null
fi
rm -f "$out/$name.efi"
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
    --source-uri="$bucket/$name.tar.gz" --guest-os-features="$features" --quiet
gcloud compute instances create "$name" --project="$project" --zone="$zone" \
    "${gce_args[@]}" --machine-type="$machine" --image="$name" --boot-disk-interface=NVME \
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
grep -aE "$marker|SYSCALLBENCH|SMPBENCH|FL4: speculation|FL4: AMD SEV|FL4: [0-9]+ core|l4h-root: [0-9]+ core|panic|fault" "$log" || true
echo "serial log: $log"
grep -aqE "$marker: PASS" "$log"
