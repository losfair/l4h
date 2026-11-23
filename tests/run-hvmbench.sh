#!/usr/bin/env bash
# HVM vs PV guest performance: the same workload (tests/guest/init-vmcmp:
# vmcmp.c, bench.c, ping and TCP to a PV sink) in a PV guest, then in an
# HVM guest (DESIGN.md §5.11), with equal memory, vCPUs, disk and switch.
# Needs nested VT-x or AMD-V.  HB_MODE=kvm runs the baseline instead:
# the host's Linux kernel with KVM as L1 in the same QEMU, the guest under
# QEMU there (tests/guest/init-kvmbase), with HB_MEM and HB_REPS.
# Both preallocate their RAM (-mem-prealloc): a host that backs it lazily
# with THP and the huge zero page splits the 2 MiB mappings of RAM that
# was read before it was written, as FL4's boot does (it zeroes only
# what is not zero), and the guest then runs on 4K pages there.  Knobs: HB_MEM (MiB), HB_VCPUS, HB_KINDS
# (pv,hvm), HB_REPS; L4H_KERNEL_VARIANT / L4H_FL4_SOURCE pick the kernel.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/guest
mkdir -p "$out"
if [ "${HB_SKIP_BUILD:-0}" != 1 ]; then
    "$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
        || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
    "$root/tools/build-l4hctl.sh"
    bzimage=$("$root/tools/build-linux-hvm.sh" 2>"$root/build/linux-hvm-build.log") \
        || { tail -20 "$root/build/linux-hvm-build.log"; exit 1; }
    cp "$bzimage" "$out/bzImage"
fi
"$l4h_cc" -O2 -static -o "$out/vmcmp" "$root/tests/guest/vmcmp.c"
"$l4h_cc" -O2 -static -o "$out/bench" "$root/tests/guest/bench.c"
"$l4h_cc" -O2 -static -o "$out/netbench" "$root/tests/guest/netbench.c"
"$l4h_cc" -O2 -static -o "$out/mstime" "$root/tests/guest/mstime.c"
"$root/tools/mkinitramfs.sh" "$out/benchvm.cpio.gz" "$root/tests/guest/init-benchvm" "$out/netbench" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/vmcmp.cpio.gz" "$root/tests/guest/init-vmcmp" \
    "$out/vmcmp" "$out/bench" "$out/netbench" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/hvmbench.cpio.gz" "$root/tests/guest/init-hvmbench" \
    "$l4h_ctl" "$out/mstime" "$out/bzImage" "$out/vmcmp.cpio.gz" "$out/benchvm.cpio.gz" >/dev/null
rm -f "$out/hvmbench.img" && truncate -s 1G "$out/hvmbench.img"
if [ "${HB_MODE:-l4h}" = kvm ]; then
    source "$root/tests/kvm-vmms.sh"
    "$root/tools/mkinitramfs.sh" "$out/kvmbase.cpio.gz" "$root/tests/guest/init-kvmbase" \
        "$out/mstime" "$out/netbench" "$out/bzImage" "$out/vmcmp.cpio.gz" >/dev/null
    kvm_vmms_append "$out/kvmbase.cpio.gz" qemu
    kernel=${KVMTEST_KERNEL:-/boot/vmlinuz-$(uname -r)}
    mods=$(mktemp -d)
    trap 'rm -rf "$mods"' EXIT
    mkdir -p "$mods/lib/kvm"
    for m in virt/lib/irqbypass arch/x86/kvm/kvm arch/x86/kvm/kvm-amd arch/x86/kvm/kvm-intel drivers/crypto/ccp/ccp \
        drivers/block/virtio_blk drivers/net/tun drivers/net/tap drivers/vhost/vhost_iotlb drivers/vhost/vhost drivers/vhost/vhost_net; do
        xz -dc "/lib/modules/$(uname -r)/kernel/$m.ko.xz" >"$mods/lib/kvm/$(basename "$m").ko"
    done
    (cd "$mods" && find . | cpio -o -H newc --quiet | gzip -1) >>"$out/kvmbase.cpio.gz"
    log=$root/build/hvmbench-kvm.log
    timeout "${HVMBENCH_TIMEOUT:-120}" qemu-system-x86_64 -accel kvm -cpu "${L4H_QEMU_CPU:-host,+invtsc}" \
        -smp "${L4H_SMP:-4}" -m "${L4H_MEM:-3G}" -name kvmbase,debug-threads=on -mem-prealloc -display none -vga none -nic none -no-reboot -monitor none \
        -drive file="$out/hvmbench.img",if=none,id=d0,format=raw,cache=none,aio=native -device virtio-blk-pci,drive=d0,disable-legacy=on \
        -serial "file:$log" -kernel "$kernel" -initrd "$out/kvmbase.cpio.gz" \
        -append "console=ttyS0 quiet panic=-1 HB_MEM=${HB_MEM:-1024} HB_REPS=${HB_REPS:-1}${HB_SPIN:+ HB_SPIN=1}${HB_GUEST_ARGS:+ HB_GUEST_ARGS=$HB_GUEST_ARGS}${HB_KVMAMD_ARGS:+ HB_KVMAMD_ARGS=$HB_KVMAMD_ARGS}" </dev/null || true
    grep -a "HVMBENCH" "$log" || true
    grep -aq "HVMBENCH: done" "$log"
    exit
fi
export L4H_QEMU_CPU=${L4H_QEMU_CPU:-host,+invtsc}
L4H_MEM=${L4H_MEM:-3G} L4H_DOM0_DISKS=0 L4H_DOM0_MEM_MB=512 L4H_SMP=${L4H_SMP:-4} \
L4H_QEMU_ARGS="-name l4h,debug-threads=on -mem-prealloc -drive file=$out/hvmbench.img,if=none,id=d0,format=raw,cache=none,aio=native -device virtio-blk-pci,drive=d0,disable-legacy=on" \
    "$root/tools/run-dom0.sh" "$out/hvmbench.cpio.gz" \
    "console=hvc0 HB_MEM=${HB_MEM:-1024} HB_VCPUS=${HB_VCPUS:-1} HB_KINDS=${HB_KINDS:-pv,hvm} HB_REPS=${HB_REPS:-1}${HB_SPIN:+ HB_SPIN=1}" \
    ${HVMBENCH_TIMEOUT:-900} | grep -a "HVMBENCH" || true
grep -aq "HVMBENCH: done" "$root/build/qemu.log"
