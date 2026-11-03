#!/usr/bin/env bash
# Multikernel (DESIGN.md §11.3): l4h-mkshim boots MK_PARTITIONS (default 2)
# seL4 kernels on one QEMU q35 machine, each partition with its own CPUs,
# RAM, virtio disk and virtio NIC.  Each partition's dom0 boots, gets an
# address by DHCP over its own NIC, and runs a VM that no other dom0 sees;
# a secondary's dom0 is refused host-reboot; then partition 0's dom0
# resets the whole machine.  The other kernels' consoles reach the serial
# port through partition 0 ("[pN]" lines).
# MK_PARTITIONS=N (2..8) needs 2N CPUs; L4H_QEMU_IOMMU=intel|amd adds an
# IOMMU the partitions share.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
n=${MK_PARTITIONS:-2}
out=$root/build/mktest
log=$root/build/mktest.log
mkdir -p "$out"
rm -f "$log"

"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
objcopy --strip-debug "$l4h_linux_out/vmlinux" "$out/vmlinux"
"$root/tools/build-l4hctl.sh" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/vm.cpio.gz" "$root/tests/guest/init-mkvm" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-mktest" \
    "$l4h_ctl" "$out/vm.cpio.gz" "$root/tests/guest/udhcpc.script" >/dev/null
"$root/tools/build-mkshim.sh" "$n" >/dev/null
"$root/tools/build-host.sh"
objcopy --strip-debug "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" "$out/l4h-root.elf"
cp "$root/build/mkshim/l4h-mkshim.elf" "$out/"

# Partition k has the PCI slots 4 + 2k (disk) and 5 + 2k (NIC), two CPUs
# and 1 GiB; partition 0 the rest.
conf=$out/l4h-mk.conf
echo "partitions = $n" > "$conf"
devices=()
mods="$out/l4h-root.elf l4h-root,$out/vmlinux guest-kernel,$out/dom0.cpio.gz dom0-initrd,$conf l4h-mk.conf"
for k in $(seq 0 $((n - 1))); do
    disk=$((4 + 2 * k)) nic=$((5 + 2 * k))
    truncate -s 64M "$out/disk$k.img"
    devices+=(-drive "file=$out/disk$k.img,if=none,id=d$k,format=raw"
        -device "virtio-blk-pci,drive=d$k,bus=pcie.0,addr=$(printf '%#x' $disk)"
        -netdev "user,id=n$k"
        -device "virtio-net-pci,netdev=n$k,disable-legacy=on,bus=pcie.0,addr=$(printf '%#x' $nic)")
    if [ "$k" != 0 ]; then
        printf 'p%d.cpus = 2\np%d.mem = 1G\np%d.pci = 00:%02x.0, 00:%02x.0\n' "$k" "$k" "$k" "$disk" "$nic" >> "$conf"
    fi
    printf 'dom0_cmdline=console=hvc0 MKP=%d\ndom0_mem_mb=256\nboot_disk=00:%02x.0\nuplink_nic=00:%02x.0\n' \
        "$k" "$disk" "$nic" > "$out/p$k.conf"
    mods+=",$out/p$k.conf p$k:l4h-config,$root/build/mkshim/kernel-s$k.elf kernel-s$k"
done

iommu=()
case "${L4H_QEMU_IOMMU:-}" in
    amd) iommu=(-machine kernel-irqchip=split -device amd-iommu,intremap=on) ;;
    intel) iommu=(-machine kernel-irqchip=split -device intel-iommu,intremap=on,caching-mode=on) ;;
    '') ;;
esac
if [ ${#iommu[@]} -ne 0 ]; then
    iommu+=(-global virtio-blk-pci.iommu_platform=on -global virtio-net-pci.iommu_platform=on)
fi

qemu-system-x86_64 -machine q35 -enable-kvm -cpu "${L4H_QEMU_CPU:-host,-vmx,+invtsc}" \
    -smp $((2 * n)) -m "${MK_MEM:-$((2 * n + 2))G}" -nographic -serial mon:stdio -no-reboot \
    "${iommu[@]}" \
    -kernel "$out/l4h-mkshim.elf" -append "console_port=0x3f8" -initrd "$mods" \
    "${devices[@]}" </dev/null >"$log" 2>&1 &
qemu=$!
end=$((SECONDS + ${MKTEST_TIMEOUT:-300}))
while kill -0 "$qemu" 2>/dev/null; do
    if [ "$SECONDS" -ge "$end" ] || grep -aq "MKTEST p[0-9]*: FAIL\|cannot boot\|panic" "$log"; then
        sleep 1
        kill "$qemu" 2>/dev/null || true
        break
    fi
    sleep 1
done
wait "$qemu" 2>/dev/null || true
grep -aE "l4h-mkshim|MKTEST|MKVM|partition|host reboot|\[p[0-9]\] .*(panic|fault|error)|panic" "$log" | head -100
ok=1
for k in $(seq 0 $((n - 1))); do
    grep -aq "MKTEST p$k: done" "$log" || { echo "partition $k did not finish"; ok=0; }
    [ "$k" = 0 ] || grep -aq "MKTEST p$k: host-reboot refused" "$log" || { echo "partition $k: host-reboot not refused"; ok=0; }
    [ "$k" = 0 ] || grep -aq "^l4h-root: RTC set for partition $k" "$log" || { echo "partition $k: rtc-set did not reach partition 0"; ok=0; }
done
grep -aqE "^l4h-root: host reboot \(dom0\)\s*$" "$log" || { echo "partition 0 did not reset the machine"; ok=0; }
[ "$ok" = 1 ] && echo "MKTEST: PASS" || { echo "MKTEST: FAIL (log: $log)"; exit 1; }
