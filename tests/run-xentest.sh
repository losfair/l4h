#!/usr/bin/env bash
# l4h partitions as Xen HVM guests (DESIGN.md §11.2), nested in QEMU/KVM:
# Xen and a minimal Linux dom0 (tools/build-xen-dom0.sh) boot two l4h UEFI
# images under OVMF, each with its own virtio-net NIC passed through.  The
# two NICs share one QEMU hub, and each l4h's dom0 pings the other's
# across it.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/xen/test
mkdir -p "$out"
log=$out/qemu.log
rm -f "$log"
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$l4h_linux_out/vmlinux.stripped"
"$l4h_host_build"
L4H_GUEST_KERNEL=$l4h_linux_out/vmlinux.stripped L4H_GUEST_KMODS= \
    "$root/tools/mkefi.sh" "$out/l4h.efi" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/xenvm.cpio.gz" "$root/tests/guest/init-xenvm" >/dev/null

# Partition a gets the NIC at 00:06.0 and disk vda, b 00:07.0 and vdb.
part() { # name ip peer nic disk
    printf 'dom0_mem_mb=256\ndom0_cmdline="console=hvc0 IP0=%s/24 PEER=%s"\n' "$2" "$3" > "$out/$1.conf"
    "$root/tools/mkimage.sh" -e "$out/l4h.efi" -i "$out/xenvm.cpio.gz" -c "$out/$1.conf" "$out/$1.raw" >/dev/null
    cat > "$out/l4h-$1.cfg" <<CFG
name = "l4h-$1"
type = "hvm"
bios = "ovmf"
bios_path_override = "/usr/lib/xen/boot/ovmf.fd"
memory = 1536
vcpus = 2
disk = [ "format=raw,vdev=hda,access=rw,backendtype=qdisk,target=/dev/$5" ]
pci = [ "0000:$4" ]
serial = "file:/var/log/xen/l4h-$1.serial"
vga = "none"
vnc = 0
on_poweroff = "destroy"
on_crash = "destroy"
CFG
}
part a 10.0.0.1 10.0.0.2 00:06.0 vda
part b 10.0.0.2 10.0.0.1 00:07.0 vdb
cat > "$out/run" <<'RUN'
#!/bin/sh
# Copy the partitions' serial output to the console as it comes, and wait
# for them to reach each other.
xl list
for p in a b; do
    touch /var/log/xen/l4h-$p.serial
    tail -f /var/log/xen/l4h-$p.serial | while IFS= read -r l; do echo "l4h-$p| $l"; done &
done
end=$(( $(cut -d. -f1 /proc/uptime) + ${XENTEST_TIMEOUT:-600} ))
while [ "$(cut -d. -f1 /proc/uptime)" -lt "$end" ]; do
    n=$(cat /var/log/xen/l4h-[ab].serial 2>/dev/null | grep -c "XENVM: ping .*")
    [ "$n" -ge 2 ] && break
    { xl domid l4h-a && xl domid l4h-b; } >/dev/null 2>&1 || break
    sleep 5
done
sleep 1
kill $(jobs -p) 2>/dev/null
for p in a b; do
    echo "--- l4h-$p serial: $(wc -c < /var/log/xen/l4h-$p.serial) bytes, tail:"
    tail -n 30 /var/log/xen/l4h-$p.serial
done
for p in a b; do
    grep -a "XENVM:" /var/log/xen/l4h-$p.serial | tr -d '\r' | sed "s/^/XENTEST: $p: /"
done
xl list
tail -n 5 /var/log/xen/qemu-dm-l4h-*.log /var/log/xen/xl-l4h-*.log 2>/dev/null
if [ "$(cat /var/log/xen/l4h-[ab].serial | grep -c "XENVM: ping .* ok")" -eq 2 ]; then
    echo "XENTEST: PASS"
else
    echo "XENTEST: FAIL"
fi
RUN
chmod +x "$out/run"
"$root/tools/build-xen-dom0.sh" "$out/l4h-a.cfg" "$out/l4h-b.cfg" "$out/run" >/dev/null

L4H_XEN_DOM0_ARGS="xen-pciback.hide=(00:06.0)(00:07.0)" \
    timeout "${XENTEST_TIMEOUT:-900}" "$root/tools/run-xen-qemu.sh" \
    -drive file="$out/a.raw",format=raw,if=none,id=da -device virtio-blk-pci,drive=da,addr=0x4 \
    -drive file="$out/b.raw",format=raw,if=none,id=db -device virtio-blk-pci,drive=db,addr=0x5 \
    -netdev hubport,id=na,hubid=0 -device virtio-net-pci,netdev=na,addr=0x6,disable-legacy=on,iommu_platform=on,ats=on \
    -netdev hubport,id=nb,hubid=0 -device virtio-net-pci,netdev=nb,addr=0x7,disable-legacy=on,iommu_platform=on,ats=on \
    </dev/null >"$log" 2>&1 || true
grep -aE "XENTEST|dom0:|\(XEN\).*(IOMMU|VT-d|l4h-|d[12]v)" "$log" | tr -d '\r' || true
grep -aq "XENTEST: PASS" "$log"
