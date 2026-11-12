#!/usr/bin/env bash
# Exercise the shipped mkefi configuration under OVMF with a front GRUB
# chainloading two FAT slots. Check both selectors, runtime grubenv, disk
# growth with unchanged l4h.conf, odd sector counts, fallback after selection
# failure, GRUB literals, and a PCI inventory larger than one page.
# L4H_TEST_KERNEL may name an already-built compatible guest kernel.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export PATH="$PATH:/usr/sbin:/sbin"
source "$root/tools/host-profile.sh"
out=$root/build/platformtest
boot_label='L4H`BOOT'
runtime_env='/EFI/L4H/grub`env'
mkdir -p "$out"
python3 "$root/tests/test_mkefi.py"
if [ -n "${L4H_TEST_KERNEL:-}" ]; then
    guest_kernel=$L4H_TEST_KERNEL
else
    "$root/tools/build-linux.sh" vmlinux >"$out/linux-build.log" 2>&1
    guest_kernel=$root/build/linux-l4h/vmlinux
fi
"$root/tools/build-host.sh" >"$out/host-build.log" 2>&1
"$root/tools/build-l4hctl.sh"
export L4H_GUEST_KERNEL=$guest_kernel L4H_GUEST_KMODS= L4H_MKSHIM=
# The runtime image is identical in both slots. Fixed selectors also work
# without a shared environment block, even with an empty cmdpath.
L4H_ESP_LABEL="$boot_label" L4H_BOOT_ENV="$runtime_env" "$root/tools/mkefi.sh" "$out/runtime.efi"
L4H_ESP_UUID=1111-1111 "$root/tools/mkefi.sh" "$out/fixed-a.efi"
L4H_ESP_LABEL=L4HSLOTB "$root/tools/mkefi.sh" "$out/fixed-b.efi"
for slot in A B; do
    printf '%s\n' "$slot" > "$out/platform-slot"
    "$root/tools/mkinitramfs.sh" "$out/$slot.cpio.gz" "$root/tests/guest/init-platformtest" \
        "$root/tools/l4hctl/target/release/l4hctl" "$out/platform-slot" >/dev/null
    cat > "$out/$slot.conf" <<CFG
echo "PLATFORMTEST: source $slot"
dom0_mem_mb=256
dom0_disks=1
dom0_disk0_windows=786432:end-2048
dom0_cmdline="console=hvc0 platform_slot=$slot"
CFG
done
cat > "$out/front.cfg" <<'CFG'
serial --port=0x3f8 --speed=115200
terminal_input serial
terminal_output serial
search --no-floppy --set=bootpart --label 'L4H`BOOT'
load_env --file "($bootpart)/EFI/L4H/frontenv" l4h_chain_uuid
search --no-floppy --set=slot --fs-uuid "$l4h_chain_uuid"
chainloader "($slot)/EFI/l4h.efi"
boot
echo 'PLATFORMTEST: fallback'
search --no-floppy --set=fallback --fs-uuid 2222-2222
chainloader "($fallback)/EFI/fallback.efi"
boot
echo 'PLATFORMTEST: fallback failed'
exit
CFG
grub-script-check "$out/front.cfg"
grub-mkstandalone -O x86_64-efi -o "$out/front.efi" --compress=xz \
    --modules='part_gpt fat search search_fs_uuid search_label loadenv chain serial terminal' \
    --locales= --fonts= --themes= "boot/grub/grub.cfg=$out/front.cfg"
disk=$out/disk.raw
rm -f "$disk"
truncate -s 512M "$disk"
sfdisk -q "$disk" <<'GPT'
label: gpt
start=2048, size=64MiB, type=U
start=133120, size=128MiB, type=U
start=395264, size=128MiB, type=U
GPT
bootpart=$disk@@1048576
slota=$disk@@68157440
slotb=$disk@@202375168
for row in "$bootpart 131072 aaaaaaaa $boot_label" "$slota 262144 11111111 L4HSLOTA" "$slotb 262144 22222222 L4HSLOTB"; do
    read -r part sectors serial label <<< "$row"
    mformat -i "$part" -T "$sectors" -F -N "$serial" -v "$label" ::
    mmd -i "$part" ::/EFI
done
mcopy -i "$slotb" "$out/fixed-b.efi" ::/EFI/fallback.efi
mmd -i "$bootpart" ::/EFI/BOOT ::/EFI/L4H
mcopy -i "$bootpart" "$out/front.efi" ::/EFI/BOOT/BOOTX64.EFI
for slot in A B; do
    if [ "$slot" = A ]; then part=$slota; else part=$slotb; fi
    mmd -i "$part" ::/l4h ::/l4h/dom0
    mcopy -i "$part" "$out/$slot.cpio.gz" ::/l4h/dom0/initrd
    mcopy -i "$part" "$out/$slot.conf" ::/l4h/l4h.conf
    mcopy -i "$part" "$out/runtime.efi" ::/EFI/l4h.efi
done
# Enough unhandled functions to force CTL_PCI_LIST through multiple pages.
devices=(-device pci-bridge,id=bulk,chassis_nr=1 -device qemu-xhci)
for i in $(seq 0 127); do
    printf -v addr '%x.%x' "$((i / 8))" "$((i % 8))"
    devices+=(-device "pci-testdev,bus=bulk,addr=$addr,multifunction=on")
done
qemu=
trap 'if [ -n "$qemu" ]; then kill "$qemu" 2>/dev/null || true; wait "$qemu" 2>/dev/null || true; fi' EXIT
run() {
    local name=$1 expected=$2 chain=$3 selector=$4 fault=${5:-}
    grub-editenv "$out/frontenv" create
    grub-editenv "$out/frontenv" set "l4h_chain_uuid=$chain"
    mcopy -o -i "$bootpart" "$out/frontenv" ::/EFI/L4H/frontenv
    grub-editenv "$out/grubenv" create
    grub-editenv "$out/grubenv" set "$selector"
    if [ "$fault" = conflict ]; then grub-editenv "$out/grubenv" set l4h_esp_label=L4HSLOTB; fi
    if [ "$fault" = corrupt ]; then printf 'invalid environment block\n' > "$out/grubenv"; fi
    mcopy -o -i "$bootpart" "$out/grubenv" "::$runtime_env"
    if [ "$fault" = missing ]; then mdel -i "$bootpart" "::$runtime_env"; fi
    # Clear a previous run's completion marker before the child starts.
    : > "$out/$name.log"
    timeout "${PLATFORMTEST_TIMEOUT:-120}" "$root/tools/run-uefi.sh" "$disk" "${devices[@]}" \
        >"$out/$name.log" 2>&1 </dev/null &
    qemu=$!
    while kill -0 "$qemu" 2>/dev/null; do
        if grep -aq 'l4h-vmmgr: all guests stopped' "$out/$name.log"; then
            kill "$qemu" 2>/dev/null || true
            break
        fi
        sleep 1
    done
    wait "$qemu" || true
    qemu=
    python3 - "$out/$name.log" "$expected" "$disk" <<'PY'
import json, pathlib, re, sys
log, expected, disk = sys.argv[1:]
text = pathlib.Path(log).read_text(errors='replace')
if expected == 'fail':
    failure = text.index('l4h: boot partition selection failed')
    fallback = text.index('PLATFORMTEST: fallback')
    assert failure < fallback
    assert not re.search(r'PLATFORMTEST: (source|initrd)', text[:fallback])
    expected = 'B'
else:
    assert 'PLATFORMTEST: fallback' not in text
assert f'PLATFORMTEST: PASS {expected}' in text, text[-6000:]
assert 'PLATFORMTEST: FAIL' not in text
other = 'B' if expected == 'A' else 'A'
assert f'PLATFORMTEST: source {other}' not in text
assert f'PLATFORMTEST: initrd {other}' not in text
pci = json.loads(re.search(r'PLATFORMTEST: PCI_JSON (\[.*\])', text)[1])
assert len(pci) > 124, len(pci)
assert len([p for p in pci if (p['vendor'], p['device']) == (0x1b36, 5)]) == 128
bdfs = [p['pci'] for p in pci]
assert bdfs == sorted(set(bdfs))
assert {'none', 'blkd', 'netd', 'memd', 'firmware'} <= {p['owner'] for p in pci}
assert any((p['vendor'], p['device'], p['subsystem_vendor'], p['class']) == (0x1af4, 0x1041, 0x1af4, 2) for p in pci)
capacity = pathlib.Path(disk).stat().st_size // 512
end = (capacity - 2048) & ~7
assert f'PLATFORMTEST: geometry {capacity} {end - 786432}' in text
with open(disk, 'rb') as f:
    for sector, byte in [(786432 - 8, 0xa5), (786432, 0x5a), (end - 8, 0x6b), (end, 0xa5)]:
        f.seek(sector * 512)
        assert f.read(4096) == bytes([byte]) * 4096, sector
print(f'{pathlib.Path(log).stem}: slot {expected}, {capacity} sectors, {len(pci)} PCI functions: PASS')
PY
}
guards() {
    python3 - "$disk" <<'PY'
import os, sys
with open(sys.argv[1], 'r+b') as f:
    capacity = os.fstat(f.fileno()).st_size // 512
    for sector in [786432 - 8, (capacity - 2048) & ~7]:
        f.seek(sector * 512)
        f.write(b'\xa5' * 4096)
PY
}
guards
run runtime-a A 1111-1111 l4h_esp_uuid=1111-1111
run runtime-b B 2222-2222 l4h_esp_label=L4HSLOTB
run runtime-override B 1111-1111 l4h_esp_uuid=2222-2222
# Resize the raw disk, without rewriting either slot's settings.
truncate -s 640M "$disk"
guards
run resized-a A 1111-1111 l4h_esp_uuid=1111-1111
truncate -s $((640 * 1024 * 1024 + 512)) "$disk"
guards
run odd-sectors-a A 1111-1111 l4h_esp_uuid=1111-1111
mcopy -o -i "$slota" "$out/fixed-a.efi" ::/EFI/l4h.efi
mcopy -o -i "$slotb" "$out/fixed-b.efi" ::/EFI/l4h.efi
run fixed-a A 1111-1111 ignored=1
run fixed-b B 2222-2222 ignored=1
mcopy -o -i "$slota" "$out/runtime.efi" ::/EFI/l4h.efi
run missing-slot fail 1111-1111 l4h_esp_uuid=3333-3333
run missing-selector fail 1111-1111 ignored=1
run conflicting-selector fail 1111-1111 l4h_esp_uuid=1111-1111 conflict
run option-as-selector fail 1111-1111 l4h_esp_uuid=--set=root
run corrupt-env fail 1111-1111 l4h_esp_uuid=1111-1111 corrupt
run missing-env fail 1111-1111 l4h_esp_uuid=1111-1111 missing
echo 'PLATFORMTEST: PASS'
