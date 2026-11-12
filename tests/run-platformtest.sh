#!/usr/bin/env bash
# Exercise the shipped mkefi configuration under OVMF with a front GRUB
# chainloading two FAT slots. Check discovered and built-in selectors, disk
# growth with unchanged l4h.conf, odd sector counts, fallback after selection
# failure, GRUB literals, and a PCI inventory larger than one page.
# A software TPM checks measurement of the selector and selected files.
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
env -u L4H_ESP_UUID -u L4H_ESP_LABEL -u L4H_BOOT_ENV "$root/tools/mkefi.sh" "$out/default.efi"
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
# A failed image must return an error, including for native BootOrder
# callers. GRUB propagates StartImage's EFI status through the boot command.
if boot; then
    echo 'PLATFORMTEST: successful EFI return'
    halt
fi
echo 'PLATFORMTEST: fallback'
search --no-floppy --set=fallback --fs-uuid 2222-2222
chainloader "($fallback)/EFI/fallback.efi"
boot
echo 'PLATFORMTEST: fallback failed'
exit
CFG
grub-script-check "$out/front.cfg"
grub-mkstandalone -O x86_64-efi -o "$out/front.efi" --compress=xz \
    --modules='part_gpt fat search search_fs_uuid search_label loadenv chain serial terminal halt' \
    --locales= --fonts= --themes= "boot/grub/grub.cfg=$out/front.cfg"
# Positive control: upstream GRUB's bare exit really returns EFI_SUCCESS.
# The front loader must reject that status, rather than call it a fallback.
printf 'exit\n' > "$out/return-success.cfg"
grub-mkstandalone -O x86_64-efi -o "$out/return-success.efi" --compress=xz \
    --modules='normal minicmd' --locales= --fonts= --themes= \
    "boot/grub/grub.cfg=$out/return-success.cfg"
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
    mmd -i "$part" ::/l4h ::/l4h/dom0 ::/EFI/L4H
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
tpm=()
trap 'if [ -n "$qemu" ]; then kill "$qemu" 2>/dev/null || true; wait "$qemu" 2>/dev/null || true; fi' EXIT
run() {
    local name=$1 expected=$2 chain=$3 selector=$4 fault=${5:-}
    local envpath=${6:-$runtime_env}
    grub-editenv "$out/frontenv" create
    grub-editenv "$out/frontenv" set "l4h_chain_uuid=$chain"
    mcopy -o -i "$bootpart" "$out/frontenv" ::/EFI/L4H/frontenv
    grub-editenv "$out/grubenv" create
    grub-editenv "$out/grubenv" set "$selector"
    if [ "$fault" = conflict ]; then grub-editenv "$out/grubenv" set l4h_esp_label=L4HSLOTB; fi
    if [ "$fault" = extra ]; then
        grub-editenv "$out/grubenv" set l4h_boot_ok=0 esp=invalid serial_port=0
    fi
    if [ "$fault" = corrupt ]; then printf 'invalid environment block\n' > "$out/grubenv"; fi
    mcopy -o -i "$bootpart" "$out/grubenv" "::$envpath"
    if [ "$fault" = missing ]; then mdel -i "$bootpart" "::$envpath"; fi
    if [ "$fault" = duplicate ] || [ "$fault" = slot ]; then
        mcopy -o -i "$slota" "$out/grubenv" "::$envpath"
    fi
    if [ "$fault" = slot ]; then mdel -i "$bootpart" "::$envpath"; fi
    if [ ${#tpm[@]} -ne 0 ]; then "$root/tools/swtpm.sh" "$out/tpm"; fi
    # Clear a previous run's completion marker before the child starts.
    : > "$out/$name.log"
    timeout "${PLATFORMTEST_TIMEOUT:-120}" "$root/tools/run-uefi.sh" "$disk" "${devices[@]}" "${tpm[@]}" \
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
    if [ "$fault" = duplicate ] || [ "$fault" = slot ]; then mdel -i "$slota" "::$envpath"; fi
    python3 - "$out/$name.log" "$expected" "$disk" <<'PY'
import json, pathlib, re, sys
log, expected, disk = sys.argv[1:]
text = pathlib.Path(log).read_text(errors='replace')
if expected == 'success':
    assert 'PLATFORMTEST: successful EFI return' in text, text[-6000:]
    assert 'PLATFORMTEST: fallback' not in text
    print('exit-status-control: rejected EFI_SUCCESS: PASS')
    sys.exit(0)
assert 'PLATFORMTEST: successful EFI return' not in text
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
# Release defaults: the same application can select A even though B also
# has /l4h, or override the slot the front loader chainloaded it from.
for part in "$slota" "$slotb"; do
    mcopy -o -i "$part" "$out/default.efi" ::/EFI/l4h.efi
done
default_env=/EFI/L4H/grubenv
run discovered-a A 1111-1111 l4h_esp_uuid=1111-1111 '' "$default_env"
run discovered-b B 2222-2222 l4h_esp_label=L4HSLOTB '' "$default_env"
run discovered-override A 2222-2222 l4h_esp_uuid=1111-1111 '' "$default_env"
run discovered-on-slot A 2222-2222 l4h_esp_uuid=1111-1111 slot "$default_env"
run discovered-whitelist A 1111-1111 l4h_esp_uuid=1111-1111 extra "$default_env"
run discovered-missing-slot fail 1111-1111 l4h_esp_uuid=3333-3333 '' "$default_env"
run discovered-empty fail 1111-1111 ignored=1 '' "$default_env"
run discovered-conflict fail 1111-1111 l4h_esp_uuid=1111-1111 conflict "$default_env"
run discovered-option fail 1111-1111 l4h_esp_uuid=--set=root '' "$default_env"
run discovered-corrupt fail 1111-1111 ignored=1 corrupt "$default_env"
run discovered-duplicate fail 1111-1111 l4h_esp_uuid=1111-1111 duplicate "$default_env"
run discovered-absent B 1111-1111 ignored=1 missing "$default_env"
# Built-in settings take precedence over a bad default selector.
mcopy -o -i "$slota" "$out/fixed-a.efi" ::/EFI/l4h.efi
run fixed-ignores-discovery A 1111-1111 ignored=1 corrupt "$default_env"
mcopy -o -i "$slota" "$out/runtime.efi" ::/EFI/l4h.efi
run runtime-ignores-discovery A 1111-1111 l4h_esp_uuid=1111-1111
# PCR 9 must cover the discovered selector, including ignored variables,
# while excluding the unchosen slot's settings and initramfs.
mcopy -o -i "$slota" "$out/default.efi" ::/EFI/l4h.efi
tpm=(-chardev "socket,id=tpm,path=$out/tpm/sock" -tpmdev emulator,id=tpm0,chardev=tpm -device tpm-crb,tpmdev=tpm0)
run measured-a A 1111-1111 l4h_esp_uuid=1111-1111 '' "$default_env"
cp "$out/B.conf" "$out/B-changed.conf"
printf '# unchosen slot changed\n' >> "$out/B-changed.conf"
printf 'unchosen initrd changed\n' > "$out/other-initrd"
mcopy -o -i "$slotb" "$out/B-changed.conf" ::/l4h/l4h.conf
mcopy -o -i "$slotb" "$out/other-initrd" ::/l4h/dom0/initrd
run measured-other-slot A 1111-1111 l4h_esp_uuid=1111-1111 '' "$default_env"
run measured-selector A 1111-1111 l4h_esp_uuid=1111-1111 extra "$default_env"
python3 - "$root" "$out" <<'PY'
import pathlib, re, runpy, sys
root, out = map(pathlib.Path, sys.argv[1:])
decode = runpy.run_path(str(root / 'tools/l4h-attest.py'))['cbor_decode']
def pcr9(name):
    text = (out / (name + '.log')).read_text(errors='replace')
    evidence = bytes.fromhex(re.search(r'PLATFORMTEST: EVIDENCE ([0-9a-f]+)', text)[1])
    return decode(evidence)['pcrs'][9]
base = pcr9('measured-a')
assert base != bytes(32)
assert base == pcr9('measured-other-slot'), 'unchosen slot affected PCR 9'
assert base != pcr9('measured-selector'), 'selector not measured into PCR 9'
print('discovered selector measured, unchosen slot excluded from PCR 9: PASS')
PY
tpm=()
mcopy -o -i "$slotb" "$out/B.conf" ::/l4h/l4h.conf
mcopy -o -i "$slotb" "$out/B.cpio.gz" ::/l4h/dom0/initrd
mcopy -o -i "$slota" "$out/return-success.efi" ::/EFI/l4h.efi
run exit-status-control success 1111-1111 ignored=1
echo 'PLATFORMTEST: PASS'
