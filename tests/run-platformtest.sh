#!/usr/bin/env bash
# Exercise the shipped mkefi configuration under OVMF with a front GRUB
# chainloading two FAT slots. Check runtime selectors, disk
# growth with unchanged l4h.conf, odd sector counts, fallback after selection
# failure, GRUB literals, and a PCI inventory larger than one page.
# A software TPM checks the loader's measurements. PLATFORM_FL4_EFI may
# name a prebuilt native FL4 application (including its guest and SDK).
# L4H_TEST_KERNEL may name an already-built compatible guest kernel.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export PATH="$PATH:/usr/sbin:/sbin"
source "$root/tools/host-profile.sh"
out=$root/build/platformtest
boot_label='L4H`BOOT'
slot_a_label='L4H$`SLOTA'
runtime_env=/EFI/L4H/grubenv
mkdir -p "$out"
python3 "$root/tests/test_mkefi.py"
if [ -n "${PLATFORM_FL4_EFI:-}" ]; then
    rustc +stable --edition=2024 --test "$root/tests/fl4-efi-policy.rs" -o "$out/fl4-efi-policy"
    "$out/fl4-efi-policy"
    cp "$PLATFORM_FL4_EFI" "$out/l4h.efi"
else
    if [ -n "${L4H_TEST_KERNEL:-}" ]; then
        guest_kernel=$L4H_TEST_KERNEL
    else
        "$root/tools/build-linux.sh" vmlinux >"$out/linux-build.log" 2>&1
        guest_kernel=$root/build/linux-l4h/vmlinux
    fi
    "$root/tools/build-host.sh" >"$out/host-build.log" 2>&1
    L4H_GUEST_KERNEL=$guest_kernel L4H_GUEST_SDK= L4H_MKSHIM= "$root/tools/mkefi.sh" "$out/l4h.efi"
fi
"$root/tools/build-l4hctl.sh"
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
load_env --file "($bootpart)/EFI/L4H/frontenv" l4h_chain_uuid l4h_retry
search --no-floppy --set=slot --fs-uuid "$l4h_chain_uuid"
chainloader "($slot)/EFI/l4h.efi"
# A failed image must return an error, including for native BootOrder
# callers. GRUB propagates StartImage's EFI status through the boot command.
if boot; then
    echo 'PLATFORMTEST: successful EFI return'
    halt
fi
echo 'PLATFORMTEST: fallback'
if [ "$l4h_retry" = 1 ]; then
    # Recover by updating the runtime selector and retrying the same image.
    l4h_esp_uuid=2222-2222
    l4h_esp_label=
    save_env --file "($bootpart)/EFI/L4H/grubenv" l4h_esp_uuid l4h_esp_label
    search --no-floppy --set=slot --fs-uuid "$l4h_esp_uuid"
    chainloader "($slot)/EFI/l4h.efi"
    boot
    echo 'PLATFORMTEST: fallback failed'
fi
halt
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
for row in "$bootpart 131072 aaaaaaaa $boot_label" "$slota 262144 11111111 $slot_a_label" "$slotb 262144 22222222 L4HSLOTB"; do
    read -r part sectors serial label <<< "$row"
    mformat -i "$part" -T "$sectors" -F -N "$serial" -v "$label" ::
    mmd -i "$part" ::/EFI
done
mmd -i "$bootpart" ::/EFI/BOOT ::/EFI/L4H
mcopy -i "$bootpart" "$out/front.efi" ::/EFI/BOOT/BOOTX64.EFI
for slot in A B; do
    if [ "$slot" = A ]; then part=$slota; else part=$slotb; fi
    mmd -i "$part" ::/l4h ::/l4h/dom0 ::/EFI/L4H
    mcopy -i "$part" "$out/$slot.cpio.gz" ::/l4h/dom0/initrd
    mcopy -i "$part" "$out/$slot.conf" ::/l4h/l4h.conf
    mcopy -i "$part" "$out/l4h.efi" ::/EFI/l4h.efi
done
# Enough unhandled functions to force CTL_PCI_LIST through multiple pages.
devices=(-device pci-bridge,id=bulk,chassis_nr=1 -device qemu-xhci)
for i in $(seq 0 127); do
    printf -v addr '%x.%x' "$((i / 8))" "$((i % 8))"
    devices+=(-device "pci-testdev,bus=bulk,addr=$addr,multifunction=on")
done
guards() {
    python3 - "$1" <<'PY'
import os, sys
with open(sys.argv[1], 'r+b') as f:
    capacity = os.fstat(f.fileno()).st_size // 512
    for sector in [786432 - 8, (capacity - 2048) & ~7]:
        f.seek(sector * 512)
        f.write(b'\xa5' * 4096)
PY
}
guards "$disk"
cp "$out/B.conf" "$out/B-changed.conf"
printf '# unchosen slot changed\n' >> "$out/B-changed.conf"
printf 'unchosen initrd changed\n' > "$out/other-initrd"

run_case() {
    local name=$1 expected=$2 chain=$3 selector=$4 fault=${5:-} size=${6:-} with_tpm=${7:-0}
    local case_dir=$out/case-$name
    rm -rf "$case_dir" && mkdir -p "$case_dir"
    # Not local: run_case runs in its own subshell and its EXIT trap fires
    # after run_case returns (when locals are already out of scope).
    case_disk=$case_dir/disk.raw
    cp --sparse=always --reflink=auto "$disk" "$case_disk"
    if [ -n "$size" ]; then
        truncate -s "$size" "$case_disk"
        guards "$case_disk"
    fi
    local c_boot=$case_disk@@1048576
    local c_slota=$case_disk@@68157440
    local c_slotb=$case_disk@@202375168
    local retry=0
    if [ "$fault" = retry ]; then retry=1; fi
    grub-editenv "$case_dir/frontenv" create
    grub-editenv "$case_dir/frontenv" set "l4h_chain_uuid=$chain" "l4h_retry=$retry"
    mcopy -o -i "$c_boot" "$case_dir/frontenv" ::/EFI/L4H/frontenv
    grub-editenv "$case_dir/grubenv" create
    grub-editenv "$case_dir/grubenv" set "$selector"
    if [ "$fault" = conflict ]; then grub-editenv "$case_dir/grubenv" set l4h_esp_label=L4HSLOTB; fi
    if [ "$fault" = extra ]; then
        grub-editenv "$case_dir/grubenv" set l4h_boot_ok=0 esp=invalid serial_port=0
    fi
    if [ "$fault" = corrupt ]; then printf 'invalid environment block\n' > "$case_dir/grubenv"; fi
    mcopy -o -i "$c_boot" "$case_dir/grubenv" "::$runtime_env"
    if [ "$fault" = missing ]; then mdel -i "$c_boot" "::$runtime_env"; fi
    if [ "$fault" = duplicate ] || [ "$fault" = slot ]; then
        mcopy -o -i "$c_slota" "$case_dir/grubenv" "::$runtime_env"
    fi
    if [ "$fault" = slot ]; then mdel -i "$c_boot" "::$runtime_env"; fi
    if [ "$fault" = invalid-slot-config ]; then
        mdel -i "$c_slota" ::/l4h/l4h.conf
        mmd -i "$c_slota" ::/l4h/l4h.conf
    fi
    if [ "$fault" = other-slot ]; then
        mcopy -o -i "$c_slotb" "$out/B-changed.conf" ::/l4h/l4h.conf
        mcopy -o -i "$c_slotb" "$out/other-initrd" ::/l4h/dom0/initrd
    fi
    if [ "$fault" = return-success ]; then
        mcopy -o -i "$c_slota" "$out/return-success.efi" ::/EFI/l4h.efi
    fi
    local case_tpm=()
    tpm_dir=
    qemu=
    cleanup_case() {
        if [ -n "${qemu:-}" ]; then kill "$qemu" 2>/dev/null || true; wait "$qemu" 2>/dev/null || true; fi
        [ -z "${tpm_dir:-}" ] || rm -rf "$tpm_dir"
        [ -z "${case_disk:-}" ] || rm -f "$case_disk"
    }
    trap cleanup_case EXIT
    if [ "$with_tpm" = 1 ]; then
        tpm_dir=$(mktemp -d /tmp/l4h-ptpm.XXXXXX)
        "$root/tools/swtpm.sh" "$tpm_dir"
        case_tpm=(-chardev "socket,id=tpm,path=$tpm_dir/sock" -tpmdev emulator,id=tpm0,chardev=tpm -device tpm-crb,tpmdev=tpm0)
    fi
    # Clear a previous run's completion marker before the child starts.
    : > "$out/$name.log"
    L4H_SMP=${PLATFORMTEST_SMP:-1} L4H_MEM=${PLATFORMTEST_MEM:-2G} \
        timeout "${PLATFORMTEST_TIMEOUT:-120}" "$root/tools/run-uefi.sh" "$case_disk" "${devices[@]}" "${case_tpm[@]}" \
        >"$out/$name.log" 2>&1 </dev/null &
    qemu=$!
    while kill -0 "$qemu" 2>/dev/null; do
        if grep -aq 'l4h-vmmgr: all guests stopped' "$out/$name.log"; then
            kill "$qemu" 2>/dev/null || true
            break
        fi
        sleep 0.2
    done
    wait "$qemu" || true
    qemu=
    python3 - "$out/$name.log" "$expected" "$case_disk" <<'PY'
import json, pathlib, re, sys
log, expected, disk = sys.argv[1:]
text = pathlib.Path(log).read_text(errors='replace')
if expected == 'success':
    assert 'PLATFORMTEST: successful EFI return' in text, text[-6000:]
    assert 'PLATFORMTEST: fallback' not in text
    print('exit-status-control: rejected EFI_SUCCESS: PASS')
    sys.exit(0)
assert 'PLATFORMTEST: successful EFI return' not in text
if expected in ('fail', 'file-error', 'retry'):
    reason = 'cannot read /l4h/l4h.conf' if expected == 'file-error' else 'boot partition selection failed'
    failure = text.index(reason)
    fallback = text.index('PLATFORMTEST: fallback')
    assert failure < fallback
    assert not re.search(r'PLATFORMTEST: (source|initrd)', text[:fallback])
    if expected != 'retry':
        assert not re.search(r'PLATFORMTEST: (source|initrd)', text)
        print(f'{pathlib.Path(log).stem}: EFI error returned to caller: PASS')
        sys.exit(0)
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
assert {'none', 'blkd', 'nicd', 'memd', 'firmware'} <= {p['owner'] for p in pci}
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

jobs=${PLATFORMTEST_JOBS:-$(nproc)}
[ "$jobs" -le 4 ] || jobs=4
pids=() names=()
trap 'for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true' EXIT
start_case() {
    local name=$1
    while [ "$(jobs -rp | wc -l)" -ge "$jobs" ]; do
        sleep 0.1
    done
    ( run_case "$@" ) >"$out/$name.out" 2>&1 &
    pids+=($!)
    names+=("$name")
}

start_case runtime-a A 1111-1111 l4h_esp_uuid=1111-1111
start_case runtime-b B 2222-2222 l4h_esp_label=L4HSLOTB
start_case runtime-override B 1111-1111 l4h_esp_uuid=2222-2222
start_case runtime-label-literal A 2222-2222 "l4h_esp_label=$slot_a_label"
# Resize the raw disk, without rewriting either slot's settings.
start_case resized-a A 1111-1111 l4h_esp_uuid=1111-1111 '' 640M
start_case odd-sectors-a A 1111-1111 l4h_esp_uuid=1111-1111 '' $((640 * 1024 * 1024 + 512))
start_case runtime-on-slot A 2222-2222 l4h_esp_uuid=1111-1111 slot
start_case runtime-whitelist A 1111-1111 l4h_esp_uuid=1111-1111 extra
start_case runtime-retry retry 1111-1111 l4h_esp_uuid=3333-3333 retry
start_case missing-slot fail 1111-1111 l4h_esp_uuid=3333-3333
start_case missing-selector fail 1111-1111 ignored=1
start_case conflicting-selector fail 1111-1111 l4h_esp_uuid=1111-1111 conflict
start_case option-as-selector fail 1111-1111 l4h_esp_uuid=--set=root
start_case corrupt-env fail 1111-1111 l4h_esp_uuid=1111-1111 corrupt
start_case duplicate-env fail 1111-1111 l4h_esp_uuid=1111-1111 duplicate
# GRUB's no-device search finds B first in this fixture. The native
# loader uses the filesystem device supplied by the front chainloader.
if [ -n "${PLATFORM_FL4_EFI:-}" ]; then
    start_case missing-env A 1111-1111 ignored=1 missing
    start_case invalid-slot-config file-error 1111-1111 l4h_esp_uuid=1111-1111 invalid-slot-config
else
    start_case missing-env B 1111-1111 ignored=1 missing
fi
# Both loaders exclude the unchosen slot. GRUB also measures the selector
# block, while the native loader measures only the selected slot's two
# files, each as one event: its module name, NUL, `present`, NUL, then the
# file's exact bytes (l4h-config, then dom0-initrd).
start_case measured-a A 1111-1111 l4h_esp_uuid=1111-1111 '' '' 1
start_case measured-other-slot A 1111-1111 l4h_esp_uuid=1111-1111 other-slot '' 1
start_case measured-selector A 1111-1111 l4h_esp_uuid=1111-1111 extra '' 1
start_case exit-status-control success 1111-1111 ignored=1 return-success

fail=0
for i in "${!pids[@]}"; do
    if ! wait "${pids[$i]}"; then
        fail=1
    fi
    cat "$out/${names[$i]}.out"
done
trap - EXIT
[ "$fail" = 0 ] || exit 1

python3 - "$root" "$out" "${PLATFORM_FL4_EFI:-}" <<'PY'
import hashlib, pathlib, re, runpy, sys
root, out = map(pathlib.Path, sys.argv[1:3])
decode = runpy.run_path(str(root / 'tools/l4h-attest.py'))['cbor_decode']
def pcrs(name):
    text = (out / (name + '.log')).read_text(errors='replace')
    evidence = bytes.fromhex(re.search(r'PLATFORMTEST: EVIDENCE ([0-9a-f]+)', text)[1])
    return decode(evidence)['pcrs']
baseline, other, selector = (pcrs('measured-' + case) for case in ('a', 'other-slot', 'selector'))
base = baseline[9]
assert base != bytes(32)
assert base == other[9], 'unchosen slot affected PCR 9'
if sys.argv[3]:
    assert baseline[8] == other[8] == selector[8] == bytes(32), 'native loader changed PCR 8'
    expected = bytes(32)
    for slot, file in [(b'l4h-config', 'A.conf'), (b'dom0-initrd', 'A.cpio.gz')]:
        event = slot + b'\0present\0' + (out / file).read_bytes()
        expected = hashlib.sha256(expected + hashlib.sha256(event).digest()).digest()
    assert base == selector[9] == expected, 'incorrect native boot file measurements'
else:
    assert base != selector[9], 'selector not measured into PCR 9'
print('selected slot PCR 9 measurements: PASS')
PY
echo 'PLATFORMTEST: PASS'
