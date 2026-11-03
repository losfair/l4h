#!/usr/bin/env bash
# Multikernel (DESIGN.md §11.4): l4h-mkshim boots MK_PARTITIONS (default 2)
# seL4 kernels on one QEMU q35 machine, each partition with its own CPUs,
# RAM, virtio disk and virtio NIC.  Each partition's dom0 boots, gets an
# address by DHCP over its own NIC, and runs a VM that no other dom0 sees;
# a secondary's dom0 is refused host-reboot.  Partitions 0 and 1 are
# linked (link.p0-p1): their dom0s ping each other over the link, with no
# switch outside the machine, and partition 1's floods it while its
# rtc-set and heartbeats must still reach partition 0.  Then partition 0's dom0 resets the whole
# machine.  The other kernels' consoles reach the serial
# port through partition 0 ("[pN]" lines).
# MK_PARTITIONS=N (2..8) needs 2N CPUs; L4H_QEMU_IOMMU=intel|amd adds an
# IOMMU the partitions share.  MK_BOOT=uefi or bios boots a disk image from
# tools/mkimage.sh through GRUB (OVMF or SeaBIOS) instead of QEMU's
# multiboot loader, with the configuration on the EFI system partition.
# MK_UPLINK=1 gives partition 1 no NIC: the link is `uplink`, on both
# partitions' switch 0, and partition 1's dom0 gets its address through
# partition 0's NIC.
# MK_BRIDGES=1 puts partition 1's disk behind a PCIe root port and its NIC
# behind a root port and a PCIe-to-PCI bridge, whose requester ID it
# borrows: with an IOMMU, partition 1 must read partition 0's bridges.
# MK_STRESS=S: for S seconds partitions 0 and 1 flood the link both ways,
# download a file from each other over it (checked against their own
# copy), and make and destroy VMs one after another, all at once.
# MK_MACHINE=pc boots an i440FX machine, which has no MCFG (as on GCE): the
# partitions share PCI configuration ports under a lock instead of ECAM.
# MK_ATTEST=1 adds a software TPM (swtpm), which only partition 0 sees:
# every dom0 and VM gets a report, the other partitions' through partition
# 0's trustd, and tools/l4h-attest.py verifies each against its
# partition's evidence; a second boot activates a credential made for the
# attestation key in every partition (DESIGN.md §10.2).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
n=${MK_PARTITIONS:-2}
machine=${MK_MACHINE:-q35}
rootbus=pcie.0
[ "$machine" = pc ] && rootbus=pci.0
attest=${MK_ATTEST:-}
out=$root/build/mktest
log=$root/build/mktest.log
mkdir -p "$out"
rm -f "$log"

"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
objcopy --strip-debug "$l4h_linux_out/vmlinux" "$out/vmlinux"
"$root/tools/build-l4hctl.sh" >/dev/null
"$root/tools/mkinitramfs.sh" "$out/vm.cpio.gz" "$root/tests/guest/init-mkvm" "$l4h_ctl" >/dev/null
dom0_initramfs() {  # dom0_initramfs [extra files...]
    "$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-mktest" \
        "$l4h_ctl" "$out/vm.cpio.gz" "$root/tests/guest/udhcpc.script" "$@" >/dev/null
}
dom0_initramfs
"$root/tools/build-mkshim.sh" "$n" >/dev/null
"$root/tools/build-host.sh"
objcopy --strip-debug "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" "$out/l4h-root.elf"
cp "$root/build/mkshim/l4h-mkshim.elf" "$out/"

nonce=
if [ -n "$attest" ]; then
    nonce=$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')
    # A fresh TPM, so that the EK certificate is the one from this CA.
    rm -rf "$out/tpm" "$out/att"
fi

# Partition k has the PCI slots 4 + 2k (disk) and 5 + 2k (NIC), two CPUs
# and 1 GiB; partition 0 the rest.  With an IOMMU, each dom0 leaves its
# disk to VMs, whose I/O pools are attached and drained (init-mktest).
mkiommu=() dom0_disks=""
if [ -n "${L4H_QEMU_IOMMU:-}" ]; then
    mkiommu=(MKIOMMU=1) dom0_disks=$'\ndom0_disks=0'
fi
conf=$out/l4h-mk.conf
echo "partitions = $n" > "$conf"
[ "$n" -lt 2 ] || echo "link.p0-p1 = $([ -n "${MK_UPLINK:-}" ] && echo uplink || echo 1)" >> "$conf"
devices=() cmdline=()
mods="$out/l4h-root.elf l4h-root,$out/vmlinux guest-kernel,$out/dom0.cpio.gz dom0-initrd,$conf l4h-mk.conf"
for k in $(seq 0 $((n - 1))); do
    disk=$((4 + 2 * k)) nic=$((5 + 2 * k))
    disk_bdf=$(printf '00:%02x.0' $disk) nic_bdf=$(printf '00:%02x.0' $nic)
    if [ "$k" = 1 ] && [ -n "${MK_BRIDGES:-}" ]; then
        # The firmware numbers the buses depth first: root port 00:10.0
        # gets bus 1, 00:11.0 bus 2, and the bridge on bus 2 bus 3.
        devices+=(-device pcie-root-port,id=rp1,bus=pcie.0,addr=0x10,chassis=1,slot=1
            -device pcie-root-port,id=rp2,bus=pcie.0,addr=0x11,chassis=2,slot=2
            -device pcie-pci-bridge,id=pb1,bus=rp2,addr=0
            -drive "file=$out/disk$k.img,if=none,id=d$k,format=raw"
            -device "virtio-blk-pci,drive=d$k,bus=rp1,addr=0"
            -netdev "user,id=n$k"
            -device "virtio-net-pci,netdev=n$k,disable-legacy=on,bus=pb1,addr=1")
        disk_bdf=01:00.0 nic_bdf=03:01.0
    elif [ "$k" = 1 ] && [ -n "${MK_UPLINK:-}" ]; then
        devices+=(-drive "file=$out/disk$k.img,if=none,id=d$k,format=raw"
            -device "virtio-blk-pci,drive=d$k,bus=$rootbus,addr=$(printf '%#x' $disk)")
        nic_bdf=
    else
        devices+=(-drive "file=$out/disk$k.img,if=none,id=d$k,format=raw"
            -device "virtio-blk-pci,drive=d$k,bus=$rootbus,addr=$(printf '%#x' $disk)"
            -netdev "user,id=n$k"
            -device "virtio-net-pci,netdev=n$k,disable-legacy=on,bus=$rootbus,addr=$(printf '%#x' $nic)")
    fi
    if [ "$k" != 0 ]; then
        printf 'p%d.cpus = 2\np%d.mem = 1G\np%d.pci = %s%s\n' "$k" "$k" "$k" "$disk_bdf" "${nic_bdf:+, $nic_bdf}" >> "$conf"
    fi
    # Partitions 0 and 1 know their peer over the link.
    peer=
    [ "$k" -lt 2 ] && [ -z "${MK_UPLINK:-}" ] && peer=" MKPEER=$((1 - k))"
    # The attestation check measures this exact command line.
    cmdline[k]="console=hvc0 MKP=$k$peer${MK_STRESS:+ MKSTRESS=$MK_STRESS}${nonce:+ attest_nonce=$nonce}${mkiommu[*]:+ ${mkiommu[*]}}"
    printf 'dom0_cmdline="%s"\ndom0_mem_mb=256\nboot_disk=%s\n%s%s\n' \
        "${cmdline[k]}" "$disk_bdf" "${nic_bdf:+uplink_nic=$nic_bdf}" "$dom0_disks" > "$out/p$k.conf"
    mods+=",$out/p$k.conf p$k:l4h-config,$root/build/mkshim/kernel-s$k.elf kernel-s$k"
done

boot=(-kernel "$out/l4h-mkshim.elf" -append "console_port=0x3f8" -initrd "$mods")
if [ -n "${MK_BOOT:-}" ]; then
    # The ESP's /l4h: l4h-mk.conf, pN/l4h.conf and the dom0 initramfs all
    # partitions share.
    rm -rf "$out/esp"
    mkdir -p "$out/esp"
    cp "$conf" "$out/esp/"
    for k in $(seq 0 $((n - 1))); do
        mkdir -p "$out/esp/p$k"
        cp "$out/p$k.conf" "$out/esp/p$k/l4h.conf"
    done
    L4H_GUEST_KMODS= L4H_GUEST_KERNEL="$out/vmlinux" "$root/tools/mkimage.sh" -i "$out/dom0.cpio.gz" -m "$out/esp" \
        "$out/mk.raw" "$out/l4h-root.elf" >/dev/null
    # On the chipset's AHCI controller, which no partition drives.
    boot=(-drive "file=$out/mk.raw,format=raw,if=none,id=boot" -device ide-hd,drive=boot,bus=ide.0,bootindex=0)
    case $MK_BOOT in
        uefi) boot+=(-bios /usr/share/ovmf/OVMF.fd) ;;
        bios) ;;
        *) echo "unsupported MK_BOOT: $MK_BOOT (use uefi or bios)" >&2; exit 1 ;;
    esac
fi

iommu=()
case "${L4H_QEMU_IOMMU:-}" in
    amd) iommu=(-machine kernel-irqchip=split -device amd-iommu,intremap=on) ;;
    intel) iommu=(-machine kernel-irqchip=split -device intel-iommu,intremap=on,caching-mode=on) ;;
    '') ;;
esac
if [ ${#iommu[@]} -ne 0 ]; then
    iommu+=(-global virtio-blk-pci.iommu_platform=on -global virtio-blk-pci.disable-legacy=on
        -global virtio-net-pci.iommu_platform=on)
fi

run_qemu() {
    local tpm=()
    for k in $(seq 0 $((n - 1))); do
        # Fresh disks: dom0 leaves its attestation at the start of its own.
        rm -f "$out/disk$k.img"
        truncate -s 64M "$out/disk$k.img"
    done
    if [ -n "$attest" ]; then
        "$root/tools/swtpm.sh" "$out/tpm"
        tpm=(-chardev socket,id=tpm,path="$out/tpm/sock" -tpmdev emulator,id=tpm0,chardev=tpm -device tpm-crb,tpmdev=tpm0)
    fi
    rm -f "$log"
    qemu-system-x86_64 -machine "$machine" -enable-kvm -cpu "${L4H_QEMU_CPU:-host,-vmx,+invtsc}" \
        -smp $((2 * n)) -m "${MK_MEM:-$((2 * n + 2))G}" -nographic -serial mon:stdio -no-reboot \
        "${iommu[@]}" "${tpm[@]}" \
        "${boot[@]}" \
        "${devices[@]}" ${MK_QEMU_ARGS:-} </dev/null >"$log" 2>&1 &
    local qemu=$!
    local end=$((SECONDS + ${MKTEST_TIMEOUT:-$((300 + ${MK_STRESS:-0}))}))
    while kill -0 "$qemu" 2>/dev/null; do
        if [ "$SECONDS" -ge "$end" ] || grep -aq "MKTEST p[0-9]*: FAIL\|cannot boot\|panic" "$log"; then
            sleep 1
            kill "$qemu" 2>/dev/null || true
            break
        fi
        sleep 1
    done
    wait "$qemu" 2>/dev/null || true
    grep -aE "l4h-mkshim|MKTEST|MKVM|partition|host reboot|trustd|TPM|\[p[0-9]\] .*(panic|fault|error)|panic" "$log" \
        | grep -av "MKVM: report" | awk 'NR <= 100'
    ok=1
    for k in $(seq 0 $((n - 1))); do
        grep -aq "MKTEST p$k: done" "$log" || { echo "partition $k did not finish"; ok=0; }
        [ "$k" -ge 2 ] || [ -n "${MK_UPLINK:-}" ] || grep -aq "MKTEST p$k: link ok" "$log" || { echo "partition $k: no ping over the link"; ok=0; }
        [ "$k" = 0 ] || grep -aq "MKTEST p$k: host-reboot refused" "$log" || { echo "partition $k: host-reboot not refused"; ok=0; }
        [ "$k" = 0 ] || grep -aq "l4h-root: RTC set for partition $k" "$log" || { echo "partition $k: rtc-set did not reach partition 0"; ok=0; }
    done
    # Partition 1 flooded the link during its rtc-set: control traffic
    # has a channel of its own.
    if [ "$n" -ge 2 ] && [ -n "${MK_STRESS:-}" ]; then
        for k in 0 1; do
            grep -aq "MKTEST p$k: stress ok" "$log" || { echo "partition $k: stress did not finish"; ok=0; }
        done
        ! grep -aq "stopped: no heartbeat" "$log" || { echo "heartbeats lost under stress"; ok=0; }
    elif [ "$n" -ge 2 ] && [ -z "${MK_UPLINK:-}" ]; then
        grep -aq "MKTEST p1: flood ok" "$log" || { echo "partition 1: no flood over the link"; ok=0; }
        ! grep -aq "partition 1 stopped: no heartbeat" "$log" || { echo "partition 1's heartbeats lost in the flood"; ok=0; }
    fi
    grep -aqE "^l4h-root: host reboot \(dom0\)\s*$" "$log" || { echo "partition 0 did not reset the machine"; ok=0; }
    if [ "$machine" = pc ]; then
        [ "$(grep -ac "l4h-root: no ECAM: PCI configuration through ports" "$log")" = "$n" ] \
            || { echo "not every partition shares the PCI configuration ports"; ok=0; }
    fi
    # One IOMMU for all: every partition's devices confined and interrupts
    # remapped, pools drained, and partition 0 (which gets every
    # partition's faults) saw none.
    if [ -n "${L4H_QEMU_IOMMU:-}" ]; then
        for k in $(seq 0 $((n - 1))); do
            grep -aq "MKTEST p$k: pool drained" "$log" || { echo "partition $k: no I/O pool drained"; ok=0; }
            grep -aqE "MKTEST p$k: iommu state: *on" "$log" \
                && grep -aqE "MKTEST p$k: iommu interrupts: *remapped" "$log" \
                || { echo "partition $k: IOMMU not on and remapping"; ok=0; }
        done
        if grep -aE "l4h-root: (VT-d [0-9]+: .*fault|iommu: .*(fault|illegal|error|timeout))" "$log"; then
            echo "IOMMU faults"; ok=0
        fi
    fi
    [ "$ok" = 1 ] || { echo "MKTEST: FAIL (log: $log)"; exit 1; }
}

run_qemu
if [ -z "$attest" ]; then
    echo "MKTEST: PASS"
    exit 0
fi

# What each dom0 left on its disk.
fail() { echo "MKTEST: FAIL: $*"; exit 1; }
saved() {  # saved <boot>: into $out/att/<boot>/p<k>
    for k in $(seq 0 $((n - 1))); do
        mkdir -p "$out/att/$1/p$k"
        tar -xf "$out/disk$k.img" -C "$out/att/$1/p$k" || fail "partition $k saved no attestation"
    done
}
saved 1
tool=$root/tools/l4h-attest.py
ca=$out/tpm/ca/issuercert.pem
json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))" "$@"; }
for k in $(seq 0 $((n - 1))); do
    a=$out/att/1/p$k
    python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex(open(sys.argv[1]).read().strip()))" \
        "$a/vm.report.hex" > "$a/vm.report"
    vm_launch=$(python3 "$tool" measure "$out/vmlinux" --initrd "$out/vm.cpio.gz" \
        --cmdline "console=hvc0 MKP=$k attest_nonce=$nonce")
    dom0_launch=$(python3 "$tool" measure "$out/vmlinux" --initrd "$out/dom0.cpio.gz" \
        --cmdline "${cmdline[k]}")
    python3 "$tool" verify "$a/vm.report" "$a/evidence" --data "$nonce" --launch "$vm_launch" --ek-ca "$ca" \
        > "$a/vm.json" 2>/dev/null || fail "partition $k: the VM's report"
    python3 "$tool" verify "$a/dom0.report" "$a/evidence" --data "$nonce" --launch "$dom0_launch" --ek-ca "$ca" \
        > "$a/dom0.json" 2>/dev/null || fail "partition $k: dom0's report"
    for w in vm dom0; do
        [ "$(json "$a/$w.json" 'd["guest"]["partition"]')" = "$k" ] || fail "partition $k: $w's report names another partition"
        [ "$(json "$a/$w.json" 'd["host"]["partition"]')" = "$k" ] || fail "partition $k: evidence for another partition"
    done
    # Partition 0 quotes its own key first.
    before=$(json "$a/vm.json" 'd["host"]["keys_before"]')
    if [ "$k" = 0 ]; then [ "$before" = "[]" ] || fail "partition 0's key is not the first"; fi
    if [ "$k" != 0 ]; then [ "${before:0:2}" = "[0" ] || fail "partition $k's chain does not start with partition 0"; fi
    echo "MKTEST: partition $k: dom0's and the VM's reports verify (VM guest $(json "$a/vm.json" 'd["guest"]["guest"]'), keys before: $before)"
done
# One TPM: the same attestation key; and a report verifies only with its
# own partition's evidence.
p0=$out/att/1/p0 p1=$out/att/1/p1
ak=$(json "$p0/dom0.json" 'd["host"]["ak_name"]')
[ "$(json "$p1/dom0.json" 'd["host"]["ak_name"]')" = "$ak" ] || fail "partitions quoted by different AKs"
! python3 "$tool" verify "$p1/vm.report" "$p0/evidence" 2>/dev/null || fail "partition 1's report verified with partition 0's evidence"
python3 "$tool" verify "$p1/vm.report" "$p1/evidence" --data "$nonce" --ak-name "$ak" --ek-ca "$ca"
echo "MKTEST: reports verify and name their partitions"

# ActivateCredential, partition 0's own and the others' through it.
secret=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
python3 "$tool" make-credential "$p1/evidence" "$secret" -o "$out/cred" || fail "make-credential"
dom0_initramfs "$out/cred"
run_qemu
saved 2
for k in $(seq 0 $((n - 1))); do
    [ "$(cat "$out/att/2/p$k/secret")" = "$secret" ] || fail "partition $k: credential not activated"
done
echo "MKTEST: the credential activates in every partition"
echo "MKTEST: PASS"
