#!/usr/bin/env bash
# Full native Linux -> installer -> L4H -> native round trip in OVMF/KVM.
# Usage: tests/run-install-vm.sh debian-13-nocloud-amd64.qcow2 [release-directory] [1|2]
# INSTALL_VM_SWAP_NAMES=1 with two NICs also exercises an eth0/eth1 name swap.
# INSTALL_VM_FIRMWARE=bios boots the VM as a DigitalOcean droplet instead:
# SeaBIOS on i440fx, a virtio-blk boot disk and transitional virtio-net, so
# the installer takes its BIOS GRUB path.
# Requires prebuilt release artifacts, sudo, QEMU/KVM, OVMF and util-linux.
# The input image is never modified. Only the new test image is mounted.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
base=$(realpath "$1")
release=$(realpath "${2:-$root/build/efi}")
nics=${3:-1}
firmware=${INSTALL_VM_FIRMWARE:-uefi}
[[ $nics == 1 || $nics == 2 ]] || { echo 'NIC count must be 1 or 2' >&2; exit 1; }
[[ $firmware == uefi || $firmware == bios ]] || { echo 'INSTALL_VM_FIRMWARE must be uefi or bios' >&2; exit 1; }
[[ ${INSTALL_VM_SWAP_NAMES:-0} != 1 || $nics == 2 ]] || { echo 'name swap needs two NICs' >&2; exit 1; }
work=$root/build/install-vm-run
mkdir -p "$work"
[[ ! -e $work/disk.raw ]] || { echo "move $work aside before rerunning" >&2; exit 1; }
qemu-img convert -f qcow2 -O raw "$base" "$work/disk.raw"
loop=''
mounted=0
qemu=''
cleanup() {
    if [[ -n $qemu ]]; then kill "$qemu" 2>/dev/null || true; wait "$qemu" 2>/dev/null || true; fi
    ((mounted == 0)) || sudo umount "$work/root"
    [[ -z $loop ]] || sudo losetup -d "$loop"
}
trap cleanup EXIT
loop=$(sudo losetup --find --show --partscan "$work/disk.raw")
sudo udevadm settle
rootpart=''
while read -r dev type; do
    case "$type" in
        0fc63daf-8483-4772-8e79-3d69d8477de4|4f68bce3-e8cd-4db1-96e7-fbcaf984b709)
            [[ -z $rootpart ]] || { echo 'image has multiple Linux root candidates' >&2; exit 1; }
            rootpart=$dev ;;
    esac
done < <(sudo lsblk -rpn -o NAME,PARTTYPE "$loop")
[[ -n $rootpart ]] || { echo 'no Linux partition in test image' >&2; exit 1; }
root_index=${rootpart#"$loop"p}
[[ $root_index =~ ^[0-9]+$ ]]
mkdir -p "$work/root"
sudo mount "$rootpart" "$work/root"
mounted=1
guest=$work/root
sudo mkdir -p "$guest/opt/l4h-install-test/release"
printf '%s\n' "$nics" | sudo tee "$guest/opt/l4h-install-test/nic-count" >/dev/null
if [[ ${INSTALL_VM_SWAP_NAMES:-0} == 1 ]]; then
    sudo touch "$guest/opt/l4h-install-test/swap-names"
fi
sudo cp "$root/tools/install.sh" "$guest/opt/l4h-install-test/"
boot_files=(l4h-generic.efi)
[[ $firmware == uefi ]] || boot_files=(l4h-bios-x86_64.tar.xz)
for file in l4h-dom0-x86_64.tar.xz "${boot_files[@]}"; do
    sudo cp "$release/$file" "$guest/opt/l4h-install-test/release/"
done
(cd "$release" && sha256sum l4h-dom0-x86_64.tar.xz "${boot_files[@]}") | sudo tee "$guest/opt/l4h-install-test/release/SHA256SUMS" >/dev/null
sudo install -m 755 "$root/tests/guest/install-test" "$guest/opt/l4h-install-test/run"
sudo install -m 755 "$root/tests/guest/install-curl-fixture" "$guest/opt/l4h-install-test/curl-fixture"
sudo tee "$guest/etc/systemd/system/l4h-install-test.service" >/dev/null <<'UNIT'
[Unit]
Description=L4H installer VM test
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
ExecStart=/opt/l4h-install-test/run
[Install]
WantedBy=multi-user.target
UNIT
sudo mkdir -p "$guest/etc/systemd/system/multi-user.target.wants"
sudo ln -s ../l4h-install-test.service "$guest/etc/systemd/system/multi-user.target.wants/"
# Avoid the nocloud image's interactive firstboot wizard. Test a headless
# machine with no active AppArmor profiles (L4H does not ship AppArmor).
printf '%s\n' 717089e020494de6bb70bd36f88ce1ad | sudo tee "$guest/etc/machine-id" >/dev/null
sudo sed -i 's/ ro / ro apparmor=0 /g' "$guest/boot/grub/grub.cfg"
sudo umount "$guest"
mounted=0
sudo losetup -d "$loop"
loop=''
qemu_user=${L4H_QEMU_USER:-${SUDO_USER:-$(id -un)}}
if [[ $firmware == uefi ]]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd "$work/vars.fd"
    machine=(-machine q35
        -drive 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd'
        -drive "if=pflash,format=raw,file=$work/vars.fd"
        -drive "if=none,id=disk,format=raw,file=$work/disk.raw"
        -device 'nvme,drive=disk,serial=l4h-install-test')
    nic=virtio-net-pci,disable-legacy=on
else
    machine=(-machine pc
        -drive "if=none,id=disk,format=raw,file=$work/disk.raw"
        -device 'virtio-blk-pci,drive=disk,serial=l4h-install-test')
    nic=virtio-net-pci
fi
network=(-netdev 'user,id=net' -device "$nic,netdev=net,mac=52:54:00:12:34:56")
if [[ $nics == 2 ]]; then
    network+=(-netdev 'user,id=net2,net=10.0.3.0/24' -device "$nic,netdev=net2,mac=52:54:00:12:34:57")
fi
echo "Running KVM ($firmware) as $qemu_user with $nics NIC(s); serial log: $work/serial.log"
timeout "${INSTALL_VM_TIMEOUT:-600}" sudo -u "$qemu_user" qemu-system-x86_64 \
    -enable-kvm -cpu host,-vmx -m 6G -smp 2 "${machine[@]}" \
    "${network[@]}" \
    -display none -serial "file:$work/serial.log" -monitor none &
qemu=$!
while kill -0 "$qemu" 2>/dev/null; do
    if grep -aq 'INSTALLVM: FAIL' "$work/serial.log" 2>/dev/null; then
        kill "$qemu" 2>/dev/null || true
        break
    fi
    sleep 1
done
wait "$qemu" || true
qemu=''
grep -a 'INSTALLVM:' "$work/serial.log"
grep -aq 'INSTALLVM: PASS' "$work/serial.log"
if grep -aq 'INSTALLVM: FAIL' "$work/serial.log"; then exit 1; fi
# Release builds may not mirror dom0's console to the hardware UART. Read
# the persisted test log after QEMU exits, without changing the test disk.
loop=$(sudo losetup --find --show --read-only --partscan "$work/disk.raw")
sudo udevadm settle
sudo mount -o ro "${loop}p${root_index}" "$work/root"
mounted=1
sudo cat "$work/root/opt/l4h-install-test/result.log" | tee "$work/guest-result.log" >/dev/null
sudo umount "$work/root"
mounted=0
sudo losetup -d "$loop"
loop=''
grep -a 'INSTALLVM:' "$work/guest-result.log"
grep -aq 'INSTALLVM: dom0 kernel' "$work/guest-result.log"
grep -aq 'INSTALLVM: existing userspace, modules, network and persistent root passed' "$work/guest-result.log"
