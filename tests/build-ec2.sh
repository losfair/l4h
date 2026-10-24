#!/usr/bin/env bash
# Build the EC2 integration-test disk. Import it with tools/ec2-image.py.
# L4H_EC2_PEER optionally names a same-subnet HTTP/ICMP test peer at MTU
# 9001, serving /payload and /payload.sha256 on TCP 8000.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=${L4H_EC2_OUT:-$root/build/ec2}
mkdir -p "$out/work"
out=$(cd "$out" && pwd)
export TMPDIR="$out/work"
export L4H_JOBS=${L4H_JOBS:-6}
"$root/tools/build-kernel.sh" >"$out/kernel-build.log" 2>&1
"$root/tools/build-linux.sh" vmlinux >"$out/linux-build.log" 2>&1
"$root/tools/build-host.sh" >"$out/host-build.log" 2>&1
RUSTFLAGS='-C target-feature=+crt-static' cargo +stable build --locked --release \
    --manifest-path "$root/tools/l4hctl/Cargo.toml"
gcc -O2 -static -pthread -o "$out/selftest" "$root/tests/guest/selftest.c"
"$root/tools/mkinitramfs.sh" "$out/selftest.cpio.gz" "$root/tests/guest/init-ec2-selftest" "$out/selftest"
"$root/tools/mkinitramfs.sh" "$out/disk.cpio.gz" "$root/tests/guest/init-ec2-disk"
"$root/tools/mkinitramfs.sh" "$out/vm.cpio.gz" "$root/tests/guest/init-vm"
"$root/tools/mkinitramfs.sh" "$out/dom0.cpio.gz" "$root/tests/guest/init-ec2" \
    "$root/tools/l4hctl/target/release/l4hctl" "$root/tests/guest/udhcpc.script" \
    "$out/selftest.cpio.gz" "$out/disk.cpio.gz" "$out/vm.cpio.gz"
cat >"$out/l4h.conf" <<CONF
dom0_disks=0
dom0_mem_mb=768
dom0_vcpus=2
dom0_cmdline="console=hvc0${L4H_EC2_PEER:+ ec2_peer=$L4H_EC2_PEER}"
CONF
L4H_GUEST_KMODS= "$root/tools/mkimage.sh" -i "$out/dom0.cpio.gz" \
    -c "$out/l4h.conf" "$out/l4h.raw"
