#!/usr/bin/env python3
"""Exercise two virtio NICs and disks behind VT-d and PCI bridge types.

Requires built kernel/host/guest images, like vtd-qemu.py. With --tap TAP0
TAP1, use existing user-accessible TAPs and vhost-net instead of QEMU user
networking. Both networks must provide a gateway at 10.0.2.2/24.
"""
import argparse
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/vtdtest"


def devices(topology, platform, taps):
    bridge, bus = [], "pcie.0"
    if topology in ("pci", "nested-pci"):
        bridge = ["-device", "i82801b11-bridge,id=pci.1,bus=pcie.0,addr=0x1e"]
        bus = "pci.1"
        if topology == "nested-pci":
            bridge += ["-device", "pci-bridge,id=pci.2,bus=pci.1,addr=2,chassis_nr=2"]
            bus = "pci.2"
    elif topology == "pcie-pci":
        bridge = ["-device", "pcie-root-port,id=rp,addr=5",
                  "-device", "pcie-pci-bridge,id=pci.2,bus=rp"]
        bus = "pci.2"
    for n in range(2):
        backend = f"tap,ifname={taps[n]},script=no,downscript=no,vhost=on" if taps else "user"
        modern = ",disable-legacy=on" if platform == "on" else ""
        bridge += ["-netdev", f"{backend},id=n{n}", "-device",
                   f"virtio-net-pci,netdev=n{n},bus={bus},addr={n + 3},"
                   f"mac=52:54:00:12:34:{n + 1:02x},iommu_platform={platform}{modern}"]
        bridge += ["-drive", f"file={OUT / f'net-disk{n}.raw'},if=none,id=d{n},format=raw",
                   "-device", f"virtio-blk-pci,drive=d{n},bus={bus},addr={n + 5},disable-legacy=on"]
    return bridge


def run(topology, platform, taps, env):
    name = f"net-{topology}-{platform}-{'vhost' if taps else 'user'}"
    log = OUT / f"{name}.log"
    with log.open("w") as output:
        proc = subprocess.Popen([
            str(ROOT / "tools/run-qemu.sh"),
            str(ROOT / "host/target/x86_64-sel4-roottask/debug/l4h-root.elf"),
            *devices(topology, platform, taps),
        ], env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 240
            while proc.poll() is None and time.monotonic() < deadline:
                text = log.read_text(errors="replace")
                if "VTDNET: PASS" in text or "VTDNET: FAIL" in text or "panicked" in text:
                    break
                time.sleep(0.1)
            text = log.read_text(errors="replace")
            assert "VTDNET: PASS" in text, f"{name} failed; see {log}"
            assert "VT-d 0:" not in text, f"IOMMU fault; see {log}"
            print(f"VTDNET: {name} PASS", flush=True)
        finally:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tap", nargs=2, metavar=("TAP0", "TAP1"))
    parser.add_argument("--topology", choices=("root", "pci", "pcie-pci", "nested-pci"))
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    subprocess.run([ROOT / "tools/build-l4hctl.sh"], check=True)
    peer = OUT / "netvm.cpio.gz"
    initrd = OUT / "vtd-net.cpio.gz"
    subprocess.run([ROOT / "tools/mkinitramfs.sh", peer, ROOT / "tests/guest/init-vtd-netvm"], check=True)
    subprocess.run([ROOT / "tools/mkinitramfs.sh", initrd, ROOT / "tests/guest/init-vtd-net",
                    ROOT / "tools/l4hctl/target/release/l4hctl", peer], check=True)
    for n in range(2):
        with (OUT / f"net-disk{n}.raw").open("wb") as disk:
            disk.truncate(16 << 20)
    config = OUT / "net.conf"
    config.write_text("dom0_mem_mb=256\ndom0_disks=0\nwatchdog_secs=0\niommu=1\niommu_intremap=1\n")
    env = dict(os.environ, L4H_QEMU_IOMMU="intel", L4H_MEM="8G", L4H_SMP="4",
               L4H_DOM0_INITRD=str(initrd), L4H_CONFIG=str(config), L4H_GUEST_KMODS="")
    env.setdefault("L4H_GUEST_KERNEL", str(ROOT / "build/linux-l4h/vmlinux.stripped"))
    for topology, platform in [("root", "on"), ("pci", "on"), ("pci", "off"),
                               ("pcie-pci", "on"), ("pcie-pci", "off"),
                               ("nested-pci", "on"), ("nested-pci", "off")]:
        if args.topology is None or topology == args.topology:
            run(topology, platform, args.tap, env)


if __name__ == "__main__":
    main()
