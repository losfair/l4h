#!/usr/bin/env python3
"""Inject DMA and forged MSIs from an unattached EDU device through VT-d.

Uses QEMU's qtest transport to program the device, without adding test
hooks to root. The normal root task must block and log every request.
QEMU 10 passes compatibility MSIs through regardless of CFIS, so only
the disable bit's programming can be checked for that interrupt format.
EDU registers: https://www.qemu.org/docs/master/specs/edu.html
"""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/vtdtest"


def wait_for(predicate, description, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError(f"timeout: {description}; see {OUT / 'isolation.log'}")


class Qtest:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(str(path))
        self.file = self.sock.makefile("rwb", buffering=0)

    def command(self, command):
        self.file.write((command + "\n").encode())
        while True:
            line = self.file.readline().decode().strip()
            if line.startswith("IRQ"):
                continue
            assert line.startswith("OK"), (command, line)
            return int(line.split()[1], 0) if len(line.split()) > 1 else None

    def read(self, addr):
        return self.command(f"readl {addr:#x}")

    def write(self, addr, value):
        self.command(f"writel {addr:#x} {value:#x}")

    def config(self, dev, off, value=None, bus=0):
        self.command(f"outl 0xcf8 {0x80000000 | bus << 16 | dev << 11 | (off & ~3):#x}")
        if value is not None:
            self.command(f"outl 0xcfc {value:#x}")
        else:
            return self.command("inl 0xcfc")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge", choices=("pci", "pcie-pci"))
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    initrd = OUT / "isolation.cpio.gz"
    subprocess.run([ROOT / "tools/mkinitramfs.sh", initrd, ROOT / "tests/guest/init-vtd"], check=True)
    disk = OUT / "isolation.img"
    with disk.open("wb") as f:
        f.truncate(16 << 20)
    config = OUT / "isolation.conf"
    config.write_text("dom0_mem_mb=128\ndom0_vcpus=1\nwatchdog_secs=0\niommu=1\niommu_intremap=1\n")
    env = dict(os.environ, L4H_QEMU_IOMMU="intel", L4H_DOM0_INITRD=str(initrd), L4H_CONFIG=str(config))
    env.setdefault("L4H_GUEST_KERNEL", str(ROOT / "build/linux-l4h/vmlinux.stripped"))
    log = OUT / (f"isolation-{args.bridge}.log" if args.bridge else "isolation.log")
    bridges = []
    disk_bus = "pcie.0"
    if args.bridge == "pci":
        bridges = ["-device", "i82801b11-bridge,id=br,bus=pcie.0,addr=0x1e"]
        disk_bus, alias, secondary = "br", "00:1e.0", 1
    elif args.bridge == "pcie-pci":
        bridges = ["-device", "pcie-root-port,id=rp,addr=8", "-device", "pcie-pci-bridge,id=br,bus=rp"]
        disk_bus, alias, secondary = "br", "02:00.0", 2
    if args.bridge:
        bridges += ["-device", "edu,bus=br,addr=6,dma_mask=0xffffffffffffffff"]
    with tempfile.TemporaryDirectory(prefix="l4h-vtd-") as tmp, log.open("w") as output:
        sock = Path(tmp) / "qtest.sock"
        command = [str(ROOT / "tools/run-qemu.sh"),
            str(ROOT / "host/target/x86_64-sel4-roottask/debug/l4h-root.elf"),
            "-qtest", f"unix:{sock},server=on,wait=off", "-qtest-log", "/dev/null",
            *bridges,
            "-drive", f"file={disk},if=none,id=vtdtest,format=raw",
            "-device", f"virtio-blk-pci,drive=vtdtest,disable-legacy=on,addr=5,bus={disk_bus}",
            "-device", "edu,addr=6,dma_mask=0xffffffffffffffff"]
        proc = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        try:
            wait_for(lambda: "VTDTEST: ready" in log.read_text(), "guest boot", 120)
            # Component startup messages can interleave on the serial
            # console. Check remapping via the hardware registers below.
            q = Qtest(sock)
            fault_counts = {}
            def fault(reason, name, requester="00:06.0"):
                key = (requester, reason)
                fault_counts[key] = fault_counts.get(key, 0) + 1
                wait_for(lambda: log.read_text().count(f"{requester}: fault {reason:#x},") >= fault_counts[key], name)
                # Root prints before clearing F. Injecting the next fault
                # in that interval would legitimately be compressed away.
                wait_for(lambda: q.read(0xfed90034) & 2 == 0, "fault acknowledgement")

            assert q.config(6, 0) == 0x11e81234
            # The UART's I/O APIC pin must carry a remapping handle,
            # with compatibility interrupts still globally disabled.
            q.write(0xfec00000, 0x10 + 4 * 2)
            rte_low = q.read(0xfec00010)
            q.write(0xfec00000, 0x11 + 4 * 2)
            rte_high = q.read(0xfec00010)
            assert rte_high & (1 << 16), "UART I/O APIC entry is not remappable"
            assert rte_low & 255 == 0x38, "UART vector does not match the IRTE"
            assert rte_low & ((1 << 16) | (1 << 15) | (7 << 8)) == 0, "UART is masked or not fixed/edge"
            uart_index = (rte_high >> 17) | ((rte_low >> 11 & 1) << 15)
            bar = q.config(6, 0x10) & ~15
            assert bar != 0
            q.config(6, 4, (q.config(6, 4) & 0xffff) | 0x406)  # memory, master, INTx off

            # A requester with no context cannot overwrite even one DWORD.
            # Scratch RAM is below seL4/root's images and unused after boot.
            scratch = 0x50000
            q.write(scratch, 0xa55a5aa5)
            q.write(bar + 0x80, 0x40000)  # EDU's internal (zeroed) buffer
            q.write(bar + 0x88, scratch)
            q.write(bar + 0x90, 4)
            q.write(bar + 0x98, 3)  # start, device -> RAM
            wait_for(lambda: q.read(bar + 0x98) & 1 == 0, "EDU DMA completion")
            assert q.read(scratch) == 0xa55a5aa5, "unattached device overwrote RAM"
            fault(0x2, "DMA context fault")
            print("VTDTEST: unattached DMA blocked", flush=True)

            if args.bridge:
                # This EDU shares the disk's requester, so its context is
                # present. It still cannot write outside the group's pool.
                assert q.config(6, 0, bus=secondary) == 0x11e81234
                shared_bar = q.config(6, 0x10, bus=secondary) & ~15
                assert shared_bar != 0
                q.config(6, 4, (q.config(6, 4, bus=secondary) & 0xffff) | 0x406, bus=secondary)
                q.write(shared_bar + 0x80, 0x40000)
                q.write(shared_bar + 0x88, scratch)
                q.write(shared_bar + 0x90, 4)
                q.write(shared_bar + 0x98, 3)
                wait_for(lambda: q.read(shared_bar + 0x98) & 1 == 0, "shared requester DMA completion")
                assert q.read(scratch) == 0xa55a5aa5, "shared requester wrote outside its domain"
                fault(0x5, "shared requester DMA write fault", alias)
                print("VTDTEST: shared requester DMA remains confined", flush=True)

            cap = q.config(6, 0x34) & 255
            for _ in range(48):
                header = q.config(6, cap)
                if header & 255 == 5:
                    break
                cap = header >> 8 & 255
                assert cap != 0, "EDU has no MSI capability"
            else:
                raise AssertionError("invalid EDU capability chain")
            data_offset = cap + (12 if header & (1 << 23) else 8)
            if data_offset == cap + 12:
                q.config(6, cap + 8, 0)
            q.config(6, cap, header | (1 << 16))  # MSI enable

            # Entry zero belongs to the disk's requester (its bridge alias
            # when present). Another requester cannot use even a valid entry.
            for address, data, reason, name in [
                (0xfee00010, 0, 0x26, "another device's IRTE"),
                (0xfee00010 | ((uart_index & 0x7fff) << 5) | ((uart_index >> 15) << 2),
                 0, 0x26, "UART I/O APIC's IRTE"),
                (0xfee01ff0, 0, 0x22, "absent IRTE"),
            ]:
                q.config(6, cap + 4, address)
                q.config(6, data_offset, data)
                q.write(bar + 0x60, 1)
                fault(reason, name)
                q.write(bar + 0x64, 1)
                print(f"VTDTEST: {name} blocked", flush=True)
            status = q.read(0xfed9001c)
            assert status & (1 << 25), "interrupt remapping is not enabled"
            assert status & (1 << 23) == 0, "compatibility interrupts are enabled"
            print("VTDTEST: CFIS=0 checked; QEMU does not enforce compatibility blocking", flush=True)
            q.file.close()
            q.sock.close()
            assert "panicked" not in log.read_text()
            print("VTDTEST: isolation PASS", flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    main()
