#!/usr/bin/env python3
"""Check shared AMD-Vi tables and reject DMA/MSIs from emulated EDU devices.

QEMU's AMD-Vi does not log every blocked request, so check scratch RAM
and interrupt-abort traces directly. Uses the unmodified root task.
"""
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/amdvitest"
Qtest = runpy.run_path(str(ROOT / "tests/vtd-qemu.py"))["Qtest"]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    log = OUT / "isolation.log"
    initrd = OUT / "isolation.cpio.gz"
    subprocess.run([ROOT / "tools/mkinitramfs.sh", initrd, ROOT / "tests/guest/init-vtd"], check=True)
    config = OUT / "isolation.conf"
    config.write_text("dom0_mem_mb=128\ndom0_disks=0\nwatchdog_secs=0\niommu=1\niommu_intremap=1\n")
    env = dict(os.environ, L4H_QEMU_IOMMU="amd", L4H_DOM0_INITRD=str(initrd),
               L4H_CONFIG=str(config), L4H_GUEST_KMODS="")
    env.setdefault("L4H_GUEST_KERNEL", str(ROOT / "build/linux-l4h/vmlinux.stripped"))
    devices = ["-device", "i82801b11-bridge,id=br,bus=pcie.0,addr=0x1e",
               "-device", "edu,addr=7,dma_mask=0xffffffffffffffff",
               "-device", "edu,bus=br,addr=7,dma_mask=0xffffffffffffffff"]
    for n in range(2):
        disk = OUT / f"isolation{n}.raw"
        with disk.open("wb") as f:
            f.truncate(16 << 20)
        devices += ["-drive", f"file={disk},if=none,id=d{n},format=raw", "-device",
                    f"virtio-blk-pci,drive=d{n},bus=br,addr={5 + n},disable-legacy=on",
                    "-netdev", f"user,id=n{n}", "-device",
                    f"virtio-net-pci,netdev=n{n},bus=br,addr={3 + n},disable-legacy=on",
                    ]

    def wait_for(predicate, what, timeout=15):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(0.02)
        raise AssertionError(f"timeout: {what}; see {log}")

    with tempfile.TemporaryDirectory(prefix="l4h-amdvi-") as tmp, log.open("w") as output:
        sock = Path(tmp) / "qtest.sock"
        proc = subprocess.Popen([
            ROOT / "tools/run-qemu.sh",
            ROOT / "host/target/x86_64-sel4-roottask/debug/l4h-root.elf",
            "-qtest", f"unix:{sock},server=on,wait=off", "-qtest-log", "/dev/null",
            "-trace", "enable=amdvi_ir_target_abort", *devices,
        ], env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        try:
            wait_for(lambda: "VTDTEST: ready" in log.read_text(), "guest boot", 120)
            q = Qtest(sock)
            read64 = lambda addr: q.command(f"readq {addr:#x}")
            devtab = read64(0xfed80000) & 0x000fffffffff_f000
            dte = lambda sid: tuple(read64(devtab + 32 * sid + 8 * i) for i in range(3))
            group = dte(0xf0)
            for sid in [0x118, 0x120, 0x128, 0x130]:
                assert dte(sid) == group, f"{sid:#x} replaced the shared domain/interrupt table"
            assert (group[0] >> 9) & 7 == 4, "missing DMA domain"
            assert (group[2] >> 60) & 3 == 2, "interrupt remapping disabled"
            assert (group[2] >> 1) & 15 == 8, "shared interrupt table is too small"
            irt = group[2] & 0x000fffffffff_f000
            vectors = [q.read(irt + 4 * i) for i in range(256)]
            assert sum(bool(v & 1) for v in vectors) == 4, "sibling vectors were lost"
            assert len({v >> 16 & 255 for v in vectors if v & 1}) == 4
            print("AMDVITEST: siblings share DMA and interrupt tables PASS", flush=True)

            scratch = 0x50000  # unused low RAM, below seL4/root's images
            for bus, reason in [(0, "int_ctl abort"), (1, "RemapEn is disabled")]:
                assert q.config(7, 0, bus=bus) == 0x11e81234
                bar = q.config(7, 0x10, bus=bus) & ~15
                assert bar
                q.config(7, 4, (q.config(7, 4, bus=bus) & 0xffff) | 0x406, bus=bus)
                q.write(scratch, 0xa55a5aa5)
                q.write(bar + 0x80, 0x40000)
                q.write(bar + 0x88, scratch)
                q.write(bar + 0x90, 4)
                q.write(bar + 0x98, 3)
                wait_for(lambda: q.read(bar + 0x98) & 1 == 0, "EDU DMA completion")
                assert q.read(scratch) == 0xa55a5aa5, f"EDU on bus {bus} wrote outside its domain"

                cap = q.config(7, 0x34, bus=bus) & 255
                for _ in range(48):
                    header = q.config(7, cap, bus=bus)
                    if header & 255 == 5:
                        break
                    cap = header >> 8 & 255
                    assert cap, "EDU has no MSI capability"
                else:
                    raise AssertionError("invalid EDU capability chain")
                data_offset = cap + (12 if header & (1 << 23) else 8)
                if data_offset == cap + 12:
                    q.config(7, cap + 8, 0, bus=bus)
                q.config(7, cap, header | (1 << 16), bus=bus)
                q.config(7, cap + 4, 0xfee00000, bus=bus)
                # Another requester cannot use the group's index 0. A
                # group member cannot use its unallocated index 255.
                q.config(7, data_offset, 255 if bus else 0, bus=bus)
                q.write(bar + 0x60, 1)
                wait_for(lambda: reason in log.read_text(), "MSI rejection")
                q.write(bar + 0x64, 1)
            q.file.close()
            q.sock.close()
            assert "panicked" not in log.read_text()
            print("AMDVITEST: DMA and interrupt isolation PASS", flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    main()
