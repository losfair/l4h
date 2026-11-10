#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check boot RAM clearing, untyped watermarks and initial user context.

Requires built debug seL4 and l4h-root, QEMU and GDB. L4H_ARCH=aarch64
also requires the kernel loader and gdb-multiarch. Linux need not boot.
"""
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
from host_profile import root_elf  # noqa: E402
ARCH = os.environ.get("L4H_ARCH", "x86_64")
assert ARCH in ("x86_64", "aarch64"), ARCH
ARM = ARCH == "aarch64"
SUFFIX = "-aarch64" if ARM else ""
KERNEL = ROOT / f"build/kernel{SUFFIX}/kernel.elf"
PREFIX = ROOT / f"build/sel4{SUFFIX}"
APP = root_elf(ARCH)
BASE = 0x60000000 if ARM else 0x20000000
OFFSETS = (0, 0x1FF8, 0x2800)
PATTERN = 0x123456789ABCDEF0


def main():
    # Locate the boot segment so the test can distinguish deferred boot
    # memory from ordinary RAM without assuming the kernel's load address.
    elf = KERNEL.read_bytes()
    assert elf[:6] == b"\x7fELF\x02\x01", "expected a little-endian ELF64 kernel"
    phoff = struct.unpack_from("<Q", elf, 32)[0]
    entsize, count = struct.unpack_from("<HH", elf, 54)
    loads = [struct.unpack_from("<IIQQQQQQ", elf, phoff + i * entsize)
             for i in range(count)]
    loads = [p for p in loads if p[0] == 1]
    boot_pa = min(p[4] for p in loads)
    # x86 also has an identity-mapped entry segment before its high mapping.
    boot = min((p for p in loads if p[3] >= 0xffffff8000000000), key=lambda p: p[4])
    kernel_offset = boot[3] - boot[4]
    root_entry = struct.unpack_from("<Q", APP.read_bytes(), 24)[0]
    # Exercise a user-written TLS register at the very first kernel entry.
    # A remote stall can abandon lock acquisition before the C entry hook,
    # so the saved context must already contain the user's value there.
    tls_probe = """
python
# Keep interrupts masked until this controlled synchronous entry. Replace
# the first two user instructions with MSR TPIDR_EL0,x0 and SVC #0.
inferior.write_memory(int(gdb.parse_and_eval('$pc')), bytes.fromhex('40d01bd5010000d4'))
gdb.execute('set $x0 = 0x12345678')
gdb.execute('set $x7 = 0')
gdb.execute('set $cpsr = $cpsr | 0x80')
end
thbreak *c_handle_syscall
continue
python
tcb = gdb.parse_and_eval('ksSMP[0].system.ksCurThread').dereference()
saved = int(tcb['tcbArch']['tcbContext']['registers'][int(gdb.parse_and_eval('TPIDR_EL0'))])
assert saved == 0x12345678, f'TLS not saved before kernel lock: {saved:#x}'
print('ARM_TLS: user thread pointer saved before kernel lock: PASS')
end
""" if ARM else ""

    with tempfile.TemporaryDirectory(prefix="l4h-bootmem-") as tmp:
        work = Path(tmp)
        shutil.copyfile(APP, work / "root.elf")
        if ARM:
            image = work / "image"
            subprocess.run([
                str(ROOT / "build/loader-target/release/sel4-kernel-loader-add-payload"),
                "--sel4-prefix", str(PREFIX), "--loader",
                str(ROOT / "build/loader-target/aarch64-unknown-none/release/sel4-kernel-loader"),
                "--app", str(work / "root.elf"), "-o", str(image),
            ], check=True)
            memory = (PREFIX / ".l4h-memory-mb").read_text().strip()
            assert int(memory) >= 1024, "test needs at least 1 GiB of ARM RAM"
            command = ["qemu-system-aarch64", "-machine",
                       "virt,virtualization=off,secure=off,gic-version=2,highmem-ecam=off,highmem-mmio=off",
                       "-accel", "tcg", "-cpu", "cortex-a57", "-m", memory,
                       "-kernel", str(image)]
        else:
            image = work / "kernel32.elf"
            subprocess.run(["objcopy", "-O", "elf32-i386", str(KERNEL), str(image)], check=True)
            command = ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host,-vmx,-svm,+invtsc",
                       "-m", "1G", "-kernel", str(image), "-initrd", str(work / "root.elf")]

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        command += ["-smp", "4" if ARM else "1", "-display", "none", "-monitor", "none", "-serial", "stdio",
                    "-no-reboot", "-S", "-gdb", f"tcp:127.0.0.1:{port}"]
        for offset in OFFSETS:
            command += ["-device", f"loader,addr={BASE + offset:#x},data={PATTERN:#x},data-len=8"]

        script = work / "check.gdb"
        script.write_text(f"""set pagination off
set confirm off
set tcp auto-retry on
set tcp connect-timeout 15
target remote 127.0.0.1:{port}
thbreak create_untypeds
continue
python
import gdb
base = 0xffffff8000000000 + {BASE}
inferior = gdb.selected_inferior()
for offset in {OFFSETS!r}:
    assert int.from_bytes(inferior.read_memory(base + offset, 8), 'little') == {PATTERN}, 'missing boot poison'
end
thbreak bi_finalise
continue
python
assert not any(bytes(inferior.read_memory(base, 3 * 4096))), 'boot RAM was not cleared'
boot_end = int(gdb.parse_and_eval('(unsigned long)&ki_boot_end')) - {kernel_offset}
bi = gdb.parse_and_eval('ndks_boot.bi_frame').dereference()
slots = gdb.parse_and_eval('(cte_t *)rootserver.cnode')
first = int(bi['untyped']['start'])
counts = [0, 0, 0]
poison_cap = False
for i in range(int(bi['untyped']['end']) - first):
    desc = bi['untypedList'][i]
    pa, bits, device = int(desc['paddr']), int(desc['sizeBits']), bool(desc['isDevice'])
    recycled = not device and pa < boot_end and pa + (1 << bits) > {boot_pa}
    # seL4's 64-bit untyped layout: words[1] bits 63:16 are capFreeIndex.
    free_index = int(slots[first + i]['cap']['words'][1]) >> 16
    expected = (1 << (bits - 4)) if device or recycled else 0
    assert free_index == expected, f'wrong watermark at {{pa:#x}}: {{free_index:#x}} != {{expected:#x}}'
    counts[0 if device else 1 if recycled else 2] += 1
    if not device and pa <= {BASE} and {BASE} + 3 * 4096 <= pa + (1 << bits):
        assert not recycled
        poison_cap = True
assert all(counts) and poison_cap, (counts, poison_cap)
end
# Continue past secondary-CPU startup: the loader's page tables must stay
# valid until every CPU has switched to the kernel's own tables.
thbreak *{root_entry:#x}
continue
python
assert int(gdb.parse_and_eval('$pc')) == {root_entry}, 'root task did not start'
print('BOOTMEM: dirty RAM cleared; device and live boot memory deferred; first-use watermarks; root-task entry: PASS')
end
{tls_probe}
detach
quit
""")
        log = ROOT / f"build/bootmem-{ARCH}"
        with log.with_suffix(".serial.log").open("w") as output:
            proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output)
            try:
                with log.with_suffix(".gdb.log").open("w") as debug_output:
                    result = subprocess.run([
                        "gdb-multiarch" if ARM else "gdb", "-q", "-batch", "-x", str(script), str(KERNEL)
                    ], stdout=debug_output, stderr=subprocess.STDOUT, text=True, timeout=120)
                debug_log = log.with_suffix(".gdb.log").read_text()
                assert result.returncode == 0 and "BOOTMEM:" in debug_log, debug_log
                for line in debug_log.splitlines():
                    if line.startswith(("BOOTMEM:", "ARM_TLS:")):
                        print(line)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    main()
