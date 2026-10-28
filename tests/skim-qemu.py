#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check SKIM mappings and syscall state at the actual user/kernel boundary.

Requires a built debug SKIM kernel, l4h-root, QEMU/KVM and GDB. The root
task's first instructions are replaced in this disposable VM; Linux need
not boot. This checks architectural isolation, not speculative leakage.
"""
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VARIANT = os.environ.get("L4H_KERNEL_VARIANT", "skim-xapic-nopcid")
KERNEL = ROOT / f"build/sel4-{VARIANT}/bin/kernel.elf"
APP = ROOT / "host/target/x86_64-sel4-roottask/debug/l4h-root.elf"
CPU = os.environ.get("L4H_QEMU_CPU", "host,vendor=GenuineIntel,-vmx,+invtsc,-arch-capabilities,-pcid,-invpcid,-x2apic")


def main():
    entry = struct.unpack_from("<Q", APP.read_bytes(), 24)[0]
    with tempfile.TemporaryDirectory(prefix="l4h-skim-") as tmp:
        work = Path(tmp)
        image = work / "kernel32.elf"
        subprocess.run(["objcopy", "-O", "elf32-i386", str(KERNEL), str(image)], check=True)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        script = work / "check.gdb"
        script.write_text(f"""set pagination off
set confirm off
set tcp auto-retry on
set tcp connect-timeout 15
target remote 127.0.0.1:{port}
thbreak *{entry:#x}
continue
python
import gdb
inf = gdb.selected_inferior()
def value(expr):
    return int(gdb.parse_and_eval(expr))
def address(symbol):
    return value('(unsigned long)&' + symbol)
skim_start, skim_end = address('ki_skim_start'), address('ki_skim_end')
try:
    scratch = address('nodeSkimScratch')
    tcb_expr = 'ksSMP[0].system.ksCurThread'
except gdb.error:
    scratch = address('x64KSSyscallUserRSP')
    tcb_expr = 'ksCurThread'
user_cr3 = value('$cr3')

def isolated():
    # Inspect physical page tables, including every high-half mapping.
    # A supervisor-only mapping is still readable through Meltdown.
    reply = gdb.execute('maintenance packet Qqemu.PhyMemMode:1', to_string=True)
    assert 'OK' in reply, reply
    leaves = []
    def walk(table, level, va):
        data = bytes(inf.read_memory(table, 4096))
        for i in range(256 if level == 4 else 0, 512):
            pte = int.from_bytes(data[i * 8:i * 8 + 8], 'little')
            if not pte & 1:
                continue
            size = 1 << (12 + 9 * (level - 1))
            base = va | (i * size)
            if level == 4:
                base |= 0xffff000000000000
            if level == 1 or pte & 128:
                assert skim_start <= base and base + size <= skim_end, f'exposed kernel mapping {{base:#x}} + {{size:#x}}'
                assert not pte & 4, f'user-accessible SKIM mapping {{base:#x}}'
                leaves.append((base, size))
            else:
                walk(pte & 0x000ffffffffff000, level - 1, base)
    try:
        walk(value('$cr3') & 0x000ffffffffff000, 4, 0)
    finally:
        gdb.execute('maintenance packet Qqemu.PhyMemMode:0', to_string=True)
    assert leaves and sum(size for _, size in leaves) == skim_end - skim_start, leaves
    assert bytes(inf.read_memory(scratch, 8)) == bytes(8), 'stale SKIM scratch'

assert value('$pc') == {entry}, 'root task did not reach user mode'
isolated()  # initial IRET return also clears its RCX scratch
# A raw syscall with an unmapped stack and no libsel4 RSP-in-RBX convention.
inf.write_memory({entry}, bytes.fromhex('0f05ebfe'))
gdb.execute('set $rsp = 0x7f0000000007')
gdb.execute('set $rbx = 0x123456789')
gdb.execute('set $r12 = 0x987654321')
gdb.execute('set $gs_base = 0x12345000')
gdb.execute('set $rdx = (long)SysYield')
end
thbreak *c_handle_syscall
continue
python
tcb = gdb.parse_and_eval(tcb_expr).dereference()
regs = tcb['tcbArch']['tcbContext']['registers']
assert int(regs[value('RSP')]) == 0x7f0000000007, 'entry lost RSP'
assert value('$cr3') != user_cr3, 'entry retained user page tables'
assert bytes(inf.read_memory(scratch, 8)) == bytes(8), 'entry left scratch'
# Stop immediately before SYSRET, after the user CR3 and registers are restored.
start = address('restore_user_context')
insns = gdb.selected_frame().architecture().disassemble(start, count=400)
sysret = next(i['addr'] for i in insns if i['asm'].startswith('sysret'))
gdb.Breakpoint('*' + hex(sysret), type=gdb.BP_HARDWARE_BREAKPOINT, temporary=True)
end
continue
python
assert value('$cr3') == user_cr3, 'return retained kernel page tables'
assert value('$rsp') == 0x7f0000000007, 'return lost RSP'
assert value('$rbx') == 0x123456789 and value('$r12') == 0x987654321, 'return lost registers'
assert value('$gs_base') == 0x12345000, 'return lost user GS'
isolated()
end
thbreak *{entry + 2:#x}
continue
python
assert value('$pc') == {entry + 2} and value('$cs') & 3 == 3, 'SYSRET did not reach user mode'
assert value('$rsp') == 0x7f0000000007, 'SYSRET changed RSP'
print('SKIM: isolated mappings, cleared scratch, raw syscall RSP/registers/GS: PASS')
end
detach
quit
""")
        command = ["qemu-system-x86_64", "-enable-kvm", "-cpu", CPU, "-m", "1G", "-smp", "1",
                   "-kernel", str(image), "-initrd", str(APP), "-display", "none", "-monitor", "none",
                   "-serial", "stdio", "-no-reboot", "-S", "-gdb", f"tcp:127.0.0.1:{port}"]
        log = ROOT / f"build/skim-{VARIANT}"
        with log.with_suffix(".serial.log").open("w") as output:
            proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output)
            try:
                with log.with_suffix(".gdb.log").open("w") as output:
                    result = subprocess.run(["gdb", "-q", "-batch", "-x", str(script), str(KERNEL)],
                                            stdout=output, stderr=subprocess.STDOUT, timeout=120)
                debug = log.with_suffix(".gdb.log").read_text()
                assert result.returncode == 0 and "SKIM:" in debug, debug
                print(next(line for line in debug.splitlines() if line.startswith("SKIM:")))
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    main()
