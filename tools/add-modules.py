#!/usr/bin/env python3
"""Append named files to a built l4h-root ELF, for root to read at boot.

Usage: add-modules.py IN.elf OUT.elf NAME=FILE...
e.g.   add-modules.py l4h-root.elf root-dom0.elf guest-kernel=vmlinux \\
           guest-sdk=sdk.erofs dom0-initrd=dom0.cpio.gz l4h-config=l4h.conf

The files become one more loadable segment, right after root's last one, so
seL4 (x86_64) or the kernel loader (aarch64) maps them with the rest of
root.  Its program header replaces PT_GNU_STACK, which seL4 ignores, and its
address and size go into root's anchor (host/l4h-root/src/bootmod.rs).
Modules from the boot loader override appended ones of the same name.
Strip the ELF first if you want to: stripping afterwards may drop the
segment.
"""
import struct
import sys

ANCHOR_MAGIC = b"l4h-modules-v1\0\0"
TABLE_MAGIC = b"L4HMODS1"
NAME_LEN = 64
PAGE = 4096
PT_LOAD = 1
PT_GNU_STACK = 0x6474E551
PF_R = 4
MACHINES = {62: "x86_64", 183: "aarch64"}


def align(n, a):
    return (n + a - 1) // a * a


def main(argv):
    if len(argv) < 4:
        sys.exit(__doc__.strip())
    src, dst, specs = argv[1], argv[2], argv[3:]
    elf = bytearray(open(src, "rb").read())
    if elf[:4] != b"\x7fELF" or elf[4] != 2 or elf[5] != 1:
        sys.exit(f"{src}: not a 64-bit little-endian ELF")
    machine = struct.unpack_from("<H", elf, 18)[0]
    if machine not in MACHINES:
        sys.exit(f"{src}: unsupported machine {machine}")
    phoff, = struct.unpack_from("<Q", elf, 32)
    phentsize, phnum = struct.unpack_from("<HH", elf, 54)

    def phdr(i):
        # p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
        return list(struct.unpack_from("<IIQQQQQQ", elf, phoff + i * phentsize))

    phdrs = [phdr(i) for i in range(phnum)]
    stack = [i for i, p in enumerate(phdrs) if p[0] == PT_GNU_STACK]
    if not stack:
        sys.exit(f"{src}: no PT_GNU_STACK program header to reuse")
    end = max(p[3] + p[6] for p in phdrs if p[0] == PT_LOAD)

    at = elf.find(ANCHOR_MAGIC)
    if at < 0 or elf.find(ANCHOR_MAGIC, at + 1) >= 0:
        sys.exit(f"{src}: no single l4h-root module anchor (not an l4h-root ELF?)")
    va, size = struct.unpack_from("<QQ", elf, at + 16)
    if va or size:
        sys.exit(f"{src}: already has modules; start from the ELF tools/build-host.sh built")

    files = []
    for spec in specs:
        name, sep, path = spec.partition("=")
        if not sep or not name or len(name.encode()) >= NAME_LEN:
            sys.exit(f"bad module {spec!r}: want NAME=FILE, NAME under {NAME_LEN} bytes")
        files.append((name.encode(), open(path, "rb").read()))

    # The segment: header, entries, then each file page-aligned.
    table = TABLE_MAGIC + struct.pack("<Q", len(files))
    off = align(len(table) + len(files) * (NAME_LEN + 16), PAGE)
    entries, body = b"", b""
    for name, data in files:
        entries += name.ljust(NAME_LEN, b"\0") + struct.pack("<QQ", off, len(data))
        body += data.ljust(align(len(data), PAGE), b"\0")
        off += align(len(data), PAGE)
    seg = (table + entries).ljust(align(len(table) + len(entries), PAGE), b"\0") + body

    seg_va = align(end, PAGE)
    seg_off = align(len(elf), PAGE)
    elf += b"\0" * (seg_off - len(elf)) + seg
    struct.pack_into("<IIQQQQQQ", elf, phoff + stack[0] * phentsize,
                     PT_LOAD, PF_R, seg_off, seg_va, seg_va, len(seg), len(seg), PAGE)
    struct.pack_into("<QQ", elf, at + 16, seg_va, len(seg))
    open(dst, "wb").write(elf)
    names = ", ".join(n.decode() for n, _ in files)
    print(f"{dst}: {MACHINES[machine]}, {len(seg) >> 10} KiB of modules at {seg_va:#x} ({names})")


if __name__ == "__main__":
    main(sys.argv)
