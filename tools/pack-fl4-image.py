#!/usr/bin/env python3
"""Pack l4h-fl4-image.bin, FL4 kernel.elf, and root-dom0.elf into an ARM64
Linux `Image` bootable by QEMU `-kernel` and Apple `VZLinuxBootLoader`.

Layout:
  [0 .. stub_len)            : l4h-fl4-image.bin (4 KiB aligned, image_size patched at 0x10)
  [stub_len .. stub_len+56)  : FL4IMG01 trailer header
  [kernel_off .. +kernel_len): raw FL4 kernel.elf (4 KiB aligned)
  [root_off   .. +root_len)  : raw root-dom0.elf (4 KiB aligned, verbatim once)
  --- end of file ---
  [unpack_off .. +unpack_len): NOLOAD unpack arena in RAM (2 MiB aligned),
                               covered by header image_size = unpack_off + unpack_len.

Usage: pack-fl4-image.py <stub.bin> <kernel.elf> <root-dom0.elf> <out.Image>
"""
import pathlib
import struct
import sys

PAGE = 4096
MB2 = 2 << 20
ARM64_MAGIC = 0x644D5241
TRAILER_MAGIC = b"FL4IMG01"
TRAILER_FMT = "<8s6Q"


def align_up(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def elf_load_span(data: bytes, path: str) -> int:
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError(f"{path}: not a 64-bit little-endian ELF")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize = struct.unpack_from("<H", data, 54)[0]
    phnum = struct.unpack_from("<H", data, 56)[0]
    lo = None
    hi = 0
    for i in range(phnum):
        off = phoff + i * phentsize
        p_type, _, _, p_vaddr, _, _, p_memsz = struct.unpack_from("<IIQQQQQ", data, off)
        if p_type == 1 and p_memsz > 0:
            lo = p_vaddr if lo is None else min(lo, p_vaddr)
            hi = max(hi, p_vaddr + p_memsz)
    if lo is None:
        raise ValueError(f"{path}: no PT_LOAD segments")
    lo &= ~(PAGE - 1)
    hi = align_up(hi, PAGE)
    return hi - lo


def main() -> int:
    if len(sys.argv) != 5:
        print("usage: pack-fl4-image.py <stub.bin> <kernel.elf> <root-dom0.elf> <out.Image>", file=sys.stderr)
        return 2

    stub_path, kernel_path, root_path, out_path = sys.argv[1:5]
    stub = bytearray(pathlib.Path(stub_path).read_bytes())
    kernel = pathlib.Path(kernel_path).read_bytes()
    root = pathlib.Path(root_path).read_bytes()

    if len(stub) < 64 or len(stub) % PAGE != 0:
        raise ValueError(f"{stub_path}: size {len(stub)} must be a non-zero multiple of {PAGE}")
    magic = struct.unpack_from("<I", stub, 0x38)[0]
    if magic != ARM64_MAGIC:
        raise ValueError(f"{stub_path}: bad ARM64 Image magic {magic:#x}")

    trailer_off = len(stub)
    trailer_size = struct.calcsize(TRAILER_FMT)
    kernel_off = align_up(trailer_off + trailer_size, PAGE)
    root_off = align_up(kernel_off + len(kernel), PAGE)
    file_end = align_up(root_off + len(root), PAGE)

    k_span = elf_load_span(kernel, kernel_path)
    r_span = elf_load_span(root, root_path)
    k_region = align_up(k_span + 16 * PAGE, MB2)
    unpack_off = align_up(file_end, MB2)
    unpack_len = align_up(k_region + r_span + MB2, MB2)
    image_size = unpack_off + unpack_len

    # Patch ARM64 Linux Image header image_size at offset 0x10.
    struct.pack_into("<Q", stub, 0x10, image_size)

    trailer = struct.pack(
        TRAILER_FMT,
        TRAILER_MAGIC,
        kernel_off,
        len(kernel),
        root_off,
        len(root),
        unpack_off,
        unpack_len,
    )

    out = bytearray(file_end)
    out[0 : len(stub)] = stub
    out[trailer_off : trailer_off + trailer_size] = trailer
    out[kernel_off : kernel_off + len(kernel)] = kernel
    out[root_off : root_off + len(root)] = root

    pathlib.Path(out_path).write_bytes(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
