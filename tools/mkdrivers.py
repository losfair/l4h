#!/usr/bin/env python3
"""Pack NIC driver images and firmware blobs into a driver bundle
(host/l4h-root/src/drivers.rs): the l4h-drivers boot module, which root
also has built in.

Usage: mkdrivers.py OUT DRIVER.elf... [--firmware NAME=FILE]...
"""
import struct
import sys

MAGIC = b"L4HDRVS1"
NAME = 48
KIND_DRIVER, KIND_FIRMWARE = 1, 2
ALIGN = 4096


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    out, rest = argv[0], argv[1:]
    entries = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--firmware":
            name, path = rest[i + 1].split("=", 1)
            entries.append((name, KIND_FIRMWARE, open(path, "rb").read()))
            i += 2
            continue
        data = open(a, "rb").read()
        entries.append((a.rsplit("/", 1)[-1], KIND_DRIVER, data))
        i += 1
    for name, _, _ in entries:
        if len(name.encode()) >= NAME:
            sys.exit(f"mkdrivers: name too long: {name}")
    toc = 16 + len(entries) * (NAME + 24)
    offset = (toc + ALIGN - 1) // ALIGN * ALIGN
    header = MAGIC + struct.pack("<II", len(entries), 0)
    table, blobs = b"", b""
    for name, kind, data in entries:
        table += name.encode().ljust(NAME, b"\0") + struct.pack("<IIQQ", kind, 0, offset + len(blobs), len(data))
        blobs += data + b"\0" * (-len(data) % ALIGN)
    with open(out, "wb") as f:
        f.write(header + table + b"\0" * (offset - toc) + blobs)


if __name__ == "__main__":
    main(sys.argv[1:])
