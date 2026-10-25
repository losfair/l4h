#!/usr/bin/env python3
"""Take apart the images of an Android build, for tools/mkandroid.sh.

Usage: android-image.py size IMG
       android-image.py unsparse IMG OUT OFFSET
       android-image.py lp-offset FILE OFFSET NAME
       android-image.py ramdisk BOOT.img OUT        (boot or init_boot)
       android-image.py vendor-boot VENDOR_BOOT.img OUTDIR

size prints the size of the raw image of IMG, an Android sparse image or
a raw one.  unsparse writes that raw image into the file OUT at byte
OFFSET, leaving its blocks of zeros unwritten.  lp-offset prints the byte
offset in FILE of the logical partition NAME of the raw super image at
byte OFFSET of FILE (liblp's format, the first metadata slot), which must
be one extent.  ramdisk writes the ramdisk
of a boot image (header version 3 or 4).  vendor-boot writes the vendor
ramdisks, concatenated, to OUTDIR/ramdisk, the bootconfig to
OUTDIR/bootconfig and the kernel command line to OUTDIR/cmdline.
"""
import os
import struct
import sys

SPARSE_MAGIC = 0xED26FF3A
CHUNK_RAW, CHUNK_FILL, CHUNK_DONT_CARE, CHUNK_CRC32 = 0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4
BOOT_PAGE = 4096  # Fixed for boot image header versions 3 and 4.
LP_GEOMETRY_MAGIC, LP_METADATA_MAGIC = 0x616C4467, 0x414C5030
LP_GEOMETRY_SIZE = 4096  # At 4096, after the reserved first 4 KiB, and again after it.


def pages(n, page):
    return (n + page - 1) // page * page


def sparse_header(f):
    hdr = f.read(28)
    if len(hdr) < 28 or struct.unpack_from("<I", hdr)[0] != SPARSE_MAGIC:
        return None
    return struct.unpack("<IHHHHIIII", hdr)


def size(src):
    with open(src, "rb") as f:
        hdr = sparse_header(f)
    print(hdr[5] * hdr[6] if hdr else os.path.getsize(src))


def copy_nonzero(f, out, pos, left):
    """Copy left bytes from f to out at pos, skipping blocks of zeros."""
    while left:
        buf = f.read(min(left, 1 << 20))
        if not buf:
            sys.exit("unexpected end of image")
        for i in range(0, len(buf), 4096):
            b = buf[i:i + 4096]
            if b.count(0) != len(b):
                out.seek(pos + i)
                out.write(b)
        pos += len(buf)
        left -= len(buf)


def unsparse(src, dst, offset):
    with open(src, "rb") as f, open(dst, "r+b") as out:
        hdr = sparse_header(f)
        if not hdr:
            f.seek(0)
            copy_nonzero(f, out, offset, os.path.getsize(src))
            return
        _magic, _major, _minor, fhdr, chdr, blk, _total, nchunks, _crc = hdr
        f.seek(fhdr)
        pos = offset
        for _ in range(nchunks):
            ctype, _res, nblk, size = struct.unpack("<HHII", f.read(12))
            f.seek(chdr - 12, os.SEEK_CUR)
            body = size - chdr
            if ctype == CHUNK_RAW:
                copy_nonzero(f, out, pos, body)
            elif ctype == CHUNK_FILL:
                fill = f.read(4)
                if fill != b"\0\0\0\0":
                    out.seek(pos)
                    out.write(fill * (nblk * blk // 4))
            elif ctype in (CHUNK_DONT_CARE, CHUNK_CRC32):
                f.seek(body, os.SEEK_CUR)
            else:
                sys.exit(f"{src}: unknown sparse chunk type {ctype:#x}")
            if ctype != CHUNK_CRC32:
                pos += nblk * blk


def lp_offset(src, offset, name):
    with open(src, "rb") as f:
        f.seek(offset + LP_GEOMETRY_SIZE)
        g = f.read(LP_GEOMETRY_SIZE)
        if struct.unpack_from("<I", g)[0] != LP_GEOMETRY_MAGIC:
            sys.exit(f"{src}: no super partition at {offset}")
        max_size = struct.unpack_from("<I", g, 40)[0]
        # The primary metadata slots follow the two geometry copies.
        f.seek(offset + 3 * LP_GEOMETRY_SIZE)
        h = f.read(max_size)
        if struct.unpack_from("<I", h)[0] != LP_METADATA_MAGIC:
            sys.exit(f"{src}: bad super metadata")
        hdr_size, = struct.unpack_from("<I", h, 8)
        tables = h[hdr_size:]
        # partitions, extents, groups, block devices: (offset, count, size)
        descs = [struct.unpack_from("<III", h, 80 + 12 * i) for i in range(4)]
        def entries(i):
            o, n, sz = descs[i]
            return [tables[o + sz * k:o + sz * (k + 1)] for k in range(n)]
        extents = [struct.unpack_from("<QIQI", e) for e in entries(1)]
        for e in entries(0):
            if e[:36].rstrip(b"\0").decode() != name:
                continue
            first, count = struct.unpack_from("<II", e, 40)
            if count != 1:
                sys.exit(f"{src}: {name} has {count} extents")
            _sectors, _target, data, _dev = extents[first]
            print(offset + data * 512)
            return
        sys.exit(f"{src}: no logical partition {name}")


def boot_ramdisk(src, dst):
    d = open(src, "rb").read()
    if d[:8] != b"ANDROID!":
        sys.exit(f"{src}: not a boot image")
    kernel, ramdisk = struct.unpack_from("<II", d, 8)
    version = struct.unpack_from("<I", d, 40)[0]
    if version not in (3, 4):
        sys.exit(f"{src}: boot image header version {version}, not 3 or 4")
    off = BOOT_PAGE + pages(kernel, BOOT_PAGE)
    open(dst, "wb").write(d[off:off + ramdisk])


def vendor_boot(src, outdir):
    d = open(src, "rb").read()
    if d[:8] != b"VNDRBOOT":
        sys.exit(f"{src}: not a vendor boot image")
    version, page, _kaddr, _raddr, ramdisk = struct.unpack_from("<IIIII", d, 8)
    cmdline = d[28:28 + 2048].split(b"\0")[0]
    hdr_size, dtb = struct.unpack_from("<II", d, 2096)
    bootconfig = 0
    if version >= 4:
        _table, _entries, _entry, bootconfig = struct.unpack_from("<IIII", d, 2112)
    off = pages(hdr_size, page)
    os.makedirs(outdir, exist_ok=True)
    open(os.path.join(outdir, "ramdisk"), "wb").write(d[off:off + ramdisk])
    off += pages(ramdisk, page) + pages(dtb, page)
    if version >= 4:
        off += pages(_table, page)
    open(os.path.join(outdir, "bootconfig"), "wb").write(d[off:off + bootconfig])
    open(os.path.join(outdir, "cmdline"), "wb").write(cmdline + b"\n")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "size" and len(args) == 1:
        size(*args)
    elif cmd == "unsparse" and len(args) == 3:
        unsparse(args[0], args[1], int(args[2]))
    elif cmd == "lp-offset" and len(args) == 3:
        lp_offset(args[0], int(args[1]), args[2])
    elif cmd == "ramdisk" and len(args) == 2:
        boot_ramdisk(*args)
    elif cmd == "vendor-boot" and len(args) == 2:
        vendor_boot(*args)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
