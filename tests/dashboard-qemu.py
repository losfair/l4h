#!/usr/bin/env python3
"""Verify dom0's dashboard title on QEMU's screen (tests/run-biostest.sh).

Usage: dashboard-qemu.py SERIAL_LOG QMP_SOCKET

tests/guest/init-image prints a line once the title is "l4h", once dom0 has
set TITLE and once it has restored "l4h", and waits after each.  This takes
a screenshot after each line and looks at the title bar: the cells past
"l4h" that TITLE covers are blank, then hold glyphs, then are blank again.
"""
import json
from pathlib import Path
import socket
import sys
import time

TITLE = "biostest dashboard title"
DEFAULT = "l4h"
# 1024 pixels wide: 8x8 glyphs doubled vertically; the title starts at
# column 1 of row 0 (host/l4h-root/src/dashboard.rs).
WIDTH, CELL_W, CELL_H, FIRST_COL = 1024, 8, 16, 1
# The dashboard redraws within 100 ms of a new title, and every second.
SETTLE = 2
DEADLINE = time.monotonic() + 180


def wait_for(log, marker):
    while time.monotonic() < DEADLINE:
        text = log.read_bytes() if log.exists() else b""
        if marker.encode() in text:
            return
        assert b"IMAGETEST: done" not in text, f"dom0 finished without {marker!r}"
        time.sleep(0.2)
    raise TimeoutError(marker)


def connect(path):
    while time.monotonic() < DEADLINE:
        sock = socket.socket(socket.AF_UNIX)
        try:
            sock.settimeout(30)
            sock.connect(str(path))
            return sock.makefile("rwb", buffering=0)
        except (FileNotFoundError, ConnectionRefusedError):
            sock.close()
            time.sleep(0.2)
    raise TimeoutError(f"QEMU socket {path}")


def qmp(stream, command, **arguments):
    stream.write(json.dumps({"execute": command, "arguments": arguments}).encode() + b"\n")
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("QMP connection closed")
        response = json.loads(line)
        assert "error" not in response, response
        if "return" in response:
            return response["return"]


def screenshot(stream, path):
    """The screen's rows, each a bytes of RGB triples."""
    path.unlink(missing_ok=True)
    qmp(stream, "screendump", filename=str(path))
    data = path.read_bytes()
    # A binary PPM: "P6", width, height and maximum, then the pixels.
    fields, pos = [], 0
    while len(fields) < 4:
        end = pos
        while not data[end:end + 1].isspace():
            end += 1
        fields.append(data[pos:end])
        pos = end + 1
    assert fields[0] == b"P6" and fields[3] == b"255", fields
    width, height = int(fields[1]), int(fields[2])
    assert width == WIDTH and len(data) - pos == width * height * 3, (width, height, len(data) - pos)
    return [data[pos + y * width * 3:pos + (y + 1) * width * 3] for y in range(height)]


def blank(rows, first, count):
    """Whether cells `first` to `first + count` of the title bar hold no glyph."""
    lo, hi = first * CELL_W * 3, (first + count) * CELL_W * 3
    pixels = {row[x:x + 3] for row in rows[:CELL_H] for x in range(lo, hi, 3)}
    return len(pixels) == 1


def main():
    log, sock = Path(sys.argv[1]), Path(sys.argv[2])
    stream = connect(sock)
    stream.readline()  # greeting
    qmp(stream, "qmp_capabilities")
    shot = sock.with_suffix(".ppm")
    rest = (FIRST_COL + len(DEFAULT), len(TITLE) - len(DEFAULT))
    for marker, titled in (("title default", False), ("title set", True), ("title reset", False)):
        wait_for(log, f"IMAGETEST: {marker}")
        time.sleep(SETTLE)
        rows = screenshot(stream, shot)
        assert not blank(rows, FIRST_COL, len(DEFAULT)), f"{marker}: no title on the screen"
        assert blank(rows, *rest) != titled, f"{marker}: title bar past {DEFAULT!r} is {'blank' if titled else 'not blank'}"
        print(f"DASHTEST: {marker} ok", flush=True)
    shot.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
