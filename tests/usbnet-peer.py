#!/usr/bin/env python3
"""The far end of tests/run-usbnetbench.sh, on the build host: QEMU's user
networking takes the guest's connections to 10.0.2.2 here.  On RX_PORT it
sends BYTES and closes (the guest's receive); on TX_PORT it reads BYTES and
closes (the guest's send), printing what it measured.

Usage: usbnet-peer.py RX_PORT TX_PORT BYTES
"""
import socket
import sys
import threading
import time

rx_port, tx_port, total = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
chunk = b"\0" * (1 << 16)


def serve(port, handle):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(4)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def send(c):
    left = total
    while left:
        left -= c.send(chunk[: min(left, len(chunk))])
    c.close()


def recv(c):
    n, t0 = 0, None
    while n < total:
        b = c.recv(1 << 16)
        if not b:
            break
        if t0 is None:
            t0 = time.monotonic()
        n += len(b)
    t = time.monotonic() - (t0 or time.monotonic())
    print(f"usbnet-peer: received {n} bytes at {n / max(t, 1e-6) / 1e6:.1f} MB/s", flush=True)
    c.close()


threading.Thread(target=serve, args=(rx_port, send), daemon=True).start()
serve(tx_port, recv)
