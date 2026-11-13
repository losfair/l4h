#!/usr/bin/env python3
"""The far end of tests/run-e1000etest.sh, on the build host: QEMU's user
networking takes the guest's connections to 10.0.2.2 here.  On RX_PORT it
sends BYTES of random data and closes (the guest's receive); on TX_PORT it
reads BYTES and closes (the guest's send).  Each transfer's SHA-256 goes
to LOG, a line "rx|tx HEX", for the test to compare with the guest's.

Usage: nic-peer.py RX_PORT TX_PORT BYTES LOG
"""
import hashlib
import os
import socket
import sys
import threading

rx_port, tx_port, total, log = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
lock = threading.Lock()


def record(kind, h):
    with lock, open(log, "a") as f:
        f.write(f"{kind} {h.hexdigest()}\n")


def serve(port, handle):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(4)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def send(c):
    h, left = hashlib.sha256(), total
    while left:
        b = os.urandom(min(left, 1 << 16))
        c.sendall(b)
        h.update(b)
        left -= len(b)
    c.close()
    record("rx", h)


def recv(c):
    h, left = hashlib.sha256(), total
    while left:
        b = c.recv(min(left, 1 << 16))
        if not b:
            break
        h.update(b)
        left -= len(b)
    c.close()
    record("tx", h)


threading.Thread(target=serve, args=(rx_port, send), daemon=True).start()
serve(tx_port, recv)
