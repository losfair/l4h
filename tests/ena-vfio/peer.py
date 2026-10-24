#!/usr/bin/env python3
"""Controlled UDP echo / TCP sink for ena-vfio, listening on one peer IP."""
import socket
import sys
import threading


def udp(address):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        sock.bind((address, 9000))
        print(f"UDP echo ready on {address}:9000", flush=True)
        while True:
            data, source = sock.recvfrom(65535)
            sock.sendto(data, source)


def sink(conn, address):
    with conn:
        conn.settimeout(30)
        count = 0
        valid = True
        try:
            while data := conn.recv(65536):
                valid &= all(byte == (count + i) % 251 for i, byte in enumerate(data))
                count += len(data)
        except (ConnectionResetError, TimeoutError):
            pass
        print(f"TCP {address}: {count} bytes, pattern {'PASS' if valid else 'FAIL'}", flush=True)


if __name__ == "__main__":
    address = sys.argv[1]
    threading.Thread(target=udp, args=(address,), daemon=True).start()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, 9001))
        sock.listen()
        print(f"TCP sink ready on {address}:9001", flush=True)
        while True:
            conn, remote = sock.accept()
            threading.Thread(target=sink, args=(conn, remote), daemon=True).start()
