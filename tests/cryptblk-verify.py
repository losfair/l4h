#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compare raw windows with OpenSSL EVP AES-256-XTS (enc has no XTS mode)."""
import ctypes as c
import ctypes.util
import sys
from pathlib import Path

lib = c.CDLL(ctypes.util.find_library('crypto'))
lib.EVP_CIPHER_CTX_new.restype = c.c_void_p
lib.EVP_aes_256_xts.restype = c.c_void_p
lib.EVP_EncryptInit_ex.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p, c.c_void_p, c.c_void_p]
lib.EVP_EncryptUpdate.argtypes = [c.c_void_p, c.c_void_p, c.POINTER(c.c_int), c.c_void_p, c.c_int]
lib.EVP_EncryptFinal_ex.argtypes = [c.c_void_p, c.c_void_p, c.POINTER(c.c_int)]
lib.EVP_CIPHER_CTX_free.argtypes = [c.c_void_p]

def encrypt(key, index, data):
    ctx = lib.EVP_CIPHER_CTX_new()
    assert ctx
    try:
        out = c.create_string_buffer(len(data) + 16)
        n = c.c_int()
        assert lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_xts(), None, key, index.to_bytes(16, 'little')) == 1
        assert lib.EVP_EncryptUpdate(ctx, out, c.byref(n), data, len(data)) == 1
        assert n.value == len(data)
        assert lib.EVP_EncryptFinal_ex(ctx, c.byref(out, len(data)), c.byref(n)) == 1
        assert n.value == 0
        return out.raw[:len(data)]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)

if __name__ == '__main__':
    disk = Path(sys.argv[1]).read_bytes()
    key = bytes(range(64))
    for unit in range(14 * 256 * 1024 // 4096):
        off = unit * 4096
        plain = bytes((i * 7 + (i // 4096) * 19 + (i >> 8)) & 255 for i in range(off, off + 4096))
        cipher = encrypt(key, unit, plain)
        assert disk[2048 * 512 + off:2048 * 512 + off + 4096] == cipher, f'ciphertext unit {unit}'
        assert disk[18432 * 512 + off:18432 * 512 + off + 4096] == plain, f'plain unit {unit}'
    assert disk[:2048 * 512] == bytes(2048 * 512), 'write before window'
    print('CRYPTBLK: raw encrypted and plain windows match OpenSSL EVP')
