#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# BSD 2-Clause License
#
# Copyright (c) 2026, l4h contributors
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Verifier side of l4h attestation (DESIGN.md §10.2).

  l4h-attest.py measure KERNEL [--initrd F] [--cmdline S]
      The launch digest of a guest booted with these files: what its
      reports carry as "launch".
  l4h-attest.py verify REPORT EVIDENCE [--data HEX] [--launch HEX]
                [--pcr N=HEX]... [--ak-name HEX] [--ek-ca PEM]
                [--deny-taint SPEC] [--require-seal SPEC]
      Check a report (l4hctl attest report -o) against the host evidence
      (l4hctl attest evidence -o), and print what they claim as JSON.
      Without --ak-name the attestation key is not known to be a TPM's.
  l4h-attest.py make-credential EVIDENCE SECRET_HEX -o FILE [--ek PEM]
      A credential for the host's attestation key, encrypted to its EK
      (TPM2_MakeCredential; the format of tpm2_makecredential).  A guest
      decrypts it with `l4hctl attest activate FILE`: the secret coming
      back proves the AK is in the TPM with that EK, so its name (printed
      by verify) can be pinned with --ak-name.

Needs the Python `cryptography` package.
"""

import argparse
import hashlib
import hmac
import json
import os
import struct
import sys

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_DOMAIN = b"l4h-trustd-key-v1"
KEY_PCR = 15


class Fail(Exception):
    pass


# ---- CBOR (RFC 8949), the subset trustd writes


def cbor_decode(b):
    def item(i):
        ib = b[i]
        major, info = ib >> 5, ib & 31
        i += 1
        if info < 24:
            v = info
        elif info in (24, 25, 26, 27):
            n = 1 << (info - 24)
            v = int.from_bytes(b[i:i + n], "big")
            i += n
        else:
            raise Fail("unsupported CBOR item")
        if major == 0:
            return v, i
        if major == 1:
            return -1 - v, i
        if major == 2:
            return bytes(b[i:i + v]), i + v
        if major == 3:
            return b[i:i + v].decode(), i + v
        if major == 4:
            out = []
            for _ in range(v):
                x, i = item(i)
                out.append(x)
            return out, i
        if major == 5:
            out = {}
            for _ in range(v):
                k, i = item(i)
                out[k], i = item(i)
            return out, i
        if major == 6:
            x, i = item(i)
            return ("tag", v, x), i
        if major == 7 and info in (20, 21):
            return info == 21, i
        raise Fail("unsupported CBOR item")

    try:
        v, end = item(0)
    except (IndexError, UnicodeDecodeError):
        raise Fail("malformed CBOR")
    if end != len(b):
        raise Fail("trailing bytes after CBOR item")
    return v


def cbor_bytes(b):
    """A CBOR byte string (for COSE's Sig_structure)."""
    n = len(b)
    if n < 24:
        head = bytes([0x40 | n])
    elif n < 256:
        head = bytes([0x58, n])
    elif n < 65536:
        head = b"\x59" + n.to_bytes(2, "big")
    else:
        head = b"\x5a" + n.to_bytes(4, "big")
    return head + b


# ---- TPM structures


class Reader:
    def __init__(self, b):
        self.b, self.at = b, 0

    def take(self, n):
        if self.at + n > len(self.b):
            raise Fail("truncated TPM structure")
        s = self.b[self.at:self.at + n]
        self.at += n
        return s

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack(">H", self.take(2))[0]

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def tpm2b(self):
        return self.take(self.u16())


def tpm_name(public):
    """The name of a TPMT_PUBLIC: its nameAlg, then its digest (sha256)."""
    if struct.unpack(">H", public[2:4])[0] != 0x000B:
        raise Fail("name algorithm is not sha256")
    return public[2:4] + hashlib.sha256(public).digest()


def parse_public(public):
    """(attributes, key) of a TPMT_PUBLIC with an RSA or ECC P-256 key."""
    r = Reader(public)
    alg, _name_alg, attrs = r.u16(), r.u16(), r.u32()
    r.tpm2b()  # authPolicy
    if alg == 0x0023:  # ECC
        sym = r.u16()
        if sym != 0x0010:
            r.u16(), r.u16()
        scheme = r.u16()
        if scheme != 0x0010:
            r.u16()
        curve, kdf = r.u16(), r.u16()
        if kdf != 0x0010:
            r.u16()
        if curve != 0x0003:
            raise Fail("not a P-256 key")
        x, y = r.tpm2b(), r.tpm2b()
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
        return attrs, key
    if alg == 0x0001:  # RSA
        sym = r.u16()
        if sym != 0x0010:
            r.u16(), r.u16()
        scheme = r.u16()
        if scheme != 0x0010:
            r.u16()
        r.u16()  # keyBits
        e = r.u32() or 65537
        n = int.from_bytes(r.tpm2b(), "big")
        return attrs, rsa.RSAPublicNumbers(e, n).public_key()
    raise Fail("unsupported key type %#x" % alg)


def parse_quote(attest):
    r = Reader(attest)
    if r.u32() != 0xFF544347 or r.u16() != 0x8018:
        raise Fail("not a TPM quote")
    q = {"signer": r.tpm2b(), "extra": r.tpm2b()}
    q["clock"], q["reset_count"], q["restart_count"], q["safe"] = r.u64(), r.u32(), r.u32(), r.u8()
    q["firmware"] = r.u64()
    pcrs = []
    for _ in range(r.u32()):
        alg = r.u16()
        bits = r.take(r.u8())
        for i in range(8 * len(bits)):
            if bits[i // 8] >> (i % 8) & 1:
                pcrs.append((alg, i))
    q["pcrs"], q["digest"] = pcrs, r.tpm2b()
    return q


def tpm_ecdsa(sig):
    """An ECDSA TPMT_SIGNATURE as DER."""
    r = Reader(sig)
    if r.u16() != 0x0018 or r.u16() != 0x000B:
        raise Fail("quote signature is not ECDSA with sha256")
    return encode_dss_signature(int.from_bytes(r.tpm2b(), "big"), int.from_bytes(r.tpm2b(), "big"))


def cose_p256(k):
    """A P-256 key from a COSE_Key (EC2)."""
    if k.get(1) != 2 or k.get(-1) != 1:
        raise Fail("host key is not an EC2 P-256 COSE_Key")
    return ec.EllipticCurvePublicNumbers(int.from_bytes(k[-2], "big"), int.from_bytes(k[-3], "big"), ec.SECP256R1()).public_key()


def point(key):
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


# ---- measure


def launch_digest(kernel, initrd, cmdline):
    """The digest root computes at boot (guest.rs, Guest::measure)."""
    if kernel[:4] != b"\x7fELF" or kernel[4] != 2 or kernel[5] != 1:
        raise Fail("kernel: not a 64-bit little-endian ELF")
    entry, phoff = struct.unpack_from("<QQ", kernel, 24)
    phentsize, phnum = struct.unpack_from("<HH", kernel, 54)
    loads = []
    for i in range(phnum):
        p = phoff + i * phentsize
        if struct.unpack_from("<I", kernel, p)[0] != 1:
            continue
        off, vaddr = struct.unpack_from("<QQ", kernel, p + 8)
        filesz, memsz = struct.unpack_from("<QQ", kernel, p + 32)
        loads.append((vaddr, memsz, kernel[off:off + filesz]))
    if not loads:
        raise Fail("kernel: no loadable segments")
    base = min(v for v, _, _ in loads) & ~0xFFF
    end = (max(v + m for v, m, _ in loads) - base + 0xFFF) & ~0xFFF
    image = bytearray(end)
    for v, _, data in loads:
        image[v - base:v - base + len(data)] = data
    cmd = cmdline.encode()[:2047]
    h = hashlib.sha256(b"l4h-launch-v1")
    h.update(struct.pack("<QQQ", base, entry, end))
    h.update(image)
    h.update(struct.pack("<Q", len(initrd)))
    h.update(initrd)
    h.update(struct.pack("<Q", len(cmd)))
    h.update(cmd)
    return h.digest()


# ---- verify


def check_evidence(ev, pins, ak_name, ek_ca):
    """The host's signing key and what the evidence shows about it."""
    if ev.get("v") != 1:
        raise Fail("unknown evidence version")
    ak = ev["ak"]
    attrs, ak_key = parse_public(ak)
    # A restricted signing key of the TPM only signs what the TPM made.
    if attrs & (1 << 1 | 1 << 16 | 1 << 18) != (1 << 1 | 1 << 16 | 1 << 18):
        raise Fail("attestation key is not a fixedTPM restricted signing key")
    if not isinstance(ak_key, ec.EllipticCurvePublicKey):
        raise Fail("attestation key is not ECC")
    name = tpm_name(ak)
    if ak_name is not None and name != ak_name:
        raise Fail("attestation key is not the pinned one (name %s)" % name.hex())
    try:
        ak_key.verify(tpm_ecdsa(ev["quotesig"]), ev["quote"], ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Fail("quote signature does not verify")
    q = parse_quote(ev["quote"])
    key = cose_p256(ev["key"])
    if q["extra"] != hashlib.sha256(KEY_DOMAIN + point(key)).digest():
        raise Fail("the quote is not over this host key")
    pcrs = ev["pcrs"]
    if any(alg != 0x000B for alg, _ in q["pcrs"]) or [i for _, i in q["pcrs"]] != sorted(pcrs):
        raise Fail("quoted PCRs differ from the evidence's")
    if hashlib.sha256(b"".join(pcrs[i] for i in sorted(pcrs))).digest() != q["digest"]:
        raise Fail("PCR values do not match the quote")
    # Quoted before trustd extended it: the first key since TPM reset.
    if pcrs.get(KEY_PCR) != bytes(32):
        raise Fail("PCR %d is not zero: not the first host key of this boot" % KEY_PCR)
    for i, want in pins.items():
        if pcrs.get(i) != want:
            raise Fail("PCR %d is %s, not %s" % (i, pcrs.get(i, b"").hex(), want.hex()))
    ek = None
    if "ekcert" in ev:
        cert = x509.load_der_x509_certificate(ev["ekcert"])
        ek = {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string()}
        if ek_ca:
            ca = x509.load_pem_x509_certificate(open(ek_ca, "rb").read())
            try:
                cert.verify_directly_issued_by(ca)
            except (ValueError, TypeError, InvalidSignature):
                raise Fail("EK certificate not issued by %s" % ek_ca)
            ek["verified"] = True
    elif ek_ca:
        raise Fail("no EK certificate in the evidence")
    host = {
        "key": hashlib.sha256(point(key)).hexdigest(),
        "ak_name": name.hex(),
        "ak_pinned": ak_name is not None,
        "reset_count": q["reset_count"],
        "restart_count": q["restart_count"],
        "pcrs": {str(i): pcrs[i].hex() for i in sorted(pcrs)},
        "ek_cert": ek,
    }
    return key, host


HOST_FLAGS = {"console-in": 0, "console-out": 1}
LINUX_TAINT = "PFSRMBUDAWCIOELKXTNJ"


def flag_spec(spec):
    """Comma-separated host names, numbers and inclusive bit ranges."""
    bits = set()
    if not spec.strip():
        return bits
    for part in spec.split(","):
        part = part.strip()
        if part in HOST_FLAGS:
            bits.add(HOST_FLAGS[part])
            continue
        try:
            bounds = [int(n) for n in part.split("-")]
            if len(bounds) not in (1, 2) or min(bounds) < 0 or bounds[0] > bounds[-1]:
                raise ValueError()
            bits.update(range(bounds[0], bounds[-1] + 1))
        except ValueError:
            raise Fail("invalid flag specification: %s" % part)
    return bits


def flag_name(bit):
    if bit < 2:
        return ("console-in", "console-out")[bit]
    if 64 <= bit < 64 + len(LINUX_TAINT):
        return LINUX_TAINT[bit - 64]
    return None


def flag_list(bits):
    return [str(b) + ("(%s)" % flag_name(b) if flag_name(b) else "") for b in sorted(bits)]


def check_flags(claims, deny_taint, require_seal):
    def bitmap(key):
        if key not in claims:
            return set()  # old hosts; cannot satisfy a required seal
        b = claims[key]
        if not isinstance(b, bytes) or len(b) < 32:
            raise Fail("%s must be a byte string of at least 32 bytes" % key)
        return {i for i in range(len(b) * 8) if b[i // 8] & (1 << (i % 8))}

    taint, seal = bitmap("taint"), bitmap("seal")
    denied = taint & flag_spec(deny_taint)
    missing = flag_spec(require_seal) - seal
    if denied:
        raise Fail("denied taint: %s" % ",".join(flag_list(denied)))
    if missing:
        raise Fail("required seal missing: %s" % ",".join(flag_list(missing)))
    return {"taint_bits": flag_list(taint), "seal_bits": flag_list(seal)}


def check_report(rep, key, data, launch, deny_taint="console-in", require_seal=""):
    if not (isinstance(rep, tuple) and rep[:2] == ("tag", 18)) or len(rep[2]) != 4:
        raise Fail("report is not a COSE_Sign1")
    protected, _unprotected, payload, sig = rep[2]
    if cbor_decode(protected) != {1: -7}:
        raise Fail("report is not ES256")
    tbs = b"\x84\x6aSignature1" + cbor_bytes(protected) + b"\x40" + cbor_bytes(payload)
    if len(sig) != 64:
        raise Fail("bad report signature")
    try:
        key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), tbs, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Fail("report signature does not verify")
    c = cbor_decode(payload)
    if c.get("v") != 1:
        raise Fail("unknown report version")
    if c["host"] != hashlib.sha256(point(key)).digest():
        raise Fail("report names another host key")
    if data is not None and c["data"] != data.ljust(64, b"\0"):
        raise Fail("report data is not the expected nonce")
    if launch is not None and c["launch"] != launch:
        raise Fail("launch digest %s is not the expected one" % c["launch"].hex())
    flags = check_flags(c, deny_taint, require_seal)
    return {**{k: (v.hex() if isinstance(v, bytes) else v) for k, v in c.items()}, **flags}


# ---- make-credential


def kdfa(key, label, context_u, context_v, bits):
    out, i = b"", 1
    while len(out) * 8 < bits:
        out += hmac.new(key, struct.pack(">I", i) + label + b"\0" + context_u + context_v + struct.pack(">I", bits), hashlib.sha256).digest()
        i += 1
    return out[:bits // 8]


def kdfe(z, label, party_u, party_v, bits):
    out, i = b"", 1
    while len(out) * 8 < bits:
        out += hashlib.sha256(struct.pack(">I", i) + z + label + b"\0" + party_u + party_v).digest()
        i += 1
    return out[:bits // 8]


def make_credential(ek, name, secret):
    """TPM2_MakeCredential (TPM 2.0 Part 1, 24.4) for an EK with the
    default template (AES-128-CFB, sha256)."""
    if isinstance(ek, rsa.RSAPublicKey):
        seed = os.urandom(32)
        enc_secret = ek.encrypt(seed, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"IDENTITY\0"))
    else:
        eph = ec.generate_private_key(ek.curve)
        z = eph.exchange(ec.ECDH(), ek)
        size = (ek.curve.key_size + 7) // 8
        n = eph.public_key().public_numbers()
        ex, ey = n.x.to_bytes(size, "big"), n.y.to_bytes(size, "big")
        seed = kdfe(z, b"IDENTITY", ex, ek.public_numbers().x.to_bytes(size, "big"), 256)
        enc_secret = struct.pack(">H", size) + ex + struct.pack(">H", size) + ey
    sym = kdfa(seed, b"STORAGE", name, b"", 128)
    enc = Cipher(algorithms.AES(sym), modes.CFB(bytes(16))).encryptor()
    enc_identity = enc.update(struct.pack(">H", len(secret)) + secret) + enc.finalize()
    integrity = hmac.new(kdfa(seed, b"INTEGRITY", b"", b"", 256), enc_identity + name, hashlib.sha256).digest()
    blob = struct.pack(">H", len(integrity)) + integrity + enc_identity
    return b"\xba\xdc\xc0\xde\0\0\0\1" + struct.pack(">H", len(blob)) + blob + struct.pack(">H", len(enc_secret)) + enc_secret


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("measure")
    m.add_argument("kernel")
    m.add_argument("--initrd")
    m.add_argument("--cmdline", default="")
    v = sub.add_parser("verify")
    v.add_argument("report")
    v.add_argument("evidence")
    v.add_argument("--data", help="expected report data (hex)")
    v.add_argument("--launch", help="expected launch digest (hex)")
    v.add_argument("--pcr", action="append", default=[], help="N=HEX: expected sha256 PCR value")
    v.add_argument("--ak-name", help="the enrolled attestation key's name (hex)")
    v.add_argument("--deny-taint", default="console-in", help="deny host names, bit numbers or ranges (default: console-in; '' disables)")
    v.add_argument("--require-seal", default="", help="require sealed host names, bit numbers or ranges")
    v.add_argument("--ek-ca", help="CA certificate (PEM) that issued the EK certificate")
    c = sub.add_parser("make-credential")
    c.add_argument("evidence")
    c.add_argument("secret", help="hex, at most 32 bytes")
    c.add_argument("-o", required=True)
    c.add_argument("--ek", help="the EK's public key (PEM), if the evidence has no EK certificate")
    a = ap.parse_args()
    try:
        if a.cmd == "measure":
            initrd = open(a.initrd, "rb").read() if a.initrd else b""
            print(launch_digest(open(a.kernel, "rb").read(), initrd, a.cmdline).hex())
        elif a.cmd == "verify":
            pins = {}
            for p in a.pcr:
                i, _, val = p.partition("=")
                pins[int(i)] = bytes.fromhex(val)
            ev = cbor_decode(open(a.evidence, "rb").read())
            ak_name = bytes.fromhex(a.ak_name) if a.ak_name else None
            key, host = check_evidence(ev, pins, ak_name, a.ek_ca)
            data = bytes.fromhex(a.data) if a.data is not None else None
            launch = bytes.fromhex(a.launch) if a.launch else None
            guest = check_report(cbor_decode(open(a.report, "rb").read()), key, data, launch, a.deny_taint, a.require_seal)
            print(json.dumps({"host": host, "guest": guest}, indent=2))
            if ak_name is None:
                print("l4h-attest: warning: attestation key not pinned (--ak-name)", file=sys.stderr)
        else:
            ev = cbor_decode(open(a.evidence, "rb").read())
            if a.ek:
                ek = serialization.load_pem_public_key(open(a.ek, "rb").read())
            elif "ekcert" in ev:
                ek = x509.load_der_x509_certificate(ev["ekcert"]).public_key()
            else:
                raise Fail("no EK certificate in the evidence: give --ek")
            secret = bytes.fromhex(a.secret)
            if not 0 < len(secret) <= 32:
                raise Fail("the secret is 1 to 32 bytes")
            open(a.o, "wb").write(make_credential(ek, tpm_name(ev["ak"]), secret))
    except Fail as e:
        print("l4h-attest: %s" % e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
