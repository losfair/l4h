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

  l4h-attest.py measure KERNEL [--initrd F] [--cmdline S] [--initrd-gpa N]
      The launch digest of a guest booted with these files: what its
      reports carry as "launch".  The initrd's address is part of it.
  l4h-attest.py verify REPORT EVIDENCE [--data HEX] [--launch HEX]
                [--pcr N=HEX]... [--ak-name HEX] [--ek-ca PEM]
                [--deny-taint SPEC] [--require-seal SPEC] [--event-log FILE]
      Check a report (l4hctl attest report -o) against the host evidence
      (l4hctl attest evidence -o), and print what they claim as JSON.
      Without --ak-name the attestation key is not known to be a TPM's.
      By default the guest must have sealed console-in and not taken
      console input before: input after the report would be unattested.
      A multikernel host's report and evidence name the partition the
      guest runs in (version 2); verify prints it as "partition".
      --event-log takes the host's UEFI TPM event log (l4hctl attest
      event-log -o): replayed, it must give the quoted PCRs 0-14, which
      nothing changes after the firmware's ExitBootServices (trustd quotes
      before it extends PCR 15).  Its events then say what the firmware
      measured.
  l4h-attest.py event-log FILE
      The events of a UEFI TPM 2.0 event log (TCG2 crypto agile format)
      and the SHA-256 PCR values they replay to, as JSON.
  l4h-attest.py make-credential EVIDENCE SECRET_HEX -o FILE [--ek PEM]
                [--ek-ca PEM]
      A credential for the host's attestation key, encrypted to its EK
      (TPM2_MakeCredential; the format of tpm2_makecredential).  A guest
      decrypts it with `l4hctl attest activate FILE`: the secret coming
      back proves the AK is in the TPM with that EK, so its name (printed
      by verify) can be pinned with --ak-name.  The AK must be a fixedTPM
      restricted signing key, as verify requires.  The EK is --ek, else
      the key of the evidence's EK certificate, which --ek-ca checks as
      verify does (without it the certificate is only what the host
      says), else the evidence's "ekpub" (a TPM without a certificate in
      NV, such as AMD's fTPM): that one is only what the host says, so
      check it against the manufacturer's certificate for it first.  The
      EK certificate in later evidence is not bound to the AK: only the
      credential enrolled with a checked EK is.

Needs the Python `cryptography` package.
"""

import argparse
import datetime
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
# A multikernel partition's key: the domain, the partition (u32
# little-endian), then the key.
KEY_DOMAIN_PARTITION = b"l4h-trustd-key-v2"
KEY_PCR = 15


class Fail(Exception):
    pass


# What parsing data from the host can raise besides Fail: a field missing
# or of the wrong type, a number out of range (an off-curve point among
# them), a structure cut short.
MALFORMED = (KeyError, IndexError, TypeError, ValueError, AttributeError, struct.error)


def is_int(x):
    """A CBOR integer: not a CBOR true or false, which Python's bool, an
    int that equals 1 or 0, would let through."""
    return type(x) is int


def checked(what):
    """Make `what` input that a function cannot parse a Fail."""
    def wrap(f):
        def g(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except MALFORMED as e:
                raise Fail("malformed %s (%s: %s)" % (what, type(e).__name__, e))
        g.__name__, g.__doc__ = f.__name__, f.__doc__
        return g
    return wrap


# ---- CBOR (RFC 8949), the subset trustd writes


# Deeper than anything trustd writes (a report or evidence nests 3 deep).
CBOR_MAX_DEPTH = 16


def cbor_decode(b):
    def take(i, n):
        if i + n > len(b):
            raise Fail("malformed CBOR")
        return b[i:i + n], i + n

    def item(i, depth):
        if depth > CBOR_MAX_DEPTH:
            raise Fail("CBOR nesting too deep")
        (ib,), i = take(i, 1)
        major, info = ib >> 5, ib & 31
        if info < 24:
            v = info
        elif info in (24, 25, 26, 27):
            raw, i = take(i, 1 << (info - 24))
            v = int.from_bytes(raw, "big")
        else:
            raise Fail("unsupported CBOR item")
        if major == 0:
            return v, i
        if major == 1:
            return -1 - v, i
        if major == 2:
            raw, i = take(i, v)
            return bytes(raw), i
        if major == 3:
            raw, i = take(i, v)
            return bytes(raw).decode(), i
        if major == 4:
            out = []
            for _ in range(v):
                x, i = item(i, depth + 1)
                out.append(x)
            return out, i
        if major == 5:
            out = {}
            for _ in range(v):
                k, i = item(i, depth + 1)
                # A key given twice could say one thing to one verifier and
                # another to the next; a list or map is no key.
                try:
                    dup = k in out
                except TypeError:
                    dup = True
                if dup:
                    raise Fail("duplicate or invalid CBOR map key")
                out[k], i = item(i, depth + 1)
            return out, i
        if major == 6:
            x, i = item(i, depth + 1)
            return ("tag", v, x), i
        if major == 7 and info in (20, 21):
            return info == 21, i
        raise Fail("unsupported CBOR item")

    try:
        v, end = item(0, 0)
    except (IndexError, UnicodeDecodeError, RecursionError):
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


# ---- The UEFI TPM 2.0 event log (TCG PC Client Platform Firmware Profile,
# crypto agile format: a TCG_PCR_EVENT holding the Spec ID event, then
# TCG_PCR_EVENT2s; little-endian)


EV_NO_ACTION = 3
TPM_ALG_SHA256 = 0x000B
SPEC_ID = b"Spec ID Event03\0"
STARTUP_LOCALITY = b"StartupLocality\0"
# PCRs nothing extends after ExitBootServices: trustd quotes them before
# it extends KEY_PCR.
EVENT_LOG_PCRS = range(KEY_PCR)
EVENT_TYPES = {
    0x0: "EV_PREBOOT_CERT", 0x1: "EV_POST_CODE", 0x3: "EV_NO_ACTION", 0x4: "EV_SEPARATOR", 0x5: "EV_ACTION",
    0x6: "EV_EVENT_TAG", 0x7: "EV_S_CRTM_CONTENTS", 0x8: "EV_S_CRTM_VERSION", 0x9: "EV_CPU_MICROCODE",
    0xA: "EV_PLATFORM_CONFIG_FLAGS", 0xB: "EV_TABLE_OF_DEVICES", 0xC: "EV_COMPACT_HASH", 0xD: "EV_IPL",
    0xE: "EV_IPL_PARTITION_DATA", 0xF: "EV_NONHOST_CODE", 0x10: "EV_NONHOST_CONFIG", 0x11: "EV_NONHOST_INFO",
    0x12: "EV_OMIT_BOOT_DEVICE_EVENTS", 0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
    0x80000002: "EV_EFI_VARIABLE_BOOT", 0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
    0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER", 0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
    0x80000006: "EV_EFI_GPT_EVENT", 0x80000007: "EV_EFI_ACTION", 0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
    0x80000009: "EV_EFI_HANDOFF_TABLES", 0x8000000A: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
    0x8000000B: "EV_EFI_HANDOFF_TABLES2", 0x8000000C: "EV_EFI_VARIABLE_BOOT2", 0x80000010: "EV_EFI_HCRTM_EVENT",
    0x800000E0: "EV_EFI_VARIABLE_AUTHORITY", 0x800000E1: "EV_EFI_SPDM_FIRMWARE_BLOB",
    0x800000E2: "EV_EFI_SPDM_FIRMWARE_CONFIG",
}


class LogReader:
    def __init__(self, b):
        self.b, self.at = b, 0

    def take(self, n):
        if n > len(self.b) - self.at:
            raise Fail("event log cut short at byte %d" % self.at)
        s = self.b[self.at:self.at + n]
        self.at += n
        return s

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]


@checked("event log")
def parse_event_log(log):
    """The digest sizes the Spec ID event lists ({algorithm: size}) and the
    TCG_PCR_EVENT2s after it, each {"pcr", "type", "digests": {algorithm:
    digest}, "data"}.  The whole log must be events: no bytes left over."""
    if not isinstance(log, bytes):
        raise Fail("event log is not bytes")
    r = LogReader(log)
    # The header: a TCG 1.2 TCG_PCR_EVENT (SHA-1 digest) of type
    # EV_NO_ACTION holding TCG_EfiSpecIDEventStruct.
    pcr, kind, _, size = r.u32(), r.u32(), r.take(20), r.u32()
    spec = LogReader(r.take(size))
    if pcr != 0 or kind != EV_NO_ACTION or spec.take(16) != SPEC_ID:
        raise Fail("not a TCG2 crypto agile event log (no Spec ID Event03)")
    spec.take(4 + 4)  # platformClass, version, errata, uintnSize
    sizes = {}
    for _ in range(spec.u32()):
        alg, n = spec.u16(), spec.u16()
        if alg in sizes or not 0 < n <= 64:
            raise Fail("Spec ID event: bad digest algorithm %#06x (size %d)" % (alg, n))
        sizes[alg] = n
    if not sizes:
        raise Fail("Spec ID event lists no digest algorithms")
    spec.take(spec.u8())  # vendorInfo
    if spec.at != len(spec.b):
        raise Fail("Spec ID event has %d bytes past its end" % (len(spec.b) - spec.at))
    events = []
    while r.at < len(log):
        at = r.at
        pcr, kind, count = r.u32(), r.u32(), r.u32()
        if count > len(sizes):
            raise Fail("event at byte %d: %d digests, the log has %d algorithms" % (at, count, len(sizes)))
        digests = {}
        for _ in range(count):
            alg = r.u16()
            if alg not in sizes or alg in digests:
                raise Fail("event at byte %d: unexpected digest algorithm %#06x" % (at, alg))
            digests[alg] = r.take(sizes[alg])
        data = r.take(r.u32())
        events.append({"pcr": pcr, "type": kind, "digests": digests, "data": data})
    return sizes, events


def replay_event_log(log):
    """The SHA-256 PCRs 0-23 that the log's events extend from TPM2_Startup
    (PC Client: 17-22 start at all ones), and the events."""
    sizes, events = parse_event_log(log)
    if sizes.get(TPM_ALG_SHA256) != 32:
        raise Fail("the event log has no SHA-256 digests")
    pcrs = {i: (b"\xff" if 17 <= i <= 22 else b"\x00") * 32 for i in range(24)}
    extended = set()
    for n, e in enumerate(events):
        if e["type"] == EV_NO_ACTION:
            # Not extended; the startup locality (PFP 10.4.5.3) is PCR 0's
            # initial value.
            if e["data"][:len(STARTUP_LOCALITY)] == STARTUP_LOCALITY and len(e["data"]) == len(STARTUP_LOCALITY) + 1:
                if e["pcr"] == 0 and 0 not in extended:
                    pcrs[0] = bytes(31) + e["data"][-1:]
            continue
        if not 0 <= e["pcr"] < 24:
            raise Fail("event %d extends PCR %d" % (n, e["pcr"]))
        if TPM_ALG_SHA256 not in e["digests"]:
            raise Fail("event %d (PCR %d) has no SHA-256 digest" % (n, e["pcr"]))
        pcrs[e["pcr"]] = hashlib.sha256(pcrs[e["pcr"]] + e["digests"][TPM_ALG_SHA256]).digest()
        extended.add(e["pcr"])
    return pcrs, events


def check_event_log(log, quoted):
    """That the log replays to the quoted PCRs 0-14 (`quoted`, the
    evidence's {index: value}); the number of its events."""
    pcrs, events = replay_event_log(log)
    for i in EVENT_LOG_PCRS:
        if i not in quoted:
            raise Fail("PCR %d is not quoted: the event log cannot be checked" % i)
        if quoted[i] != pcrs[i]:
            raise Fail("event log does not match the quote: PCR %d replays to %s, the quote has %s"
                       % (i, pcrs[i].hex(), quoted[i].hex()))
    return len(events)


def event_log_summary(log):
    pcrs, events = replay_event_log(log)
    sizes, _ = parse_event_log(log)

    def data(e):
        d = e["data"]
        return d.decode("ascii") if d and all(32 <= b < 127 for b in d) else d[:32].hex() + ("..." if len(d) > 32 else "")
    return {
        "algorithms": ["%#06x" % alg for alg in sizes],
        "events": [{"pcr": e["pcr"], "type": EVENT_TYPES.get(e["type"], "%#x" % e["type"]),
                    "sha256": e["digests"][TPM_ALG_SHA256].hex() if TPM_ALG_SHA256 in e["digests"] else None,
                    "size": len(e["data"]), "data": data(e)} for e in events],
        "pcrs": {str(i): pcrs[i].hex() for i in sorted({e["pcr"] for e in events if e["type"] != EV_NO_ACTION})},
    }


def tpm_name(public):
    """The name of a TPMT_PUBLIC: its nameAlg, then its digest (sha256)."""
    if not isinstance(public, bytes) or len(public) < 4:
        raise Fail("malformed TPM public area")
    if struct.unpack(">H", public[2:4])[0] != 0x000B:
        raise Fail("name algorithm is not sha256")
    return public[2:4] + hashlib.sha256(public).digest()


# TPMT_SYM_DEF_OBJECT: a symmetric algorithm of an object (TPMI_ALG_SYM_OBJECT,
# TPM 2.0 Part 2, 9.27), with key bits and mode, or TPM_ALG_NULL.  XOR is
# no object's.
SYM_OBJECT = {0x0006, 0x0013, 0x0026}  # AES, SM4, CAMELLIA
# The bytes of the details of an asymmetric scheme after its algorithm
# (TPMU_ASYM_SCHEME): a hash algorithm, also a count for ECDAA, nothing for
# RSAES.  TPM_ALG_NULL has none.
RSA_SCHEMES = {0x0010: 0, 0x0014: 2, 0x0015: 0, 0x0016: 2, 0x0017: 2}
ECC_SCHEMES = {0x0010: 0, 0x0018: 2, 0x0019: 2, 0x001A: 4, 0x001B: 2, 0x001C: 2, 0x001D: 2}
# TPMT_KDF_SCHEME: MGF1, KDF1_SP800_56A, KDF2, KDF1_SP800_108, with a hash.
KDF_SCHEMES = {0x0010: 0, 0x0007: 2, 0x0020: 2, 0x0021: 2, 0x0022: 2}


def tpm_scheme(r, known, what):
    alg = r.u16()
    if alg not in known:
        raise Fail("unknown %s %#x" % (what, alg))
    r.take(known[alg])


def tpm_end(r, what):
    if r.at != len(r.b):
        raise Fail("trailing bytes after the %s" % what)


@checked("TPM public area")
def parse_public(public):
    """(attributes, key) of a TPMT_PUBLIC with an RSA or ECC P-256 key."""
    r = Reader(public)
    alg, _name_alg, attrs = r.u16(), r.u16(), r.u32()
    r.tpm2b()  # authPolicy
    if alg not in (0x0001, 0x0023):
        raise Fail("unsupported key type %#x" % alg)
    sym = r.u16()
    if sym in SYM_OBJECT:
        r.u16(), r.u16()  # keyBits, mode
    elif sym != 0x0010:
        raise Fail("unknown symmetric algorithm %#x" % sym)
    if alg == 0x0023:  # ECC
        tpm_scheme(r, ECC_SCHEMES, "ECC scheme")
        curve = r.u16()
        tpm_scheme(r, KDF_SCHEMES, "KDF scheme")
        if curve != 0x0003:
            raise Fail("not a P-256 key")
        x, y = r.tpm2b(), r.tpm2b()
        tpm_end(r, "TPM public area")
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
        return attrs, key
    # RSA
    tpm_scheme(r, RSA_SCHEMES, "RSA scheme")
    r.u16()  # keyBits
    e = r.u32() or 65537
    n = int.from_bytes(r.tpm2b(), "big")
    tpm_end(r, "TPM public area")
    return attrs, rsa.RSAPublicNumbers(e, n).public_key()


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
    tpm_end(r, "TPM quote")
    return q


def tpm_ecdsa(sig):
    """An ECDSA TPMT_SIGNATURE as DER."""
    r = Reader(sig)
    if r.u16() != 0x0018 or r.u16() != 0x000B:
        raise Fail("quote signature is not ECDSA with sha256")
    sig_r, sig_s = r.tpm2b(), r.tpm2b()
    tpm_end(r, "quote signature")
    return encode_dss_signature(int.from_bytes(sig_r, "big"), int.from_bytes(sig_s, "big"))


@checked("host key")
def cose_p256(k):
    """A P-256 key from a COSE_Key (EC2)."""
    if not (is_int(k.get(1)) and k[1] == 2 and is_int(k.get(-1)) and k[-1] == 1):
        raise Fail("host key is not an EC2 P-256 COSE_Key")
    x, y = k.get(-2), k.get(-3)
    if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
        raise Fail("host key coordinates are not 32 bytes each")
    return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()


def point(key):
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


# ---- measure


@checked("kernel")
def launch_digest(kernel, initrd, cmdline, initrd_gpa=None):
    """The digest vmmgr computes at boot (guest.rs, Guest::measure).  The
    initrd is where vmmgr puts it, 1 MiB past the kernel's end
    (kimage::Kernel::initrd_gpa), unless `initrd_gpa` says otherwise; with
    no initrd its address is 0."""
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
    if not initrd:
        gpa = 0
    elif initrd_gpa is None:
        gpa = end + (1 << 20)
    else:
        gpa = initrd_gpa
    h = hashlib.sha256(b"l4h-launch-v2")
    h.update(struct.pack("<QQQ", base, entry, end))
    h.update(image)
    h.update(struct.pack("<QQ", gpa, len(initrd)))
    h.update(initrd)
    h.update(struct.pack("<Q", len(cmd)))
    h.update(cmd)
    return h.digest()


# ---- verify


def key_binding(point_bytes, partition):
    """What the quote's qualifying data is for a host key."""
    if partition is None:
        return hashlib.sha256(KEY_DOMAIN + point_bytes).digest()
    return hashlib.sha256(KEY_DOMAIN_PARTITION + struct.pack("<I", partition) + point_bytes).digest()


def key_chain(ev, partition):
    """PCR 15 as a multikernel partition's key was quoted: the keys the
    primary's trustd extended before it, one per partition, the primary's
    first (the primary quotes its own key before serving the others)."""
    chain = ev.get("chain")
    if not isinstance(chain, list):
        raise Fail("multikernel evidence without its key chain")
    pcr, seen = bytes(32), {partition}
    for i, e in enumerate(chain):
        if not (isinstance(e, list) and len(e) == 2 and is_int(e[0]) and 0 <= e[0] < 8 and isinstance(e[1], bytes)
                and len(e[1]) == 65 and e[1][0] == 4):
            raise Fail("malformed key chain")
        k, pt = e
        if k in seen:
            raise Fail("key chain has two keys of partition %d" % k)
        if i == 0 and k != 0:
            raise Fail("key chain does not start with partition 0's key")
        seen.add(k)
        pcr = hashlib.sha256(pcr + key_binding(pt, k)).digest()
    return pcr, [e[0] for e in chain]


# TCG's EK certificate extended key usage (tcg-kp-EKCertificate).
EK_CERT_EKU = x509.ObjectIdentifier("2.23.133.8.1")


def check_ek_cert(cert, cas, where, now=None):
    """That `cert` is an EK certificate one of `cas` issued and that both
    are valid now: the CA is a CA that may sign certificates, the EK
    certificate is not a CA's, and if it limits its use, to an EK's."""
    now = now or datetime.datetime.now(datetime.timezone.utc)

    def ext(c, kind):
        try:
            return c.extensions.get_extension_for_class(kind).value
        except x509.ExtensionNotFound:
            return None

    def valid(c):
        return c.not_valid_before_utc <= now <= c.not_valid_after_utc

    try:
        if not valid(cert):
            raise Fail("EK certificate expired or not yet valid")
        bc = ext(cert, x509.BasicConstraints)
        if bc is not None and bc.ca:
            raise Fail("EK certificate is a CA certificate")
        eku = ext(cert, x509.ExtendedKeyUsage)
        if eku is not None and EK_CERT_EKU not in eku:
            raise Fail("EK certificate is not for an EK (extended key usage)")
        why = "EK certificate not issued by %s" % where
        for ca in cas:
            try:
                cert.verify_directly_issued_by(ca)
            except (ValueError, TypeError, InvalidSignature):
                continue
            bc = ext(ca, x509.BasicConstraints)
            ku = ext(ca, x509.KeyUsage)
            if bc is None or not bc.ca:
                why = "EK certificate issuer is not a CA"
            elif ku is not None and not ku.key_cert_sign:
                why = "EK certificate issuer may not sign certificates"
            elif not valid(ca):
                why = "EK certificate issuer expired or not yet valid"
            else:
                return
        raise Fail(why)
    except ValueError as e:
        raise Fail("malformed certificate: %s" % e)


@checked("evidence")
def attestation_key(ev):
    """The evidence's attestation key and its name: a fixedTPM restricted
    signing key (ECC), the only kind whose quotes the TPM made."""
    ak = ev["ak"]
    attrs, ak_key = parse_public(ak)
    # A restricted signing key of the TPM only signs what the TPM made.
    if attrs & (1 << 1 | 1 << 16 | 1 << 18) != (1 << 1 | 1 << 16 | 1 << 18):
        raise Fail("attestation key is not a fixedTPM restricted signing key")
    if not isinstance(ak_key, ec.EllipticCurvePublicKey):
        raise Fail("attestation key is not ECC")
    return ak_key, tpm_name(ak)


def load_cas(ek_ca):
    try:
        with open(ek_ca, "rb") as f:
            return x509.load_pem_x509_certificates(f.read())
    except ValueError:
        raise Fail("no CA certificate in %s" % ek_ca)


@checked("evidence")
def check_evidence(ev, pins, ak_name, ek_ca):
    """The host's signing key and what the evidence shows about it."""
    if not isinstance(ev, dict):
        raise Fail("evidence is not a CBOR map")
    if not is_int(ev.get("v")) or ev["v"] not in (1, 2):
        raise Fail("unknown evidence version")
    partition = ev.get("partition") if ev["v"] == 2 else None
    if ev["v"] == 2 and not (is_int(partition) and 0 <= partition < 8):
        raise Fail("multikernel evidence without a valid partition")
    ak_key, name = attestation_key(ev)
    if ak_name is not None and name != ak_name:
        raise Fail("attestation key is not the pinned one (name %s)" % name.hex())
    try:
        ak_key.verify(tpm_ecdsa(ev["quotesig"]), ev["quote"], ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Fail("quote signature does not verify")
    q = parse_quote(ev["quote"])
    key = cose_p256(ev["key"])
    if q["extra"] != key_binding(point(key), partition):
        raise Fail("the quote is not over this host key")
    pcrs = ev["pcrs"]
    # Each a sha256 PCR's value, 32 bytes: the quote signs only their
    # concatenation, which values of other lengths could split elsewhere
    # (PCR 15 zero, its real value appended to PCR 14's).
    if not isinstance(pcrs, dict) or not all(is_int(i) and isinstance(v, bytes) and len(v) == 32 for i, v in pcrs.items()):
        raise Fail("PCRs are not a map of PCR numbers to values")
    if any(alg != 0x000B for alg, _ in q["pcrs"]) or [i for _, i in q["pcrs"]] != sorted(pcrs):
        raise Fail("quoted PCRs differ from the evidence's")
    if hashlib.sha256(b"".join(pcrs[i] for i in sorted(pcrs))).digest() != q["digest"]:
        raise Fail("PCR values do not match the quote")
    # Quoted before trustd extended it: the first key since TPM reset, or
    # on a multikernel host the first of this partition, after the keys
    # the evidence lists.
    if partition is None:
        if pcrs.get(KEY_PCR) != bytes(32):
            raise Fail("PCR %d is not zero: not the first host key of this boot" % KEY_PCR)
        before = None
    else:
        want, before = key_chain(ev, partition)
        if partition == 0 and before:
            raise Fail("partition 0's key is not the first of this boot")
        # Partition 0 quotes and extends its key before serving any other
        # partition: another's chain starts with it, never empty.
        if partition != 0 and not before:
            raise Fail("key chain is empty: partition %d's key cannot be the first of this boot" % partition)
        if pcrs.get(KEY_PCR) != want:
            raise Fail("PCR %d is not the chain of the %d keys before partition %d's" % (KEY_PCR, len(before), partition))
    for i, want in pins.items():
        if pcrs.get(i) != want:
            raise Fail("PCR %d is %s, not %s" % (i, pcrs.get(i, b"").hex(), want.hex()))
    ek = None
    if "ekcert" in ev:
        try:
            cert = x509.load_der_x509_certificate(ev["ekcert"])
            ek = {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string()}
        except (ValueError, TypeError):
            raise Fail("malformed EK certificate")
        if ek_ca:
            check_ek_cert(cert, load_cas(ek_ca), ek_ca)
            ek["verified"] = True
    elif ek_ca:
        raise Fail("no EK certificate in the evidence")
    host = {
        "key": hashlib.sha256(point(key)).hexdigest(),
        **({} if partition is None else {"partition": partition, "keys_before": before}),
        "ak_name": name.hex(),
        "ak_pinned": ak_name is not None,
        "reset_count": q["reset_count"],
        "restart_count": q["restart_count"],
        "pcrs": {str(i): pcrs[i].hex() for i in sorted(pcrs)},
        "ek_cert": ek,
        # What the host says, unsigned: the EK's TPMT_PUBLIC when the TPM
        # has no EK certificate, and TPM_PT_MANUFACTURER.
        "ekpub": ev["ekpub"].hex() if "ekpub" in ev else None,
        "vendor": ev.get("vendor"),
    }
    return key, partition, host


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


@checked("report")
def check_report(rep, key, data, launch, deny_taint="console-in", require_seal="console-in", partition=None):
    if not (isinstance(rep, tuple) and rep[:2] == ("tag", 18)) or not isinstance(rep[2], list) or len(rep[2]) != 4:
        raise Fail("report is not a COSE_Sign1")
    protected, _unprotected, payload, sig = rep[2]
    if not all(isinstance(x, bytes) for x in (protected, payload, sig)):
        raise Fail("report is not a COSE_Sign1")
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
    if not isinstance(c, dict):
        raise Fail("report claims are not a CBOR map")
    if not is_int(c.get("v")) or c["v"] not in (1, 2):
        raise Fail("unknown report version")
    if "partition" in c and not is_int(c["partition"]):
        raise Fail("report partition is not an integer")
    # Version 2: a multikernel partition's, as its evidence says.
    if (c["v"] == 2) != (partition is not None) or c.get("partition") != partition:
        raise Fail("report is for partition %s, the evidence for %s" % (c.get("partition"), partition))
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


@checked("evidence")
def evidence_ek(ev, ek_pem=None, ek_ca=None):
    """The EK to make a credential for: `ek_pem`, else the key of the
    evidence's EK certificate, checked against the CA certificates in file
    `ek_ca` if given, else its EK public area (ekpub)."""
    if not isinstance(ev, dict):
        raise Fail("evidence is not a CBOR map")
    if ek_pem:
        return serialization.load_pem_public_key(ek_pem)
    if "ekcert" in ev:
        try:
            cert = x509.load_der_x509_certificate(ev["ekcert"])
        except (ValueError, TypeError):
            raise Fail("malformed EK certificate")
        if ek_ca:
            check_ek_cert(cert, load_cas(ek_ca), ek_ca)
        else:
            # Anyone can make a certificate: the credential would go to
            # whatever key the host chose, and the AK it enrolls be
            # anyone's.
            print("l4h-attest: warning: EK certificate not verified (--ek-ca): the EK is only what the host says",
                  file=sys.stderr)
        return cert.public_key()
    if ek_ca:
        raise Fail("no EK certificate in the evidence")
    if "ekpub" in ev:
        attrs, ek = parse_public(ev["ekpub"])
        # fixedTPM, restricted, decrypt: a storage key, as an EK is.
        if attrs & (1 << 1 | 1 << 16 | 1 << 17) != (1 << 1 | 1 << 16 | 1 << 17):
            raise Fail("ekpub is not a fixedTPM restricted decryption key")
        print("l4h-attest: warning: the EK is the evidence's ekpub, which the host only claims: "
              "check it against the TPM manufacturer's certificate", file=sys.stderr)
        return ek
    raise Fail("no EK certificate or ekpub in the evidence: give --ek")


def make_credential(ek, name, secret):
    """TPM2_MakeCredential (TPM 2.0 Part 1, 24.4) for an EK with the
    default template (AES-128-CFB, sha256)."""
    if not isinstance(ek, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise Fail("the EK is neither an RSA nor an ECC key")
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
    m.add_argument("--initrd-gpa", type=lambda x: int(x, 0),
                   help="where dom0 loaded the initrd (default: 1 MiB past the kernel's end, as vmmgr does)")
    v = sub.add_parser("verify")
    v.add_argument("report")
    v.add_argument("evidence")
    v.add_argument("--data", help="expected report data (hex)")
    v.add_argument("--launch", help="expected launch digest (hex)")
    v.add_argument("--pcr", action="append", default=[], help="N=HEX: expected sha256 PCR value")
    v.add_argument("--ak-name", help="the enrolled attestation key's name (hex)")
    v.add_argument("--deny-taint", default="console-in", help="deny host names, bit numbers or ranges (default: console-in; '' disables)")
    v.add_argument("--require-seal", default="console-in",
                   help="require sealed host names, bit numbers or ranges (default: console-in; '' disables)")
    v.add_argument("--ek-ca", help="CA certificates (PEM, one or more) one of which issued the EK certificate")
    v.add_argument("--event-log", help="the host's UEFI TPM event log (l4hctl attest event-log -o): must replay to PCRs 0-14")
    e = sub.add_parser("event-log")
    e.add_argument("log")
    c = sub.add_parser("make-credential")
    c.add_argument("evidence")
    c.add_argument("secret", help="hex, at most 32 bytes")
    c.add_argument("-o", required=True)
    c.add_argument("--ek", help="the EK's public key (PEM), instead of the evidence's EK certificate or ekpub")
    c.add_argument("--ek-ca", help="CA certificates (PEM, one or more) one of which issued the EK certificate")
    a = ap.parse_args()
    try:
        if a.cmd == "measure":
            initrd = open(a.initrd, "rb").read() if a.initrd else b""
            print(launch_digest(open(a.kernel, "rb").read(), initrd, a.cmdline, a.initrd_gpa).hex())
        elif a.cmd == "verify":
            pins = {}
            for p in a.pcr:
                i, _, val = p.partition("=")
                pins[int(i)] = bytes.fromhex(val)
            ev = cbor_decode(open(a.evidence, "rb").read())
            ak_name = bytes.fromhex(a.ak_name) if a.ak_name else None
            key, partition, host = check_evidence(ev, pins, ak_name, a.ek_ca)
            if a.event_log:
                host["event_log_events"] = check_event_log(open(a.event_log, "rb").read(), ev["pcrs"])
            data = bytes.fromhex(a.data) if a.data is not None else None
            launch = bytes.fromhex(a.launch) if a.launch else None
            guest = check_report(cbor_decode(open(a.report, "rb").read()), key, data, launch, a.deny_taint, a.require_seal,
                                 partition)
            print(json.dumps({"host": host, "guest": guest}, indent=2))
            if ak_name is None:
                print("l4h-attest: warning: attestation key not pinned (--ak-name)", file=sys.stderr)
        elif a.cmd == "event-log":
            print(json.dumps(event_log_summary(open(a.log, "rb").read()), indent=2))
        else:
            ev = cbor_decode(open(a.evidence, "rb").read())
            ek = evidence_ek(ev, open(a.ek, "rb").read() if a.ek else None, a.ek_ca)
            secret = bytes.fromhex(a.secret)
            if not 0 < len(secret) <= 32:
                raise Fail("the secret is 1 to 32 bytes")
            # Only a TPM's restricted signing key is worth enrolling: the
            # credential activates for any object of that name.
            _, name = attestation_key(ev)
            open(a.o, "wb").write(make_credential(ek, name, secret))
    except Fail as e:
        print("l4h-attest: %s" % e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
