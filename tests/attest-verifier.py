#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Policy checks on signed reports, including old and future hosts, and
which EK a credential is made for."""
import contextlib
import datetime
import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import unittest
import sys

sys.dont_write_bytecode = True
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

spec = importlib.util.spec_from_file_location("attest", Path(__file__).resolve().parents[1] / "tools/l4h-attest.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def encode(x):
    if isinstance(x, bytes):
        return a.cbor_bytes(x)
    if isinstance(x, str):
        b = x.encode()
        assert len(b) < 24
        return bytes([0x60 + len(b)]) + b
    if isinstance(x, dict):
        return bytes([0xa0 + len(x)]) + b"".join(encode(k) + encode(v) for k, v in x.items())
    assert 0 <= x < 24
    return bytes([x])


def bitmap(*bits, size=32):
    b = bytearray(size)
    for bit in bits:
        b[bit // 8] |= 1 << (bit % 8)
    return bytes(b)


class Verify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = ec.generate_private_key(ec.SECP256R1())

    def signed(self, **flags):
        c = {"v": 1, "host": hashlib.sha256(a.point(self.key.public_key())).digest(), **flags}
        p, protected = encode(c), b"\xa1\x01\x26"
        tbs = b"\x84\x6aSignature1" + a.cbor_bytes(protected) + b"\x40" + a.cbor_bytes(p)
        r, s = decode_dss_signature(self.key.sign(tbs, ec.ECDSA(hashes.SHA256())))
        return ("tag", 18, [protected, {}, p, r.to_bytes(32, "big") + s.to_bytes(32, "big")])

    def check(self, rep, **policy):
        return a.check_report(rep, self.key.public_key(), None, None, **policy)

    def test_default_denies_input_only(self):
        rep = self.signed(taint=bitmap(0, 1, 65, 200), seal=bitmap(0))
        with self.assertRaisesRegex(a.Fail, "console-in"):
            self.check(rep)
        got = self.check(rep, deny_taint="")
        self.assertEqual(got["taint_bits"], ["0(console-in)", "1(console-out)", "65(F)", "200"])
        self.check(self.signed(taint=bitmap(1, 65, 200), seal=bitmap()))

    def test_required_seal_and_guest_policy(self):
        rep = self.signed(taint=bitmap(65, 200), seal=bitmap(0, 130))
        self.check(rep, deny_taint="130", require_seal="console-in,130")
        for policy in ({"deny_taint": "64-127"}, {"require_seal": "130-131"}):
            with self.assertRaises(a.Fail):
                self.check(rep, **policy)

    def test_old_and_long_bitmaps(self):
        rep = self.signed()
        self.check(rep)
        with self.assertRaises(a.Fail):
            self.check(rep, require_seal="0")
        rep = self.signed(taint=bitmap(260, size=40), seal=bitmap(270, size=40))
        self.check(rep, require_seal="270")
        with self.assertRaises(a.Fail):
            self.check(rep, deny_taint="256-300")
        with self.assertRaises(a.Fail):
            self.check(rep, require_seal="320")

    def test_malformed_bitmap_and_specs(self):
        for key in ("taint", "seal"):
            for bad in (b"", bytes(31), "00", 0):
                with self.assertRaises(a.Fail):
                    self.check(self.signed(**{key: bad}))
        for spec in ("-1", "64-0", "no-such-flag", "128,", "1-2-3"):
            with self.assertRaises(a.Fail):
                a.flag_spec(spec)
        self.assertEqual(a.flag_spec("console-in,64-66,200"), {0, 64, 65, 66, 200})

    def test_flags_are_covered_by_signature(self):
        rep = self.signed(taint=bitmap(0), seal=bitmap())
        c = a.cbor_decode(rep[2][2])
        c["taint"] = bitmap()
        rep[2][2] = encode(c)
        with self.assertRaisesRegex(a.Fail, "signature"):
            self.check(rep)


def rsa_public(key, attrs):
    """A TPMT_PUBLIC of an RSA 2048 key, as trustd's EK template gives."""
    n = key.public_key().public_numbers().n.to_bytes(256, "big")
    return (struct.pack(">HHI", 0x0001, 0x000B, attrs) + struct.pack(">H", 32) + bytes(32)
            + struct.pack(">HHHHHI", 0x0006, 128, 0x0043, 0x0010, 2048, 0) + struct.pack(">H", 256) + n)


class EvidenceEk(unittest.TestCase):
    # fixedTPM, fixedParent, sensitiveDataOrigin, adminWithPolicy,
    # restricted, decrypt.
    EK_ATTRS = 1 << 1 | 1 << 4 | 1 << 5 | 1 << 7 | 1 << 16 | 1 << 17

    @classmethod
    def setUpClass(cls):
        cls.ek = rsa.generate_private_key(65537, 2048)
        cls.other = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "ek")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cls.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(cls.other.public_key())
                    .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                    .sign(cls.other, hashes.SHA256()).public_bytes(serialization.Encoding.DER))

    def ek_of(self, ev, pem=None):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            ek = a.evidence_ek(ev, pem)
        return ek.public_numbers(), err.getvalue()

    def test_ekpub_without_certificate(self):
        got, warning = self.ek_of({"ekpub": rsa_public(self.ek, self.EK_ATTRS)})
        self.assertEqual(got, self.ek.public_key().public_numbers())
        self.assertIn("only claims", warning)

    def test_certificate_and_pem_come_first(self):
        ev = {"ekcert": self.cert, "ekpub": rsa_public(self.ek, self.EK_ATTRS)}
        self.assertEqual(self.ek_of(ev)[0], self.other.public_key().public_numbers())
        pem = self.ek.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(self.ek_of({"ekcert": self.cert}, pem)[0], self.ek.public_key().public_numbers())

    def test_ekpub_must_be_a_restricted_decryption_key(self):
        for attrs in (self.EK_ATTRS & ~(1 << 16), self.EK_ATTRS & ~(1 << 17), self.EK_ATTRS & ~(1 << 1)):
            with self.assertRaisesRegex(a.Fail, "restricted decryption"):
                self.ek_of({"ekpub": rsa_public(self.ek, attrs)})

    def test_no_ek(self):
        with self.assertRaisesRegex(a.Fail, "--ek"):
            self.ek_of({})


if __name__ == "__main__":
    unittest.main()
