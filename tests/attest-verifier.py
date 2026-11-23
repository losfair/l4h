#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Policy checks on signed reports, including old and future hosts, which
EK a credential is made for and which AK it enrolls, and malformed input."""
import contextlib
import os
import subprocess
import tempfile
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
    if x is True or x is False:
        return b"\xf5" if x else b"\xf4"
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
        self.check(self.signed(taint=bitmap(1, 65, 200), seal=bitmap(0)))

    def test_default_requires_input_sealed(self):
        # Unsealed, input could come after the report: refused unless the
        # verifier opts out.
        rep = self.signed(taint=bitmap(), seal=bitmap(1))
        with self.assertRaisesRegex(a.Fail, "required seal missing: 0\\(console-in\\)"):
            self.check(rep)
        self.check(rep, require_seal="")
        self.check(self.signed(taint=bitmap(), seal=bitmap(0)))
        # Not overridden by another requirement unless it says so.
        with self.assertRaises(a.Fail):
            self.check(rep, require_seal="console-in,console-out")
        self.check(rep, require_seal="console-out")

    def test_required_seal_and_guest_policy(self):
        rep = self.signed(taint=bitmap(65, 200), seal=bitmap(0, 130))
        self.check(rep, deny_taint="130", require_seal="console-in,130")
        for policy in ({"deny_taint": "64-127"}, {"require_seal": "130-131"}):
            with self.assertRaises(a.Fail):
                self.check(rep, **policy)

    def test_old_and_long_bitmaps(self):
        rep = self.signed()
        self.check(rep, require_seal="")
        with self.assertRaises(a.Fail):
            self.check(rep)
        with self.assertRaises(a.Fail):
            self.check(rep, require_seal="0")
        rep = self.signed(taint=bitmap(260, size=40), seal=bitmap(0, 270, size=40))
        self.check(rep)
        self.check(rep, require_seal="270")
        with self.assertRaises(a.Fail):
            self.check(rep, deny_taint="256-300")
        with self.assertRaises(a.Fail):
            self.check(rep, require_seal="320")

    def test_malformed_bitmap_and_specs(self):
        for key in ("taint", "seal"):
            for bad in (b"", bytes(31), "00", 0):
                with self.assertRaises(a.Fail):
                    self.check(self.signed(**{key: bad}), require_seal="")
        for spec in ("-1", "64-0", "no-such-flag", "128,", "1-2-3"):
            with self.assertRaises(a.Fail):
                a.flag_spec(spec)
        self.assertEqual(a.flag_spec("console-in,64-66,200"), {0, 64, 65, 66, 200})

    def test_flags_are_covered_by_signature(self):
        rep = self.signed(taint=bitmap(0), seal=bitmap(0))
        c = a.cbor_decode(rep[2][2])
        c["taint"] = bitmap()
        rep[2][2] = encode(c)
        with self.assertRaisesRegex(a.Fail, "signature"):
            self.check(rep)


class Cbor(unittest.TestCase):
    def test_duplicate_and_invalid_keys(self):
        # {"v": 1, "v": 2}: which "v" a verifier sees must not be a choice.
        with self.assertRaisesRegex(a.Fail, "duplicate"):
            a.cbor_decode(b"\xa2\x61v\x01\x61v\x02")
        # A list as a key.
        with self.assertRaisesRegex(a.Fail, "invalid CBOR map key"):
            a.cbor_decode(b"\xa1\x80\x01")
        self.assertEqual(a.cbor_decode(b"\xa2\x61v\x01\x61w\x02"), {"v": 1, "w": 2})

    def test_nesting(self):
        deep = b"\x81" * 17 + b"\x00"
        with self.assertRaisesRegex(a.Fail, "too deep"):
            a.cbor_decode(deep)
        ok = b"\x81" * 16 + b"\x00"
        v = a.cbor_decode(ok)
        for _ in range(16):
            v = v[0]
        self.assertEqual(v, 0)
        # Far deeper than Python's recursion: still a Fail.
        with self.assertRaises(a.Fail):
            a.cbor_decode(b"\x81" * 100000 + b"\x00")

    def test_lengths_past_the_input(self):
        # A byte string, text and integer that say more than is there:
        # a slice would quietly give less.
        for bad in (b"\x45abc", b"\x58\x10abc", b"\x63ab", b"\x19\x01", b"\x1b" + bytes(4), b"\x82\x01", b"\xa1\x01", b""):
            with self.assertRaisesRegex(a.Fail, "malformed CBOR"):
                a.cbor_decode(bad)
        self.assertEqual(a.cbor_decode(b"\x43abc"), b"abc")


class Launch(unittest.TestCase):
    @staticmethod
    def kernel():
        """A 64-bit ELF with one loadable segment of 4 KiB at 0x1000."""
        ehdr = bytearray(64)
        ehdr[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<QQ", ehdr, 24, 0x1000, 64)
        struct.pack_into("<HH", ehdr, 54, 56, 1)
        phdr = bytearray(56)
        struct.pack_into("<I", phdr, 0, 1)
        struct.pack_into("<QQ", phdr, 8, 120, 0x1000)
        struct.pack_into("<QQ", phdr, 32, 8, 0x1000)
        return bytes(ehdr + phdr) + b"l4hkernl"

    def test_initrd_address_is_measured(self):
        k, rd = self.kernel(), b"initrd"
        default = a.launch_digest(k, rd, "console=hvc0")
        # vmmgr's: 1 MiB past the kernel's end (4 KiB here).
        self.assertEqual(default, a.launch_digest(k, rd, "console=hvc0", 0x1000 + (1 << 20)))
        self.assertNotEqual(default, a.launch_digest(k, rd, "console=hvc0", 0x1000 + (2 << 20)))
        # Without an initrd its address is 0, whatever is asked.
        self.assertEqual(a.launch_digest(k, b"", ""), a.launch_digest(k, b"", "", 0x1234000))
        h = hashlib.sha256(b"l4h-launch-v2")
        h.update(struct.pack("<QQQ", 0x1000, 0x1000, 0x1000))
        h.update(b"l4hkernl".ljust(0x1000, b"\0"))
        h.update(struct.pack("<QQ", 0x1000 + (1 << 20), len(rd)) + rd)
        h.update(struct.pack("<Q", 12) + b"console=hvc0")
        self.assertEqual(default, h.digest())


class EkCertificate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = ec.generate_private_key(ec.SECP256R1())
        cls.ek_key = ec.generate_private_key(ec.SECP256R1())
        cls.now = datetime.datetime.now(datetime.timezone.utc)

    def cert(self, subject, key, issuer, issuer_key, ca=None, path_length=None, key_usage=None, eku=None, days=(-1, 1)):
        b = (x509.CertificateBuilder().subject_name(self.name(subject)).issuer_name(self.name(issuer))
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(self.now + datetime.timedelta(days=days[0]))
             .not_valid_after(self.now + datetime.timedelta(days=days[1])))
        if ca is not None:
            b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        if key_usage is not None:
            b = b.add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                              data_encipherment=False, key_agreement=False, key_cert_sign=key_usage,
                                              crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        if eku is not None:
            b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        return b.sign(issuer_key, hashes.SHA256())

    @staticmethod
    def name(cn):
        return x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])

    def ca(self, **kw):
        kw.setdefault("ca", True)
        return self.cert("ca", self.ca_key, "ca", self.ca_key, **kw)

    def ek(self, **kw):
        return self.cert("ek", self.ek_key, "ca", self.ca_key, **kw)

    def check(self, ek, cas):
        a.check_ek_cert(ek, cas, "ca.pem")

    def test_good(self):
        self.check(self.ek(), [self.ca(key_usage=True)])
        self.check(self.ek(ca=False, eku=[a.EK_CERT_EKU]), [self.ca()])
        # One of several CAs in the bundle.
        other = ec.generate_private_key(ec.SECP256R1())
        self.check(self.ek(), [self.cert("other", other, "other", other, ca=True), self.ca()])

    def test_issuer_must_be_a_signing_ca(self):
        for ca, why in ((self.ca(ca=False), "not a CA"), (self.cert("ca", self.ca_key, "ca", self.ca_key), "not a CA"),
                        (self.ca(key_usage=False), "may not sign"), (self.ca(days=(-3, -2)), "issuer expired")):
            with self.assertRaisesRegex(a.Fail, why):
                self.check(self.ek(), [ca])

    def test_ek_certificate(self):
        for ek, why in ((self.ek(days=(-3, -2)), "expired"), (self.ek(days=(1, 2)), "not yet valid"),
                        (self.ek(ca=True), "is a CA certificate"),
                        (self.ek(eku=[x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), "extended key usage")):
            with self.assertRaisesRegex(a.Fail, why):
                self.check(ek, [self.ca()])
        other = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaisesRegex(a.Fail, "not issued by"):
            self.check(self.ek(), [self.cert("ca", other, "ca", other, ca=True)])

    def test_intermediate_and_root(self):
        """A manufacturer's chain: EK <- intermediate <- root, both CAs in
        the file.  Each hop is checked."""
        root_key = ec.generate_private_key(ec.SECP256R1())
        root = self.cert("root", root_key, "root", root_key, ca=True, key_usage=True)
        inter = self.cert("ca", self.ca_key, "root", root_key, ca=True, key_usage=True)
        for cas in ([inter, root], [root, inter]):
            self.check(self.ek(), cas)
        # The intermediate alone, its root not given: pinned as given.
        self.check(self.ek(), [inter])
        # The root alone does not issue the EK certificate.
        with self.assertRaisesRegex(a.Fail, "not issued by"):
            self.check(self.ek(), [root])
        # A hop above the intermediate that does not hold: the root expired,
        # not a CA, may not sign; the intermediate expired.
        for bad_root, why in ((self.cert("root", root_key, "root", root_key, ca=True, days=(-3, -2)), "expired"),
                              (self.cert("root", root_key, "root", root_key, ca=False), "not a CA"),
                              (self.cert("root", root_key, "root", root_key, ca=True, key_usage=False), "may not sign")):
            with self.assertRaisesRegex(a.Fail, why):
                self.check(self.ek(), [self.cert("ca", self.ca_key, "root", root_key, ca=True), bad_root])
        with self.assertRaisesRegex(a.Fail, "expired"):
            self.check(self.ek(), [self.cert("ca", self.ca_key, "root", root_key, ca=True, days=(-3, -2)), root])
        # An intermediate the named root did not sign (another key of the
        # same name): refused, not taken as pinned.
        forger = ec.generate_private_key(ec.SECP256R1())
        forged = self.cert("ca", self.ca_key, "root", forger, ca=True)
        with self.assertRaisesRegex(a.Fail, "not issued by"):
            self.check(self.ek(), [forged, root])
        # Three deep.
        mid_key = ec.generate_private_key(ec.SECP256R1())
        mid = self.cert("mid", mid_key, "root", root_key, ca=True)
        low = self.cert("ca", self.ca_key, "mid", mid_key, ca=True)
        self.check(self.ek(), [low, mid, root])
        with self.assertRaisesRegex(a.Fail, "expired"):
            self.check(self.ek(), [low, self.cert("mid", mid_key, "root", root_key, ca=True, days=(-3, -2)), root])
        # Two CAs that issue each other (A <- B <- A): no root, refused,
        # not taken as pinned.
        k2 = ec.generate_private_key(ec.SECP256R1())
        x = self.cert("ca", self.ca_key, "y", k2, ca=True)
        y = self.cert("y", k2, "ca", self.ca_key, ca=True)
        for cas in ([x, y], [y, x]):
            with self.assertRaisesRegex(a.Fail, "EK CA chain loops"):
                self.check(self.ek(), cas)

    def test_root_self_signature(self):
        """A CA that names itself its issuer is a root only if it signed
        itself: one whose self-signature does not verify is refused, not
        taken as pinned."""
        root_key = ec.generate_private_key(ec.SECP256R1())
        inter = self.cert("ca", self.ca_key, "root", root_key, ca=True)
        # "root" by name, signed by another key.
        forger = ec.generate_private_key(ec.SECP256R1())
        broken = self.cert("root", root_key, "root", forger, ca=True)
        with self.assertRaisesRegex(a.Fail, "EK root CA CN=root self-signature does not verify"):
            self.check(self.ek(), [inter, broken])
        # A CA issuing the EK certificate that claims to be self-signed but
        # is not.
        fake_root = self.cert("ca", self.ca_key, "ca", forger, ca=True)
        with self.assertRaisesRegex(a.Fail, "self-signature does not verify"):
            self.check(self.ek(), [fake_root])
        # Its signature bytes tampered.
        good = self.ca()
        der = bytearray(good.public_bytes(serialization.Encoding.DER))
        der[-5] ^= 1
        tampered = x509.load_der_x509_certificate(bytes(der))
        self.check(self.ek(), [good])
        with self.assertRaisesRegex(a.Fail, "self-signature does not verify"):
            self.check(self.ek(), [tampered])

    def test_path_length_constraint(self):
        """RFC 5280 pathLenConstraint counts non-self-issued intermediate CAs
        along each candidate path; the leaf EK certificate does not count."""
        # path_length=0 may directly issue the leaf EK certificate.
        self.check(self.ek(), [self.ca(path_length=0)])
        root_key = ec.generate_private_key(ec.SECP256R1())
        mid_key = ec.generate_private_key(ec.SECP256R1())
        root0 = self.cert("root", root_key, "root", root_key, ca=True, path_length=0)
        root1 = self.cert("root", root_key, "root", root_key, ca=True, path_length=1)
        root2 = self.cert("root", root_key, "root", root_key, ca=True, path_length=2)
        inter = self.cert("ca", self.ca_key, "root", root_key, ca=True, path_length=0)
        # 1 non-self-issued intermediate: path_length=0 rejects, 1 accepts.
        with self.assertRaisesRegex(a.Fail, "path length constraint"):
            self.check(self.ek(), [inter, root0])
        self.check(self.ek(), [inter, root1])
        # 2 non-self-issued intermediates: path_length=1 rejects, 2 accepts.
        mid1 = self.cert("mid", mid_key, "root", root_key, ca=True, path_length=1)
        mid0 = self.cert("mid", mid_key, "root", root_key, ca=True, path_length=0)
        low = self.cert("ca", self.ca_key, "mid", mid_key, ca=True, path_length=0)
        with self.assertRaisesRegex(a.Fail, "path length constraint"):
            self.check(self.ek(), [low, mid1, root1])
        with self.assertRaisesRegex(a.Fail, "path length constraint"):
            self.check(self.ek(), [low, mid0, root2])
        self.check(self.ek(), [low, mid1, root2])
        # Pinned intermediate chain without root still enforces path_length.
        with self.assertRaisesRegex(a.Fail, "path length constraint"):
            self.check(self.ek(), [low, mid0])
        self.check(self.ek(), [low, mid1])
        # Alternative paths: one fails path_length, another passes, in any order.
        alt_key = ec.generate_private_key(ec.SECP256R1())
        alt_root = self.cert("alt", alt_key, "alt", alt_key, ca=True, path_length=1)
        inter_alt = self.cert("ca", self.ca_key, "alt", alt_key, ca=True, path_length=0)
        for cas in ([inter, root0, inter_alt, alt_root], [alt_root, inter_alt, root0, inter]):
            self.check(self.ek(), cas)

    def test_self_issued_rollover_and_order(self):
        """Subject == Issuer is self-issued, not necessarily self-signed: a
        rollover CA chains to a same-named verifying issuer and does not count
        toward pathLenConstraint."""
        old_key = ec.generate_private_key(ec.SECP256R1())
        new_key = ec.generate_private_key(ec.SECP256R1())
        old_root0 = self.cert("root", old_key, "root", old_key, ca=True, path_length=0)
        old_root1 = self.cert("root", old_key, "root", old_key, ca=True, path_length=1)
        new_root = self.cert("root", new_key, "root", old_key, ca=True, path_length=1)
        inter = self.cert("ca", self.ca_key, "root", new_key, ca=True, path_length=0)
        # Valid rollover chain works regardless of CA order in the bundle.
        for cas in ([inter, new_root, old_root1], [old_root1, new_root, inter], [new_root, old_root1, inter]):
            self.check(self.ek(), cas)
        # Self-issued rollover directly issuing EK passes under path_length=0.
        direct_new = self.cert("ca", self.ca_key, "ca", old_key, ca=True, path_length=0)
        direct_old = self.cert("ca", old_key, "ca", old_key, ca=True, path_length=0)
        for cas in ([direct_new, direct_old], [direct_old, direct_new]):
            self.check(self.ek(), cas)
        # Non-self-issued intermediate below rollover still counts toward old_root0.
        with self.assertRaisesRegex(a.Fail, "path length constraint"):
            self.check(self.ek(), [inter, new_root, old_root0])
        # Rollover without its old root (or with an unrelated same-named root) fails.
        other_key = ec.generate_private_key(ec.SECP256R1())
        other_root = self.cert("root", other_key, "root", other_key, ca=True)
        for cas in ([inter, new_root], [inter, new_root, other_root]):
            with self.assertRaisesRegex(a.Fail, "self-signature does not verify"):
                self.check(self.ek(), cas)
        # Two mutually signing same-named CAs (no self-signed root): loop refused.
        loop_a = self.cert("ca", self.ca_key, "ca", old_key, ca=True)
        loop_b = self.cert("ca", old_key, "ca", self.ca_key, ca=True)
        for cas in ([loop_a, loop_b], [loop_b, loop_a]):
            with self.assertRaisesRegex(a.Fail, "EK CA chain loops"):
                self.check(self.ek(), cas)
        # Chain length boundary (EK_CHAIN_MAX) still holds.
        keys = [self.ca_key] + [ec.generate_private_key(ec.SECP256R1()) for _ in range(a.EK_CHAIN_MAX)]
        chain8 = [self.cert("c%d" % i, keys[i], "c%d" % (i + 1), keys[i + 1], ca=True) for i in range(a.EK_CHAIN_MAX - 1)]
        chain8[0] = self.cert("ca", keys[0], "c1", keys[1], ca=True)
        root8 = self.cert("c%d" % (a.EK_CHAIN_MAX - 1), keys[a.EK_CHAIN_MAX - 1],
                          "c%d" % (a.EK_CHAIN_MAX - 1), keys[a.EK_CHAIN_MAX - 1], ca=True)
        self.check(self.ek(), chain8 + [root8])
        chain9 = chain8 + [self.cert("c%d" % (a.EK_CHAIN_MAX - 1), keys[a.EK_CHAIN_MAX - 1],
                                     "c%d" % a.EK_CHAIN_MAX, keys[a.EK_CHAIN_MAX], ca=True),
                           self.cert("c%d" % a.EK_CHAIN_MAX, keys[a.EK_CHAIN_MAX],
                                     "c%d" % a.EK_CHAIN_MAX, keys[a.EK_CHAIN_MAX], ca=True)]
        with self.assertRaisesRegex(a.Fail, "EK CA chain longer than %d" % a.EK_CHAIN_MAX):
            self.check(self.ek(), chain9)


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


def ecc_public(key, attrs):
    """A TPMT_PUBLIC of an ECC P-256 signing key (ECDSA, sha256)."""
    n = key.public_key().public_numbers()
    return (struct.pack(">HHI", 0x0023, 0x000B, attrs) + struct.pack(">H", 0)
            + struct.pack(">HHHHH", 0x0010, 0x0018, 0x000B, 0x0003, 0x0010)
            + struct.pack(">H", 32) + n.x.to_bytes(32, "big") + struct.pack(">H", 32) + n.y.to_bytes(32, "big"))


class Enrollment(unittest.TestCase):
    """make-credential: an EK certificate is the host's word unless a CA
    the verifier trusts issued it, and only a TPM's restricted signing key
    is enrolled."""
    # fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth,
    # restricted, sign.
    AK_ATTRS = 1 << 1 | 1 << 4 | 1 << 5 | 1 << 6 | 1 << 16 | 1 << 18

    @classmethod
    def setUpClass(cls):
        cls.ca_key = ec.generate_private_key(ec.SECP256R1())
        cls.ek = rsa.generate_private_key(65537, 2048)
        cls.ak = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)

        def cert(subject, key, issuer_key, ca):
            b = (x509.CertificateBuilder().subject_name(EkCertificate.name(subject)).issuer_name(EkCertificate.name("ca"))
                 .public_key(key.public_key()).serial_number(x509.random_serial_number())
                 .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
                 .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
            return b.sign(issuer_key, hashes.SHA256())
        cls.ca = cert("ca", cls.ca_key, cls.ca_key, True)
        cls.issued = cert("ek", cls.ek, cls.ca_key, False).public_bytes(serialization.Encoding.DER)
        # The host's own: a CA of its making that "issued" its key.
        forger = ec.generate_private_key(ec.SECP256R1())
        cls.forged = cert("ek", cls.ek, forger, False).public_bytes(serialization.Encoding.DER)
        tmp = tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False)
        tmp.write(cls.ca.public_bytes(serialization.Encoding.PEM))
        tmp.close()
        cls.ca_pem = tmp.name

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.ca_pem)

    def ek_of(self, ev, ek_ca=None):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            ek = a.evidence_ek(ev, None, ek_ca)
        return ek.public_numbers(), err.getvalue()

    def test_certificate_checked_with_ek_ca(self):
        got, warning = self.ek_of({"ekcert": self.issued}, self.ca_pem)
        self.assertEqual(got, self.ek.public_key().public_numbers())
        self.assertNotIn("l4h-attest: warning", warning)
        with self.assertRaisesRegex(a.Fail, "not issued by"):
            self.ek_of({"ekcert": self.forged}, self.ca_pem)
        # Asked for, a certificate must be there: ekpub is not one.
        with self.assertRaisesRegex(a.Fail, "no EK certificate"):
            self.ek_of({"ekpub": rsa_public(self.ek, EvidenceEk.EK_ATTRS)}, self.ca_pem)
        with self.assertRaisesRegex(a.Fail, "malformed EK certificate"):
            self.ek_of({"ekcert": b"\x30\x00"}, self.ca_pem)

    def test_unchecked_certificate_warns(self):
        for cert in (self.issued, self.forged):
            got, warning = self.ek_of({"ekcert": cert})
            self.assertEqual(got, self.ek.public_key().public_numbers())
            self.assertIn("EK certificate not verified (--ek-ca)", warning)

    def test_only_a_restricted_signing_key_is_enrolled(self):
        key, name = a.attestation_key({"ak": ecc_public(self.ak, self.AK_ATTRS)})
        self.assertEqual(key.public_numbers(), self.ak.public_key().public_numbers())
        self.assertEqual(name, a.tpm_name(ecc_public(self.ak, self.AK_ATTRS)))
        for attrs in (self.AK_ATTRS & ~(1 << 16), self.AK_ATTRS & ~(1 << 18), self.AK_ATTRS & ~(1 << 1)):
            with self.assertRaisesRegex(a.Fail, "fixedTPM restricted signing"):
                a.attestation_key({"ak": ecc_public(self.ak, attrs)})
        with self.assertRaisesRegex(a.Fail, "not ECC"):
            a.attestation_key({"ak": rsa_public(self.ek, self.AK_ATTRS)})

    def run_tool(self, *args):
        tool = Path(__file__).resolve().parents[1] / "tools/l4h-attest.py"
        return subprocess.run([sys.executable, str(tool), *args], capture_output=True, text=True)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            ev = os.path.join(d, "evidence")
            out = os.path.join(d, "cred")
            body = {"ak": ecc_public(self.ak, self.AK_ATTRS), "ekcert": self.forged}
            with open(ev, "wb") as f:
                f.write(encode(body))
            r = self.run_tool("make-credential", ev, "00" * 32, "-o", out, "--ek-ca", self.ca_pem)
            self.assertEqual((r.returncode, r.stderr.strip()), (1, "l4h-attest: EK certificate not issued by %s" % self.ca_pem))
            self.assertFalse(os.path.exists(out))
            with open(ev, "wb") as f:
                f.write(encode({**body, "ekcert": self.issued}))
            r = self.run_tool("make-credential", ev, "00" * 32, "-o", out, "--ek-ca", self.ca_pem)
            self.assertEqual(r.returncode, 0)
            self.assertNotIn("l4h-attest: warning", r.stderr)
            self.assertTrue(os.path.getsize(out) > 0)
            # An AK that is not a restricted signing key, and a malformed
            # one: refused, as l4h-attest's errors.
            # The guest driver's combined evidence (v 3): its TPM part.
            with open(ev, "wb") as f:
                f.write(cbor({"v": 3, "tdx": {"v": 1, "type": "tdx"}, "tpm": {**body, "ekcert": self.issued}}))
            r = self.run_tool("make-credential", ev, "00" * 32, "-o", out + "3", "--ek-ca", self.ca_pem)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.getsize(out + "3") > 0)
            # TDX evidence alone has no TPM to make a credential for.
            with open(ev, "wb") as f:
                f.write(cbor({"v": 1, "type": "tdx", "key": {}, "quote": b""}))
            r = self.run_tool("make-credential", ev, "00" * 32, "-o", out + "4")
            self.assertEqual((r.returncode, r.stderr.strip()), (1, "l4h-attest: no TPM evidence in this file"))
            for ak, why in ((ecc_public(self.ak, self.AK_ATTRS & ~(1 << 16)), "restricted signing key"),
                            (b"\x00\x23", "truncated")):
                with open(ev, "wb") as f:
                    f.write(encode({**body, "ekcert": self.issued, "ak": ak}))
                r = self.run_tool("make-credential", ev, "00" * 32, "-o", out + "2", "--ek-ca", self.ca_pem)
                self.assertEqual(r.returncode, 1)
                self.assertRegex(r.stderr, "^l4h-attest: .*%s" % why)
                self.assertNotIn("Traceback", r.stderr)


def quote(extra, pcrs):
    """A TPMS_ATTEST of a quote of sha256 PCRs `pcrs` (index: value)."""
    sel = bytearray(3)
    for i in pcrs:
        sel[i // 8] |= 1 << (i % 8)
    digest = hashlib.sha256(b"".join(pcrs[i] for i in sorted(pcrs))).digest()
    return (struct.pack(">IH", 0xFF544347, 0x8018) + struct.pack(">H", 0) + struct.pack(">H", len(extra)) + extra
            + struct.pack(">QIIBQ", 1, 2, 3, 1, 4) + struct.pack(">IHB", 1, 0x000B, 3) + bytes(sel)
            + struct.pack(">H", 32) + digest)


def tpm_signature(key, data):
    r, s_ = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return struct.pack(">HH", 0x0018, 0x000B) + struct.pack(">H", 32) + r.to_bytes(32, "big") + struct.pack(">H", 32) + s_.to_bytes(32, "big")


class Evidence(unittest.TestCase):
    """The evidence's integers are integers, not CBOR's true or false, and
    its TPM structures end where they should."""

    @classmethod
    def setUpClass(cls):
        cls.ak = ec.generate_private_key(ec.SECP256R1())
        cls.host = ec.generate_private_key(ec.SECP256R1())
        cls.other = ec.generate_private_key(ec.SECP256R1())
        cls.ek = rsa.generate_private_key(65537, 2048)

    def evidence(self, partition=None, chain=None, **over):
        n = self.host.public_key().public_numbers()
        key = {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
        binding = a.key_binding(a.point(self.host.public_key()), partition)
        pcr15 = bytes(32)
        for k, pt in chain or []:
            pcr15 = hashlib.sha256(pcr15 + a.key_binding(pt, k)).digest()
        pcrs = {0: bytes([7]) * 32, a.KEY_PCR: pcr15}
        q = quote(binding, pcrs)
        ev = {"v": 1 if partition is None else 2, "ak": ecc_public(self.ak, Enrollment.AK_ATTRS), "key": key,
              "pcrs": pcrs, "quote": q, "quotesig": tpm_signature(self.ak, q)}
        if partition is not None:
            ev["partition"] = partition
            ev["chain"] = [list(e) for e in chain or []]
        ev.update(over)
        return ev

    def check(self, ev):
        return a.check_evidence(ev, {}, None, None)

    def test_good(self):
        key, partition, host = self.check(self.evidence())
        self.assertEqual((key.public_numbers(), partition), (self.host.public_key().public_numbers(), None))
        other = a.point(self.other.public_key())
        key, partition, host = self.check(self.evidence(1, [(0, other)]))
        self.assertEqual((partition, host["partition"], host["keys_before"]), (1, 1, [0]))
        self.assertIs(type(host["partition"]), int)

    def test_secondary_partition_needs_a_key_chain(self):
        # Partition 0 quotes first and extends PCR 15 with its key before
        # serving any other partition: a secondary partition's evidence
        # with no key before its own (PCR 15 still zero) cannot be.
        for p in range(1, 8):
            with self.assertRaisesRegex(a.Fail, "key chain is empty"):
                self.check(self.evidence(p, []))
        # Partition 0's own evidence has none, and needs none.
        key, partition, host = self.check(self.evidence(0, []))
        self.assertEqual((partition, host["keys_before"]), (0, []))

    def test_booleans_are_not_integers(self):
        with self.assertRaisesRegex(a.Fail, "evidence version"):
            self.check(self.evidence(v=True))
        # Bound to partition 1, as true would be.
        ev = self.evidence(1, [(0, a.point(self.other.public_key()))])
        with self.assertRaisesRegex(a.Fail, "valid partition"):
            self.check({**ev, "partition": True})
        # Partition 0's key first, as false would be.
        ev = self.evidence(1, [(0, a.point(self.other.public_key()))])
        with self.assertRaisesRegex(a.Fail, "malformed key chain"):
            self.check({**ev, "chain": [[False, a.point(self.other.public_key())]]})
        for k in (-1, 8):
            with self.assertRaisesRegex(a.Fail, "malformed key chain"):
                self.check({**ev, "chain": [[k, a.point(self.other.public_key())]]})
        ev = self.evidence()
        pcrs = dict(ev["pcrs"])
        pcrs[True] = pcrs.pop(0)
        with self.assertRaisesRegex(a.Fail, "PCRs"):
            self.check({**ev, "pcrs": pcrs})

    def test_pcr_values_are_digests(self):
        # The TPM quoted PCRs 0..16 after trustd extended PCR 15 with the
        # real host key; the evidence moves the boundaries between the
        # values so that their concatenation, and so the digest, stays the
        # same, but PCR 15 reads as zero.
        n = self.host.public_key().public_numbers()
        key = {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
        real = {i: bytes([i + 1]) * 32 for i in range(16)}
        real[16] = bytes(32)
        q = quote(a.key_binding(a.point(self.host.public_key()), None), real)
        shifted = {i: real[i] for i in range(14)}
        shifted[14] = real[14] + real[15]
        shifted[a.KEY_PCR] = bytes(32)
        shifted[16] = b""
        self.assertEqual(b"".join(shifted[i] for i in sorted(shifted)), b"".join(real[i] for i in sorted(real)))
        ev = {"v": 1, "ak": ecc_public(self.ak, Enrollment.AK_ATTRS), "key": key, "pcrs": shifted, "quote": q,
              "quotesig": tpm_signature(self.ak, q)}
        pins = {i: real[i] for i in range(14)}
        with self.assertRaisesRegex(a.Fail, "PCRs are not a map"):
            a.check_evidence(ev, pins, None, None)
        for bad in (b"", bytes(31), bytes(33), bytes(64)):
            ev = self.evidence()
            with self.assertRaisesRegex(a.Fail, "PCRs are not a map", msg=len(bad)):
                self.check({**ev, "pcrs": {**ev["pcrs"], 0: bad}})

    def test_host_key_fields(self):
        n = self.host.public_key().public_numbers()
        x, y = n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")
        self.assertEqual(a.cose_p256({1: 2, -1: 1, -2: x, -3: y}).public_numbers(), n)
        for k in ({1: 2, -1: True, -2: x, -3: y}, {1: 2.0, -1: 1, -2: x, -3: y}, {1: 2, -1: 1.0, -2: x, -3: y},
                  {1: 2, -1: 1, -2: b"\0" + x, -3: y}, {1: 2, -1: 1, -2: x, -3: y[1:]},
                  {1: 2, -1: 1, -2: n.x, -3: y}, {1: 2, -1: 1, -2: x, -3: list(y)}, {1: 2, -1: 1, -2: x}):
            with self.assertRaises(a.Fail, msg=repr(k)[:60]):
                a.cose_p256(k)

    def test_trailing_bytes(self):
        ev = self.evidence()
        for field in ("ak", "quote", "quotesig"):
            bad = {**ev, field: ev[field] + b"\0"}
            if field == "quote":
                bad["quotesig"] = tpm_signature(self.ak, bad["quote"])
            with self.assertRaisesRegex(a.Fail, "trailing bytes", msg=field):
                self.check(bad)
        with self.assertRaisesRegex(a.Fail, "trailing bytes"):
            a.parse_public(rsa_public(self.ek, EvidenceEk.EK_ATTRS) + b"\0")

    def test_public_area_parameters(self):
        n = self.ak.public_key().public_numbers()
        point = struct.pack(">H", 32) + n.x.to_bytes(32, "big") + struct.pack(">H", 32) + n.y.to_bytes(32, "big")

        def ecc(params):
            return struct.pack(">HHI", 0x0023, 0x000B, Enrollment.AK_ATTRS) + struct.pack(">H", 0) + params + point

        good = (
            struct.pack(">HHHHH", 0x0010, 0x0018, 0x000B, 0x0003, 0x0010),  # ECDSA
            struct.pack(">HHHHHH", 0x0010, 0x001A, 0x000B, 1, 0x0003, 0x0010),  # ECDAA, with a count
            struct.pack(">HHHHHHH", 0x0006, 128, 0x0043, 0x0010, 0x0003, 0x0007, 0x000B),  # AES, MGF1
        )
        for params in good:
            _, key = a.parse_public(ecc(params))
            self.assertEqual(key.public_numbers(), n, params.hex())
        bad = (
            struct.pack(">HHHHH", 0x000A, 0x0018, 0x000B, 0x0003, 0x0010),  # XOR is no object's
            struct.pack(">HHHHHH", 0x0001, 128, 0x0043, 0x0018, 0x000B, 0x0003),  # RSA is not symmetric
            struct.pack(">HHHHH", 0x0010, 0x0042, 0x000B, 0x0003, 0x0010),  # unknown scheme
            struct.pack(">HHHHH", 0x0010, 0x0018, 0x000B, 0x0003, 0x0042),  # unknown KDF
        )
        for params in bad:
            with self.assertRaisesRegex(a.Fail, "unknown", msg=params.hex()):
                a.parse_public(ecc(params))
        # RSAES has no details: the key bits come next.
        k = self.ek
        m = k.public_key().public_numbers().n.to_bytes(256, "big")
        rsaes = (struct.pack(">HHI", 0x0001, 0x000B, EvidenceEk.EK_ATTRS) + struct.pack(">H", 0)
                 + struct.pack(">HHHHHI", 0x0006, 128, 0x0043, 0x0015, 2048, 0) + struct.pack(">H", 256) + m)
        self.assertEqual(a.parse_public(rsaes)[1].public_numbers(), k.public_key().public_numbers())

    def test_report_integers(self):
        v = Verify()
        v.key = self.host
        rep = v.signed(taint=bitmap(), seal=bitmap(0))
        v.check(rep)
        for claims in ({"v": True}, {"v": 2, "partition": True}):
            with self.assertRaisesRegex(a.Fail, "version|partition", msg=repr(claims)):
                a.check_report(signed_claims(self.host, claims), self.host.public_key(), None, None,
                               partition=1 if "partition" in claims else None)


def signed_claims(key, extra):
    """A report with the claims Verify.signed() gives, and `extra`."""
    c = {"v": 1, "host": hashlib.sha256(a.point(key.public_key())).digest(), "taint": bitmap(), "seal": bitmap(0), **extra}
    p, protected = encode(c), b"\xa1\x01\x26"
    tbs = b"\x84\x6aSignature1" + a.cbor_bytes(protected) + b"\x40" + a.cbor_bytes(p)
    r, s_ = decode_dss_signature(key.sign(tbs, ec.ECDSA(hashes.SHA256())))
    return ("tag", 18, [protected, {}, p, r.to_bytes(32, "big") + s_.to_bytes(32, "big")])


class Malformed(unittest.TestCase):
    """Whatever the host sends, a check fails with Fail, never another
    exception: a caller that handles Fail is not crashed, and the tool
    says what was wrong."""

    def test_evidence(self):
        ak = ecc_public(ec.generate_private_key(ec.SECP256R1()), Enrollment.AK_ATTRS)
        # Off the curve: a point (1, 1).
        off_curve = ak[:-68] + struct.pack(">H", 32) + (1).to_bytes(32, "big") + struct.pack(">H", 32) + (1).to_bytes(32, "big")
        for ev in ([], "v", {"v": 1}, {"v": 1, "ak": 5}, {"v": 1, "ak": b"\x00"}, {"v": 1, "ak": ak[:20]},
                   {"v": 1, "ak": off_curve}, {"v": 1, "ak": ak}, {"v": 1, "ak": ak, "quotesig": b"", "quote": b""},
                   {"v": 2, "partition": 0, "ak": ak}):
            with self.assertRaises(a.Fail, msg=repr(ev)[:80]):
                a.check_evidence(ev, {}, None, None)
        for ev in ([], {"ak": 5}, {"ekcert": 5}, {"ekpub": b"\x00\x01"}):
            with self.assertRaises(a.Fail, msg=repr(ev)), contextlib.redirect_stderr(io.StringIO()):
                a.evidence_ek(ev)
        for ev in ({}, {"ak": None}, {"ak": b"\x00\x23\x00"}):
            with self.assertRaises(a.Fail, msg=repr(ev)):
                a.attestation_key(ev)
        with self.assertRaises(a.Fail):
            a.tpm_name(b"\x00")
        with self.assertRaises(a.Fail):
            a.cose_p256({1: 2, -1: 1, -2: b"\x01", -3: b"\x01"})
        with self.assertRaises(a.Fail):
            a.cose_p256({1: 2, -1: 1, -2: 5})
        with self.assertRaises(a.Fail):
            a.make_credential(object(), b"\x00\x0b" + bytes(32), b"s")

    def test_report(self):
        key = ec.generate_private_key(ec.SECP256R1()).public_key()
        for rep in (None, ("tag", 18, 5), ("tag", 18, [1, 2, 3, 4]), ("tag", 18, [b"\xa1\x01\x26", {}, 5, bytes(64)]),
                    ("tag", 18, [b"\xa1\x01\x26", {}, b"", bytes(64)])):
            with self.assertRaises(a.Fail, msg=repr(rep)):
                a.check_report(rep, key, None, None)
        # Signed, but claims that are not a map, or lack the host.
        v = Verify()
        v.key = ec.generate_private_key(ec.SECP256R1())
        for claims in (b"\x05", encode({"v": 1})):
            protected = b"\xa1\x01\x26"
            tbs = b"\x84\x6aSignature1" + a.cbor_bytes(protected) + b"\x40" + a.cbor_bytes(claims)
            r, s_ = decode_dss_signature(v.key.sign(tbs, ec.ECDSA(hashes.SHA256())))
            rep = ("tag", 18, [protected, {}, claims, r.to_bytes(32, "big") + s_.to_bytes(32, "big")])
            with self.assertRaises(a.Fail, msg=repr(claims)):
                a.check_report(rep, v.key.public_key(), None, None)

    def test_kernel(self):
        k = Launch.kernel()
        # Cut in the ELF header, and in the program header.
        for bad in (k[:30], k[:60], k[:64 + 20]):
            with self.assertRaises(a.Fail):
                a.launch_digest(bad, b"", "")


SHA1, SHA256, SHA384 = 0x0004, 0x000B, 0x000C
SIZES = {SHA1: 20, SHA256: 32, SHA384: 48}


def spec_id(algs=(SHA1, SHA256, SHA384), vendor=b""):
    """The log's header: a TCG_PCR_EVENT holding the Spec ID event."""
    body = (b"Spec ID Event03\0" + struct.pack("<IBBBB", 0, 0, 2, 0, 2) + struct.pack("<I", len(algs))
            + b"".join(struct.pack("<HH", alg, SIZES[alg]) for alg in algs) + bytes([len(vendor)]) + vendor)
    return struct.pack("<II", 0, 3) + bytes(20) + struct.pack("<I", len(body)) + body


def event2(pcr, kind, data, algs=(SHA1, SHA256, SHA384), digests=None):
    """A TCG_PCR_EVENT2 measuring `data` in every bank (or with `digests`)."""
    if digests is None:
        digests = {alg: hashlib.new({SHA1: "sha1", SHA256: "sha256", SHA384: "sha384"}[alg], data).digest() for alg in algs}
    return (struct.pack("<III", pcr, kind, len(digests)) + b"".join(struct.pack("<H", alg) + d for alg, d in digests.items())
            + struct.pack("<I", len(data)) + data)


def cbor(x):
    """Any CBOR the tools read: negative keys (COSE), tags (COSE_Sign1)."""
    def head(major, n):
        for limit, extra in ((24, 0), (1 << 8, 1), (1 << 16, 2), (1 << 32, 4), (1 << 64, 8)):
            if n < limit:
                code = n if not extra else {1: 24, 2: 25, 4: 26, 8: 27}[extra]
                return bytes([major << 5 | code]) + (n.to_bytes(extra, "big") if extra else b"")
    if isinstance(x, tuple):
        return head(6, x[1]) + cbor(x[2])
    if isinstance(x, bytes):
        return head(2, len(x)) + x
    if isinstance(x, str):
        return head(3, len(x.encode())) + x.encode()
    if isinstance(x, list):
        return head(4, len(x)) + b"".join(map(cbor, x))
    if isinstance(x, dict):
        return head(5, len(x)) + b"".join(cbor(k) + cbor(v) for k, v in x.items())
    if x is True or x is False:
        return b"\xf5" if x else b"\xf4"
    return head(0, x) if x >= 0 else head(1, -1 - x)


def extend(pcr, *datas):
    for d in datas:
        pcr = hashlib.sha256(pcr + hashlib.sha256(d).digest()).digest()
    return pcr


class EventLog(unittest.TestCase):
    """The UEFI TPM event log replays to the quoted PCRs 0-14."""

    EVENTS = [(0, 0x8, b"crtm version"), (0, 0x80000008, b"firmware blob"), (7, 0x80000001, b"SecureBoot"),
              (1, 0x80000002, b"BootOrder"), (4, 0x80000003, b"l4h efi app"), (2, 0x4, b"\0\0\0\0"),
              (5, 0x80000007, b"Exit Boot Services Invocation")]

    def log(self, events=EVENTS, header=None, extra=b""):
        return (header if header is not None else spec_id()) + b"".join(event2(*e) for e in events) + extra

    def replayed(self, events=EVENTS, pcr0=bytes(32)):
        pcrs = {i: bytes(32) for i in range(15)}
        pcrs[0] = pcr0
        for i, _, d in events:
            pcrs[i] = extend(pcrs[i], d)
        return pcrs

    def test_replay_banks(self):
        pcrs, events = a.replay_event_log(self.log())
        self.assertEqual(len(events), len(self.EVENTS))
        want = self.replayed()
        self.assertEqual({i: pcrs[i] for i in range(15)}, want)
        # PC Client: 17-22 start at all ones, the rest at zeros.
        self.assertEqual(pcrs[17], b"\xff" * 32)
        self.assertEqual(pcrs[23], bytes(32))
        # A SHA-256-only log too.
        log = spec_id((SHA256,)) + b"".join(event2(*e, algs=(SHA256,)) for e in self.EVENTS)
        self.assertEqual({i: a.replay_event_log(log)[0][i] for i in range(15)}, want)
        self.assertEqual(a.check_event_log(self.log(), {**want, 15: bytes(32)}), len(self.EVENTS))

    def test_startup_locality(self):
        loc = event2(0, 3, b"StartupLocality\0\x03", digests={SHA1: bytes(20), SHA256: bytes(32), SHA384: bytes(48)})
        log = spec_id() + loc + b"".join(event2(*e) for e in self.EVENTS)
        pcrs, _ = a.replay_event_log(log)
        self.assertEqual(pcrs[0], self.replayed(pcr0=bytes(31) + b"\x03")[0])
        # Only before PCR 0 is extended.
        log = spec_id() + event2(*self.EVENTS[0]) + loc + b"".join(event2(*e) for e in self.EVENTS[1:])
        self.assertEqual(a.replay_event_log(log)[0][0], self.replayed()[0])
        # Locality 0 too; reserved values (neither 0, 3 nor 4) are refused.
        zero = event2(0, 3, b"StartupLocality\0\x00", digests={SHA256: bytes(32)})
        self.assertEqual(a.replay_event_log(spec_id() + zero + b"".join(event2(*e) for e in self.EVENTS))[0][0],
                         self.replayed()[0])
        for bad in (1, 2, 5, 0xFF):
            ev = event2(0, 3, b"StartupLocality\0" + bytes([bad]), digests={SHA256: bytes(32)})
            with self.assertRaisesRegex(a.Fail, "StartupLocality %d is not 0, 3 or 4" % bad):
                a.replay_event_log(spec_id() + ev + b"".join(event2(*e) for e in self.EVENTS))

    def test_startup_locality_4_hcrtm(self):
        """PFP 1.06 rev52 3.3.4.1 & 10.4.5.3: StartupLocality 4 and
        EV_EFI_HCRTM_EVENT ("HCRTM") are symmetrically paired once on PCR 0's
        first extend, allowing intervening EV_NO_ACTION or other-PCR events."""
        loc = lambda v, pcr=0: event2(pcr, 3, b"StartupLocality\0" + bytes([v]), digests={SHA256: bytes(32)})
        loc4 = loc(4)
        # EventData is fixed 5-byte "HCRTM"; the bank digest is the hardware
        # measurement, not SHA-256("HCRTM") (PFP 1.06 rev52 10.4.5.5).
        hcrtm_digest = hashlib.sha256(b"hw-measured-hcrtm-components").digest()
        hcrtm_ev = event2(0, a.EV_EFI_HCRTM_EVENT, b"HCRTM", digests={SHA256: hcrtm_digest})
        tail = b"".join(event2(*e) for e in self.EVENTS)
        pcr0 = hashlib.sha256(bytes(31) + b"\x04" + hcrtm_digest).digest()
        want = self.replayed(events=self.EVENTS, pcr0=pcr0)

        log = spec_id() + loc4 + hcrtm_ev + tail
        pcrs, _ = a.replay_event_log(log)
        self.assertEqual({i: pcrs[i] for i in range(15)}, want)
        self.assertEqual(a.check_event_log(log, {**want, 15: bytes(32)}), len(self.EVENTS) + 2)

        # Intervening EV_NO_ACTION metadata and another PCR's event are allowed.
        no_action = event2(0, 3, b"SP800-155 Event3\0", digests={SHA256: bytes(32)})
        other_pcr = (7, 0x80000001, b"pre-hcrtm pcr7")
        log_interleaved = spec_id() + loc4 + no_action + event2(*other_pcr) + hcrtm_ev + tail
        pcrs_interleaved, _ = a.replay_event_log(log_interleaved)
        want_interleaved = self.replayed(events=[other_pcr] + list(self.EVENTS), pcr0=pcr0)
        self.assertEqual({i: pcrs_interleaved[i] for i in range(15)}, want_interleaved)

        # Symmetric rejections: missing/wrong/bare/duplicate H-CRTM or locality.
        bad_logs = [
            ("requires PCR 0's first event to be EV_EFI_HCRTM_EVENT", spec_id() + loc4 + tail),
            ("unexpected EV_EFI_HCRTM_EVENT", spec_id() + loc4 + event2(0, a.EV_EFI_HCRTM_EVENT, b"HCRTM\0") + tail),
            ("unexpected EV_EFI_HCRTM_EVENT", spec_id() + loc4 + event2(1, a.EV_EFI_HCRTM_EVENT, b"HCRTM") + tail),
            ("unexpected EV_EFI_HCRTM_EVENT", spec_id() + hcrtm_ev + tail),
            ("unexpected EV_EFI_HCRTM_EVENT", spec_id() + loc(0) + hcrtm_ev + tail),
            ("unexpected EV_EFI_HCRTM_EVENT", spec_id() + loc(3) + hcrtm_ev + tail),
            ("unexpected EV_EFI_HCRTM_EVENT", spec_id() + loc4 + hcrtm_ev + hcrtm_ev + tail),
            ("without a PCR 0 EV_EFI_HCRTM_EVENT", spec_id() + loc4),
            ("before it is extended", spec_id() + event2(*self.EVENTS[0]) + loc4 + hcrtm_ev),
            ("must be on PCR 0", spec_id() + loc(4, pcr=1) + hcrtm_ev),
            ("duplicate StartupLocality", spec_id() + loc(3) + loc4 + hcrtm_ev),
            ("duplicate StartupLocality", spec_id() + loc4 + loc(0) + hcrtm_ev),
            ("duplicate StartupLocality", spec_id() + loc4 + hcrtm_ev + loc(3) + tail),
        ]
        for why, bad in bad_logs:
            with self.assertRaisesRegex(a.Fail, why):
                a.replay_event_log(bad)

    def test_pcr15_is_trustds(self):
        """The firmware extending PCR 15 would have trustd's key quoted
        over a PCR 15 it did not start from zero."""
        events = self.EVENTS + [(a.KEY_PCR, 0xD, b"preloaded")]
        with self.assertRaisesRegex(a.Fail, "extends PCR 15, which is trustd's"):
            a.check_event_log(self.log(events), self.replayed())

    def test_no_action_not_extended(self):
        noise = event2(4, 3, b"NvIndexInstance\0", digests={SHA1: bytes(20), SHA256: b"\x55" * 32, SHA384: bytes(48)})
        log = spec_id() + noise + b"".join(event2(*e) for e in self.EVENTS) + noise
        pcrs, events = a.replay_event_log(log)
        self.assertEqual(len(events), len(self.EVENTS) + 2)
        self.assertEqual({i: pcrs[i] for i in range(15)}, self.replayed())

    def test_tampered_digest(self):
        want = self.replayed()
        log = bytearray(self.log())
        # The SHA-256 digest of the event that measured the EFI application.
        d = hashlib.sha256(b"l4h efi app").digest()
        at = bytes(log).index(d)
        log[at] ^= 1
        with self.assertRaisesRegex(a.Fail, "PCR 4 replays to"):
            a.check_event_log(bytes(log), want)
        # And a quote that differs from an honest log.
        with self.assertRaisesRegex(a.Fail, "PCR 7 replays to"):
            a.check_event_log(self.log(), {**want, 7: bytes(32)})
        with self.assertRaisesRegex(a.Fail, "PCR 3 is not quoted"):
            a.check_event_log(self.log(), {i: v for i, v in want.items() if i != 3})

    def test_malformed(self):
        good = self.log()
        cases = [
            b"", good[:10], good[:len(spec_id()) - 1],
            # Cut in the last event, and a byte past it.
            good[:-1], good + b"\0",
            # Not crypto agile (a TCG 1.2 log), and a Spec ID event with no
            # algorithms or a repeated one.
            struct.pack("<II", 0, 0x8) + bytes(20) + struct.pack("<I", 4) + b"abcd",
            self.log(header=spec_id(())), self.log(header=spec_id((SHA256, SHA256))),
            # An algorithm the header did not list; no SHA-256 at all.
            spec_id((SHA1, SHA256)) + event2(0, 8, b"x", algs=(SHA1, SHA384)),
            spec_id((SHA1,)) + event2(0, 8, b"x", algs=(SHA1,)),
            # An event without a SHA-256 digest, one past PCR 23, an event
            # size past the end.
            spec_id() + event2(0, 8, b"x", algs=(SHA1,)),
            spec_id() + event2(24, 8, b"x"),
            spec_id() + struct.pack("<III", 0, 8, 0) + struct.pack("<I", 0xFFFFFFFF),
            spec_id() + struct.pack("<III", 0, 8, 0xFFFFFFFF),
        ]
        for bad in cases:
            with self.assertRaises(a.Fail, msg=bad[:80].hex()):
                a.check_event_log(bad, self.replayed())

    def test_error_separator_rejected(self):
        # Normal EV_SEPARATOR (0x00000000) is already in EVENTS and passes;
        # error EV_SEPARATOR (0xffffffff) must be rejected.
        bad = self.log(self.EVENTS + [(4, 0x4, b"\xff\xff\xff\xff")])
        with self.assertRaisesRegex(a.Fail, r"error EV_SEPARATOR \(0xffffffff\) in PCR 4"):
            a.replay_event_log(bad)

    def test_verify_cli(self):
        Evidence.setUpClass()
        pcrs = {**self.replayed(), a.KEY_PCR: bytes(32)}
        n = Evidence.host.public_key().public_numbers()
        key = {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
        q = quote(a.key_binding(a.point(Evidence.host.public_key()), None), pcrs)
        ev = {"v": 1, "ak": ecc_public(Evidence.ak, Enrollment.AK_ATTRS), "key": key, "pcrs": pcrs, "quote": q,
              "quotesig": tpm_signature(Evidence.ak, q)}
        rep = signed_claims(Evidence.host, {"seal": bitmap(0), "taint": bitmap()})
        pcr_pins = ["--pcr", "4=" + pcrs[4].hex(), "--pcr", "9=" + pcrs[9].hex()]
        with tempfile.TemporaryDirectory() as d:
            paths = {}
            for name, data in (("ev", cbor(ev)), ("rep", cbor(rep)), ("log", self.log()),
                               ("bad", self.log(self.EVENTS[:-1]))):
                paths[name] = os.path.join(d, name)
                Path(paths[name]).write_bytes(data)
            tool = [sys.executable, str(Path(__file__).resolve().parents[1] / "tools/l4h-attest.py")]
            run = lambda *args: subprocess.run(tool + list(args), capture_output=True, text=True)
            r = run("verify", paths["rep"], paths["ev"], "--event-log", paths["log"],
                    "--insecure-unpinned-ak", "--insecure-unpinned-measurements")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('"event_log_events": %d' % len(self.EVENTS), r.stdout)
            self.assertIn('"measurements_pinned": false', r.stdout)
            self.assertIn("INSECURE: --insecure-unpinned-ak", r.stderr)
            self.assertIn("INSECURE: --insecure-unpinned-measurements", r.stderr)
            # The AK not pinned: refused by default; pinned without PCR 4 & 9: refused by default.
            r = run("verify", paths["rep"], paths["ev"])
            self.assertEqual(r.returncode, 1)
            self.assertRegex(r.stderr, "^l4h-attest: the attestation key is not pinned: .*--ak-name")
            self.assertEqual(r.stdout, "")
            ak = a.tpm_name(ev["ak"]).hex()
            for partial in ((), ("--pcr", "4=" + pcrs[4].hex()), ("--pcr", "9=" + pcrs[9].hex())):
                r = run("verify", paths["rep"], paths["ev"], "--ak-name", ak, *partial)
                self.assertEqual(r.returncode, 1, partial)
                self.assertIn("--insecure-unpinned-measurements", r.stderr)
            # Pinned AK and pinned PCR 4 & 9: passes with no warning.
            r = run("verify", paths["rep"], paths["ev"], "--ak-name", ak, *pcr_pins)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("event_log_events", r.stdout)
            self.assertIn('"measurements_pinned": true', r.stdout)
            self.assertNotIn("warning", r.stderr.lower())
            r = run("verify", paths["rep"], paths["ev"], "--ak-name", "000b" + "00" * 32, *pcr_pins)
            self.assertEqual(r.returncode, 1)
            self.assertIn("not the pinned one", r.stderr)
            r = run("verify", paths["rep"], paths["ev"], "--event-log", paths["bad"], "--ak-name", ak, *pcr_pins)
            self.assertEqual(r.returncode, 1)
            self.assertRegex(r.stderr, "^l4h-attest: event log does not match the quote: PCR 5 ")
            self.assertNotIn("Traceback", r.stderr)
            r = run("event-log", paths["log"])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('"EV_EFI_BOOT_SERVICES_APPLICATION"', r.stdout)
            r = run("event-log", paths["bad"] + "x")
            self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
