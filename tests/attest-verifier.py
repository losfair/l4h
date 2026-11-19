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

    def cert(self, subject, key, issuer, issuer_key, ca=None, key_usage=None, eku=None, days=(-1, 1)):
        b = (x509.CertificateBuilder().subject_name(self.name(subject)).issuer_name(self.name(issuer))
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(self.now + datetime.timedelta(days=days[0]))
             .not_valid_after(self.now + datetime.timedelta(days=days[1])))
        if ca is not None:
            b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
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


if __name__ == "__main__":
    unittest.main()
