#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Policy checks on signed reports, including old and future hosts."""
import hashlib
import importlib.util
from pathlib import Path
import unittest
import sys

sys.dont_write_bytecode = True
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
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


if __name__ == "__main__":
    unittest.main()
