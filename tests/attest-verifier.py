#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Policy checks on signed reports, including old and future hosts."""
import hashlib
import importlib.util
from pathlib import Path
import unittest
import struct
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


def kexec_event(auth, previous, flags=3, control=0):
    initrd = hashlib.sha256(b"initrd" if flags & 1 else b"").digest()
    config = hashlib.sha256(b"config" if flags & 2 else b"").digest()
    return previous + auth + initrd + config + hashlib.sha256(b"boot").digest() + struct.pack("<II", flags, control)


def kexec_log(events):
    return a.KEXEC_LOG_MAGIC + struct.pack("<II", a.KEXEC_LOG_VERSION, len(events)) + b"".join(events)


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
    def test_kexec_log_replay_and_tampering(self):
        auth1, auth2 = b"\x11" * 32, b"\x22" * 32
        key1, key2 = b"\x33" * 32, b"\x44" * 32
        initrd, config = hashlib.sha256(b"initrd").digest(), hashlib.sha256(b"config").digest()
        event1, event2 = kexec_event(auth1, key1, control=0x8600000), kexec_event(auth2, key2)
        log = kexec_log([event1, event2])
        count, pcr14, pcr15, events = a.replay_kexec_log(log, {auth1, auth2}, {initrd}, {config})
        self.assertEqual(count, 2)
        self.assertEqual(pcr14, a.pcr_extend(a.pcr_extend(bytes(32), a.kexec_event_digest(event1)), a.kexec_event_digest(event2)))
        self.assertEqual(pcr15, a.pcr_extend(a.pcr_extend(bytes(32), key1), key2))
        self.assertEqual(events[0]["control"], 0x8600000)
        self.assertEqual(events[0]["initrd"], initrd.hex())
        self.assertEqual(events[1]["config"], config.hex())
        with self.assertRaisesRegex(a.Fail, "untrusted EFI"):
            a.replay_kexec_log(log, {auth1}, {initrd}, {config})
        with self.assertRaisesRegex(a.Fail, "missing a host key"):
            a.replay_kexec_log(kexec_log([kexec_event(auth1, bytes(32))]), {auth1}, {initrd}, {config})
        with self.assertRaisesRegex(a.Fail, "count"):
            a.replay_kexec_log(log + event2, {auth1, auth2}, {initrd}, {config})
        with self.assertRaisesRegex(a.Fail, "count"):
            a.replay_kexec_log(log[:-1], {auth1, auth2}, {initrd}, {config})

    def test_kexec_initrd_and_config_policy(self):
        auth, key = b"\x11" * 32, b"\x33" * 32
        initrd, config = hashlib.sha256(b"initrd").digest(), hashlib.sha256(b"config").digest()
        event = kexec_event(auth, key)
        for offset, name in ((64, "initrd"), (96, "l4h.conf")):
            bad = bytearray(event)
            bad[offset] ^= 1
            with self.assertRaisesRegex(a.Fail, "untrusted " + name):
                a.replay_kexec_log(kexec_log([bytes(bad)]), {auth}, {initrd}, {config})
        with self.assertRaisesRegex(a.Fail, "untrusted initrd"):
            a.replay_kexec_log(kexec_log([event]), {auth})
        with self.assertRaisesRegex(a.Fail, "missing a trusted initrd"):
            a.replay_kexec_log(kexec_log([kexec_event(auth, key, flags=2)]), {auth}, {initrd}, {config})
        bad = bytearray(kexec_event(auth, key, flags=2))
        bad[64] ^= 1
        with self.assertRaisesRegex(a.Fail, "absent initrd"):
            a.replay_kexec_log(kexec_log([bytes(bad)]), {auth}, set(), {config})

    def test_authenticode_gapped_sections(self):
        data = bytearray(0x200)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3c, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x84, 0x8664)
        struct.pack_into("<H", data, 0x86, 2)
        struct.pack_into("<H", data, 0x94, 0xf0)
        optional = 0x98
        struct.pack_into("<H", data, optional, 0x20b)
        struct.pack_into("<I", data, optional + 60, 0x200)
        struct.pack_into("<I", data, optional + 108, 16)
        section = optional + 0xf0
        struct.pack_into("<II", data, section + 16, 0x80, 0x200)
        struct.pack_into("<II", data, section + 40 + 16, 0x40, 0x300)
        data.extend(bytes(i % 251 for i in range(0x80)))
        data.extend(b"\x5a" * 0x80)
        data.extend(bytes(0x80 + i for i in range(0x40)))

        checksum = optional + 64
        security = optional + 112 + 4 * 8
        hashed_size = 0x200 + 0x80 + 0x40
        expected = (data[:checksum] + data[checksum + 4:security] + data[security + 8:0x200]
                    + data[0x200:0x280] + data[0x300:0x340] + data[hashed_size:])
        self.assertEqual(a.authenticode_digest(bytes(data)), hashlib.sha256(expected).digest())


if __name__ == "__main__":
    unittest.main()
