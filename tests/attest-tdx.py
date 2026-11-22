#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""tools/l4h-attest.py on Intel TDX: DCAP quotes v4 and v5 down to a root
CA made here (PCK chain with real SGX extensions, QE report, TCB info, QE
identity and CRLs signed as Intel's are), the host key's binding, a guest's
fresh quote, the CC event log, evidence of both roots of trust together,
fetch-collateral, and every tampering the verifier must refuse."""
import contextlib
import copy
import datetime
import hashlib
import importlib.util
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

TOOL = Path(__file__).resolve().parents[1] / "tools/l4h-attest.py"
spec = importlib.util.spec_from_file_location("attest", TOOL)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

NOW = datetime.datetime.now(datetime.timezone.utc)
SHA256, SHA384 = 0x000B, 0x000C


def cbor(x):
    """Deterministic enough CBOR for what the host writes (maps as given)."""
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


# ---- DER, for the PCK certificate's SGX extensions


def der(tag, body):
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(b)]) + b + body


def der_oid(s):
    p = [int(x) for x in s.split(".")]
    out = bytearray([40 * p[0] + p[1]])
    for n in p[2:]:
        enc = [n & 0x7F]
        n >>= 7
        while n:
            enc.append(0x80 | n & 0x7F)
            n >>= 7
        out += bytes(reversed(enc))
    return der(0x06, bytes(out))


def der_int(n):
    return der(0x02, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big"))


def sgx_extension(fmspc, pceid, comps, pcesvn, cpusvn=bytes(range(16))):
    o = a.SGX_EXTENSIONS_OID
    tcb = [der(0x30, der_oid("%s.2.%d" % (o, i + 1)) + der_int(c)) for i, c in enumerate(comps)]
    tcb.append(der(0x30, der_oid(o + ".2.17") + der_int(pcesvn)))
    tcb.append(der(0x30, der_oid(o + ".2.18") + der(0x04, cpusvn)))
    entries = [
        der(0x30, der_oid(o + ".1") + der(0x04, bytes(16))),
        der(0x30, der_oid(o + ".2") + der(0x30, b"".join(tcb))),
        der(0x30, der_oid(o + ".3") + der(0x04, pceid)),
        der(0x30, der_oid(o + ".4") + der(0x04, fmspc)),
        der(0x30, der_oid(o + ".5") + der(0x0A, b"\x00")),
    ]
    return der(0x30, b"".join(entries))


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Intel")])


def key_usage(sign=False, cert_sign=False, crl_sign=False):
    return x509.KeyUsage(digital_signature=sign, content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement=False, key_cert_sign=cert_sign, crl_sign=crl_sign,
                         encipher_only=False, decipher_only=False)


def cert(subject, key, issuer, issuer_key, ca, days=(-1, 365), ext=None, serial=None, ku=None):
    b = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer))
         .public_key(key.public_key()).serial_number(serial or x509.random_serial_number())
         .not_valid_before(NOW + datetime.timedelta(days=days[0])).not_valid_after(NOW + datetime.timedelta(days=days[1]))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ku is not None:
        b = b.add_extension(ku, critical=True)
    elif ca:
        b = b.add_extension(key_usage(cert_sign=True, crl_sign=True), critical=True)
    if ext is not None:
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(a.SGX_EXTENSIONS_OID), ext), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def pem(*certs):
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def raw_sig(key, data):
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def xy(key):
    n = key.public_key().public_numbers()
    return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")


def crl(issuer_cert, issuer_key, revoked=(), days=(-1, 30)):
    b = (x509.CertificateRevocationListBuilder().issuer_name(issuer_cert.subject)
         .last_update(NOW + datetime.timedelta(days=days[0])).next_update(NOW + datetime.timedelta(days=days[1])))
    for serial in revoked:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(NOW).build())
    return b.sign(issuer_key, hashes.SHA256())


FMSPC = bytes.fromhex("00806f050000")
PCEID = bytes.fromhex("0000")
PCK_COMPS = [3, 3, 2, 2, 4, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]
PCESVN = 11
MRSIGNER_QE = bytes(range(32))
MRSIGNERSEAM = bytes(48)
TEE_TCB_SVN = bytes([3, 0, 5] + [0] * 13)


class Intel:
    """A root CA, PCK CA and leaf, the QE's report and a TCB signing
    certificate, made once, as Intel's are."""

    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = cert("Intel SGX Root CA", self.root_key, "Intel SGX Root CA", self.root_key, True, days=(-10, 3650))
        self.pck_ca_key = ec.generate_private_key(ec.SECP256R1())
        self.pck_ca = cert("Intel SGX PCK Platform CA", self.pck_ca_key, "Intel SGX Root CA", self.root_key, True)
        self.pck_key = ec.generate_private_key(ec.SECP256R1())
        self.pck = cert("Intel SGX PCK Certificate", self.pck_key, "Intel SGX PCK Platform CA", self.pck_ca_key, False,
                        ext=sgx_extension(FMSPC, PCEID, PCK_COMPS, PCESVN))
        self.tcb_key = ec.generate_private_key(ec.SECP256R1())
        self.tcb = cert("Intel SGX TCB Signing", self.tcb_key, "Intel SGX Root CA", self.root_key, False,
                        ku=key_usage(sign=True))
        self.att_key = ec.generate_private_key(ec.SECP256R1())


def tdreport_fields(reportdata, rtmr3=bytes(48), debug=False, mrtd=b"\x11" * 48, rtmrs=(b"\x21" * 48, b"\x22" * 48, b"\x23" * 48),
                    tee_tcb_svn=TEE_TCB_SVN):
    attrs = bytearray(8)
    attrs[0] = 1 if debug else 0
    return {
        "tee_tcb_svn": tee_tcb_svn, "mrseam": b"\x05" * 48, "mrsignerseam": MRSIGNERSEAM, "seam_attributes": bytes(8),
        "td_attributes": bytes(attrs), "xfam": b"\xe7\x02" + bytes(6), "mrtd": mrtd, "mrconfigid": bytes(48),
        "mrowner": bytes(48), "mrownerconfig": bytes(48), "rtmr0": rtmrs[0], "rtmr1": rtmrs[1], "rtmr2": rtmrs[2],
        "rtmr3": rtmr3, "reportdata": reportdata, "tee_tcb_svn2": tee_tcb_svn, "mrservicetd": bytes(48),
    }


def qe_report(att_key_xy, auth, isvsvn=8, mrsigner=MRSIGNER_QE, prodid=2, reportdata=None):
    r = bytearray(384)
    r[48:64] = bytes([0x11]) + bytes(15)
    r[128:160] = mrsigner
    struct.pack_into("<HH", r, 256, prodid, isvsvn)
    r[320:352] = hashlib.sha256(att_key_xy + auth).digest() if reportdata is None else reportdata
    return bytes(r)


def make_quote(intel, fields, version=4, body_type=2, chain=None, tamper=None):
    """A TDX DCAP quote over `fields`.  `tamper` changes a part before it is
    signed or assembled ({"header": f, "qe_report": f, ...})."""
    tamper = tamper or {}
    header = bytearray(48)
    struct.pack_into("<HHIHH", header, 0, version, 2, 0x81, 13, 8)
    header[12:28] = a.INTEL_QE_VENDOR_ID
    header = bytes(tamper.get("header", lambda h: h)(bytes(header)))
    size = a.TD15_BODY if body_type == 3 else a.TD10_BODY
    body = bytearray(size)
    for n, off, ln in a.TD_BODY_FIELDS:
        if off + ln <= size:
            body[off:off + ln] = fields[n]
    desc = struct.pack("<HI", body_type, size) if version == 5 else b""
    signed = header + desc + bytes(body)
    att = xy(intel.att_key)
    auth = bytes(range(32))
    qe = tamper.get("qe_report", lambda q: q)(qe_report(att, auth))
    qe_sig = tamper.get("qe_sig", lambda s: s)(raw_sig(intel.pck_key, qe))
    chain = pem(intel.pck, intel.pck_ca, intel.root) if chain is None else chain
    inner = struct.pack("<HI", 5, len(chain)) + chain
    cert = qe + qe_sig + struct.pack("<H", len(auth)) + auth + inner
    sig = tamper.get("sig", lambda s: s)(raw_sig(intel.att_key, signed))
    sig_data = sig + att + struct.pack("<HI", 6, len(cert)) + cert
    return signed + struct.pack("<I", len(sig_data)) + sig_data


def tcb_level(status, sgx=PCK_COMPS, pcesvn=PCESVN, tdx=(3, 0, 5) + (0,) * 13, date="2025-01-01T00:00:00Z", advisories=()):
    lv = {"tcb": {"sgxtcbcomponents": [{"svn": s} for s in sgx], "pcesvn": pcesvn,
                  "tdxtcbcomponents": [{"svn": s} for s in tdx]}, "tcbDate": date, "tcbStatus": status}
    if advisories:
        lv["advisoryIDs"] = list(advisories)
    return lv


def tcb_info(levels=None, fmspc=FMSPC, identities=None, days=(-1, 30), id_="TDX", version=3, mrsigner=MRSIGNERSEAM):
    info = {
        "id": id_, "version": version,
        "issueDate": (NOW + datetime.timedelta(days=days[0])).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nextUpdate": (NOW + datetime.timedelta(days=days[1])).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fmspc": fmspc.hex(), "pceId": PCEID.hex(), "tcbType": 0, "tcbEvaluationDataNumber": 17,
        "tdxModule": {"mrsigner": mrsigner.hex(), "attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF"},
        "tcbLevels": levels if levels is not None else [
            tcb_level("UpToDate", tdx=(4, 0, 6) + (0,) * 13, advisories=("INTEL-SA-99999",)),
            tcb_level("SWHardeningNeeded", advisories=("INTEL-SA-00837",)),
            tcb_level("OutOfDate", sgx=[0] * 16, pcesvn=0, tdx=(0,) * 16)],
    }
    if identities is not None:
        info["tdxModuleIdentities"] = identities
    return info


def signed_doc(field, value, key, tamper_text=False):
    """Intel's signed JSON: the signature over the field's text as written."""
    text = json.dumps(value, separators=(",", ":"))
    sig = raw_sig(key, text.encode())
    if tamper_text:
        text = text.replace('"tcbEvaluationDataNumber":17', '"tcbEvaluationDataNumber":18')
    return ('{"%s":%s,"signature":"%s"}' % (field, text, sig.hex())).encode()


def qe_identity(isvsvn_levels=((8, "UpToDate"), (6, "OutOfDate")), mrsigner=MRSIGNER_QE, days=(-1, 30), id_="TD_QE"):
    return {
        "id": id_, "version": 2,
        "issueDate": (NOW + datetime.timedelta(days=days[0])).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nextUpdate": (NOW + datetime.timedelta(days=days[1])).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tcbEvaluationDataNumber": 17, "miscselect": "00000000", "miscselectMask": "FFFFFFFF",
        "attributes": "11000000000000000000000000000000", "attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
        "mrsigner": mrsigner.hex(), "isvprodid": 2,
        "tcbLevels": [{"tcb": {"isvsvn": s}, "tcbDate": "2025-01-01T00:00:00Z", "tcbStatus": st} for s, st in isvsvn_levels],
    }


def ccel(events, header_mr=0):
    """A CC event log: the Spec ID header (SHA-384 only, its MrIndex
    `header_mr`), then events (mr index, type, data)."""
    body = (b"Spec ID Event03\0" + struct.pack("<IBBBB", 0, 0, 2, 0, 2) + struct.pack("<I", 1)
            + struct.pack("<HH", SHA384, 48) + b"\0")
    log = struct.pack("<II", header_mr, 3) + bytes(20) + struct.pack("<I", len(body)) + body
    for mr, kind, data in events:
        log += struct.pack("<IIIH", mr, kind, 1, SHA384) + hashlib.sha384(data).digest() + struct.pack("<I", len(data)) + data
    return log


def replay(events):
    rtmrs = [bytes(48)] * 4
    for mr, kind, data in events:
        if kind != 3:
            rtmrs[mr - 1] = hashlib.sha384(rtmrs[mr - 1] + hashlib.sha384(data).digest()).digest()
    return rtmrs


# The platform's TCB, exactly: UpToDate.
UP_TO_DATE = [tcb_level("UpToDate", tdx=(3, 0, 5) + (0,) * 13)]

CC_EVENTS = [(1, 0x80000008, b"TDVF hob"), (1, 0x80000001, b"SecureBoot"), (2, 0x80000003, b"l4h-fl4.efi"),
             (2, 0x80000007, b"Exit Boot Services Invocation"), (3, 0xD, b"root task")]


class Host:
    """The host's key and the report it signs, in the forms trustd writes."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.point = a.point(self.key.public_key())

    def cose_key(self):
        n = self.key.public_key().public_numbers()
        return {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}

    def report(self, data=b"nonce", **claims):
        c = {"v": 1, "host": hashlib.sha256(self.point).digest(), "data": data.ljust(64, b"\0"), "taint": bytes(32),
             "seal": bytes([1]) + bytes(31), "launch": b"\x77" * 32, **claims}
        p, protected = cbor(c), b"\xa1\x01\x26"
        tbs = b"\x84\x6aSignature1" + a.cbor_bytes(protected) + b"\x40" + a.cbor_bytes(p)
        return cbor(("tag", 18, [protected, {}, p, raw_sig(self.key, tbs)]))


class Tdx(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.intel = Intel()
        cls.host = Host()
        cls.binding = a.tdx_key_binding(cls.host.point)
        cls.rtmrs = replay(CC_EVENTS)

    def fields(self, debug=False, **over):
        f = tdreport_fields(self.binding + bytes(16), rtmrs=self.rtmrs[:3], debug=debug)
        f.update(over)
        return f

    def evidence(self, quote=None, **over):
        ev = {"v": 1, "key": self.host.cose_key(), "type": "tdx", "quote": quote or make_quote(self.intel, self.fields())}
        ev.update(over)
        return ev

    def collateral(self, d, tcb=None, qe=None, pck_crl=None, chain=None, root_crl=None, tamper_tcb=False,
                   no_root_crl=False, qe_chain=None, qe_key=None):
        files = {
            "tcb_info.json": signed_doc("tcbInfo", tcb if tcb is not None else tcb_info(UP_TO_DATE), self.intel.tcb_key, tamper_tcb),
            "qe_identity.json": signed_doc("enclaveIdentity", qe if qe is not None else qe_identity(), qe_key or self.intel.tcb_key),
            "pck_crl.pem": (pck_crl if pck_crl is not None else crl(self.intel.pck_ca, self.intel.pck_ca_key)).public_bytes(serialization.Encoding.PEM),
            "tcb_signing_chain.pem": chain or pem(self.intel.tcb, self.intel.root),
        }
        if not no_root_crl:
            files["root_ca_crl.der"] = (root_crl if root_crl is not None else crl(self.intel.root, self.intel.root_key)).public_bytes(
                serialization.Encoding.DER)
        if qe_chain is not None:
            files["qe_identity_signing_chain.pem"] = qe_chain
        for n in ("root_ca_crl.der", "qe_identity_signing_chain.pem"):
            if n not in files and os.path.exists(os.path.join(d, n)):
                os.remove(os.path.join(d, n))
        for n, b in files.items():
            with open(os.path.join(d, n), "wb") as f:
                f.write(b)
        return a.Collateral(d)

    def policy(self, collateral=None, roots=None, **kw):
        return a.TdxPolicy([self.intel.root] if roots is None else roots, collateral, **kw)

    def check(self, ev, collateral=None, **kw):
        return a.check_tdx_evidence(ev, self.policy(collateral, **kw))

    def refused(self, ev, why, collateral=None, **kw):
        with self.assertRaisesRegex(a.Fail, why):
            self.check(ev, collateral, **kw)

    # ---- good

    def test_quote_versions(self):
        for v, t in ((4, 2), (5, 2), (5, 3)):
            q = make_quote(self.intel, self.fields(), v, t)
            key, info = self.check(self.evidence(q))
            self.assertEqual(a.point(key), self.host.point)
            self.assertEqual(info["quote_version"], v)
            self.assertEqual(info["body"], "TD15" if t == 3 else "TD10")
            self.assertEqual(info["mrtd"], (b"\x11" * 48).hex())
            self.assertEqual(info["fmspc"], FMSPC.hex())
            self.assertIsNone(info["tcb_status"])
            self.assertEqual(info["key"], hashlib.sha256(self.host.point).hexdigest())
            if t == 3:
                self.assertIn("mrservicetd", info)

    def test_collateral_up_to_date(self):
        with tempfile.TemporaryDirectory() as d:
            col = self.collateral(d)
            _, info = self.check(self.evidence(), col)
            self.assertEqual((info["tcb_status"], info["qe_tcb_status"]), ("UpToDate", "UpToDate"))
            # The platform reaches only the second level: SWHardeningNeeded.
            col = self.collateral(d, tcb=tcb_info(), root_crl=crl(self.intel.root, self.intel.root_key))
            self.refused(self.evidence(), "tcb status is SWHardeningNeeded", col)
            _, info = self.check(self.evidence(), col, allowed={"UpToDate", "SWHardeningNeeded"})
            self.assertEqual(info["advisory_ids"], ["INTEL-SA-00837"])

    def test_tdx_module_identity(self):
        # TEE_TCB_SVN[1] > 0: the module's own levels count, and SVN
        # bytes 0-1 are not compared with the platform's levels.
        svn = bytes([2, 1, 5] + [0] * 13)
        q = make_quote(self.intel, self.fields(tee_tcb_svn=svn))
        ident = [{"id": "TDX_01", "mrsigner": MRSIGNERSEAM.hex(), "attributes": "0000000000000000",
                  "attributesMask": "FFFFFFFFFFFFFFFF",
                  "tcbLevels": [{"tcb": {"isvsvn": 3}, "tcbDate": "2025-01-01T00:00:00Z", "tcbStatus": "UpToDate"},
                                {"tcb": {"isvsvn": 1}, "tcbDate": "2024-01-01T00:00:00Z", "tcbStatus": "OutOfDate"}]}]
        levels = [tcb_level("UpToDate", tdx=(9, 9, 5) + (0,) * 13)]
        with tempfile.TemporaryDirectory() as d:
            col = self.collateral(d, tcb=tcb_info(levels, identities=ident))
            self.refused(self.evidence(q), "tdx module tcb status is OutOfDate", col)
            _, info = self.check(self.evidence(q), col, allowed={"UpToDate", "OutOfDate"})
            self.assertEqual(info["tdx_module_tcb_status"], "OutOfDate")
            col = self.collateral(d, tcb=tcb_info(levels, identities=[]))
            self.refused(self.evidence(q), "no TDX module identity TDX_01", col)

    def test_cc_event_log(self):
        log = ccel(CC_EVENTS)
        _, info = self.check(self.evidence(), cc_event_log=log)
        self.assertEqual(info["cc_event_log_events"], len(CC_EVENTS))
        bad = ccel(CC_EVENTS[:-1])
        self.refused(self.evidence(), "CC event log does not match the quote: RTMR 2", cc_event_log=bad)
        # A TPM log (SHA-256): not the TD's.
        tpm_body = (b"Spec ID Event03\0" + struct.pack("<IBBBB", 0, 0, 2, 0, 2) + struct.pack("<I", 1)
                    + struct.pack("<HH", SHA256, 32) + b"\0")
        tpm_log = struct.pack("<II", 0, 3) + bytes(20) + struct.pack("<I", len(tpm_body)) + tpm_body
        self.refused(self.evidence(), "no SHA-384", cc_event_log=tpm_log)
        # An event that names MRTD (0) or no register at all.
        self.refused(self.evidence(), "measurement register 0", cc_event_log=ccel([(0, 0xD, b"x")]))
        self.refused(self.evidence(), "measurement register 5", cc_event_log=ccel([(5, 0xD, b"x")]))
        s = a.cc_event_log_summary(log)
        self.assertEqual(s["rtmrs"]["2"], self.rtmrs[2].hex())
        self.assertEqual(s["events"][2]["rtmr"], 1)
        self.assertTrue(a.is_cc_event_log(log) and not a.is_cc_event_log(tpm_log))

    def test_measurement_pins(self):
        self.check(self.evidence(), mrtd=b"\x11" * 48, rtmrs={0: self.rtmrs[0], 2: self.rtmrs[2]})
        self.refused(self.evidence(), "MRTD is", mrtd=b"\x12" * 48)
        self.refused(self.evidence(), "RTMR 1 is", rtmrs={1: bytes(48)})

    # ---- the host key's binding

    def test_key_binding(self):
        other = Host()
        # The quote binds another key.
        q = make_quote(self.intel, self.fields(reportdata=a.tdx_key_binding(other.point) + bytes(16)))
        self.refused(self.evidence(q), "not over this host key")
        # Right hash, REPORTDATA's last 16 bytes not zero.
        q = make_quote(self.intel, self.fields(reportdata=self.binding + b"\x01" + bytes(15)))
        self.refused(self.evidence(q), "not over this host key")
        # The evidence's key swapped.
        self.refused(self.evidence(key=other.cose_key()), "not over this host key")
        # TPM's domain: a TPM binding is no TDX one.
        q = make_quote(self.intel, self.fields(reportdata=hashlib.sha384(a.KEY_DOMAIN + self.host.point).digest() + bytes(16)))
        self.refused(self.evidence(q), "not over this host key")

    def test_rtmr3_must_be_zero(self):
        for rtmr3 in (b"\x01" + bytes(47), a.tdx_rtmr_extended(self.binding)):
            q = make_quote(self.intel, self.fields(rtmr3=rtmr3))
            self.refused(self.evidence(q), "RTMR 3 is not zero")

    def test_evidence_fields(self):
        self.refused(self.evidence(v=2), "unknown TDX evidence version")
        self.refused(self.evidence(v=True), "unknown TDX evidence version")
        self.refused(self.evidence(extra=1), "unknown fields")
        ev = self.evidence()
        del ev["key"]
        self.refused(ev, "unknown fields")
        self.refused(self.evidence(quote=b"\0" * 100), "TDX quote")

    # ---- the quote and its chain

    def test_quote_signature(self):
        self.refused(self.evidence(make_quote(self.intel, self.fields(), tamper={"sig": lambda s: s[:-1] + bytes([s[-1] ^ 1])})),
                     "TDX quote signature does not verify")
        # The body changed after signing: a debug TD made to look sealed.
        q = bytearray(make_quote(self.intel, self.fields(debug=True)))
        q[48 + 120] &= ~1
        self.refused(self.evidence(bytes(q)), "TDX quote signature does not verify")
        # v5: the body descriptor is signed too.
        q = bytearray(make_quote(self.intel, self.fields(), 5, 3))
        q[48] = 2
        with self.assertRaises(a.Fail):
            self.check(self.evidence(bytes(q)))

    def test_debug_td(self):
        q = make_quote(self.intel, self.fields(debug=True))
        self.refused(self.evidence(q), "debug TD")
        _, info = self.check(self.evidence(q), allow_debug=True)
        self.assertTrue(info["debug"])

    def test_qe_report(self):
        # Its REPORTDATA binds another attestation key.
        bad = make_quote(self.intel, self.fields(), tamper={"qe_report": lambda r: r[:320] + bytes(32) + r[352:]})
        self.refused(self.evidence(bad), "does not bind the quote's attestation key")
        bad = make_quote(self.intel, self.fields(), tamper={"qe_report": lambda r: r[:383] + b"\x01"})
        self.refused(self.evidence(bad), "does not bind the quote's attestation key")
        # Not signed by the PCK key.
        bad = make_quote(self.intel, self.fields(), tamper={"qe_sig": lambda s: raw_sig(self.intel.att_key, b"x")})
        self.refused(self.evidence(bad), "QE report is not signed by the PCK certificate")

    def test_header(self):
        for f, why in ((lambda h: h[:12] + bytes(16) + h[28:], "not from Intel's QE"),
                       (lambda h: struct.pack("<H", 3) + h[2:], "neither 4 nor 5"),
                       (lambda h: h[:2] + struct.pack("<H", 3) + h[4:], "not ECDSA P-256"),
                       (lambda h: h[:4] + struct.pack("<I", 0) + h[8:], "not a TDX quote")):
            self.refused(self.evidence(make_quote(self.intel, self.fields(), tamper={"header": f})), why)

    def test_structure(self):
        q = make_quote(self.intel, self.fields())
        self.refused(self.evidence(q + b"\0"), "trailing bytes")
        self.refused(self.evidence(q[:-1]), "cut short")
        self.refused(self.evidence(q[:600]), "cut short")
        q5 = bytearray(make_quote(self.intel, self.fields(), 5, 2))
        struct.pack_into("<I", q5, 50, 648)
        self.refused(self.evidence(bytes(q5)), "neither TD 1.0's nor TD 1.5's")

    def test_pck_chain(self):
        intel = self.intel
        stranger_key = ec.generate_private_key(ec.SECP256R1())
        stranger = cert("Intel SGX Root CA", stranger_key, "Intel SGX Root CA", stranger_key, True)
        # Pinned to another root.
        self.refused(self.evidence(), "not issued by", roots=[stranger])
        self.refused(self.evidence(), "Intel's root CA", roots=[])
        # A chain the quote names, made by someone else.
        ca2 = cert("Intel SGX PCK Platform CA", stranger_key, "Intel SGX Root CA", stranger_key, True)
        leaf2 = cert("Intel SGX PCK Certificate", intel.pck_key, "Intel SGX PCK Platform CA", stranger_key, False,
                     ext=sgx_extension(FMSPC, PCEID, PCK_COMPS, PCESVN))
        q = make_quote(intel, self.fields(), chain=pem(leaf2, ca2, stranger))
        self.refused(self.evidence(q), "not issued by")
        # Expired leaf.
        old = cert("Intel SGX PCK Certificate", intel.pck_key, "Intel SGX PCK Platform CA", intel.pck_ca_key, False,
                   days=(-30, -1), ext=sgx_extension(FMSPC, PCEID, PCK_COMPS, PCESVN))
        self.refused(self.evidence(make_quote(intel, self.fields(), chain=pem(old, intel.pck_ca))), "expired")
        # The leaf a CA; the PCK CA not one.
        ca_leaf = cert("Intel SGX PCK Certificate", intel.pck_key, "Intel SGX PCK Platform CA", intel.pck_ca_key, True,
                       ext=sgx_extension(FMSPC, PCEID, PCK_COMPS, PCESVN))
        self.refused(self.evidence(make_quote(intel, self.fields(), chain=pem(ca_leaf, intel.pck_ca))), "is a CA certificate")
        not_ca = cert("Intel SGX PCK Platform CA", intel.pck_ca_key, "Intel SGX Root CA", intel.root_key, False)
        self.refused(self.evidence(make_quote(intel, self.fields(), chain=pem(intel.pck, not_ca))), "not a CA")
        # No SGX extensions.
        plain = cert("Intel SGX PCK Certificate", intel.pck_key, "Intel SGX PCK Platform CA", intel.pck_ca_key, False)
        self.refused(self.evidence(make_quote(intel, self.fields(), chain=pem(plain, intel.pck_ca))), "without SGX extensions")
        # The leaf alone; no PEM at all.
        self.refused(self.evidence(make_quote(intel, self.fields(), chain=pem(intel.pck))), "lacks its CA")
        self.refused(self.evidence(make_quote(intel, self.fields(), chain=b"junk")), "no certificate")

    def test_sgx_extensions(self):
        ext = a.sgx_extensions(self.intel.pck)
        self.assertEqual((ext["fmspc"], ext["pceid"]), (FMSPC, PCEID))
        self.assertEqual(ext["tcb"]["components"], PCK_COMPS)
        self.assertEqual(ext["tcb"]["pcesvn"], PCESVN)
        self.assertEqual(ext["tcb"]["cpusvn"], bytes(range(16)))
        self.assertEqual(ext["sgx_type"], 0)
        # Big component SVNs (two-byte DER integers) parse.
        c = cert("x", self.intel.pck_key, "y", self.intel.pck_ca_key, False,
                 ext=sgx_extension(FMSPC, PCEID, [200] * 16, 300))
        self.assertEqual(a.sgx_extensions(c)["tcb"]["components"], [200] * 16)
        self.assertEqual(a.sgx_extensions(c)["tcb"]["pcesvn"], 300)

    # ---- collateral

    def test_collateral_signatures_and_chain(self):
        stranger_key = ec.generate_private_key(ec.SECP256R1())
        with tempfile.TemporaryDirectory() as d:
            self.refused(self.evidence(), "TCB info signature", self.collateral(d, tamper_tcb=True))
            fake = cert("Intel SGX TCB Signing", stranger_key, "Intel SGX Root CA", stranger_key, False)
            self.refused(self.evidence(), "not issued by", self.collateral(d, chain=pem(fake)))
            self.refused(self.evidence(), "is a root CA", self.collateral(d, chain=pem(self.intel.root)))
            # QE identity signed by someone else.
            col = self.collateral(d)
            with open(os.path.join(d, "qe_identity.json"), "wb") as f:
                f.write(signed_doc("enclaveIdentity", qe_identity(), stranger_key))
            self.refused(self.evidence(), "QE identity signature", a.Collateral(d))
            os.remove(os.path.join(d, "qe_identity.json"))
            self.refused(self.evidence(), "without qe_identity.json", a.Collateral(d))

    def test_collateral_contents(self):
        with tempfile.TemporaryDirectory() as d:
            self.refused(self.evidence(), "FMSPC", self.collateral(d, tcb=tcb_info(fmspc=bytes(6))))
            self.refused(self.evidence(), "not TDX's", self.collateral(d, tcb=tcb_info(id_="SGX")))
            self.refused(self.evidence(), "not TDX's", self.collateral(d, tcb=tcb_info(version=2)))
            self.refused(self.evidence(), "TDX module signer", self.collateral(d, tcb=tcb_info(mrsigner=b"\x01" * 48)))
            self.refused(self.evidence(), "no TCB level matches",
                         self.collateral(d, tcb=tcb_info([tcb_level("UpToDate", pcesvn=PCESVN + 1)])))
            self.refused(self.evidence(), "tcb status is OutOfDate",
                         self.collateral(d, tcb=tcb_info([tcb_level("OutOfDate")])))
            self.refused(self.evidence(), "QE signer", self.collateral(d, qe=qe_identity(mrsigner=bytes(32))))
            self.refused(self.evidence(), "not TDX's QE", self.collateral(d, qe=qe_identity(id_="QE")))
            self.refused(self.evidence(), "qe tcb status is OutOfDate",
                         self.collateral(d, qe=qe_identity(((9, "UpToDate"), (8, "OutOfDate")))))
            self.refused(self.evidence(), "no QE identity TCB level", self.collateral(d, qe=qe_identity(((9, "UpToDate"),))))

    def test_stale_collateral(self):
        with tempfile.TemporaryDirectory() as d:
            col = self.collateral(d, tcb=tcb_info(UP_TO_DATE, days=(-60, -1)))
            self.refused(self.evidence(), "TCB info is out of date", col)
            self.check(self.evidence(), col, stale_ok=True)
            col = self.collateral(d, qe=qe_identity(days=(-60, -1)))
            self.refused(self.evidence(), "QE identity is out of date", col)
            col = self.collateral(d, pck_crl=crl(self.intel.pck_ca, self.intel.pck_ca_key, days=(-60, -1)))
            self.refused(self.evidence(), "PCK CRL is out of date", col)

    def test_revocation(self):
        intel = self.intel
        with tempfile.TemporaryDirectory() as d:
            col = self.collateral(d, pck_crl=crl(intel.pck_ca, intel.pck_ca_key, [intel.pck.serial_number]))
            self.refused(self.evidence(), "PCK certificate is revoked", col)
            # A CRL the PCK CA did not sign.
            col = self.collateral(d, pck_crl=crl(intel.pck_ca, intel.root_key))
            self.refused(self.evidence(), "PCK CRL is not signed", col)
            col = self.collateral(d, root_crl=crl(intel.root, intel.root_key, [intel.pck_ca.serial_number]))
            self.refused(self.evidence(), "PCK CA certificate is revoked", col)
            col = self.collateral(d, root_crl=crl(intel.root, intel.root_key, [intel.tcb.serial_number]))
            self.refused(self.evidence(), "TCB signing certificate is revoked", col)

    # ---- review fixes

    def test_collateral_needs_root_crl_and_signers(self):
        intel = self.intel
        with tempfile.TemporaryDirectory() as d:
            self.refused(self.evidence(), "without root_ca_crl.der", self.collateral(d, no_root_crl=True))
            # A TCB signing certificate by another name, or not for signing.
            other = cert("Intel SGX PCK Platform CA", intel.tcb_key, "Intel SGX Root CA", intel.root_key, False,
                         ku=key_usage(sign=True))
            self.refused(self.evidence(), "not Intel's TCB signing certificate", self.collateral(d, chain=pem(other)))
            no_sign = cert("Intel SGX TCB Signing", intel.tcb_key, "Intel SGX Root CA", intel.root_key, False,
                           ku=key_usage(cert_sign=False))
            self.refused(self.evidence(), "may not sign", self.collateral(d, chain=pem(no_sign)))
            # A CRL from a CA that may not sign CRLs.
            ca_no_crl = cert("Intel SGX PCK Platform CA", intel.pck_ca_key, "Intel SGX Root CA", intel.root_key, True,
                             ku=key_usage(cert_sign=True))
            q = make_quote(intel, self.fields(), chain=pem(intel.pck, ca_no_crl))
            self.refused(self.evidence(q), "may not sign CRLs", self.collateral(d, pck_crl=crl(ca_no_crl, intel.pck_ca_key)))

    def test_qe_identity_signing_chain(self):
        intel = self.intel
        qe_key = ec.generate_private_key(ec.SECP256R1())
        qe_cert = cert("Intel SGX TCB Signing", qe_key, "Intel SGX Root CA", intel.root_key, False, ku=key_usage(sign=True))
        with tempfile.TemporaryDirectory() as d:
            # QE identity signed by its own signing certificate, given.
            self.check(self.evidence(), self.collateral(d, qe_chain=pem(qe_cert, intel.root), qe_key=qe_key))
            # Without it, TCB info's certificate does not verify it.
            self.refused(self.evidence(), "QE identity signature", self.collateral(d, qe_key=qe_key))
            # Revoked by the root CA.
            col = self.collateral(d, qe_chain=pem(qe_cert), qe_key=qe_key,
                                  root_crl=crl(intel.root, intel.root_key, [qe_cert.serial_number]))
            self.refused(self.evidence(), "QE identity signing certificate is revoked", col)

    def test_migratable_td(self):
        f = self.fields()
        attrs = bytearray(f["td_attributes"])
        attrs[3] |= 0x20
        q = make_quote(self.intel, self.fields(td_attributes=bytes(attrs)))
        self.refused(self.evidence(q), "migratable")
        _, info = self.check(self.evidence(q), allow_migratable=True)
        self.assertTrue(info["migratable"])
        _, info = self.check(self.evidence())
        self.assertFalse(info["migratable"])

    def test_tdx_1_5_module_ignores_tdx_1_0_entry(self):
        # TDX 1.5 (TEE_TCB_SVN[1] > 0): tdxModule (TDX 1.0's signer) is not
        # this module's; its identity entry is.
        svn = bytes([2, 1, 5] + [0] * 13)
        q = make_quote(self.intel, self.fields(tee_tcb_svn=svn))
        ident = [{"id": "TDX_01", "mrsigner": MRSIGNERSEAM.hex(), "attributes": "0000000000000000",
                  "attributesMask": "FFFFFFFFFFFFFFFF",
                  "tcbLevels": [{"tcb": {"isvsvn": 2}, "tcbDate": "2025-01-01T00:00:00Z", "tcbStatus": "UpToDate",
                                 "advisoryIDs": ["INTEL-SA-01111", "INTEL-SA-00837"]}]}]
        levels = [tcb_level("UpToDate", tdx=(9, 9, 5) + (0,) * 13, advisories=("INTEL-SA-00837",))]
        with tempfile.TemporaryDirectory() as d:
            col = self.collateral(d, tcb=tcb_info(levels, identities=ident, mrsigner=b"\x01" * 48))
            _, info = self.check(self.evidence(q), col)
            self.assertEqual(info["tdx_module_tcb_status"], "UpToDate")
            # Advisories of the platform, the module and the QE, each once.
            self.assertEqual(info["advisory_ids"], ["INTEL-SA-00837", "INTEL-SA-01111"])
            # TDX 1.0 still checks tdxModule.
            self.refused(self.evidence(), "TDX module signer",
                         self.collateral(d, tcb=tcb_info(UP_TO_DATE, mrsigner=b"\x01" * 48)))

    def test_svns_are_the_pck_and_qe_reports(self):
        # Header bytes 8-11 are reserved: not the SVNs reported.
        q = make_quote(self.intel, self.fields(), tamper={"header": lambda h: h[:8] + b"\xff" * 4 + h[12:]})
        _, info = self.check(self.evidence(q))
        self.assertEqual((info["pce_svn"], info["qe_svn"]), (PCESVN, 8))

    def test_cc_event_log_zero_padding(self):
        log = ccel(CC_EVENTS)
        _, info = self.check(self.evidence(), cc_event_log=log + bytes(4096))
        self.assertEqual(info["cc_event_log_events"], len(CC_EVENTS))
        self.refused(self.evidence(), "event log", cc_event_log=log + bytes(100) + b"\x01")
        self.assertTrue(a.is_cc_event_log(log + bytes(64)))
        # The TPM's log stays strict.
        with self.assertRaises(a.Fail):
            a.parse_event_log(log + bytes(4))

    def test_cc_event_log_header_mr_index(self):
        # EDK2's TdTcg2Dxe (GCE's TDVF) writes the header's MrIndex as 1.
        log = ccel(CC_EVENTS, header_mr=1)
        _, info = self.check(self.evidence(), cc_event_log=log)
        self.assertEqual(info["cc_event_log_events"], len(CC_EVENTS))
        self.assertEqual(a.cc_event_log_summary(log)["rtmrs"]["1"], self.rtmrs[1].hex())
        self.assertTrue(a.is_cc_event_log(log))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ccel")
            with open(path, "wb") as f:
                f.write(log)
            for args in ((), ("--cc",)):
                r = self.run_tool("event-log", path, *args)
                self.assertEqual(r.returncode, 0, (args, r.stderr))
                self.assertEqual(json.loads(r.stdout)["rtmrs"]["2"], self.rtmrs[2].hex())
        # No other register.
        for bad in (2, 4):
            with self.assertRaisesRegex(a.Fail, "not a TCG2 crypto agile event log"):
                a.replay_cc_event_log(ccel(CC_EVENTS, header_mr=bad))
        # A TPM log's header stays at PCR 0.
        body = (b"Spec ID Event03\0" + struct.pack("<IBBBB", 0, 0, 2, 0, 2) + struct.pack("<I", 1)
                + struct.pack("<HH", SHA256, 32) + b"\0")
        tpm = struct.pack("<II", 1, 3) + bytes(20) + struct.pack("<I", len(body)) + body
        for f in (a.parse_event_log, a.replay_event_log):
            with self.assertRaisesRegex(a.Fail, "not a TCG2 crypto agile event log"):
                f(tpm)
        self.assertFalse(a.is_cc_event_log(tpm))

    def test_quote_chain_with_nul_terminator(self):
        q = make_quote(self.intel, self.fields(), chain=pem(self.intel.pck, self.intel.pck_ca) + b"\x00\x00")
        self.check(self.evidence(q))

    def test_attestation_key_off_the_curve(self):
        good = make_quote(self.intel, self.fields())
        p = a.parse_tdx_quote(good)
        at = good.index(p["att_key"])
        bad = good[:at] + bytes(64) + good[at + 64:]
        self.refused(self.evidence(bad), "invalid P-256 attestation key")

    def test_sgx_tcb_extension_oids(self):
        o = a.SGX_EXTENSIONS_OID
        tcb = [der(0x30, der_oid("%s.2.%d" % (o, i + 1)) + der_int(1)) for i in range(16)]
        tcb.append(der(0x30, der_oid("1.2.3.4") + der_int(1)))  # outside the TCB's OIDs
        ext = der(0x30, der(0x30, der_oid(o + ".2") + der(0x30, b"".join(tcb)))
                  + der(0x30, der_oid(o + ".3") + der(0x04, PCEID)) + der(0x30, der_oid(o + ".4") + der(0x04, FMSPC)))
        c = cert("x", self.intel.pck_key, "y", self.intel.pck_ca_key, False, ext=ext)
        with self.assertRaisesRegex(a.Fail, "malformed SGX TCB extension"):
            a.sgx_extensions(c)

    # ---- a guest's fresh quote (ATTEST_TDX_QUOTE)

    def answer(self, report=None, rtmr3=None, reportdata=None, key=None):
        report = report or self.host.report(b"fresh")
        f = self.fields(rtmr3=a.tdx_rtmr_extended(self.binding) if rtmr3 is None else rtmr3,
                        reportdata=a.tdx_guest_report_data(report) if reportdata is None else reportdata)
        return {"key": key or self.host.cose_key(), "quote": make_quote(self.intel, f, 5, 3), "report": report}

    def test_fresh_quote(self):
        ans = self.answer()
        key, info = a.check_tdx_quote_answer(ans, self.policy())
        self.assertEqual(a.point(key), self.host.point)
        guest = a.check_report(a.cbor_decode(ans["report"]), key, b"fresh", None)
        self.assertEqual(guest["data"], b"fresh".ljust(64, b"\0").hex())
        # The report swapped for another the key signed: not the quoted one.
        other = dict(ans, report=self.host.report(b"other"))
        with self.assertRaisesRegex(a.Fail, "not over this report"):
            a.check_tdx_quote_answer(other, self.policy())
        # RTMR 3 not the key's: zero (no key bound yet), or another key's.
        for rtmr3 in (bytes(48), a.tdx_rtmr_extended(a.tdx_key_binding(Host().point))):
            with self.assertRaisesRegex(a.Fail, "RTMR 3 does not hold this host key"):
                a.check_tdx_quote_answer(self.answer(rtmr3=rtmr3), self.policy())
        # Another key claimed: RTMR 3 gives it away.
        with self.assertRaisesRegex(a.Fail, "RTMR 3 does not hold"):
            a.check_tdx_quote_answer(self.answer(key=Host().cose_key()), self.policy())
        # The key's binding in REPORTDATA (the evidence's), not the report's.
        with self.assertRaisesRegex(a.Fail, "not over this report"):
            a.check_tdx_quote_answer(self.answer(reportdata=self.binding + bytes(16)), self.policy())
        with self.assertRaisesRegex(a.Fail, "not a TDX quote answer"):
            a.check_tdx_quote_answer(dict(ans, extra=1), self.policy())

    # ---- which evidence

    def test_split_evidence(self):
        tdx, tpm = self.evidence(), {"v": 1, "ak": b"", "key": {}}
        self.assertEqual(a.split_evidence(tdx), (None, tdx))
        self.assertEqual(a.split_evidence(tpm), (tpm, None))
        self.assertEqual(a.split_evidence({"v": 3, "tdx": tdx, "tpm": tpm}), (tpm, tdx))
        with self.assertRaisesRegex(a.Fail, "combined evidence"):
            a.split_evidence({"v": 3, "tdx": tdx})
        self.assertEqual(a.quote_of({"v": 3, "tdx": tdx, "tpm": tpm}), tdx["quote"])

    # ---- the command line

    def run_tool(self, *args):
        return subprocess.run([sys.executable, "-I", str(TOOL)] + list(args), capture_output=True, text=True)

    def files(self, d, **docs):
        out = {}
        for n, v in docs.items():
            out[n] = os.path.join(d, n)
            with open(out[n], "wb") as f:
                f.write(v if isinstance(v, bytes) else cbor(v))
        return out

    def tpm_evidence(self, host, partition=None):
        """TPM evidence for `host`'s key, as tests/attest-verifier.py makes it."""
        spec2 = importlib.util.spec_from_file_location("attest_verifier", Path(__file__).with_name("attest-verifier.py"))
        tv = importlib.util.module_from_spec(spec2)
        with contextlib.redirect_stdout(io.StringIO()):
            spec2.loader.exec_module(tv)
        e = tv.Evidence()
        e.ak, e.host = ec.generate_private_key(ec.SECP256R1()), host.key
        return e.evidence(partition, [(0, Host().point)] if partition else None)

    def test_cli_verify(self):
        report = self.host.report(b"cli")
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "root.pem")
            with open(root, "wb") as f:
                f.write(pem(self.intel.root))
            tpm = self.tpm_evidence(self.host)
            p = self.files(d, rep=report, tdx=self.evidence(), tpm=tpm,
                           both={"v": 3, "tdx": self.evidence(), "tpm": tpm}, log=ccel(CC_EVENTS),
                           other_tpm=self.tpm_evidence(Host()), mk_tpm=self.tpm_evidence(self.host, 1))
            col = os.path.join(d, "col")
            os.mkdir(col)
            self.collateral(col, tcb=tcb_info([tcb_level("UpToDate", tdx=(3, 0, 5) + (0,) * 13)]))
            # TDX alone, with collateral and the CC event log.
            r = self.run_tool("verify", p["rep"], p["tdx"], "--intel-root-ca", root, "--collateral-dir", col,
                              "--cc-event-log", p["log"], "--data", b"cli".hex(), "--rtmr", "1=" + self.rtmrs[1].hex())
            self.assertEqual(r.returncode, 0, r.stderr)
            out = json.loads(r.stdout)
            self.assertEqual(set(out), {"tdx", "guest"})
            self.assertEqual(out["tdx"]["tcb_status"], "UpToDate")
            self.assertEqual(out["tdx"]["cc_event_log_events"], len(CC_EVENTS))
            self.assertNotIn("warning", r.stderr)
            # Without collateral: a warning.
            r = self.run_tool("verify", p["rep"], p["tdx"], "--intel-root-ca", root)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("TCB status not checked", r.stderr)
            # Without the root: refused.
            r = self.run_tool("verify", p["rep"], p["tdx"])
            self.assertEqual(r.returncode, 1)
            self.assertIn("--intel-root-ca", r.stderr)
            # Both, combined (the guest driver's v3) and side by side.
            for args in ((p["both"],), ("--tdx-evidence", p["tdx"], "--tpm-evidence", p["tpm"]), (p["tpm"], "--tdx-evidence", p["tdx"])):
                r = self.run_tool("verify", p["rep"], *args, "--intel-root-ca", root)
                self.assertEqual(r.returncode, 0, (args, r.stderr))
                out = json.loads(r.stdout)
                self.assertEqual(set(out), {"host", "tdx", "guest"})
                self.assertEqual(out["host"]["key"], out["tdx"]["key"])
            # The TPM alone: as before, no TDX in the output.
            r = self.run_tool("verify", p["rep"], p["tpm"])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(set(json.loads(r.stdout)), {"host", "guest"})
            # TPM evidence alone where TDX was asked for (a host that left
            # its TDX evidence out): refused, whichever TDX option.
            for opts in (("--intel-root-ca", root), ("--mrtd", "11" * 48), ("--rtmr", "0=" + "00" * 48),
                         ("--collateral-dir", col), ("--cc-event-log", p["log"]), ("--allow-debug",),
                         ("--allow-migratable",), ("--root-ca-crl", root)):
                r = self.run_tool("verify", p["rep"], p["tpm"], *opts)
                self.assertEqual(r.returncode, 1, opts)
                self.assertIn("TDX options without TDX evidence", r.stderr)
            # The two roots of trust speak of different keys, or the TPM's
            # of a partition.
            r = self.run_tool("verify", p["rep"], "--tdx-evidence", p["tdx"], "--tpm-evidence", p["other_tpm"], "--intel-root-ca", root)
            self.assertEqual(r.returncode, 1)
            self.assertIn("different host keys", r.stderr)
            r = self.run_tool("verify", p["rep"], "--tdx-evidence", p["tdx"], "--tpm-evidence", p["mk_tpm"], "--intel-root-ca", root)
            self.assertEqual(r.returncode, 1)
            self.assertRegex(r.stderr, "single kernel|partition")
            # Two of one kind.
            r = self.run_tool("verify", p["rep"], p["both"], "--tdx-evidence", p["tdx"], "--intel-root-ca", root)
            self.assertEqual(r.returncode, 1)
            self.assertIn("two TDX evidences", r.stderr)
            r = self.run_tool("verify", p["rep"])
            self.assertEqual(r.returncode, 1)
            self.assertIn("no evidence", r.stderr)
            # Another host's report.
            p2 = self.files(d, rep2=Host().report(b"cli"))
            r = self.run_tool("verify", p2["rep2"], p["tdx"], "--intel-root-ca", root)
            self.assertEqual(r.returncode, 1)
            self.assertIn("report", r.stderr)
            for r in (r,):
                self.assertNotIn("Traceback", r.stderr)

    def test_cli_fresh_quote_and_event_log(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "root.pem")
            with open(root, "wb") as f:
                f.write(pem(self.intel.root))
            other = Host()
            p = self.files(d, ans=self.answer(), tdx=self.evidence(), log=ccel(CC_EVENTS),
                           other_ev={"v": 1, "key": other.cose_key(), "type": "tdx",
                                     "quote": make_quote(self.intel, self.fields(reportdata=a.tdx_key_binding(other.point) + bytes(16)))})
            r = self.run_tool("verify-tdx-quote", p["ans"], "--intel-root-ca", root, "--tdx-evidence", p["tdx"], "--data", b"fresh".hex())
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(set(json.loads(r.stdout)), {"tdx", "guest"})
            r = self.run_tool("verify-tdx-quote", p["ans"], "--intel-root-ca", root, "--tdx-evidence", p["other_ev"])
            self.assertEqual(r.returncode, 1)
            self.assertIn("not the TDX evidence's", r.stderr)
            r = self.run_tool("verify-tdx-quote", p["ans"], "--intel-root-ca", root, "--data", "00")
            self.assertEqual(r.returncode, 1)
            self.assertIn("nonce", r.stderr)
            r = self.run_tool("event-log", p["log"])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)["rtmrs"]["0"], self.rtmrs[0].hex())
            r = self.run_tool("verify", p["tdx"], p["tdx"], "--rtmr", "3=" + "00" * 48, "--intel-root-ca", root)
            self.assertEqual(r.returncode, 1)
            self.assertIn("RTMR 0, 1 or 2", r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_fetch_collateral(self):
        intel = self.intel
        tcb_body = signed_doc("tcbInfo", tcb_info([tcb_level("UpToDate", tdx=(3, 0, 5) + (0,) * 13)]), intel.tcb_key)
        qe_body = signed_doc("enclaveIdentity", qe_identity(), intel.tcb_key)
        import urllib.parse
        chain = urllib.parse.quote(pem(intel.tcb, intel.root).decode())
        asked = []

        def get(url):
            asked.append(url)
            if "/tcb?fmspc=" in url:
                return {"tcb-info-issuer-chain": chain}, tcb_body
            if url.endswith("/qe/identity"):
                return {"sgx-enclave-identity-issuer-chain": chain}, qe_body
            if "pckcrl?ca=platform" in url:
                return {}, crl(intel.pck_ca, intel.pck_ca_key).public_bytes(serialization.Encoding.PEM)
            if url == a.INTEL_ROOT_CA_CRL:
                return {}, crl(intel.root, intel.root_key).public_bytes(serialization.Encoding.DER)
            raise AssertionError(url)

        with tempfile.TemporaryDirectory() as d:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                files = a.fetch_collateral(self.evidence()["quote"], d, get=get)
            self.assertIn("check it against Intel's published root", err.getvalue())
            self.assertIn("fmspc=%s" % FMSPC.hex().upper(), asked[0])
            self.assertIn("intel_root_ca.pem", files)
            self.assertIn("qe_identity_signing_chain.pem", files)
            with open(os.path.join(d, "intel_root_ca.pem"), "rb") as f:
                self.assertEqual(x509.load_pem_x509_certificate(f.read()), intel.root)
            _, info = self.check(self.evidence(), a.Collateral(d))
            self.assertEqual(info["tcb_status"], "UpToDate")

            def no_chain(url):
                h, b = get(url)
                return {}, b
            with self.assertRaisesRegex(a.Fail, "TCB-Info-Issuer-Chain"):
                a.fetch_collateral(self.evidence()["quote"], d, get=no_chain)


if __name__ == "__main__":
    unittest.main()
