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
  l4h-attest.py measure KERNEL --hvm x86_64|aarch64 --kernel-gpa N
                [--initrd F --initrd-gpa N] [--cmdline S]
      The launch digest of an HVM guest: KERNEL is the image dom0 loads (a
      bzImage, Image or ELF vmlinux), and the addresses are where it loads
      the files (`l4hctl hvm-layout` prints l4hctl's).
  l4h-attest.py measure-host [--efi FILE] [--config FILE] [--initrd FILE]
      Expected host boot measurements: PCR 9 (SHA-256) and RTMR 2 (SHA-384)
      for l4h.conf and dom0 initrd (policy.rs domain separation), and with
      --efi the PE/COFF Authenticode SHA-256 and SHA-384 digests.
  l4h-attest.py verify REPORT EVIDENCE [--data HEX] [--launch HEX]
                [--pcr N=HEX]... [--ak-name HEX | --insecure-unpinned-ak]
                [--insecure-unpinned-measurements] [--ignore-tpm]
                [--ek-ca PEM] [--deny-taint SPEC] [--require-seal SPEC]
                [--event-log FILE] [--allow-efi-drivers]
      Check a report (l4hctl attest report -o) against the host evidence
      (l4hctl attest evidence -o), and print what they claim as JSON.
      TPM evidence needs --ak-name, the AK enrolled with make-credential:
      without it the attestation key is not known to be a TPM's, which
      only --insecure-unpinned-ak accepts (to read the AK's name before
      enrolling it).  --ek-ca may hold intermediate CAs and their root:
      each hop is checked.  TPM evidence also needs --pcr 2=... (option
      ROMs and UEFI drivers from outside the firmware), --pcr 4=... (the
      UEFI application, l4h) and --pcr 9=... (l4h.conf, dom0's initrd),
      or --insecure-unpinned-measurements; without --pcr 0=... (the
      firmware itself) verify warns.
      By default the guest must have sealed console-in and not taken
      console input before: input after the report would be unattested.
      A multikernel host's report and evidence name the partition the
      guest runs in (version 2); verify prints it as "partition".
      --event-log takes the host's UEFI TPM event log (l4hctl attest
      event-log -o): replayed, it must give the quoted PCRs 0-14, which
      nothing changes after the firmware's ExitBootServices (trustd quotes
      before it extends PCR 15), and leave PCR 15 zero, and must load no
      UEFI driver or application from outside the firmware
      (EV_EFI_BOOT_SERVICES_DRIVER, EV_EFI_RUNTIME_SERVICES_DRIVER or
      EV_EFI_BOOT_SERVICES_APPLICATION in PCR 2, as option ROMs are; l4h
      itself is PCR 4's): --allow-efi-drivers accepts them, with a
      warning.  Its events then
      say what the firmware measured.
      Intel TDX: EVIDENCE may also be the host's TDX evidence (l4hctl
      attest tdx-evidence -o) or the guest driver's TPM and TDX evidence
      together (configfs-tsm auxblob, {"v": 3, "tdx", "tpm"}); or give
      --tdx-evidence and --tpm-evidence, which must name the same key.
      A TDX quote is checked down to --intel-root-ca (Intel's SGX root
      CA, pinned; required), its TD must not be a debug TD
      (--allow-debug) nor migratable or bound to a service TD
      (--allow-migratable), and --collateral-dir (fetch-collateral; the
      root CA's CRL too; required) must show the QE Intel's and the TDX
      module Intel's, their TCB status and the platform's (a TD 1.5
      quote's at launch and current) UpToDate (--allow-tcb-status S to
      accept more) and no certificate revoked.  --insecure-skip-collateral
      skips that, for tests only: without it anyone with an SGX machine
      can forge a quote.  The quote's REPORTDATA must bind the host key
      and RTMR 3 be zero: trustd extends it with the key at once, so it
      was the first of this boot.  --mrtd and --rtmr N=HEX pin measurements;
      --cc-event-log (l4hctl attest tdx-event-log -o) must replay to
      RTMR 0-2, leave RTMR 3 zero and load no UEFI driver or application
      in RTMR 0 (as --event-log in PCR 2; --allow-efi-drivers accepts
      them).  With
      neither --rtmr 0=... nor --cc-event-log, RTMR 0 (the TD firmware's
      configuration, TDHOB, ACPI tables, drivers) is unchecked: verify
      warns.
  l4h-attest.py verify-tdx-quote ANSWER [--tdx-evidence F] [--data HEX]
                [TDX options as verify] [--allow-efi-drivers]
      A guest's fresh TDX quote (l4hctl attest tdx-quote -o): its
      REPORTDATA must bind the report it carries, and its RTMR 3 the host
      key (extended once from zero); the report is then checked as verify
      does.  With --tdx-evidence, the key must be the evidence's.
  l4h-attest.py event-log FILE [--cc]
      The events of a UEFI TPM 2.0 event log (TCG2 crypto agile format)
      and the SHA-256 PCR values they replay to, as JSON; of a CC event
      log (SHA-384, the default without SHA-256 digests), the RTMRs.
  l4h-attest.py fetch-collateral EVIDENCE -o DIR
      Intel's collateral for the TDX quote in EVIDENCE (TDX or combined
      evidence, a tdx-quote answer or a raw quote), from Intel's PCS: TCB
      info and QE identity with their signing chains, the PCK and root CA
      CRLs, for --collateral-dir; and intel_root_ca.pem, the root PCS's chain
      ends in, which is only what the network said: compare it with
      Intel's published root before pinning it.
  l4h-attest.py make-credential EVIDENCE SECRET_HEX -o FILE [--ek PEM]
                [--ek-ca PEM]
      A credential for the host's attestation key (EVIDENCE: TPM or
      combined evidence), encrypted to its EK
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

Needs the Python `cryptography` package (fetch-collateral, network access
to api.trustedservices.intel.com).
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
EV_SEPARATOR = 4
EV_EFI_HCRTM_EVENT = 0x80000010
# UEFI drivers and applications the firmware loaded from outside its own
# volumes (option ROMs), PFP 1.06 rev52 10.4.1: measured into PCR 2 (on
# TDX RTMR 0, CC measurement register 1).  Their code ran before l4h, with
# the firmware's privilege.  The boot application, l4h, is measured into
# PCR 4 (RTMR 1) instead, which these checks leave alone.
EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003
EV_EFI_BOOT_SERVICES_DRIVER = 0x80000004
EV_EFI_RUNTIME_SERVICES_DRIVER = 0x80000005
EFI_DRIVER_EVENTS = (EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_BOOT_SERVICES_DRIVER, EV_EFI_RUNTIME_SERVICES_DRIVER)
EFI_DRIVER_PCR = 2
EV_SEPARATOR_ERR_SHA256 = hashlib.sha256(b"\xff\xff\xff\xff").digest()
EV_SEPARATOR_ERR_SHA384 = hashlib.sha384(b"\xff\xff\xff\xff").digest()
TPM_ALG_SHA256 = 0x000B
SPEC_ID = b"Spec ID Event03\0"
STARTUP_LOCALITY = b"StartupLocality\0"
STARTUP_LOCALITIES = (0, 3, 4)
HCRTM_DATA = b"HCRTM"
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
def parse_event_log(log, zero_pad=False, cc=False):
    """The digest sizes the Spec ID event lists ({algorithm: size}) and the
    TCG_PCR_EVENT2s after it, each {"pcr", "type", "digests": {algorithm:
    digest}, "data"}.  The whole log must be events: no bytes left over,
    but with `zero_pad` (a CC event log, which the ACPI CCEL table's area
    leaves zero past its end) zero bytes after the last event.  `cc`: a CC
    event log, whose header may name measurement register 1 (below)."""
    if not isinstance(log, bytes):
        raise Fail("event log is not bytes")
    r = LogReader(log)
    # The header: a TCG 1.2 TCG_PCR_EVENT (SHA-1 digest) of type
    # EV_NO_ACTION holding TCG_EfiSpecIDEventStruct.
    pcr, kind, _, size = r.u32(), r.u32(), r.take(20), r.u32()
    spec = LogReader(r.take(size))
    # A CC event log's header is the same EV_NO_ACTION event, but EDK2's
    # TdTcg2Dxe (GCE's TDVF) writes its MrIndex as 1 ("PCRIndex 0 maps to
    # MrIndex 1"), others 0: neither extends anything.
    if pcr not in ((0, 1) if cc else (0,)) or kind != EV_NO_ACTION or spec.take(16) != SPEC_ID:
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
        if zero_pad and not any(log[r.at:]):
            break
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
    locality = None
    need_hcrtm = False
    for n, e in enumerate(events):
        if e["type"] == EV_NO_ACTION:
            # Not extended; the startup locality (PFP 1.06 rev52 10.4.5.3)
            # is PCR 0's initial value.
            if e["data"][:len(STARTUP_LOCALITY)] == STARTUP_LOCALITY and len(e["data"]) == len(STARTUP_LOCALITY) + 1:
                loc = e["data"][-1]
                # 0 or 3 without an H-CRTM sequence, or 4 with an H-CRTM
                # sequence (PFP 1.06 rev52 3.3.4.1, 10.4.5.3); all other
                # values are reserved by TCG.
                if loc not in STARTUP_LOCALITIES:
                    raise Fail("event %d: StartupLocality %d is not 0, 3 or 4" % (n, loc))
                if locality == 4 or (loc == 4 and locality is not None):
                    raise Fail("event %d: duplicate StartupLocality %d" % (n, loc))
                if loc == 4:
                    if e["pcr"] != 0 or 0 in extended:
                        raise Fail("event %d: StartupLocality 4 must be on PCR 0 before it is extended" % n)
                    pcrs[0] = bytes(31) + b"\x04"
                    locality = 4
                    need_hcrtm = True
                elif e["pcr"] == 0 and 0 not in extended:
                    pcrs[0] = bytes(31) + bytes([loc])
                    locality = loc
            continue
        if e["type"] == EV_EFI_HCRTM_EVENT:
            # PFP 1.06 rev52 3.3.4.1, 10.4.5.3: EV_EFI_HCRTM_EVENT ("HCRTM")
            # is valid once, as PCR 0's first extend after StartupLocality 4.
            if not need_hcrtm or e["pcr"] != 0 or e["data"] != HCRTM_DATA:
                raise Fail("event %d: unexpected EV_EFI_HCRTM_EVENT" % n)
            need_hcrtm = False
        elif need_hcrtm and e["pcr"] == 0:
            raise Fail("event %d: StartupLocality 4 requires PCR 0's first event to be EV_EFI_HCRTM_EVENT" % n)
        if not 0 <= e["pcr"] < 24:
            raise Fail("event %d extends PCR %d" % (n, e["pcr"]))
        if TPM_ALG_SHA256 not in e["digests"]:
            raise Fail("event %d (PCR %d) has no SHA-256 digest" % (n, e["pcr"]))
        if e["type"] == EV_SEPARATOR and e["digests"][TPM_ALG_SHA256] == EV_SEPARATOR_ERR_SHA256:
            raise Fail("event %d: error EV_SEPARATOR (0xffffffff) in PCR %d" % (n, e["pcr"]))
        pcrs[e["pcr"]] = hashlib.sha256(pcrs[e["pcr"]] + e["digests"][TPM_ALG_SHA256]).digest()
        extended.add(e["pcr"])
    if need_hcrtm:
        raise Fail("StartupLocality 4 without a PCR 0 EV_EFI_HCRTM_EVENT")
    return pcrs, events


def efi_drivers(events, register, what, event="event"):
    """The events in `register` loading a UEFI driver or application from outside the
    firmware, as "EVENT N: TYPE in WHAT"."""
    return ["%s %d: %s in %s" % (event, n, EVENT_TYPES[e["type"]], what) for n, e in enumerate(events)
            if e["pcr"] == register and e["type"] in EFI_DRIVER_EVENTS]


def check_efi_drivers(drivers, allow):
    if drivers and not allow:
        raise Fail("%s: UEFI code from outside the firmware (an option ROM's driver or application) ran before l4h; "
                   "--allow-efi-drivers accepts it" % drivers[0])
    return len(drivers)


def check_event_log(log, quoted, allow_efi_drivers=False):
    """That the log replays to the quoted PCRs 0-14 (`quoted`, the
    evidence's {index: value}) and loads no UEFI driver or application from outside the
    firmware unless `allow_efi_drivers`; the number of its events and of
    such drivers."""
    pcrs, events = replay_event_log(log)
    # PCR 15 is trustd's alone: a log in which the firmware extended it
    # would have the key's quote taken over a PCR 15 that was not zero.
    if pcrs[KEY_PCR] != bytes(32):
        raise Fail("the event log extends PCR %d, which is trustd's" % KEY_PCR)
    for i in EVENT_LOG_PCRS:
        if i not in quoted:
            raise Fail("PCR %d is not quoted: the event log cannot be checked" % i)
        if quoted[i] != pcrs[i]:
            raise Fail("event log does not match the quote: PCR %d replays to %s, the quote has %s"
                       % (i, pcrs[i].hex(), quoted[i].hex()))
    drivers = check_efi_drivers(efi_drivers(events, EFI_DRIVER_PCR, "PCR %d" % EFI_DRIVER_PCR), allow_efi_drivers)
    return len(events), drivers


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


HVM_ARCH = {"x86_64": 1, "aarch64": 2}


def hvm_launch_digest(arch, kernel, initrd, cmdline, kernel_gpa, initrd_gpa, flags=0):
    """The digest vmmgr computes when it starts an HVM guest (hvm.rs,
    launch_digest): over the image files as dom0 loaded them, where it
    loaded them, the boot flags and the command line."""
    if arch not in HVM_ARCH:
        raise Fail("--hvm: x86_64 or aarch64")
    if not kernel:
        raise Fail("kernel: empty")
    if kernel_gpa is None or (initrd and initrd_gpa is None):
        raise Fail("--hvm needs --kernel-gpa, and --initrd-gpa with an initrd (l4hctl hvm-layout prints them)")
    # The command line as the host got it: a control request's data holds
    # no more (abi.h, L4H_CTL_DATA_MAX), and l4hctl refuses a longer one
    # rather than cut it.
    cmd = cmdline.encode()
    if len(cmd) > 1984:
        raise Fail("--cmdline: %d bytes; an HVM guest's is at most 1984" % len(cmd))
    h = hashlib.sha256(b"l4h-launch-hvm-v1")
    h.update(struct.pack("<QQQQ", HVM_ARCH[arch], flags, kernel_gpa, len(kernel)))
    h.update(hashlib.sha256(kernel).digest())
    h.update(struct.pack("<QQ", initrd_gpa if initrd else 0, len(initrd)))
    h.update(hashlib.sha256(initrd).digest())
    h.update(struct.pack("<Q", len(cmd)))
    h.update(cmd)
    return h.digest()


# ---- measure-host


HOST_SLOTS = (
    ("l4h-config", b"l4h-config\0present\0", b"l4h-config\0absent"),
    ("dom0-initrd", b"dom0-initrd\0present\0", b"dom0-initrd\0absent"),
)


@checked("PE/COFF image")
def pe_authenticode_digests(pe):
    """Microsoft PE/COFF Authenticode SHA-256 and SHA-384 digests (skipping
    CheckSum, the Security Directory entry, and the trailing Attribute
    Certificate Table)."""
    if not isinstance(pe, bytes) or len(pe) < 64 or pe[:2] != b"MZ":
        raise Fail("not a PE/COFF image (missing MZ header)")
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    if e_lfanew + 24 > len(pe) or pe[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise Fail("not a PE/COFF image (missing PE signature)")
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", pe, coff + 2)[0]
    opt_size = struct.unpack_from("<H", pe, coff + 16)[0]
    opt = coff + 20
    if opt + opt_size > len(pe) or opt_size < 68:
        raise Fail("PE/COFF optional header out of bounds")
    magic = struct.unpack_from("<H", pe, opt)[0]
    if magic == 0x10B:  # PE32
        num_rva_off, dd_off = opt + 92, opt + 96
    elif magic == 0x20B:  # PE32+
        num_rva_off, dd_off = opt + 108, opt + 112
    else:
        raise Fail("unsupported PE/COFF magic %#x (expected PE32 or PE32+)" % magic)
    checksum_off = opt + 64
    size_of_headers = struct.unpack_from("<I", pe, opt + 60)[0]
    sec_table = opt + opt_size
    sec_table_end = sec_table + num_sections * 40
    if size_of_headers < sec_table_end or size_of_headers > len(pe):
        raise Fail("PE/COFF SizeOfHeaders out of bounds")
    if num_rva_off + 4 > opt + opt_size:
        raise Fail("PE/COFF optional header missing NumberOfRvaAndSizes")
    num_rva = struct.unpack_from("<I", pe, num_rva_off)[0]
    sec_dir_off = None
    cert_off, cert_size = 0, 0
    if num_rva > 4:
        sec_dir_off = dd_off + 4 * 8
        if sec_dir_off + 8 > opt + opt_size:
            raise Fail("PE/COFF Security Directory entry out of bounds")
        cert_off, cert_size = struct.unpack_from("<II", pe, sec_dir_off)
        if cert_size > 0 and (cert_off < size_of_headers or cert_off + cert_size != len(pe)):
            raise Fail("PE/COFF Attribute Certificate Table out of bounds")

    h256, h384 = hashlib.sha256(), hashlib.sha384()

    def feed(chunk):
        h256.update(chunk)
        h384.update(chunk)

    feed(pe[:checksum_off])
    if sec_dir_off is not None:
        feed(pe[checksum_off + 4:sec_dir_off])
        feed(pe[sec_dir_off + 8:size_of_headers])
    else:
        feed(pe[checksum_off + 4:size_of_headers])

    sections = []
    for i in range(num_sections):
        s = sec_table + i * 40
        raw_size, raw_ptr = struct.unpack_from("<II", pe, s + 16)
        if raw_size == 0:
            continue
        if raw_ptr < size_of_headers or raw_ptr + raw_size > len(pe) - cert_size:
            raise Fail("PE/COFF section %d out of bounds" % i)
        sections.append((raw_ptr, raw_size))
    sections.sort(key=lambda x: x[0])

    total_hashed = size_of_headers
    for raw_ptr, raw_size in sections:
        feed(pe[raw_ptr:raw_ptr + raw_size])
        total_hashed += raw_size

    extra_end = len(pe) - cert_size
    if total_hashed > extra_end:
        raise Fail("PE/COFF sections overlap or exceed image size")
    if extra_end > total_hashed:
        feed(pe[total_hashed:extra_end])

    return h256.digest(), h384.digest()


def measure_host(efi=None, config=None, initrd=None):
    """Compute expected PCR 9 (SHA-256) and RTMR 2 (SHA-384) values for
    l4h-fl4-efi's external slots (policy.rs), and optional PE/COFF Authenticode
    digests of the EFI image."""
    pcr9 = bytes(32)
    rtmr2 = bytes(48)
    events = []
    for (name, present_pfx, absent_val), content in zip(HOST_SLOTS, (config, initrd)):
        data = (present_pfx + content) if content is not None else absent_val
        d256 = hashlib.sha256(data).digest()
        d384 = hashlib.sha384(data).digest()
        pcr9 = hashlib.sha256(pcr9 + d256).digest()
        rtmr2 = hashlib.sha384(rtmr2 + d384).digest()
        events.append({"name": name, "present": content is not None, "sha256": d256.hex(), "sha384": d384.hex()})
    out = {"pcr9": pcr9.hex(), "rtmr2": rtmr2.hex(), "events": events}
    if efi is not None:
        a256, a384 = pe_authenticode_digests(efi)
        out["efi_authenticode_sha256"] = a256.hex()
        out["efi_authenticode_sha384"] = a384.hex()
    return out


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


# The longest CA chain an EK certificate is checked along (manufacturers'
# are two or three deep).
EK_CHAIN_MAX = 8


def check_ek_cert(cert, cas, where, now=None):
    """That `cert` is an EK certificate one of `cas` issued and that both
    are valid now: the CA is a CA that may sign certificates within its
    RFC 5280 pathLenConstraint, the EK certificate is not a CA's, and if
    it limits its use, to an EK's.  `cas` may hold the manufacturer's
    intermediate CAs (including self-issued key-rollover CAs) and their
    root: a CA whose issuer is among `cas` too must have been issued by it
    (each hop checked as the first, up to a self-signed root); a
    non-self-issued CA whose issuer is not in `cas` is pinned as given."""
    now = now or datetime.datetime.now(datetime.timezone.utc)

    def ext(c, kind):
        try:
            return c.extensions.get_extension_for_class(kind).value
        except x509.ExtensionNotFound:
            return None

    def valid(c):
        return c.not_valid_before_utc <= now <= c.not_valid_after_utc

    def signed_by(c, ca):
        try:
            c.verify_directly_issued_by(ca)
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False

    def ca_why(ca, what, depth):
        """Why `ca` may not have issued `what`, or None.
        `depth`: non-self-issued intermediate CAs between `ca` and the leaf EK
        certificate (RFC 5280 4.2.1.9, 6.1.4)."""
        bc = ext(ca, x509.BasicConstraints)
        ku = ext(ca, x509.KeyUsage)
        if bc is None or not bc.ca:
            return "%s issuer is not a CA" % what
        if bc.path_length is not None and depth > bc.path_length:
            return "%s issuer path length constraint (%d) exceeded" % (what, bc.path_length)
        if ku is not None and not ku.key_cert_sign:
            return "%s issuer may not sign certificates" % what
        if not valid(ca):
            return "%s issuer expired or not yet valid" % what
        return None

    def up(ca, seen, depth):
        """Why the chain above `ca` (one of `cas`) does not hold, or None."""
        if len(seen) > EK_CHAIN_MAX:
            return "EK CA chain longer than %d" % EK_CHAIN_MAX
        self_issued = ca.issuer == ca.subject
        if self_issued and signed_by(ca, ca):
            return None
        named = [p for p in cas if p.subject == ca.issuer and p != ca]
        if not named:
            if self_issued:
                # Subject == Issuer without a valid self-signature or another
                # verifying issuer in `cas`: a broken root, never pinned.
                return "EK root CA %s self-signature does not verify" % ca.subject.rfc4514_string()
            return None  # pinned as given: its issuer is not in the file
        parents = [p for p in named if p not in seen]
        if not parents:
            return "EK CA chain loops"
        # RFC 5280 6.1.4: self-issued intermediate CAs (e.g. key rollover) do
        # not count toward pathLenConstraint.
        next_depth = depth + (0 if self_issued else 1)
        why = ("EK root CA %s self-signature does not verify" % ca.subject.rfc4514_string()
               if self_issued else "EK CA %s not issued by %s" % (ca.subject.rfc4514_string(), where))
        for p in parents:
            if not signed_by(ca, p):
                continue
            why = ca_why(p, "EK CA %s:" % ca.subject.rfc4514_string(), next_depth) or up(p, seen + [p], next_depth)
            if why is None:
                return None
        return why

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
            if not signed_by(cert, ca):
                continue
            why = ca_why(ca, "EK certificate", 0) or up(ca, [ca], 0)
            if why is None:
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


# What `verify` requires pinned in TPM evidence (unless
# --insecure-unpinned-measurements): PCR 2, UEFI drivers from outside the
# firmware (option ROMs); PCR 4, the UEFI application (l4h); PCR 9,
# l4h.conf and dom0's initrd.  PCR 0, the firmware itself, is only warned
# about: a cloud's vTPM firmware is the cloud's to vouch for.
TPM_REQUIRED_PCRS = (2, 4, 9)


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
        "measurements_pinned": all(i in pins for i in TPM_REQUIRED_PCRS),
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


HOST_FLAGS = {"console-in": 0}
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
    if bit == 0:
        return "console-in"
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


# ---- Intel TDX (DESIGN.md §10.2): the host's TDX evidence, its DCAP
# quote (Intel TDX DCAP Quote Generation Library: v4 and v5), Intel's
# collateral for it (PCS v4: TCB info, QE identity, CRLs), the CC event
# log, and a guest's fresh quote over its report.

TDX_KEY_DOMAIN = b"l4h-trustd-key-tdx-v1"
TDX_REPORT_DOMAIN = b"l4h-tdx-report-v1"
TDX_KEY_RTMR = 3
INTEL_QE_VENDOR_ID = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")
QUOTE_HEADER = 48
TD10_BODY, TD15_BODY = 584, 648
TEE_TYPE_TDX = 0x81
ATT_KEY_ECDSA_P256 = 2
# The certification data: the QE report's (holding the PCK certificate
# chain's).
CERT_QE_REPORT, CERT_PCK_CHAIN = 6, 5
SGX_EXTENSIONS_OID = "1.2.840.113741.1.13.1"
DEFAULT_TCB_STATUS = frozenset({"UpToDate"})
PCS_TDX = "https://api.trustedservices.intel.com/tdx/certification/v4"
PCS_SGX = "https://api.trustedservices.intel.com/sgx/certification/v4"
INTEL_ROOT_CA_CRL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
# The TD quote body's fields: (name, offset, length).  TD 1.5's adds the
# last two.
TD_BODY_FIELDS = [
    ("tee_tcb_svn", 0, 16), ("mrseam", 16, 48), ("mrsignerseam", 64, 48), ("seam_attributes", 112, 8),
    ("td_attributes", 120, 8), ("xfam", 128, 8), ("mrtd", 136, 48), ("mrconfigid", 184, 48),
    ("mrowner", 232, 48), ("mrownerconfig", 280, 48), ("rtmr0", 328, 48), ("rtmr1", 376, 48),
    ("rtmr2", 424, 48), ("rtmr3", 472, 48), ("reportdata", 520, 64),
    ("tee_tcb_svn2", 584, 16), ("mrservicetd", 600, 48),
]


def tdx_key_binding(point_bytes):
    """What a TDX quote binds the host key to: its REPORTDATA's first 48
    bytes, and what trustd extended RTMR 3 with."""
    return hashlib.sha384(TDX_KEY_DOMAIN + point_bytes).digest()


def tdx_rtmr_extended(binding):
    """RTMR 3 after trustd extended it once, from zero, with `binding`."""
    return hashlib.sha384(bytes(48) + binding).digest()


def tdx_guest_report_data(report):
    """REPORTDATA of a guest's fresh quote over its report (the COSE_Sign1's
    bytes)."""
    return hashlib.sha384(TDX_REPORT_DOMAIN + hashlib.sha256(report).digest()).digest() + bytes(16)


class LeReader:
    def __init__(self, b, what):
        self.b, self.at, self.what = b, 0, what

    def take(self, n):
        if n > len(self.b) - self.at:
            raise Fail("%s cut short" % self.what)
        s = self.b[self.at:self.at + n]
        self.at += n
        return s

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]


@checked("TDX quote")
def parse_tdx_quote(q):
    """A TDX DCAP quote, v4 or v5, with ECDSA-P256 signatures, parsed in
    full: every byte belongs to one of its parts."""
    if not isinstance(q, bytes):
        raise Fail("TDX quote is not bytes")
    r = LeReader(q, "TDX quote")
    header = r.take(QUOTE_HEADER)
    version, key_type, tee_type = struct.unpack_from("<HHI", header)
    if version not in (4, 5):
        raise Fail("TDX quote version %d is neither 4 nor 5" % version)
    if key_type != ATT_KEY_ECDSA_P256:
        raise Fail("TDX quote attestation key is not ECDSA P-256")
    if tee_type != TEE_TYPE_TDX:
        raise Fail("not a TDX quote (TEE type %#x)" % tee_type)
    # Bytes 8-11 are reserved in v4 and v5: the SVNs are the PCK
    # certificate's and the QE report's (verify_tdx_quote).
    if header[12:28] != INTEL_QE_VENDOR_ID:
        raise Fail("TDX quote is not from Intel's QE (vendor %s)" % header[12:28].hex())
    if version == 4:
        size = TD10_BODY
    else:
        kind, size = r.u16(), r.u32()
        if (kind, size) not in ((2, TD10_BODY), (3, TD15_BODY)):
            raise Fail("TDX quote v5 body is neither TD 1.0's nor TD 1.5's (type %d, %d bytes)" % (kind, size))
    body = r.take(size)
    signed = q[:r.at]
    sig_data = LeReader(r.take(r.u32()), "TDX quote signature data")
    if r.at != len(q):
        raise Fail("trailing bytes after the TDX quote")
    sig, att_key = sig_data.take(64), sig_data.take(64)
    if sig_data.u16() != CERT_QE_REPORT:
        raise Fail("TDX quote certification data is not the QE report's")
    cert = LeReader(sig_data.take(sig_data.u32()), "TDX quote QE report certification data")
    if sig_data.at != len(sig_data.b):
        raise Fail("trailing bytes after the TDX quote signature data")
    qe_report, qe_report_sig = cert.take(384), cert.take(64)
    qe_auth = cert.take(cert.u16())
    if cert.u16() != CERT_PCK_CHAIN:
        raise Fail("TDX quote has no PCK certificate chain")
    chain = cert.take(cert.u32())
    if cert.at != len(cert.b):
        raise Fail("trailing bytes after the TDX quote certification data")
    fields = {name: body[off:off + n] for name, off, n in TD_BODY_FIELDS if off + n <= len(body)}
    return {"version": version, "body": body, "fields": fields,
            "signed": signed, "sig": sig, "att_key": att_key, "qe_report": qe_report, "qe_report_sig": qe_report_sig,
            "qe_auth": qe_auth, "pck_chain": chain}


def p256_raw(xy):
    """A P-256 key from its 64-byte x || y."""
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(xy[:32], "big"), int.from_bytes(xy[32:], "big"),
                                             ec.SECP256R1()).public_key()
    except ValueError:
        raise Fail("invalid P-256 attestation key")


def ecdsa_raw_ok(key, sig, data):
    """Whether `sig` (r || s, 32 bytes each) is `key`'s ECDSA-SHA256 over
    `data`."""
    try:
        key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), data,
                   ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---- DER, for the PCK certificate's SGX extensions (Intel SGX PCK
# Certificate and CRL Profile)


def der_item(b, at=0):
    """(tag, contents, end) of the DER item at `at`."""
    if at + 2 > len(b):
        raise Fail("malformed DER")
    tag, n = b[at], b[at + 1]
    at += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or at + k > len(b):
            raise Fail("malformed DER length")
        n, at = int.from_bytes(b[at:at + k], "big"), at + k
    if at + n > len(b):
        raise Fail("malformed DER")
    return tag, b[at:at + n], at + n


def der_seq(b):
    """The items of a DER SEQUENCE's contents."""
    out, at = [], 0
    while at < len(b):
        tag, v, at = der_item(b, at)
        out.append((tag, v))
    return out


def der_oid(v):
    first, rest = divmod(v[0], 40) if v[0] < 80 else (2, v[0] - 80)
    parts, n = [first, rest], 0
    for c in v[1:]:
        n = n << 7 | c & 0x7F
        if not c & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


def der_int(v):
    return int.from_bytes(v, "big", signed=True)


@checked("PCK certificate SGX extensions")
def sgx_extensions(cert):
    """The PCK certificate's SGX extensions: FMSPC, PCE-ID, the PCK's TCB
    (16 component SVNs, PCESVN, CPUSVN), PPID, SGX type."""
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(SGX_EXTENSIONS_OID)).value
    except x509.ExtensionNotFound:
        raise Fail("PCK certificate without SGX extensions")
    tag, v, end = der_item(ext.value)
    if tag != 0x30 or end != len(ext.value):
        raise Fail("malformed SGX extensions")
    out = {}
    for tag, entry in der_seq(v):
        items = der_seq(entry)
        if tag != 0x30 or len(items) != 2 or items[0][0] != 0x06:
            raise Fail("malformed SGX extension")
        oid, (vtag, val) = der_oid(items[0][1]), items[1]
        name = oid[len(SGX_EXTENSIONS_OID) + 1:] if oid.startswith(SGX_EXTENSIONS_OID + ".") else None
        if name == "1":
            out["ppid"] = val
        elif name == "2":
            comps, tcb = [None] * 16, {}
            for t, e in der_seq(val):
                sub = der_seq(e)
                if t != 0x30 or len(sub) != 2 or sub[0][0] != 0x06:
                    raise Fail("malformed SGX TCB extension")
                sub_oid = der_oid(sub[0][1])
                if not sub_oid.startswith(SGX_EXTENSIONS_OID + ".2.") or not sub_oid.rsplit(".", 1)[1].isdigit():
                    raise Fail("malformed SGX TCB extension")
                n = sub_oid.rsplit(".", 1)[1]
                if 1 <= int(n) <= 16:
                    comps[int(n) - 1] = der_int(sub[1][1])
                elif n == "17":
                    tcb["pcesvn"] = der_int(sub[1][1])
                elif n == "18":
                    tcb["cpusvn"] = sub[1][1]
            if None in comps or "pcesvn" not in tcb:
                raise Fail("SGX TCB extension incomplete")
            out["tcb"] = {"components": comps, **tcb}
        elif name == "3":
            out["pceid"] = val
        elif name == "4":
            out["fmspc"] = val
        elif name == "5":
            out["sgx_type"] = der_int(val)
    for k in ("fmspc", "pceid", "tcb"):
        if k not in out:
            raise Fail("PCK certificate SGX extensions lack %s" % k)
    if len(out["fmspc"]) != 6 or len(out["pceid"]) != 2:
        raise Fail("malformed FMSPC or PCE-ID")
    return out


# ---- Certificates and collateral


def load_certs(data, what):
    try:
        # A quote's PEM chain may end in NULs.
        certs = x509.load_pem_x509_certificates(data.rstrip(b"\x00"))
    except ValueError:
        certs = []
    if not certs:
        raise Fail("no certificate in %s" % what)
    return certs


def cert_ext(c, kind):
    try:
        return c.extensions.get_extension_for_class(kind).value
    except x509.ExtensionNotFound:
        return None


def check_issued(cert, issuer, what, now, ca=False):
    """That `issuer` (a CA that may sign certificates) signed `cert`, and
    that both are valid at `now`; `ca`: `cert` is a CA's too."""
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        raise Fail("%s not issued by %s" % (what, issuer.subject.rfc4514_string()))
    for c, name in ((cert, what), (issuer, "the issuer of " + what)):
        if not c.not_valid_before_utc <= now <= c.not_valid_after_utc:
            raise Fail("%s expired or not yet valid" % name)
    bc, ku = cert_ext(issuer, x509.BasicConstraints), cert_ext(issuer, x509.KeyUsage)
    if bc is None or not bc.ca:
        raise Fail("the issuer of %s is not a CA" % what)
    if ku is not None and not ku.key_cert_sign:
        raise Fail("the issuer of %s may not sign certificates" % what)
    bc = cert_ext(cert, x509.BasicConstraints)
    if ca and (bc is None or not bc.ca):
        raise Fail("%s is not a CA" % what)
    if not ca and bc is not None and bc.ca:
        raise Fail("%s is a CA certificate" % what)


def to_root(cert, roots, what, now):
    """That `cert` (a CA's) is one of the pinned `roots`, or issued by one."""
    for root in roots:
        if cert == root:
            if not root.not_valid_before_utc <= now <= root.not_valid_after_utc:
                raise Fail("the Intel root CA expired or is not yet valid")
            return root
    why = None
    for root in roots:
        try:
            check_issued(cert, root, what, now, ca=True)
            return root
        except Fail as e:
            why = e
    raise why or Fail("%s not issued by the pinned Intel root CA" % what)


def load_crl(data, what):
    try:
        return x509.load_pem_x509_crl(data)
    except ValueError:
        try:
            return x509.load_der_x509_crl(data)
        except ValueError:
            raise Fail("malformed CRL %s" % what)


def check_crl(crl, issuer, certs, what, now, stale_ok):
    """That `issuer` signed `crl`, which is current, and revokes none of
    `certs` ((certificate, name) pairs)."""
    if crl.issuer != issuer.subject or not crl.is_signature_valid(issuer.public_key()):
        raise Fail("%s is not signed by %s" % (what, issuer.subject.rfc4514_string()))
    ku = cert_ext(issuer, x509.KeyUsage)
    if ku is not None and not ku.crl_sign:
        raise Fail("the issuer of %s may not sign CRLs" % what)
    if not stale_ok and (crl.next_update_utc is None or crl.next_update_utc < now or crl.last_update_utc > now):
        raise Fail("%s is out of date" % what)
    for c, name in certs:
        if crl.get_revoked_certificate_by_serial_number(c.serial_number) is not None:
            raise Fail("%s is revoked (%s)" % (name, what))


def signed_json(text, field, what):
    """The value of `field` in Intel's signed JSON `text` (bytes), as it is
    written (the signature is over those bytes), its parsed value, and the
    signature."""
    try:
        s = text.decode()
        doc = json.loads(s)
        key = '"%s"' % field
        at = s.index(key) + len(key)
        while s[at] in " \t\r\n:":
            at += 1
        value, end = json.JSONDecoder().raw_decode(s, at)
        sig = bytes.fromhex(doc["signature"])
    except (ValueError, KeyError, TypeError, IndexError, UnicodeDecodeError):
        raise Fail("malformed %s" % what)
    if not isinstance(doc, dict) or doc.get(field) != value or not isinstance(value, dict) or len(sig) != 64:
        raise Fail("malformed %s" % what)
    return s[at:end].encode(), value, sig


def iso_time(t, what):
    try:
        d = datetime.datetime.fromisoformat(t.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise Fail("malformed %s" % what)
    return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)


def check_current(doc, what, now, stale_ok):
    if stale_ok:
        return
    if not iso_time(doc.get("issueDate"), what + " issueDate") <= now <= iso_time(doc.get("nextUpdate"), what + " nextUpdate"):
        raise Fail("%s is out of date (next update %s)" % (what, doc.get("nextUpdate")))


def hex_field(doc, key, n, what):
    v = doc.get(key)
    try:
        b = bytes.fromhex(v)
    except (TypeError, ValueError):
        raise Fail("malformed %s %s" % (what, key))
    if len(b) != n:
        raise Fail("malformed %s %s" % (what, key))
    return b


def masked(value, mask):
    return bytes(a & b for a, b in zip(value, mask))


@checked("TCB info")
def tdx_tcb_status(info, fields, ext, svn_field="tee_tcb_svn"):
    """The TCB status of the quote's platform (TCB info's tcbLevels, Intel's
    TDX quote verification): the first level that the PCK's SGX TCB and the
    TD's TEE_TCB_SVN (or `svn_field`: TEE_TCB_SVN2, a TD 1.5 quote's module
    after a TD-preserving update) reach, and with a TDX module of major
    version 1 or later, its module identity's first level its SVN
    reaches."""
    svn = fields[svn_field]
    comps, pcesvn = ext["tcb"]["components"], ext["tcb"]["pcesvn"]
    # TDX 1.0's module (TEE_TCB_SVN[1] zero) is tdxModule's; a later one,
    # its tdxModuleIdentities entry's alone (below).
    if svn[1] == 0:
        mod = info.get("tdxModule")
        if not isinstance(mod, dict):
            raise Fail("TCB info has no tdxModule")
        if hex_field(mod, "mrsigner", 48, "tdxModule") != fields["mrsignerseam"]:
            raise Fail("TDX module signer (MRSIGNERSEAM) is not the one TCB info names")
        if masked(fields["seam_attributes"], hex_field(mod, "attributesMask", 8, "tdxModule")) != hex_field(mod, "attributes", 8, "tdxModule"):
            raise Fail("TDX module attributes are not the ones TCB info names")
    level = None
    for lv in info["tcbLevels"]:
        t = lv["tcb"]
        sgx = [c["svn"] for c in t["sgxtcbcomponents"]]
        tdx = [c["svn"] for c in t["tdxtcbcomponents"]]
        if len(sgx) != 16 or len(tdx) != 16 or not all(is_int(x) for x in sgx + tdx) or not is_int(t["pcesvn"]):
            raise Fail("malformed TCB level")
        start = 2 if svn[1] > 0 else 0
        if all(c >= s for c, s in zip(comps, sgx)) and pcesvn >= t["pcesvn"] and all(svn[i] >= tdx[i] for i in range(start, 16)):
            level = lv
            break
    if level is None:
        raise Fail("no TCB level matches the platform (TCB status unknown: revoked or too old)")
    module = None
    if svn[1] > 0:
        want = "TDX_%02X" % svn[1]
        ident = [m for m in info.get("tdxModuleIdentities", []) if m.get("id") == want]
        if not ident:
            raise Fail("TCB info has no TDX module identity %s" % want)
        m = ident[0]
        if hex_field(m, "mrsigner", 48, want) != fields["mrsignerseam"]:
            raise Fail("TDX module signer is not the one %s names" % want)
        if masked(fields["seam_attributes"], hex_field(m, "attributesMask", 8, want)) != hex_field(m, "attributes", 8, want):
            raise Fail("TDX module attributes are not the ones %s names" % want)
        for lv in m["tcbLevels"]:
            if is_int(lv["tcb"]["isvsvn"]) and svn[0] >= lv["tcb"]["isvsvn"]:
                module = lv
                break
        if module is None:
            raise Fail("no %s TCB level matches the TDX module's SVN %d" % (want, svn[0]))
    return level, module


@checked("QE identity")
def qe_tcb_status(ident, qe_report):
    """The QE's TCB status from QE identity, after its identity checks."""
    misc = struct.unpack_from("<I", qe_report, 16)[0]
    want_misc = struct.unpack("<I", hex_field(ident, "miscselect", 4, "QE identity"))[0]
    misc_mask = struct.unpack("<I", hex_field(ident, "miscselectMask", 4, "QE identity"))[0]
    if misc & misc_mask != want_misc:
        raise Fail("QE MISCSELECT is not the one QE identity names")
    if masked(qe_report[48:64], hex_field(ident, "attributesMask", 16, "QE identity")) != hex_field(ident, "attributes", 16, "QE identity"):
        raise Fail("QE attributes are not the ones QE identity names")
    if qe_report[128:160] != hex_field(ident, "mrsigner", 32, "QE identity"):
        raise Fail("QE signer (MRSIGNER) is not Intel's")
    prod, isvsvn = struct.unpack_from("<HH", qe_report, 256)
    if not is_int(ident.get("isvprodid")) or prod != ident["isvprodid"]:
        raise Fail("QE product ID is not the one QE identity names")
    for lv in ident["tcbLevels"]:
        if is_int(lv["tcb"]["isvsvn"]) and isvsvn >= lv["tcb"]["isvsvn"]:
            return lv
    raise Fail("no QE identity TCB level matches the QE's SVN %d" % isvsvn)


class Collateral:
    """Intel's collateral for TDX quotes, as files: TCB info, QE identity
    (both signed by a TCB signing certificate the root CA issued: QE
    identity's own chain if given, else TCB info's), the PCK CRL and the
    root CA's CRL."""

    NAMES = {"tcb_info": "tcb_info.json", "qe_identity": "qe_identity.json", "pck_crl": "pck_crl.pem",
             "tcb_signing_chain": "tcb_signing_chain.pem", "root_ca_crl": "root_ca_crl.der",
             "qe_identity_signing_chain": "qe_identity_signing_chain.pem"}
    REQUIRED = ("tcb_info", "qe_identity", "tcb_signing_chain", "pck_crl", "root_ca_crl")

    def __init__(self, directory=None, **paths):
        self.files = {}
        for key, name in self.NAMES.items():
            path = paths.get(key) or (os.path.join(directory, name) if directory else None)
            if path and (paths.get(key) or os.path.exists(path)):
                try:
                    with open(path, "rb") as f:
                        self.files[key] = f.read()
                except OSError as e:
                    raise Fail("%s: %s" % (path, e.strerror))

    def __bool__(self):
        return bool(self.files)


TCB_SIGNING_CN = "Intel SGX TCB Signing"


def tcb_signer(chain, roots, what, now):
    """The TCB signing certificate first in `chain`, issued by one of the
    pinned `roots`, named and marked as one: the certificate and its root."""
    signer = load_certs(chain, what)[0]
    if signer in roots:
        raise Fail("%s is a root CA" % what)
    cn = signer.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not cn or TCB_SIGNING_CN not in cn[0].value:
        raise Fail("%s is not Intel's TCB signing certificate (%s)" % (what, signer.subject.rfc4514_string()))
    ku = cert_ext(signer, x509.KeyUsage)
    if ku is not None and not ku.digital_signature:
        raise Fail("%s may not sign" % what)
    why = None
    for r in roots:
        try:
            check_issued(signer, r, what, now)
            return signer, r
        except Fail as e:
            why = e
    raise why or Fail("%s not issued by the pinned Intel root CA" % what)


def merged(*lists):
    """The items of `lists` in order, each once."""
    out = []
    for xs in lists:
        for x in xs:
            if x not in out:
                out.append(x)
    return out


def check_collateral(q, ext, leaf, pck_ca, pck_root, roots, col, allowed, now, stale_ok):
    """The quote's TCB status and its QE's, against Intel's collateral.
    `pck_root`: the pinned root the PCK CA chains to."""
    for need in Collateral.REQUIRED:
        if need not in col.files:
            raise Fail("collateral without %s (fetch-collateral saves it)" % Collateral.NAMES[need])
    signer, root = tcb_signer(col.files["tcb_signing_chain"], roots, "the TCB signing certificate", now)
    qe_signer, qe_root = (tcb_signer(col.files["qe_identity_signing_chain"], roots, "the QE identity signing certificate", now)
                          if "qe_identity_signing_chain" in col.files else (signer, root))
    # Each certificate the root CA CRL covers is checked against the root
    # that issued it: the CRL must be that root's.  With several pinned
    # roots (Intel rotating its root), one CRL cannot speak for a
    # certificate of another root, which would then go unchecked.
    revocable = [(pck_ca, pck_root, "the PCK CA certificate"), (signer, root, "the TCB signing certificate")]
    if qe_signer != signer:
        revocable.append((qe_signer, qe_root, "the QE identity signing certificate"))
    root_crl = load_crl(col.files["root_ca_crl"], "root CA CRL")
    for r in merged([r for _, r, _ in revocable]):
        check_crl(root_crl, r, [(c, n) for c, cr, n in revocable if cr == r], "the root CA CRL", now, stale_ok)
    check_crl(load_crl(col.files["pck_crl"], "PCK CRL"), pck_ca, [(leaf, "the PCK certificate")], "the PCK CRL", now, stale_ok)

    raw, info, sig = signed_json(col.files["tcb_info"], "tcbInfo", "TCB info")
    if not ecdsa_raw_ok(signer.public_key(), sig, raw):
        raise Fail("TCB info signature does not verify")
    if info.get("id") != "TDX" or info.get("version") != 3:
        raise Fail("TCB info is not TDX's (version 3)")
    check_current(info, "TCB info", now, stale_ok)
    if hex_field(info, "fmspc", 6, "TCB info") != ext["fmspc"]:
        raise Fail("TCB info is for FMSPC %s, the PCK certificate's is %s" % (info.get("fmspc"), ext["fmspc"].hex()))
    if hex_field(info, "pceId", 2, "TCB info") != ext["pceid"]:
        raise Fail("TCB info is for another PCE")
    level, module = tdx_tcb_status(info, q["fields"], ext)
    # TD 1.5: TEE_TCB_SVN is the module's at the TD's launch, TEE_TCB_SVN2
    # its current one (after a TD-preserving update).  Both must pass.
    current = tdx_tcb_status(info, q["fields"], ext, "tee_tcb_svn2") if "tee_tcb_svn2" in q["fields"] else None

    raw, ident, sig = signed_json(col.files["qe_identity"], "enclaveIdentity", "QE identity")
    if not ecdsa_raw_ok(qe_signer.public_key(), sig, raw):
        raise Fail("QE identity signature does not verify")
    if ident.get("id") != "TD_QE" or ident.get("version") != 2:
        raise Fail("QE identity is not TDX's QE's (version 2)")
    check_current(ident, "QE identity", now, stale_ok)
    qe = qe_tcb_status(ident, q["qe_report"])

    statuses = {"tcb_status": level["tcbStatus"], "qe_tcb_status": qe["tcbStatus"]}
    if module is not None:
        statuses["tdx_module_tcb_status"] = module["tcbStatus"]
    levels = [level, module]
    if current is not None:
        statuses["tcb_status_current"] = current[0]["tcbStatus"]
        if current[1] is not None:
            statuses["tdx_module_tcb_status_current"] = current[1]["tcbStatus"]
        levels += list(current)
    for what, status in statuses.items():
        if status not in allowed:
            raise Fail("%s is %s (allow it with --allow-tcb-status)" % (what.replace("_", " "), status))
    advisories = merged(*[(lv or {}).get("advisoryIDs", []) for lv in levels], qe.get("advisoryIDs", []))
    return {**statuses, "advisory_ids": advisories, "tcb_date": level.get("tcbDate"),
            "tcb_evaluation_data_number": info.get("tcbEvaluationDataNumber")}


class TdxPolicy:
    """What a TDX quote must show: Intel's root CA (pinned), the collateral
    for its TCB status (required unless `require_collateral` is False:
    only for tests), debug or not, and measurements."""

    def __init__(self, roots, collateral=None, allowed=DEFAULT_TCB_STATUS, allow_debug=False, stale_ok=False,
                 mrtd=None, rtmrs=None, cc_event_log=None, now=None, allow_migratable=False, require_collateral=True,
                 allow_efi_drivers=False):
        self.roots, self.collateral, self.allowed = roots, collateral, frozenset(allowed)
        self.require_collateral = require_collateral
        self.allow_debug, self.stale_ok, self.allow_migratable = allow_debug, stale_ok, allow_migratable
        self.mrtd, self.rtmrs, self.cc_event_log = mrtd, rtmrs or {}, cc_event_log
        self.allow_efi_drivers = allow_efi_drivers
        self.now = now or datetime.datetime.now(datetime.timezone.utc)


def verify_tdx_quote(q, policy):
    """Check a TDX quote down to Intel's root CA: the attestation key's
    signature over header and body, the QE report binding that key and
    signed by the PCK certificate, the PCK chain, then the TD's attributes,
    measurements and TCB status.  The parsed quote and what it says."""
    if not policy.roots:
        raise Fail("a TDX quote needs Intel's root CA (--intel-root-ca)")
    # Without collateral nothing says the QE is Intel's (QE identity: its
    # MRSIGNER, ISVPRODID, ISVSVN, a non-debug enclave) nor the TDX module
    # (TCB info: MRSIGNERSEAM): any SGX machine with flexible launch control
    # has the real PCE sign the report of an enclave of anyone's making,
    # which then signs any quote.
    if not policy.collateral and policy.require_collateral:
        raise Fail("a TDX quote needs Intel's collateral (--collateral-dir, from fetch-collateral) to check the QE's "
                   "identity and the TDX module's signer; --insecure-skip-collateral skips it, for tests only")
    p = parse_tdx_quote(q)
    if not ecdsa_raw_ok(p256_raw(p["att_key"]), p["sig"], p["signed"]):
        raise Fail("TDX quote signature does not verify")
    qe = p["qe_report"]
    if qe[320:352] != hashlib.sha256(p["att_key"] + p["qe_auth"]).digest() or qe[352:384] != bytes(32):
        raise Fail("the QE report does not bind the quote's attestation key")
    certs = load_certs(p["pck_chain"], "the quote's PCK certificate chain")
    if len(certs) < 2:
        raise Fail("the quote's PCK certificate chain lacks its CA")
    leaf, pck_ca = certs[0], certs[1]
    check_issued(leaf, pck_ca, "the PCK certificate", policy.now)
    pck_root = to_root(pck_ca, policy.roots, "the PCK CA certificate", policy.now)
    if not isinstance(leaf.public_key(), ec.EllipticCurvePublicKey) or not ecdsa_raw_ok(leaf.public_key(), p["qe_report_sig"], qe):
        raise Fail("the QE report is not signed by the PCK certificate")
    ext = sgx_extensions(leaf)
    f = p["fields"]
    # TD_ATTRIBUTES bits 7:0 (TUD: debug and profiling bits): any non-zero bit
    # opens the TD's state to the host.
    if f["td_attributes"][0] != 0 and not policy.allow_debug:
        raise Fail("the TD is a debug TD or has TUD attributes set (td_attributes[0]=%#04x): allow it with --allow-debug"
                   % f["td_attributes"][0])
    # TD_ATTRIBUTES.MIGRATABLE (bit 29): a migration TD could move this TD's
    # state elsewhere.
    migratable = bool(f["td_attributes"][3] & 0x20)
    if migratable and not policy.allow_migratable:
        raise Fail("the TD is migratable: allow it with --allow-migratable")
    # TD 1.5: a service TD (a migration TD among them) bound to this TD
    # can read and move its state.
    if "mrservicetd" in f and f["mrservicetd"] != bytes(48) and not policy.allow_migratable:
        raise Fail("TD15 quote binds a non-zero MRSERVICETD: allow it with --allow-migratable")
    if policy.mrtd is not None and f["mrtd"] != policy.mrtd:
        raise Fail("MRTD is %s, not %s" % (f["mrtd"].hex(), policy.mrtd.hex()))
    for i, want in policy.rtmrs.items():
        if f["rtmr%d" % i] != want:
            raise Fail("RTMR %d is %s, not %s" % (i, f["rtmr%d" % i].hex(), want.hex()))
    out = {
        "quote_version": p["version"],
        "body": "TD15" if len(p["body"]) == TD15_BODY else "TD10",
        "debug": bool(f["td_attributes"][0] != 0),
        "migratable": migratable,
        "sept_ve_disable": bool(f["td_attributes"][3] & 0x10),
        "perfmon": bool(f["td_attributes"][7] & 0x80),
        "measurements_pinned": policy.mrtd is not None and 1 in policy.rtmrs and 2 in policy.rtmrs,
        **{k: v.hex() for k, v in f.items() if k != "reportdata"},
        "fmspc": ext["fmspc"].hex(),
        "pceid": ext["pceid"].hex(),
        "qe_svn": struct.unpack_from("<H", qe, 258)[0],
        "pce_svn": ext["tcb"]["pcesvn"],
        "pck_subject": leaf.subject.rfc4514_string(),
    }
    if policy.cc_event_log is not None:
        out["cc_event_log_events"], out["cc_event_log_efi_drivers"] = check_cc_event_log(
            policy.cc_event_log, f, policy.allow_efi_drivers)
    if policy.collateral:
        out.update(check_collateral(p, ext, leaf, pck_ca, pck_root, policy.roots, policy.collateral, policy.allowed,
                                    policy.now, policy.stale_ok))
    else:
        out["tcb_status"] = None
    return p, out


@checked("TDX evidence")
def check_tdx_evidence(ev, policy):
    """The host's signing key and what its TDX evidence shows about it: a
    quote whose REPORTDATA binds the key, taken while RTMR 3 was zero (the
    first key of this boot: trustd extends RTMR 3 with it at once)."""
    if not isinstance(ev, dict) or ev.get("type") != "tdx":
        raise Fail("not TDX evidence")
    if not is_int(ev.get("v")) or ev["v"] != 1:
        raise Fail("unknown TDX evidence version")
    if set(ev) != {"v", "type", "key", "quote"}:
        raise Fail("TDX evidence has unknown fields")
    key = cose_p256(ev["key"])
    p, out = verify_tdx_quote(ev["quote"], policy)
    binding = tdx_key_binding(point(key))
    if p["fields"]["reportdata"] != binding + bytes(16):
        raise Fail("the TDX quote is not over this host key")
    if p["fields"]["rtmr3"] != bytes(48):
        raise Fail("RTMR 3 is not zero: not the first host key of this boot")
    return key, {"key": hashlib.sha256(point(key)).hexdigest(), **out}


@checked("TDX quote answer")
def check_tdx_quote_answer(ans, policy):
    """A guest's fresh quote (l4hctl attest tdx-quote): the host key, the
    quote and the report it is over.  The quote's REPORTDATA must bind the
    report, and its RTMR 3 the key (extended once from zero).  The key
    (to check the report with) and what the quote says."""
    if not isinstance(ans, dict) or set(ans) != {"key", "quote", "report"} or not isinstance(ans["report"], bytes):
        raise Fail("not a TDX quote answer")
    key = cose_p256(ans["key"])
    p, out = verify_tdx_quote(ans["quote"], policy)
    if p["fields"]["reportdata"] != tdx_guest_report_data(ans["report"]):
        raise Fail("the TDX quote is not over this report")
    if p["fields"]["rtmr3"] != tdx_rtmr_extended(tdx_key_binding(point(key))):
        raise Fail("RTMR 3 does not hold this host key: not the first key of this boot")
    return key, {"key": hashlib.sha256(point(key)).hexdigest(), **out}


# ---- The CC event log (CCEL): a TCG2 crypto agile log whose digests are
# SHA-384 and whose PCR index is the CC measurement register: 1-4 are RTMR
# 0-3 (0, MRTD, is never extended).


TPM_ALG_SHA384 = 0x000C


def replay_cc_event_log(log):
    """RTMR 0-3 as the log's events extend them from zero, and the events."""
    sizes, events = parse_event_log(log, zero_pad=True, cc=True)
    if sizes.get(TPM_ALG_SHA384) != 48:
        raise Fail("the CC event log has no SHA-384 digests")
    rtmrs = [bytes(48)] * 4
    for n, e in enumerate(events):
        if e["type"] == EV_NO_ACTION:
            continue
        if not 1 <= e["pcr"] <= 4:
            raise Fail("CC event %d extends measurement register %d" % (n, e["pcr"]))
        if TPM_ALG_SHA384 not in e["digests"]:
            raise Fail("CC event %d has no SHA-384 digest" % n)
        if e["type"] == EV_SEPARATOR and e["digests"][TPM_ALG_SHA384] == EV_SEPARATOR_ERR_SHA384:
            raise Fail("CC event %d: error EV_SEPARATOR (0xffffffff) in RTMR %d" % (n, e["pcr"] - 1))
        i = e["pcr"] - 1
        rtmrs[i] = hashlib.sha384(rtmrs[i] + e["digests"][TPM_ALG_SHA384]).digest()
    return rtmrs, events


def check_cc_event_log(log, fields, allow_efi_drivers=False):
    """That the CC event log replays to the quote's RTMR 0-2 (RTMR 3 is
    trustd's key) and loads no UEFI driver or application from outside the firmware
    (in RTMR 0) unless `allow_efi_drivers`; the number of its events and
    of such drivers."""
    rtmrs, events = replay_cc_event_log(log)
    # RTMR 3 is trustd's alone: the firmware must not have extended it.
    if rtmrs[TDX_KEY_RTMR] != bytes(48):
        raise Fail("the CC event log extends RTMR %d, which is trustd's" % TDX_KEY_RTMR)
    for i in range(3):
        if rtmrs[i] != fields["rtmr%d" % i]:
            raise Fail("CC event log does not match the quote: RTMR %d replays to %s, the quote has %s"
                       % (i, rtmrs[i].hex(), fields["rtmr%d" % i].hex()))
    # Register index 1 is RTMR 0, where the TD firmware measures drivers.
    drivers = check_efi_drivers(efi_drivers(events, 1, "RTMR 0", "CC event"), allow_efi_drivers)
    return len(events), drivers


def cc_event_log_summary(log):
    rtmrs, events = replay_cc_event_log(log)

    def data(e):
        d = e["data"]
        return d.decode("ascii") if d and all(32 <= b < 127 for b in d) else d[:32].hex() + ("..." if len(d) > 32 else "")
    return {
        "algorithms": ["%#06x" % TPM_ALG_SHA384],
        "events": [{"rtmr": e["pcr"] - 1 if e["type"] != EV_NO_ACTION else None,
                    "type": EVENT_TYPES.get(e["type"], "%#x" % e["type"]),
                    "sha384": e["digests"][TPM_ALG_SHA384].hex() if TPM_ALG_SHA384 in e["digests"] else None,
                    "size": len(e["data"]), "data": data(e)} for e in events],
        "rtmrs": {str(i): rtmrs[i].hex() for i in range(4)},
    }


def is_cc_event_log(log):
    """A log with SHA-384 digests and no SHA-256 ones: a CCEL, not a TPM's."""
    sizes, _ = parse_event_log(log, zero_pad=True, cc=True)
    return TPM_ALG_SHA256 not in sizes and TPM_ALG_SHA384 in sizes


# ---- Which evidence: the TPM's (v1, v2), TDX's (type "tdx"), or the
# guest driver's both together (v3: {"v": 3, "tdx": ..., "tpm": ...}).


@checked("evidence")
def split_evidence(ev):
    """(TPM evidence, TDX evidence), either None."""
    if not isinstance(ev, dict):
        raise Fail("evidence is not a CBOR map")
    if ev.get("type") == "tdx":
        return None, ev
    if is_int(ev.get("v")) and ev["v"] == 3:
        if set(ev) != {"v", "tdx", "tpm"}:
            raise Fail("combined evidence is not {v, tdx, tpm}")
        return ev["tpm"], ev["tdx"]
    return ev, None


def quote_of(doc):
    """The TDX quote in TDX evidence, combined evidence or a quote answer."""
    if isinstance(doc, dict):
        if "quote" in doc and isinstance(doc["quote"], bytes):
            return doc["quote"]
        if isinstance(doc.get("tdx"), dict):
            return quote_of(doc["tdx"])
    raise Fail("no TDX quote in this file")


# ---- fetch-collateral


def pcs_get(url):
    """(headers, body) of an HTTPS GET."""
    import urllib.request
    import urllib.error
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "l4h-attest"}), timeout=60) as r:
            return {k.lower(): v for k, v in r.headers.items()}, r.read()
    except (urllib.error.URLError, OSError) as e:
        raise Fail("%s: %s" % (url, e))


def issuer_chain(headers, name):
    import urllib.parse
    v = headers.get(name.lower())
    if not v:
        raise Fail("PCS answer without %s" % name)
    return urllib.parse.unquote(v).encode()


def fetch_collateral(quote, out, get=pcs_get, tdx_base=PCS_TDX, sgx_base=PCS_SGX, root_crl=INTEL_ROOT_CA_CRL):
    """Save Intel's collateral for `quote` in directory `out` (Collateral's
    names, and intel_root_ca.pem: the root of PCS's chain, which is only
    what the network said: compare it with Intel's published root before
    pinning it).  The files written."""
    p = parse_tdx_quote(quote)
    certs = load_certs(p["pck_chain"], "the quote's PCK certificate chain")
    ext = sgx_extensions(certs[0])
    if len(certs) < 2:
        raise Fail("the quote's PCK certificate chain lacks its CA")
    cn = certs[1].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    ca = "processor" if cn and "Processor" in cn[0].value else "platform"
    os.makedirs(out, exist_ok=True)
    files = {}
    h, body = get("%s/tcb?fmspc=%s" % (tdx_base, ext["fmspc"].hex().upper()))
    files["tcb_info.json"] = body
    chain = issuer_chain(h, "TCB-Info-Issuer-Chain")
    files["tcb_signing_chain.pem"] = chain
    h, body = get("%s/qe/identity" % tdx_base)
    files["qe_identity.json"] = body
    files["qe_identity_signing_chain.pem"] = issuer_chain(h, "SGX-Enclave-Identity-Issuer-Chain")
    h, body = get("%s/pckcrl?ca=%s&encoding=pem" % (sgx_base, ca))
    files["pck_crl.pem"] = body
    _, body = get(root_crl)
    files["root_ca_crl.der"] = body
    roots = [c for c in load_certs(chain, "the TCB info issuer chain") if c.subject == c.issuer]
    if not roots:
        raise Fail("the TCB info issuer chain has no root CA")
    files["intel_root_ca.pem"] = roots[0].public_bytes(serialization.Encoding.PEM)
    for name, data in files.items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
    fp = hashlib.sha256(roots[0].public_bytes(serialization.Encoding.DER)).hexdigest()
    print("l4h-attest: saved %s; intel_root_ca.pem (SHA-256 %s) is what PCS sent: check it against Intel's "
          "published root before pinning it with --intel-root-ca" % (", ".join(sorted(files)), fp), file=sys.stderr)
    return sorted(files)


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


def add_tdx_options(v):
    v.add_argument("--intel-root-ca", help="Intel's SGX root CA certificate (PEM), pinned: TDX quotes chain to it")
    v.add_argument("--collateral-dir", help="Intel's collateral for the quote (fetch-collateral -o): TCB info, QE identity, CRLs")
    v.add_argument("--tcb-info", help="TDX TCB info (JSON), instead of the collateral directory's")
    v.add_argument("--qe-identity", help="TDX QE identity (JSON), instead of the collateral directory's")
    v.add_argument("--pck-crl", help="the PCK CA's CRL (PEM or DER), instead of the collateral directory's")
    v.add_argument("--tcb-signing-chain", help="the TCB signing certificate (PEM), instead of the collateral directory's")
    v.add_argument("--qe-identity-signing-chain",
                   help="QE identity's signing certificate (PEM), instead of the collateral directory's (default: TCB info's)")
    v.add_argument("--root-ca-crl", help="the Intel root CA's CRL (DER or PEM), instead of the collateral directory's")
    v.add_argument("--allow-tcb-status", action="append", default=[],
                   help="also accept this TCB status (e.g. SWHardeningNeeded); repeatable or comma-separated")
    v.add_argument("--allow-debug", action="store_true", help="accept a debug TD (its memory is open to the host)")
    v.add_argument("--allow-migratable", action="store_true", help="accept a migratable TD (TD_ATTRIBUTES.MIGRATABLE)")
    v.add_argument("--allow-stale-collateral", action="store_true", help="accept collateral and CRLs past their next update")
    v.add_argument("--insecure-skip-collateral", action="store_true",
                   help="INSECURE, for tests: check no collateral, so neither the QE's identity nor the TDX module's "
                        "signer, the CRLs or the TCB status (anyone with an SGX machine can then forge a quote)")
    v.add_argument("--mrtd", help="expected MRTD (hex): the TD's initial memory, its firmware")
    v.add_argument("--rtmr", action="append", default=[], help="N=HEX (N 0-2): expected RTMR value")
    v.add_argument("--cc-event-log", help="the host's CC event log (l4hctl attest tdx-event-log -o): must replay to RTMR 0-2")


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise Fail("%s: %s" % (path, e.strerror))


def tdx_policy(a):
    roots = load_certs(read(a.intel_root_ca), a.intel_root_ca) if a.intel_root_ca else []
    col = Collateral(a.collateral_dir, tcb_info=a.tcb_info, qe_identity=a.qe_identity, pck_crl=a.pck_crl,
                     tcb_signing_chain=a.tcb_signing_chain, root_ca_crl=a.root_ca_crl,
                     qe_identity_signing_chain=a.qe_identity_signing_chain)
    allowed = set(DEFAULT_TCB_STATUS)
    for s in a.allow_tcb_status:
        allowed.update(x.strip() for x in s.split(",") if x.strip())
    rtmrs = {}
    for r in a.rtmr:
        i, _, val = r.partition("=")
        if i not in ("0", "1", "2"):
            raise Fail("--rtmr: RTMR 0, 1 or 2 (RTMR 3 is the host key's)")
        rtmrs[int(i)] = bytes.fromhex(val)
    return TdxPolicy(roots, col, allowed, a.allow_debug, a.allow_stale_collateral,
                     bytes.fromhex(a.mrtd) if a.mrtd else None, rtmrs,
                     read(a.cc_event_log) if a.cc_event_log else None, allow_migratable=a.allow_migratable,
                     require_collateral=not a.insecure_skip_collateral, allow_efi_drivers=a.allow_efi_drivers)


TDX_OPTIONS = ("intel_root_ca", "collateral_dir", "tcb_info", "qe_identity", "pck_crl", "tcb_signing_chain",
               "qe_identity_signing_chain", "root_ca_crl", "allow_tcb_status", "allow_debug", "allow_migratable",
               "allow_stale_collateral", "insecure_skip_collateral", "mrtd", "rtmr", "cc_event_log")


def tdx_options_given(a):
    """Whether any TDX option was given: without TDX evidence they would be
    checked against nothing."""
    return any(getattr(a, o) for o in TDX_OPTIONS)


def efi_driver_warning(n, where):
    print("l4h-attest: WARNING: --allow-efi-drivers: the event log shows %d UEFI driver(s) or application(s) from "
          "outside the firmware (option ROMs; %s), whose code ran before l4h: only a pinned %s says which"
          % (n, where, where),
          file=sys.stderr)


def tdx_warnings(info, policy):
    if info.get("tcb_status") is None:
        print("l4h-attest: WARNING: INSECURE: --insecure-skip-collateral: the QE's identity (MRSIGNER, product, "
              "SVN, debug), the TDX module's signer (MRSIGNERSEAM), the CRLs and the TCB status were NOT checked: "
              "anyone with an SGX machine could have forged this TDX quote", file=sys.stderr)
    if not info.get("measurements_pinned", False):
        print("l4h-attest: WARNING: INSECURE: --insecure-unpinned-measurements: MRTD, RTMR 1 and RTMR 2 were NOT all "
              "pinned (--mrtd --rtmr 1=... --rtmr 2=...)", file=sys.stderr)
    if 0 not in policy.rtmrs and policy.cc_event_log is None:
        print("l4h-attest: WARNING: RTMR 0 was neither pinned (--rtmr 0=...) nor replayed (--cc-event-log): the TD "
              "firmware's configuration (TDHOB, CFV), its ACPI tables and the UEFI drivers it loaded before l4h were "
              "NOT checked", file=sys.stderr)
    if info.get("cc_event_log_efi_drivers"):
        efi_driver_warning(info["cc_event_log_efi_drivers"], "RTMR 0")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("measure")
    m.add_argument("kernel")
    m.add_argument("--initrd")
    m.add_argument("--cmdline", default="")
    m.add_argument("--initrd-gpa", type=lambda x: int(x, 0),
                   help="where dom0 loaded the initrd (default: 1 MiB past the kernel's end, as vmmgr does)")
    m.add_argument("--hvm", metavar="ARCH", help="an HVM guest of this architecture (x86_64 or aarch64)")
    m.add_argument("--kernel-gpa", type=lambda x: int(x, 0), help="--hvm: where dom0 loaded the kernel image")
    mh = sub.add_parser("measure-host")
    mh.add_argument("--efi", help="UEFI application (PE/COFF): also compute Authenticode SHA-256 and SHA-384 digests")
    mh.add_argument("--config", help="l4h.conf file (absent if omitted)")
    mh.add_argument("--initrd", help="dom0 initrd file (absent if omitted)")
    v = sub.add_parser("verify")
    v.add_argument("report")
    v.add_argument("evidence", nargs="?", help="TPM, TDX or combined evidence (with --tpm-evidence or --tdx-evidence: optional)")
    v.add_argument("--tpm-evidence", help="the host's TPM evidence (l4hctl attest evidence -o), checked with the TDX evidence")
    v.add_argument("--tdx-evidence", help="the host's TDX evidence (l4hctl attest tdx-evidence -o), checked with the TPM evidence")
    v.add_argument("--ignore-tpm", action="store_true",
                   help="with TDX evidence, ignore the TPM part of combined (v=3) evidence and verify TDX alone")
    v.add_argument("--data", help="expected report data (hex)")
    v.add_argument("--launch", help="expected launch digest (hex)")
    v.add_argument("--pcr", action="append", default=[], help="N=HEX: expected sha256 PCR value")
    v.add_argument("--ak-name", help="the enrolled attestation key's name (hex): required with TPM evidence")
    v.add_argument("--insecure-unpinned-ak", action="store_true",
                   help="accept TPM evidence without --ak-name (its AK is then not known to be a TPM's: to read the "
                        "AK's name before enrolling it, or for tests)")
    v.add_argument("--insecure-unpinned-measurements", action="store_true",
                   help="INSECURE: accept evidence without pinning platform measurements (--mrtd/--rtmr 1,2 for TDX; "
                        "--pcr 2,4,9 for TPM)")
    v.add_argument("--deny-taint", default="console-in", help="deny host names, bit numbers or ranges (default: console-in; '' disables)")
    v.add_argument("--require-seal", default="console-in",
                   help="require sealed host names, bit numbers or ranges (default: console-in; '' disables)")
    v.add_argument("--ek-ca", help="CA certificates (PEM, one or more) one of which issued the EK certificate")
    v.add_argument("--event-log", help="the host's UEFI TPM event log (l4hctl attest event-log -o): must replay to PCRs 0-14")
    v.add_argument("--allow-efi-drivers", action="store_true",
                   help="accept an event log (--event-log, --cc-event-log) in which the firmware loaded UEFI drivers or "
                        "applications from outside itself (option ROMs; PCR 2, RTMR 0)")
    add_tdx_options(v)
    tq = sub.add_parser("verify-tdx-quote")
    tq.add_argument("answer", help="l4hctl attest tdx-quote -o: the host key, a fresh TDX quote and the report it is over")
    tq.add_argument("--tdx-evidence", help="the host's TDX evidence: the answer's key must be its key")
    tq.add_argument("--data", help="expected report data (hex)")
    tq.add_argument("--launch", help="expected launch digest (hex)")
    tq.add_argument("--insecure-unpinned-measurements", action="store_true",
                    help="INSECURE: accept a TDX quote without pinning --mrtd, --rtmr 1=... and --rtmr 2=...")
    tq.add_argument("--allow-efi-drivers", action="store_true",
                    help="accept a CC event log (--cc-event-log) in which the TD firmware loaded UEFI drivers or "
                         "applications from outside itself (RTMR 0)")
    tq.add_argument("--deny-taint", default="console-in", help="as verify")
    tq.add_argument("--require-seal", default="console-in", help="as verify")
    add_tdx_options(tq)
    e = sub.add_parser("event-log")
    e.add_argument("log")
    e.add_argument("--cc", action="store_true", help="a CC event log (SHA-384, RTMRs): the default when it has no SHA-256 digests")
    fc = sub.add_parser("fetch-collateral")
    fc.add_argument("evidence", help="TDX or combined evidence, a tdx-quote answer, or a raw quote")
    fc.add_argument("-o", required=True, help="directory to save the collateral in")
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
            kernel = open(a.kernel, "rb").read()
            if a.hvm:
                print(hvm_launch_digest(a.hvm, kernel, initrd, a.cmdline, a.kernel_gpa, a.initrd_gpa).hex())
            elif a.kernel_gpa is not None:
                raise Fail("--kernel-gpa is an HVM guest's (--hvm)")
            else:
                print(launch_digest(kernel, initrd, a.cmdline, a.initrd_gpa).hex())
        elif a.cmd == "measure-host":
            efi = read(a.efi) if a.efi else None
            config = read(a.config) if a.config else None
            initrd = read(a.initrd) if a.initrd else None
            print(json.dumps(measure_host(efi=efi, config=config, initrd=initrd), indent=2))
        elif a.cmd == "verify":
            pins = {}
            for p in a.pcr:
                i, _, val = p.partition("=")
                pins[int(i)] = bytes.fromhex(val)
            tpm_ev, tdx_ev = split_evidence(cbor_decode(read(a.evidence))) if a.evidence else (None, None)
            if a.tpm_evidence:
                if tpm_ev is not None:
                    raise Fail("two TPM evidences: the positional one and --tpm-evidence")
                tpm_ev = cbor_decode(read(a.tpm_evidence))
            if a.tdx_evidence:
                if tdx_ev is not None:
                    raise Fail("two TDX evidences: the positional one and --tdx-evidence")
                tdx_ev = cbor_decode(read(a.tdx_evidence))
            if a.ignore_tpm:
                if tdx_ev is None:
                    raise Fail("--ignore-tpm requires TDX evidence")
                if a.tpm_evidence:
                    raise Fail("--ignore-tpm cannot be used with --tpm-evidence")
                tpm_ev = None
            if tpm_ev is None and tdx_ev is None:
                raise Fail("no evidence")
            if a.allow_efi_drivers and not (a.event_log or a.cc_event_log):
                raise Fail("--allow-efi-drivers without --event-log or --cc-event-log: no event log to check")
            out, key, partition = {}, None, None
            ak_name = bytes.fromhex(a.ak_name) if a.ak_name else None
            if tpm_ev is not None:
                # An AK not pinned is any key's: whoever made the evidence
                # signed its quote.  Only an enrolled AK (make-credential,
                # activate) is known to be in a TPM.
                if ak_name is None and not a.insecure_unpinned_ak:
                    raise Fail("the attestation key is not pinned: enroll it (make-credential, l4hctl attest activate) "
                               "and give its name with --ak-name, or --insecure-unpinned-ak to accept any key")
                if any(i not in pins for i in TPM_REQUIRED_PCRS) and not a.insecure_unpinned_measurements:
                    raise Fail("TPM platform measurements are not pinned: pass --pcr 2=..., --pcr 4=... and --pcr 9=..., "
                               "or --insecure-unpinned-measurements")
                key, partition, host = check_evidence(tpm_ev, pins, ak_name, a.ek_ca)
                if a.event_log:
                    host["event_log_events"], host["event_log_efi_drivers"] = check_event_log(
                        read(a.event_log), tpm_ev["pcrs"], a.allow_efi_drivers)
                out["host"] = host
            elif a.event_log or pins or a.ak_name or a.ek_ca or a.insecure_unpinned_ak:
                raise Fail("TPM options without TPM evidence")
            if tdx_ev is not None:
                policy = tdx_policy(a)
                if (policy.mrtd is None or 1 not in policy.rtmrs or 2 not in policy.rtmrs) and not a.insecure_unpinned_measurements:
                    raise Fail("TDX platform measurements are not pinned: pass --mrtd, --rtmr 1=... and --rtmr 2=..., "
                               "or --insecure-unpinned-measurements")
                tdx_key, info = check_tdx_evidence(tdx_ev, policy)
                # Both roots of trust must speak of the same key, and of the
                # one machine trustd runs alone on.
                if key is not None and point(key) != point(tdx_key):
                    raise Fail("the TPM and TDX evidence are for different host keys")
                if partition is not None:
                    raise Fail("TDX evidence is a single kernel's, the TPM evidence partition %d's" % partition)
                key = tdx_key
                out["tdx"] = info
            elif tdx_options_given(a):
                # Evidence without the TDX quote the options ask about: a
                # host that swapped TDX evidence for TPM evidence alone
                # must not pass a TDX policy unchecked.
                raise Fail("TDX options without TDX evidence")
            data = bytes.fromhex(a.data) if a.data is not None else None
            launch = bytes.fromhex(a.launch) if a.launch else None
            out["guest"] = check_report(cbor_decode(read(a.report)), key, data, launch, a.deny_taint, a.require_seal, partition)
            print(json.dumps(out, indent=2))
            if tpm_ev is not None and ak_name is None:
                print("l4h-attest: WARNING: INSECURE: --insecure-unpinned-ak: the attestation key is not pinned "
                      "(--ak-name), so not known to be a TPM's", file=sys.stderr)
            if tpm_ev is not None and not out["host"]["measurements_pinned"]:
                print("l4h-attest: WARNING: INSECURE: --insecure-unpinned-measurements: PCR 2, PCR 4 and PCR 9 were NOT "
                      "all pinned (--pcr 2=... --pcr 4=... --pcr 9=...)", file=sys.stderr)
            if tpm_ev is not None and 0 not in pins:
                print("l4h-attest: WARNING: PCR 0 (the platform firmware) was NOT pinned (--pcr 0=...): on bare metal, "
                      "pin it with the AK (--ak-name) from a known-good boot; on a cloud vTPM whose firmware the cloud "
                      "vouches for (GCE), this may be accepted", file=sys.stderr)
            if out.get("host", {}).get("event_log_efi_drivers"):
                efi_driver_warning(out["host"]["event_log_efi_drivers"], "PCR %d" % EFI_DRIVER_PCR)
            if tdx_ev is not None:
                tdx_warnings(out["tdx"], policy)
        elif a.cmd == "verify-tdx-quote":
            policy = tdx_policy(a)
            if (policy.mrtd is None or 1 not in policy.rtmrs or 2 not in policy.rtmrs) and not a.insecure_unpinned_measurements:
                raise Fail("TDX platform measurements are not pinned: pass --mrtd, --rtmr 1=... and --rtmr 2=..., "
                           "or --insecure-unpinned-measurements")
            if a.allow_efi_drivers and not a.cc_event_log:
                raise Fail("--allow-efi-drivers without --cc-event-log: no event log to check")
            ans = cbor_decode(read(a.answer))
            key, info = check_tdx_quote_answer(ans, policy)
            if a.tdx_evidence:
                ev_key, _ = check_tdx_evidence(cbor_decode(read(a.tdx_evidence)), policy)
                if point(ev_key) != point(key):
                    raise Fail("the quote answer's key is not the TDX evidence's")
            data = bytes.fromhex(a.data) if a.data is not None else None
            launch = bytes.fromhex(a.launch) if a.launch else None
            guest = check_report(cbor_decode(ans["report"]), key, data, launch, a.deny_taint, a.require_seal)
            print(json.dumps({"tdx": info, "guest": guest}, indent=2))
            tdx_warnings(info, policy)
        elif a.cmd == "event-log":
            log = read(a.log)
            if a.cc or is_cc_event_log(log):
                print(json.dumps(cc_event_log_summary(log), indent=2))
            else:
                print(json.dumps(event_log_summary(log), indent=2))
        elif a.cmd == "fetch-collateral":
            raw = read(a.evidence)
            try:
                q = quote_of(cbor_decode(raw))
            except Fail:
                q = raw
            fetch_collateral(q, a.o)
        else:
            # TPM evidence, or the guest driver's combined evidence (v 3).
            ev, _ = split_evidence(cbor_decode(read(a.evidence)))
            if ev is None:
                raise Fail("no TPM evidence in this file")
            ek = evidence_ek(ev, read(a.ek) if a.ek else None, a.ek_ca)
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
    except ValueError as e:
        print("l4h-attest: %s" % e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
