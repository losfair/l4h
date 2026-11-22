//! Intel TDX attestation, the parts free of seL4 (tests/trustd-tdx
//! compiles this file unchanged): the TDREPORT_STRUCT the TDX module
//! writes, the GHCI GetQuote buffer, the check of the DCAP quote the VMM
//! answers against the TDREPORT trustd sent, and the CBOR trustd gives
//! guests (tdxrt.rs does the calls).
//!
//! trustd binds its signing key K to the TD as it binds it to a TPM
//! (main.rs): the quote of a TDREPORT whose REPORTDATA is
//! SHA-384("l4h-trustd-key-tdx-v1" || K) || 0^16, taken while RTMR 3 was
//! zero, after which trustd extends RTMR 3 with the same hash.  RTMR 3 then
//! shows, in every later quote, that K was the first key of this boot;
//! only trustd holds the TdxControl capability, and never extends it again.

use sha2::{Digest, Sha256, Sha384};

use crate::cbor::{Enc, Overflow};

/// TDREPORT_STRUCT (Intel TDX Module ABI): REPORTMACSTRUCT (256 bytes),
/// TEE_TCB_INFO (239) and 17 reserved, then TDINFO_STRUCT (512).
pub const REPORT_SIZE: usize = 1024;
/// REPORTMACSTRUCT.REPORTTYPE.TYPE: TDX.
pub const REPORT_TYPE_TDX: u8 = 0x81;
pub const REPORTDATA: usize = 128;
// TEE_TCB_INFO, at 256: VALID (8), then these.
pub const TEE_TCB_SVN: usize = 264;
pub const MRSEAM: usize = 280;
pub const MRSIGNERSEAM: usize = 328;
pub const SEAM_ATTRIBUTES: usize = 376;
pub const TEE_TCB_SVN2: usize = 384;
// TDINFO_STRUCT, at 512.
pub const TDINFO: usize = 512;
pub const TD_ATTRIBUTES: usize = TDINFO;
pub const XFAM: usize = TDINFO + 8;
pub const MRTD: usize = TDINFO + 16;
pub const MRCONFIGID: usize = MRTD + 48;
pub const MROWNER: usize = MRCONFIGID + 48;
pub const MROWNERCONFIG: usize = MROWNER + 48;
pub const RTMR0: usize = MROWNERCONFIG + 48;
pub const SERVTD_HASH: usize = RTMR0 + 4 * 48;
const _: () = assert!(RTMR0 == 720 && SERVTD_HASH == 912 && SERVTD_HASH + 48 + 64 == REPORT_SIZE);

/// The RTMR trustd extends with its key's binding.
pub const KEY_RTMR: usize = 3;

/// RTMR `i` (0-3) of a TDREPORT.
pub fn rtmr(report: &[u8; REPORT_SIZE], i: usize) -> &[u8; 48] {
    report[RTMR0 + 48 * i..RTMR0 + 48 * (i + 1)].try_into().unwrap()
}

pub const KEY_DOMAIN: &[u8] = b"l4h-trustd-key-tdx-v1";
/// A guest's fresh quote (abi::ATTEST_TDX_QUOTE) over its report.
pub const REPORT_DOMAIN: &[u8] = b"l4h-tdx-report-v1";

/// What trustd binds to the TD for key `point` (its SEC1 point): in the
/// quote's REPORTDATA, and in RTMR 3.
pub fn key_binding(point: &[u8; 65]) -> [u8; 48] {
    Sha384::new().chain_update(KEY_DOMAIN).chain_update(point).finalize().into()
}

/// REPORTDATA for a 48-byte hash: the hash, then 16 zero bytes.
pub fn report_data(hash: &[u8; 48]) -> [u8; 64] {
    let mut d = [0u8; 64];
    d[..48].copy_from_slice(hash);
    d
}

/// REPORTDATA of a guest's fresh quote over its report (the COSE_Sign1's
/// bytes).
pub fn guest_report_data(report: &[u8]) -> [u8; 64] {
    let inner: [u8; 32] = Sha256::digest(report).into();
    report_data(&Sha384::new().chain_update(REPORT_DOMAIN).chain_update(inner).finalize().into())
}

/// RTMR 3 once trustd extended it from zero with `binding`
/// (TDG.MR.RTMR.EXTEND: SHA-384 of the old value and the extension).
pub fn rtmr_extended(binding: &[u8; 48]) -> [u8; 48] {
    Sha384::new().chain_update([0u8; 48]).chain_update(binding).finalize().into()
}

/// Why a TDREPORT cannot start the key's binding, if it cannot: not a
/// TDX report, another REPORTDATA than trustd asked for, or RTMR 3 not
/// zero (something extended it before trustd: not the first key).
pub fn check_first_report(report: &[u8; REPORT_SIZE], data: &[u8; 64]) -> Result<(), &'static str> {
    if report[0] != REPORT_TYPE_TDX {
        return Err("not a TDX TDREPORT");
    }
    if report[REPORTDATA..REPORTDATA + 64] != data[..] {
        return Err("TDREPORT with another REPORTDATA");
    }
    if rtmr(report, KEY_RTMR) != &[0u8; 48] {
        return Err("RTMR 3 is not zero: another key was bound to this TD before");
    }
    Ok(())
}

// ---- The GHCI GetQuote buffer (TDG.VP.VMCALL<GetQuote>): u64 version,
// u64 status, u32 in_len, u32 out_len, then the TDREPORT on input, the
// quote on output; little-endian.

pub const GHCI_HEADER: usize = 24;
pub const GHCI_VERSION: u64 = 1;
/// The VMM is making the quote: the buffer is its own.
pub const GET_QUOTE_IN_FLIGHT: u64 = u64::MAX;
/// The VMM's quoting service is not available just now.
pub const GET_QUOTE_SERVICE_UNAVAILABLE: u64 = 0x8000_0000_0000_0002;

/// The request for a quote of `report`: the header and the TDREPORT, the
/// first GHCI_HEADER + REPORT_SIZE bytes of the buffer (the rest zero).
pub fn ghci_request(report: &[u8; REPORT_SIZE]) -> [u8; GHCI_HEADER + REPORT_SIZE] {
    let mut b = [0u8; GHCI_HEADER + REPORT_SIZE];
    b[..8].copy_from_slice(&GHCI_VERSION.to_le_bytes());
    b[16..20].copy_from_slice(&(REPORT_SIZE as u32).to_le_bytes());
    b[GHCI_HEADER..].copy_from_slice(report);
    b
}

/// The status word of the buffer, which the VMM changes from
/// GET_QUOTE_IN_FLIGHT when it is done.
pub const GHCI_STATUS: usize = 8;

/// What the VMM answered, from trustd's own copy of the buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer<'a> {
    /// Not yet: the status is IN_FLIGHT, or still the 0 trustd wrote with
    /// no quote (a VMM that has not marked it in flight yet).
    Pending,
    /// The VMM's error status.
    Failed(u64),
    /// The quote, as long as out_len says.
    Quote(&'a [u8]),
}

pub fn ghci_answer(copy: &[u8]) -> Result<Answer<'_>, &'static str> {
    if copy.len() < GHCI_HEADER {
        return Err("GetQuote buffer too short");
    }
    let status = u64::from_le_bytes(copy[8..16].try_into().unwrap());
    let out_len = u32::from_le_bytes(copy[20..24].try_into().unwrap()) as usize;
    match status {
        GET_QUOTE_IN_FLIGHT => Ok(Answer::Pending),
        0 if out_len == 0 => Ok(Answer::Pending),
        0 => copy.get(GHCI_HEADER..GHCI_HEADER + out_len).map(Answer::Quote).ok_or("quote longer than the GetQuote buffer"),
        s => Ok(Answer::Failed(s)),
    }
}

// ---- DCAP quotes (Intel TDX DCAP Quote Generation Library): a 48-byte
// header, the TD quote body (v4: TD 1.0's, 584 bytes; v5: a u16 type and
// u32 size first, TD 1.0's or TD 1.5's, 648), then a u32 length and the
// signature data.

pub const QUOTE_HEADER: usize = 48;
pub const TD10_BODY: usize = 584;
pub const TD15_BODY: usize = 648;
/// The header's attestation key type: ECDSA-256 with P-256.
pub const ATT_KEY_ECDSA_P256: u16 = 2;
pub const TEE_TYPE_TDX: u32 = 0x81;
/// v5 body types.
pub const BODY_TD10: u16 = 2;
pub const BODY_TD15: u16 = 3;

/// Each field of a TD quote body that the QE copies from the TDREPORT:
/// (offset in the body, offset in the TDREPORT, length).  TD 1.0's body
/// first; TD 1.5's adds the last two.
pub const BODY_FIELDS: [(usize, usize, usize); 14] = [
    (0, TEE_TCB_SVN, 16),
    (16, MRSEAM, 48),
    (64, MRSIGNERSEAM, 48),
    (112, SEAM_ATTRIBUTES, 8),
    (120, TD_ATTRIBUTES, 8),
    (128, XFAM, 8),
    (136, MRTD, 48),
    (184, MRCONFIGID, 48),
    (232, MROWNER, 48),
    (280, MROWNERCONFIG, 48),
    (328, RTMR0, 4 * 48),
    (520, REPORTDATA, 64),
    (584, TEE_TCB_SVN2, 16),
    (600, SERVTD_HASH, 48),
];
const _: () = assert!(520 + 64 == TD10_BODY && 600 + 48 == TD15_BODY);

/// The body of `quote` and the quote's length to the end of its signature
/// data, if its header is a TDX ECDSA-P256 quote of version 4 or 5.
pub fn quote_body(quote: &[u8]) -> Result<(&[u8], usize), &'static str> {
    let u16_at = |i: usize| quote.get(i..i + 2).map(|b| u16::from_le_bytes(b.try_into().unwrap())).ok_or("quote cut short");
    let u32_at = |i: usize| quote.get(i..i + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).ok_or("quote cut short");
    let version = u16_at(0)?;
    if u16_at(2)? != ATT_KEY_ECDSA_P256 {
        return Err("quote attestation key is not ECDSA P-256");
    }
    if u32_at(4)? != TEE_TYPE_TDX {
        return Err("not a TDX quote");
    }
    let (at, size) = match version {
        4 => (QUOTE_HEADER, TD10_BODY),
        5 => {
            let size = match (u16_at(QUOTE_HEADER)?, u32_at(QUOTE_HEADER + 2)? as usize) {
                (BODY_TD10, TD10_BODY) => TD10_BODY,
                (BODY_TD15, TD15_BODY) => TD15_BODY,
                _ => return Err("v5 quote body is neither TD 1.0's nor TD 1.5's"),
            };
            (QUOTE_HEADER + 6, size)
        }
        _ => return Err("quote version is neither 4 nor 5"),
    };
    let body = quote.get(at..at + size).ok_or("quote cut short")?;
    let sig_len = u32_at(at + size)? as usize;
    let end = (at + size + 4).checked_add(sig_len).filter(|&e| e <= quote.len()).ok_or("quote signature data cut short")?;
    Ok((body, end))
}

/// Check the quote the VMM answered for `report`: a TDX ECDSA-P256 quote
/// whose body is, field by field, the TDREPORT trustd sent.  Its length
/// to the end of its signature data (anything after is not the quote's).
/// The signatures are the verifier's to check: the VMM could make up any
/// quote, but not one a verifier accepts for another report.
pub fn check_quote(quote: &[u8], report: &[u8; REPORT_SIZE]) -> Result<usize, &'static str> {
    let (body, end) = quote_body(quote)?;
    let fields = if body.len() == TD15_BODY { &BODY_FIELDS[..] } else { &BODY_FIELDS[..12] };
    for &(b, r, n) in fields {
        if body[b..b + n] != report[r..r + n] {
            return Err("quote body differs from the TDREPORT sent");
        }
    }
    Ok(end)
}

// ---- What guests get.

/// The key's COSE_Key (EC2, P-256) as main.rs writes it.
pub fn cose_key(e: &mut Enc, point: &[u8; 65]) {
    e.map(4).uint(1).uint(2).nint(0).uint(1).nint(1).bytes(&point[1..33]).nint(2).bytes(&point[33..]);
}

/// The TDX evidence (abi::ATTEST_TDX_EVIDENCE) into `out`, keys in the
/// order of their encodings (RFC 8949 §4.2.1): its length.
pub fn encode_evidence(out: &mut [u8], point: &[u8; 65], quote: &[u8]) -> Result<usize, Overflow> {
    let mut e = Enc::new(out);
    e.map(4);
    e.text("v").uint(1);
    e.text("key");
    cose_key(&mut e, point);
    e.text("type").text("tdx");
    e.text("quote").bytes(quote);
    Ok(e.done()?.len())
}

/// A guest's fresh quote (abi::ATTEST_TDX_QUOTE) into `out`: the key that
/// signed `report`, the quote over it, and the report.
pub fn encode_quote_answer(out: &mut [u8], point: &[u8; 65], quote: &[u8], report: &[u8]) -> Result<usize, Overflow> {
    let mut e = Enc::new(out);
    e.map(3);
    e.text("key");
    cose_key(&mut e, point);
    e.text("quote").bytes(quote);
    e.text("report").bytes(report);
    Ok(e.done()?.len())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A TDREPORT with every byte its offset's low byte (distinct fields),
    /// TDX's type and the given REPORTDATA and RTMR 3.
    fn report(data: &[u8; 64], rtmr3: &[u8; 48]) -> [u8; REPORT_SIZE] {
        let mut r = [0u8; REPORT_SIZE];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        r[0] = REPORT_TYPE_TDX;
        r[REPORTDATA..REPORTDATA + 64].copy_from_slice(data);
        r[RTMR0 + 3 * 48..RTMR0 + 4 * 48].copy_from_slice(rtmr3);
        r
    }

    /// A quote of `version` (5: with `body_type`) whose body the QE made
    /// from `r`, with `sig` bytes of signature data.
    fn quote(version: u16, body_type: u16, r: &[u8; REPORT_SIZE], sig: usize) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&version.to_le_bytes());
        q.extend_from_slice(&ATT_KEY_ECDSA_P256.to_le_bytes());
        q.extend_from_slice(&TEE_TYPE_TDX.to_le_bytes());
        q.resize(QUOTE_HEADER, 0xaa);
        let size = if body_type == BODY_TD15 { TD15_BODY } else { TD10_BODY };
        if version == 5 {
            q.extend_from_slice(&body_type.to_le_bytes());
            q.extend_from_slice(&(size as u32).to_le_bytes());
        }
        let mut body = std::vec![0u8; size];
        let n = if size == TD15_BODY { 14 } else { 12 };
        for &(b, o, len) in &BODY_FIELDS[..n] {
            body[b..b + len].copy_from_slice(&r[o..o + len]);
        }
        q.extend_from_slice(&body);
        q.extend_from_slice(&(sig as u32).to_le_bytes());
        q.extend(std::iter::repeat_n(0x5a, sig));
        q
    }

    fn point() -> [u8; 65] {
        let mut p = [0u8; 65];
        p[0] = 4;
        for (i, b) in p[1..].iter_mut().enumerate() {
            *b = i as u8;
        }
        p
    }

    #[test]
    fn tdreport_offsets_are_the_tdx_module_abis() {
        // Linux's tdx-guest.c: REPORTDATA at 128, TEE_TCB_INFO at 256,
        // TDINFO 256 bytes later; MRTD after ATTRIBUTES and XFAM; RTMR 3
        // after MRCONFIGID, MROWNER, MROWNERCONFIG and RTMR 0-2.
        assert_eq!((REPORTDATA, TDINFO, MRTD), (128, 512, 528));
        assert_eq!(RTMR0 + 3 * 48, 864);
        let r = report(&[1; 64], &[9; 48]);
        assert_eq!(rtmr(&r, 3), &[9u8; 48]);
        assert_eq!(&r[864..912], &[9u8; 48]);
        assert_eq!(rtmr(&r, 0)[0], r[720]);
    }

    #[test]
    fn key_binding_is_the_domain_and_the_point() {
        let p = point();
        let want: [u8; 48] = Sha384::digest([b"l4h-trustd-key-tdx-v1".as_slice(), &p].concat()).into();
        assert_eq!(key_binding(&p), want);
        let d = report_data(&want);
        assert_eq!(&d[..48], &want);
        assert_eq!(&d[48..], &[0u8; 16]);
        let extended: [u8; 48] = Sha384::digest([[0u8; 48].as_slice(), &want].concat()).into();
        assert_eq!(rtmr_extended(&want), extended);
        // Another point, another binding.
        let mut q = p;
        q[64] ^= 1;
        assert_ne!(key_binding(&q), want);
    }

    #[test]
    fn guest_report_data_hashes_the_report() {
        let rep = b"a COSE_Sign1";
        let inner: [u8; 32] = Sha256::digest(rep).into();
        let outer: [u8; 48] = Sha384::digest([b"l4h-tdx-report-v1".as_slice(), &inner].concat()).into();
        let d = guest_report_data(rep);
        assert_eq!(&d[..48], &outer);
        assert_eq!(&d[48..], &[0u8; 16]);
    }

    #[test]
    fn the_first_report_needs_rtmr3_zero() {
        let data = report_data(&key_binding(&point()));
        assert_eq!(check_first_report(&report(&data, &[0; 48]), &data), Ok(()));
        // Something extended RTMR 3 before: never a second key.
        let mut once = [0u8; 48];
        once[47] = 1;
        assert!(check_first_report(&report(&data, &once), &data).is_err());
        assert!(check_first_report(&report(&data, &rtmr_extended(&key_binding(&point()))), &data).is_err());
        // Another REPORTDATA, or not a TDX report.
        assert!(check_first_report(&report(&[0; 64], &[0; 48]), &data).is_err());
        let mut sgx = report(&data, &[0; 48]);
        sgx[0] = 0;
        assert!(check_first_report(&sgx, &data).is_err());
    }

    #[test]
    fn ghci_request_and_answers() {
        let r = report(&[1; 64], &[0; 48]);
        let b = ghci_request(&r);
        assert_eq!(u64::from_le_bytes(b[..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(b[16..20].try_into().unwrap()), 1024);
        assert_eq!(u32::from_le_bytes(b[20..24].try_into().unwrap()), 0);
        assert_eq!(&b[24..], &r[..]);

        let mut buf = std::vec![0u8; 4096];
        buf[..b.len()].copy_from_slice(&b);
        // As written: no quote yet.
        assert_eq!(ghci_answer(&buf), Ok(Answer::Pending));
        buf[8..16].copy_from_slice(&GET_QUOTE_IN_FLIGHT.to_le_bytes());
        assert_eq!(ghci_answer(&buf), Ok(Answer::Pending));
        buf[8..16].copy_from_slice(&GET_QUOTE_SERVICE_UNAVAILABLE.to_le_bytes());
        assert_eq!(ghci_answer(&buf), Ok(Answer::Failed(GET_QUOTE_SERVICE_UNAVAILABLE)));
        buf[8..16].copy_from_slice(&0u64.to_le_bytes());
        buf[20..24].copy_from_slice(&100u32.to_le_bytes());
        assert_eq!(ghci_answer(&buf), Ok(Answer::Quote(&buf[24..124])));
        // out_len past the buffer.
        buf[20..24].copy_from_slice(&(4096u32 - 23).to_le_bytes());
        assert!(ghci_answer(&buf).is_err());
        assert!(ghci_answer(&buf[..10]).is_err());
    }

    #[test]
    fn a_quote_of_the_report_sent_passes() {
        let r = report(&report_data(&key_binding(&point())), &[0; 48]);
        for (v, t) in [(4, 0), (5, BODY_TD10), (5, BODY_TD15)] {
            let q = quote(v, t, &r, 100);
            assert_eq!(check_quote(&q, &r), Ok(q.len()), "v{v} type {t}");
            // What follows the signature data is not the quote's.
            let mut longer = q.clone();
            longer.extend_from_slice(&[0; 32]);
            assert_eq!(check_quote(&longer, &r), Ok(q.len()), "v{v} type {t}");
        }
    }

    #[test]
    fn every_body_field_is_checked() {
        let r = report(&report_data(&key_binding(&point())), &[0; 48]);
        for (v, t, n) in [(4u16, 0u16, 12usize), (5, BODY_TD10, 12), (5, BODY_TD15, 14)] {
            let q = quote(v, t, &r, 64);
            let at = if v == 5 { QUOTE_HEADER + 6 } else { QUOTE_HEADER };
            for &(b, _, len) in &BODY_FIELDS[..n] {
                for i in [0, len - 1] {
                    let mut bad = q.clone();
                    bad[at + b + i] ^= 0x80;
                    assert!(check_quote(&bad, &r).is_err(), "v{v} type {t}: body byte {}", b + i);
                }
            }
            // A different TDREPORT: its REPORTDATA, or its RTMR 3.
            let mut other = r;
            other[REPORTDATA] ^= 1;
            assert!(check_quote(&q, &other).is_err());
            let mut other = r;
            other[RTMR0 + 3 * 48] ^= 1;
            assert!(check_quote(&q, &other).is_err());
        }
    }

    #[test]
    fn malformed_quotes_are_refused() {
        let r = report(&[3; 64], &[0; 48]);
        let q = quote(4, 0, &r, 64);
        let mut bad = q.clone();
        bad[0] = 3;
        assert!(check_quote(&bad, &r).is_err(), "version 3");
        let mut bad = q.clone();
        bad[2] = 3;
        assert!(check_quote(&bad, &r).is_err(), "ECDSA P-384 key");
        let mut bad = q.clone();
        bad[4] = 0;
        assert!(check_quote(&bad, &r).is_err(), "SGX");
        assert!(check_quote(&q[..q.len() - 1], &r).is_err(), "signature cut short");
        assert!(check_quote(&q[..QUOTE_HEADER + 100], &r).is_err(), "body cut short");
        let mut huge = q.clone();
        let at = QUOTE_HEADER + TD10_BODY;
        huge[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(check_quote(&huge, &r).is_err(), "signature length past the end");
        // v5 with a body type and size that do not go together.
        let mut v5 = quote(5, BODY_TD15, &r, 64);
        v5[QUOTE_HEADER..QUOTE_HEADER + 2].copy_from_slice(&BODY_TD10.to_le_bytes());
        assert!(check_quote(&v5, &r).is_err());
        let mut v5 = quote(5, BODY_TD10, &r, 64);
        v5[QUOTE_HEADER..QUOTE_HEADER + 2].copy_from_slice(&1u16.to_le_bytes());
        assert!(check_quote(&v5, &r).is_err(), "an SGX body");
    }

    #[test]
    fn evidence_is_deterministic_cbor() {
        let p = point();
        let q = std::vec![0x11u8; 300];
        let mut out = [0u8; 1024];
        let n = encode_evidence(&mut out, &p, &q).unwrap();
        let mut want = std::vec![0xa4, 0x61, b'v', 0x01, 0x63, b'k', b'e', b'y', 0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 32];
        want.extend_from_slice(&p[1..33]);
        want.extend_from_slice(&[0x22, 0x58, 32]);
        want.extend_from_slice(&p[33..]);
        want.extend_from_slice(&[0x64, b't', b'y', b'p', b'e', 0x63, b't', b'd', b'x']);
        want.extend_from_slice(&[0x65, b'q', b'u', b'o', b't', b'e', 0x59, 0x01, 0x2c]);
        want.extend_from_slice(&q);
        assert_eq!(&out[..n], &want[..]);
        // Too small a buffer: nothing half written passes.
        assert!(encode_evidence(&mut out[..n - 1], &p, &q).is_err());
    }

    #[test]
    fn quote_answer_is_deterministic_cbor() {
        let p = point();
        let mut out = [0u8; 1024];
        let n = encode_quote_answer(&mut out, &p, &[1, 2, 3], &[9; 30]).unwrap();
        // "key" < "quote" < "report": shorter encodings first.
        assert_eq!(&out[..5], &[0xa3, 0x63, b'k', b'e', b'y']);
        let rest = &out[5 + 75..n];
        assert_eq!(&rest[..10], &[0x65, b'q', b'u', b'o', b't', b'e', 0x43, 1, 2, 3]);
        assert_eq!(&rest[10..19], &[0x66, b'r', b'e', b'p', b'o', b'r', b't', 0x58, 30]);
        assert_eq!(rest.len(), 19 + 30);
    }
}
