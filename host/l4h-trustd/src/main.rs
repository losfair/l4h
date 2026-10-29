//! l4h-trustd: attestation for guests (DESIGN.md §9.2).
//!
//! At start, trustd generates a P-256 signing key and has the TPM quote
//! the PCRs, which hold the measurements of what booted (the UEFI
//! application with seL4, root and every host component, then dom0's
//! files), with the hash of the key as the quote's qualifying data.  It
//! then extends PCR 15 with the same hash: the quote shows PCR 15 zero,
//! so it is the first and only key trustd issued in this boot.  The key
//! signs guests' reports; the quote, the attestation key and the EK
//! certificate make the host evidence.  The TPM is used at start, for
//! ActivateCredential, and for root-only kexec measurement.
//!
//! Guests ask through their attestation device (l4h_attest_page): a kick,
//! then the answer in the page and an event, so that a vCPU never waits
//! for us.  We answer one request at a time, and each guest's
//! ActivateCredential calls are rate limited, so that no guest keeps the
//! TPM busy for the others.
//!
//! Nothing here allocates (DESIGN.md §9): requests are copied, and answers
//! built, in fixed buffers, and the evidence is made once into one.  The
//! heap is the AML interpreter's (aml::HEAP).

#![no_std]
#![no_main]

// For the AML interpreter only (aml::HEAP).
extern crate alloc;

mod aml;
mod cbor;
mod flags;
mod time;
mod tpm;
mod tpm2;

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use l4h_abi as abi;
use l4h_rt::host::trust::{self, GuestRecord, TrustdConfig};
use l4h_rt::{Info, cap, host, info, sel4};
use sel4::cap_type;

use crate::cbor::{Enc, Overflow};
use crate::tpm::{Error, Tpm};
use crate::tpm2::Template;

const EAGAIN: i64 = 11;
const EINVAL: i64 = 22;
const EIO: i64 = 5;
const ENOSYS: i64 = 38;
const ENODEV: i64 = 19;

/// ActivateCredential per guest: up to ACTIVATE_BURST at once, then one
/// every ACTIVATE_INTERVAL_MS (about 80 ms of TPM time each, on a discrete
/// TPM).  Beyond that, -EAGAIN without using the TPM.
const ACTIVATE_BURST: u64 = 5;
const ACTIVATE_INTERVAL_MS: u64 = 1000;

/// PCRs in the quote: the static ones (SRTM), 0-15.
const QUOTE_PCRS: u32 = 0xffff;
/// Extended with the key's hash once it is quoted.
const KEY_PCR: u32 = 15;
/// Records each new image before a host kexec.
const KEXEC_PCR: u32 = 14;
const KEY_DOMAIN: &[u8] = b"l4h-trustd-key-v1";

/// The host evidence's room: the complete kexec log, the largest EK
/// certificate, and 2 KiB for keys, PCRs, quote and encoding overhead.
const EVIDENCE_MAX: usize = trust::KEXEC_LOG_MAX + EK_CERT_MAX + 2048;
/// The largest EK certificate we put in the evidence (a few hundred bytes
/// to 2 KiB in practice).  A larger one is left out: the evidence is
/// still usable, without the certificate a verifier can check the TPM by.
const EK_CERT_MAX: usize = 4096;

/// The largest report payload: each key, and the longest encoding of its
/// value.
const PAYLOAD_MAX: usize = 1
    + (2 + 9)
    + (4 + 9)
    + (5 + 2 + abi::ATTEST_DATA_SIZE)
    + (5 + 1)
    + (5 + 2 + 32)
    + (5 + 2 + 32)
    + (6 + 2 + 32)
    + (6 + 9)
    + (6 + 9)
    + (7 + 2 + 32)
    + (9 + 9);
/// The room for a report, and for each of its pieces: the COSE_Sign1 is
/// the payload with 76 bytes around it (the Sig_structure, 20).
const REPORT_MAX: usize = 512;
const _: () = assert!(PAYLOAD_MAX + 76 <= REPORT_MAX);
/// An answer we build: a report, or a credential (a TPM2B_DIGEST, at most
/// 64 bytes).
const ANSWER_MAX: usize = REPORT_MAX;

struct State {
    tpm: Tpm,
    key: SigningKey,
    /// SHA-256 of the key's SEC1 point.
    key_id: [u8; 32],
    /// The public value this host extends into PCR 15 after its quote.
    key_extension: [u8; 32],
    /// The attestation key's handle.
    ak: u32,
    /// The EK, created on first use (ActivateCredential), RSA unless the
    /// TPM has an ECC EK certificate.
    ek: Option<u32>,
    ek_ecc: bool,
    /// The host evidence: its first `evidence_len` bytes.
    evidence: [u8; EVIDENCE_MAX],
    evidence_len: usize,
}

/// The P-256 point of `key`, uncompressed (0x04, x, y).
fn point(key: &SigningKey) -> [u8; 65] {
    key.verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap()
}

/// `r`, with what failed.
fn step<T>(what: &'static str, r: Result<T, Error>) -> Result<T, (&'static str, Error)> {
    r.map_err(|e| (what, e))
}

fn kexec_log(cfg: &TrustdConfig) -> Result<Option<(&'static [u8], u64)>, (&'static str, Error)> {
    let invalid = || -> Result<Option<(&'static [u8], u64)>, (&'static str, Error)> {
        Ok(Some((&[], 1)))
    };
    if cfg.kexec_log_size == trust::KEXEC_LOG_INVALID {
        return invalid();
    }
    let size = match usize::try_from(cfg.kexec_log_size) {
        Ok(size) => size,
        Err(_) => return invalid(),
    };
    if size == 0 {
        return Ok(None);
    }
    if cfg.kexec_log_va == 0 || size < trust::KEXEC_LOG_HEADER {
        return invalid();
    }
    let bytes = unsafe { core::slice::from_raw_parts(cfg.kexec_log_va as *const u8, size) };
    match trust::kexec_log_count(bytes) {
        Ok(count) => Ok(Some((bytes, count as u64))),
        Err(_) => invalid(),
    }
}

fn init(cfg: &TrustdConfig, hz: u64) -> Result<State, (&'static str, Error)> {
    let klog = kexec_log(cfg)?;
    let t0 = host::ticks::now();
    let mut tpm = step("interface", Tpm::new(cfg, hz))?;
    step("Startup", tpm2::startup(&mut tpm))?;
    let key = loop {
        let mut seed = [0u8; 32];
        step("GetRandom", tpm2::get_random(&mut tpm, &mut seed))?;
        if let Ok(k) = SigningKey::from_bytes(&seed.into()) {
            break k;
        }
    };
    let p = point(&key);
    let key_id: [u8; 32] = Sha256::digest(p).into();
    let bound: [u8; 32] = Sha256::new().chain_update(KEY_DOMAIN).chain_update(p).finalize().into();

    // The EK certificate, if the manufacturer stored one.
    let mut cert = [0u8; EK_CERT_MAX];
    let read = |tpm: &mut Tpm, index, cert: &mut [u8]| step("NV_Read (EK certificate)", tpm2::nv_read(tpm, index, cert));
    let (ek_cert, ek_ecc) = match read(&mut tpm, tpm2::NV_EK_CERT_ECC, &mut cert)? {
        Some(n) => (Some(n), true),
        None => (read(&mut tpm, tpm2::NV_EK_CERT_RSA, &mut cert)?, false),
    };
    let ek_cert = match ek_cert {
        Some(n) if n > EK_CERT_MAX => {
            info!("l4h-trustd: the EK certificate ({} bytes) is larger than {}: left out of the evidence", n, EK_CERT_MAX);
            None
        }
        c => c.map(|n| &cert[..n]),
    };

    // The evidence, as the TPM answers: keys in the order of their
    // encodings (RFC 8949 §4.2.1).
    let mut evidence = [0u8; EVIDENCE_MAX];
    let mut e = Enc::new(&mut evidence);
    e.map(6 + ek_cert.is_some() as usize + 2 * klog.is_some() as usize);
    e.text("v").uint(1);
    let (ak, ak_public) = step("CreatePrimary (AK)", tpm2::create_primary(&mut tpm, tpm2::RH_ENDORSEMENT, Template::Ak))?;
    e.text("ak").bytes(ak_public);
    // A COSE_Key (EC2, P-256).
    e.text("key").map(4).uint(1).uint(2).nint(0).uint(1).nint(1).bytes(&p[1..33]).nint(2).bytes(&p[33..]);
    if let Some((log, _)) = klog {
        e.text("klog").bytes(log);
    }
    let pcrs = step("PCR_Read", tpm2::pcr_read(&mut tpm, QUOTE_PCRS))?;
    e.text("pcrs").map(pcrs.len());
    for (i, v) in &pcrs {
        e.uint(*i as u64).bytes(v);
    }
    if let Some((_, count)) = klog {
        e.text("kexec").uint(count);
    }
    let (quote, sig) = step("Quote", tpm2::quote(&mut tpm, ak, &bound, QUOTE_PCRS))?;
    e.text("quote").bytes(quote);
    if let Some(c) = ek_cert {
        e.text("ekcert").bytes(c);
    }
    e.text("quotesig").bytes(sig);
    let evidence_len = e.done().map_err(|Overflow| ("evidence", Error::Bad("larger than EVIDENCE_MAX")))?.len();
    step("PCR_Extend", tpm2::pcr_extend(&mut tpm, KEY_PCR, &bound))?;
    info!(
        "l4h-trustd: ready in {} ms: signing key {:02x}{:02x}{:02x}{:02x}..., {} EK certificate",
        (host::ticks::now() - t0) * 1000 / hz.max(1),
        key_id[0], key_id[1], key_id[2], key_id[3],
        match (&ek_cert, ek_ecc) {
            (None, _) => "no",
            (Some(_), true) => "an ECC",
            (Some(_), false) => "an RSA",
        }
    );
    Ok(State { tpm, key, key_id, key_extension: bound, ak, ek: None, ek_ecc, evidence, evidence_len })
}

/// Guest `id`'s record, if it runs.
fn record(id: usize) -> Option<GuestRecord> {
    if id >= trust::MAX_RECORDS {
        return None;
    }
    let p = (trust::REGISTRY_VA as *const GuestRecord).wrapping_add(id);
    loop {
        let r = unsafe { p.read_volatile() };
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let again = unsafe { core::ptr::addr_of!((*p).instance).read_volatile() };
        if again == r.instance {
            return (r.instance != 0).then_some(r);
        }
    }
}

impl State {
    /// The COSE_Sign1 report on guest `id`, whose record is `r`, with the
    /// guest's `data`, in `out`: its length.
    fn report(&self, id: usize, r: &GuestRecord, data: &[u8; abi::ATTEST_DATA_SIZE], out: &mut [u8]) -> Result<usize, Overflow> {
        let mut payload = [0u8; REPORT_MAX];
        let mut c = Enc::new(&mut payload);
        let flags = flags::read(id, r.instance).bytes();
        c.map(11);
        c.text("v").uint(1);
        c.text("ram").uint(r.ram);
        c.text("data").bytes(data);
        c.text("dom0").bool(r.flags & trust::RECORD_DOM0 != 0);
        c.text("host").bytes(&self.key_id);
        c.text("seal").bytes(&flags.seal);
        c.text("guest").uint(id as u64);
        c.text("taint").bytes(&flags.taint);
        c.text("vcpus").uint(r.vcpus as u64);
        c.text("launch").bytes(&r.launch);
        c.text("instance").uint(r.instance);
        let payload = c.done()?;
        // Protected header {1: -7}: alg ES256.
        let protected = [0xa1, 0x01, 0x26];
        let mut sig_structure = [0u8; REPORT_MAX];
        let mut s = Enc::new(&mut sig_structure);
        s.array(4).text("Signature1").bytes(&protected).bytes(&[]).bytes(payload);
        let sig: Signature = self.key.sign(s.done()?);
        let mut o = Enc::new(out);
        o.tag(18).array(4).bytes(&protected).map(0).bytes(payload).bytes(&sig.to_bytes());
        Ok(o.done()?.len())
    }

    /// The credential, in `out`: its length.
    fn activate(&mut self, blob: &[u8], secret: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let ek = match self.ek {
            Some(h) => h,
            None => {
                let (h, _) = tpm2::create_primary(&mut self.tpm, tpm2::RH_ENDORSEMENT, Template::Ek { ecc: self.ek_ecc })?;
                self.ek = Some(h);
                h
            }
        };
        tpm2::activate_credential(&mut self.tpm, self.ak, ek, blob, secret, out)
    }
}

/// Per guest id: the request last answered, and for which guest instance
/// (a new guest with the same id starts again from seq 1, with a full
/// ActivateCredential allowance).
#[derive(Clone, Copy, Default)]
struct Answered {
    instance: u64,
    seq: u32,
    /// The activation rate limit (GCRA): when the allowance is next full,
    /// in ticks; 0 when it is.
    activate_tat: u64,
}

impl Answered {
    /// May the guest use the TPM for an ActivateCredential now?  If so, it
    /// is counted.
    fn may_activate(&mut self, hz: u64) -> bool {
        let interval = hz * ACTIVATE_INTERVAL_MS / 1000;
        let now = host::ticks::now();
        let tat = self.activate_tat.max(now);
        if tat - now > interval * (ACTIVATE_BURST - 1) {
            return false;
        }
        self.activate_tat = tat + interval;
        true
    }
}

fn page(id: usize) -> *mut abi::AttestPage {
    trust::page_va(id) as *mut abi::AttestPage
}

/// The result of guest `id`'s request in its page (the evidence, or what
/// we built in `out`), or -errno.
fn execute<'a>(
    state: &'a mut Option<State>,
    id: usize,
    r: &GuestRecord,
    last: &mut Answered,
    hz: u64,
    out: &'a mut [u8; ANSWER_MAX],
) -> Result<&'a [u8], i64> {
    let p = page(id);
    let (op, in_len, blob_len) = unsafe {
        (addr_of!((*p).op).read_volatile(), addr_of!((*p).in_len).read_volatile() as usize, addr_of!((*p).blob_len).read_volatile() as usize)
    };
    // Our own copy: the guest may change the page meanwhile.
    let mut copy = [0u8; abi::ATTEST_PAGE_DATA];
    let data = &mut copy[..in_len.min(abi::ATTEST_PAGE_DATA)];
    for (i, b) in data.iter_mut().enumerate() {
        *b = unsafe { addr_of!((*p).data[i]).read_volatile() };
    }
    let data = &*data;
    if matches!(op, abi::ATTEST_ACT | abi::ATTEST_SEAL) {
        if in_len != 32 && !(op == abi::ATTEST_ACT && in_len == 36) { return Err(EINVAL); }
        let bits = core::array::from_fn(|i| u64::from_le_bytes(data[i * 8..i * 8 + 8].try_into().unwrap()));
        let options = if in_len == 36 { u32::from_le_bytes(data[32..36].try_into().unwrap()) as u64 } else { 0 };
        let op = if op == abi::ATTEST_ACT { trust::FLAGS_ACT } else { trust::FLAGS_SEAL };
        let flags = flags::call(op, id, r.instance, bits, options)?.bytes();
        out[..32].copy_from_slice(&flags.taint);
        out[32..64].copy_from_slice(&flags.seal);
        return Ok(&out[..64]);
    }
    if !matches!(op, abi::ATTEST_REPORT | abi::ATTEST_EVIDENCE | abi::ATTEST_ACTIVATE) { return Err(ENOSYS); }
    let Some(s) = state else { return Err(ENODEV) };
    match op {
        abi::ATTEST_REPORT => {
            let mut d = [0u8; abi::ATTEST_DATA_SIZE];
            let n = data.len().min(d.len());
            d[..n].copy_from_slice(&data[..n]);
            // REPORT_MAX bounds every report.
            let n = s.report(id, r, &d, out).map_err(|Overflow| EIO)?;
            Ok(&out[..n])
        }
        abi::ATTEST_EVIDENCE => Ok(&s.evidence[..s.evidence_len]),
        abi::ATTEST_ACTIVATE if blob_len > data.len() => Err(EINVAL),
        abi::ATTEST_ACTIVATE if !last.may_activate(hz) => Err(EAGAIN),
        abi::ATTEST_ACTIVATE => {
            let n = s.activate(&data[..blob_len], &data[blob_len..], out).map_err(|e| {
                info!("l4h-trustd: guest {}: ActivateCredential failed: {}", id, e);
                EIO
            })?;
            Ok(&out[..n])
        }
        _ => Err(ENOSYS),
    }
}

/// Answer guest `id`'s request `seq`: the result's piece from the
/// request's offset, then done = seq; root raises the device's event.
fn answer(id: usize, seq: u32, result: Result<&[u8], i64>) {
    let p = page(id);
    unsafe {
        let off = addr_of!((*p).offset).read_volatile() as usize;
        let (status, total, n) = match &result {
            Ok(r) => {
                let n = r.len().saturating_sub(off).min(abi::ATTEST_PAGE_DATA);
                for (i, &b) in r[off.min(r.len())..][..n].iter().enumerate() {
                    addr_of_mut!((*p).data[i]).write_volatile(b);
                }
                (0, r.len(), n)
            }
            Err(e) => (-e, 0, 0),
        };
        addr_of_mut!((*p).status).write_volatile(status as i32);
        addr_of_mut!((*p).total).write_volatile(total as u32);
        addr_of_mut!((*p).out_len).write_volatile(n as u32);
        fence(Ordering::Release);
        addr_of_mut!((*p).done).write_volatile(seq);
    }
    let attest = unsafe { &*(trust::ATTEST_EVENTS_VA as *const host::vmmgr::AttestEvents) };
    attest.done.fetch_or(1 << id, Ordering::AcqRel);
    cap::<cap_type::Notification>(trust::SLOT_VMMGR_NTFN).signal();
}

/// Measure one private root request. Root waits for the answer with a timeout;
/// this thread never calls root and never waits for a response from it.
fn measure_request(state: &mut Option<State>) {
    let p = trust::KEXEC_STATE_VA as *mut trust::KexecState;
    let mailbox = unsafe { addr_of_mut!((*p).measure) };
    let Some((seq, digest)) = (unsafe { host::handoff::Mailbox::pending(mailbox) }) else {
        return;
    };
    // This host's TPM work ends here. A kexec does not reset the TPM, so
    // its transient keys are flushed, or each host in a chain would hold
    // one of the few object slots until the next cold boot.
    let status = match state.take() {
        Some(mut s) => {
            let status = tpm2::pcr_extend(&mut s.tpm, KEXEC_PCR, &digest).map_or_else(|e| {
                l4h_rt::log!("l4h-trustd: kexec PCR extend failed: {}", e);
                EIO as u64
            }, |_| 0);
            for handle in core::iter::once(s.ak).chain(s.ek) {
                tpm2::flush(&mut s.tpm, handle);
            }
            status
        }
        None => ENODEV as u64,
    };
    unsafe { host::handoff::Mailbox::complete(mailbox, seq, status) };
    cap::<cap_type::Notification>(trust::SLOT_MEASURE_DONE).signal();
}

fn main(info: &'static Info) -> ! {
    flags::start();
    let cfg: &TrustdConfig = unsafe { info.config() };
    let hz = info.header().tsc_hz;
    let mut state = if cfg.iface == trust::TPM_NONE {
        None
    } else {
        match init(cfg, hz) {
            Ok(s) => Some(s),
            Err((what, e)) => {
                l4h_rt::log!("l4h-trustd: TPM unusable, no attestation: {}: {}", what, e);
                None
            }
        }
    };
    unsafe {
        let p = trust::KEXEC_STATE_VA as *mut trust::KexecState;
        if let Some(s) = &state {
            addr_of_mut!((*p).key_extension).write_volatile(s.key_extension);
        }
        fence(Ordering::Release);
        addr_of_mut!((*p).status).write_volatile(if state.is_some() { trust::KEXEC_READY } else { trust::KEXEC_UNAVAILABLE });
    }
    if state.is_none() {
        for id in 0..trust::MAX_RECORDS {
            unsafe { addr_of_mut!((*page(id)).state).write_volatile(abi::ATTEST_NO_REPORTS) };
        }
        info!("l4h-trustd: no TPM: flags only");
    }
    // Guests kick while we set up the TPM too: their bits wait in the
    // notification.
    let kick = cap::<cap_type::Notification>(trust::SLOT_KICK);
    let mut answered = [Answered::default(); trust::MAX_RECORDS];
    let mut out = [0u8; ANSWER_MAX];
    loop {
        let (_, mut kicked) = kick.wait();
        measure_request(&mut state);
        while kicked != 0 {
            let id = kicked.trailing_zeros() as usize;
            kicked &= kicked - 1;
            let Some(r) = record(id) else { continue };
            if state.is_none() {
                unsafe { addr_of_mut!((*page(id)).state).write_volatile(abi::ATTEST_NO_REPORTS) };
            }
            let seq = unsafe { addr_of!((*page(id)).seq).read_volatile() };
            fence(Ordering::Acquire);
            let last = &mut answered[id];
            if last.instance != r.instance {
                *last = Answered { instance: r.instance, ..Default::default() };
            }
            if seq == last.seq {
                continue;
            }
            let result = execute(&mut state, id, &r, last, hz, &mut out);
            // Destroyed meanwhile (or replaced by another guest): nobody
            // waits for this answer.
            if record(id).is_none_or(|now| now.instance != r.instance) {
                continue;
            }
            answer(id, seq, result);
            answered[id].seq = seq;
        }
    }
}

l4h_rt::component!(main, heap_size = aml::HEAP);
