//! l4h-trustd: attestation for guests (DESIGN.md §10.2).
//!
//! At start, trustd generates a P-256 signing key and has the TPM quote
//! the PCRs, which hold the measurements of what booted (the UEFI
//! application with seL4, root and every host component, then dom0's
//! files), with the hash of the key as the quote's qualifying data.  It
//! then extends PCR 15 with the same hash: the quote shows PCR 15 zero,
//! so it is the first and only key trustd issued in this boot.  The key
//! signs guests' reports; the quote, the attestation key and the EK
//! certificate make the host evidence.  The TPM is only used at start,
//! and for ActivateCredential.
//!
//! Guests ask through their attestation device (l4h_attest_page): a kick,
//! then the answer in the page and an event, so that a vCPU never waits
//! for us.  We answer one request at a time, and each guest's
//! ActivateCredential calls are rate limited, so that no guest keeps the
//! TPM busy for the others.
//!
//! In a multikernel machine every partition's trustd has its own key, and
//! the primary's, which has the TPM, quotes the others' and extends PCR 15
//! with each, in the order they come (relay.rs).  A key's quote shows PCR
//! 15 as the chain of the keys extended before it, which its evidence
//! lists, each with its partition: the primary's first, at most one per
//! partition.  Reports and evidence then carry the partition (version 2).
//!
//! Nothing here allocates (DESIGN.md §10): requests are copied, and answers
//! built, in fixed buffers, and the evidence is made once into one.  The
//! heap is the AML interpreter's (aml::HEAP).

#![no_std]
#![no_main]

// For the AML interpreter only (aml::HEAP).
extern crate alloc;

mod aml;
mod cbor;
mod flags;
mod relay;
mod time;
mod tpm;
mod tpm2;

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use l4h_abi as abi;
use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::trust::{self, GuestRecord, RelayHeader, TrustdConfig};
use l4h_rt::{Info, cap, host, info, sel4};
use sel4::cap_type;

use crate::cbor::{Enc, Overflow};
use crate::relay::{Relay, Served, Wait};
use crate::tpm::{Error, Tpm};
use crate::tpm2::Template;

use l4h_rt::host::errno::{EAGAIN, EINVAL, EIO, ENODEV, ENOSYS, ETIMEDOUT, Errno};
/// Not errnos (all of those are below): execute() did not answer, as the
/// request waits for the relay to be free (DEFER) or for its answer
/// (PENDING).
const DEFER: Errno = 1 << 32;
const PENDING: Errno = (1 << 32) + 1;

/// ActivateCredential per guest: up to ACTIVATE_BURST at once, then one
/// every ACTIVATE_INTERVAL_MS (about 80 ms of TPM time each, on a discrete
/// TPM).  Beyond that, -EAGAIN without using the TPM.
const ACTIVATE_BURST: u64 = 5;
const ACTIVATE_INTERVAL_MS: u64 = 1000;

/// PCRs in the quote: the static ones (SRTM), 0-15.
const QUOTE_PCRS: u32 = 0xffff;
/// Extended with the key's hash once it is quoted.
const KEY_PCR: u32 = 15;
const KEY_DOMAIN: &[u8] = b"l4h-trustd-key-v1";
/// A partition's key: the domain, the partition (u32 little-endian), then
/// the key.
const KEY_DOMAIN_PARTITION: &[u8] = b"l4h-trustd-key-v2";

/// A secondary asks the primary for its key's quote every second, for
/// two minutes: the primary may boot later, and its TPM take long to
/// start.  Then it runs without reports.
const KEY_EVERY_MS: u64 = 1000;
const KEY_TRIES: u32 = 120;
/// ActivateCredential through the primary: the first one creates the EK,
/// which takes a hardware TPM seconds.
const ACTIVATE_EVERY_MS: u64 = 5000;
const ACTIVATE_TRIES: u32 = 4;

/// The host evidence's room: the AK's public area, the key, 16 PCRs, the
/// quote and its signature take about 1 KiB, the rest is for the EK
/// certificate.
const EVIDENCE_MAX: usize = 8192;
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
    + (9 + 9)
    + (10 + 9);
/// The room for a report, and for each of its pieces: the COSE_Sign1 is
/// the payload with 76 bytes around it (the Sig_structure, 20).
const REPORT_MAX: usize = 512;
const _: () = assert!(PAYLOAD_MAX + 76 <= REPORT_MAX);
/// An answer we build: a report, or a credential (a TPM2B_DIGEST, at most
/// 64 bytes).
const ANSWER_MAX: usize = REPORT_MAX;
const _: () = assert!(EVIDENCE_MAX + trust::RELAY_HEADER <= trust::RELAY_MSG_MAX);

/// A fixed buffer and how much of it is used.
#[derive(Clone, Copy)]
struct Buf<const N: usize> {
    b: [u8; N],
    n: usize,
}

impl<const N: usize> Buf<N> {
    fn of(s: &[u8]) -> Option<Self> {
        let mut b = Buf { b: [0; N], n: s.len() };
        b.b.get_mut(..s.len())?.copy_from_slice(s);
        Some(b)
    }

    fn get(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

/// A partition's key quote: the chain of keys extended before it is
/// `chain[..at]`.
struct Quoted {
    at: usize,
    pcrs: ArrayVec<(u32, [u8; 32]), { tpm2::PCRS }>,
    quote: Buf<256>,
    sig: Buf<128>,
}

/// The TPM, in the partition that has it.
struct Local {
    tpm: Tpm,
    /// The attestation key's handle and public area.
    ak: u32,
    ak_public: Buf<512>,
    /// The EK, created on first use (ActivateCredential), RSA unless the
    /// TPM has an ECC EK certificate.
    ek: Option<u32>,
    ek_ecc: bool,
    ek_cert: Option<Buf<EK_CERT_MAX>>,
    /// Multikernel: the keys extended into PCR 15, in order, with their
    /// partitions, and each partition's quote.
    chain: ArrayVec<(u32, [u8; 65]), { trust::MAX_PARTITIONS }>,
    quotes: [Option<Quoted>; trust::MAX_PARTITIONS],
}

struct State {
    key: SigningKey,
    /// SHA-256 of the key's SEC1 point.
    key_id: [u8; 32],
    /// Multikernel: this partition.
    partition: Option<u32>,
    /// None in a multikernel secondary: the primary's, through the relay.
    local: Option<Local>,
    /// The host evidence: its first `evidence_len` bytes.
    evidence: [u8; EVIDENCE_MAX],
    evidence_len: usize,
}

/// What the TPM quotes for key `p`: the hash of the domain, the
/// partition (multikernel) and the key.
fn binding(partition: Option<u32>, p: &[u8; 65]) -> [u8; 32] {
    match partition {
        None => Sha256::new().chain_update(KEY_DOMAIN).chain_update(p).finalize().into(),
        Some(k) => Sha256::new().chain_update(KEY_DOMAIN_PARTITION).chain_update(k.to_le_bytes()).chain_update(p).finalize().into(),
    }
}

/// The host evidence for `point` into `out`, as the TPM answers: keys in
/// the order of their encodings (RFC 8949 §4.2.1).  Multikernel (version
/// 2): the partition, and the keys extended into PCR 15 before this one.
#[allow(clippy::too_many_arguments)]
fn encode_evidence(
    out: &mut [u8],
    ak_public: &[u8],
    point: &[u8; 65],
    pcrs: &[(u32, [u8; 32])],
    quote: &[u8],
    ek_cert: Option<&[u8]>,
    sig: &[u8],
    mk: Option<(u32, &[(u32, [u8; 65])])>,
) -> Result<usize, Overflow> {
    let mut e = Enc::new(out);
    e.map(6 + ek_cert.is_some() as usize + 2 * mk.is_some() as usize);
    e.text("v").uint(if mk.is_some() { 2 } else { 1 });
    e.text("ak").bytes(ak_public);
    // A COSE_Key (EC2, P-256).
    e.text("key").map(4).uint(1).uint(2).nint(0).uint(1).nint(1).bytes(&point[1..33]).nint(2).bytes(&point[33..]);
    e.text("pcrs").map(pcrs.len());
    for (i, v) in pcrs {
        e.uint(*i as u64).bytes(v);
    }
    if let Some((_, chain)) = mk {
        e.text("chain").array(chain.len());
        for (k, p) in chain {
            e.array(2).uint(*k as u64).bytes(p);
        }
    }
    e.text("quote").bytes(quote);
    if let Some(c) = ek_cert {
        e.text("ekcert").bytes(c);
    }
    e.text("quotesig").bytes(sig);
    if let Some((k, _)) = mk {
        e.text("partition").uint(k as u64);
    }
    Ok(e.done()?.len())
}

/// The P-256 point of `key`, uncompressed (0x04, x, y).
fn point(key: &SigningKey) -> [u8; 65] {
    key.verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap()
}

/// `r`, with what failed.
fn step<T>(what: &'static str, r: Result<T, Error>) -> Result<T, (&'static str, Error)> {
    r.map_err(|e| (what, e))
}

fn init(cfg: &TrustdConfig, hz: u64, partition: Option<u32>) -> Result<State, (&'static str, Error)> {
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
    let bound = binding(partition, &p);

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
        c => c.and_then(|n| Buf::of(&cert[..n])),
    };

    let (ak, ak_public) = step("CreatePrimary (AK)", tpm2::create_primary(&mut tpm, tpm2::RH_ENDORSEMENT, Template::Ak))?;
    let ak_public = Buf::<512>::of(ak_public).ok_or(("CreatePrimary (AK)", Error::Bad("public area too large")))?;
    let pcrs = step("PCR_Read", tpm2::pcr_read(&mut tpm, QUOTE_PCRS))?;
    let mut evidence = [0u8; EVIDENCE_MAX];
    let (quote, sig) = step("Quote", tpm2::quote(&mut tpm, ak, &bound, QUOTE_PCRS))?;
    let mk = partition.map(|k| (k, &[][..]));
    let evidence_len = encode_evidence(&mut evidence, ak_public.get(), &p, &pcrs, quote, ek_cert.as_ref().map(|c| c.get()), sig, mk)
        .map_err(|Overflow| ("evidence", Error::Bad("larger than EVIDENCE_MAX")))?;
    step("PCR_Extend", tpm2::pcr_extend(&mut tpm, KEY_PCR, &bound))?;
    let mut chain = ArrayVec::new();
    if let Some(k) = partition {
        let _ = chain.push((k, p));
    }
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
    let local = Local { tpm, ak, ak_public, ek: None, ek_ecc, ek_cert, chain, quotes: [const { None }; trust::MAX_PARTITIONS] };
    Ok(State { key, key_id, partition, local: Some(local), evidence, evidence_len })
}

/// 32 random bytes from the CPU (RDRAND), for a secondary's key: it has
/// no TPM.
#[cfg(target_arch = "x86_64")]
fn cpu_random(out: &mut [u8; 32]) -> bool {
    #[allow(unused_unsafe)]
    let ecx = unsafe { core::arch::x86_64::__cpuid(1) }.ecx;
    if ecx & (1 << 30) == 0 {
        return false;
    }
    for chunk in out.chunks_mut(8) {
        // RDRAND can fail transiently; Intel suggests 10 tries.
        let v = (0..10).find_map(|_| {
            let (v, ok): (u64, u8);
            unsafe { core::arch::asm!("rdrand {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack)) };
            (ok != 0).then_some(v)
        });
        let Some(v) = v else { return false };
        chunk.copy_from_slice(&v.to_le_bytes());
    }
    true
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu_random(_out: &mut [u8; 32]) -> bool {
    false
}

/// A multikernel secondary: a key of our own, which we ask the primary's
/// trustd to quote; its answer is our evidence (ready).
fn start_remote(relay: &mut Relay, hz: u64) -> Result<SigningKey, &'static str> {
    let key = loop {
        let mut seed = [0u8; 32];
        if !cpu_random(&mut seed) {
            return Err("no RDRAND for a key");
        }
        if let Ok(k) = SigningKey::from_bytes(&seed.into()) {
            break k;
        }
    };
    Relay::out_data()[..65].copy_from_slice(&point(&key));
    relay.start(trust::RELAY_KEY, 65, hz, KEY_EVERY_MS, KEY_TRIES, Wait::Key);
    Ok(key)
}

/// The primary's answer to start_remote: the state, or why there is none.
fn ready(key: SigningKey, partition: u32, answer: Result<&[u8], Errno>, t0: u64, hz: u64) -> Result<State, &'static str> {
    let ev = match answer {
        Ok(ev) if ev.len() <= EVIDENCE_MAX => ev,
        Ok(_) => return Err("partition 0's evidence is too large"),
        Err(ENODEV) => return Err("partition 0 has no TPM"),
        Err(ETIMEDOUT) => return Err("no answer from partition 0"),
        Err(_) => return Err("partition 0 refused to quote the key"),
    };
    let key_id: [u8; 32] = Sha256::digest(point(&key)).into();
    let mut evidence = [0u8; EVIDENCE_MAX];
    evidence[..ev.len()].copy_from_slice(ev);
    info!(
        "l4h-trustd: ready in {} ms: signing key {:02x}{:02x}{:02x}{:02x}..., quoted by partition 0",
        (host::ticks::now() - t0) * 1000 / hz.max(1),
        key_id[0], key_id[1], key_id[2], key_id[3],
    );
    Ok(State { key, key_id, partition: Some(partition), local: None, evidence, evidence_len: ev.len() })
}

/// No reports: tell every guest's driver.
fn no_reports() {
    for id in 0..trust::MAX_RECORDS {
        unsafe { addr_of_mut!((*page(id)).state).write_volatile(abi::ATTEST_NO_REPORTS) };
    }
    info!("l4h-trustd: no TPM: flags only");
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
        c.map(11 + self.partition.is_some() as usize);
        c.text("v").uint(if self.partition.is_some() { 2 } else { 1 });
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
        if let Some(k) = self.partition {
            c.text("partition").uint(k as u64);
        }
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
}

impl Local {
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

    /// Partition `k`'s evidence, from its quote, into `out`.
    fn evidence(&self, k: u32, out: &mut [u8]) -> Result<usize, Errno> {
        let q = self.quotes[k as usize].as_ref().ok_or(EINVAL)?;
        let (_, point) = &self.chain[q.at];
        encode_evidence(out, self.ak_public.get(), point, &q.pcrs, q.quote.get(), self.ek_cert.as_ref().map(|c| c.get()),
            q.sig.get(), Some((k, &self.chain[..q.at]))).map_err(|Overflow| EIO)
    }

    /// Quote partition `k`'s key `point` and extend PCR 15 with it, once:
    /// its evidence, into `out`.  The same key again gets the same
    /// evidence; another key is refused.
    fn quote_key(&mut self, k: u32, point: &[u8; 65], out: &mut [u8]) -> Result<usize, Errno> {
        if let Some(&(_, p)) = self.chain.iter().find(|(q, _)| *q == k) {
            return if p == *point { self.evidence(k, out) } else { Err(EINVAL) };
        }
        let bound = binding(Some(k), point);
        let failed = |what: &str, e: Error| {
            info!("l4h-trustd: partition {}'s key: {} failed: {}", k, what, e);
            EIO
        };
        let pcrs = tpm2::pcr_read(&mut self.tpm, QUOTE_PCRS).map_err(|e| failed("PCR_Read", e))?;
        let (quote, sig) = tpm2::quote(&mut self.tpm, self.ak, &bound, QUOTE_PCRS).map_err(|e| failed("Quote", e))?;
        let (quote, sig) = (Buf::of(quote).ok_or(EIO)?, Buf::of(sig).ok_or(EIO)?);
        // The quote is given out only once PCR 15 moved past it, so that no
        // other key gets a quote with the same chain.
        tpm2::pcr_extend(&mut self.tpm, KEY_PCR, &bound).map_err(|e| failed("PCR_Extend", e))?;
        let at = self.chain.len();
        self.chain.push((k, *point)).map_err(|_| EINVAL)?;
        self.quotes[k as usize] = Some(Quoted { at, pcrs, quote, sig });
        info!("l4h-trustd: partition {}'s key quoted, key {} in PCR 15", k, at + 1);
        self.evidence(k, out)
    }
}

/// The primary: answer what other partitions' trustds asked.
fn serve(state: &mut Option<State>, relay: &mut Relay, served: &mut [Served; trust::MAX_PARTITIONS]) {
    for k in 1..relay.count {
        let Some(m) = relay.recv(k) else { continue };
        let (head, from) = (m.head, k);
        let last = &mut served[from as usize];
        let out = Relay::out_data();
        let mut reply = RelayHeader { id: head.id, op: head.op, status: 0, len: 0, _pad: 0 };
        let result = if head.id == last.id && head.op == last.op {
            // Asked again: the answer was lost, or is on its way.
            match (last.status, head.op) {
                (0, trust::RELAY_KEY) => state.as_ref().and_then(|s| s.local.as_ref()).map_or(Err(ENODEV), |l| l.evidence(from, out)),
                (0, _) => {
                    out[..last.len].copy_from_slice(&last.data[..last.len]);
                    Ok(last.len)
                }
                (e, _) => Err(l4h_rt::host::errno::of_status(e as i64)),
            }
        } else {
            let local = state.as_mut().and_then(|s| s.local.as_mut());
            let r = match (local, head.op) {
                (None, _) => Err(ENODEV),
                (Some(l), trust::RELAY_KEY) => match <&[u8; 65]>::try_from(m.data) {
                    Ok(p) if p[0] == 4 => l.quote_key(from, p, out),
                    _ => Err(EINVAL),
                },
                (Some(l), trust::RELAY_ACTIVATE) => {
                    let blob_len = m.data.get(..4).map_or(usize::MAX, |b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
                    match m.data.get(4..).filter(|d| blob_len <= d.len()) {
                        None => Err(EINVAL),
                        Some(d) => l.activate(&d[..blob_len], &d[blob_len..], &mut out[..last.data.len()]).map_err(|e| {
                            info!("l4h-trustd: partition {}: ActivateCredential failed: {}", from, e);
                            EIO
                        }),
                    }
                }
                _ => Err(ENOSYS),
            };
            *last = Served { id: head.id, op: head.op, status: r.err().map_or(0, |e| l4h_rt::host::errno::negative(e) as i32), ..Served::default() };
            if let (Ok(n), trust::RELAY_ACTIVATE) = (r, head.op) {
                last.len = n;
                last.data[..n].copy_from_slice(&out[..n]);
            }
            r
        };
        match result {
            Ok(n) => reply.len = n as u32,
            Err(e) => reply.status = l4h_rt::host::errno::negative(e) as i32,
        }
        relay.send(from, reply);
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

/// The result of guest `id`'s request `seq` in its page (the evidence, or
/// what we built in `out`), or -errno.  `starting`: a secondary waits for
/// its key's quote.
#[allow(clippy::too_many_arguments)]
fn execute<'a>(
    state: &'a mut Option<State>,
    starting: bool,
    id: usize,
    seq: u32,
    r: &GuestRecord,
    last: &mut Answered,
    hz: u64,
    relay: Option<&mut Relay>,
    out: &'a mut [u8; ANSWER_MAX],
) -> Result<&'a [u8], Errno> {
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
    let Some(s) = state else { return Err(if starting { DEFER } else { ENODEV }) };
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
        // A secondary's goes to the primary, one at a time.
        abi::ATTEST_ACTIVATE if s.local.is_none() && relay.as_ref().is_none_or(|r| r.busy()) => {
            Err(if relay.is_some() { DEFER } else { ENODEV })
        }
        abi::ATTEST_ACTIVATE if !last.may_activate(hz) => Err(EAGAIN),
        abi::ATTEST_ACTIVATE => match (&mut s.local, relay) {
            (Some(l), _) => {
                let n = l.activate(&data[..blob_len], &data[blob_len..], out).map_err(|e| {
                    info!("l4h-trustd: guest {}: ActivateCredential failed: {}", id, e);
                    EIO
                })?;
                Ok(&out[..n])
            }
            (None, Some(relay)) => {
                let d = Relay::out_data();
                let n = 4 + data.len();
                d[..4].copy_from_slice(&(blob_len as u32).to_le_bytes());
                d[4..n].copy_from_slice(data);
                relay.start(trust::RELAY_ACTIVATE, n, hz, ACTIVATE_EVERY_MS, ACTIVATE_TRIES, Wait::Activate { id, instance: r.instance, seq });
                Err(PENDING)
            }
            (None, None) => Err(ENODEV),
        },
        _ => Err(ENOSYS),
    }
}

/// Answer guest `id`'s request `seq`: the result's piece from the
/// request's offset, then done = seq; root raises the device's event.
fn answer(id: usize, seq: u32, result: Result<&[u8], Errno>) {
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
            Err(e) => (l4h_rt::host::errno::negative(*e), 0, 0),
        };
        addr_of_mut!((*p).status).write_volatile(status as i32);
        addr_of_mut!((*p).total).write_volatile(total as u32);
        addr_of_mut!((*p).out_len).write_volatile(n as u32);
        fence(Ordering::Release);
        addr_of_mut!((*p).done).write_volatile(seq);
    }
    use l4h_rt::host::root::call::Client;
    let _ = l4h_rt::ipc::Endpoint(cap::<cap_type::Endpoint>(host::SLOT_ROOT_EP)).attest_done(id);
}

fn main(info: &'static Info) -> ! {
    flags::start();
    let cfg: &TrustdConfig = unsafe { info.config() };
    let hz = info.header().tsc_hz;
    let t0 = host::ticks::now();
    let mut relay = Relay::new(cfg.partition, cfg.partitions);
    let partition = relay.as_ref().map(|r| r.index);
    // A secondary's key, until the primary quoted it.
    let mut starting = None;
    let mut state = match (cfg.iface, relay.as_mut()) {
        (trust::TPM_NONE, _) | (trust::TPM_REMOTE, None) => None,
        (trust::TPM_REMOTE, Some(r)) => {
            match start_remote(r, hz) {
                Ok(k) => starting = Some(k),
                Err(why) => l4h_rt::log!("l4h-trustd: no attestation: {}", why),
            }
            None
        }
        _ => match init(cfg, hz, partition) {
            Ok(s) => Some(s),
            Err((what, e)) => {
                l4h_rt::log!("l4h-trustd: TPM unusable, no attestation: {}: {}", what, e);
                None
            }
        },
    };
    if state.is_none() && starting.is_none() {
        no_reports();
    }
    // Guests kick while we set up the TPM too: their bits wait in the
    // notification.
    let kick = cap::<cap_type::Notification>(trust::SLOT_KICK);
    let mut answered = [Answered::default(); trust::MAX_RECORDS];
    let mut served = [Served::default(); trust::MAX_PARTITIONS];
    let mut out = [0u8; ANSWER_MAX];
    // Guests whose requests wait for the relay.
    let mut deferred = 0u64;
    loop {
        let (_, kicked) = kick.wait();
        let mut kicked = kicked | core::mem::take(&mut deferred);
        // RELAY_BADGE is also guest 63's kick: both are looked at.
        match relay.as_mut() {
            Some(r) if r.primary() => {
                if kicked & trust::RELAY_BADGE != 0 {
                    serve(&mut state, r, &mut served);
                }
            }
            Some(r) => match r.poll() {
                Some((Wait::Key, got)) => {
                    let key = starting.take().expect("a key waits for its quote");
                    match ready(key, partition.unwrap_or(0), got, t0, hz) {
                        Ok(s) => state = Some(s),
                        Err(why) => {
                            l4h_rt::log!("l4h-trustd: no attestation: {}", why);
                            no_reports();
                        }
                    }
                }
                Some((Wait::Activate { id, instance, seq }, got)) => {
                    let result = match got {
                        Ok(c) if c.len() <= out.len() => {
                            out[..c.len()].copy_from_slice(c);
                            Ok(&out[..c.len()])
                        }
                        Ok(_) => Err(EIO),
                        Err(e) => {
                            info!("l4h-trustd: guest {}: ActivateCredential through partition 0 failed: {}", id, e);
                            Err(if e == ETIMEDOUT { EIO } else { e })
                        }
                    };
                    if record(id).is_some_and(|now| now.instance == instance) && answered[id].instance == instance {
                        answer(id, seq, result);
                        answered[id].seq = seq;
                    }
                }
                None => {}
            },
            None => {}
        }
        while kicked != 0 {
            let id = kicked.trailing_zeros() as usize;
            kicked &= kicked - 1;
            let Some(r) = record(id) else { continue };
            if state.is_none() && starting.is_none() {
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
            let result = execute(&mut state, starting.is_some(), id, seq, &r, last, hz, relay.as_mut(), &mut out);
            match result {
                Err(DEFER) => {
                    deferred |= host::badges::trustd_kick::GUEST.nth(id);
                    continue;
                }
                Err(PENDING) => continue,
                _ => {}
            }
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
