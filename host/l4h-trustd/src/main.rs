//! l4h-trustd: attestation for guests (DESIGN.md §10.2).
//!
//! At start, trustd generates a P-256 signing key and has the TPM quote
//! the PCRs, which hold the measurements of what booted (the UEFI
//! application with seL4, root and every host component, then dom0's
//! files), with the hash of the key as the quote's qualifying data.  It
//! then extends PCR 15 with the same hash: the quote shows PCR 15 zero,
//! so it is the first and only key trustd issued in this boot.  The key
//! signs guests' reports; the quote, the attestation key and the EK
//! certificate make the host evidence.  A TPM without an EK certificate in
//! NV (an AMD fTPM's is fetched from AMD by the EK's public key) gives the
//! EK's public area instead, created at start, so that a verifier can
//! find the certificate, or encrypt a credential to the EK.  The TPM is
//! only used at start, and for ActivateCredential.
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
//! On an Intel TDX trust domain (TrustdConfig::tdx != TDX_NONE, never in a
//! multikernel machine) any TPM is ignored completely and the key is bound
//! to the TD alone (tdx.rs, tdxrt.rs): a DCAP quote of a TDREPORT over its
//! hash, taken while RTMR 3 is zero, after which RTMR 3 is extended with it.
//! The TDX evidence and fresh quotes over a guest's report come in requests
//! of their own.  The key's seed is the CPU's alone (RDSEED, which the VMM
//! can neither see nor change); if TDX resources, CPU entropy or TD binding
//! fail, trustd runs flags-only without touching any TPM or partition relay.
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
mod fadt;
mod flags;
mod key;
mod relay;
mod tdx;
mod tdxrt;
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
use crate::tdxrt::Tdx;
use crate::tpm::{Error, Tpm};
use crate::tpm2::Template;

use l4h_rt::host::errno::{EAGAIN, EINVAL, EIO, ENODEV, ENOENT, ENOSYS, ETIMEDOUT, Errno};
/// Not errnos (all of those are below): execute() did not answer, as the
/// request waits for the relay to be free (DEFER) or for its answer
/// (PENDING).
const DEFER: Errno = 1 << 32;
const PENDING: Errno = (1 << 32) + 1;

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
/// certificate, or the EK's public area (at most EK_PUBLIC_MAX) when there
/// is none.
const EVIDENCE_MAX: usize = 8192;
/// The largest EK certificate we put in the evidence (a few hundred bytes
/// to 2 KiB in practice).  A larger one is left out: the evidence is
/// still usable, without the certificate a verifier can check the TPM by.
const EK_CERT_MAX: usize = 4096;
/// An EK's TPMT_PUBLIC: about 360 bytes for RSA 2048 with the policy.
const EK_PUBLIC_MAX: usize = 512;
/// The evidence has one or the other; with a chain of 8 partitions' keys
/// (72 bytes each), and the vendor, both fit.
const _: () = assert!(EK_PUBLIC_MAX <= EK_CERT_MAX && 1024 + EK_CERT_MAX + 72 * trust::MAX_PARTITIONS + 16 <= EVIDENCE_MAX);

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
    /// The EK, RSA unless the TPM has an ECC EK certificate: created at
    /// start when the TPM has no EK certificate, for its public area in the
    /// evidence, else on first use (ActivateCredential).
    ek: Option<u32>,
    ek_ecc: bool,
    ek_cert: Option<Buf<EK_CERT_MAX>>,
    /// The EK's public area, when the TPM has no EK certificate.
    ek_public: Option<Buf<EK_PUBLIC_MAX>>,
    /// TPM_PT_MANUFACTURER.
    vendor: Option<u32>,
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
    /// The key is bound to a TPM quote: `evidence` is the host evidence,
    /// its first `evidence_len` bytes.  Not on a TD whose TPM failed or
    /// that has none: its key is bound to the TD alone (Tdx).
    has_tpm: bool,
    evidence: [u8; EVIDENCE_MAX],
    evidence_len: usize,
}

impl State {
    /// A key with no TPM quote (TDX binds it).
    fn keyed(key: SigningKey, partition: Option<u32>) -> State {
        let key_id = Sha256::digest(point(&key)).into();
        State { key, key_id, partition, local: None, has_tpm: false, evidence: [0; EVIDENCE_MAX], evidence_len: 0 }
    }
}

/// What the TPM quotes for key `p`: the hash of the domain, the
/// partition (multikernel) and the key.
fn binding(partition: Option<u32>, p: &[u8; 65]) -> [u8; 32] {
    match partition {
        None => Sha256::new().chain_update(KEY_DOMAIN).chain_update(p).finalize().into(),
        Some(k) => Sha256::new().chain_update(KEY_DOMAIN_PARTITION).chain_update(k.to_le_bytes()).chain_update(p).finalize().into(),
    }
}

/// What the host says of its TPM in the evidence, unsigned: the EK
/// certificate, or the EK's public area when there is none, and the
/// manufacturer.
#[derive(Clone, Copy)]
struct TpmInfo<'a> {
    ek_cert: Option<&'a [u8]>,
    ek_public: Option<&'a [u8]>,
    vendor: Option<u32>,
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
    tpm: TpmInfo,
    sig: &[u8],
    mk: Option<(u32, &[(u32, [u8; 65])])>,
) -> Result<usize, Overflow> {
    let mut e = Enc::new(out);
    let optional = [tpm.ek_cert.is_some(), tpm.ek_public.is_some(), tpm.vendor.is_some()];
    e.map(6 + optional.iter().filter(|&&o| o).count() + 2 * mk.is_some() as usize);
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
    if let Some(p) = tpm.ek_public {
        e.text("ekpub").bytes(p);
    }
    e.text("quote").bytes(quote);
    if let Some(c) = tpm.ek_cert {
        e.text("ekcert").bytes(c);
    }
    if let Some(v) = tpm.vendor {
        e.text("vendor").uint(v as u64);
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

/// The TPM, started.
fn open_tpm(cfg: &TrustdConfig, hz: u64) -> Result<Tpm, (&'static str, Error)> {
    let mut tpm = step("interface", Tpm::new(cfg, hz))?;
    step("Startup", tpm2::startup(&mut tpm))?;
    Ok(tpm)
}

/// The TPM and a key from its randomness mixed with the CPU's
/// (key::mix_key_seed; the TPM's alone without RDSEED or RDRAND), so that
/// neither a TPM's known answers nor its bus give the key away.  Not a
/// TD's: a TD's key is the CPU's, made and bound to RTMR 3 before the TPM
/// is touched.
fn tpm_key(cfg: &TrustdConfig, hz: u64) -> Result<(Tpm, SigningKey), (&'static str, Error)> {
    let mut tpm = open_tpm(cfg, hz)?;
    let key = loop {
        let mut tpm_rand = [0u8; 32];
        let got = tpm2::get_random(&mut tpm, &mut tpm_rand);
        if got.is_err() {
            key::wipe(&mut tpm_rand);
        }
        step("GetRandom", got)?;
        let mut cpu = cpu_seed();
        let mut seed = key::mix_key_seed(&tpm_rand, cpu.as_ref());
        let k = SigningKey::from_bytes((&seed).into());
        key::wipe(&mut tpm_rand);
        if let Some(c) = cpu.as_mut() {
            key::wipe(c);
        }
        key::wipe(&mut seed);
        if let Ok(k) = k {
            break k;
        }
    };
    Ok((tpm, key))
}

/// Bind `key` to the TPM (quote, then PCR 15), started at `t0`.
fn init(mut tpm: Tpm, key: SigningKey, t0: u64, hz: u64, partition: Option<u32>) -> Result<State, (&'static str, Error)> {
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
    let vendor = tpm2::manufacturer(&mut tpm).map_err(|e| info!("l4h-trustd: GetCapability (manufacturer) failed: {}", e)).ok();
    // No certificate: the EK ActivateCredential uses, now, for its public
    // area.  An RSA key takes a hardware TPM seconds.
    let (ek, ek_public) = match ek_cert {
        Some(_) => (None, None),
        None => match tpm2::create_primary(&mut tpm, tpm2::RH_ENDORSEMENT, Template::Ek { ecc: ek_ecc }) {
            Ok((h, public)) => match Buf::of(public) {
                Some(p) => (Some(h), Some(p)),
                None => {
                    info!("l4h-trustd: the EK's public area ({} bytes) is larger than {}: left out of the evidence", public.len(), EK_PUBLIC_MAX);
                    (Some(h), None)
                }
            },
            Err(e) => {
                info!("l4h-trustd: CreatePrimary (EK) failed: {}: no EK in the evidence", e);
                (None, None)
            }
        },
    };
    let tpm_info = TpmInfo { ek_cert: ek_cert.as_ref().map(|c| c.get()), ek_public: ek_public.as_ref().map(|p| p.get()), vendor };

    let (ak, ak_public) = step("CreatePrimary (AK)", tpm2::create_primary(&mut tpm, tpm2::RH_ENDORSEMENT, Template::Ak))?;
    let ak_public = Buf::<512>::of(ak_public).ok_or(("CreatePrimary (AK)", Error::Bad("public area too large")))?;
    let pcrs = step("PCR_Read", tpm2::pcr_read(&mut tpm, QUOTE_PCRS))?;
    let mut evidence = [0u8; EVIDENCE_MAX];
    let (quote, sig) = step("Quote", tpm2::quote(&mut tpm, ak, &bound, QUOTE_PCRS))?;
    let mk = partition.map(|k| (k, &[][..]));
    let evidence_len = encode_evidence(&mut evidence, ak_public.get(), &p, &pcrs, quote, tpm_info, sig, mk)
        .map_err(|Overflow| ("evidence", Error::Bad("larger than EVIDENCE_MAX")))?;
    step("PCR_Extend", tpm2::pcr_extend(&mut tpm, KEY_PCR, &bound))?;
    let mut chain = ArrayVec::new();
    if let Some(k) = partition {
        let _ = chain.push((k, p));
    }
    info!(
        "l4h-trustd: ready in {} ms: signing key {:02x}{:02x}{:02x}{:02x}..., {}, TPM vendor {:08x}",
        (host::ticks::now() - t0) * 1000 / hz.max(1),
        key_id[0], key_id[1], key_id[2], key_id[3],
        match (&ek_cert, ek_ecc, &ek_public) {
            (Some(_), true, _) => "an ECC EK certificate",
            (Some(_), false, _) => "an RSA EK certificate",
            (None, _, Some(_)) => "no EK certificate (the EK's public area instead)",
            (None, _, None) => "no EK certificate",
        },
        vendor.unwrap_or(0),
    );
    let local = Local { tpm, ak, ak_public, ek, ek_ecc, ek_cert, ek_public, vendor, chain, quotes: [const { None }; trust::MAX_PARTITIONS] };
    Ok(State { key, key_id, partition, local: Some(local), has_tpm: true, evidence, evidence_len })
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

/// 32 bytes of the CPU's entropy for a TD's key, and mixed into a TPM
/// host's (tpm_key): RDSEED where it has it (straight from the entropy
/// source), else RDRAND.  In a TD neither exits to the VMM.
#[cfg(target_arch = "x86_64")]
fn cpu_seed() -> Option<[u8; 32]> {
    #[allow(unused_unsafe)]
    let ebx = unsafe { core::arch::x86_64::__cpuid_count(7, 0) }.ebx;
    let mut out = [0u8; 32];
    if ebx & (1 << 18) != 0 {
        let seeded = out.chunks_mut(8).all(|chunk| {
            // RDSEED fails while the entropy source refills: retry for a
            // while, pausing.
            let v = (0..1000).find_map(|_| {
                let (v, ok): (u64, u8);
                unsafe { core::arch::asm!("rdseed {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack)) };
                if ok == 0 {
                    core::hint::spin_loop();
                }
                (ok != 0).then_some(v)
            });
            v.map(|v| chunk.copy_from_slice(&v.to_le_bytes())).is_some()
        });
        if seeded {
            return Some(out);
        }
    }
    cpu_random(&mut out).then_some(out)
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu_seed() -> Option<[u8; 32]> {
    None
}

/// A key from the CPU alone (a TD's).
fn cpu_key() -> Option<SigningKey> {
    loop {
        let seed = cpu_seed()?;
        if let Ok(k) = SigningKey::from_bytes(&seed.into()) {
            return Some(k);
        }
    }
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
    Ok(State { key, key_id, partition: Some(partition), local: None, has_tpm: true, evidence, evidence_len: ev.len() })
}

/// No reports: tell every guest's driver.
fn no_reports() {
    tdxrt::set_states(abi::ATTEST_NO_REPORTS);
    info!("l4h-trustd: no TPM: flags only");
}

/// What a request page's state says (abi::AttestPage::state): which
/// quotes reports are bound to, or none at all (and none to come: not
/// while a secondary's key or the TD's quote is on its way).
fn page_state(state: &Option<State>, starting: bool, tdx: &Option<Tdx>) -> u32 {
    let tpm = state.as_ref().is_some_and(|s| s.has_tpm);
    let td = tdx.as_ref().is_some_and(|t| t.ready());
    let coming = starting || tdx.as_ref().is_some_and(|t| t.starting());
    let mut v = 0;
    if tpm {
        v |= abi::ATTEST_HAS_TPM;
    }
    if td {
        v |= abi::ATTEST_HAS_TDX;
    }
    if !tpm && !td && !coming {
        v |= abi::ATTEST_NO_REPORTS;
    }
    v
}

/// Guest `id`'s record, if it runs.
fn record(id: usize) -> Option<GuestRecord> {
    // Root maps the registry here for good.
    unsafe { trust::read_record(trust::REGISTRY_VA, id) }
}

impl State {
    /// The COSE_Sign1 report on guest `id`, whose record is `r`, with the
    /// guest's `data`, in `out`: its length.
    /// EAGAIN if the guest's flags could not be read just now: a report
    /// never says clean, or sealed, of flags it did not see.
    fn report(&self, id: usize, r: &GuestRecord, data: &[u8; abi::ATTEST_DATA_SIZE], out: &mut [u8]) -> Result<usize, Errno> {
        let mut payload = [0u8; REPORT_MAX];
        let mut c = Enc::new(&mut payload);
        let flags = flags::read(id, r.instance).ok_or(EAGAIN)?.bytes();
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
        // REPORT_MAX bounds every report.
        let payload = c.done().map_err(|Overflow| EIO)?;
        // Protected header {1: -7}: alg ES256.
        let protected = [0xa1, 0x01, 0x26];
        let mut sig_structure = [0u8; REPORT_MAX];
        let mut s = Enc::new(&mut sig_structure);
        s.array(4).text("Signature1").bytes(&protected).bytes(&[]).bytes(payload);
        let sig: Signature = self.key.sign(s.done().map_err(|Overflow| EIO)?);
        let mut o = Enc::new(out);
        o.tag(18).array(4).bytes(&protected).map(0).bytes(payload).bytes(&sig.to_bytes());
        Ok(o.done().map_err(|Overflow| EIO)?.len())
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
        let info = TpmInfo {
            ek_cert: self.ek_cert.as_ref().map(|c| c.get()),
            ek_public: self.ek_public.as_ref().map(|p| p.get()),
            vendor: self.vendor,
        };
        encode_evidence(out, self.ak_public.get(), point, &q.pcrs, q.quote.get(), info, q.sig.get(), Some((k, &self.chain[..q.at])))
            .map_err(|Overflow| EIO)
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

/// The primary: answer what other partitions' trustds asked.  A
/// partition's ActivateCredential requests have the allowance one guest's
/// have (`limits`): beyond it, -EAGAIN without using the TPM, so that no
/// partition keeps the TPM from this one's guests.
fn serve(state: &mut Option<State>, relay: &mut Relay, served: &mut [Served; trust::MAX_PARTITIONS],
    limits: &mut [trust::ActivateLimit; trust::MAX_PARTITIONS], hz: u64) {
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
                    // On the curve, before PCR 15 binds it for good.
                    Ok(p) if key::partition_key_ok(p) => l.quote_key(from, p, out),
                    _ => Err(EINVAL),
                },
                (Some(l), trust::RELAY_ACTIVATE) => {
                    let blob_len = m.data.get(..4).map_or(usize::MAX, |b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
                    match m.data.get(4..).filter(|d| blob_len <= d.len()) {
                        None => Err(EINVAL),
                        Some(_) if !limits[from as usize].allow(host::ticks::now(), hz) => Err(EAGAIN),
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
    /// The activation rate limit: up to trust::ACTIVATE_BURST at once,
    /// then one every ACTIVATE_INTERVAL_MS.  Beyond that, -EAGAIN without
    /// using the TPM.
    activate: trust::ActivateLimit,
    /// TDX quotes (abi::ATTEST_TDX_QUOTE), limited as ActivateCredential:
    /// each takes the VMM's quoting service.
    quote: trust::ActivateLimit,
}

impl Answered {
    /// May the guest use the TPM for an ActivateCredential now?  If so, it
    /// is counted.
    fn may_activate(&mut self, hz: u64) -> bool {
        self.activate.allow(host::ticks::now(), hz)
    }
}

/// Request page `p` (trust::page_va).
fn page(p: usize) -> *mut abi::AttestPage {
    trust::page_va(p) as *mut abi::AttestPage
}

/// The request page of guest `id`, whose record is `r`.
fn page_of(id: usize, r: &GuestRecord) -> usize {
    trust::page_of(id, r.flags & trust::RECORD_PAGE_B != 0)
}

/// The result of guest `id`'s request `seq` in its page (the evidence, or
/// what we built in `out`), or -errno.  `starting`: a secondary waits for
/// its key's quote.  `event_log`, `cc_event_log`: the host's TPM and CC
/// event logs, empty if none.  `tdx`: the TD's attestation; `others_waiting`:
/// other guests' requests wait (TDX quotes take turns).
#[allow(clippy::too_many_arguments)]
fn execute<'a>(
    state: &'a mut Option<State>,
    tdx: &'a mut Option<Tdx>,
    starting: bool,
    event_log: &'static [u8],
    cc_event_log: &'static [u8],
    id: usize,
    seq: u32,
    r: &GuestRecord,
    last: &mut Answered,
    hz: u64,
    relay: Option<&mut Relay>,
    others_waiting: bool,
    out: &'a mut [u8; ANSWER_MAX],
) -> Result<&'a [u8], Errno> {
    let p = page(page_of(id, r));
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
    // The firmware's log, as root mapped it: with a TPM or without (flags
    // only), every guest alike.  None is ENOENT, not ENODEV, which would
    // tell the guest there are no reports.
    if op == abi::ATTEST_EVENT_LOG {
        if in_len != 0 { return Err(EINVAL); }
        return if event_log.is_empty() { Err(ENOENT) } else { Ok(event_log) };
    }
    // The TD's log, as the TPM's.
    if op == abi::ATTEST_TDX_EVENT_LOG {
        if in_len != 0 { return Err(EINVAL); }
        return if cc_event_log.is_empty() { Err(ENOENT) } else { Ok(cc_event_log) };
    }
    if !matches!(op, abi::ATTEST_REPORT | abi::ATTEST_EVIDENCE | abi::ATTEST_ACTIVATE | abi::ATTEST_TDX_EVIDENCE | abi::ATTEST_TDX_QUOTE) {
        return Err(ENOSYS);
    }
    let Some(s) = state else { return Err(if starting { DEFER } else { ENODEV }) };
    // TDX's requests, and the TPM's on a TD without one.
    let td_starting = tdx.as_ref().is_some_and(|t| t.starting());
    match op {
        abi::ATTEST_TDX_EVIDENCE => {
            return match tdx.as_ref() {
                Some(t) if t.ready() => Ok(t.evidence().unwrap_or_default()),
                _ if td_starting => Err(DEFER),
                _ => Err(ENODEV),
            };
        }
        abi::ATTEST_TDX_QUOTE => {
            if data.len() != abi::ATTEST_DATA_SIZE { return Err(EINVAL); }
            let Some(t) = tdx.as_mut() else { return Err(ENODEV) };
            let d: [u8; abi::ATTEST_DATA_SIZE] = data.try_into().unwrap();
            let s = &*s;
            return t.request(id, r.instance, seq, &d, tdxrt::offset(p), others_waiting,
                || last.quote.allow(host::ticks::now(), hz), |buf| s.report(id, r, &d, buf));
        }
        abi::ATTEST_REPORT if !s.has_tpm && !tdx.as_ref().is_some_and(|t| t.ready()) => {
            return Err(if td_starting { DEFER } else { ENODEV });
        }
        abi::ATTEST_EVIDENCE | abi::ATTEST_ACTIVATE if !s.has_tpm => return Err(ENODEV),
        _ => {}
    }
    match op {
        abi::ATTEST_REPORT => {
            let mut d = [0u8; abi::ATTEST_DATA_SIZE];
            let n = data.len().min(d.len());
            d[..n].copy_from_slice(&data[..n]);
            let n = s.report(id, r, &d, out)?;
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

/// Answer guest `id`'s request `seq`, if the guest is still `instance`:
/// the result's piece from the request's offset, then done = seq; root
/// raises the device's event.  Whether it was answered.
fn answer(id: usize, instance: u64, seq: u32, result: Result<&[u8], Errno>) -> bool {
    let Some(r) = record(id).filter(|r| r.instance == instance) else { return false };
    let at = page_of(id, &r);
    // Say which page we write before we look a last time whether the guest
    // runs: root, which unregisters a guest before it gives its id to
    // another, then either sees this and gives the new guest the other
    // page, or we see the guest gone (trust::Status).  Otherwise a stale
    // answer could land in the next guest's page.
    let status = unsafe { &*(trust::STATUS_VA as *const trust::Status) };
    status.answering.store(at as u64 + 1, Ordering::SeqCst);
    fence(Ordering::SeqCst);
    let running = record(id).is_some_and(|now| now.instance == instance && page_of(id, &now) == at);
    if running {
        write_answer(page(at), seq, result);
    }
    status.answering.store(0, Ordering::Release);
    if running {
        use l4h_rt::host::root::call::Client;
        let _ = l4h_rt::ipc::Endpoint::of(&l4h_rt::host::wiring::TRUSTD_ROOT, l4h_rt::host::wiring::p::Trustd, 0).attest_done(id);
    }
    running
}

fn write_answer(p: *mut abi::AttestPage, seq: u32, result: Result<&[u8], Errno>) {
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
}

/// A log root mapped read-only at `va` for good, `size` bytes of it (at
/// most `max`), which nothing writes; empty if none.
fn mapped_log(va: usize, size: u64, max: usize) -> &'static [u8] {
    if size > 0 && size <= max as u64 {
        unsafe { core::slice::from_raw_parts(va as *const u8, size as usize) }
    } else {
        &[]
    }
}

fn main(info: &'static Info) -> ! {
    // The same image is the flags server, in spaces of its own.
    if info.header().kind == host::KIND_FLAGS {
        flags::serve();
    }
    let cfg: &TrustdConfig = unsafe { info.config() };
    let hz = info.header().tsc_hz;
    let t0 = host::ticks::now();
    // A known TD (TrustdConfig::in_td) completely ignores any TPM and relay
    // paths and never falls back to a non-TD TPM or multikernel relay.
    let in_td = cfg.in_td();
    // Root maps the event log read-only here for good, cfg.event_log_size
    // bytes of it (trust::EVENT_LOG_VA), and nothing writes it.
    // Defense in depth: in a TD, never serve a TPM event log even if present.
    let event_log = if in_td { &[] } else { mapped_log(trust::EVENT_LOG_VA, cfg.event_log_size, trust::EVENT_LOG_MAX) };
    let cc_event_log = mapped_log(trust::CC_EVENT_LOG_VA, cfg.cc_event_log_size, trust::CC_EVENT_LOG_MAX);
    let warn_flags = trust::EVENT_LOG_TRUNCATED | trust::EVENT_LOG_TCG_1_2;
    if !in_td && cfg.event_log_flags & warn_flags != 0 {
        l4h_rt::log!("l4h-trustd: warning: TPM event log has anomalous flags {:#x} (truncated/TCG 1.2)", cfg.event_log_flags);
    }
    if in_td && cfg.cc_event_log_flags & warn_flags != 0 {
        l4h_rt::log!("l4h-trustd: warning: CC event log has anomalous flags {:#x} (truncated/TCG 1.2)", cfg.cc_event_log_flags);
    }
    let mut relay = if in_td { None } else { Relay::new(cfg.partition, cfg.partitions) };
    let partition = relay.as_ref().map(|r| r.index);
    // A secondary's key, until the primary quoted it.
    let mut starting = None;
    let mut tdx = None;
    let mut state = if in_td {
        let capable = cfg.tdx_capable() && cfg.partitions == 1 && cfg.partition == 0;
        if !capable {
            l4h_rt::log!("l4h-trustd: TD without usable TDX attestation: flags only");
        }
        // Strict TD startup order (never touching any TPM):
        // 1. CPU entropy -> key.
        // 2. Synchronous TDREPORT + check_first_report + RTMR.EXTEND.
        // 3. Start the GetQuote job with its 120 s timeout and poll once.
        match tdx::td_startup(
            capable,
            || {
                let key = cpu_key();
                if key.is_none() {
                    l4h_rt::log!("l4h-trustd: no key from RDSEED or RDRAND: no TDX attestation");
                }
                key
            },
            |key| match Tdx::bind(&point(key)) {
                Ok(bound) => Ok(bound),
                Err(why) => {
                    l4h_rt::log!("l4h-trustd: no TDX attestation: {}", why);
                    Err(why)
                }
            },
            host::ticks::now,
            |bound, now| {
                let mut t = bound.start_quote(hz, now);
                match t.poll() {
                    Some(tdxrt::Event::Failed) => None,
                    Some(tdxrt::Event::Ready) => {
                        info!("l4h-trustd: TDX attestation ready");
                        Some(t)
                    }
                    _ => Some(t),
                }
            },
        ) {
            None => None,
            Some((key, quote)) => {
                tdx = quote;
                Some(State::keyed(key, None))
            }
        }
    } else {
        match (cfg.iface, relay.as_mut()) {
            (trust::TPM_NONE, _) | (trust::TPM_REMOTE, None) => None,
            (trust::TPM_REMOTE, Some(r)) => {
                match start_remote(r, hz) {
                    Ok(k) => starting = Some(k),
                    Err(why) => l4h_rt::log!("l4h-trustd: no attestation: {}", why),
                }
                None
            }
            _ => match tpm_key(cfg, hz) {
                Ok((tpm, key)) => match init(tpm, key, t0, hz, partition) {
                    Ok(s) => Some(s),
                    Err((what, e)) => {
                        l4h_rt::log!("l4h-trustd: TPM unusable, no attestation: {}: {}", what, e);
                        None
                    }
                },
                Err((what, e)) => {
                    l4h_rt::log!("l4h-trustd: TPM unusable, no attestation: {}: {}", what, e);
                    None
                }
            },
        }
    };
    // A key bound to nothing (a TD whose GetQuote failed, without a TPM).
    if state.as_ref().is_some_and(|s| !s.has_tpm) && tdx.is_none() {
        state = None;
    }
    if state.is_none() && starting.is_none() {
        no_reports();
    } else {
        tdxrt::set_states(page_state(&state, starting.is_some(), &tdx));
    }
    // Guests kick while we set up the TPM too: their bits wait in the
    // notification.
    let kick = cap::<cap_type::Notification>(trust::SLOT_KICK);
    let mut answered = [Answered::default(); trust::MAX_RECORDS];
    let mut served = [Served::default(); trust::MAX_PARTITIONS];
    let mut relayed = [trust::ActivateLimit::default(); trust::MAX_PARTITIONS];
    let mut out = [0u8; ANSWER_MAX];
    // Guests whose requests wait for the relay, or TDX.
    let mut deferred = 0u64;
    let status = unsafe { &*(trust::STATUS_VA as *const trust::Status) };
    // The guest last looked at (round robin).
    let mut last_guest = trust::MAX_RECORDS - 1;
    loop {
        // Root's timer, while we wait for what has no kick of our own.
        status.wake.store((deferred != 0 || tdx.as_ref().is_some_and(|t| t.busy())) as u64, Ordering::Relaxed);
        let (_, kicked) = kick.wait();
        let mut kicked = kicked | core::mem::take(&mut deferred);
        // The TD's quote: the key's, or a guest's.
        match tdx.as_mut().and_then(|t| t.poll()) {
            Some(tdxrt::Event::Ready) => {
                info!("l4h-trustd: TDX attestation ready");
                tdxrt::set_states(page_state(&state, starting.is_some(), &tdx));
            }
            Some(tdxrt::Event::Failed) => {
                tdx = None;
                if state.as_ref().is_some_and(|s| !s.has_tpm) {
                    state = None;
                    no_reports();
                } else {
                    tdxrt::set_states(page_state(&state, starting.is_some(), &tdx));
                }
            }
            Some(tdxrt::Event::Quoted { id, instance, seq, result }) => {
                let t = tdx.as_mut().expect("a quote's TDX");
                if answered[id].instance == instance && answer(id, instance, seq, result.map(|n| t.answer(n))) {
                    answered[id].seq = seq;
                } else {
                    // Gone, or replaced: its answer is kept for no one.
                    t.release_held(id, instance);
                }
            }
            None => {}
        }
        // RELAY_BADGE is also guest 63's kick: both are looked at.
        match relay.as_mut() {
            Some(r) if r.primary() => {
                if kicked & trust::RELAY_BADGE != 0 {
                    serve(&mut state, r, &mut served, &mut relayed, hz);
                }
            }
            Some(r) => match r.poll() {
                Some((Wait::Key, got)) => {
                    let key = starting.take().expect("a key waits for its quote");
                    match ready(key, partition.unwrap_or(0), got, t0, hz) {
                        Ok(s) => {
                            state = Some(s);
                            tdxrt::set_states(page_state(&state, false, &tdx));
                        }
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
                    if answered[id].instance == instance && answer(id, instance, seq, result) {
                        answered[id].seq = seq;
                    }
                }
                None => {}
            },
            None => {}
        }
        while kicked != 0 {
            // Round robin, from the guest after the last one served: no
            // guest id goes first for good (a low one could otherwise keep
            // the TDX quote slot from the others).
            let guest = host::badges::trustd_kick::GUEST;
            let Some(id) = (1..=trust::MAX_RECORDS).map(|k| (last_guest + k) % trust::MAX_RECORDS)
                .find(|&i| kicked & guest.nth(i) != 0) else { break };
            last_guest = id;
            kicked &= !guest.nth(id);
            let others_waiting = (kicked | deferred) & !guest.nth(id) != 0;
            let Some(r) = record(id) else { continue };
            let p = page(page_of(id, &r));
            // A new guest's page has root's state: ours, before we answer.
            unsafe { addr_of_mut!((*p).state).write_volatile(page_state(&state, starting.is_some(), &tdx)) };
            let seq = unsafe { addr_of!((*p).seq).read_volatile() };
            fence(Ordering::Acquire);
            let last = &mut answered[id];
            if last.instance != r.instance {
                *last = Answered { instance: r.instance, ..Default::default() };
            }
            if seq == last.seq {
                continue;
            }
            let result = execute(&mut state, &mut tdx, starting.is_some(), event_log, cc_event_log, id, seq, &r, last, hz,
                relay.as_mut(), others_waiting, &mut out);
            match result {
                Err(DEFER) => {
                    deferred |= host::badges::trustd_kick::GUEST.nth(id);
                    continue;
                }
                Err(PENDING) => continue,
                _ => {}
            }
            // Not if destroyed meanwhile (or replaced by another guest):
            // nobody waits for this answer.
            if answer(id, r.instance, seq, result) {
                answered[id].seq = seq;
            }
        }
    }
}

l4h_rt::component!(main, heap_size = aml::HEAP);
