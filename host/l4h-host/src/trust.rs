//! l4h-trustd: the attestation service (DESIGN.md §9.2).  Each guest has
//! an attestation device (L4H_DEV_ATTEST): a request page, which trustd
//! maps at page_va(guest), and the kick notification, badged with
//! kick_badge(guest). trustd answers in the page, then updates vmmgr's
//! attestation page and signals vmmgr directly to raise the device's event.
//! l4h-root tells trustd about guests through the registry page, which it
//! writes and trustd only reads. Root's kexec state is a separate private
//! page: init publishes the key extension there, and measurement uses a
//! sequence-numbered request with a bounded wait, never a synchronous call.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
use l4h_abi as abi;

/// The TPM interface.
pub const TPM_NONE: u32 = 0;
pub const TPM_TIS: u32 = 1;
pub const TPM_CRB: u32 = 2;

/// How a CRB command starts (the ACPI TPM2 start method).
/// The start register (7).
pub const START_CRB: u32 = 1;
/// The start register, then the TPM device's _DSM (2 and 8: AMD fTPM).
/// trustd runs the firmware's AML for it (aml.rs).
pub const START_ACPI: u32 = 2;
/// The Pluton doorbells after each request (13).
pub const START_PLUTON: u32 = 3;

/// A physical range trustd has mapped, at TPM_VA + i * RANGE_STRIDE for
/// range i.  size 0: unused.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Range {
    pub paddr: u64,
    pub size: u64,
}

pub const MAX_RANGES: usize = 6;
pub const RANGE_STRIDE: usize = 1 << 20;

/// trustd's configuration (info page).  The registers and buffers are
/// given by their VAs in trustd, in the mapped ranges; 0 if absent.
#[repr(C)]
pub struct TrustdConfig {
    pub iface: u32,
    pub start: u32,
    pub ranges: [Range; MAX_RANGES],
    /// FIFO: locality 0's registers.  CRB: its locality registers, which
    /// the ACPI start and Pluton interfaces lack.
    pub loc_va: u64,
    /// CRB: the control area (CTRL_REQ, ...).
    pub ctrl_va: u64,
    pub cmd_va: u64,
    pub cmd_size: u64,
    pub rsp_va: u64,
    pub rsp_size: u64,
    /// Pluton: the start and reply doorbells.
    pub start_va: u64,
    pub reply_va: u64,
    /// START_ACPI: the firmware's ACPI tables at AML_VA, back to back with
    /// their headers: the FADT, the DSDT, then the SSDTs.
    pub aml_size: u64,
    /// The previous kexec event log, read-only in trustd (0 if absent).
    pub kexec_log_va: u64,
    pub kexec_log_size: u64,
}

pub const TPM_VA: usize = crate::MMIO_VA;
/// The registry page, read-only in trustd.
pub const REGISTRY_VA: usize = crate::SHARED_VA;
pub const AML_VA: usize = crate::SHARED_VA + 0x100_0000;
/// The request pages, one per guest id; trustd owns them, so that they
/// stay mapped while it answers a guest that is being destroyed.
pub const PAGES_VA: usize = crate::SHARED_VA + 0x1000;
pub const fn page_va(guest: usize) -> usize {
    PAGES_VA + guest * 4096
}
/// The kick notification: guest g signals it with kick_badge(g).  The
/// bound notification (SLOT_NTFN) is trustd's timer.
pub const SLOT_KICK: u64 = crate::SLOT_FIRST_FREE;
pub const SLOT_FLAGS_EP: u64 = SLOT_KICK + 1;
pub const SLOT_FLAGS_CALL: u64 = SLOT_KICK + 2;
pub const SLOT_FLAGS_TCB: u64 = SLOT_KICK + 3;
pub const SLOT_FLAGS_REPLY: u64 = SLOT_KICK + 4;
pub const SLOT_ATTEST_EVENTS: u64 = SLOT_KICK + 5;
pub const SLOT_VMMGR_NTFN: u64 = SLOT_KICK + 6;
pub const SLOT_MEASURE_DONE: u64 = SLOT_KICK + 7;
pub const FLAGS_IPCBUF_VA: usize = crate::KEEPER_IPCBUF_VA;
pub const FLAGS_STACK_TOP: usize = crate::KEEPER_STACK_TOP;
pub const FLAGS_STACK_SIZE: usize = crate::KEEPER_STACK_SIZE;
pub const FLAGS_VA: usize = crate::SHARED_VA + 0x8_0000;
/// Only the flags thread uses this writable alias. All readers use FLAGS_VA.
pub const FLAGS_WRITE_VA: usize = FLAGS_VA + FLAGS_SIZE;
pub const FLAGS_SIZE: usize = 8192;
pub const FLAGS_ROOT: u64 = 1;
pub const FLAGS_TRUSTD: u64 = 2;
pub const FLAGS_READY: u64 = 0;
pub const FLAGS_ACT: u64 = 1;
pub const FLAGS_SEAL: u64 = 2;
pub const fn kick_badge(guest: usize) -> u64 {
    1 << guest
}
/// Most ACPI table bytes root gives trustd.
pub const AML_MAX: usize = 4 << 20;
/// The kexec event log passed to the next host as `kexec-log`.
pub const KEXEC_LOG_MAGIC: [u8; 8] = *b"L4HKXLOG";
pub const KEXEC_LOG_VERSION: u32 = 1;
pub const KEXEC_LOG_HEADER: usize = 16;
pub const KEXEC_LOG_EVENT: usize = 168;
/// TrustdConfig.kexec_log_size sentinel: an oversized/invalid history. The
/// evidence includes an empty klog with count 1, so verification fails closed
/// instead of disabling trustd or accepting a false cold boot.
pub const KEXEC_LOG_INVALID: u64 = u64::MAX;

/// Number of events in a log, checking its complete encoded size. An empty
/// slice is the cold-boot history; a present log has at least one event.
pub fn kexec_log_count(bytes: &[u8]) -> Result<u32, &'static str> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() < KEXEC_LOG_HEADER || bytes[..8] != KEXEC_LOG_MAGIC ||
        u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != KEXEC_LOG_VERSION
    {
        return Err("bad kexec log header");
    }
    let count = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    if count == 0 || bytes.len() != KEXEC_LOG_HEADER + count as usize * KEXEC_LOG_EVENT {
        return Err("kexec log event count does not match its size");
    }
    Ok(count)
}

/// The kexec event log, up to 16 KiB.
pub const KEXEC_LOG_MAX: usize = 16 << 10;
pub const KEXEC_LOG_VA: usize = AML_VA + AML_MAX;
/// Root and trustd's private state, never mapped into a guest. The flags
/// thread is not involved in these requests.
pub const KEXEC_STATE_VA: usize = KEXEC_LOG_VA + KEXEC_LOG_MAX;
/// vmmgr's attestation page, writable by trustd for guest completions.
pub const ATTEST_EVENTS_VA: usize = KEXEC_STATE_VA + 4096;

pub const KEXEC_STARTING: u32 = 0;
pub const KEXEC_READY: u32 = 1;
pub const KEXEC_UNAVAILABLE: u32 = 2;
pub use crate::handoff::MEASURE_DONE_BADGE;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KexecState {
    /// KEXEC_STARTING, KEXEC_READY or KEXEC_UNAVAILABLE, written once after init.
    pub status: u32,
    /// This host's public PCR 15 extension value, valid when status is READY.
    pub key_extension: [u8; 32],
    /// The event digest root asks trustd to extend into PCR 14, answered
    /// with zero or a positive errno.
    pub measure: crate::handoff::Mailbox<[u8; 32]>,
}
const _: () = assert!(core::mem::size_of::<KexecState>() <= 4096);

/// The record of guest `id` at REGISTRY_VA + id * size_of::<GuestRecord>().
/// root fills it before the guest starts and writes `instance` last
/// (non-zero: a running guest); it zeroes `instance` first when the guest
/// is destroyed.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GuestRecord {
    /// Unique per guest created since boot, from 1.
    pub instance: u64,
    pub ram: u64,
    pub vcpus: u32,
    pub flags: u32,
    /// The launch digest (DESIGN.md §9.2): SHA-256 of the kernel image,
    /// initramfs and command line the guest booted with.
    pub launch: [u8; 32],
    pub reserved: u64,
}

pub const RECORD_DOM0: u32 = 1;
pub const MAX_RECORDS: usize = 64;
const _: () = assert!(core::mem::size_of::<GuestRecord>() == 64);
const _: () = assert!(MAX_RECORDS * core::mem::size_of::<GuestRecord>() <= 4096);
const _: () = assert!(MAX_RECORDS <= 64 && page_va(MAX_RECORDS) <= AML_VA);

/// One instance's consistent flags. A different instance reads as empty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub instance: u64,
    pub taint: [u64; 4],
    pub seal: [u64; 4],
}

impl Flags {
    pub fn for_instance(self, instance: u64) -> Self {
        if self.instance == instance { self } else { Self { instance, ..Self::default() } }
    }

    pub fn bytes(&self) -> abi::AttestFlags {
        let bytes = |words: &[u64; 4]| core::array::from_fn(|i| (words[i / 8] >> (8 * (i % 8))) as u8);
        abi::AttestFlags { taint: bytes(&self.taint), seal: bytes(&self.seal) }
    }

    /// Actor fast path: check the seal even when already tainted. If
    /// false, ACT must succeed before any of the operation's effects.
    pub fn acted(&self, bits: u64) -> Result<bool, i64> {
        if self.seal[0] & bits != 0 { Err(1) } else { Ok(self.taint[0] & bits == bits) }
    }

    /// Shared actor steps: check every seal, and record only the first
    /// effect. `record` must synchronously ACT through the flags service.
    pub fn act(&self, bits: u64, effect: bool, record: impl FnOnce() -> Result<(), i64>) -> Result<(), i64> {
        if self.acted(bits)? || !effect { Ok(()) } else { record() }
    }
}

/// Two cache lines per guest, two frames in all. Atomics also make
/// concurrent reads defined in Rust; the seqlock covers the whole entry.
#[repr(C, align(128))]
pub struct FlagsEntry {
    seq: AtomicU32,
    reserved: u32,
    instance: AtomicU64,
    taint: [AtomicU64; 4],
    seal: [AtomicU64; 4],
}

impl FlagsEntry {
    pub const fn new() -> Self {
        Self { seq: AtomicU32::new(0), reserved: 0, instance: AtomicU64::new(0),
            taint: [const { AtomicU64::new(0) }; 4], seal: [const { AtomicU64::new(0) }; 4] }
    }

    pub fn read(&self) -> Flags {
        loop {
            let seq = self.seq.load(Ordering::Acquire);
            if seq & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let flags = Flags {
                instance: self.instance.load(Ordering::Relaxed),
                taint: core::array::from_fn(|i| self.taint[i].load(Ordering::Relaxed)),
                seal: core::array::from_fn(|i| self.seal[i].load(Ordering::Relaxed)),
            };
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == seq { return flags; }
        }
    }

    /// Serialized by the flags endpoint. Positive errno on failure;
    /// invalid requests and sealed ACTs change nothing, including instance.
    ///
    /// # Safety
    /// There must be exactly one writer of this entry.
    pub unsafe fn update(&self, badge: u64, op: u64, instance: u64, bits: [u64; 4], flags: u64) -> Result<Flags, i64> {
        let sealable = bits[0] & !abi::FLAGS_HOST_DEFINED == 0 && bits[1] == 0;
        let allowed = match (badge, op) {
            (FLAGS_ROOT, FLAGS_ACT) => bits[0] & !abi::FLAGS_HOST_DEFINED == 0 && bits[1..] == [0; 3] && flags == 0,
            (FLAGS_TRUSTD, FLAGS_ACT) => bits[0] == 0 && (flags & abi::ACT_SEAL as u64 == 0 || sealable),
            (FLAGS_TRUSTD, FLAGS_SEAL) => sealable && flags == 0,
            _ => false,
        };
        if !allowed || flags & !(abi::ACT_SEAL as u64) != 0 || instance == 0 { return Err(22); }
        let old = self.read();
        if instance < old.instance { return Err(3); }
        let mut next = old.for_instance(instance);
        if op == FLAGS_ACT && (0..4).any(|i| next.seal[i] & bits[i] != 0) { return Err(1); }
        for i in 0..4 {
            if op == FLAGS_ACT { next.taint[i] |= bits[i]; }
            if op == FLAGS_SEAL || flags & abi::ACT_SEAL as u64 != 0 { next.seal[i] |= bits[i]; }
        }
        self.seq.fetch_add(1, Ordering::Relaxed);
        fence(Ordering::Release);
        self.instance.store(instance, Ordering::Relaxed);
        for i in 0..4 {
            self.taint[i].store(next.taint[i], Ordering::Relaxed);
            self.seal[i].store(next.seal[i], Ordering::Relaxed);
        }
        self.seq.fetch_add(1, Ordering::Release);
        Ok(next)
    }
}
const _: () = assert!(core::mem::size_of::<FlagsEntry>() == 128);
const _: () = assert!(MAX_RECORDS * core::mem::size_of::<FlagsEntry>() == FLAGS_SIZE);

/// trustd -> root (ROOT_CALL_HW): an access the firmware's AML makes
/// outside trustd's own ranges.  MR0 = HW_*, MR1 = physical address, I/O
/// port or PCI function (bus << 8 | device << 3 | function), MR2 = PCI
/// config offset, MR3 = width in bytes, MR4 = the value to write.  Returns
/// the value read; root refuses RAM, memory and ports in use, and the
/// config space of the PCI functions the host drives (reads give all ones,
/// writes are dropped).
pub const HW_MEM_READ: u64 = 0;
pub const HW_MEM_WRITE: u64 = 1;
pub const HW_IO_READ: u64 = 2;
pub const HW_IO_WRITE: u64 = 3;
pub const HW_PCI_READ: u64 = 4;
pub const HW_PCI_WRITE: u64 = 5;
