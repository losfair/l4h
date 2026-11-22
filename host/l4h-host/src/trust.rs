//! l4h-trustd: the attestation service (DESIGN.md §10.2).  Each guest has
//! an attestation device (L4H_DEV_ATTEST): a request page, which trustd
//! maps at page_va(page_of(guest, ...)), and the kick notification, badged
//! with badges::trustd_kick::GUEST bit guest.  trustd answers in the page
//! and has root raise the device's event (root::call::attest_done).
//! l4h-root tells trustd about guests through the registry page, which it
//! writes and trustd only reads.  The flags (`call`) are served by the
//! flags server, the trustd image in spaces of its own (host::KIND_FLAGS),
//! which alone maps them writable; trustd's main thread, whose TPM
//! commands can take seconds and which parses guests' pages and runs the
//! firmware's AML, only calls it.  Root waits only for the flags server,
//! in its start-up handshake.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
use l4h_abi as abi;

/// The TPM interface.
pub const TPM_NONE: u32 = 0;
pub const TPM_TIS: u32 = 1;
pub const TPM_CRB: u32 = 2;
/// A multikernel secondary: the primary's trustd has the TPM, and quotes
/// this trustd's key and runs its ActivateCredential through the relay.
pub const TPM_REMOTE: u32 = 3;

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
    /// Multikernel: this partition and how many there are; 1 partition
    /// when root is the only kernel (no relay).
    pub partition: u32,
    pub partitions: u32,
    /// The UEFI TPM event log (BootInfo TPM_EVENT_LOG), mapped read-only
    /// at EVENT_LOG_VA: its exact length, 0 if none, and its flags
    /// (EVENT_LOG_TRUNCATED, EVENT_LOG_TCG_1_2).
    pub event_log_size: u64,
    pub event_log_flags: u64,
}

pub const TPM_VA: usize = crate::MMIO_VA;
/// The registry page, read-only in trustd.
pub const REGISTRY_VA: usize = crate::SHARED_VA;
pub const AML_VA: usize = crate::SHARED_VA + 0x100_0000;
/// The request pages, two per guest id: trustd owns them, so that they
/// stay mapped while it answers a guest that is being destroyed, and a
/// new guest with the id gets the other one while trustd may still be
/// writing an answer for the old one (Status).  The registry says which
/// a running guest has (RECORD_PAGE_B).
pub const PAGES_VA: usize = crate::SHARED_VA + 0x1000;
pub const PAGES: usize = 2 * MAX_RECORDS;
pub const fn page_va(page: usize) -> usize {
    PAGES_VA + page * 4096
}
/// The page of guest `guest`: its first, or its second (`b`).
pub const fn page_of(guest: usize, b: bool) -> usize {
    guest + if b { MAX_RECORDS } else { 0 }
}
/// The kick notification: guest g signals it with badges::trustd_kick::GUEST bit g.  The
/// bound notification (SLOT_NTFN) is trustd's timer.
pub const SLOT_KICK: u64 = crate::SLOT_FIRST_FREE;
/// The main thread's capability to the flags server (wiring::TRUSTD_FLAGS).
pub const SLOT_FLAGS_CALL: u64 = SLOT_KICK + 1;
/// The flags: read-only in trustd, root and vmmgr; the flags server's
/// mapping, at the same address in its own space, is the only writable
/// one.  The flags server also maps the registry, read-only.
pub const FLAGS_VA: usize = crate::SHARED_VA + 0x9_0000;
pub const FLAGS_SIZE: usize = 8192;
/// trustd's status page (Status): it writes it, root reads it.
pub const STATUS_VA: usize = FLAGS_VA + FLAGS_SIZE;

/// What trustd tells root (STATUS_VA).
#[repr(C)]
pub struct Status {
    /// 1 + the request page (page_va) trustd may be writing an answer
    /// into, or 0.  trustd sets it before it looks a last time whether the
    /// guest it answers still runs, and clears it once it has answered;
    /// root, which unregisters a guest before it gives its id to another,
    /// gives the new guest the other page while this names the old one's.
    pub answering: AtomicU64,
}

/// The relay between partitions' trustds (multikernel only, DESIGN.md
/// §10.2): the primary's trustd, which has the TPM, quotes each other
/// partition's key and runs their ActivateCredential.  Root carries the
/// messages over the control channels (MSG_TPM_REQUEST, MSG_TPM_REPLY),
/// which may lose them: requests have ids, the requester retries, and the
/// primary answers a repeated id again without using the TPM again.
///
/// The relay pages are slots of RELAY_SLOT_SIZE: a `RelaySlot` header,
/// then a message.  trustd writes a message to the outbox, slot 0 at
/// RELAY_VA, and calls root (root::call::relay), which copies it to the
/// channel.  Root writes what comes from partition k into inbox slot k
/// (relay_slot_va(k), seqlocked) and signals the kick with RELAY_BADGE.
/// While a secondary waits for an answer, it sets the outbox's `wake`, and
/// root signals the kick on its timer too, so that trustd can send the
/// request again or give up.
pub const RELAY_VA: usize = crate::SHARED_VA + 0xa_0000;
pub const RELAY_SLOT_SIZE: usize = 12 * 1024;
pub const RELAY_PAGES: usize = (1 + MAX_PARTITIONS) * RELAY_SLOT_SIZE / 4096;
/// Partition k's inbox slot (the outbox is at RELAY_VA).
pub const fn relay_slot_va(partition: usize) -> usize {
    RELAY_VA + (1 + partition) * RELAY_SLOT_SIZE
}
/// The partitions a relay serves (l4h_partition::MAX_PARTITIONS).
pub const MAX_PARTITIONS: usize = 8;
/// The largest message: a reply with the evidence (EVIDENCE_MAX in
/// trustd) and its header; it fits a channel message.
pub const RELAY_MSG_MAX: usize = 9216;
/// Also guest 63's kick bit: kicks are only hints (trustd answers a guest
/// whose page has a new seq), so trustd looks at both.
pub const RELAY_BADGE: u64 = crate::badges::trustd_kick::GUEST.nth(MAX_RECORDS - 1);
const _: () = assert!(page_va(PAGES) <= FLAGS_VA && STATUS_VA + 4096 <= RELAY_VA && RELAY_VA + RELAY_PAGES * 4096 <= AML_VA);
const _: () = assert!(RELAY_MSG_MAX + core::mem::size_of::<RelaySlot>() <= RELAY_SLOT_SIZE);

/// A relay slot's header; the message follows.  In an inbox slot root
/// makes `seq` odd while it writes the slot.  In the outbox, trustd sets
/// `wake` while it waits for an answer.
#[repr(C)]
pub struct RelaySlot {
    pub seq: AtomicU32,
    pub len: AtomicU32,
    pub wake: AtomicU32,
    pub _pad: u32,
}
pub const RELAY_SLOT_HEADER: usize = core::mem::size_of::<RelaySlot>();

/// A message: RelayHeader, then `len` bytes.  A request's `op` is
/// RELAY_KEY or RELAY_ACTIVATE; a reply has the request's id and `op` and
/// its status (0 or -errno) in `status`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RelayHeader {
    pub id: u64,
    pub op: u32,
    pub status: i32,
    pub len: u32,
    pub _pad: u32,
}
pub const RELAY_HEADER: usize = core::mem::size_of::<RelayHeader>();

/// Quote this key (its SEC1 point, 65 bytes) and extend PCR 15 with it,
/// once per partition; the reply is the partition's evidence.
pub const RELAY_KEY: u32 = 1;
/// ActivateCredential: u32 blob length, the blob, the secret; the reply
/// is the credential.
pub const RELAY_ACTIVATE: u32 = 2;
use crate::badges::flags as flags_badge;
use crate::errno::{EAGAIN, EINVAL, EPERM, ESRCH, Errno};

crate::senders! {
    /// Who calls the flags server, by its badge (badges::flags): root (its
    /// start-up handshake), vmmgr (the host actor, for the console) or
    /// trustd's main thread (for guests).
    pub enum Sender in flags_badge {
        Root: [ROOT];
        Trustd: [TRUSTD];
        Vmmgr: [VMMGR];
    }
}

crate::protocol! {
    /// The flags server's endpoint (crate::wire::protocol): a thread with
    /// no heap, TPM, AML or calls back to root, in spaces of its own, so
    /// that trustd's main thread can reach the flags only through these
    /// calls.  It runs on a scheduling context of its own (FLAGS_BUDGET_US
    /// of every FLAGS_PERIOD_US), never on a caller's: a caller that sends
    /// without calling, which donates nothing, leaves it able to run, and
    /// one caller's flood delays another's call by less than a period.
    /// FlagsEntry::update checks what each caller may set; a reply's first
    /// word is 0 or an errno.
    pub mod call (from: Sender) {
        /// Root's start-up handshake: the thread is waiting.
        Ready / ready = 0 from [Root] () -> ();
        /// Taint guest `guest`'s `bits` (and seal them with abi::ACT_SEAL in
        /// `flags`), for `instance`: its flags.
        Act / act = 1 from [Vmmgr, Trustd] (guest: usize, instance: u64, bits: [u64; 4], flags: u64) -> Flags;
        /// Seal guest `guest`'s `bits`, for `instance`: its flags.
        Seal / seal = 2 from [Trustd] (guest: usize, instance: u64, bits: [u64; 4], flags: u64) -> Flags;
        /// Nothing, in its turn: when the server answers, no write of an
        /// entry is under way that was when the call was made.  For a
        /// reader that found an entry being written at every look
        /// (FlagsEntry::read_synced): the server was stopped in the middle
        /// of the write, out of budget, and goes on at its next.
        Sync / sync = 3 from [Vmmgr, Trustd] () -> ();
    }
}
/// The ops of FlagsEntry::update: the labels of `call`'s act and seal, as
/// the protocol declares them.
pub const FLAGS_ACT: u64 = call::Request::Act { guest: 0, instance: 0, bits: [0; 4], flags: 0 }.label();
pub const FLAGS_SEAL: u64 = call::Request::Seal { guest: 0, instance: 0, bits: [0; 4], flags: 0 }.label();
/// Most ACPI table bytes root gives trustd.
pub const AML_MAX: usize = 4 << 20;
/// The UEFI TPM event log the boot loader passed on (TrustdConfig), which
/// trustd gives guests as it is (abi::ATTEST_EVENT_LOG), right after the
/// ACPI tables.  At most EVENT_LOG_MAX bytes, as FL4 takes (MAX_TPM_LOG).
pub const EVENT_LOG_VA: usize = AML_VA + AML_MAX;
pub const EVENT_LOG_MAX: usize = 1 << 20;
const _: () = assert!(AML_VA + AML_MAX <= EVENT_LOG_VA && EVENT_LOG_VA + EVENT_LOG_MAX <= crate::MMIO_VA);
/// TrustdConfig::event_log_flags (seL4_TpmEventLog's): events are missing
/// at the end of the log; the log is TCG 1.2 (SHA-1), not crypto agile.
pub const EVENT_LOG_TRUNCATED: u64 = 1 << 0;
pub const EVENT_LOG_TCG_1_2: u64 = 1 << 1;

/// The flags server's scheduling context, and its keeper's: FLAGS_BUDGET_US
/// of every FLAGS_PERIOD_US, at the highest priority.  A request takes
/// microseconds, so honest callers never use the budget up.  A caller that
/// floods it (trustd's main thread, were it an attacker's) takes at most
/// this tenth of the server's core from what runs below, and makes another
/// caller (vmmgr, for the console) wait for the next budget: less than
/// FLAGS_PERIOD_US, and one request of the flooder's, since callers are
/// served in the order they came.
pub const FLAGS_BUDGET_US: u64 = 1000;
pub const FLAGS_PERIOD_US: u64 = 10_000;

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
    /// The launch digest (DESIGN.md §10.2): SHA-256 of the kernel image,
    /// initramfs and command line the guest booted with.
    pub launch: [u8; 32],
    pub reserved: u64,
}

pub const RECORD_DOM0: u32 = 1;
/// The guest's request page is its second (page_of(id, true)); root sets
/// it.
pub const RECORD_PAGE_B: u32 = 2;
pub const MAX_RECORDS: usize = 64;
const _: () = assert!(core::mem::size_of::<GuestRecord>() == 64);
const _: () = assert!(MAX_RECORDS * core::mem::size_of::<GuestRecord>() <= 4096);
const _: () = assert!(MAX_RECORDS <= 64 && page_va(PAGES) <= AML_VA);

/// The instance guest `id` runs as, from the registry: 0 if none.
///
/// # Safety
/// The registry must be mapped at `registry`.
pub unsafe fn registered(registry: usize, id: usize) -> u64 {
    if id >= MAX_RECORDS {
        return 0;
    }
    let p = (registry as *const GuestRecord).wrapping_add(id);
    unsafe { core::ptr::addr_of!((*p).instance).read_volatile() }
}

/// Both ends of a registry record: root writes it (`write_record`,
/// `clear_record`), trustd reads it (`read_record`).  A record's fields are
/// written only while its instance is 0, before the instance; instances are
/// never given twice (root counts them, from 1).  So a reader that reads
/// the instance, the fields, and the same instance again has that
/// instance's fields.  One read of the whole record would not do: its
/// loads come in any order, its instance's after a destroyed guest's
/// launch digest, which a report would then give a guest started on its
/// id.
///
/// Write guest `id`'s record, for `instance` (non-zero): its fields, then
/// the instance.  False, and nothing written, if the record holds an
/// instance (a running guest's record stays as it is) or there is none
/// for `id`.
///
/// # Safety
/// The registry must be mapped writable at `registry`, and its only writer
/// this.
pub unsafe fn write_record(registry: usize, id: usize, instance: u64, r: &GuestRecord) -> bool {
    use core::ptr::{addr_of, addr_of_mut};
    if id >= MAX_RECORDS || instance == 0 {
        return false;
    }
    let p = (registry as *mut GuestRecord).wrapping_add(id);
    unsafe {
        if addr_of!((*p).instance).read_volatile() != 0 {
            return false;
        }
        addr_of_mut!((*p).ram).write_volatile(r.ram);
        addr_of_mut!((*p).vcpus).write_volatile(r.vcpus);
        addr_of_mut!((*p).flags).write_volatile(r.flags);
        addr_of_mut!((*p).launch).write_volatile(r.launch);
        addr_of_mut!((*p).reserved).write_volatile(0);
        fence(Ordering::Release);
        addr_of_mut!((*p).instance).write_volatile(instance);
    }
    true
}

/// Guest `id` is destroyed: its record holds no instance, which a reader
/// sees before any field the next guest's `write_record` writes.
///
/// # Safety
/// As `write_record`.
pub unsafe fn clear_record(registry: usize, id: usize) {
    if id >= MAX_RECORDS {
        return;
    }
    let p = (registry as *mut GuestRecord).wrapping_add(id);
    unsafe { core::ptr::addr_of_mut!((*p).instance).write_volatile(0) };
    fence(Ordering::SeqCst);
}

/// Guest `id`'s record, if it runs: one instance's fields (`write_record`).
///
/// # Safety
/// The registry must be mapped at `registry`.
pub unsafe fn read_record(registry: usize, id: usize) -> Option<GuestRecord> {
    if id >= MAX_RECORDS {
        return None;
    }
    let p = (registry as *const GuestRecord).wrapping_add(id);
    let instance = || unsafe { core::ptr::addr_of!((*p).instance).read_volatile() };
    loop {
        let first = instance();
        if first == 0 {
            return None;
        }
        fence(Ordering::Acquire);
        let r = unsafe { p.read_volatile() };
        fence(Ordering::Acquire);
        if instance() == first {
            return Some(GuestRecord { instance: first, ..r });
        }
    }
}

/// One instance's consistent flags. A different instance reads as empty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub instance: u64,
    pub taint: [u64; 4],
    pub seal: [u64; 4],
}

impl crate::wire::Wire for Flags {
    const MAX_WORDS: usize = 9;
    fn put(&self, out: &mut [u64]) -> usize {
        out[0] = self.instance;
        out[1..5].copy_from_slice(&self.taint);
        out[5..9].copy_from_slice(&self.seal);
        9
    }
    fn get(words: &[u64]) -> Option<(Self, usize)> {
        let w = words.get(..9)?;
        Some((Flags { instance: w[0], taint: w[1..5].try_into().ok()?, seal: w[5..9].try_into().ok()? }, 9))
    }
}

impl Flags {
    /// What a reader has in place of an entry it could not read
    /// (FlagsEntry::read): every bit tainted and sealed, whatever the
    /// instance, so that nothing is taken for clean or allowed.  No guest
    /// has this instance: `update` refuses it.
    pub const UNAVAILABLE: Flags = Flags { instance: u64::MAX, taint: [u64::MAX; 4], seal: [u64::MAX; 4] };

    pub fn unavailable(&self) -> bool {
        self.instance == Self::UNAVAILABLE.instance
    }

    pub fn for_instance(self, instance: u64) -> Self {
        if self.instance == instance || self.unavailable() { self } else { Self { instance, ..Self::default() } }
    }

    pub fn bytes(&self) -> abi::AttestFlags {
        let bytes = |words: &[u64; 4]| core::array::from_fn(|i| (words[i / 8] >> (8 * (i % 8))) as u8);
        abi::AttestFlags { taint: bytes(&self.taint), seal: bytes(&self.seal) }
    }

    /// Actor fast path: check the seal even when already tainted. If
    /// false, ACT must succeed before any of the operation's effects.
    /// EAGAIN for flags that could not be read (UNAVAILABLE): the
    /// operation is refused, and its caller may ask again.
    pub fn acted(&self, bits: u64) -> Result<bool, Errno> {
        if self.unavailable() {
            return Err(EAGAIN);
        }
        if self.seal[0] & bits != 0 { Err(EPERM) } else { Ok(self.taint[0] & bits == bits) }
    }

    /// Shared actor steps: check every seal, and record only the first
    /// effect. `record` must synchronously ACT through the flags service.
    pub fn act(&self, bits: u64, effect: bool, record: impl FnOnce() -> Result<(), Errno>) -> Result<(), Errno> {
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

    /// Looks a reader takes at an entry before it gives up (`try_read`).
    /// A write is a dozen stores, so a few looks outlast one; more only
    /// wait for a writer that is not running.
    pub const READ_TRIES: usize = 128;

    /// The fields as they are now, each loaded on its own.
    fn fields(&self) -> Flags {
        Flags {
            instance: self.instance.load(Ordering::Relaxed),
            taint: core::array::from_fn(|i| self.taint[i].load(Ordering::Relaxed)),
            seal: core::array::from_fn(|i| self.seal[i].load(Ordering::Relaxed)),
        }
    }

    /// The entry, consistent; None if READ_TRIES looks found it being
    /// written.  The writer runs on a small budget of its own and can be
    /// stopped in the middle of a write until its next one, at worst by a
    /// caller that used the budget up: a reader does not spin for it, but
    /// asks the server (`read_synced`), whose answer comes in bounded
    /// time.
    pub fn try_read(&self) -> Option<Flags> {
        crate::seqlock::read(&self.seq, Self::READ_TRIES, || self.fields())
    }

    /// `try_read`, with Flags::UNAVAILABLE for an entry that could not be
    /// read: every bit reads as tainted and sealed, and `acted` refuses
    /// with EAGAIN, so an actor does nothing it could not check.
    pub fn read(&self) -> Flags {
        self.try_read().unwrap_or(Flags::UNAVAILABLE)
    }

    /// Times a reader asks the server to finish its write (`read_synced`).
    pub const SYNC_TRIES: usize = 3;

    /// `try_read`, and for an entry found being written at every look,
    /// again after `sync` (the server's call::sync, which returns once
    /// that write is done), SYNC_TRIES times at most.  The server's budget
    /// can run out in the middle of a write, and a caller that floods it
    /// makes that happen now and then: the entry is then unreadable until
    /// the server's next budget, which `sync` waits for (less than
    /// FLAGS_PERIOD_US, and a request of the flooder's), rather than the
    /// reader being refused.  None if the entry is still being written
    /// after that, as a failed server leaves it.
    pub fn read_synced(&self, mut sync: impl FnMut()) -> Option<Flags> {
        for _ in 0..Self::SYNC_TRIES {
            if let Some(flags) = self.try_read() {
                return Some(flags);
            }
            sync();
        }
        self.try_read()
    }

    /// Serialized by the flags endpoint. Positive errno on failure;
    /// invalid requests and sealed ACTs change nothing, including instance.
    /// `registered` is the instance the registry has for the guest (0: not
    /// started, or not attested).  trustd answers only running guests, so
    /// it must name that instance; vmmgr must too once there is one, and
    /// before (console input queued before start) names the instance root
    /// gave it.  Neither can replace a running guest's entry with another
    /// instance's.
    ///
    /// # Safety
    /// There must be exactly one writer of this entry.
    pub unsafe fn update(&self, from: Sender, op: u64, instance: u64, registered: u64, bits: [u64; 4], flags: u64)
        -> Result<Flags, Errno> {
        let sealable = bits[0] & !abi::FLAGS_HOST_DEFINED == 0 && bits[1] == 0;
        let allowed = match (from, op) {
            (Sender::Vmmgr, FLAGS_ACT) => bits[0] & !abi::FLAGS_HOST_DEFINED == 0 && bits[1..] == [0; 3] && flags == 0,
            (Sender::Trustd, FLAGS_ACT) => bits[0] == 0 && (flags & abi::ACT_SEAL as u64 == 0 || sealable),
            (Sender::Trustd, FLAGS_SEAL) => sealable && flags == 0,
            _ => false,
        };
        // Instance 0 is no guest's, and UNAVAILABLE's is what readers take
        // an unreadable entry for.
        if !allowed || flags & !(abi::ACT_SEAL as u64) != 0 || instance == 0 || instance == Flags::UNAVAILABLE.instance {
            return Err(EINVAL);
        }
        let current = match from {
            Sender::Trustd => instance == registered,
            _ => registered == 0 || instance == registered,
        };
        // The one writer finds no write under way.
        let old = self.try_read().ok_or(EAGAIN)?;
        if !current || instance < old.instance { return Err(ESRCH); }
        let mut next = old.for_instance(instance);
        if op == FLAGS_ACT && (0..4).any(|i| next.seal[i] & bits[i] != 0) { return Err(EPERM); }
        for i in 0..4 {
            if op == FLAGS_ACT { next.taint[i] |= bits[i]; }
            if op == FLAGS_SEAL || flags & abi::ACT_SEAL as u64 != 0 { next.seal[i] |= bits[i]; }
        }
        crate::seqlock::write(&self.seq, |_| {
            self.instance.store(instance, Ordering::Relaxed);
            for i in 0..4 {
                self.taint[i].store(next.taint[i], Ordering::Relaxed);
                self.seal[i].store(next.seal[i], Ordering::Relaxed);
            }
        });
        Ok(next)
    }
}
const _: () = assert!(core::mem::size_of::<FlagsEntry>() == 128);
const _: () = assert!(MAX_RECORDS * core::mem::size_of::<FlagsEntry>() == FLAGS_SIZE);

/// The `op` of trustd's root::call::hw: an access the firmware's AML
/// makes outside trustd's own ranges.
pub const HW_MEM_READ: u64 = 0;
pub const HW_MEM_WRITE: u64 = 1;
pub const HW_IO_READ: u64 = 2;
pub const HW_IO_WRITE: u64 = 3;
pub const HW_PCI_READ: u64 = 4;
pub const HW_PCI_WRITE: u64 = 5;

/// The PCI configuration registers of a function (header type 0) that say
/// where it decodes and whether it masters the bus: the command register,
/// the BARs and the expansion ROM's.  The firmware's AML never writes
/// them, in any function, by the configuration mechanism or through ECAM:
/// with them trustd could move a device root does not drive onto another's
/// addresses, or have it write memory.  Nor extended configuration space
/// (past 0x100, through ECAM only): ACS, which root turns on so that
/// confined devices are isolated from their peers (DESIGN.md §9.5), and
/// SR-IOV, ATS, PASID, Resizable BAR and the like, which would let a
/// device root does not drive bypass the IOMMU or decode elsewhere; the
/// AML's PCI_Config regions end at 0x100.  Whether a write of `width`
/// bytes at configuration offset `off` touches one.
pub const fn hw_config_write_protected(off: usize, width: usize) -> bool {
    const PROTECTED: [(usize, usize); 3] = [(0x04, 0x06), (0x10, 0x28), (0x30, 0x34)];
    let end = off.saturating_add(width);
    if end > 0x100 {
        return true;
    }
    let mut i = 0;
    while i < PROTECTED.len() {
        if off < PROTECTED[i].1 && PROTECTED[i].0 < end {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether a configuration write [off, off + width) of a function whose
/// configuration space `read8` reads meets one of the capabilities the
/// firmware's AML never writes: MSI or MSI-X (MSI's length by its Message
/// Control: 64-bit addresses, per-vector masking), as a device the
/// firmware left mastering the bus would send the AML's message as an
/// interrupt where none is remapped; PCI Express (its 0x3c bytes, within
/// the first 256), whose Device Control turns on phantom functions, which
/// would have the device's DMA reach memory as another function's, No
/// Snoop and relaxed ordering, or resets it (Initiate FLR), and whose
/// Device Control 2 turns on ID-based ordering and the like; and power
/// management (8 bytes), whose PMCSR puts the device in D3hot, resetting
/// it.  A capability list that cannot be walked (a pointer into the
/// header, more than 48 entries) refuses every write.
pub fn hw_config_cap_protected(off: usize, width: usize, read8: impl Fn(usize) -> u8) -> bool {
    let end = off.saturating_add(width);
    if read8(6) & 0x10 == 0 {
        return false;
    }
    let mut ptr = (read8(0x34) & !3) as usize;
    let mut hops = 0;
    while ptr != 0 {
        if ptr < 0x40 || hops == 48 {
            return true;
        }
        let len = match read8(ptr) {
            0x01 => 8,
            0x05 => {
                let ctrl = read8(ptr + 2) as usize | (read8(ptr + 3) as usize) << 8;
                10 + if ctrl & 0x80 != 0 { 4 } else { 0 } + if ctrl & 0x100 != 0 { 10 } else { 0 }
            }
            0x10 => 0x3c,
            0x11 => 12,
            _ => 0,
        };
        if off < ptr + len && ptr < end {
            return true;
        }
        ptr = (read8(ptr + 1) & !3) as usize;
        hops += 1;
    }
    false
}

/// The MSI-X table and pending bits of a function, as memory ranges:
/// from its capability's Message Control `ctrl` and Table and PBA
/// registers, with `bar` the address of a memory BAR (None if the BAR is
/// not one).
pub fn msix_blocks(ctrl: u16, table: u32, pba: u32, bar: impl Fn(u8) -> Option<u64>) -> [Option<(u64, u64)>; 2] {
    let n = (ctrl & 0x7ff) as u64 + 1;
    let at = |reg: u32, size: u64| bar((reg & 7) as u8).map(|b| (b.saturating_add((reg & !7) as u64), size));
    [at(table, n * 16), at(pba, n.div_ceil(64) * 8)]
}

/// The BARs of a function with header type `header`: six of type 0, two
/// of a PCI-to-PCI bridge (type 1), none of a CardBus bridge.
pub const fn bar_count(header: u8) -> usize {
    match header & 0x7f {
        0 => 6,
        1 => 2,
        _ => 0,
    }
}

/// Where a function's memory BAR `i` (of `bar_count`) decodes, from its
/// registers as `config` reads a dword at an offset: None for an I/O BAR,
/// one past the function's BARs, or a 64-bit one in the last register,
/// whose upper half is not a BAR.  Not sized: reading is all it takes.
pub fn bar_address(config: &impl Fn(usize) -> u32, header: u8, i: u8) -> Option<u64> {
    let n = bar_count(header);
    // The lower half of a 64-bit BAR before it says what register `i` is.
    let mut at = 0;
    while at < n {
        let lo = config(0x10 + 4 * at);
        let is64 = lo & 1 == 0 && (lo >> 1) & 3 == 2;
        if at == i as usize {
            return match (lo & 1 != 0, is64) {
                (true, _) => None,
                (false, false) => Some((lo & !0xf) as u64),
                (false, true) if at + 1 < n => Some((lo & !0xf) as u64 | (config(0x10 + 4 * at + 4) as u64) << 32),
                (false, true) => None,
            };
        }
        at += if is64 { 2 } else { 1 };
    }
    None
}

/// Every MSI-X table and pending bit array of a function, each passed to
/// `push`, from its configuration space as `config` reads a dword at an
/// offset: of every MSI-X capability its list has, in the BARs of its
/// header type (bridges' too), whatever the BAR's size.  False if they may
/// not be all: the capability list cannot be walked (a pointer into the
/// header, a capability past the first 256 bytes, more than 48 entries),
/// or `push` refused one.  A function the firmware left mastering the bus
/// sends what is written there as interrupts.
pub fn function_msix_blocks(config: impl Fn(usize) -> u32, mut push: impl FnMut((u64, u64)) -> bool) -> bool {
    let header = (config(0xc) >> 16) as u8 & 0x7f;
    if config(4) >> 16 & 0x10 == 0 {
        return true;
    }
    let read8 = |off: usize| (config(off & !3) >> (off % 4 * 8)) as u8;
    let mut ptr = (read8(0x34) & !3) as usize;
    let mut hops = 0;
    while ptr != 0 {
        if ptr < 0x40 || hops == 48 {
            return false;
        }
        if read8(ptr) == 0x11 {
            if ptr + 12 > 0x100 {
                return false;
            }
            let ctrl = (config(ptr) >> 16) as u16;
            let bar = |i: u8| bar_address(&config, header, i);
            for b in msix_blocks(ctrl, config(ptr + 4), config(ptr + 8), bar).into_iter().flatten() {
                if !push(b) {
                    return false;
                }
            }
        }
        ptr = (read8(ptr + 1) & !3) as usize;
        hops += 1;
    }
    true
}

/// Whether the access [addr, addr + width) lies within [base, base + size).
pub const fn hw_within(addr: usize, width: usize, base: u64, size: u64) -> bool {
    let (addr, width) = (addr as u64, width as u64);
    match (addr.checked_add(width), base.checked_add(size)) {
        (Some(end), Some(limit)) => base <= addr && end <= limit,
        _ => false,
    }
}

/// Whether the access [addr, addr + width) meets [base, base + size).
pub const fn hw_meets(addr: usize, width: usize, base: u64, size: u64) -> bool {
    let (addr, end) = (addr as u64, (addr as u64).saturating_add(width as u64));
    addr < base.saturating_add(size) && base < end
}

/// Addresses that are never RAM on a PC: the I/O APICs, the HPET, the
/// TPM, the chipset's registers, the local APIC and the firmware's flash,
/// below 4 GiB.
pub const HW_CHIPSET: (u64, u64) = (0xfec0_0000, 0x0140_0000);

/// I/O ports the AML never reaches, whatever the firmware's tables say
/// (root adds the FADT's sleep and SMI ports): the keyboard controller's
/// and port A's reset, APM's SMI command and data, the reset control
/// register, and the legacy interrupt controllers and timer, the 8259
/// PICs with their edge/level registers and the 8254 PIT, which only
/// the kernel programs.
pub const HW_REFUSED_PORTS: [(usize, usize); 9] =
    [(0x20, 2), (0x40, 4), (0x60, 1), (0x64, 1), (0x92, 1), (0xa0, 2), (0xb2, 2), (0x4d0, 2), (0xcf9, 1)];

/// The FADT's registers that put the machine to sleep or turn it off, and
/// its SMI command port: SMI_CMD, PM1a/b_CNT_BLK and PM2_CNT_BLK (I/O
/// ports), and X_PM1a/b_CNT_BLK, X_PM2_CNT_BLK and SLEEP_CONTROL_REG
/// (generic addresses, in I/O or memory space).  The AML reaches none of
/// them, in either space: SLP_TYP and SLP_EN written to any of them
/// suspend or power off the whole machine, every partition with it.
#[derive(Default, Debug)]
pub struct FadtSleep {
    /// I/O ports: (first, count).
    pub ports: crate::fixed::ArrayVec<(usize, usize), FADT_SLEEP_PORTS>,
    /// Memory: (address, length).
    pub mmio: crate::fixed::ArrayVec<(u64, u64), FADT_SLEEP_MMIO>,
}

/// The FADT's legacy blocks (4) and generic addresses (4), at most, in I/O
/// space; the generic addresses in memory space.
pub const FADT_SLEEP_PORTS: usize = 8;
pub const FADT_SLEEP_MMIO: usize = 4;

/// FadtSleep of the FADT `f` (as many of its bytes as the table has: a
/// field past its end is none).
pub fn fadt_sleep(f: &[u8]) -> FadtSleep {
    let mut out = FadtSleep::default();
    let u8_at = |i: usize| f.get(i).map_or(0, |&b| b as usize);
    let u32_at = |i: usize| f.get(i..i + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
    // SMI_CMD, PM1a/b_CNT_BLK (with PM1_CNT_LEN) and PM2_CNT_BLK (with
    // PM2_CNT_LEN), in I/O space.
    for (at, len) in [(48, 1), (64, u8_at(89)), (68, u8_at(89)), (72, u8_at(90))] {
        let port = u32_at(at);
        if port != 0 && port < 0x1_0000 {
            out.ports.must_push((port, len.max(1)));
        }
    }
    // X_PM1a/b_CNT_BLK, X_PM2_CNT_BLK and SLEEP_CONTROL_REG: a generic
    // address of 12 bytes (space, bit width, bit offset, access size,
    // address).  Its length: its bits, or its access size, at least a
    // byte (firmware leaves one or the other 0).
    for at in [172, 184, 196, 244] {
        let Some(g) = f.get(at..at + 12) else { continue };
        let addr = u64::from_le_bytes(g[4..12].try_into().unwrap());
        let access = match g[3] { a @ 1..=4 => 1u64 << (a - 1), _ => 0 };
        let len = ((g[1] as u64).div_ceil(8) + (g[2] as u64) / 8).max(access).max(1);
        match g[0] {
            0 if addr != 0 => out.mmio.must_push((addr, len)),
            1 if addr != 0 && addr < 0x1_0000 => out.ports.must_push((addr as usize, len as usize)),
            _ => {}
        }
    }
    out
}

/// The HPET's register block, where PCs put it: the AML never reaches it.
/// Its comparators deliver interrupts as MSI writes the IOMMU does not
/// remap (AMD-Vi passes a special device's through), so with it the AML
/// could send any vector, NMI or INIT to any CPU, another partition's
/// too.
pub const HPET_DEFAULT: (u64, u64) = (0xfed0_0000, 0x400);

/// The page where PCs put the chipset's I/O APIC, as HPET_DEFAULT is
/// the HPET's (every other one is the MADT's, `madt_ioapic_pages`), and
/// the local APICs' and MSIs' megabyte: the AML reaches neither.  An I/O APIC's redirection entries and a local
/// APIC's interrupt command register send any vector, NMI, INIT or SIPI,
/// and neither the IOMMU (an I/O APIC is a special device AMD-Vi passes
/// through, and none is remapped on another partition's or C seL4's
/// I/O APIC) nor the kernel stands in between.  The TPM (0xfed4_0000) and
/// AMD's FCH (its SPI and eSPI at 0xfec1_0000 and 0xfec2_0000, the rest
/// at 0xfed8_0000), whose registers an fTPM's start method may use, are
/// outside both.
pub const IOAPIC_DEFAULT: (u64, u64) = (0xfec0_0000, 0x1000);
pub const LAPIC_MSI: (u64, u64) = (0xfee0_0000, 0x10_0000);
/// The I/O APICs root keeps of the MADT for `madt_ioapic_pages`.  A table
/// with more is not truncated: it says so, and root then refuses every
/// memory write of the AML.
pub const MAX_IOAPIC_PAGES: usize = 32;

/// The register pages of the I/O APICs the MADT `table` lists (its first
/// bytes; the table is `len` bytes long), and whether they are all of
/// them: false if `table` is not the whole table, an entry runs past its
/// end, or it lists more than MAX_IOAPIC_PAGES I/O APICs.  An I/O APIC
/// entry (type 1) has its address at 4.
pub fn madt_ioapic_pages(table: &[u8], len: usize) -> (crate::fixed::ArrayVec<(u64, u64), MAX_IOAPIC_PAGES>, bool) {
    let mut pages = crate::fixed::ArrayVec::new();
    let mut complete = table.len() >= len && len >= 44;
    let t = &table[..table.len().min(len)];
    let mut at = 44;
    while at < t.len() {
        let Some(&[ty, n]) = t.get(at..at + 2).map(|h| <&[u8; 2]>::try_from(h).unwrap()) else {
            complete = false;
            break;
        };
        let Some(e) = t.get(at..at + n as usize).filter(|e| e.len() >= 2) else {
            complete = false;
            break;
        };
        if ty == 1 {
            match e.get(4..8) {
                Some(a) if n >= 12 => {
                    let page = u32::from_le_bytes(a.try_into().unwrap()) as u64 & !0xfff;
                    if !pages.iter().any(|&(p, _)| p == page) && pages.push((page, 0x1000)).is_err() {
                        complete = false;
                    }
                }
                _ => complete = false,
            }
        }
        at += e.len();
    }
    (pages, complete)
}

/// The register block of the HPET table `table` (its first bytes): its
/// base address, if in memory space, and the block's 1 KiB.
pub fn hpet_block(table: &[u8]) -> Option<(u64, u64)> {
    // The Generic Address Structure at 40: space 0 (memory), the address
    // at 44.
    let addr = u64::from_le_bytes(table.get(44..52)?.try_into().ok()?);
    (*table.get(40)? == 0 && addr != 0).then_some((addr, 0x400))
}

/// An ECAM window of the MCFG: the configuration space of buses
/// [bus_lo, bus_hi] of `segment`, a page per function from `base` (bus 0's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ecam {
    pub base: u64,
    pub segment: u16,
    pub bus_lo: u8,
    pub bus_hi: u8,
}

/// ECAM windows root keeps of the MCFG.  A table with more is not
/// truncated: `mcfg_windows` says so, and root then refuses every memory
/// write of the AML, any of which could be a configuration write.
pub const MAX_ECAM: usize = 16;
/// The MCFG's header, and an entry: base, segment, first and last bus.
pub const MCFG_HEADER: usize = 44;
pub const MCFG_ENTRY: usize = 16;
/// A buffer for a MCFG of MAX_ECAM windows.
pub const MCFG_MAX: usize = MCFG_HEADER + MAX_ECAM * MCFG_ENTRY;

impl Ecam {
    /// The function whose configuration page `paddr` is in, and the
    /// offset in it: (bus, device, function, offset).
    pub fn function(&self, paddr: usize) -> Option<(u8, u8, u8, usize)> {
        let off = (paddr as u64).checked_sub(self.base)?;
        let bus = off >> 20;
        (bus >= self.bus_lo as u64 && bus <= self.bus_hi as u64)
            .then_some((bus as u8, (off >> 15 & 0x1f) as u8, (off >> 12 & 7) as u8, (off & 0xfff) as usize))
    }
}

/// The ECAM windows of `table`, the first bytes of a MCFG that is `len`
/// bytes long, and whether they are all of them: false if the table has
/// more than MAX_ECAM, or `table` is not the whole of it.
pub fn mcfg_windows(table: &[u8], len: usize) -> (crate::fixed::ArrayVec<Ecam, MAX_ECAM>, bool) {
    let mut windows = crate::fixed::ArrayVec::new();
    let mut complete = table.len() >= len;
    for e in table.get(MCFG_HEADER..).unwrap_or(&[]).chunks_exact(MCFG_ENTRY) {
        let w = Ecam {
            base: u64::from_le_bytes([e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7]]),
            segment: u16::from_le_bytes([e[8], e[9]]),
            bus_lo: e[10],
            bus_hi: e[11],
        };
        if w.bus_lo <= w.bus_hi && windows.push(w).is_err() {
            complete = false;
        }
    }
    (windows, complete)
}

/// ActivateCredential's rate limit, per guest instance and, at a primary,
/// per partition whose trustd relays its guests' (DESIGN.md §10.2): up to
/// ACTIVATE_BURST at once, then one every ACTIVATE_INTERVAL_MS (about
/// 80 ms of TPM time each, on a discrete TPM).
pub const ACTIVATE_BURST: u64 = 5;
pub const ACTIVATE_INTERVAL_MS: u64 = 1000;

/// The limit's state (GCRA): when the allowance is next full, in ticks; 0
/// when it is.
#[derive(Clone, Copy, Default)]
pub struct ActivateLimit {
    tat: u64,
}

impl ActivateLimit {
    /// May one more use the TPM at `now` (ticks of `hz` a second)?  If so,
    /// it is counted.
    pub fn allow(&mut self, now: u64, hz: u64) -> bool {
        let interval = hz.saturating_mul(ACTIVATE_INTERVAL_MS) / 1000;
        let tat = self.tat.max(now);
        if tat - now > interval.saturating_mul(ACTIVATE_BURST - 1) {
            return false;
        }
        self.tat = tat.saturating_add(interval);
        true
    }
}

/// Notices of trustd's answers that root posts for one guest between two
/// of its timer's ticks, at most; more wait for the next tick.
pub const ATTEST_NOTICES_PER_TICK: u8 = 32;

/// Root's notices to vmmgr that trustd answered a guest
/// (root::call::attest_done, vmmgr::call::attest_done), which vmmgr turns
/// into the guest's device event.  trustd's main thread, which may run an
/// attacker's code, says when and for which guest, so root bounds what it
/// can make of that: a guest has at most one notice in vmmgr's mailbox,
/// the next waits until vmmgr has taken it, and gets at most
/// ATTEST_NOTICES_PER_TICK between two ticks of root's timer.  No answer
/// goes unsignalled: one that comes while a notice is posted, or after the
/// tick's allowance, is signalled once the notice is taken, or at the tick.
pub struct AttestNotices {
    /// Guests trustd answered whose notice is not posted yet.
    waiting: u64,
    /// Guests with a notice in the mailbox that vmmgr has not taken.
    posted: u64,
    /// 1 + the guest whose notice request k of the mailbox is, at
    /// k % RING; 0 for another request.
    at: [u8; crate::mailbox::RING],
    /// Notices each guest may still get before the next tick.
    left: [u8; MAX_RECORDS],
}

impl AttestNotices {
    pub const fn new() -> Self {
        Self { waiting: 0, posted: 0, at: [0; crate::mailbox::RING], left: [ATTEST_NOTICES_PER_TICK; MAX_RECORDS] }
    }

    /// trustd answered guest `guest`.
    pub fn answered(&mut self, guest: usize) {
        if guest < MAX_RECORDS {
            self.waiting |= 1 << guest;
        }
    }

    /// A guest whose notice may be posted now, if any.
    pub fn next(&self) -> Option<usize> {
        let mut m = self.waiting & !self.posted;
        while m != 0 {
            let g = m.trailing_zeros() as usize;
            if self.left[g] != 0 {
                return Some(g);
            }
            m &= m - 1;
        }
        None
    }

    /// `guest`'s notice (`next`) is request `k` of vmmgr's mailbox.
    pub fn posted(&mut self, guest: usize, k: u64) {
        if guest < MAX_RECORDS {
            self.waiting &= !(1 << guest);
            self.posted |= 1 << guest;
            self.left[guest] = self.left[guest].saturating_sub(1);
            self.at[k as usize % crate::mailbox::RING] = guest as u8 + 1;
        }
    }

    /// vmmgr took request `k` of its mailbox.
    pub fn taken(&mut self, k: u64) {
        let g = core::mem::take(&mut self.at[k as usize % crate::mailbox::RING]);
        if g != 0 {
            self.posted &= !(1 << (g - 1));
        }
    }

    /// Root's timer ticked: every guest has its allowance again.
    pub fn tick(&mut self) {
        self.left = [ATTEST_NOTICES_PER_TICK; MAX_RECORDS];
    }
}

impl Default for AttestNotices {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    #[test]
    fn a_record_is_one_instances() {
        let mut page = [0u64; 4096 / 8];
        let reg = page.as_mut_ptr() as usize;
        let rec = |ram, launch| GuestRecord { instance: 0, ram, vcpus: 2, flags: RECORD_DOM0, launch: [launch; 32], reserved: 7 };
        unsafe {
            assert!(read_record(reg, 3).is_none());
            assert!(write_record(reg, 3, 5, &rec(64, 0xa)));
            // A running guest's record stays; an id past the registry has none.
            assert!(!write_record(reg, 3, 6, &rec(128, 0xb)));
            assert!(!write_record(reg, MAX_RECORDS, 6, &rec(128, 0xb)));
            assert!(!write_record(reg, 4, 0, &rec(128, 0xb)));
            let r = read_record(reg, 3).unwrap();
            assert_eq!((r.instance, r.ram, r.vcpus, r.flags, r.launch, r.reserved), (5, 64, 2, RECORD_DOM0, [0xa; 32], 0));
            assert_eq!(registered(reg, 3), 5);
            clear_record(reg, 3);
            assert!(read_record(reg, 3).is_none());
            assert!(write_record(reg, 3, 6, &GuestRecord { flags: 0, ..rec(128, 0xb) }));
            let r = read_record(reg, 3).unwrap();
            assert_eq!((r.instance, r.ram, r.flags, r.launch), (6, 128, 0, [0xb; 32]));
            assert!(read_record(reg, MAX_RECORDS).is_none());
        }
    }

    #[test]
    fn an_entry_being_written_reads_as_unavailable_not_for_ever() {
        let e = FlagsEntry::new();
        unsafe { e.update(Sender::Trustd, FLAGS_SEAL, 3, 3, [1, 0, 0, 0], 0) }.unwrap();
        assert_eq!(e.read().for_instance(3).acted(1), Err(EPERM));
        // A writer stopped in the middle of a write: the reader gives up.
        e.seq.fetch_add(1, Ordering::Relaxed);
        assert_eq!(e.try_read(), None);
        let f = e.read();
        assert_eq!(f, Flags::UNAVAILABLE);
        // Whatever instance is asked for, nothing reads as clean or
        // allowed, and an actor is told to ask again.
        for instance in [0, 3, 4] {
            let f = f.for_instance(instance);
            assert!(f.unavailable());
            assert_eq!((f.taint, f.seal), ([u64::MAX; 4], [u64::MAX; 4]));
            assert_eq!(f.acted(1), Err(EAGAIN));
            assert_eq!(f.act(1, true, || panic!("acted on flags it could not read")), Err(EAGAIN));
        }
        // A reader that asks the server gets the entry once the server has
        // gone on, and nothing from one that never does.
        let mut asked = 0;
        assert_eq!(e.read_synced(|| asked += 1), None);
        assert_eq!(asked, FlagsEntry::SYNC_TRIES);
        let mut asked = 0;
        let f = e.read_synced(|| {
            asked += 1;
            e.seq.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!((f.map(|f| f.seal[0]), asked), (Some(1), 1));
        // The write has ended: the entry reads again, without asking.
        assert_eq!(e.read().seal[0], 1);
        assert_eq!(e.read_synced(|| panic!("asked for an entry that reads")).map(|f| f.seal[0]), Some(1));
        // No guest's entry can pass for an unreadable one.
        assert_eq!(unsafe { e.update(Sender::Vmmgr, FLAGS_ACT, u64::MAX, 0, [1, 0, 0, 0], 0) }, Err(EINVAL));
    }

    #[test]
    fn no_write_reaches_command_bars_or_rom() {
        for (off, width) in [(4, 1), (4, 2), (4, 4), (5, 1), (0x10, 4), (0x24, 4), (0x27, 1), (0x30, 4), (0x33, 1), (0, 8), (0x2c, 8)] {
            assert!(hw_config_write_protected(off, width), "{off:#x}+{width}");
        }
        // Status, the cache line size and latency, subsystem ids, the
        // interrupt line and the capabilities past the header are the
        // AML's.
        for (off, width) in [(6, 2), (0xc, 4), (0x28, 4), (0x2c, 4), (0x34, 4), (0x3c, 1), (0x40, 4), (0xfc, 4), (0xfe, 2)] {
            assert!(!hw_config_write_protected(off, width), "{off:#x}+{width}");
        }
        // Extended configuration space (ACS, SR-IOV, ATS...) is not, nor
        // a write that runs into it.
        for (off, width) in [(0x100, 4), (0x148, 2), (0x14c, 4), (0x200, 1), (0xffc, 4), (0xfc, 8), (0xff, 2)] {
            assert!(hw_config_write_protected(off, width), "{off:#x}+{width}");
        }
        assert!(hw_config_write_protected(0, usize::MAX));
        assert!(hw_config_write_protected(usize::MAX, 4));
    }

    #[test]
    fn accesses_within_a_range() {
        assert!(hw_within(0xfed4_0000, 4, HW_CHIPSET.0, HW_CHIPSET.1));
        assert!(hw_within(0xffff_fffc, 4, HW_CHIPSET.0, HW_CHIPSET.1));
        assert!(!hw_within(0xffff_fffd, 4, HW_CHIPSET.0, HW_CHIPSET.1));
        assert!(!hw_within(0xfebf_ffff, 2, HW_CHIPSET.0, HW_CHIPSET.1));
        assert!(!hw_within(usize::MAX, 2, 0, u64::MAX));
        assert!(!hw_within(8, 1, 4, u64::MAX));
    }

    #[test]
    fn the_hpet_and_legacy_ports_are_refused() {
        // Any byte of the block, from either side.
        for (addr, width) in [(0xfed0_0000, 4), (0xfed0_0100, 8), (0xfed0_03fc, 4), (0xfecf_fffe, 4)] {
            assert!(hw_meets(addr, width, HPET_DEFAULT.0, HPET_DEFAULT.1), "{addr:#x}+{width}");
        }
        for (addr, width) in [(0xfed0_0400, 4), (0xfecf_fffc, 4), (usize::MAX, 4)] {
            assert!(!hw_meets(addr, width, HPET_DEFAULT.0, HPET_DEFAULT.1), "{addr:#x}+{width}");
        }
        // The table's address, in memory space only.
        let mut t = [0u8; 56];
        t[44..52].copy_from_slice(&0xfed0_1000u64.to_le_bytes());
        assert_eq!(hpet_block(&t), Some((0xfed0_1000, 0x400)));
        t[40] = 1;
        assert_eq!(hpet_block(&t), None);
        assert_eq!(hpet_block(&t[..50]), None);
        // Port A's reset, the PICs, the PIT and the ELCR.
        let refused = |p: usize, w: usize| HW_REFUSED_PORTS.iter().any(|&(q, n)| hw_meets(p, w, q as u64, n as u64));
        for (port, width) in [(0x92, 1), (0x20, 1), (0x21, 1), (0xa0, 2), (0x40, 4), (0x43, 1), (0x4d0, 2), (0xcf8, 4)] {
            assert!(refused(port, width), "{port:#x}+{width}");
        }
        for (port, width) in [(0x80, 1), (0x22, 1), (0x44, 4), (0x4d2, 2), (0xcfc, 4)] {
            assert!(!refused(port, width), "{port:#x}+{width}");
        }
    }

    #[test]
    fn msi_and_msix_are_refused() {
        // Power management at 0x40, MSI at 0x50, MSI-X at 0x70.
        let space = |msi_ctrl: u16| {
            let mut c = [0u8; 256];
            c[6] = 0x10;
            c[0x34] = 0x40;
            c[0x40..0x42].copy_from_slice(&[0x01, 0x50]);
            c[0x50..0x54].copy_from_slice(&[0x05, 0x70, msi_ctrl as u8, (msi_ctrl >> 8) as u8]);
            c[0x70..0x72].copy_from_slice(&[0x11, 0x00]);
            c
        };
        let msi = |c: &[u8; 256], off: usize, width: usize| hw_config_cap_protected(off, width, |i| c.get(i).copied().unwrap_or(0xff));
        // MSI's length: 10, 14 with 64-bit addresses, 20 or 24 maskable.
        for (ctrl, len) in [(0u16, 10), (0x80, 14), (0x100, 20), (0x180, 24)] {
            let c = space(ctrl);
            assert!(msi(&c, 0x50, 4) && msi(&c, 0x50 + len - 1, 1), "{ctrl:#x}");
            assert!(msi(&c, 0x4c, 8), "{ctrl:#x}: across its start");
            assert!(!msi(&c, 0x50 + len, 1), "{ctrl:#x}: past its end");
        }
        let c = space(0x180);
        // MSI-X's 12 bytes, not what follows them or comes before MSI.
        for (off, width) in [(0x70, 2), (0x72, 2), (0x74, 4), (0x7b, 1)] {
            assert!(msi(&c, off, width), "{off:#x}+{width}");
        }
        for (off, width) in [(0x48, 4), (0x4c, 4), (0x7c, 4), (0xfc, 4), (0x08, 4), (0x100, 4)] {
            assert!(!msi(&c, off, width), "{off:#x}+{width}");
        }
        // No capability list: nothing; one that cannot be walked: all.
        let mut c = space(0);
        c[6] = 0;
        assert!(!msi(&c, 0x50, 4));
        let mut c = space(0);
        c[0x71] = 0x20;
        assert!(msi(&c, 0x80, 4));
        let mut c = space(0);
        c[0x71] = 0x40;
        assert!(msi(&c, 0x80, 4));
    }

    #[test]
    fn pcie_and_power_management_capabilities_are_refused() {
        // Power management at 0x40, a vendor capability at 0x48, PCI
        // Express at 0x60, MSI-X at 0xb0.
        let mut c = [0u8; 256];
        c[6] = 0x10;
        c[0x34] = 0x40;
        c[0x40..0x42].copy_from_slice(&[0x01, 0x48]);
        c[0x48..0x4a].copy_from_slice(&[0x09, 0x60]);
        c[0x60..0x62].copy_from_slice(&[0x10, 0xb0]);
        c[0xb0..0xb2].copy_from_slice(&[0x11, 0x00]);
        let refused = |off: usize, width: usize| hw_config_cap_protected(off, width, |i| c.get(i).copied().unwrap_or(0xff));
        // PMCSR (D3hot), Device Control (phantom functions, No Snoop,
        // Initiate FLR), Link Control, Device Control 2, and the last
        // bytes of either capability.
        for (off, width) in [(0x44, 2), (0x40, 4), (0x47, 1), (0x68, 2), (0x69, 1), (0x70, 2), (0x88, 2), (0x9b, 1)] {
            assert!(refused(off, width), "{off:#x}+{width}");
        }
        // The vendor capability, and what lies between the capabilities.
        for (off, width) in [(0x48, 4), (0x4c, 4), (0x9c, 4), (0xa0, 4), (0xbc, 4), (0xfc, 4)] {
            assert!(!refused(off, width), "{off:#x}+{width}");
        }
    }

    #[test]
    fn the_fadt_sleep_registers_are_refused_in_either_space() {
        let gas = |t: &mut [u8], at: usize, space: u8, bits: u8, access: u8, addr: u64| {
            t[at..at + 4].copy_from_slice(&[space, bits, 0, access]);
            t[at + 4..at + 12].copy_from_slice(&addr.to_le_bytes());
        };
        // SMI_CMD at 0xb2, PM1a_CNT at 0x404 (2 bytes), PM2_CNT at 0x450
        // (1); X_PM1a_CNT in memory (an AMD FCH's), X_PM1b_CNT in I/O
        // space, X_PM2_CNT in memory with only its access size, and
        // SLEEP_CONTROL_REG (ACPI 5.0, hardware-reduced) in memory.
        let mut t = [0u8; 276];
        t[48..52].copy_from_slice(&0xb2u32.to_le_bytes());
        t[64..68].copy_from_slice(&0x404u32.to_le_bytes());
        t[72..76].copy_from_slice(&0x450u32.to_le_bytes());
        t[89] = 2;
        t[90] = 1;
        gas(&mut t, 172, 0, 16, 2, 0xfed8_0804);
        gas(&mut t, 184, 1, 16, 2, 0x804);
        gas(&mut t, 196, 0, 0, 1, 0xfed8_0850);
        gas(&mut t, 244, 0, 8, 1, 0xfe00_0a10);
        let s = fadt_sleep(&t);
        assert_eq!(&s.ports[..], &[(0xb2, 1), (0x404, 2), (0x450, 1), (0x804, 2)]);
        assert_eq!(&s.mmio[..], &[(0xfed8_0804, 2), (0xfed8_0850, 1), (0xfe00_0a10, 1)]);
        // SLEEP_CONTROL_REG in I/O space too.
        gas(&mut t, 244, 1, 8, 0, 0x4b0);
        assert_eq!(fadt_sleep(&t).ports.last(), Some(&(0x4b0, 1)));
        // A table cut short (a revision 2 FADT's 244 bytes): no
        // SLEEP_CONTROL_REG, the X_ blocks still.
        let s = fadt_sleep(&t[..244]);
        assert_eq!(s.mmio.len(), 2);
        assert_eq!(s.ports.len(), 4);
        // Every field, either space: within the room there is.
        let mut t = [0u8; 276];
        for at in [48, 64, 68, 72] {
            t[at..at + 4].copy_from_slice(&0x400u32.to_le_bytes());
        }
        for at in [172, 184, 196, 244] {
            gas(&mut t, at, 1, 32, 3, 0x500);
        }
        assert_eq!(fadt_sleep(&t).ports.len(), FADT_SLEEP_PORTS);
        for at in [172, 184, 196, 244] {
            gas(&mut t, at, 0, 32, 3, 0xfed8_0000);
        }
        assert_eq!(fadt_sleep(&t).mmio.len(), FADT_SLEEP_MMIO);
    }

    #[test]
    fn msix_tables_as_memory() {
        let bar = |i: u8| match i { 0 => Some(0xfe00_0000), 2 => Some(0x40_0000_0000), _ => None };
        // 8 vectors: 128 bytes of table, 8 of pending bits; 65: 1040, 16.
        assert_eq!(msix_blocks(7, 0x2000, 0x3000 | 2, bar), [Some((0xfe00_2000, 128)), Some((0x40_0000_3000, 8))]);
        assert_eq!(msix_blocks(64, 0, 0x800, bar), [Some((0xfe00_0000, 1040)), Some((0xfe00_0800, 16))]);
        assert_eq!(msix_blocks(0, 1, 0, bar), [None, Some((0xfe00_0000, 8))]);
        assert!(hw_meets(0xfe00_207c, 4, 0xfe00_2000, 128) && !hw_meets(0xfe00_2080, 4, 0xfe00_2000, 128));
    }

    /// A function's configuration space: header type, BAR registers, and
    /// MSI-X capabilities at `caps` (offset, Table register, PBA
    /// register, next), linked from 0x34.
    fn function(header: u8, bars: &[(usize, u32)], caps: &[(usize, u32, u32, u8)]) -> [u8; 256] {
        let mut c = [0u8; 256];
        c[0xe] = header;
        for &(i, v) in bars {
            c[0x10 + 4 * i..0x14 + 4 * i].copy_from_slice(&v.to_le_bytes());
        }
        if let Some(&(first, ..)) = caps.first() {
            c[6] = 0x10;
            c[0x34] = first as u8;
        }
        for &(at, table, pba, next) in caps {
            // Message Control: 8 vectors.
            c[at..at + 4].copy_from_slice(&[0x11, next, 7, 0]);
            c[at + 4..at + 8].copy_from_slice(&table.to_le_bytes());
            c[at + 8..at + 12].copy_from_slice(&pba.to_le_bytes());
        }
        c
    }

    fn blocks_of(c: &[u8; 256], room: usize) -> (std::vec::Vec<(u64, u64)>, bool) {
        let mut v = std::vec::Vec::new();
        let complete = function_msix_blocks(|o| u32::from_le_bytes(c[o..o + 4].try_into().unwrap()), |b| {
            v.push(b);
            v.len() <= room
        });
        (v, complete)
    }

    #[test]
    fn every_msix_table_of_every_function_or_none_trusted() {
        // A PCIe root port (type 1) with MSI-X in its 64-bit BAR0: never
        // sized, its table and pending bits are still known.
        let port = function(1, &[(0, 0xfe10_0004), (1, 0x2)], &[(0x80, 0x1000, 0x1800, 0)]);
        assert_eq!(blocks_of(&port, 8), (vec![(0x2_fe10_1000, 128), (0x2_fe10_1800, 8)], true));
        // A bridge has two BARs: BIR 2 is none, and its bus numbers
        // (0x18) are not a BAR's upper half.
        let port = function(1, &[(0, 0xfe10_0000), (1, 0xfe20_0000), (2, 0x0003_0201)], &[(0x80, 2, 1, 0)]);
        assert_eq!(blocks_of(&port, 8), (vec![(0xfe20_0000, 8)], true));
        let config = |o: usize| u32::from_le_bytes(port[o..o + 4].try_into().unwrap());
        assert_eq!(bar_address(&|o| if o == 0x14 { 0xfe20_0004 } else { config(o) }, 1, 1), None);
        // A 64-bit BAR in the last register of a type 0 function is none.
        assert_eq!(bar_address(&|o| if o == 0x24 { 4 } else { 0 }, 0, 5), None);
        assert_eq!(bar_count(2), 0);
        // Every MSI-X capability, not just the first; a table in a BAR of
        // any size; I/O BARs hold none.
        let f = function(0, &[(0, 0xfd00_0000), (2, 0xe001), (4, 0xfc00_000c), (5, 0x10)],
            &[(0x40, 0x2000, 0x3000, 0x60), (0x60, 4 | 0x100, 2 | 0x200, 0)]);
        assert_eq!(blocks_of(&f, 8),
            (vec![(0xfd00_2000, 128), (0xfd00_3000, 8), (0x10_fc00_0100, 128)], true));
        // No capability list: nothing to know.
        let mut none = function(0, &[(0, 0xfd00_0000)], &[]);
        assert_eq!(blocks_of(&none, 8), (vec![], true));
        // A list that cannot be walked, or a table that does not fit, or
        // no room left: not all known.
        none[6] = 0x10;
        none[0x34] = 0x20;
        assert!(!blocks_of(&none, 8).1, "a pointer into the header");
        let looped = function(0, &[(0, 0xfd00_0000)], &[(0x40, 0, 0, 0x60), (0x60, 0, 0, 0x40)]);
        assert!(!blocks_of(&looped, 64).1, "a loop");
        let mut late = none;
        late[0x34] = 0xf8;
        late[0xf8..0xfc].copy_from_slice(&[0x11, 0, 7, 0]);
        assert!(!blocks_of(&late, 8).1, "past 256 bytes");
        let f = function(0, &[(0, 0xfd00_0000)], &[(0x40, 0, 0, 0)]);
        assert!(!blocks_of(&f, 1).1, "no room");
    }

    fn madt(entries: &[&[u8]]) -> std::vec::Vec<u8> {
        let mut t = vec![0u8; 44];
        t[..4].copy_from_slice(b"APIC");
        for e in entries {
            t.extend_from_slice(e);
        }
        let len = t.len() as u32;
        t[4..8].copy_from_slice(&len.to_le_bytes());
        t
    }

    fn ioapic(id: u8, addr: u32) -> [u8; 12] {
        let mut e = [1, 12, id, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        e[4..8].copy_from_slice(&addr.to_le_bytes());
        e
    }

    #[test]
    fn every_ioapic_and_local_apic_refused() {
        // Every I/O APIC's page, once; local APICs (type 0) are not.
        let t = madt(&[&[0, 8, 0, 0, 1, 0, 0, 0], &ioapic(0, 0xfec0_0000), &ioapic(1, 0xfec0_1000),
            &ioapic(2, 0x9d00_0400), &ioapic(3, 0x9d00_0000)]);
        let (pages, complete) = madt_ioapic_pages(&t, t.len());
        assert!(complete);
        assert_eq!(&pages[..], &[(0xfec0_0000, 0x1000), (0xfec0_1000, 0x1000), (0x9d00_0000, 0x1000)]);
        // A table read in part, an entry past its end or too short for an
        // address, or more I/O APICs than are kept: not all of them.
        assert!(!madt_ioapic_pages(&t[..t.len() - 1], t.len()).1);
        let mut bad = madt(&[&ioapic(0, 0xfec0_0000)]);
        bad.truncate(bad.len() - 2);
        assert!(!madt_ioapic_pages(&bad, bad.len()).1);
        let short = madt(&[&[1, 6, 0, 0, 0, 0]]);
        assert!(!madt_ioapic_pages(&short, short.len()).1);
        let many: std::vec::Vec<[u8; 12]> = (0..=MAX_IOAPIC_PAGES as u32).map(|i| ioapic(i as u8, 0x9000_0000 + (i << 12))).collect();
        let t = madt(&many.iter().map(|e| &e[..]).collect::<std::vec::Vec<_>>());
        let (pages, complete) = madt_ioapic_pages(&t, t.len());
        assert_eq!((pages.len(), complete), (MAX_IOAPIC_PAGES, false));
        assert!(!madt_ioapic_pages(&[], 0).1);
        // The chipset's I/O APIC, a local APIC's ICR and any MSI address
        // are refused; the HPET is apart, the TPM and AMD's FCH are not.
        for (addr, width) in [(0xfec0_0000, 4), (0xfec0_0010, 4), (0xfec0_0ffc, 4), (0xfebf_fffc, 8)] {
            assert!(hw_meets(addr, width, IOAPIC_DEFAULT.0, IOAPIC_DEFAULT.1), "{addr:#x}");
        }
        // Another I/O APIC is the MADT's to name: its page, outside the
        // default one, is refused as the table lists it (trustd's Hw).
        let t = madt(&[&ioapic(0, 0xfec0_0000), &ioapic(1, 0xfec0_1000)]);
        let (pages, _) = madt_ioapic_pages(&t, t.len());
        let refused = |addr: usize| hw_meets(addr, 4, IOAPIC_DEFAULT.0, IOAPIC_DEFAULT.1)
            || pages.iter().any(|&(b, s)| hw_meets(addr, 4, b, s));
        assert!(!hw_within(0xfec0_1000, 0x1000, IOAPIC_DEFAULT.0, IOAPIC_DEFAULT.1));
        for addr in [0xfec0_1000, 0xfec0_1010, 0xfec0_1ffc] {
            assert!(refused(addr), "{addr:#x}");
        }
        for addr in [0xfec0_2000, 0xfec1_0000, 0xfec2_0000, 0xfecf_fffc] {
            assert!(!refused(addr), "{addr:#x}");
        }
        for (addr, width) in [(0xfee0_0300, 4), (0xfee0_0310, 4), (0xfeef_f000, 8)] {
            assert!(hw_meets(addr, width, LAPIC_MSI.0, LAPIC_MSI.1), "{addr:#x}");
        }
        for addr in [0xfed0_0000, 0xfed4_0000, 0xfed4_0024, 0xfed8_0300, 0xfef0_0000, 0xfebf_fffc, 0xfec1_0000, 0xfec2_0000] {
            assert!(!hw_meets(addr, 4, IOAPIC_DEFAULT.0, IOAPIC_DEFAULT.1)
                && !hw_meets(addr, 4, LAPIC_MSI.0, LAPIC_MSI.1), "{addr:#x}");
        }
    }

    fn mcfg(entries: &[(u64, u16, u8, u8)]) -> crate::fixed::ArrayVec<u8, 1024> {
        let mut t = crate::fixed::ArrayVec::new();
        t.extend_from_slice(&[0; MCFG_HEADER]).unwrap();
        for &(base, segment, lo, hi) in entries {
            t.extend_from_slice(&base.to_le_bytes()).unwrap();
            t.extend_from_slice(&segment.to_le_bytes()).unwrap();
            t.extend_from_slice(&[lo, hi, 0, 0, 0, 0]).unwrap();
        }
        t
    }

    #[test]
    fn every_ecam_window_or_none_trusted() {
        let t = mcfg(&[(0xe000_0000, 0, 0, 0x7f), (0x8_0000_0000, 1, 0, 0xff), (0xf000_0000, 0, 0x80, 0xff), (0x1000, 0, 9, 3)]);
        let (w, complete) = mcfg_windows(&t, t.len());
        assert!(complete);
        // The fourth entry has no buses.
        assert_eq!(w.len(), 3);
        assert_eq!(w[1], Ecam { base: 0x8_0000_0000, segment: 1, bus_lo: 0, bus_hi: 0xff });
        // Bus 0x80's page is at the window's base plus 0x80 MiB.
        assert_eq!(w[2].function(0xf000_0000 + (0x81 << 20) + (3 << 15) + (2 << 12) + 0x10), Some((0x81, 3, 2, 0x10)));
        assert_eq!(w[2].function(0xf000_0000 + (0x7f << 20)), None);
        assert_eq!(w[0].function(0xe000_0000 + (0x80 << 20)), None);
        assert_eq!(w[0].function(0xdfff_ffff), None);
        // A table read in part, or with more windows than are kept, is
        // not taken for the whole.
        assert!(!mcfg_windows(&t[..MCFG_HEADER + 2 * MCFG_ENTRY], t.len()).1);
        let many: [(u64, u16, u8, u8); MAX_ECAM + 1] = core::array::from_fn(|i| ((i as u64) << 28, 0, 0, 0xff));
        let t = mcfg(&many);
        let (w, complete) = mcfg_windows(&t, t.len());
        assert_eq!((w.len(), complete), (MAX_ECAM, false));
        let (w, complete) = mcfg_windows(&[], 0);
        assert!(w.is_empty() && complete);
    }

    #[test]
    fn activations_are_limited() {
        let hz = 1000;
        let mut l = ActivateLimit::default();
        let mut now = 10_000;
        for _ in 0..ACTIVATE_BURST {
            assert!(l.allow(now, hz));
        }
        assert!(!l.allow(now, hz));
        // One more for each interval that passes.
        for _ in 0..3 {
            now += hz * ACTIVATE_INTERVAL_MS / 1000;
            assert!(l.allow(now, hz));
            assert!(!l.allow(now, hz));
        }
        // A long pause gives the burst back, no more.
        now += 1_000_000;
        for _ in 0..ACTIVATE_BURST {
            assert!(l.allow(now, hz));
        }
        assert!(!l.allow(now, hz));
        assert!(!ActivateLimit { tat: u64::MAX }.allow(0, u64::MAX));
    }

    #[test]
    fn one_notice_a_guest_until_taken_and_a_tick_bounds_them() {
        let mut n = AttestNotices::new();
        assert_eq!(n.next(), None);
        // trustd names a guest over and over: one notice.
        for _ in 0..1000 {
            n.answered(5);
        }
        assert_eq!(n.next(), Some(5));
        n.posted(5, 70);
        assert_eq!(n.next(), None);
        // An answer that comes while the notice is posted waits for vmmgr
        // to take it, and is not lost.
        n.answered(5);
        n.answered(9);
        assert_eq!(n.next(), Some(9));
        n.posted(9, 71);
        assert_eq!(n.next(), None);
        // Another request's answer frees no one.
        n.taken(69);
        assert_eq!(n.next(), None);
        n.taken(70);
        assert_eq!(n.next(), Some(5));
        // A guest's allowance between two ticks.
        let mut k = 72;
        for _ in 1..ATTEST_NOTICES_PER_TICK {
            n.posted(5, k);
            n.taken(k);
            n.answered(5);
            k += 1;
        }
        assert_eq!(n.next(), None);
        // Another guest's is its own.
        n.answered(6);
        assert_eq!(n.next(), Some(6));
        n.tick();
        assert_eq!(n.next(), Some(5));
        // No guest: nothing to post.
        let mut n = AttestNotices::new();
        n.answered(MAX_RECORDS);
        n.answered(usize::MAX);
        assert_eq!(n.next(), None);
    }
}
