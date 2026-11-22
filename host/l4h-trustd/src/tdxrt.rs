//! Intel TDX attestation at run time (tdx.rs has the formats): the key's
//! binding at start, and guests' fresh quotes (abi::ATTEST_TDX_QUOTE).
//!
//! A quote is the VMM's to make, in the frame root shares with it
//! (trust::TDX_QUOTE_VA), and takes it from milliseconds to seconds: trustd
//! never waits for one.  It has one quote out at a time, the key's at
//! start, then one guest's; it looks at the frame each time it wakes, and
//! root wakes it on its timer meanwhile (trust::Status::wake).  When the
//! VMM is done, trustd copies the frame once into its own memory and
//! parses only the copy: the VMM can write the frame at any time.
//!
//! A guest's quote is kept for it a few seconds (HOLD_MS), so that it can
//! read it in pieces past a page; meanwhile other guests' quote requests
//! wait (DEFER), their other requests do not.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_abi as abi;
use l4h_rt::host::errno::{EAGAIN, EIO, Errno};
use l4h_rt::host::trust;
use l4h_rt::{host, info};
use l4h_task::tdx as call;

use crate::tdx::{self, Answer, Asker, Holding, REPORT_SIZE, Step};
use crate::{DEFER, PENDING};

/// The key's quote: asked for again after the VMM's errors for up to
/// two minutes (its quoting service may start after this TD).
const START_TIMEOUT_MS: u64 = 120_000;
/// A guest's quote, as Linux's TDX driver waits for one.
const QUOTE_TIMEOUT_MS: u64 = 30_000;
/// Asking the VMM again after it was busy or its service unavailable.
const RETRY_MS: u64 = 1000;
/// How long a guest's quote is kept for its further pieces.
const HOLD_MS: u64 = 10_000;

/// A quote: header, body and signature data (with the PCK certificate
/// chain), within the GetQuote buffer.
pub const QUOTE_MAX: usize = trust::TDX_QUOTE_BUF - tdx::GHCI_HEADER;
/// The TDX evidence: the key (about 80 bytes) and the quote.
pub const EVIDENCE_MAX: usize = QUOTE_MAX + 128;
/// A guest's quote answer: the key, the quote, the report.
const ANSWER_MAX: usize = QUOTE_MAX + 128 + crate::REPORT_MAX;

/// trustd's own memory for the frame's copy and what it builds from it:
/// too large for its stack, and never two at once (one quote out).
struct Bufs {
    copy: [u8; trust::TDX_QUOTE_BUF],
    evidence: [u8; EVIDENCE_MAX],
    answer: [u8; ANSWER_MAX],
}

static mut BUFS: Bufs = Bufs { copy: [0; trust::TDX_QUOTE_BUF], evidence: [0; EVIDENCE_MAX], answer: [0; ANSWER_MAX] };

/// A quote the VMM is asked for.
struct Job {
    report: [u8; REPORT_SIZE],
    /// GetQuote was called (else it is to be, at next_try).
    submitted: bool,
    next_try: u64,
    deadline: u64,
}

enum Phase {
    /// The key's quote is out.
    Starting(Job),
    /// The evidence, its first `n` bytes.
    Ready(usize),
    Failed,
}

enum Slot {
    Idle,
    /// A guest's quote is out: its request `seq`, the report it is over.
    Quoting { job: Job, asker: Asker, seq: u32, report: crate::Buf<{ crate::REPORT_MAX }> },
    /// A guest's answer, the first `n` bytes of BUFS.answer, kept for its
    /// further pieces until `expires`.
    Held { asker: Asker, n: usize, expires: u64 },
}

pub struct Tdx {
    point: [u8; 65],
    /// RTMR 3 since trustd extended it with the key's binding.
    rtmr3: [u8; 48],
    hz: u64,
    phase: Phase,
    slot: Slot,
    bufs: &'static mut Bufs,
}

/// What a wake-up brought.
pub enum Event {
    /// The key's quote: TDX attestation is ready, or failed for good.
    Ready,
    Failed,
    /// Guest `id`'s quote (instance, request seq): its answer (in
    /// Tdx::answer) or why there is none.
    Quoted { id: usize, instance: u64, seq: u32, result: Result<usize, Errno> },
}

fn ms(hz: u64, ms: u64) -> u64 {
    hz.saturating_mul(ms) / 1000
}

fn frame() -> *mut u8 {
    trust::TDX_QUOTE_VA as *mut u8
}

/// The status word of the shared frame, as the VMM last wrote it.
fn shared_status() -> u64 {
    unsafe { (frame().add(tdx::GHCI_STATUS) as *const u64).read_volatile() }
}

/// TDG.MR.REPORT with `data`: the TDREPORT, copied from the report frame.
fn get_report(data: &[u8; 64]) -> Result<[u8; REPORT_SIZE], call::Error> {
    call::get_report(trust::SLOT_TDX, trust::SLOT_TDX_REPORT_FRAME, data)?;
    fence(Ordering::SeqCst);
    let mut r = [0u8; REPORT_SIZE];
    let src = trust::TDX_REPORT_VA as *const u8;
    for (i, b) in r.iter_mut().enumerate() {
        *b = unsafe { src.add(i).read_volatile() };
    }
    Ok(r)
}

impl Job {
    fn new(report: [u8; REPORT_SIZE], now: u64, timeout: u64) -> Job {
        Job { report, submitted: false, next_try: now, deadline: now.saturating_add(timeout) }
    }
}

/// How a job stands.
enum Progress {
    Waiting,
    /// The quote: the first `n` bytes of BUFS.copy past the GHCI header.
    Done(usize),
    Failed(&'static str),
}

impl Tdx {
    /// Bind `point` (the signing key) to the TD: its TDREPORT, taken while
    /// RTMR 3 is zero, then RTMR 3 extended with the binding, then the
    /// quote asked for.  None if the TD cannot attest.
    pub fn start(point: &[u8; 65], hz: u64) -> Result<Tdx, &'static str> {
        let binding = tdx::key_binding(point);
        let data = tdx::report_data(&binding);
        let report = get_report(&data).map_err(|e| {
            info!("l4h-trustd: TDG.MR.REPORT failed: {}", e);
            "TDG.MR.REPORT failed"
        })?;
        tdx::check_first_report(&report, &data)?;
        // Before the quote is asked for, so that no other key gets one with
        // RTMR 3 zero.
        call::extend_rtmr(trust::SLOT_TDX, tdx::KEY_RTMR as u64, &binding).map_err(|e| {
            info!("l4h-trustd: TDG.MR.RTMR.EXTEND failed: {}", e);
            "TDG.MR.RTMR.EXTEND failed"
        })?;
        // trustd is the only one to use the frame: anything there is from
        // before it ran.
        let bufs = unsafe { &mut *core::ptr::addr_of_mut!(BUFS) };
        let now = host::ticks::now();
        Ok(Tdx {
            point: *point,
            rtmr3: tdx::rtmr_extended(&binding),
            hz,
            phase: Phase::Starting(Job::new(report, now, ms(hz, START_TIMEOUT_MS))),
            slot: Slot::Idle,
            bufs,
        })
    }

    pub fn ready(&self) -> bool {
        matches!(self.phase, Phase::Ready(_))
    }

    pub fn starting(&self) -> bool {
        matches!(self.phase, Phase::Starting(_))
    }

    /// Whether trustd should be woken on root's timer: a quote is out, or
    /// a guest's answer is kept.
    pub fn busy(&self) -> bool {
        self.starting() || !matches!(self.slot, Slot::Idle)
    }

    /// The TDX evidence (abi::ATTEST_TDX_EVIDENCE), once ready.
    pub fn evidence(&self) -> Option<&[u8]> {
        match self.phase {
            Phase::Ready(n) => Some(&self.bufs.evidence[..n]),
            _ => None,
        }
    }

    /// The answer of an Event::Quoted.
    pub fn answer(&self, n: usize) -> &[u8] {
        &self.bufs.answer[..n]
    }

    /// Ask for `job`'s quote, or see whether it came.
    fn progress(job: &mut Job, bufs: &mut Bufs, now: u64, hz: u64) -> Progress {
        if !job.submitted {
            if now < job.next_try {
                return Progress::Waiting;
            }
            if now >= job.deadline {
                return Progress::Failed("no quote in time");
            }
            // A quote the VMM still makes (one that timed out): the frame
            // is its until it is done.
            if shared_status() == tdx::GET_QUOTE_IN_FLIGHT {
                job.next_try = now.saturating_add(ms(hz, RETRY_MS));
                return Progress::Waiting;
            }
            let req = tdx::ghci_request(&job.report);
            unsafe {
                for i in 0..trust::TDX_QUOTE_BUF {
                    frame().add(i).write_volatile(req.get(i).copied().unwrap_or(0));
                }
            }
            fence(Ordering::SeqCst);
            match call::get_quote(trust::SLOT_TDX, trust::SLOT_TDX_QUOTE_FRAME, trust::TDX_QUOTE_BUF as u64) {
                Ok(()) => job.submitted = true,
                Err(call::Error::Status(call::VMCALL_RETRY)) => job.next_try = now.saturating_add(ms(hz, RETRY_MS)),
                Err(e) => {
                    info!("l4h-trustd: TDG.VP.VMCALL<GetQuote> failed: {}", e);
                    return Progress::Failed("GetQuote refused");
                }
            }
            return Progress::Waiting;
        }
        let status = shared_status();
        if status == tdx::GET_QUOTE_IN_FLIGHT {
            return if now >= job.deadline { Progress::Failed("no quote in time") } else { Progress::Waiting };
        }
        // Done, or about to be: one copy, then only the copy is read.
        fence(Ordering::Acquire);
        for (i, b) in bufs.copy.iter_mut().enumerate() {
            *b = unsafe { frame().add(i).read_volatile() };
        }
        match tdx::ghci_answer(&bufs.copy) {
            Ok(Answer::Pending) if now < job.deadline => Progress::Waiting,
            Ok(Answer::Pending) => Progress::Failed("no quote in time"),
            Ok(Answer::Failed(s)) if now < job.deadline => {
                let why = if s == tdx::GET_QUOTE_SERVICE_UNAVAILABLE { "its quoting service is unavailable" } else { "error" };
                info!("l4h-trustd: the VMM failed a quote ({}, {:#x}): asking again", why, s);
                job.submitted = false;
                job.next_try = now.saturating_add(ms(hz, RETRY_MS));
                Progress::Waiting
            }
            Ok(Answer::Failed(_)) => Progress::Failed("the VMM failed the quote"),
            Ok(Answer::Quote(q)) => match tdx::check_quote(q, &job.report) {
                Ok(n) => Progress::Done(n),
                Err(why) => Progress::Failed(why),
            },
            Err(why) => Progress::Failed(why),
        }
    }

    /// Look at what is out: what came, if anything.
    pub fn poll(&mut self) -> Option<Event> {
        let now = host::ticks::now();
        if let Phase::Starting(job) = &mut self.phase {
            return match Self::progress(job, self.bufs, now, self.hz) {
                Progress::Waiting => None,
                Progress::Done(n) => {
                    let bufs = &mut *self.bufs;
                    let q = &bufs.copy[tdx::GHCI_HEADER..tdx::GHCI_HEADER + n];
                    match tdx::encode_evidence(&mut bufs.evidence, &self.point, q) {
                        Ok(len) => {
                            self.phase = Phase::Ready(len);
                            Some(Event::Ready)
                        }
                        Err(_) => {
                            info!("l4h-trustd: TDX evidence larger than {} bytes", EVIDENCE_MAX);
                            self.phase = Phase::Failed;
                            Some(Event::Failed)
                        }
                    }
                }
                Progress::Failed(why) => {
                    l4h_rt::log!("l4h-trustd: no TDX attestation: the key's quote: {}", why);
                    self.phase = Phase::Failed;
                    Some(Event::Failed)
                }
            };
        }
        match &mut self.slot {
            Slot::Idle => None,
            Slot::Held { expires, .. } => {
                if now >= *expires {
                    self.slot = Slot::Idle;
                }
                None
            }
            Slot::Quoting { job, asker, seq, report } => {
                let (asker, seq) = (*asker, *seq);
                let result = match Self::progress(job, self.bufs, now, self.hz) {
                    Progress::Waiting => return None,
                    Progress::Done(n) => {
                        let bufs = &mut *self.bufs;
                        let q = &bufs.copy[tdx::GHCI_HEADER..tdx::GHCI_HEADER + n];
                        tdx::encode_quote_answer(&mut bufs.answer, &self.point, q, report.get()).map_err(|_| EIO)
                    }
                    Progress::Failed(why) => {
                        info!("l4h-trustd: guest {}: no TDX quote: {}", asker.id, why);
                        Err(EIO)
                    }
                };
                self.slot = match result {
                    // The first piece goes out now; more are asked for.
                    Ok(n) if n > abi::ATTEST_PAGE_DATA => Slot::Held { asker, n, expires: now.saturating_add(ms(self.hz, HOLD_MS)) },
                    _ => Slot::Idle,
                };
                Some(Event::Quoted { id: asker.id, instance: asker.instance, seq, result })
            }
        }
    }

    /// The slot as a request sees it (tdx::decide).
    fn holding(&self) -> Holding {
        match self.slot {
            Slot::Idle => Holding::Idle,
            Slot::Quoting { asker, .. } => Holding::Quoting(asker),
            Slot::Held { asker, n, expires } => Holding::Held { asker, n, expires },
        }
    }

    /// Guest `id`'s (instance `instance`) answer is no longer wanted (the
    /// guest went away, or was replaced, while its quote was out): the
    /// slot is free for the others now, not when it expires.
    pub fn release_held(&mut self, id: usize, instance: u64) {
        if let Slot::Held { asker, .. } = self.slot {
            if asker.id == id && asker.instance == instance {
                self.slot = Slot::Idle;
            }
        }
    }

    /// Guest `id`'s (instance `instance`) quote request `seq` with `data`
    /// and the page's `offset`: its kept answer (a further piece), or
    /// PENDING once its quote is asked for, DEFER while another guest's
    /// is out or kept, or an errno.  `others_waiting`: other guests'
    /// requests wait, which go before this guest's new quote if it holds
    /// the slot.  `allow` counts it against the guest's rate limit;
    /// `report` makes its report.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &mut self,
        id: usize,
        instance: u64,
        seq: u32,
        data: &[u8; abi::ATTEST_DATA_SIZE],
        offset: usize,
        others_waiting: bool,
        allow: impl FnOnce() -> bool,
        report: impl FnOnce(&mut [u8]) -> Result<usize, Errno>,
    ) -> Result<&[u8], Errno> {
        let now = host::ticks::now();
        let me = Asker { id, instance, data: *data };
        if !self.ready() {
            return Err(if self.starting() { DEFER } else { l4h_rt::host::errno::ENODEV });
        }
        match tdx::decide(&self.holding(), &me, offset, now, others_waiting, abi::ATTEST_PAGE_DATA) {
            Step::Serve { n, release } => {
                if release {
                    self.slot = Slot::Idle;
                }
                return Ok(&self.bufs.answer[..n]);
            }
            Step::Defer { release } => {
                if release {
                    self.slot = Slot::Idle;
                }
                return Err(DEFER);
            }
            Step::Again => {
                self.slot = Slot::Idle;
                return Err(EAGAIN);
            }
            Step::Start => self.slot = Slot::Idle,
        }
        if !allow() {
            return Err(EAGAIN);
        }
        let mut rep = [0u8; crate::REPORT_MAX];
        let n = report(&mut rep)?;
        let report = crate::Buf::of(&rep[..n]).ok_or(EIO)?;
        let t = get_report(&tdx::guest_report_data(report.get())).map_err(|e| {
            info!("l4h-trustd: guest {}: TDG.MR.REPORT failed: {}", id, e);
            EIO
        })?;
        // The key is still the TD's first: nothing else extends RTMR 3.
        if tdx::rtmr(&t, tdx::KEY_RTMR) != &self.rtmr3 {
            l4h_rt::log!("l4h-trustd: RTMR 3 is no longer the key's: no TDX quote");
            return Err(EIO);
        }
        self.slot = Slot::Quoting { job: Job::new(t, now, ms(self.hz, QUOTE_TIMEOUT_MS)), asker: me, seq, report };
        // Asked for now, if the VMM takes it (and answered, if it was that
        // quick).
        match self.poll() {
            Some(Event::Quoted { result: Ok(n), .. }) => Ok(&self.bufs.answer[..n]),
            Some(Event::Quoted { result: Err(e), .. }) => Err(e),
            _ => Err(PENDING),
        }
    }
}

/// Every request page's state (abi::AttestPage::state).
pub fn set_states(state: u32) {
    for p in 0..trust::PAGES {
        unsafe { addr_of_mut!((*crate::page(p)).state).write_volatile(state) };
    }
}

/// The request page's offset.
pub fn offset(p: *mut abi::AttestPage) -> usize {
    unsafe { addr_of!((*p).offset).read_volatile() as usize }
}
