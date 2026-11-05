//! The serial ring: what host code prints, on its way to l4h-logd, the only
//! host code that writes the serial port (DESIGN.md §10.4).
//!
//! Every task of a partition writes whole lines to its partition's ring and
//! makes no seL4 call, so that printing neither waits nor stalls a core.
//! `Merge`, in logd, reads the rings of all partitions, oldest record first,
//! and hands out text line by line: lines cannot mix, because one task
//! prints them.
//!
//! This is separate from the log ring (`log`), so that console volume
//! cannot push diagnostics out of `l4hctl logs`.
//!
//! A secondary partition's ring and kernel console ring are in memory the
//! partition can write, so a reader believes nothing it finds there: the
//! slots are `ring`'s, lengths are clamped, and `next` limits how much of
//! a pass one ring can take.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering::SeqCst, compiler_fence};

use crate::ring::{self, Buf, Entry};

/// Slots of `Ring`, which with its header makes exactly 256 KiB. A dom0 boot
/// prints a few hundred lines. A deeper ring only makes output later: a
/// full one takes up to 20 s to print at 115200 baud, 30 s where each byte
/// costs logd a slow VM exit, and everything else waits behind a flood.
pub const CAPACITY: usize = 1023;
pub const TEXT_SIZE: usize = 232;
const WORDS: usize = TEXT_SIZE / 8;
pub const PAGES: usize = core::mem::size_of::<Ring>() / 4096;
pub const FRAME_RADIX: usize = PAGES.next_power_of_two().trailing_zeros() as usize;
const _: () = assert!(PAGES == 1 << FRAME_RADIX && PAGES == 64);
/// Where the ring is in every task of a partition.
pub const VA: usize = 0x1010_0000;
const _: () = assert!(VA >= crate::log::VA + crate::log::PAGES * 4096
    && VA + PAGES * 4096 < crate::KEEPER_STACK_TOP - crate::KEEPER_STACK_SIZE);

/// Partitions on a machine (l4h_partition::MAX_PARTITIONS).
pub const MAX_RINGS: usize = 8;

/// logd's address space: partition k's ring and kernel console ring, and
/// the part of the framebuffer it draws on.
pub const RINGS_VA: usize = crate::SHARED_VA;
pub const KERNEL_RINGS_VA: usize = crate::SHARED_VA + 0x1000_0000;
pub const KERNEL_RING_STRIDE: usize = 1 << 20;
pub const FB_VA: usize = crate::MMIO_VA;
/// The UART's registers (aarch64).
pub const UART_VA: usize = FB_VA + (1 << 30);
/// The capability to the UART's I/O ports (x86).
pub const SLOT_UART: u64 = crate::SLOT_FIRST_FREE;

/// What root tells logd.
#[repr(C)]
pub struct LogdConfig {
    pub tsc_hz: u64,
    /// The UART's first I/O port (x86).
    pub uart_base: u16,
    pub _pad: u16,
    /// Bit k: partition k's serial ring, and its kernel's console ring.
    pub rings: u32,
    pub kernel_rings: u32,
    pub kernel_ring_size: u32,
    pub kernel_ring_header: u32,
    /// The framebuffer console: a pitch of 0 means none. `fb_offset` is
    /// the distance of its top left pixel from FB_VA.
    pub fb_pitch: u32,
    pub fb_width: u32,
    pub fb_height: u32,
    pub fb_offset: u64,
}
const _: () = assert!(crate::CONFIG_OFFSET + core::mem::size_of::<LogdConfig>() <= crate::INFO_SIZE);

impl LogdConfig {
    /// Add the partitions' rings to `merge`, as mapped at these addresses.
    pub fn add_inputs(&self, merge: &mut Merge, rings_va: usize, kernel_va: usize) {
        for k in 1..MAX_RINGS {
            if self.rings & 1 << k != 0 {
                // Root mapped it for good; it is only ever read as atomics.
                let ring = unsafe { &*((rings_va + k * PAGES * 4096) as *const Ring) };
                merge.add_ring(k, ring, Some(k as u32));
            }
            if self.kernel_rings & 1 << k != 0 {
                merge.add_kernel(k, KernelRing {
                    va: kernel_va + k * KERNEL_RING_STRIDE,
                    size: self.kernel_ring_size as usize,
                    header: self.kernel_ring_header as usize,
                });
            }
        }
    }
}
/// The longest message `record` keeps, as consecutive records.
const MESSAGE_MAX: usize = 1024;
/// What one ring can take of a pass: a ring that always claims to have
/// the oldest record delays others by this much, and no more, apart from
/// `LINE_RECORDS`. Reports of what it lost count too.
const PASS_RECORDS: u32 = 64;
/// What a ring keeps of its share for the rest of a line it has started:
/// the records of the longest message. Longer lines can split where a pass
/// ends, or a line without an end would have no bound.
const LINE_RECORDS: u32 = MESSAGE_MAX.div_ceil(TEXT_SIZE) as u32;
const KERNEL_LINE_MAX: usize = 160;
/// A line handed out: its text and what `next` puts around it.
pub const LINE_MAX: usize = if TEXT_SIZE > KERNEL_LINE_MAX { TEXT_SIZE } else { KERNEL_LINE_MAX } + 48;

/// `source` bit: the record is guest N's console (N in the low bits), which
/// prints as `[vmN] ` at the start of a line.
pub const SOURCE_GUEST: u32 = 1 << 31;
/// `source` of dom0's console, which has no prefix.
pub const SOURCE_DOM0: u32 = 1 << 30;

/// Meta bit: the line goes on in the next record.
const MORE: u64 = 1;
const SOURCE_SHIFT: u32 = 1;

/// Page-aligned so that root can share its frames, and in memory shared
/// between partitions for a secondary's.
#[repr(C, align(4096))]
pub struct Ring {
    /// The sequence after the last one printed whole or reported lost,
    /// which tells root when a reset can go ahead. Only the reader writes it.
    drained: AtomicU64,
    ring: ring::Ring<CAPACITY, WORDS>,
}

impl Ring {
    pub const fn new() -> Self {
        Self { drained: AtomicU64::new(0), ring: ring::Ring::new() }
    }

    /// Write text as one line, or as the start of one if `more`: as
    /// consecutive records, which a reader prints next to each other.
    pub fn write(&self, ticks: u64, source: u32, text: &[u8], more: bool) {
        let mut n = 0;
        for_records(text, more, |_, _| n += 1);
        let mut seq = self.ring.claim(n);
        let meta = (source as u64) << SOURCE_SHIFT;
        for_records(text, more, |record, more| {
            let mut buf = Buf::<WORDS>::new();
            buf.bytes_mut()[..record.len()].copy_from_slice(record);
            self.ring.commit(seq, ticks, meta | if more { MORE } else { 0 }, record.len(), &buf);
            seq += 1;
        });
    }

    pub fn head(&self) -> u64 {
        self.ring.head()
    }

    /// Whether everything written so far has been printed.
    pub fn is_drained(&self) -> bool {
        self.drained.load(SeqCst) >= self.head()
    }

    /// Copy every record to `to`, the ring its writers move to.
    pub fn copy_to(&self, to: &Ring) {
        for seq in 0..self.head() {
            if let Entry::Ready(r) = self.ring.get(seq) {
                let at = to.ring.claim(1);
                to.ring.commit(at, r.ticks, r.meta, r.text().len(), &r.buf());
            }
        }
    }
}

/// The records of a message: one for each of its lines, split where a
/// line does not fit, with no newlines left in them.
fn for_records(mut text: &[u8], more: bool, mut f: impl FnMut(&[u8], bool)) {
    loop {
        let room = text.len().min(TEXT_SIZE);
        match text[..room].iter().position(|&c| c == b'\n') {
            Some(i) => {
                f(&text[..i], false);
                text = &text[i + 1..];
                if text.is_empty() {
                    return;
                }
            }
            None if room == text.len() => return f(text, more),
            None => {
                f(&text[..room], true);
                text = &text[room..];
            }
        }
    }
}

/// A message on the stack, marked if it does not fit.
struct Message {
    bytes: [u8; MESSAGE_MAX],
    len: usize,
    truncated: bool,
}

impl Message {
    const SUFFIX: &[u8] = b" [truncated]";

    fn finish(&mut self) -> &[u8] {
        if self.truncated {
            self.bytes[self.len..self.len + Self::SUFFIX.len()].copy_from_slice(Self::SUFFIX);
            self.len += Self::SUFFIX.len();
        }
        &self.bytes[..self.len]
    }
}

impl Write for Message {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.truncated {
            return Ok(());
        }
        let mut n = s.len().min(MESSAGE_MAX - Self::SUFFIX.len() - self.len);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        self.bytes[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        self.truncated = n < s.len();
        Ok(())
    }
}

static RING: AtomicPtr<Ring> = AtomicPtr::new(core::ptr::null_mut());
static SOURCE: AtomicU32 = AtomicU32::new(0);

/// Install this process's mapping before starting its secondary thread.
/// A later call moves to another ring.
pub fn init(ring: &'static Ring, source: u32) {
    SOURCE.store(source, SeqCst);
    RING.store(core::ptr::from_ref(ring).cast_mut(), SeqCst);
}

/// Print text of `source`, as `Ring::write`.
pub fn write(source: u32, text: &[u8], more: bool) {
    let p = RING.load(SeqCst);
    if !p.is_null() {
        // init only accepts a mapping that lives for the process's lifetime.
        unsafe { &*p }.write(crate::ticks::now(), source, text, more);
    }
}

/// Print a message of this process as one line.
pub fn record(args: fmt::Arguments<'_>) {
    let mut m = Message { bytes: [0; MESSAGE_MAX], len: 0, truncated: false };
    let _ = m.write_fmt(args);
    write(SOURCE.load(SeqCst), m.finish(), false);
}

/// A kernel console ring (kernel patch 0035): its header's first word
/// counts the bytes ever written, then the bytes follow as a circle.
#[derive(Clone, Copy)]
pub struct KernelRing {
    pub va: usize,
    pub size: usize,
    pub header: usize,
}

struct Input {
    ring: &'static Ring,
    /// Printed as `[pN] ` at the start of a line; a secondary's ring.
    partition: Option<u32>,
    cursor: u64,
    /// Records skipped since the last report.
    lost: u64,
    /// When to stop waiting for the uncommitted record at the cursor.
    deadline: Option<u64>,
    budget: u32,
}

struct KernelInput {
    ring: KernelRing,
    partition: u32,
    tail: u64,
    line: [u8; KERNEL_LINE_MAX],
    len: usize,
    budget: u32,
}

/// A line to print.
pub struct Line {
    bytes: [u8; LINE_MAX],
    len: usize,
}

impl Line {
    pub const fn new() -> Self {
        Self { bytes: [0; LINE_MAX], len: 0 }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn push(&mut self, s: &[u8]) {
        let n = s.len().min(LINE_MAX - self.len);
        self.bytes[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push(s.as_bytes());
        Ok(())
    }
}

/// What the line `next` handed out moves, once it has been printed.
#[derive(Clone, Copy)]
enum Commit {
    None,
    Ring(usize, u64),
}

/// The reader of every ring on the machine.
pub struct Merge {
    inputs: [Option<Input>; MAX_RINGS],
    kernels: [Option<KernelInput>; MAX_RINGS],
    /// The input and source of a line that has no end on the port yet.
    open: Option<(usize, u32)>,
    /// How long, in ticks, a claimed record gets to be committed.
    grace: u64,
    commit: Commit,
}

impl Merge {
    /// Start at the beginning of `home`. A writer gets `grace` ticks to
    /// commit what it claimed.
    pub fn new(home: &'static Ring, grace: u64) -> Self {
        let mut m = Self {
            inputs: [const { None }; MAX_RINGS],
            kernels: [const { None }; MAX_RINGS],
            open: None,
            grace,
            commit: Commit::None,
        };
        m.add_ring(0, home, None);
        m
    }

    /// Add secondary partition k's ring (`partition` is k), or partition
    /// 0's for k = 0.
    pub fn add_ring(&mut self, k: usize, ring: &'static Ring, partition: Option<u32>) {
        self.inputs[k] = Some(Input { ring, partition, cursor: 0, lost: 0, deadline: None, budget: PASS_RECORDS + LINE_RECORDS });
    }

    /// Add the console ring of partition k's kernel.
    pub fn add_kernel(&mut self, k: usize, ring: KernelRing) {
        self.kernels[k] = Some(KernelInput {
            ring, partition: k as u32, tail: 0, line: [0; KERNEL_LINE_MAX], len: 0, budget: PASS_RECORDS,
        });
    }

    /// Print what the rings have, each its share, until nothing is left
    /// that can be printed; false if that was nothing at all. `now` reads
    /// the clock. All of logd's reading goes through here: `next` only
    /// returns false at the end of a pass, so budgets refill only then.
    pub fn pass(&mut self, now: impl Fn() -> u64, mut print: impl FnMut(&[u8])) -> bool {
        self.begin_pass();
        let (mut line, mut printed) = (Line::new(), false);
        while self.next(now(), &mut line) {
            print(line.bytes());
            // Printed means printed: the writes above come before this.
            compiler_fence(SeqCst);
            self.commit();
            printed = true;
        }
        printed
    }

    fn begin_pass(&mut self) {
        for i in self.inputs.iter_mut().flatten() {
            i.budget = PASS_RECORDS + LINE_RECORDS;
        }
        for i in self.kernels.iter_mut().flatten() {
            i.budget = PASS_RECORDS;
        }
    }

    /// Say that the line last handed out has been printed.
    fn commit(&mut self) {
        match core::mem::replace(&mut self.commit, Commit::None) {
            Commit::None => {}
            Commit::Ring(k, seq) => {
                if let Some(i) = &self.inputs[k] {
                    i.ring.drained.store(seq, SeqCst);
                }
            }
        }
    }

    /// The next line to print, into `out`: the oldest record of any ring,
    /// or else a line of a kernel's. False if there is nothing for now.
    fn next(&mut self, now: u64, out: &mut Line) -> bool {
        out.len = 0;
        let mut best: Option<(usize, ring::Record<WORDS>)> = None;
        // The rest of an open line was claimed with it: it comes next,
        // whatever the time on the records between.
        let open = self.open.map(|(k, _)| k);
        let (mut hold, mut continues) = (false, false);
        for (k, slot) in self.inputs.iter_mut().enumerate() {
            let Some(i) = slot else { continue };
            if i.budget <= if open == Some(k) { 0 } else { LINE_RECORDS } {
                continue;
            }
            let peek = i.peek(now, self.grace);
            if i.lost != 0 {
                let lost = core::mem::take(&mut i.lost);
                i.budget -= 1;
                end_line(&mut self.open, out);
                write_prefix(out, i.partition, 0);
                let _ = write!(out, "({} lines lost)\r\n", lost);
                self.commit = Commit::Ring(k, i.cursor);
                return true;
            }
            match peek {
                Peek::Ready(r) => {
                    let rest = self.open == Some((k, (r.meta >> SOURCE_SHIFT) as u32));
                    if rest {
                        continues = true;
                    } else if i.budget <= LINE_RECORDS {
                        continue;
                    }
                    if rest || !continues && best.as_ref().is_none_or(|(_, b)| r.ticks < b.ticks) {
                        best = Some((k, r));
                    }
                }
                // Only partition 0's tasks are worth waiting for: a
                // secondary could ask for a grace period every time.
                Peek::Pending => hold |= open == Some(k) && i.partition.is_none(),
                Peek::Empty => {}
            }
        }
        if hold {
            return false;
        }
        if let Some((k, r)) = best {
            let Some(i) = &mut self.inputs[k] else { return false };
            let source = (r.meta >> SOURCE_SHIFT) as u32;
            let more = r.meta & MORE != 0;
            if self.open != Some((k, source)) {
                end_line(&mut self.open, out);
                write_prefix(out, i.partition, source);
            }
            for &c in r.text() {
                // The prefix says whose a line is: a record cannot make
                // a line that looks like someone else's.
                out.push(&[if c == b'\n' || i.partition.is_some() && c == b'\r' { b' ' } else { c }]);
            }
            if more {
                self.open = Some((k, source));
            } else {
                out.push(b"\r\n");
                self.open = None;
            }
            i.cursor += 1;
            i.budget -= 1;
            self.commit = Commit::Ring(k, i.cursor);
            return true;
        }
        for k in 0..MAX_RINGS {
            let Some(i) = &mut self.kernels[k] else { continue };
            if i.budget == 0 {
                continue;
            }
            match i.line() {
                KernelLine::None => {}
                KernelLine::Lost(n) => {
                    i.budget -= 1;
                    end_line(&mut self.open, out);
                    let _ = write!(out, "[p{}] ({} bytes lost)\r\n", k, n);
                    return true;
                }
                KernelLine::Text => {
                    i.budget -= 1;
                    end_line(&mut self.open, out);
                    let _ = write!(out, "[p{}] ", i.partition);
                    out.push(&i.line[..i.len]);
                    out.push(b"\r\n");
                    i.len = 0;
                    return true;
                }
            }
        }
        false
    }

}

fn end_line(open: &mut Option<(usize, u32)>, out: &mut Line) {
    if open.take().is_some() {
        out.push(b"\r\n");
    }
}

fn write_prefix(out: &mut Line, partition: Option<u32>, source: u32) {
    if let Some(p) = partition {
        let _ = write!(out, "[p{}] ", p);
    }
    if source & SOURCE_GUEST != 0 {
        let _ = write!(out, "[vm{}] ", source & !SOURCE_GUEST);
    }
}

enum Peek {
    Ready(ring::Record<WORDS>),
    Pending,
    Empty,
}

impl Input {
    /// The record at the cursor, skipping and counting what cannot be
    /// read: at most the ring's capacity, however wrong it is.
    fn peek(&mut self, now: u64, grace: u64) -> Peek {
        // A secondary can change this at any time: everything below comes
        // from this one read, which bounds the scan to the ring's capacity.
        let head = self.ring.head();
        // Only a secondary whose memory went wrong moves its head back.
        if self.cursor > head {
            self.cursor = head;
        }
        let oldest = head.saturating_sub(CAPACITY as u64);
        if self.cursor < oldest {
            self.lost += oldest - self.cursor;
            self.cursor = oldest;
            self.deadline = None;
        }
        while self.cursor < head {
            match self.ring.ring.get(self.cursor) {
                Entry::Ready(r) => {
                    self.deadline = None;
                    return Peek::Ready(r);
                }
                Entry::Pending => {
                    let deadline = *self.deadline.get_or_insert(now.saturating_add(grace));
                    if now < deadline {
                        return Peek::Pending;
                    }
                }
                Entry::Gone => {}
            }
            self.deadline = None;
            self.lost += 1;
            self.cursor += 1;
        }
        Peek::Empty
    }
}

enum KernelLine {
    None,
    Lost(u64),
    /// In `line` and `len`.
    Text,
}

impl KernelInput {
    /// Read up to the end of a line.
    fn line(&mut self) -> KernelLine {
        let r = self.ring;
        // The ring's mapping holds its header and `size` bytes.
        let head = unsafe { (r.va as *const u64).read_volatile() };
        let cap = (r.size - r.header) as u64;
        if head < self.tail {
            self.tail = head;
            self.len = 0;
        }
        if head - self.tail > cap {
            let lost = head - self.tail - cap;
            self.tail = head - cap;
            self.len = 0;
            return KernelLine::Lost(lost);
        }
        while self.tail < head {
            let at = r.va + r.header + (self.tail % cap) as usize;
            let c = unsafe { (at as *const u8).read_volatile() };
            self.tail += 1;
            match c {
                b'\r' => {}
                b'\n' => return KernelLine::Text,
                c => {
                    self.line[self.len] = c;
                    self.len += 1;
                    if self.len == self.line.len() {
                        return KernelLine::Text;
                    }
                }
            }
        }
        KernelLine::None
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{boxed::Box, string::String, sync::Arc, thread, vec::Vec};

    const GRACE: u64 = 100;

    fn ring() -> &'static Ring {
        // Too large for a test thread's stack; all zeroes is Ring::new().
        unsafe { &*std::alloc::alloc_zeroed(std::alloc::Layout::new::<Ring>()).cast() }
    }

    /// Everything `m` prints at time `now`.
    fn drain(m: &mut Merge, now: u64) -> String {
        let mut s = String::new();
        for _ in 0..100_000 {
            if !m.pass(|| now, |line| s.push_str(core::str::from_utf8(line).unwrap())) {
                break;
            }
        }
        s
    }

    #[test]
    fn lines_print_whole_with_prefixes_and_crlf() {
        let (home, other) = (ring(), ring());
        let mut m = Merge::new(home, GRACE);
        m.add_ring(1, other, Some(1));
        home.write(10, 0, b"root line", false);
        other.write(20, SOURCE_GUEST | 3, b"guest line", false);
        home.write(30, SOURCE_GUEST | 2, b"vm2 line", false);
        other.write(40, 0, b"secondary root", false);
        assert_eq!(
            drain(&mut m, 50),
            "root line\r\n[p1] [vm3] guest line\r\n[vm2] vm2 line\r\n[p1] secondary root\r\n"
        );
        assert_eq!(home.drained.load(SeqCst), 2);
        assert_eq!(other.drained.load(SeqCst), 2);
        assert_eq!(drain(&mut m, 60), "");
    }

    #[test]
    fn long_and_multi_line_messages_become_consecutive_records() {
        let home = ring();
        let long = "x".repeat(TEXT_SIZE * 2 + 5);
        home.write(1, 0, std::format!("{long}\nsecond\n").as_bytes(), false);
        assert_eq!(home.head(), 4);
        let mut m = Merge::new(home, GRACE);
        assert_eq!(drain(&mut m, 2), std::format!("{long}\r\nsecond\r\n"));
    }

    #[test]
    fn an_empty_line_is_a_line() {
        let home = ring();
        home.write(1, 0, b"", false);
        home.write(1, 0, b"\n", false);
        let mut m = Merge::new(home, GRACE);
        assert_eq!(drain(&mut m, 2), "\r\n\r\n");
    }

    #[test]
    fn a_partial_line_is_continued_or_ended_by_another_source() {
        let home = ring();
        let mut m = Merge::new(home, GRACE);
        home.write(1, SOURCE_GUEST | 1, b"login: ", true);
        assert_eq!(drain(&mut m, 2), "[vm1] login: ");
        home.write(3, SOURCE_GUEST | 1, b"root", false);
        assert_eq!(drain(&mut m, 4), "root\r\n");
        home.write(5, SOURCE_GUEST | 1, b"# ", true);
        home.write(6, 0, b"host", false);
        home.write(7, SOURCE_GUEST | 1, b"ls", false);
        assert_eq!(drain(&mut m, 8), "[vm1] # \r\nhost\r\n[vm1] ls\r\n");
    }

    #[test]
    fn wrapping_reports_lost_lines_once() {
        let home = ring();
        for i in 0..CAPACITY + 17 {
            home.write(i as u64, 0, std::format!("record {i}").as_bytes(), false);
        }
        let mut m = Merge::new(home, GRACE);
        let text = drain(&mut m, u64::MAX);
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("(17 lines lost)"));
        assert_eq!(lines.next(), Some("record 17"));
        assert_eq!(lines.count(), CAPACITY - 1);
        assert_eq!(text.matches("lost").count(), 1);
    }

    #[test]
    fn a_stranded_slot_waits_its_grace_and_then_counts_as_lost() {
        let home = ring();
        home.ring.claim(1);
        home.write(1, 0, b"after", false);
        let mut m = Merge::new(home, GRACE);
        assert_eq!(drain(&mut m, 1000), "");
        assert_eq!(drain(&mut m, 1000 + GRACE - 1), "");
        assert_eq!(drain(&mut m, 1000 + GRACE), "(1 lines lost)\r\nafter\r\n");
    }

    #[test]
    fn a_late_commit_within_the_grace_is_not_lost() {
        let home = ring();
        let seq = home.ring.claim(1);
        let mut m = Merge::new(home, GRACE);
        assert_eq!(drain(&mut m, 10), "");
        let mut buf = Buf::new();
        buf.bytes_mut()[..4].copy_from_slice(b"late");
        home.ring.commit(seq, 1, 0, 4, &buf);
        assert_eq!(drain(&mut m, 20), "late\r\n");
    }

    #[test]
    fn the_rest_of_an_open_line_holds_other_rings_back() {
        let (home, other) = (ring(), ring());
        let mut m = Merge::new(home, GRACE);
        m.add_ring(1, other, Some(1));
        let seq = home.ring.claim(2);
        let mut buf = Buf::new();
        buf.bytes_mut()[..3].copy_from_slice(b"one");
        home.ring.commit(seq, 1, MORE, 3, &buf);
        other.write(2, 0, b"other", false);
        assert_eq!(drain(&mut m, 10), "one");
        buf.bytes_mut()[..3].copy_from_slice(b"two");
        home.ring.commit(seq + 1, 3, 0, 3, &buf);
        assert_eq!(drain(&mut m, 11), "two\r\n[p1] other\r\n");
    }

    #[test]
    fn corrupt_records_of_a_secondary_are_skipped_and_reported() {
        let (home, other) = (ring(), ring());
        let mut m = Merge::new(home, GRACE);
        m.add_ring(1, other, Some(1));
        other.write(1, 0, b"good", false);
        other.write(2, 0, b"bad length", false);
        // A length past the slot, a state from the future, and a record
        // that tries to start a line of its own.
        let slots = unsafe { core::slice::from_raw_parts(other.ring.slots.as_ptr().cast::<[AtomicU64; 32]>(), CAPACITY) };
        slots[1][1].store(0xffff, SeqCst);
        other.write(3, 0, b"from the future", false);
        slots[2][0].store(1 << 40, SeqCst);
        other.write(4, 0, b"a\nb\rc", false);
        home.write(5, 0, b"home", false);
        assert_eq!(
            drain(&mut m, 10),
            "[p1] good\r\n[p1] (2 lines lost)\r\n[p1] a\r\n[p1] b c\r\nhome\r\n"
        );
    }

    #[test]
    fn a_wild_head_cannot_stop_the_reader_or_other_rings() {
        let (home, other) = (ring(), ring());
        let mut m = Merge::new(home, GRACE);
        m.add_ring(1, other, Some(1));
        other.ring.head.store(u64::MAX, SeqCst);
        home.write(5, 0, b"home", false);
        let text = drain(&mut m, u64::MAX);
        assert!(text.contains("home\r\n"), "{text}");
        other.ring.head.store(3, SeqCst);
        home.write(5, 0, b"again", false);
        assert!(drain(&mut m, u64::MAX).contains("again\r\n"));
    }

    #[test]
    fn a_flood_with_the_oldest_timestamps_shares_each_pass() {
        let (home, other) = (ring(), ring());
        let mut m = Merge::new(home, GRACE);
        m.add_ring(1, other, Some(1));
        for _ in 0..1000 {
            other.write(0, 0, b"flood", false);
        }
        home.write(5, 0, b"home", false);
        let (mut line, mut before) = (Line::new(), 0);
        loop {
            assert!(m.next(10, &mut line));
            if line.bytes() == b"home\r\n" {
                break;
            }
            before += 1;
        }
        assert_eq!(before, PASS_RECORDS);
    }

    /// Run logd's loop while `attack` acts before each pass, and say how
    /// many passes went by until `home` printed.
    fn passes_until_home(m: &mut Merge, mut attack: impl FnMut()) -> Option<usize> {
        let mut now = 10;
        for pass in 0..2000 {
            attack();
            let mut home = false;
            let printed = m.pass(|| now, |line| home |= line.ends_with(b"home\r\n"));
            if home {
                return Some(pass);
            }
            if !printed {
                now += 10;
            }
        }
        None
    }

    #[test]
    fn a_secondary_cannot_hold_others_back_with_lines_it_never_ends() {
        let (home, other) = (ring(), ring());
        let mut m = Merge::new(home, GRACE);
        m.add_ring(1, other, Some(1));
        home.write(5, 0, b"home", false);
        // The start of a line claiming to be the oldest, and never its rest.
        let attack = || {
            let seq = other.ring.claim(2);
            let mut buf = Buf::new();
            buf.bytes_mut()[0] = b'x';
            other.ring.commit(seq, 0, MORE, 1, &buf);
        };
        assert_eq!(passes_until_home(&mut m, attack), Some(0));
    }

    #[test]
    fn a_secondary_cannot_hold_others_back_with_lost_reports() {
        let (home, other) = (ring(), ring());
        let mut m = Merge::new(home, GRACE);
        m.add_ring(1, other, Some(1));
        home.write(5, 0, b"home", false);
        // Each report needs a record to skip: one for every `next`.
        let (mut line, mut before) = (Line::new(), 0);
        for _ in 0..PASS_RECORDS * 2 {
            other.ring.claim(1);
            other.ring.slots[other.head() as usize - 1].state.store(u64::MAX, SeqCst);
            assert!(m.next(10, &mut line));
            if line.bytes() == b"home\r\n" {
                break;
            }
            before += 1;
        }
        assert_eq!(before, PASS_RECORDS);
    }

    #[test]
    fn a_kernel_ring_cannot_hold_others_back_with_lost_reports() {
        let (mut bad, mut good) = (Kernel::new(), Kernel::new());
        let mut m = Merge::new(ring(), GRACE);
        m.add_kernel(1, bad.ring());
        m.add_kernel(2, good.ring());
        good.print(b"good\n");
        let (mut line, mut before) = (Line::new(), 0);
        loop {
            bad.0[0] += 1000;
            assert!(m.next(10, &mut line));
            if line.bytes() == b"[p2] good\r\n" {
                break;
            }
            before += 1;
        }
        assert_eq!(before, PASS_RECORDS);
    }

    #[test]
    fn the_slot_of_a_writer_that_died_in_commit_is_taken_back() {
        let home = ring();
        let mut m = Merge::new(home, GRACE);
        // Sequence 0 died between claiming the slot and committing it.
        let seq = home.ring.claim(1);
        home.ring.slots[seq as usize].state.store(1, SeqCst);
        assert_eq!(drain(&mut m, GRACE), "");
        assert_eq!(drain(&mut m, GRACE * 2), "(1 lines lost)\r\n");
        let mut text = String::new();
        for i in 1..=CAPACITY * 2 {
            home.write(i as u64, 0, std::format!("record {i}").as_bytes(), false);
            text += &drain(&mut m, GRACE * 3);
        }
        assert_eq!(text.lines().count(), CAPACITY * 2);
        assert!(!text.contains("lost"), "{text}");
    }

    #[test]
    fn a_writer_a_lap_behind_cannot_undo_its_slot_being_taken_back() {
        let home = ring();
        let seq = home.ring.claim(1);
        home.ring.slots[seq as usize].state.store(1, SeqCst);
        home.ring.head.store(CAPACITY as u64, SeqCst);
        home.write(1, 0, b"new", false);
        // The slot's old writer wakes up and tries again.
        let mut buf = Buf::new();
        buf.bytes_mut()[..3].copy_from_slice(b"old");
        home.ring.commit(seq, 2, 0, 3, &buf);
        let Entry::Ready(r) = home.ring.get(CAPACITY as u64) else { panic!("record gone") };
        assert_eq!(r.text(), b"new");
    }

    #[test]
    fn a_writer_leaves_a_slot_a_later_writer_is_in() {
        let home = ring();
        home.ring.slots[0].state.store(2 * CAPACITY as u64 + 1, SeqCst);
        home.ring.commit(0, 1, 0, 0, &Buf::new());
        assert_eq!(home.ring.slots[0].state.load(SeqCst), 2 * CAPACITY as u64 + 1);
    }

    #[test]
    fn a_head_that_changes_between_reads_cannot_stop_the_reader() {
        let (home, other) = (ring(), ring());
        let mut m = Merge::new(home, GRACE);
        m.add_ring(1, other, Some(1));
        home.write(5, 0, b"home", false);
        let stop: &'static AtomicU64 = std::boxed::Box::leak(Box::new(AtomicU64::new(0)));
        let attacker = thread::spawn(move || {
            while stop.load(SeqCst) == 0 {
                other.ring.head.store(u64::MAX, SeqCst);
                other.ring.head.store((1 << 63) + 2 * CAPACITY as u64, SeqCst);
            }
        });
        let (done, finished) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let start = std::time::Instant::now();
            while start.elapsed().as_secs() < 1 {
                m.pass(|| 0, |_| {});
            }
            let _ = done.send(());
        });
        let result = finished.recv_timeout(std::time::Duration::from_secs(20));
        stop.store(1, SeqCst);
        attacker.join().unwrap();
        result.expect("the reader stopped");
    }

    #[test]
    fn a_line_is_not_split_where_its_ring_runs_out_of_budget() {
        let (home, other) = (ring(), ring());
        let mut m = Merge::new(home, GRACE);
        m.add_ring(1, other, Some(1));
        for i in 0..PASS_RECORDS - 1 {
            home.write(1, 0, std::format!("record {i}").as_bytes(), false);
        }
        let long = "x".repeat(TEXT_SIZE + 10);
        home.write(2, 0, long.as_bytes(), false);
        other.write(3, 0, b"other", false);
        let text = drain(&mut m, 10);
        assert!(text.contains(&std::format!("\n{long}\r\n")), "{text}");
        assert!(text.ends_with("[p1] other\r\n"), "{text}");
    }

    #[test]
    fn the_longest_message_is_not_split_where_its_ring_runs_out_of_budget() {
        let (home, other) = (ring(), ring());
        let mut m = Merge::new(home, GRACE);
        m.add_ring(1, other, Some(1));
        for i in 0..PASS_RECORDS - 1 {
            home.write(1, 0, std::format!("record {i}").as_bytes(), false);
        }
        let long = "x".repeat(MESSAGE_MAX);
        home.write(2, 0, long.as_bytes(), false);
        other.write(3, 0, b"other", false);
        assert!(drain(&mut m, 10).contains(&std::format!("\n{long}\r\n")));
    }

    #[test]
    fn a_line_without_an_end_cannot_keep_a_ring_going_past_its_reserve() {
        let (home, other) = (ring(), ring());
        let mut m = Merge::new(home, GRACE);
        m.add_ring(1, other, Some(1));
        for _ in 0..1000 {
            other.write(0, 0, b"x", true);
        }
        home.write(5, 0, b"home", false);
        let (mut line, mut before) = (Line::new(), 0);
        loop {
            assert!(m.next(10, &mut line));
            if line.bytes().ends_with(b"home\r\n") {
                break;
            }
            before += 1;
        }
        assert_eq!(before, PASS_RECORDS + LINE_RECORDS);
    }

    #[test]
    fn a_stranded_last_record_does_not_keep_a_ring_undrained() {
        let home = ring();
        let mut m = Merge::new(home, GRACE);
        home.write(1, 0, b"line", false);
        home.ring.claim(1);
        assert_eq!(drain(&mut m, 10), "line\r\n");
        assert!(!home.is_drained());
        assert_eq!(drain(&mut m, 10 + GRACE), "(1 lines lost)\r\n");
        assert!(home.is_drained());
    }

    #[test]
    fn a_ring_is_drained_once_its_last_line_is_printed_whole() {
        let home = ring();
        let mut m = Merge::new(home, GRACE);
        assert!(home.is_drained());
        home.write(1, 0, b"line", false);
        assert!(!home.is_drained());
        let mut line = Line::new();
        assert!(m.next(2, &mut line));
        assert!(!home.is_drained());
        m.commit();
        assert!(home.is_drained());
    }

    struct Kernel(Box<[u64; 32]>);

    impl Kernel {
        const HEADER: usize = 64;
        const SIZE: usize = 256;
        fn new() -> Self {
            Self(Box::new([0; 32]))
        }
        fn ring(&self) -> KernelRing {
            KernelRing { va: self.0.as_ptr() as usize, size: Self::SIZE, header: Self::HEADER }
        }
        fn print(&mut self, s: &[u8]) {
            let base = self.0.as_mut_ptr().cast::<u8>();
            let cap = (Self::SIZE - Self::HEADER) as u64;
            for &c in s {
                let head = self.0[0];
                unsafe { base.add(Self::HEADER + (head % cap) as usize).write(c) };
                self.0[0] = head + 1;
            }
        }
    }

    #[test]
    fn kernel_rings_print_by_line_and_report_loss() {
        let home = ring();
        let mut k = Kernel::new();
        let mut m = Merge::new(home, GRACE);
        m.add_kernel(2, k.ring());
        k.print(b"boot\r\npar");
        assert_eq!(drain(&mut m, 1), "[p2] boot\r\n");
        k.print(b"tial\n");
        assert_eq!(drain(&mut m, 2), "[p2] partial\r\n");
        k.print(&[b'a'; 300]);
        k.print(b"\n");
        let text = drain(&mut m, 3);
        assert!(text.starts_with("[p2] (109 bytes lost)\r\n[p2] aaa"), "{text}");
    }

    #[test]
    fn concurrent_writers_keep_their_lines_whole() {
        // Few enough records never to wrap, so that none may be lost.
        const MESSAGES: usize = 80;
        let home: Arc<&'static Ring> = Arc::new(ring());
        let writers: Vec<_> = (0..4u32).map(|id| {
            let ring = Arc::clone(&home);
            thread::spawn(move || {
                for i in 0..MESSAGES {
                    let body = std::format!("{id}:{i}:{}", "x".repeat(i % 200));
                    ring.write(i as u64, id, std::format!("{body}|{body}").as_bytes(), false);
                }
            })
        }).collect();
        let (mut m, mut text) = (Merge::new(*home, u64::MAX / 2), Vec::new());
        loop {
            let finished = writers.iter().all(|w| w.is_finished());
            let any = m.pass(|| 0, |line| text.extend_from_slice(line));
            if !any && finished {
                break;
            }
            thread::yield_now();
        }
        for writer in writers {
            writer.join().unwrap();
        }
        let text = String::from_utf8(text).unwrap();
        for l in text.lines() {
            let (a, b) = l.split_once('|').unwrap();
            assert_eq!(a, b);
        }
        assert_eq!(text.lines().count(), 4 * MESSAGES);
    }
}
