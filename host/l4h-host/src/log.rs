//! Bounded host diagnostics shared by root and every host component
//! (DESIGN.md §10, "Host log").
//!
//! Each writer has a lane of its own: a `ring` of records in frames that
//! only it, and the task that spawned it, can write. A component cannot
//! write, overwrite or erase another's records, and vmmgr, which reads
//! every lane read-only for `l4hctl logs`, takes whose a record is from the
//! lane it is in, never from the record. Lanes are fixed at start, one per
//! writer there can be (`Writer`); the area that holds them is a static of
//! root's. Readers skip unavailable records and report the gap.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst};

use crate::ring::{self, Buf, Entry, View};

pub const TEXT_SIZE: usize = 480;
const WORDS: usize = TEXT_SIZE / 8;
const PAGE: usize = 4096;
/// Where a writer maps its own lane.
pub const VA: usize = 0x1002_0000;
/// Where vmmgr, the reader, maps the whole area, read-only.
pub const READ_VA: usize = 0x5200_0000_0000;
pub const PAGES: usize = core::mem::size_of::<Ring>() / PAGE;
/// The guests' VMMs' lanes, the area's first pages: what vmmgr holds of
/// it, to give each VMM its own.
pub const VMM_PAGES: usize = MAX_VMMS * lane_pages(SMALL);

/// Writers of each kind there can be: a blkd per disk controller (root's
/// `pci::MAX_DISK_CTRLS`, which root checks), a usbd per xHCI controller,
/// a VMM per guest.
pub const MAX_BLKDS: usize = 64;
pub const MAX_USBDS: usize = crate::usb::MAX_USB_CTRLS;
pub const MAX_NICDS: usize = crate::nicd::MAX_UPLINKS;
pub const MAX_VMMS: usize = crate::memd::MAX_GUESTS;

/// Component ids (root's `*_ID` constants, which root checks).
pub const BLKD_ID_BASE: u32 = 0x100;
pub const NETD_ID: u32 = 0x200;
pub const MEMD_ID: u32 = 0x400;
pub const LOGD_ID: u32 = 0x600;
/// What `l4hctl logs` prints for guest g's VMM, `VMM_ID_BASE + g`: a VMM's
/// component id is its guest's, and guest 0's would be root's 0.
pub const VMM_ID_BASE: u32 = 0x1000;

// No two writers print the same id: each kind's ids end before the next
// kind's start, and root's 0 is below them all.
const _: () = {
    let ranges = [
        (BLKD_ID_BASE, MAX_BLKDS),
        (NETD_ID, 1),
        (crate::root::TRUSTD_ID, 1),
        (crate::root::FLAGS_ID, 1),
        (MEMD_ID, 1),
        (crate::vmmgr::VMMGR_ID, 1),
        (LOGD_ID, 1),
        (crate::usb::USBD_ID_BASE, MAX_USBDS),
        (crate::nicd::NICD_ID_BASE, MAX_NICDS),
        (VMM_ID_BASE, MAX_VMMS),
    ];
    let (mut i, mut end) = (0, 1);
    while i < ranges.len() {
        assert!(ranges[i].0 >= end);
        end = ranges[i].0 + ranges[i].1 as u32;
        i += 1;
    }
};

/// Who writes a lane. A record's writer is the lane's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Writer {
    Root,
    Logd,
    Memd,
    Trustd,
    /// trustd's flags server.
    Flags,
    Vmmgr,
    Netd,
    Blkd(u32),
    Usbd(u32),
    /// Uplink n's nicd.
    Nicd(u32),
    /// Guest g's VMM, and what it prints of its guest's console.
    Vmm(u32),
    /// dom0's VMM in the serial ring, where dom0's console is (`serial`).
    Dom0,
}

impl Writer {
    /// Every writer, in `index` order.
    pub const COUNT: usize = 7 + MAX_BLKDS + MAX_USBDS + MAX_NICDS + MAX_VMMS + 1;

    /// The writer that a component of `kind` and `id` is, if any.
    pub fn of(kind: u32, id: u32) -> Option<Writer> {
        let index = |base: u32, max: usize| id.checked_sub(base).filter(|&i| (i as usize) < max);
        Some(match kind {
            crate::KIND_LOGD => Writer::Logd,
            crate::KIND_MEMD => Writer::Memd,
            crate::KIND_TRUSTD => Writer::Trustd,
            crate::KIND_FLAGS => Writer::Flags,
            crate::KIND_VMMGR => Writer::Vmmgr,
            crate::KIND_NETD => Writer::Netd,
            crate::KIND_BLKD => Writer::Blkd(index(BLKD_ID_BASE, MAX_BLKDS)?),
            crate::KIND_USBD => Writer::Usbd(index(crate::usb::USBD_ID_BASE, MAX_USBDS)?),
            crate::KIND_NICD => Writer::Nicd(index(crate::nicd::NICD_ID_BASE, MAX_NICDS)?),
            crate::KIND_VMM => Writer::Vmm(index(0, MAX_VMMS)?),
            _ => return None,
        })
    }

    pub const fn index(self) -> usize {
        match self {
            Writer::Root => 0,
            Writer::Logd => 1,
            Writer::Memd => 2,
            Writer::Trustd => 3,
            Writer::Flags => 4,
            Writer::Vmmgr => 5,
            Writer::Netd => 6,
            Writer::Blkd(c) => 7 + c as usize,
            Writer::Usbd(i) => 7 + MAX_BLKDS + i as usize,
            Writer::Nicd(i) => 7 + MAX_BLKDS + MAX_USBDS + i as usize,
            Writer::Vmm(g) => 7 + MAX_BLKDS + MAX_USBDS + MAX_NICDS + g as usize,
            Writer::Dom0 => Self::COUNT - 1,
        }
    }

    pub const fn from_index(i: usize) -> Option<Writer> {
        const B: usize = 7 + MAX_BLKDS;
        const U: usize = B + MAX_USBDS;
        const N: usize = U + MAX_NICDS;
        Some(match i {
            0 => Writer::Root,
            1 => Writer::Logd,
            2 => Writer::Memd,
            3 => Writer::Trustd,
            4 => Writer::Flags,
            5 => Writer::Vmmgr,
            6 => Writer::Netd,
            7..B => Writer::Blkd((i - 7) as u32),
            B..U => Writer::Usbd((i - B) as u32),
            U..N => Writer::Nicd((i - U) as u32),
            _ if i < Self::COUNT - 1 => Writer::Vmm((i - N) as u32),
            _ if i == Self::COUNT - 1 => Writer::Dom0,
            _ => return None,
        })
    }

    pub fn all() -> impl Iterator<Item = Writer> {
        (0..Self::COUNT).filter_map(Self::from_index)
    }

    /// The id `l4hctl logs` prints: the component's (root: 0), but a VMM's,
    /// whose component id is its guest's. No two writers have the same.
    pub fn id(self) -> u32 {
        match self {
            Writer::Root => 0,
            Writer::Logd => LOGD_ID,
            Writer::Memd => MEMD_ID,
            Writer::Trustd => crate::root::TRUSTD_ID,
            Writer::Flags => crate::root::FLAGS_ID,
            Writer::Vmmgr => crate::vmmgr::VMMGR_ID,
            Writer::Netd => NETD_ID,
            Writer::Blkd(c) => BLKD_ID_BASE + c,
            Writer::Usbd(i) => crate::usb::USBD_ID_BASE + i,
            Writer::Nicd(i) => crate::nicd::NICD_ID_BASE + i,
            Writer::Vmm(g) => VMM_ID_BASE + g,
            Writer::Dom0 => u32::MAX,
        }
    }

    /// Its name on the serial port, as `[name] ` (`serial`).
    pub fn name(self, out: &mut impl Write) -> fmt::Result {
        match self {
            Writer::Root => out.write_str("root"),
            Writer::Logd => out.write_str("logd"),
            Writer::Memd => out.write_str("memd"),
            Writer::Trustd => out.write_str("trustd"),
            Writer::Flags => out.write_str("flags"),
            Writer::Vmmgr => out.write_str("vmmgr"),
            Writer::Netd => out.write_str("netd"),
            Writer::Blkd(c) => write!(out, "blkd{}", c),
            Writer::Usbd(i) => write!(out, "usbd{}", i),
            Writer::Nicd(i) => write!(out, "nicd{}", i),
            Writer::Vmm(g) => write!(out, "vmm{}", g),
            Writer::Dom0 => out.write_str("dom0 vmm"),
        }
    }
}

/// Records of each lane: they fill its pages. Root's holds its boot log and
/// what it prints of devices and guests, vmmgr's the guests' lifecycle;
/// other components log little, and only their own.
const ROOT: usize = 255;
const VMMGR: usize = 63;
const SERVICE: usize = 15;
const SMALL: usize = 7;

/// The bytes of a lane of `records` records, and its pages.
const fn lane_bytes(records: usize) -> usize {
    core::mem::offset_of!(ring::Ring<1, WORDS>, slots) + records * core::mem::size_of::<ring::Slot<WORDS>>()
}

pub const fn lane_pages(records: usize) -> usize {
    lane_bytes(records).div_ceil(PAGE)
}

/// One writer's records, in pages of their own.
#[repr(C, align(4096))]
pub struct Lane<const N: usize>(ring::Ring<N, WORDS>);

impl<const N: usize> Lane<N> {
    const fn new() -> Self {
        Self(ring::Ring::new())
    }
}

#[repr(C, align(4096))]
struct Clock {
    start_ticks: AtomicU64,
    hz: AtomicU64,
}

/// The lanes of every writer of a partition, and the clock their times
/// count from, which only root writes. Page-aligned so that root can share
/// each lane's frames without sharing any other root data.
#[repr(C)]
pub struct Ring {
    vmm: [Lane<SMALL>; MAX_VMMS],
    clock: Clock,
    root: Lane<ROOT>,
    vmmgr: Lane<VMMGR>,
    service: [Lane<SERVICE>; 5],
    blkd: [Lane<SMALL>; MAX_BLKDS],
    usbd: [Lane<SMALL>; MAX_USBDS],
    nicd: [Lane<SMALL>; MAX_NICDS],
}

const _: () = {
    let sizes = [
        (core::mem::size_of::<Lane<ROOT>>(), ROOT),
        (core::mem::size_of::<Lane<VMMGR>>(), VMMGR),
        (core::mem::size_of::<Lane<SERVICE>>(), SERVICE),
        (core::mem::size_of::<Lane<SMALL>>(), SMALL),
    ];
    let mut i = 0;
    while i < sizes.len() {
        // Each lane is whole pages, and fills them: one more record would not fit.
        assert!(sizes[i].0 == lane_pages(sizes[i].1) * PAGE);
        assert!(lane_bytes(sizes[i].1 + 1) > sizes[i].0);
        i += 1;
    }
    assert!(core::mem::size_of::<Ring>() % PAGE == 0);
    assert!(core::mem::offset_of!(Ring, clock) == VMM_PAGES * PAGE);
    // A writer's lane, at VA, fits below the serial ring.
    assert!(VA >= crate::KEEPER_IPCBUF_VA + PAGE && VA + core::mem::size_of::<Lane<ROOT>>() <= crate::serial::VA);
    assert!(READ_VA >= crate::vmmgr::CTL_DATA_VA + (1 << 30));
};

/// Where a writer's lane is in the area, in pages, and its records.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LaneAt {
    pub page: usize,
    pub pages: usize,
    pub records: usize,
}

impl LaneAt {
    const fn new(offset: usize, records: usize) -> Self {
        Self { page: offset / PAGE, pages: lane_pages(records), records }
    }
}

/// `w`'s lane (dom0's VMM's is its guest's).
pub fn lane_at(w: Writer) -> Option<LaneAt> {
    use core::mem::{offset_of, size_of};
    let (small, service) = (size_of::<Lane<SMALL>>(), size_of::<Lane<SERVICE>>());
    let svc = |i: usize| LaneAt::new(offset_of!(Ring, service) + i * service, SERVICE);
    Some(match w {
        Writer::Root => LaneAt::new(offset_of!(Ring, root), ROOT),
        Writer::Vmmgr => LaneAt::new(offset_of!(Ring, vmmgr), VMMGR),
        Writer::Logd => svc(0),
        Writer::Memd => svc(1),
        Writer::Trustd => svc(2),
        Writer::Flags => svc(3),
        Writer::Netd => svc(4),
        Writer::Blkd(c) => LaneAt::new(offset_of!(Ring, blkd) + c as usize * small, SMALL),
        Writer::Usbd(i) => LaneAt::new(offset_of!(Ring, usbd) + i as usize * small, SMALL),
        Writer::Nicd(i) => LaneAt::new(offset_of!(Ring, nicd) + i as usize * small, SMALL),
        Writer::Vmm(g) => LaneAt::new(offset_of!(Ring, vmm) + g as usize * small, SMALL),
        Writer::Dom0 => return None,
    })
}

impl Ring {
    pub const fn new() -> Self {
        Self {
            vmm: [const { Lane::new() }; MAX_VMMS],
            clock: Clock { start_ticks: AtomicU64::new(0), hz: AtomicU64::new(0) },
            root: Lane::new(),
            vmmgr: Lane::new(),
            service: [const { Lane::new() }; 5],
            blkd: [const { Lane::new() }; MAX_BLKDS],
            usbd: [const { Lane::new() }; MAX_USBDS],
            nicd: [const { Lane::new() }; MAX_NICDS],
        }
    }

    /// Root sets the common clock before starting any component.
    pub fn set_clock(&self, start_ticks: u64, hz: u64) {
        self.clock.start_ticks.store(start_ticks, SeqCst);
        self.clock.hz.store(hz.max(1), SeqCst);
    }

    /// `w`'s lane, as its reader indexes it: with the number of slots the
    /// layout gives it.
    pub fn lane(&self, w: Writer) -> Option<View<'_, WORDS>> {
        let i = |n: u32| n as usize;
        Some(match w {
            Writer::Root => self.root.0.view(),
            Writer::Vmmgr => self.vmmgr.0.view(),
            Writer::Logd => self.service[0].0.view(),
            Writer::Memd => self.service[1].0.view(),
            Writer::Trustd => self.service[2].0.view(),
            Writer::Flags => self.service[3].0.view(),
            Writer::Netd => self.service[4].0.view(),
            Writer::Blkd(c) => self.blkd.get(i(c))?.0.view(),
            Writer::Usbd(u) => self.usbd.get(i(u))?.0.view(),
            Writer::Nicd(u) => self.nicd.get(i(u))?.0.view(),
            Writer::Vmm(g) => self.vmm.get(i(g))?.0.view(),
            Writer::Dom0 => return None,
        })
    }

    pub fn write(&self, w: Writer, ticks: u64, args: fmt::Arguments<'_>) {
        if let Some(lane) = self.lane(w) {
            write_to(lane, || ticks, args);
        }
    }

    /// Read whole lines of every lane, oldest first, without consuming
    /// them (`CTL_LOG_READ`). Cursors are times, in ticks: `end == 0`
    /// snapshots what is older than a moment ago, and subsequent reads can
    /// use the returned end to finish that snapshot even while new messages
    /// arrive. Cursor 0 starts at boot; lost counts overwritten, dropped and
    /// not-yet-committed records.
    pub fn read(&self, cursor: u64, end: u64, out: &mut [u8]) -> Option<Read> {
        // Before any lane is looked at (`write_to` reads the time after it
        // claims).
        let now = crate::ticks::now_ordered();
        self.read_at(now, cursor, end, out)
    }

    /// Whether a writer has claimed a slot of some lane and not committed
    /// it yet.
    fn in_flight(&self) -> bool {
        Writer::all().filter_map(|w| self.lane(w)).any(|lane| {
            let head = lane.head();
            (lane.oldest_at(head)..head).any(|seq| lane.pending(seq))
        })
    }

    fn read_at(&self, now: u64, cursor: u64, until: u64, out: &mut [u8]) -> Option<Read> {
        let hz = self.clock.hz.load(SeqCst).max(1);
        let start = self.clock.start_ticks.load(SeqCst);
        // A writer reads the time after it claims its slot (`write_to`),
        // and `now` was read before any lane was: a record not yet claimed
        // is later than `now`, in the next snapshot.  One claimed and not
        // committed may be older: then a snapshot ends a moment ago, so
        // that it is in the next one rather than missed.
        // Only a cursor no read gave is refused: one in the future, or past
        // the caller's own end.  A cursor a read gave is at most the `now`
        // of that read, which a snapshot that ends a moment ago can be
        // before: that read is empty, at the cursor, not an error, or any
        // writer could make others' reads fail by leaving a slot claimed.
        if cursor > now || (until != 0 && cursor > until) {
            return None;
        }
        let snapshot = if self.in_flight() { now.saturating_sub(hz / 10) } else { now };
        // An end still to come is no end: this read's is the snapshot's, as
        // for 0, and fixed by the end it reports.  An end that moved on with
        // the clock would never be reached while some slot stays claimed.
        let until = if until > now { 0 } else { until };
        // What this read scans to, and the end it reports: the caller's own,
        // if it gave one, even when this read stops earlier, so that a
        // snapshot is finished by later reads rather than taken as done
        // where a slot in flight made this one stop.
        let end = if until == 0 { snapshot } else { until.min(snapshot) }.max(cursor);
        let reported = if until == 0 { end } else { until };
        let (mut len, mut lost, mut last) = (0, 0u64, None);
        // The records of one time are never split between reads: where
        // they start in `out`, and what was lost before them.
        let mut group: Option<(u64, usize, u64)> = None;
        // The records each lane has given this read, which bound it
        // (`next_key`).
        let mut taken = [0; Writer::COUNT];
        while let Some(key) = self.next_key(cursor, end, last, &mut taken) {
            last = Some(key);
            let (ticks, w, seq) = key;
            let Some(lane) = Writer::from_index(w).and_then(|w| self.lane(w)) else { continue };
            let r = match lane.get(seq) {
                Entry::Ready(r) if r.ticks == ticks => r,
                _ => {
                    lost = lost.saturating_add(1);
                    continue;
                }
            };
            if group.is_none_or(|(t, ..)| t != ticks) {
                group = Some((ticks, len, lost));
            }
            lost = lost.saturating_add(gap(lane, seq, cursor));
            let mut line = Line::new();
            let us = ticks.saturating_sub(start) as u128 * 1_000_000 / hz as u128;
            let id = Writer::from_index(w).map_or(0, Writer::id);
            let _ = write!(line, "[{:>6}.{:06}] [{:#x}] ", us / 1_000_000, us % 1_000_000, id);
            printable(r.text(), |b| line.push(b));
            line.push(b"\n");
            if line.len > out.len() - len {
                let Some((_, at, before)) = group.filter(|&(_, at, _)| at != 0 || len == 0) else {
                    // A time whose records do not fit at once: the rest of
                    // them is lost, rather than the reader stuck.
                    lost = lost.saturating_add(1 + self.count_at(ticks, cursor, end, key, &mut taken));
                    return Some(Read { next: ticks.saturating_add(1).min(end), len, lost, end: reported });
                };
                return Some(Read { next: ticks, len: at, lost: before, end: reported });
            }
            out[len..len + line.len].copy_from_slice(&line.bytes[..line.len]);
            len += line.len;
        }
        Some(Read { next: end, len, lost, end: reported })
    }

    /// The first record after `last` of those of [cursor, end), in the
    /// order of (time, lane, sequence), looking at each lane's slots once,
    /// and counted in `taken` for its lane.
    ///
    /// A lane gives one read no more records than it has slots: what an
    /// honest writer's holds of a time before the read began. A writer that
    /// changes its head, states and times as the reader goes can make
    /// records without end, each after the last and none readable; past
    /// its slots its lane is left out of the rest of the read, which so
    /// takes no more records than all lanes have slots, and goes on to the
    /// other lanes' and to its end.
    fn next_key(&self, cursor: u64, end: u64, last: Option<(u64, usize, u64)>, taken: &mut [u16; Writer::COUNT]) -> Option<(u64, usize, u64)> {
        let mut best = None;
        for w in Writer::all() {
            let Some(lane) = self.lane(w) else { continue };
            if taken[w.index()] as usize >= lane.capacity() {
                continue;
            }
            // One read of head bounds the scan to the lane's capacity.
            let head = lane.head();
            for seq in lane.oldest_at(head)..head {
                let Some(ticks) = lane.ticks(seq) else { continue };
                let key = (ticks, w.index(), seq);
                if (cursor..end).contains(&ticks) && last.is_none_or(|l| key > l) && best.is_none_or(|b| key < b) {
                    best = Some(key);
                }
            }
        }
        if let Some((_, w, _)) = best {
            taken[w] += 1;
        }
        best
    }

    /// Records of time `ticks` after `key`.
    fn count_at(&self, ticks: u64, cursor: u64, end: u64, mut key: (u64, usize, u64), taken: &mut [u16; Writer::COUNT]) -> u64 {
        let mut n = 0;
        while let Some(next) = self.next_key(cursor, end, Some(key), taken).filter(|k| k.0 == ticks) {
            n += 1;
            key = next;
        }
        n
    }
}

/// What a reader knows to be lost of `lane` before its record `seq`: the
/// unavailable slots since the lane's previous record, or, if it has none,
/// since the oldest it holds; from boot (`cursor` 0) also what was
/// overwritten. Each gap is counted with the record after it, which a
/// sequence of reads returns once. A lane that a follower's read finds
/// overwritten since its last record counts as at least one.
///
/// What was overwritten is the lane's head less its slots, which its
/// writer can make anything: a lane counts for `LOST_MAX` at most, so that
/// no writer's number hides, in a sum that no longer grows, what the
/// others lost.
fn gap(lane: View<'_, WORDS>, seq: u64, cursor: u64) -> u64 {
    // Head may have moved since `seq` was found, anywhere: the scan stays
    // within a lap of `seq`.
    let floor = seq.saturating_sub(lane.capacity() as u64);
    let oldest = lane.oldest_at(lane.head()).clamp(floor, seq);
    let mut n = 0;
    for s in (oldest..seq).rev() {
        if lane.ticks(s).is_some() {
            return n;
        }
        n += 1;
    }
    match (cursor, oldest) {
        (_, 0) => n,
        (0, _) => n.saturating_add(oldest.min(LOST_MAX)),
        _ => n + 1,
    }
}

/// The most one record's gap adds to a read's lost count (`gap`): more
/// records than a writer overwrites in a host's lifetime, and so few that
/// all a read returns cannot bring the count near its end.
const LOST_MAX: u64 = 1 << 32;

pub struct Read {
    pub next: u64,
    pub len: usize,
    pub lost: u64,
    pub end: u64,
}

/// A line `read` hands out.
struct Line {
    bytes: [u8; TEXT_SIZE + 64],
    len: usize,
}

impl Line {
    fn new() -> Self {
        Self { bytes: [0; TEXT_SIZE + 64], len: 0 }
    }

    fn push(&mut self, s: &[u8]) {
        let n = s.len().min(self.bytes.len() - self.len);
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

/// Hand on `text` as a terminal shows it as text and nothing else: what a
/// record holds is its writer's (a guest's name, say, or a guest's
/// console), and a control character or escape sequence could move the
/// cursor over another line, or make a line look like another writer's.
/// Tabs and line ends become spaces; other control characters (C0, DEL,
/// C1), the characters that end a line or change the direction text is
/// shown in (`reorders`), and bytes that are not UTF-8 become `?`. What is
/// left is text for a terminal that reads UTF-8: one that reads single
/// bytes takes some bytes of a character for controls. The one place the
/// host's readers that print (`serial::Merge`, `Ring::read`) clean text.
pub fn printable(text: &[u8], mut push: impl FnMut(&[u8])) {
    for chunk in text.utf8_chunks() {
        let valid = chunk.valid();
        let mut from = 0;
        for (i, c) in valid.char_indices() {
            if c.is_control() || reorders(c) {
                push(&valid.as_bytes()[from..i]);
                push(if matches!(c, '\t' | '\r' | '\n') { b" " } else { b"?" });
                from = i + c.len_utf8();
            }
        }
        push(&valid.as_bytes()[from..]);
        if !chunk.invalid().is_empty() {
            push(b"?");
        }
    }
}

/// Whether `c`, which is no control character, still moves text on a
/// terminal that reads UTF-8: the line and paragraph separators, and the
/// marks, embeddings, overrides and isolates of bidirectional text, which
/// can show a line's text before its prefix or in another order.
fn reorders(c: char) -> bool {
    matches!(c, '\u{2028}' | '\u{2029}' | '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Limits what a less trusted party (a guest, or its VMM) can make a
/// component log: per key, a guest id below N, `BURST` records at once and
/// then one a second. `allow` says whether to write the record, and how
/// many before it were not. State is fixed: N buckets.
pub struct RateLimit<const N: usize> {
    buckets: [Bucket; N],
}

#[derive(Clone, Copy)]
struct Bucket {
    /// Records it may write now, at the time of `at`.
    tokens: u64,
    at: u64,
    dropped: u64,
}

impl<const N: usize> RateLimit<N> {
    pub const BURST: u64 = 8;

    pub const fn new() -> Self {
        Self { buckets: [Bucket { tokens: Self::BURST, at: 0, dropped: 0 }; N] }
    }

    /// Whether to log a record for `key` now (`now` in ticks of `hz` a
    /// second): `Some(n)` if so, n the records not logged since the last
    /// that was. Keys from N up share the last bucket.
    pub fn allow(&mut self, key: usize, now: u64, hz: u64) -> Option<Suppressed> {
        let b = &mut self.buckets[key.min(N - 1)];
        let hz = hz.max(1);
        // Whole seconds since the bucket's time; a clock that goes back
        // refills nothing.
        let secs = now.saturating_sub(b.at) / hz;
        if secs != 0 {
            b.tokens = b.tokens.saturating_add(secs).min(Self::BURST);
            b.at = b.at.saturating_add(secs.saturating_mul(hz));
        }
        if now < b.at {
            b.at = now;
        }
        if b.tokens == 0 {
            b.dropped = b.dropped.saturating_add(1);
            return None;
        }
        b.tokens -= 1;
        Some(Suppressed(core::mem::take(&mut b.dropped)))
    }
}

impl<const N: usize> Default for RateLimit<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Records `RateLimit` did not let through, for the next one that it did
/// to say: nothing, or ` (N earlier records not logged)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Suppressed(pub u64);

impl fmt::Display for Suppressed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => Ok(()),
            n => write!(f, " ({} earlier records not logged)", n),
        }
    }
}

struct Text {
    buf: Buf<WORDS>,
    len: usize,
    truncated: bool,
}

impl Text {
    const SUFFIX: &str = " [truncated]";
    fn new() -> Self { Self { buf: Buf::new(), len: 0, truncated: false } }
    fn finish(&mut self) {
        if self.truncated {
            let suffix = Self::SUFFIX.as_bytes();
            self.buf.bytes_mut()[self.len..self.len + suffix.len()].copy_from_slice(suffix);
            self.len += suffix.len();
        }
    }
}

impl Write for Text {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.truncated { return Ok(()); }
        let mut n = s.len().min(TEXT_SIZE - Self::SUFFIX.len() - self.len);
        while !s.is_char_boundary(n) { n -= 1; }
        self.buf.bytes_mut()[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        self.truncated = n < s.len();
        Ok(())
    }
}

/// A record into `lane`: its text only. Its time and writer are put
/// around it by the reader.
/// Write a record of `args`, at the time `ticks` gives once its slot is
/// claimed: a reader that finds no slot claimed and uncommitted then knows
/// that what is not written yet is later than its own time (`Ring::read`).
fn write_to(lane: View<'_, WORDS>, ticks: impl FnOnce() -> u64, args: fmt::Arguments<'_>) {
    let mut text = Text::new();
    let _ = text.write_fmt(args);
    text.finish();
    let seq = lane.claim(1);
    lane.commit(seq, ticks(), 0, text.len, &text.buf);
}

/// This process's lane: its address and slots (0: none).
static LANE_VA: AtomicUsize = AtomicUsize::new(0);
static LANE_RECORDS: AtomicUsize = AtomicUsize::new(0);

/// Root's: write to its own lane of `area`. Install before starting
/// another thread.
pub fn init(area: &'static Ring, _source: u32) {
    LANE_RECORDS.store(ROOT, SeqCst);
    LANE_VA.store(core::ptr::from_ref(&area.root) as usize, SeqCst);
}

/// A component's: write to the lane of `records` records its parent
/// mapped at `VA` (none if 0, `info_records`). Call before starting
/// another thread.
///
/// The lane may have been another writer's (a guest id's VMM lane is the
/// next VMM's of that id), which no longer runs: one it left as no honest
/// writer does, or with a record of a time still to come, is reset first
/// (`ring::View::adopt`), so that this writer's records go in and none of
/// the other's comes up later as this one's. Readers count what a reset
/// took as lost.
pub fn init_lane(records: usize) {
    if records != 0 {
        // The parent mapped a lane of `records` records there for good.
        unsafe { View::<WORDS>::at(VA, records) }.adopt(Some(crate::ticks::now_ordered()));
    }
    LANE_RECORDS.store(records, SeqCst);
    LANE_VA.store(if records == 0 { 0 } else { VA }, SeqCst);
}

pub fn record(args: fmt::Arguments<'_>) {
    let (va, n) = (LANE_VA.load(SeqCst), LANE_RECORDS.load(SeqCst));
    if va != 0 && n != 0 {
        // init and init_lane only take a lane that lives for the process's lifetime.
        write_to(unsafe { View::at(va, n) }, crate::ticks::now_ordered, args);
    }
}

/// What a parent tells a component of its lanes, in its info page
/// (`InfoHeader::reserved[LANES_INFO]`): the records of its log lane and
/// of its serial lane (0: none).
pub const LANES_INFO: usize = 0;

pub const fn lanes_info(log: usize, serial: usize) -> u64 {
    (log as u64 & 0xffff_ffff) | (serial as u64) << 32
}

/// `lanes_info`'s log and serial records.
pub const fn info_records(info: u64) -> (usize, usize) {
    ((info & 0xffff_ffff) as usize, (info >> 32) as usize)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{string::String, sync::Arc, thread, vec::Vec};

    const HZ: u64 = 1_000_000;
    /// Reads are at this time: they see everything written before it, or
    /// before `NOW - HZ / 10` while a slot is claimed and not committed.
    const NOW: u64 = 1 << 40;

    fn ring() -> &'static Ring {
        // Too large for a test thread's stack; all zeroes is Ring::new().
        let ring: &'static Ring = unsafe { &*std::alloc::alloc_zeroed(std::alloc::Layout::new::<Ring>()).cast() };
        ring.set_clock(100, HZ);
        ring
    }

    fn read(ring: &Ring, cursor: u64, end: u64) -> (Read, String) {
        let mut out = [0; 1984];
        let r = ring.read_at(NOW, cursor, end, &mut out).unwrap();
        let text = String::from_utf8(out[..r.len].to_vec()).unwrap();
        (r, text)
    }

    #[test]
    fn timestamps_cursors_and_independent_readers() {
        let ring = ring();
        let (r, text) = read(ring, 0, 0);
        assert_eq!((r.next, r.len, text.as_str()), (r.end, 0, ""));
        ring.write(Writer::Vmmgr, 1_250_100, format_args!("guest 2 kernel fault"));
        let (r, text) = read(ring, 0, 0);
        assert_eq!(text, "[     1.250000] [0x500] guest 2 kernel fault\n");
        assert_eq!((r.next, r.lost), (r.end, 0));
        assert_eq!(read(ring, 0, 0).1, text);
        assert_eq!(read(ring, 1_250_101, 0).1, "");
        assert!(ring.read_at(NOW, NOW + 1, 0, &mut [0; 1984]).is_none());
        ring.write(Writer::Netd, 1_250_200, format_args!("next"));
        // A snapshot that ended before it does not take it.
        assert_eq!(read(ring, 1_250_101, 1_250_150).1, "");
        assert_eq!(read(ring, 1_250_101, 0).1, "[     1.250100] [0x200] next\n");
    }

    /// A read that filled its output gives a cursor less than a moment
    /// old; a writer that then leaves a slot claimed and not committed
    /// makes the next snapshot end before that cursor.  That read is empty,
    /// at the cursor, not an error: no writer can make another's read fail.
    /// A snapshot's reader is told its end, not this read's, and reads on to
    /// it rather than leaving out records it was promised.
    #[test]
    fn a_claimed_slot_does_not_fail_a_recent_cursor() {
        let ring = ring();
        let long = "x".repeat(400);
        for k in 0..6 {
            ring.write(Writer::Netd, NOW - 1000 + k, format_args!("{long}"));
        }
        let (first, before) = read(ring, 0, 0);
        assert!(first.next > NOW - HZ / 10 && first.next < first.end, "a full read stops at a recent record");
        let seq = ring.lane(Writer::Usbd(0)).unwrap().claim(1);
        // A follower: nothing yet, and nothing to wait for but the next read.
        let (r, text) = read(ring, first.next, 0);
        assert_eq!((r.next, r.len, r.end, text.as_str()), (first.next, 0, first.next, ""));
        // A snapshot: not done (next is short of its end), so its reader
        // reads on rather than leaving out the records it has not had.
        let (r, text) = read(ring, first.next, first.end);
        assert_eq!((r.next, r.len, r.end, text.as_str()), (first.next, 0, first.end, ""));
        ring.lane(Writer::Usbd(0)).unwrap().commit(seq, NOW - 1, 0, 0, &crate::ring::Buf([0; WORDS]));
        let (r, text) = read(ring, first.next, first.end);
        assert_eq!((r.next, r.end), (first.end, first.end));
        assert_eq!(before.matches(&long).count() + text.matches(&long).count(), 6, "the rest of the snapshot: {text:?}");
        // An end still to come is the snapshot's: with nothing in flight,
        // now; with a slot claimed for good, a moment ago, and a reader that
        // reads on with the end it was given finishes there.
        let (r, _) = read(ring, first.end, u64::MAX);
        assert_eq!((r.next, r.end), (NOW, NOW));
        ring.lane(Writer::Usbd(1)).unwrap().claim(1);
        let (r, _) = read(ring, 0, u64::MAX);
        assert_eq!(r.end, NOW - HZ / 10, "fixed at the first read");
        let mut cursor = r.next;
        for later in 1..8 {
            if cursor == r.end {
                break;
            }
            let mut out = [0; 1984];
            let n = ring.read_at(NOW + later * HZ, cursor, r.end, &mut out).unwrap();
            assert_eq!(n.end, r.end, "the end stays the snapshot's");
            cursor = n.next;
        }
        assert_eq!(cursor, r.end, "the snapshot finished");
        // What only a caller could have made up is still refused.
        assert!(ring.read_at(NOW, NOW + 1, 0, &mut [0; 1984]).is_none());
        assert!(ring.read_at(NOW, first.next, first.next - 1, &mut [0; 1984]).is_none());
    }

    /// Whatever writers do (records at any recent time, slots claimed and
    /// committed late or never), a reader that passes back what reads gave
    /// is never refused, a snapshot finishes within a moment of time once
    /// its records fit, and gives no record twice.
    #[test]
    fn reads_from_what_reads_gave_never_fail_and_snapshots_finish() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rand = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for _ in 0..40 {
            let ring = ring();
            let lanes = [Writer::Netd, Writer::Vmm(0), Writer::Usbd(0), Writer::Memd];
            let mut now = NOW;
            let mut open = std::vec::Vec::new();
            let mut id = 0;
            let mut write = |ring: &Ring, now: u64, rand: &mut dyn FnMut(u64) -> u64, open: &mut Vec<(Writer, u64)>| {
                let w = lanes[rand(lanes.len() as u64) as usize];
                match rand(4) {
                    0 => open.push((w, ring.lane(w).unwrap().claim(1))),
                    1 if !open.is_empty() => {
                        let (w, seq) = open.swap_remove(rand(open.len() as u64) as usize);
                        ring.lane(w).unwrap().commit(seq, now - rand(HZ / 5), 0, 0, &crate::ring::Buf([0; WORDS]));
                    }
                    _ => {
                        id += 1;
                        ring.write(w, now - rand(HZ / 5), format_args!("r{id} {}", "y".repeat(rand(300) as usize)));
                    }
                }
            };
            for _ in 0..30 {
                write(ring, now, &mut rand, &mut open);
            }
            // A follower and a snapshot, reading as time goes on and writers
            // keep writing.
            let (mut follow, mut snap, mut snap_end) = (0, 0, 0);
            let mut seen = std::collections::BTreeSet::new();
            let mut snap_done = false;
            for step in 0..400 {
                now += rand(HZ / 20) + 1;
                write(ring, now, &mut rand, &mut open);
                let mut out = [0; 1984];
                let r = ring.read_at(now, follow, 0, &mut out).expect("a follower's cursor is refused");
                assert!(r.next >= follow && r.next <= r.end && r.end <= now);
                follow = r.next;
                if !snap_done {
                    let r = ring.read_at(now, snap, snap_end, &mut out).expect("a snapshot's cursor is refused");
                    assert!(r.next >= snap && r.next <= r.end && r.end <= now);
                    if snap_end != 0 {
                        assert_eq!(r.end, snap_end, "a snapshot's end moved");
                    }
                    for line in std::str::from_utf8(&out[..r.len]).unwrap().lines() {
                        if let Some(rid) = line.split("] ").nth(2).and_then(|t| t.split(' ').next()).filter(|t| t.starts_with('r')) {
                            assert!(seen.insert(std::string::String::from(rid)), "{rid} twice in one snapshot");
                        }
                    }
                    (snap, snap_end) = (r.next, r.end);
                    snap_done = snap == snap_end;
                }
                if step == 200 {
                    // Then every slot left open is committed, or not: the
                    // snapshot is done by now in any case.
                    assert!(snap_done, "a snapshot did not finish");
                }
            }
        }
    }

    #[test]
    fn a_read_sees_what_was_written_just_before_it() {
        // vmmgr logs a guest's fault and stops it; dom0 reads at once.
        let ring = ring();
        ring.write(Writer::Vmmgr, NOW - 1, format_args!("guest 1 vCPU 0 kernel fault"));
        assert!(read(ring, 0, 0).1.contains("kernel fault"));
        // A slot claimed and not committed may hold an older record: the
        // snapshot then ends a moment ago, and takes it once it is in.
        let lane = ring.lane(Writer::Netd).unwrap();
        let seq = lane.claim(1);
        ring.write(Writer::Root, NOW - 2, format_args!("recent"));
        let (r, text) = read(ring, 0, 0);
        assert!(!text.contains("recent") && r.end == NOW - HZ / 10, "{text}");
        let mut text = Text::new();
        let _ = text.write_fmt(format_args!("late"));
        text.finish();
        lane.commit(seq, NOW - 3, 0, text.len, &text.buf);
        let text = read(ring, r.end, 0).1;
        assert!(text.contains("late") && text.contains("recent"), "{text}");
    }

    #[test]
    fn lanes_merge_by_time() {
        let ring = ring();
        ring.write(Writer::Root, 300, format_args!("c"));
        ring.write(Writer::Vmm(3), 100, format_args!("a"));
        ring.write(Writer::Blkd(2), 200, format_args!("b"));
        ring.write(Writer::Usbd(1), 400, format_args!("d"));
        let text = read(ring, 0, 0).1;
        let lines: Vec<_> = text.lines().map(|l| l.split_once("] ").unwrap().1).collect();
        assert_eq!(lines, ["[0x1003] a", "[0x102] b", "[0x0] c", "[0x701] d"]);
    }

    #[test]
    fn a_record_is_the_lanes_whatever_it_says() {
        let ring = ring();
        // A VMM that writes what looks like root's record, with a line end
        // and an escape sequence that would move the cursor.
        ring.write(Writer::Vmm(5), 200, format_args!("x\n[     0.000001] [0x0] l4h-root: \x1b[1Aok\r"));
        let text = read(ring, 0, 0).1;
        assert_eq!(text, "[     0.000100] [0x1005] x [     0.000001] [0x0] l4h-root: ?[1Aok \n");
    }

    #[test]
    fn printable_text_keeps_utf8_and_replaces_controls() {
        let mut s = Vec::new();
        printable("é\tna\u{9b}me\u{7f}".as_bytes(), |b| s.extend_from_slice(b));
        printable(b"\xff\xfe!", |b| s.extend_from_slice(b));
        assert_eq!(String::from_utf8(s).unwrap(), "é na?me???!");
    }

    #[test]
    fn printable_text_cannot_end_a_line_or_reorder_it() {
        // A right-to-left override would show the text before the prefix,
        // and a line separator start a line without one.
        let text = "ab\u{202e}cd\u{2028}e\u{2029}f\u{200f}g\u{200e}h\u{061c}i\u{202a}j\u{2066}k\u{2069}l\u{85}m\u{9b}2J";
        let mut s = Vec::new();
        printable(text.as_bytes(), |b| s.extend_from_slice(b));
        assert_eq!(String::from_utf8(s).unwrap(), "ab?cd?e?f?g?h?i?j?k?l?m?2J");
        // Letters next to them in the tables stay.
        let mut s = Vec::new();
        printable("א\u{200d}ب\u{2010}".as_bytes(), |b| s.extend_from_slice(b));
        assert_eq!(String::from_utf8(s).unwrap(), "א\u{200d}ب\u{2010}");
    }

    #[test]
    fn wrapped_lanes_report_loss_and_snapshots_finish() {
        let ring = ring();
        for i in 0..ROOT + 17 {
            ring.write(Writer::Root, 1000 + i as u64, format_args!("record {i}"));
        }
        let (mut cursor, mut end, mut lost, mut lines) = (0, 0, 0, Vec::new());
        loop {
            let (r, text) = read(ring, cursor, end);
            assert!(r.next >= cursor && r.next <= r.end);
            cursor = r.next;
            end = r.end;
            lost += r.lost;
            lines.extend(text.lines().map(String::from));
            // New logging must not extend the snapshot being read.
            ring.write(Writer::Root, NOW, format_args!("later"));
            if cursor == end { break; }
        }
        assert_eq!(lost, 17);
        assert_eq!(lines.len(), ROOT);
        assert!(lines[0].ends_with("record 17"));
        assert!(lines.last().unwrap().ends_with("record 271"));
    }

    #[test]
    fn one_writer_cannot_erase_anothers_records() {
        let ring = ring();
        ring.write(Writer::Vmmgr, 1000, format_args!("guest 1 kernel fault"));
        // A blkd floods its lane, and scribbles over every word of it.
        for i in 0..1000 {
            ring.write(Writer::Blkd(0), 2000 + i, format_args!("flood"));
        }
        let lane = lane_at(Writer::Blkd(0)).unwrap();
        let words = unsafe {
            core::slice::from_raw_parts((ring as *const Ring as *const AtomicU64).add(lane.page * PAGE / 8), lane.pages * PAGE / 8)
        };
        for w in words {
            w.store(u64::MAX, SeqCst);
        }
        let text = read(ring, 0, 0).1;
        assert!(text.contains("[0x500] guest 1 kernel fault\n"), "{text}");
        assert!(!text.contains("flood"));
    }

    #[test]
    fn a_wild_head_and_times_cannot_stop_the_reader() {
        let ring = ring();
        ring.write(Writer::Root, 1000, format_args!("root"));
        ring.write(Writer::Netd, u64::MAX, format_args!("future"));
        ring.write(Writer::Netd, 0, format_args!("past"));
        ring.lane(Writer::Memd).unwrap().claim(u64::MAX - 3);
        let text = read(ring, 0, 0).1;
        assert!(text.contains("] [0x0] root\n") && text.contains("past") && !text.contains("future"), "{text}");
    }

    #[test]
    fn a_head_that_changes_between_reads_cannot_stop_the_reader() {
        let ring = ring();
        let lane = ring.lane(Writer::Memd).unwrap();
        lane.claim(1 << 40);
        ring.write(Writer::Memd, 1000, format_args!("memd"));
        ring.write(Writer::Root, 2000, format_args!("root"));
        let stop: &'static AtomicU64 = std::boxed::Box::leak(std::boxed::Box::new(AtomicU64::new(0)));
        let attacker = thread::spawn(move || {
            while stop.load(SeqCst) == 0 {
                ring.memd_head().store(0, SeqCst);
                ring.memd_head().store((1 << 40) + 1, SeqCst);
            }
        });
        let (done, finished) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let start = std::time::Instant::now();
            while start.elapsed().as_millis() < 500 {
                assert!(read(ring, 0, 0).1.contains("root"));
            }
            let _ = done.send(());
        });
        let result = finished.recv_timeout(std::time::Duration::from_secs(20));
        stop.store(1, SeqCst);
        attacker.join().unwrap();
        result.expect("the reader stopped");
    }

    impl Ring {
        fn memd_head(&self) -> &AtomicU64 {
            &self.service[1].0.head
        }
    }

    #[test]
    fn a_writer_that_keeps_making_records_cannot_stop_the_reader() {
        let ring = ring();
        ring.write(Writer::Root, 2000, format_args!("root"));
        // A VMM that commits, as the reader goes, a record after every one
        // the reader has looked at, each of the time a read from boot
        // starts at and none with its checksum: the next of the read each
        // time, and never one it can return. A few a scan of the lanes, so
        // that the reader finds each committed.
        let stop: &'static AtomicU64 = std::boxed::Box::leak(std::boxed::Box::new(AtomicU64::new(0)));
        let attacker = thread::spawn(move || {
            let lane = &ring.vmm[5].0;
            let mut seq = 0u64;
            while stop.load(SeqCst) == 0 {
                lane.slots[(seq % SMALL as u64) as usize].state.store(2 * seq + 2, SeqCst);
                seq += 1;
                lane.head.store(seq, SeqCst);
                let wait = std::time::Instant::now();
                while wait.elapsed().as_micros() < 2 {
                    core::hint::spin_loop();
                }
            }
        });
        let (done, finished) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let start = std::time::Instant::now();
            let mut reads = 0;
            while start.elapsed().as_millis() < 500 || reads < 20 {
                let (r, text) = read(ring, 0, 0);
                // The read ends, with the others' records, past the lane.
                assert!(text.contains("] [0x0] root\n"), "{text}");
                assert_eq!(r.next, r.end);
                assert!(r.lost <= SMALL as u64, "{}", r.lost);
                reads += 1;
            }
            let _ = done.send(());
        });
        let result = finished.recv_timeout(std::time::Duration::from_secs(20));
        stop.store(1, SeqCst);
        attacker.join().unwrap();
        result.expect("the reader stopped");
    }

    #[test]
    fn a_read_takes_no_more_records_of_a_lane_than_it_has_slots() {
        let ring = ring();
        ring.write(Writer::Root, 2000, format_args!("root"));
        // Every slot of a lane committed without its checksum.
        let lane = &ring.blkd[3].0;
        for seq in 0..SMALL as u64 {
            lane.slots[seq as usize].state.store(2 * seq + 2, SeqCst);
        }
        lane.head.store(SMALL as u64, SeqCst);
        let (r, text) = read(ring, 0, 0);
        assert!(text.ends_with("] [0x0] root\n"), "{text}");
        assert_eq!((r.lost, r.next), (SMALL as u64, r.end));
    }

    #[test]
    fn a_wild_head_cannot_hide_what_other_lanes_lost() {
        let ring = ring();
        for i in 0..ROOT + 17 {
            ring.write(Writer::Root, 1000 + i as u64, format_args!("record {i}"));
        }
        // Two lanes whose heads say that nearly every sequence there is
        // was overwritten: their sum would be the largest count.
        for w in [Writer::Memd, Writer::Netd] {
            ring.lane(w).unwrap().claim((1 << 63) - 2);
            ring.write(w, 500, format_args!("wild"));
        }
        let (mut cursor, mut end, mut lost) = (0, 0, 0u64);
        loop {
            let (r, _) = read(ring, cursor, end);
            lost = lost.checked_add(r.lost).unwrap();
            (cursor, end) = (r.next, r.end);
            if cursor == end { break; }
        }
        // Each counts for the most a lane can, and the slots before its
        // record; root's 17 are still told.
        assert_eq!(lost, 2 * (LOST_MAX + SERVICE as u64 - 1) + 17);
    }

    #[test]
    fn a_lane_is_reset_for_its_next_writer_if_it_was_left_wrong() {
        let ring = ring();
        let lane = ring.lane(Writer::Vmm(2)).unwrap();
        // The VMM of a guest left a record for a time to come, to pass for
        // the next VMM's of that guest id.
        ring.write(Writer::Vmm(2), 1000, format_args!("old"));
        ring.write(Writer::Vmm(2), NOW + 5000, format_args!("due later"));
        assert!(lane.adopt(Some(NOW - 10)));
        ring.write(Writer::Vmm(2), NOW - 5, format_args!("new"));
        let (r, text) = read(ring, 0, 0);
        assert_eq!(text.lines().count(), 1);
        assert!(text.ends_with("] [0x1002] new\n"), "{text}");
        // What the reset took is lost, not waited for.
        assert_eq!((r.lost, r.end), (SMALL as u64 - 1, NOW));
        let mut out = [0; 1984];
        let later = ring.read_at(NOW + 10_000, r.end, 0, &mut out).unwrap();
        assert_eq!((later.len, later.lost), (0, 0));

        // A lane whose head and slots would drop every record written.
        let lane = &ring.vmm[3].0;
        lane.head.store(u64::MAX - 1, SeqCst);
        for slot in &lane.slots {
            slot.state.store(u64::MAX, SeqCst);
        }
        ring.write(Writer::Vmm(3), NOW - 4, format_args!("dropped"));
        assert!(!read(ring, 0, 0).1.contains("dropped"));
        assert!(ring.lane(Writer::Vmm(3)).unwrap().adopt(Some(NOW - 3)));
        ring.write(Writer::Vmm(3), NOW - 2, format_args!("kept"));
        assert!(read(ring, 0, 0).1.ends_with("] [0x1003] kept\n"));

        // One an honest VMM left stays as it is, with its records.
        ring.write(Writer::Vmm(4), 1000, format_args!("panic text"));
        assert!(!ring.lane(Writer::Vmm(4)).unwrap().adopt(Some(NOW)));
        assert!(read(ring, 0, 0).1.contains("] [0x1004] panic text\n"));
    }

    #[test]
    fn a_full_read_does_not_split_records_of_one_time() {
        let ring = ring();
        let long = "x".repeat(400);
        for i in 0..4 {
            ring.write(Writer::Root, 1000 + i, format_args!("{long}"));
        }
        // Two records of one time, from two writers: the second does not
        // fit after the first four, and neither goes in this read.
        ring.write(Writer::Netd, 2000, format_args!("{long}"));
        ring.write(Writer::Memd, 2000, format_args!("{long}"));
        let (r, text) = read(ring, 0, 0);
        assert_eq!((text.lines().count(), r.next), (4, 2000));
        let (r, text) = read(ring, r.next, r.end);
        assert_eq!((text.lines().count(), r.next, r.lost), (2, r.end, 0));
    }

    #[test]
    fn records_of_one_time_too_many_for_a_read_are_lost_not_stuck() {
        let ring = ring();
        let long = "x".repeat(400);
        for _ in 0..SERVICE {
            ring.write(Writer::Netd, 2000, format_args!("{long}"));
        }
        let (r, text) = read(ring, 0, 0);
        assert_eq!((text.lines().count(), r.next), (4, 2001));
        assert_eq!(r.lost, SERVICE as u64 - 4);
    }

    #[test]
    fn long_utf8_records_are_marked_and_never_split() {
        let ring = ring();
        ring.write(Writer::Root, 1000, format_args!("{}", "é".repeat(TEXT_SIZE)));
        let (r, text) = read(ring, 0, 0);
        assert!(text.ends_with(" [truncated]\n"));
        assert!(text.len() <= TEXT_SIZE + 30);
        let mut small = [0; 16];
        let short = ring.read_at(NOW, 0, 0, &mut small).unwrap();
        assert_eq!((short.next, short.len, short.lost), (1000, 0, 0));
        ring.write(Writer::Root, 2000, format_args!("following"));
        assert!(read(ring, 1001, 0).1.ends_with("following\n"));
        assert_eq!(r.next, r.end);
    }

    #[test]
    fn abandoned_writer_does_not_block_other_slots_or_readers() {
        let ring = ring();
        let lane = ring.lane(Writer::Root).unwrap();
        // Simulate a fault after claiming sequence 0 but before commit.
        lane.claim(1);
        ring.root.0.slots[0].state.store(1, SeqCst);
        for i in 1..=ROOT * 3 { ring.write(Writer::Root, 1000 + i as u64, format_args!("record {i}")); }
        let (r, text) = read(ring, 0, 0);
        let (mut lost, mut count, mut cursor, end) = (r.lost, text.lines().count(), r.next, r.end);
        while cursor != end {
            let (r, text) = read(ring, cursor, end);
            lost += r.lost;
            count += text.lines().count();
            cursor = r.next;
        }
        // The next writer of that slot took it back.
        assert_eq!(count, ROOT);
        assert_eq!(lost + count as u64, (ROOT * 3 + 1) as u64);
    }

    #[test]
    fn concurrent_writes_and_reads_never_return_torn_records() {
        let ring = ring();
        let ring = Arc::new(ring);
        let writers: Vec<_> = (0..4u32).map(|id| {
            let ring = Arc::clone(&ring);
            thread::spawn(move || {
                for i in 0..3000u64 {
                    // Different lengths and contents catch mismatched length,
                    // prefix and payload from different generations of a slot.
                    let body = std::format!("{id}:{i}:{}", "x".repeat(i as usize % 180));
                    ring.write(Writer::Blkd(id), 1000 + i, format_args!("{}|{}", body, body));
                }
            })
        }).collect();
        for _ in 0..200 {
            let (_, text) = read(&ring, 0, 0);
            for line in text.lines() {
                let (_, body) = line.split_once("] ").unwrap();
                let (source, body) = body.split_once("] ").unwrap();
                let (a, b) = body.split_once('|').unwrap();
                assert_eq!(a, b);
                assert_eq!(source, std::format!("[0x10{}", &a[..1]));
            }
            thread::yield_now();
        }
        for writer in writers { writer.join().unwrap(); }
    }

    #[test]
    fn rate_limit_lets_a_burst_through_then_one_a_second() {
        let mut limit = RateLimit::<4>::new();
        let hz = 100;
        for _ in 0..RateLimit::<4>::BURST {
            assert_eq!(limit.allow(1, 1000, hz), Some(Suppressed(0)));
        }
        assert_eq!(limit.allow(1, 1000, hz), None);
        assert_eq!(limit.allow(1, 1099, hz), None);
        // Another guest has its own.
        assert_eq!(limit.allow(2, 1099, hz), Some(Suppressed(0)));
        assert_eq!(limit.allow(1, 1100, hz), Some(Suppressed(2)));
        assert_eq!(limit.allow(1, 1100, hz), None);
        // Keys past the end share the last bucket; times that go back or
        // wrap refill nothing and do not panic.
        assert!(limit.allow(usize::MAX, u64::MAX, hz).is_some());
        assert!(limit.allow(3, 0, 0).is_some());
        assert_eq!(std::format!("x{}", Suppressed(3)), "x (3 earlier records not logged)");
    }

    #[test]
    fn writers_and_lanes_agree() {
        for (i, w) in Writer::all().enumerate() {
            assert_eq!(w.index(), i);
            if w != Writer::Dom0 && w != Writer::Root {
                let kind = match w {
                    Writer::Logd => crate::KIND_LOGD,
                    Writer::Memd => crate::KIND_MEMD,
                    Writer::Trustd => crate::KIND_TRUSTD,
                    Writer::Flags => crate::KIND_FLAGS,
                    Writer::Vmmgr => crate::KIND_VMMGR,
                    Writer::Netd => crate::KIND_NETD,
                    Writer::Blkd(_) => crate::KIND_BLKD,
                    Writer::Usbd(_) => crate::KIND_USBD,
                    Writer::Nicd(_) => crate::KIND_NICD,
                    _ => crate::KIND_VMM,
                };
                // A VMM's component id is its guest's.
                let id = match w {
                    Writer::Vmm(g) => g,
                    w => w.id(),
                };
                assert_eq!(Writer::of(kind, id), Some(w));
            }
        }
        // No id is printed for two writers.
        let mut ids: Vec<_> = Writer::all().filter(|&w| w != Writer::Dom0).map(Writer::id).collect();
        ids.sort();
        assert!(ids.windows(2).all(|p| p[0] < p[1]), "{ids:x?}");
        assert_eq!(Writer::all().count(), Writer::COUNT);
        assert_eq!(Writer::of(crate::KIND_BLKD, BLKD_ID_BASE + MAX_BLKDS as u32), None);
        assert_eq!(Writer::of(crate::KIND_VMM, MAX_VMMS as u32), None);
        // Lanes do not overlap, and the VMMs' come first.
        let mut lanes: Vec<_> = Writer::all().filter_map(lane_at).collect();
        lanes.sort_by_key(|l| l.page);
        assert_eq!(lanes[0].page, 0);
        for pair in lanes.windows(2) {
            assert!(pair[0].page + pair[0].pages <= pair[1].page);
        }
        assert_eq!(lane_at(Writer::Vmm(MAX_VMMS as u32 - 1)).map(|l| l.page + l.pages), Some(VMM_PAGES));
        assert!(lanes.last().map(|l| l.page + l.pages) <= Some(PAGES));
        assert_eq!(info_records(lanes_info(7, 1023)), (7, 1023));
    }
}
