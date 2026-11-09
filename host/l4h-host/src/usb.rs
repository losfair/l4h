//! l4h-usbd, the driver of one xHCI controller (DESIGN.md §9.7): its
//! configuration and service calls, and the guest-facing parts that need no
//! hardware: copying and checking the records a guest writes into its
//! queue area (l4h_abi::usb), and laying out the transfer TRBs usbd builds
//! from them.
//!
//! Everything here is pure, so tests/fuzz-usbreq and the unit tests in
//! tests/usb.rs run it on the build host unchanged.  The rules:
//!
//! - usbd reads a guest index once, and checks it against its own copy and
//!   the ring size (`Sq::avail`, `Cq::room`);
//! - a record is copied out of the shared page before it is checked
//!   (`read_record`), since the guest can rewrite it at any time;
//! - every data pointer is a translated segment of the client's I/O pool
//!   (`blk::Pool::translate`); nothing else a guest supplies becomes an
//!   address;
//! - every endpoint field is in the xHCI range for its type and speed.

use l4h_abi::usb as abi;

pub use crate::blk::Pool;
use crate::fixed::ArrayVec;
use core::sync::atomic::AtomicU64;

pub const USBD_ID_BASE: u32 = 0x700;

/// Controllers root lists (DESIGN.md §9.7), and USB controllers a guest
/// may have.
pub const MAX_USB_CTRLS: usize = 16;
pub const MAX_GUEST_USB: usize = abi::MAX_GUEST_USB;
/// Device slots usbd enables (MaxSlotsEn): enough for a hub tree, and
/// bounded tables.
pub const MAX_SLOTS: u32 = 64;
/// usbd's fixed DMA structures: DCBAA, scratchpad array, ERST, command
/// ring, input context, event ring (EVENT_TRBS).
pub const FIXED_BYTES: usize = 128 << 10;
pub const EVENT_TRBS: usize = 4096;

/// Transfer rings in usbd's fixed pool, RING_BYTES each.
pub const USB_RINGS: usize = 256;
/// TRBs of a ring (contiguous, one segment); the last is the Link TRB back
/// to the start.
pub const RING_TRBS: usize = 512;
pub const RING_BYTES: usize = RING_TRBS * 16;
/// TRBs of one URB: a TD (or the TDs of an isoch URB) never takes more of
/// a ring, so a ring always has room for one more URB once it has this
/// many free.
pub const MAX_URB_TRBS: usize = 192;
// A TD crosses the Link TRB only where its data before it ends on a packet
// boundary (xHCI 1.2 §4.11.7.1, `link_ok`); otherwise the URB goes at the
// start after no-ops.  Even an empty ring has room for both.
const _: () = assert!(2 * MAX_URB_TRBS + 1 < RING_TRBS - 1 && USB_RINGS % 64 == 0 && 65536 % RING_BYTES == 0);
/// The largest URB, whatever the pool: 32 x 64 KiB pieces, plus one TRB
/// per segment boundary, fit MAX_URB_TRBS (64 segments, each across a
/// 64 KiB boundary, take 128).
pub const MAX_TRANSFER: u32 = 2 << 20;

/// Bytes of usbd's DMA region for a controller with `slots` device slots
/// and `scratch` scratchpad buffers of `page` bytes: a power of two (an
/// Untyped), at least 4 MiB.
pub fn dma_bytes(slots: u32, scratch: u32, page: u32) -> usize {
    let _ = slots;
    let fixed = FIXED_BYTES + MAX_SLOTS as usize * 4096 // output device contexts
        + USB_RINGS * RING_BYTES;
    // The scratchpad buffers start on a controller page.
    let total = fixed + page as usize + scratch as usize * page as usize;
    total.next_power_of_two().max(4 << 20)
}

use crate::wire::RootOnly;

crate::protocol! {
    /// Root's requests to usbd (crate::mailbox, crate::wire::protocol; a
    /// failed usbd answers wire::FAILED).  Root never waits for usbd, which
    /// a guest drives and could keep busy: it posts a request and finishes
    /// what it was for when usbd has answered.
    pub mod call (from: RootOnly) {
        /// Take the controller from the firmware (legacy handoff, halt,
        /// reset, capability walk).  Posted once, before any guest has the
        /// controller.
        Claim / claim = 1 from [Root] () -> Claimed;
        /// Root has mapped client area `area`'s frames at queue_va(area),
        /// given the VMM's notification at USBD_SLOT_CLIENT_IRQ + area and
        /// turned bus mastering on: start the controller for the pool.
        /// Posted only once the requests before it are answered (bus
        /// mastering stays off while a claim or remove runs).
        Attach / attach = 2 from [Root] (area: usize, gpa: u64, paddr: u64, size: u64) -> ();
        /// Root has turned bus mastering off and taken the notification
        /// away: forget everything, halt and reset the controller and let
        /// go of the area, which root then frees (the next guest gets fresh
        /// frames).  Done once the controller has nothing of the client's
        /// left, also if the attach before it was refused.
        Remove / remove = 3 from [Root] (area: usize) -> ();
    }
}
const _: () = assert!(call::Request::MAX_WORDS <= crate::mailbox::ARGS
    && call::Request::MAX_REPLY_WORDS <= crate::mailbox::ANSWER);

crate::wire_struct! {
    /// A claimed controller: its USB 2 and USB 3 ports, and whether it
    /// addresses 64 bits.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Claimed {
        pub usb2: u16,
        pub usb3: u16,
        pub ac64: bool,
    }
}

/// What usbd publishes in its mailbox (host::mailbox, the second page),
/// for CTL_USB_INFO.
#[repr(C)]
pub struct Published {
    /// Requests refused, controller resets.
    pub refused: AtomicU64,
    pub resets: AtomicU64,
}

/// Badges of usbd's bound notification (badges::usbd).
pub const USBD_BADGE_IRQ: u64 = crate::badges::usbd::IRQ;
/// The client kicked.
pub const USBD_BADGE_KICK: u64 = crate::badges::usbd::KICK;

/// usbd's CSpace slots, beyond the common ones.
pub const USBD_SLOT_IRQ: u64 = 16;
/// Client area idx's VMM notification (badged host::vmm_badge_usb(n)),
/// idx < AREAS.  Root deletes it at `remove` without waiting: usbd signals
/// it with NBSend, which an empty slot ignores.
pub const USBD_SLOT_CLIENT_IRQ: u64 = 32;

/// Client areas: one attached, and one draining (`remove` still running)
/// while the next guest's is already mapped.
pub const AREAS: usize = 2;

/// Where root maps client area `idx` into usbd.
pub const fn queue_va(idx: usize) -> usize {
    crate::SHARED_VA + idx * 0x10_0000
}
const _: () = assert!(abi::AREA_PAGES * 4096 <= 0x10_0000 && queue_va(AREAS) <= crate::MMIO_VA);

/// usbd's configuration (its info page).
#[repr(C)]
pub struct UsbdConfig {
    /// BAR 0, mapped uncached at bar0_va.
    pub bar0_va: u64,
    pub bar0_len: u64,
    pub pci_bdf: u32,
    /// Test builds: make the legacy handoff time out (tests/run-usbtest.sh).
    pub force_handoff_timeout: u32,
    /// The DMA region, physically contiguous: mapped at dma_va.
    pub dma_va: u64,
    pub dma_paddr: u64,
    pub dma_size: u64,
}

// ---------------------------------------------------------------------
// The controller's extended capabilities.

/// What usbd needs of the extended capabilities (xHCI 1.2 §7).
pub struct XCaps {
    /// Offset of USB Legacy Support, if any.
    pub legacy: Option<usize>,
    /// Major revision (2 or 3) of each root port, index = port number.
    pub port_proto: [u8; 256],
}

/// Extended capabilities walked at most.
pub const MAX_XCAPS: usize = 256;

/// Walk the extended capability list from `first` (bytes into BAR 0, 0:
/// none) through `read32`, inside `bar_len` bytes and at most MAX_XCAPS
/// entries: a malformed list (a loop, an offset past the BAR) ends the
/// walk instead of reaching outside it.  Ports outside 1..=max_ports, or
/// claimed twice, are ignored.
pub fn xcaps(read32: impl Fn(usize) -> u32, first: usize, bar_len: usize, max_ports: u32) -> XCaps {
    let mut x = XCaps { legacy: None, port_proto: [0; 256] };
    let mut off = first;
    for _ in 0..MAX_XCAPS {
        if off == 0 || off % 4 != 0 || off.checked_add(16).is_none_or(|e| e > bar_len) {
            break;
        }
        let v = read32(off);
        match v & 0xff {
            1 => x.legacy = x.legacy.or(Some(off)),
            2 => {
                let major = (v >> 24) as u8;
                let ports = read32(off + 8);
                let (start, count) = ((ports & 0xff) as usize, ((ports >> 8) & 0xff) as usize);
                for p in start..start + count {
                    if (1..=max_ports as usize).contains(&p) && p < 256 && x.port_proto[p] == 0 && matches!(major, 2 | 3) {
                        x.port_proto[p] = major;
                    }
                }
            }
            _ => {}
        }
        let next = ((v >> 8) & 0xff) as usize;
        if next == 0 {
            break;
        }
        off += next << 2;
    }
    x
}

// ---------------------------------------------------------------------
// Queue indices.

/// A submission queue the guest produces into: usbd's tail and the size.
#[derive(Clone, Copy, Debug)]
pub struct Sq {
    pub tail: u32,
    pub size: u32,
}

impl Sq {
    /// Records available at the guest's `head`, or None if it is further
    /// from our tail than the queue holds (the guest is broken).
    pub fn avail(&self, head: u32) -> Option<u32> {
        let n = head.wrapping_sub(self.tail);
        (n <= self.size).then_some(n)
    }
}

/// A queue usbd produces into: its head, the size, and the guest's tail
/// as last read.
#[derive(Clone, Copy, Debug)]
pub struct Cq {
    pub head: u32,
    pub size: u32,
}

impl Cq {
    /// Free entries given the guest's `tail`, or None if the tail is not
    /// between our head minus the size and our head.
    pub fn room(&self, tail: u32) -> Option<u32> {
        let used = self.head.wrapping_sub(tail);
        (used <= self.size).then(|| self.size - used)
    }
}

/// Copy record `i` of `n` records of type T at `base`, which the guest can
/// write while we read.
///
/// # Safety
/// `base` must point to n mapped records of T.
pub unsafe fn read_record<T: Copy>(base: *const T, n: u32, i: u32) -> T {
    unsafe { core::ptr::read_volatile(base.add((i % n) as usize)) }
}

// ---------------------------------------------------------------------
// Transfers.

/// A transfer usbd accepted: its data translated to physical addresses.
pub struct Xfer {
    pub tag: u32,
    pub slot: u16,
    pub dci: u8,
    pub ty: u8,
    pub flags: u32,
    pub stream: u32,
    /// Isoch: usbd's choice, set when it is posted (iso_start, iso_next).
    pub start_frame: u32,
    pub length: u32,
    pub setup: [u8; 8],
    /// (physical address, bytes)
    pub segs: ArrayVec<(u64, u32), { abi::MAX_SEGS }>,
    /// (offset, bytes) in the data
    pub iso: ArrayVec<(u32, u32), { abi::MAX_ISO }>,
}

const XF_ALL: u32 = abi::XF_IN | abi::XF_ZERO_PACKET | abi::XF_SHORT_NOT_OK | abi::XF_ISO_ASAP;

/// Check a copied transfer record against the client's pool and translate
/// its segments: Err(ST_INVALID) for anything malformed.  Whether the slot,
/// endpoint and stream exist and match the type is usbd's to check.
pub fn check_xfer(r: &abi::XferReq, pool: &Pool, max_transfer: u32) -> Result<Xfer, i32> {
    let bad = Err(abi::ST_INVALID);
    let (n_segs, n_iso) = (r.n_segs as usize, r.n_iso as usize);
    if r.ty > abi::XFER_ISOC || !(1..=31).contains(&r.dci) || r.flags & !XF_ALL != 0
        || n_segs > abi::MAX_SEGS || n_iso > abi::MAX_ISO || r.length > max_transfer {
        return bad;
    }
    // ep0 carries control transfers only, and they go nowhere else.
    if (r.dci == 1) != (r.ty == abi::XFER_CONTROL) {
        return bad;
    }
    if (r.ty == abi::XFER_ISOC) != (n_iso > 0) {
        return bad;
    }
    let mut segs = ArrayVec::new();
    let mut total: u32 = 0;
    for s in &r.segs[..n_segs] {
        if s.len == 0 {
            return bad;
        }
        let Some(pa) = pool.translate(s.gpa, s.len as u64) else { return bad };
        let Some(t) = total.checked_add(s.len) else { return bad };
        total = t;
        segs.must_push((pa, s.len));
    }
    if total != r.length {
        return bad;
    }
    let mut iso = ArrayVec::new();
    for p in &r.iso[..n_iso] {
        if p.offset.checked_add(p.len).is_none_or(|end| end > r.length) {
            return bad;
        }
        iso.must_push((p.offset, p.len));
    }
    if r.ty == abi::XFER_CONTROL {
        let w_length = u16::from_le_bytes([r.setup[6], r.setup[7]]) as u32;
        let dir_in = r.setup[0] & 0x80 != 0;
        // The data stage's direction is the setup packet's.
        if r.length > w_length || (r.length > 0 && dir_in != (r.flags & abi::XF_IN != 0)) {
            return bad;
        }
    }
    if r.ty != abi::XFER_ISOC && r.flags & abi::XF_ISO_ASAP != 0 {
        return bad;
    }
    Ok(Xfer {
        tag: r.tag, slot: r.slot, dci: r.dci, ty: r.ty, flags: r.flags, stream: r.stream,
        start_frame: r.start_frame, length: r.length, setup: r.setup, segs, iso,
    })
}

// ---------------------------------------------------------------------
// Endpoints and devices.

/// Whether xHCI endpoint context fields `ep` are in range for a device of
/// `speed` (abi::SPEED_*).  xHCI 1.2 §6.2.3, USB 2.0 §5.5-5.8, USB 3.2
/// §9.6.6-9.6.7.
pub fn ep_ok(ep: &abi::Ep, speed: u32) -> bool {
    let (burst, mult) = ((ep.burst_mult & 0xf) as u32, ((ep.burst_mult >> 4) & 3) as u32);
    if ep.burst_mult & 0xc0 != 0 || !(2..=31).contains(&ep.dci) || ep.interval > 15 || !speed_ok(speed) {
        return false;
    }
    // The DCI says the direction: odd IN, even OUT.
    let dir_in = ep.ty >= abi::EP_ISOC_IN;
    if ep.ty != abi::EP_CONTROL && dir_in != (ep.dci % 2 == 1) {
        return false;
    }
    let ss = matches!(speed, abi::SPEED_SUPER | abi::SPEED_SUPER_PLUS);
    let hs = speed == abi::SPEED_HIGH;
    let mps = ep.max_packet as u32;
    // Burst is USB 3's max burst, or high speed's additional transactions
    // of a periodic endpoint; mult only for SuperSpeed isoch.
    let shape = match ep.ty {
        abi::EP_CONTROL => {
            burst == 0 && mult == 0 && match speed {
                abi::SPEED_LOW => mps == 8,
                abi::SPEED_FULL => matches!(mps, 8 | 16 | 32 | 64),
                abi::SPEED_HIGH => mps == 64,
                _ => mps == 512,
            }
        }
        abi::EP_BULK_OUT | abi::EP_BULK_IN => {
            mult == 0 && match speed {
                abi::SPEED_LOW => false,
                abi::SPEED_FULL => burst == 0 && matches!(mps, 8 | 16 | 32 | 64),
                abi::SPEED_HIGH => burst == 0 && mps == 512,
                _ => mps == 1024,
            }
        }
        abi::EP_INT_OUT | abi::EP_INT_IN => {
            mult == 0 && (1..=1024).contains(&mps) && match speed {
                abi::SPEED_LOW => burst == 0 && mps <= 8,
                abi::SPEED_FULL => burst == 0 && mps <= 64,
                abi::SPEED_HIGH => burst <= 2,
                // SuperSpeed: bMaxBurst 0..15, 1024-byte packets to burst.
                _ => burst == 0 || mps == 1024,
            }
        }
        abi::EP_ISOC_OUT | abi::EP_ISOC_IN => {
            // Zero-bandwidth alternate settings have isoch endpoints with
            // no packets.
            mps <= 1024 && match speed {
                abi::SPEED_LOW => false,
                abi::SPEED_FULL => burst == 0 && mult == 0 && mps <= 1023,
                abi::SPEED_HIGH => burst <= 2 && mult == 0,
                _ => mult <= 2 && (burst == 0 && mult == 0 || mps == 1024),
            }
        }
        _ => false,
    };
    let _ = (ss, hs);
    // A periodic endpoint's ESIT payload is at most a service interval's
    // packets: max packet x (burst + 1) x (mult + 1); others have none.
    let periodic = matches!(ep.ty, abi::EP_INT_OUT | abi::EP_INT_IN | abi::EP_ISOC_OUT | abi::EP_ISOC_IN);
    let esit_ok = if periodic { ep.max_esit as u32 <= mps * (burst + 1) * (mult + 1) } else { ep.max_esit == 0 };
    shape && esit_ok
}

/// Whether a route string has at most 5 tiers of hub ports 1..15: each
/// nibble is a port, 0 ends it, and nothing follows a 0.
pub fn route_ok(route: u32) -> bool {
    if route >> 20 != 0 {
        return false;
    }
    let mut end = false;
    for t in 0..5 {
        let p = (route >> (4 * t)) & 0xf;
        if p == 0 {
            end = true;
        } else if end {
            return false;
        }
    }
    true
}

pub fn speed_ok(speed: u32) -> bool {
    (abi::SPEED_FULL..=abi::SPEED_SUPER_PLUS).contains(&speed)
}

/// The PORTSC bits a PORT_SET or PORT_CLEAR names, None if the feature or
/// value is not allowed (xHCI 1.2 §5.4.8).  `portsc_value` makes the
/// value to write from them.
pub fn portsc_write(set: bool, feature: u32, value: u32, usb3: bool) -> Option<u32> {
    const PED: u32 = 1 << 1;
    const PR: u32 = 1 << 4;
    const PP: u32 = 1 << 9;
    const LWS: u32 = 1 << 16;
    const WPR: u32 = 1 << 31;
    const CHANGES: u32 = 0x7f << 17;
    match (set, feature) {
        (true, abi::PF_POWER) => Some(PP),
        (false, abi::PF_POWER) => Some(PP),
        (true, abi::PF_RESET) => Some(PR),
        (true, abi::PF_WARM_RESET) if usb3 => Some(WPR),
        (true, abi::PF_LINK_STATE) => {
            let ok = if usb3 { matches!(value, 0 | 3 | 4 | 5) } else { matches!(value, 0 | 3 | 15) };
            ok.then_some(LWS | value << 5)
        }
        (false, abi::PF_ENABLE) if !usb3 => Some(PED),
        (true, abi::PF_WAKE) | (false, abi::PF_WAKE) if value & !7 == 0 => Some(value << 25),
        (false, abi::PF_CHANGE) if value & !CHANGES == 0 => Some(value),
        _ => None,
    }
}

/// PORTSC bits kept by a write: PP, the wake enables and PIC; everything
/// else is a status, a change (RW1C) or a command bit, written as 0.
pub const PORTSC_PRESERVE: u32 = (1 << 9) | (3 << 14) | (7 << 25);

/// The PORTSC value that applies `bits` (from portsc_write) to the
/// current value `cur`: clearing power or wake enables drops them from
/// the preserved bits; everything else is written as ones (commands, the
/// RW1C enable and change bits).
pub fn portsc_value(cur: u32, set: bool, feature: u32, bits: u32) -> u32 {
    let keep = cur & PORTSC_PRESERVE;
    if !set && matches!(feature, abi::PF_POWER | abi::PF_WAKE) { keep & !bits } else { keep | bits }
}

// ---------------------------------------------------------------------
// TRBs.

pub const TRB_NORMAL: u32 = 1;
pub const TRB_SETUP: u32 = 2;
pub const TRB_DATA: u32 = 3;
pub const TRB_STATUS: u32 = 4;
pub const TRB_ISOCH: u32 = 5;
pub const TRB_LINK: u32 = 6;
pub const TRB_EVENT_DATA: u32 = 7;
pub const TRB_NOOP: u32 = 8;

pub const TRB_CYCLE: u32 = 1 << 0;
pub const TRB_TC: u32 = 1 << 1; // Link: toggle cycle
pub const TRB_ENT: u32 = 1 << 1;
pub const TRB_ISP: u32 = 1 << 2;
pub const TRB_CH: u32 = 1 << 4;
pub const TRB_IOC: u32 = 1 << 5;
pub const TRB_IDT: u32 = 1 << 6;
pub const TRB_BEI: u32 = 1 << 9;
pub const TRB_DIR_IN: u32 = 1 << 16;
pub const TRB_SIA: u32 = 1 << 31;

/// A TRB as usbd builds it, without the cycle bit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Trb {
    pub param: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    pub fn ty(&self) -> u32 {
        (self.control >> 10) & 0x3f
    }
    pub fn len(&self) -> u32 {
        self.status & 0x1ffff
    }
}

/// The TRBs of one URB.
pub type Trbs = ArrayVec<Trb, MAX_URB_TRBS>;
/// The last TRB of each of its TDs (one, or one per isoch packet).
pub type TdEnds = ArrayVec<u16, { abi::MAX_ISO }>;

/// What usbd knows of the endpoint a transfer goes to.
#[derive(Clone, Copy, Debug)]
pub struct EpShape {
    pub max_packet: u32,
    /// Max burst + 1 (USB 3) and mult + 1: packets per service interval
    /// for the isoch TBC fields.
    pub burst: u32,
    pub mult: u32,
    /// HCIVERSION >= 0x100: TD Size counts packets, not KiB.
    pub hci_1_0: bool,
    /// Isoch scheduling: a low or full speed device (its start frame in
    /// frames; at high speed and above, in microframes, as Linux's URB
    /// start_frame), and the service interval in microframes (2^Interval).
    pub full_speed: bool,
    pub period: u32,
    /// The controller when the URB is posted: MFINDEX, its Isochronous
    /// Scheduling Threshold in microframes, and whether it has the
    /// Contiguous Frame ID Capability (without it, or for a Frame ID out
    /// of the valid window, a TD goes as soon as possible, as Linux does).
    pub mfindex: u32,
    pub ist: u32,
    pub cfc: bool,
}

/// Whether URB `trbs` (TDs ending at `ends`) may be written with the Link
/// TRB after its first `before` TRBs: the TD the link falls in has a
/// multiple of `max_packet` data bytes before it (none, or a TD boundary,
/// also does).
pub fn link_ok(trbs: &[Trb], ends: &[u16], before: usize, max_packet: u32) -> bool {
    if before == 0 || before >= trbs.len() {
        return true;
    }
    // The TD holding TRB `before`, and where it starts.
    let td = ends.iter().position(|&e| e as usize >= before).unwrap_or(0);
    let start = if td == 0 { 0 } else { ends[td - 1] as usize + 1 };
    if start == before {
        return true;
    }
    let data: u32 = trbs[start..before].iter()
        .filter(|t| matches!(t.ty(), TRB_NORMAL | TRB_DATA | TRB_ISOCH))
        .map(|t| t.len())
        .fold(0, u32::wrapping_add);
    max_packet != 0 && data % max_packet == 0
}

/// The Frame ID of isoch packet `k` of an URB scheduled from `start`, as
/// Linux's xhci_get_isoc_frame_id: packets one service interval apart.
pub fn iso_frame(ep: &EpShape, start: u32, k: u32) -> u32 {
    let period = ep.period.max(1);
    let frame = if ep.full_speed {
        start.wrapping_add(k.wrapping_mul((period / 8).max(1)))
    } else {
        start.wrapping_add(k.wrapping_mul(period)) >> 3
    };
    frame & 0x7ff
}

/// Where an isoch URB to an idle endpoint starts, as Linux's
/// xhci_queue_isoc_tx_prepare: the next frame after the scheduling
/// threshold and some slack, at a service interval boundary.  In the
/// URB's units (iso_frame).
pub fn iso_start(ep: &EpShape) -> u32 {
    let period = ep.period.max(1);
    let mf = ((ep.mfindex & 0x3fff) + ep.ist + 10).next_multiple_of(8);
    if ep.full_speed {
        (mf.next_multiple_of(period.max(8)) >> 3) & 0x7ff
    } else {
        mf.next_multiple_of(period) & 0x3fff
    }
}

/// Where the URB after one of `n` packets from `start` starts.
pub fn iso_next(ep: &EpShape, start: u32, n: u32) -> u32 {
    let period = ep.period.max(1);
    if ep.full_speed {
        start.wrapping_add(n.wrapping_mul((period / 8).max(1))) & 0x7ff
    } else {
        start.wrapping_add(n.wrapping_mul(period)) & 0x3fff
    }
}

/// Whether Frame ID `frame` may be scheduled now: between MFINDEX + IST
/// + 1 microframe and MFINDEX + 895 ms, in whole frames (xHCI 1.2
/// §4.11.2.5, as Linux's xhci_get_isoc_frame_id).
pub fn iso_frame_ok(ep: &EpShape, frame: u32) -> bool {
    let mf = ep.mfindex & 0x3fff;
    let first = ((mf + ep.ist + 1).next_multiple_of(8) >> 3) & 0x7ff;
    let last = ((mf + 895 * 8) >> 3) & 0x7ff;
    match first.cmp(&last) {
        core::cmp::Ordering::Less => (first..=last).contains(&frame),
        core::cmp::Ordering::Greater => frame >= first || frame <= last,
        core::cmp::Ordering::Equal => false,
    }
}

/// TD Size of a TRB of `len` bytes after `done` bytes of a TD of `total`
/// (xHCI 1.2 §4.11.2.4): packets left after this TRB, at most 31; 0 on the
/// last TRB.
fn td_size(ep: &EpShape, done: u32, len: u32, total: u32) -> u32 {
    if !ep.hci_1_0 {
        return ((total - done - len) >> 10).min(31);
    }
    if done + len == total || ep.max_packet == 0 {
        return 0;
    }
    let packets = total.div_ceil(ep.max_packet);
    (packets - (done + len) / ep.max_packet).min(31)
}

/// The pieces of data [off, off + len) of `x`, split where a TRB buffer
/// may not go: the end of a segment, a 64 KiB boundary.
fn pieces(x: &Xfer, off: u32, len: u32, mut f: impl FnMut(u64, u32) -> Result<(), i32>) -> Result<(), i32> {
    let (mut at, end) = (off, off + len);
    let mut seg_start = 0u32;
    for &(pa, slen) in x.segs.iter() {
        let seg_end = seg_start + slen;
        while at < end && at < seg_end {
            let addr = pa + (at - seg_start) as u64;
            let to_64k = (0x10000 - (addr & 0xffff)) as u32;
            let n = (end.min(seg_end) - at).min(to_64k);
            f(addr, n)?;
            at += n;
        }
        seg_start = seg_end;
        if at >= end {
            break;
        }
    }
    Ok(())
}

/// Lay out transfer `x` to an endpoint shaped `ep` as TRBs: ISP on IN
/// data TRBs, CH within each TD, IOC on the last TRB of each TD (not the
/// data TD before a bulk zero-length packet's: the URB ends with that); for
/// isoch, one TD per packet with BEI on all but the last.  The index of
/// the last TRB of each TD goes to `ends` (a control transfer's stages
/// are one TD, ending at its status stage).  Err(ST_INVALID) if it needs
/// more than MAX_URB_TRBS.
pub fn build_trbs(x: &Xfer, ep: &EpShape, out: &mut Trbs, ends: &mut TdEnds) -> Result<(), i32> {
    out.clear();
    ends.clear();
    let full = || abi::ST_INVALID;
    let dir_in = x.flags & abi::XF_IN != 0;
    let isp = if dir_in { TRB_ISP } else { 0 };
    let push = |out: &mut Trbs, t: Trb| out.push(t).map_err(|_| full());
    match x.ty {
        abi::XFER_CONTROL => {
            let trt = if x.length == 0 { 0 } else if dir_in { 3 } else { 2 };
            push(out, Trb {
                param: u64::from_le_bytes(x.setup),
                status: 8,
                control: TRB_IDT | (TRB_SETUP << 10) | (trt << 16),
            })?;
            let mut done = 0;
            pieces(x, 0, x.length, |pa, n| {
                let ty = if done == 0 { TRB_DATA } else { TRB_NORMAL };
                let dir = if done == 0 && dir_in { TRB_DIR_IN } else { 0 };
                let t = Trb { param: pa, status: n | td_size(ep, done, n, x.length) << 17, control: TRB_CH | isp | (ty << 10) | dir };
                done += n;
                push(out, t)
            })?;
            // The status stage goes the other way (IN when there is no data).
            let status_in = x.length == 0 || !dir_in;
            if let Some(last) = out.last_mut() {
                // The data stage ends before the status stage, its own TD part.
                if last.ty() != TRB_SETUP { last.control &= !TRB_CH; }
            }
            push(out, Trb { param: 0, status: 0, control: TRB_IOC | (TRB_STATUS << 10) | if status_in { TRB_DIR_IN } else { 0 } })?;
            ends.must_push((out.len() - 1) as u16);
        }
        abi::XFER_BULK | abi::XFER_INT => {
            let mut done = 0;
            pieces(x, 0, x.length, |pa, n| {
                let t = Trb { param: pa, status: n | td_size(ep, done, n, x.length) << 17, control: TRB_CH | isp | (TRB_NORMAL << 10) };
                done += n;
                push(out, t)
            })?;
            let zlp = x.flags & abi::XF_ZERO_PACKET != 0 && !dir_in && ep.max_packet != 0
                && x.length > 0 && x.length % ep.max_packet == 0;
            if zlp {
                // The zero-length packet is a TD of its own (xHCI 1.2
                // §4.9.1); the URB completes with it.
                let last = out.last_mut().ok_or_else(full)?;
                last.control &= !TRB_CH;
                ends.must_push((out.len() - 1) as u16);
            }
            if x.length == 0 || zlp {
                push(out, Trb { param: 0, status: 0, control: TRB_CH | (TRB_NORMAL << 10) })?;
            }
            let last = out.last_mut().ok_or_else(full)?;
            last.control = (last.control & !TRB_CH) | TRB_IOC;
            ends.must_push((out.len() - 1) as u16);
        }
        abi::XFER_ISOC => {
            let n_iso = x.iso.len();
            for (k, &(off, len)) in x.iso.iter().enumerate() {
                let first = out.len();
                let packets = if ep.max_packet == 0 { 1 } else { len.div_ceil(ep.max_packet).max(1) };
                // Transfer Burst Count and Last Burst Packet Count
                // (xHCI 1.2 §4.11.2.3), for the controller's scheduling.
                let burst = ep.burst.max(1);
                let tbc = packets.div_ceil(burst) - 1;
                let tlbpc = match packets % burst { 0 => burst - 1, r => r - 1 };
                let id = iso_frame(ep, x.start_frame, k as u32);
                let frame = if x.flags & abi::XF_ISO_ASAP != 0 || !ep.cfc || !iso_frame_ok(ep, id) {
                    TRB_SIA
                } else {
                    id << 20
                };
                let mut done = 0;
                pieces(x, off, len, |pa, n| {
                    let (ty, extra) = if done == 0 {
                        (TRB_ISOCH, (tbc & 3) << 7 | (tlbpc & 0xf) << 16 | frame)
                    } else {
                        (TRB_NORMAL, 0)
                    };
                    let t = Trb { param: pa, status: n | td_size(ep, done, n, len) << 17, control: TRB_CH | isp | (ty << 10) | extra };
                    done += n;
                    push(out, t)
                })?;
                if len == 0 {
                    push(out, Trb { param: 0, status: 0, control: (TRB_ISOCH << 10) | frame })?;
                }
                let n = out.len();
                let last = &mut out[n - 1];
                last.control = (last.control & !TRB_CH) | TRB_IOC | if k + 1 < n_iso { TRB_BEI } else { 0 };
                debug_assert!(out.len() > first);
                ends.must_push((out.len() - 1) as u16);
            }
        }
        _ => return Err(abi::ST_INVALID),
    }
    Ok(())
}

