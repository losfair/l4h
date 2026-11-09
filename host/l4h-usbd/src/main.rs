//! l4h-usbd: drives one xHCI controller for the guest it is assigned to
//! (DESIGN.md §9.7).  It alone writes the controller's registers, rings,
//! contexts and scratchpad, all in its own DMA region; the guest supplies
//! host-controller operations and URBs as records in its queue area, and
//! nothing of them becomes a DMA address but I/O pool segments, which are
//! translated and checked here (l4h_host::usb).  The guest's USB core does
//! enumeration, hubs and class drivers; usbd never parses device data.
//!
//! Records are copied out of the shared pages before they are checked, and
//! usbd never reads back what it published.  It accepts a request only
//! while the guest's completion queue has room for it, so the CQ never
//! overflows and a guest that does not consume completions stalls only
//! itself.  Each turn does a bounded amount of work.
//!
//! Root never calls usbd, which a guest can keep busy: it posts requests
//! (claim, attach, remove) in its mailbox (host::mailbox) and is signalled
//! when they are answered.

#![no_std]
#![no_main]

mod ring;
mod xhci;

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use l4h_abi::usb::{self as abi, Cqe, CtlReq, Event, Info, XferReq};
use l4h_rt::host::usb::{self as proto, Pool, Sq, Trb, UsbdConfig};
use l4h_rt::sel4;
use l4h_rt::host::wire::RootOnly;
use l4h_rt::{cap, host};
use l4h_virtio::Mmio;
use sel4::cap_type;

use crate::ring::{NONE, Rings, Urbs};
use crate::xhci::*;

const EINVAL: u64 = 22;

/// Root's requests, as l4h_host::usb::call declares them.
struct Requests<'a> {
    u: &'a mut Usbd,
    cfg: &'a UsbdConfig,
    tsc_hz: u64,
}

/// A handler's errno as a request's result.
fn errno(e: u64) -> Result<(), u64> {
    if e == 0 { Ok(()) } else { Err(e) }
}

impl proto::call::Server for Requests<'_> {
    fn claim(&mut self, _: RootOnly) -> Result<proto::Claimed, u64> {
        self.u.claim(self.cfg, self.tsc_hz)
    }

    fn attach(&mut self, _: RootOnly, area: usize, gpa: u64, paddr: u64, size: u64) -> Result<(), u64> {
        errno(self.u.attach(area, Pool { gpa, paddr, size }))
    }

    fn remove(&mut self, _: RootOnly, area: usize) -> Result<(), u64> {
        errno(self.u.remove(area))
    }
}
const EIO: u64 = 5;
const EBUSY: u64 = 16;

/// CQ entries transfers leave free: a control request (an URB_CANCEL)
/// always gets in once the guest has consumed its completions, even with
/// every other entry reserved for transfers in flight.
const CTL_RESERVE: u32 = 1;
/// Records taken from each submission queue in one turn: then the event
/// ring and the mailbox get their turn again.
const CTL_BUDGET: u32 = abi::CTL_SQ_SIZE as u32;
const XFER_BUDGET: u32 = abi::XFER_SQ_SIZE as u32;
// Client::skip has a bit per transfer SQ entry.
const _: () = assert!(abi::XFER_SQ_SIZE == 128);

/// Isoch TDs in flight, at most: with every other URB's two events, the
/// event ring (EVENT_TRBS) never fills.
const MAX_ISO_TDS: u32 = 2048;
const _: () = assert!(MAX_ISO_TDS as usize + 2 * abi::CQ_SIZE + 512 < proto::EVENT_TRBS);

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum EpState {
    #[default]
    Disabled,
    Running,
    /// Halted by an error; recovery (Reset Endpoint, Set TR Dequeue) due.
    Halted,
    /// Stopped by a command, or reset: a doorbell restarts it.
    Stopped,
}

#[derive(Clone, Copy, Default)]
pub struct Ep {
    pub state: EpState,
    /// The endpoint as configured.
    pub ep: abi::Ep,
    /// Its ring (no streams), or its stream context array's page.
    pub ring: u16,
    /// Streams (a power of two; 0: none) and their rings, by stream ID.
    pub streams: u16,
    pub stream_rings: [u16; abi::MAX_STREAMS as usize],
}

#[derive(Clone, Copy)]
pub struct Slot {
    pub enabled: bool,
    /// abi::SPEED_*, once addressed (0 before).
    pub speed: u32,
    pub eps: [Ep; 32],
}

impl Slot {
    const EMPTY: Slot = Slot { enabled: false, speed: 0, eps: [Ep { state: EpState::Disabled, ep: abi::Ep { dci: 0, ty: 0, interval: 0, burst_mult: 0, max_packet: 0, max_esit: 0 }, ring: NONE, streams: 0, stream_rings: [NONE; 16] }; 32] };
}

/// The guest the controller is assigned to.
struct Client {
    /// Its area (proto::queue_va), and its notification's slot.
    idx: usize,
    area: usize,
    pool: Pool,
    max_transfer: u32,
    ctl: Sq,
    xfer: Sq,
    cq_head: u32,
    eq_head: u32,
    /// Accepted requests not yet completed.
    in_flight: u32,
    iso_tds: u32,
    reset_seen: u32,
    irq: sel4::cap::Notification,
    /// Something was published since the last signal.
    notify: bool,
    lost: u32,
    /// The transfer SQ waits for CQ room or isoch TDs.
    blocked: bool,
    /// Transfer SQ records cancelled before they were taken (by position
    /// % XFER_SQ_SIZE): skipped, never completed.
    skip: u128,
}

impl Client {
    fn info(&self) -> *mut Info {
        self.area as *mut Info
    }
    fn ctrl(&self) -> *const abi::Ctrl {
        (self.area + 4096) as *const abi::Ctrl
    }
    fn guest(&self, f: impl FnOnce(&abi::Ctrl) -> &abi::Index) -> u32 {
        unsafe { read_volatile(addr_of!(f(&*self.ctrl()).v)) }
    }
    fn publish(&self, f: impl FnOnce(&mut Info) -> &mut abi::Index, v: u32) {
        fence(Ordering::Release);
        unsafe { write_volatile(addr_of_mut!(f(&mut *self.info()).v), v) }
    }
    fn set_state(&self, s: u32) {
        fence(Ordering::Release);
        unsafe { write_volatile(addr_of_mut!((*self.info()).state), s) }
    }
    /// CQ entries the guest has room for, beyond those in flight.
    fn room(&self) -> u32 {
        let c = proto::Cq { head: self.cq_head, size: abi::CQ_SIZE as u32 };
        c.room(self.guest(|c| &c.cq_tail)).map_or(0, |r| r.saturating_sub(self.in_flight))
    }
    fn post_cqe(&mut self, e: &Cqe) {
        let at = (self.area + abi::CQ_OFF) as *mut Cqe;
        unsafe { write_volatile(at.add(self.cq_head as usize % abi::CQ_SIZE), *e) };
        self.cq_head = self.cq_head.wrapping_add(1);
        self.publish(|i| &mut i.cq_head, self.cq_head);
        self.notify = true;
    }
    fn post_event(&mut self, e: Event) {
        let c = proto::Cq { head: self.eq_head, size: abi::EQ_SIZE as u32 };
        if c.room(self.guest(|c| &c.eq_tail)).is_none_or(|r| r == 0) {
            self.lost = self.lost.wrapping_add(1);
            self.publish(|i| &mut i.lost_events, self.lost);
            self.notify = true;
            return;
        }
        let at = (self.area + abi::EQ_OFF) as *mut Event;
        unsafe { write_volatile(at.add(self.eq_head as usize % abi::EQ_SIZE), e) };
        self.eq_head = self.eq_head.wrapping_add(1);
        self.publish(|i| &mut i.eq_head, self.eq_head);
        self.notify = true;
    }
}

fn cqe(tag: u32, kind: u32, status: i32) -> Cqe {
    let mut c: Cqe = unsafe { core::mem::zeroed() };
    c.tag = tag;
    c.kind = kind;
    c.status = status;
    c
}

/// A completion code as a request's status.
pub fn cc_status(cc: u32) -> i32 {
    match cc {
        CC_SUCCESS | CC_SHORT_PACKET => abi::ST_OK,
        CC_STALL => abi::ST_STALL,
        CC_BABBLE => abi::ST_BABBLE,
        CC_TRANSACTION | 36 => abi::ST_PROTO,
        CC_MISSED_SERVICE | CC_RING_UNDERRUN | CC_RING_OVERRUN => abi::ST_MISSED,
        CC_BANDWIDTH | CC_RESOURCE | CC_NO_SLOTS | 35 => abi::ST_NOSPC,
        11 | 12 => abi::ST_NODEV,
        17 | 19 => abi::ST_INVALID,
        _ => abi::ST_IO,
    }
}

/// An error that halts a non-isoch endpoint (xHCI 1.2 §4.10.2).
fn halts(cc: u32) -> bool {
    matches!(cc, CC_STALL | CC_BABBLE | CC_TRANSACTION | CC_TRB | 36)
}

/// Errors that halt a stream endpoint without a TRB to point at: a STALL
/// or transaction error during Prime Pipe, a bad stream ID or context
/// (xHCI 1.2 §4.12.2.1, §4.17.4; Linux's handle_transferless_tx_event).
fn halts_transferless(cc: u32) -> bool {
    matches!(cc, CC_STALL | CC_TRANSACTION | CC_INVALID_STREAM_TYPE | CC_INVALID_STREAM_ID)
}

pub struct Usbd {
    hc: Option<Xhci>,
    client: Option<Client>,
    slots: &'static mut [Slot; proto::MAX_SLOTS as usize + 1],
    pub rings: Rings,
    pub urbs: Urbs,
    /// Endpoints whose halt is to be cleared: (slot, DCI, ring).
    recover: l4h_rt::host::fixed::ArrayVec<(u8, u8, u16), 256>,
    /// Rings a completion made room on, to post their waiting URBs once
    /// no command is running (refill).
    refill: [u64; proto::USB_RINGS / 64],
    refused: u64,
    resets: u64,
    dead: bool,
    errors: l4h_rt::ErrorLimit,
}

static mut SLOTS: [Slot; proto::MAX_SLOTS as usize + 1] = [Slot::EMPTY; proto::MAX_SLOTS as usize + 1];

impl Usbd {
    fn hc(&mut self) -> &mut Xhci {
        self.hc.as_mut().expect("claimed")
    }

    fn hci_1_0(&self) -> bool {
        self.hc.as_ref().is_some_and(|h| h.caps.hci_version >= 0x100)
    }

    // ---- Events.

    /// Drain the event ring, handing every event but the completion of
    /// command `cmd` (its TRB's address) to `event`: that one's result.
    fn events_until(&mut self, cmd: Option<u64>) -> Option<CmdResult> {
        let mut batch = Events::new();
        let mut result = None;
        loop {
            let Some(hc) = self.hc.as_mut() else { return None };
            if !hc.take_events(&mut batch) {
                return result;
            }
            for ev in batch.iter() {
                if ev.ty() == EV_COMMAND && Some(ev.param) == cmd {
                    result = Some((ev.status >> 24, ev.control >> 24));
                } else {
                    self.event(ev);
                }
            }
        }
    }

    fn events(&mut self) {
        let _ = self.events_until(None);
    }

    /// Run a command, handling the events that come meanwhile.  None if it
    /// timed out: the controller is then reset.
    fn command(&mut self, trb: Trb) -> Option<CmdResult> {
        let pa = self.hc.as_mut()?.submit_command(trb)?;
        let end = self.hc.as_ref()?.command_deadline();
        loop {
            if let Some(r) = self.events_until(Some(pa)) {
                return Some(r);
            }
            let hc = self.hc.as_mut()?;
            let sts = hc.sts();
            if l4h_rt::host::ticks::now() > end || sts & (STS_HSE | STS_HCE) != 0 {
                l4h_rt::log!("l4h-usbd: command {} timed out or the controller failed (USBSTS {:#x})", trb.ty(), sts);
                hc.broken = true;
                self.hc_failed();
                return None;
            }
            core::hint::spin_loop();
        }
    }

    fn event(&mut self, ev: &Trb) {
        match ev.ty() {
            EV_TRANSFER => self.transfer_event(ev),
            EV_PORT => {
                let port = (ev.param >> 24) as u32 & 0xff;
                let Some(hc) = &self.hc else { return };
                if !(1..=hc.caps.max_ports).contains(&port) {
                    return;
                }
                let portsc = hc.portsc(port);
                if let Some(c) = &mut self.client {
                    c.post_event(Event { ty: abi::EV_PORT, port, portsc, reserved: [0; 5] });
                }
            }
            EV_HOST => {
                if ev.status >> 24 == CC_EVENT_RING_FULL && self.errors.allow() {
                    l4h_rt::log!("l4h-usbd: event ring full");
                }
            }
            _ => {}
        }
    }

    fn transfer_event(&mut self, ev: &Trb) {
        let (slot, dci) = ((ev.control >> 24) as usize, ((ev.control >> 16) & 0x1f) as usize);
        let (cc, resid) = (ev.status >> 24, ev.status & 0xff_ffff);
        if slot == 0 || slot > proto::MAX_SLOTS as usize || dci == 0 || ev.control & (1 << 2) != 0 {
            return;
        }
        let ep = self.slots[slot].eps[dci];
        if ep.state == EpState::Disabled {
            return;
        }
        if ev.param == 0 {
            // A stream endpoint halted between TDs: reset it, with no URB
            // to complete or skip (recover_all).
            if ep.streams != 0 && halts_transferless(cc) && ep.state != EpState::Halted {
                self.slots[slot].eps[dci].state = EpState::Halted;
                let _ = self.recover.push((slot as u8, dci as u8, NONE));
            }
            // Otherwise (a Missed Service event may have no pointer) the
            // next event with one says where the controller is (below).
            return;
        }
        let Some(hc) = &self.hc else { return };
        let dma = hc.dma;
        // The ring the TRB is on: the endpoint's, or one of its streams'.
        let in_ring = |r: u16| r != NONE && ev.param.wrapping_sub(dma.pa(dma.ring(r as usize))) < (proto::RING_TRBS * 16) as u64;
        let r = if ep.streams == 0 {
            ep.ring
        } else {
            ep.stream_rings[..ep.streams as usize].iter().copied().find(|&r| in_ring(r)).unwrap_or(NONE)
        };
        if !in_ring(r) {
            return;
        }
        let pos = ((ev.param - dma.pa(dma.ring(r as usize))) / 16) as u16;
        if pos as usize >= proto::RING_TRBS - 1 {
            return;
        }
        // The oldest URB on the ring: an event for an older one is stale.
        let mut u = self.rings.get(r).head;
        if u == NONE || !self.urbs.get(u).posted {
            return;
        }
        let mut dist = self.rings.dist(r, self.urbs.get(u).first, pos);
        if dist >= self.urbs.get(u).ntrbs {
            // Isoch: an event on a later posted URB shows the controller
            // past the ones before it, whose TDs it missed (a Missed
            // Service event, which may carry no TRB pointer, skips several)
            // or failed mid TD with no event for their end.
            if self.urbs.get(u).xfer.ty != abi::XFER_ISOC {
                return;
            }
            let mut n = self.urbs.get(u).next;
            let d = loop {
                if n == NONE || !self.urbs.get(n).posted {
                    return;
                }
                let d = self.rings.dist(r, self.urbs.get(n).first, pos);
                if d < self.urbs.get(n).ntrbs {
                    break d;
                }
                n = self.urbs.get(n).next;
            };
            while u != n {
                let next = self.urbs.get(u).next;
                let len = self.urbs.get(u).ends.len();
                self.iso_passed(u, len);
                self.iso_done(u, r);
                u = next;
            }
            dist = d;
        }
        if matches!(cc, CC_STOPPED | CC_STOPPED_LENGTH_INVALID | CC_STOPPED_SHORT) {
            // A Stop Endpoint for a cancel: what it did of the TD.  Stopped
            // - Short Packet reports the TD's bytes, Stopped - Length
            // Invalid none for its TRB (xHCI 1.2 §4.6.9).
            let (before, at) = self.data_bytes(r, u, dist);
            let done = match cc {
                CC_STOPPED_SHORT => resid.min(before.saturating_add(at)),
                CC_STOPPED_LENGTH_INVALID => before,
                _ => before.saturating_add(at.saturating_sub(resid)),
            };
            let urb = self.urbs.get_mut(u);
            urb.actual = done;
            if urb.xfer.ty == abi::XFER_ISOC {
                urb.stopped = urb.ends.iter().position(|&e| e >= dist).map_or(NONE, |t| t as u16);
            }
            return;
        }
        let ty = self.urbs.get(u).xfer.ty;
        let last = self.urbs.get(u).ntrbs - 1;
        match ty {
            abi::XFER_ISOC => self.iso_event(r, u, dist, cc, resid),
            abi::XFER_CONTROL => {
                if dist == last {
                    let urb = self.urbs.get(u);
                    let actual = if urb.short { urb.actual } else { urb.xfer.length };
                    let mut st = cc_status(cc);
                    if st == abi::ST_OK && urb.short && urb.xfer.flags & abi::XF_SHORT_NOT_OK != 0 {
                        st = abi::ST_SHORT;
                    }
                    self.complete(u, st, actual, slot, dci, r, halts(cc));
                } else if cc == CC_SHORT_PACKET {
                    let done = self.bytes(r, u, dist, resid);
                    let urb = self.urbs.get_mut(u);
                    urb.actual = done;
                    urb.short = true;
                } else if cc != CC_SUCCESS {
                    let done = self.bytes(r, u, dist, resid);
                    self.complete(u, cc_status(cc), done, slot, dci, r, halts(cc));
                }
            }
            _ => {
                let urb = self.urbs.get(u);
                let (length, flags) = (urb.xfer.length, urb.xfer.flags);
                if cc == CC_SUCCESS && dist == last {
                    self.complete(u, abi::ST_OK, length, slot, dci, r, false);
                } else if cc == CC_SUCCESS {
                    // No IOC there: a controller reporting more than asked.
                } else {
                    let done = self.bytes(r, u, dist, resid).min(length);
                    let mut st = cc_status(cc);
                    if cc == CC_SHORT_PACKET && flags & abi::XF_SHORT_NOT_OK != 0 {
                        st = abi::ST_SHORT;
                    }
                    self.complete(u, st, done, slot, dci, r, halts(cc));
                }
            }
        }
    }

    /// Data bytes of URB `u` done when its TRB `dist` reported `resid`
    /// bytes left — the data TRBs before it, from the start of its TD for
    /// isoch.
    fn bytes(&self, r: u16, u: u16, dist: u16, resid: u32) -> u32 {
        let (before, at) = self.data_bytes(r, u, dist);
        before.saturating_add(at.saturating_sub(resid))
    }

    /// Data bytes of URB `u`'s TRBs before its TRB `dist` (from the start
    /// of its TD for isoch), and of TRB `dist`.
    fn data_bytes(&self, r: u16, u: u16, dist: u16) -> (u32, u32) {
        let urb = self.urbs.get(u);
        let start = if urb.xfer.ty == abi::XFER_ISOC {
            let t = urb.ends.iter().position(|&e| e >= dist).unwrap_or(0);
            if t == 0 { 0 } else { urb.ends[t - 1] + 1 }
        } else {
            0
        };
        let (mut before, mut at) = (0u32, 0u32);
        for k in start..=dist {
            let t = self.rings.trb(self.hc.as_ref().unwrap().dma, r, urb.first, k);
            if matches!(t.ty(), proto::TRB_NORMAL | proto::TRB_DATA | proto::TRB_ISOCH) {
                if k == dist { at = t.len() } else { before = before.saturating_add(t.len()) }
            }
        }
        (before, at)
    }

    fn iso_event(&mut self, r: u16, u: u16, dist: u16, cc: u32, resid: u32) {
        let urb = self.urbs.get(u);
        let Some(t) = urb.ends.iter().position(|&e| e >= dist) else { return };
        if (t as u16) < urb.td {
            return;
        }
        let end = dist == urb.ends[t];
        if urb.mid && t as u16 == urb.td {
            // More of the TD that failed: it is over at its last TRB.
            if end {
                self.iso_passed(u, t + 1);
                self.iso_done(u, r);
            }
            return;
        }
        let st = cc_status(cc);
        let done = if cc == CC_SUCCESS { urb.xfer.iso[t].1 } else { self.bytes(r, u, dist, resid) };
        self.iso_passed(u, t);
        let urb = self.urbs.get_mut(u);
        urb.iso[t] = abi::IsoStatus { status: st, actual: if st == abi::ST_OK { done } else { 0 } };
        if st != abi::ST_OK {
            urb.errors += 1;
        }
        if st != abi::ST_OK && !end && cc != CC_MISSED_SERVICE {
            // An error before the TD's last TRB: the controller may still
            // go through the rest of it (xHCI 1.2 §4.9.1), so its TRBs
            // stay until an event shows it is past them.
            urb.mid = true;
            return;
        }
        urb.td = t as u16 + 1;
        self.iso_done(u, r);
    }

    /// Isoch URB `u`'s TDs before `to` are behind the controller: one that
    /// failed mid TD keeps its error, the others it skipped (missed
    /// service) report nothing.
    fn iso_passed(&mut self, u: u16, to: usize) {
        let urb = self.urbs.get_mut(u);
        let mut k = urb.td as usize;
        if urb.mid && k < to {
            urb.mid = false;
            k += 1;
        }
        for k in k..to {
            urb.iso[k] = abi::IsoStatus { status: abi::ST_MISSED, actual: 0 };
            urb.errors += 1;
        }
        urb.td = urb.td.max(to as u16);
    }

    /// Complete isoch URB `u` if all its TDs are done.
    fn iso_done(&mut self, u: u16, r: u16) {
        let urb = self.urbs.get(u);
        let n = urb.ends.len();
        if urb.td as usize == n && !urb.mid {
            let (slot, dci) = (urb.xfer.slot as usize, urb.xfer.dci as usize);
            let actual = urb.iso[..n].iter().map(|s| s.actual).sum();
            self.complete(u, abi::ST_OK, actual, slot, dci, r, false);
        }
    }

    /// Complete URB `u` and take it off its ring; `halted`: the endpoint
    /// stopped on it.
    #[allow(clippy::too_many_arguments)]
    fn complete(&mut self, u: u16, status: i32, actual: u32, slot: usize, dci: usize, r: u16, halted: bool) {
        let urb = self.urbs.get(u);
        let mut c = cqe(urb.xfer.tag, abi::CQ_XFER, status);
        c.actual = actual;
        c.start_frame = urb.xfer.start_frame;
        if urb.xfer.ty == abi::XFER_ISOC {
            let n = urb.ends.len();
            c.n_iso = n as u32;
            c.error_count = urb.errors;
            c.iso[..n].copy_from_slice(&urb.iso[..n]);
        }
        // What transfer() reserved, posted or not.
        let iso_tds = if urb.xfer.ty == abi::XFER_ISOC { urb.xfer.iso.len() as u32 } else { 0 };
        self.rings.unlink(&mut self.urbs, r, u);
        self.urbs.free(u);
        if halted && self.slots[slot].eps[dci].state != EpState::Disabled {
            self.slots[slot].eps[dci].state = EpState::Halted;
            let _ = self.recover.push((slot as u8, dci as u8, r));
        } else {
            // Its TRBs are free: URBs waiting for room can go on.
            self.refill[r as usize / 64] |= 1 << (r % 64);
        }
        if let Some(cl) = &mut self.client {
            cl.in_flight -= 1;
            cl.iso_tds -= iso_tds;
            cl.blocked = false;
            cl.post_cqe(&c);
        }
    }

    // ---- Rings.

    /// Post what waits on the rings completions made room on.  Not while
    /// a command runs: a doorbell would restart an endpoint being stopped.
    fn refill(&mut self) {
        for w in 0..self.refill.len() {
            while self.refill[w] != 0 {
                let b = self.refill[w].trailing_zeros() as usize;
                self.refill[w] &= !(1 << b);
                let r = (w * 64 + b) as u16;
                if self.rings.get(r).used && self.rings.first_waiting(&self.urbs, r) != NONE {
                    self.post(r);
                }
            }
        }
    }

    /// Put the URBs waiting on ring `r` on it, as far as there is room, and
    /// ring the doorbell.
    fn post(&mut self, r: u16) {
        let ring = *self.rings.get(r);
        let (slot, dci) = (ring.slot as usize, ring.dci as usize);
        let ep = self.slots[slot].eps[dci];
        if ep.state == EpState::Disabled || ep.state == EpState::Halted {
            return;
        }
        let shape = proto::EpShape {
            max_packet: ep.ep.max_packet as u32 & 0x7ff,
            burst: (ep.ep.burst_mult & 0xf) as u32 + 1,
            mult: ((ep.ep.burst_mult >> 4) & 3) as u32 + 1,
            hci_1_0: self.hci_1_0(),
            full_speed: matches!(self.slots[slot].speed, abi::SPEED_LOW | abi::SPEED_FULL),
            period: 1 << (ep.ep.interval & 15),
            mfindex: self.hc.as_ref().unwrap().mfindex(),
            ist: self.hc.as_ref().unwrap().caps.ist,
            cfc: self.hc.as_ref().unwrap().caps.cfc,
        };
        let shape = if dci == 1 { proto::EpShape { max_packet: self.ep0_mps(slot), ..shape } } else { shape };
        let dma = self.hc.as_ref().unwrap().dma;
        let mut posted = false;
        let mut u = self.rings.first_waiting(&self.urbs, r);
        while u != NONE {
            let mut trbs = proto::Trbs::new();
            let mut ends = proto::TdEnds::new();
            let head = self.rings.get(r).head;
            if self.urbs.get(u).xfer.ty == abi::XFER_ISOC {
                // Right after the URBs on the ring, or when the endpoint
                // can next be served (the USB core leaves it to the HCD).
                let start = if head != u { self.rings.get(r).next_frame } else { proto::iso_start(&shape) };
                self.urbs.get_mut(u).xfer.start_frame = start;
            }
            let urb = self.urbs.get(u);
            if proto::build_trbs(&urb.xfer, &shape, &mut trbs, &mut ends).is_err() {
                // Checked when accepted: it fits MAX_URB_TRBS.
                break;
            }
            let to_end = self.rings.to_end(r);
            let pad = trbs.len() > to_end && !proto::link_ok(&trbs, &ends, to_end, shape.max_packet);
            if !self.rings.room(r, trbs.len(), pad) {
                break;
            }
            // The no-ops of the padding stay the controller's until it is
            // past them: the URB's, from where they start.
            let start = self.rings.get(r).enq;
            let first = self.rings.write(dma, r, &trbs, pad);
            let next = urb.next;
            if urb.xfer.ty == abi::XFER_ISOC {
                self.rings.get_mut(r).next_frame = proto::iso_next(&shape, urb.xfer.start_frame, urb.xfer.iso.len() as u32);
            }
            if head == u {
                self.rings.get_mut(r).deq = start;
            }
            let urb = self.urbs.get_mut(u);
            urb.start = start;
            urb.first = first;
            urb.ntrbs = trbs.len() as u16;
            urb.ends = ends;
            urb.posted = true;
            posted = true;
            u = next;
        }
        if posted {
            self.slots[slot].eps[dci].state = EpState::Running;
            let target = dci as u32 | (ring.stream as u32) << 16;
            self.hc().ring_db(slot as u32, target);
        }
    }

    fn ep0_mps(&self, slot: usize) -> u32 {
        let Some(hc) = &self.hc else { return 8 };
        let ctx = Mmio(hc.dma.va(hc.dma.out_ctx(slot as u32)) + hc.caps.ctx_size);
        (ctx.r32(4) >> 16).max(8)
    }

    /// Clear the halts the event handler found: Reset Endpoint, then Set TR
    /// Dequeue past the URB that failed (none for a stream endpoint's
    /// transferless halt, ring NONE: its streams' dequeue pointers stay),
    /// then restart the rings.
    fn recover_all(&mut self) {
        while let Some((slot, dci, r)) = self.recover.pop() {
            let (s, d) = (slot as usize, dci as usize);
            if self.slots[s].eps[d].state != EpState::Halted || self.hc.as_ref().is_none_or(|h| h.broken) {
                continue;
            }
            let reset = Trb { param: 0, status: 0, control: (CMD_RESET_EP << 10) | (dci as u32) << 16 | (slot as u32) << 24 };
            if self.command(reset).is_none() {
                return;
            }
            if r != NONE {
                self.set_deq(s, d, r);
            }
            self.slots[s].eps[d].state = EpState::Stopped;
            // The other rings of a stream endpoint start again too.
            let ep = self.slots[s].eps[d];
            if ep.streams == 0 {
                self.post_or_ring(s, d, r);
            } else {
                for &sr in &ep.stream_rings[1..ep.streams as usize] {
                    self.post_or_ring(s, d, sr);
                }
            }
        }
    }

    /// Restart ring `r`: post what waits, or ring the doorbell if TRBs are
    /// already on it.
    fn post_or_ring(&mut self, slot: usize, dci: usize, r: u16) {
        if self.rings.get(r).head == NONE {
            return;
        }
        if self.urbs.get(self.rings.get(r).head).posted {
            self.slots[slot].eps[dci].state = EpState::Running;
            let target = dci as u32 | (self.rings.get(r).stream as u32) << 16;
            self.hc().ring_db(slot as u32, target);
        }
        self.post(r);
    }

    /// Point the endpoint (stopped or halted) at the oldest URB still on
    /// ring `r`, or at the ring's enqueue pointer.
    fn set_deq(&mut self, slot: usize, dci: usize, r: u16) {
        let dma = self.hc.as_ref().unwrap().dma;
        let (pos, cycle) = self.rings.resume_point(dma, &self.urbs, r);
        let ring = self.rings.get(r);
        let stream = ring.stream as u32;
        let sct = if stream != 0 { 1 << 1 } else { 0 };
        let param = dma.pa(dma.ring(r as usize) + pos as usize * 16) | sct | cycle as u64;
        let trb = Trb { param, status: stream << 16, control: (CMD_SET_TR_DEQ << 10) | (dci as u32) << 16 | (slot as u32) << 24 };
        let _ = self.command(trb);
        self.rings.get_mut(r).deq = pos;
    }

    // ---- Requests.

    fn client_slot(&self, slot: u16) -> Option<usize> {
        let s = slot as usize;
        let max = self.hc.as_ref()?.caps.max_slots as usize;
        (1..=max).contains(&s).then_some(s).filter(|&s| self.slots[s].enabled)
    }

    fn port_ok(&self, port: u32) -> bool {
        self.hc.as_ref().is_some_and(|h| (1..=h.caps.max_ports).contains(&port) && h.caps.port_proto[port as usize] != 0)
    }

    /// A control request: its completion.
    fn control(&mut self, r: &CtlReq) -> Cqe {
        let mut c = cqe(r.tag, abi::CQ_CTL, abi::ST_OK);
        let st = self.control_op(r, &mut c.val);
        if st == abi::ST_INVALID {
            self.refused += 1;
        }
        c.status = st;
        c
    }

    fn control_op(&mut self, r: &CtlReq, val: &mut [u32; 2]) -> i32 {
        let arg = unsafe { r.body.arg };
        if self.hc.as_ref().is_none_or(|h| h.broken) || self.dead {
            return abi::ST_SHUTDOWN;
        }
        match r.op {
            abi::OP_PORT_GET => {
                if !self.port_ok(r.port as u32) {
                    return abi::ST_INVALID;
                }
                val[0] = self.hc().portsc(r.port as u32);
                abi::ST_OK
            }
            abi::OP_PORT_SET | abi::OP_PORT_CLEAR => {
                let port = r.port as u32;
                if !self.port_ok(port) {
                    return abi::ST_INVALID;
                }
                let usb3 = self.hc().caps.port_proto[port as usize] == 3;
                let set = r.op == abi::OP_PORT_SET;
                let Some(bits) = proto::portsc_write(set, arg[0], arg[1], usb3) else { return abi::ST_INVALID };
                let cur = self.hc().portsc(port);
                self.hc().set_portsc(port, proto::portsc_value(cur, set, arg[0], bits));
                abi::ST_OK
            }
            abi::OP_SLOT_ENABLE => {
                let Some((cc, slot)) = self.command(Trb { param: 0, status: 0, control: CMD_ENABLE_SLOT << 10 }) else {
                    return abi::ST_TIMEOUT;
                };
                if cc != CC_SUCCESS {
                    return cc_status(cc);
                }
                let max = self.hc().caps.max_slots;
                if !(1..=max).contains(&slot) {
                    // Beyond MaxSlotsEn: the controller is broken.
                    return abi::ST_IO;
                }
                let s = &mut self.slots[slot as usize];
                *s = Slot::EMPTY;
                s.enabled = true;
                let hc = self.hc();
                let ctx = hc.dma.out_ctx(slot);
                unsafe { core::ptr::write_bytes(hc.dma.va(ctx) as *mut u8, 0, PAGE) };
                hc.set_dcbaa(slot, Some(hc.dma.pa(ctx)));
                val[0] = slot;
                abi::ST_OK
            }
            abi::OP_SLOT_DISABLE => {
                let Some(s) = self.client_slot(r.slot) else { return abi::ST_INVALID };
                for dci in 1..32 {
                    self.drop_ep(s, dci);
                }
                let r = self.command(Trb { param: 0, status: 0, control: CMD_DISABLE_SLOT << 10 | (s as u32) << 24 });
                self.slots[s] = Slot::EMPTY;
                if let Some(hc) = &self.hc {
                    hc.set_dcbaa(s as u32, None);
                }
                match r {
                    Some((CC_SUCCESS, _)) => abi::ST_OK,
                    Some((cc, _)) => cc_status(cc),
                    None => abi::ST_TIMEOUT,
                }
            }
            abi::OP_ADDRESS => self.address(r, val),
            abi::OP_EP_CONFIG => self.ep_config(r),
            abi::OP_HUB_CONFIG => self.hub_config(r.slot, arg[0], arg[1], arg[2]),
            abi::OP_EP0_MPS => self.ep0_mps_set(r.slot, arg[0]),
            abi::OP_DEV_RESET => {
                let Some(s) = self.client_slot(r.slot) else { return abi::ST_INVALID };
                let res = self.command(Trb { param: 0, status: 0, control: CMD_RESET_DEVICE << 10 | (s as u32) << 24 });
                // Every endpoint but ep0 is disabled now.
                for dci in 2..32 {
                    self.drop_ep(s, dci);
                }
                match res {
                    Some((CC_SUCCESS, _)) => abi::ST_OK,
                    Some((cc, _)) => cc_status(cc),
                    None => abi::ST_TIMEOUT,
                }
            }
            abi::OP_EP_RESET => self.ep_reset(r.slot, arg[0]),
            abi::OP_STREAMS_ALLOC => self.streams(r.slot, r.drop, arg[0]),
            abi::OP_STREAMS_FREE => self.streams(r.slot, r.drop, 0),
            abi::OP_URB_CANCEL => self.cancel(arg[0]),
            _ => abi::ST_INVALID,
        }
    }

    /// Complete every URB on endpoint (slot, dci) with SHUTDOWN and free its
    /// rings: the controller no longer uses them (dropped, disabled, reset).
    fn drop_ep(&mut self, s: usize, dci: usize) {
        let ep = self.slots[s].eps[dci];
        if ep.state == EpState::Disabled && ep.ring == NONE {
            return;
        }
        let mut rings = l4h_rt::host::fixed::ArrayVec::<u16, 17>::new();
        if ep.streams == 0 {
            rings.must_push(ep.ring);
        } else {
            for &r in &ep.stream_rings[1..ep.streams as usize] {
                rings.must_push(r);
            }
            rings.must_push(ep.ring);
        }
        for &r in rings.iter() {
            if r == NONE {
                continue;
            }
            while self.rings.get(r).head != NONE {
                let u = self.rings.get(r).head;
                self.complete(u, abi::ST_SHUTDOWN, 0, s, dci, r, false);
            }
            self.rings.free(r);
        }
        self.slots[s].eps[dci] = Slot::EMPTY.eps[0];
    }

    fn address(&mut self, r: &CtlReq, val: &mut [u32; 2]) -> i32 {
        let arg = unsafe { r.body.arg };
        let Some(s) = self.client_slot(r.slot) else { return abi::ST_INVALID };
        let (route, speed, tt_slot, tt_port, mtt, mps, bsr) = (arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], arg[6]);
        let mps_ok = match speed {
            abi::SPEED_LOW => mps == 8,
            abi::SPEED_FULL => matches!(mps, 8 | 16 | 32 | 64),
            abi::SPEED_HIGH => mps == 64,
            _ => mps == 512,
        };
        let tt_ok = tt_slot == 0 || (tt_slot <= 255 && self.client_slot(tt_slot as u16).is_some() && (1..=255).contains(&tt_port));
        if !proto::speed_ok(speed) || !proto::route_ok(route) || !self.port_ok(r.port as u32) || !mps_ok || !tt_ok
            || mtt > 1 || bsr > 1 {
            return abi::ST_INVALID;
        }
        // ep0's ring, new or emptied.
        let ep0 = self.slots[s].eps[1];
        let ring = if ep0.ring == NONE {
            match self.rings.alloc(s as u8, 1, 0) {
                Some(r) => r,
                None => return abi::ST_NOSPC,
            }
        } else {
            if self.rings.get(ep0.ring).head != NONE {
                return abi::ST_INVALID;
            }
            ep0.ring
        };
        let dma = self.hc().dma;
        self.rings.reinit(dma, ring);
        let cs = self.hc().caps.ctx_size;
        let (ictx, ipa) = self.hc().input_ctx();
        ictx.w32(4, 0b11); // add: slot, ep0
        let slot_ctx = Mmio(ictx.0 + cs);
        slot_ctx.w32(0, route | speed << 20 | mtt << 25 | 1 << 27);
        slot_ctx.w32(4, (r.port as u32) << 16);
        slot_ctx.w32(8, tt_slot | tt_port << 8);
        let ep_ctx = Mmio(ictx.0 + 2 * cs);
        ep_ctx.w32(4, 3 << 1 | (abi::EP_CONTROL as u32) << 3 | mps << 16);
        ep_ctx.w64(8, dma.pa(dma.ring(ring as usize)) | 1);
        ep_ctx.w32(16, 8);
        let res = self.command(Trb { param: ipa, status: 0, control: CMD_ADDRESS_DEVICE << 10 | bsr << 9 | (s as u32) << 24 });
        self.slots[s].eps[1] = Ep {
            state: EpState::Stopped,
            ep: abi::Ep { dci: 1, ty: abi::EP_CONTROL, interval: 0, burst_mult: 0, max_packet: mps as u16, max_esit: 0 },
            ring, streams: 0, stream_rings: [NONE; 16],
        };
        match res {
            Some((CC_SUCCESS, _)) => {
                self.slots[s].speed = speed;
                let hc = self.hc();
                val[0] = Mmio(hc.dma.va(hc.dma.out_ctx(s as u32))).r32(12) & 0xff;
                abi::ST_OK
            }
            Some((cc, _)) => cc_status(cc),
            None => abi::ST_TIMEOUT,
        }
    }

    /// The input context for a Configure Endpoint or Evaluate Context of
    /// slot `s`: its slot context copied from the output context.
    fn input_from_out(&mut self, s: usize) -> (Mmio, u64, usize) {
        let hc = self.hc();
        let cs = hc.caps.ctx_size;
        let out = Mmio(hc.dma.va(hc.dma.out_ctx(s as u32)));
        let (ictx, ipa) = hc.input_ctx();
        for w in 0..3 {
            ictx.w32(cs + 4 * w, out.r32(4 * w));
        }
        (ictx, ipa, cs)
    }

    fn ep_ctx(&mut self, ictx: Mmio, cs: usize, ep: &abi::Ep, ring_pa: u64, streams: u16) {
        let c = Mmio(ictx.0 + cs * (1 + ep.dci as usize));
        let isoc = matches!(ep.ty, abi::EP_ISOC_IN | abi::EP_ISOC_OUT);
        let periodic = isoc || matches!(ep.ty, abi::EP_INT_IN | abi::EP_INT_OUT);
        let (burst, mult) = ((ep.burst_mult & 0xf) as u32, ((ep.burst_mult >> 4) & 3) as u32);
        let pstreams = if streams > 1 { streams.trailing_zeros() - 1 } else { 0 };
        let lsa = if streams > 1 { 1 << 15 } else { 0 };
        c.w32(0, mult << 8 | pstreams << 10 | lsa | (ep.interval as u32) << 16);
        let cerr = if isoc { 0 } else { 3 };
        c.w32(4, cerr << 1 | (ep.ty as u32) << 3 | burst << 8 | (ep.max_packet as u32) << 16);
        c.w64(8, ring_pa | if streams > 1 { 0 } else { 1 });
        let avg = if periodic { (ep.max_esit as u32).max(1) } else { 3072 };
        c.w32(16, avg | (ep.max_esit as u32) << 16);
    }

    fn ep_config(&mut self, r: &CtlReq) -> i32 {
        let Some(s) = self.client_slot(r.slot) else { return abi::ST_INVALID };
        let speed = self.slots[s].speed;
        let n = r.n_eps as usize;
        let eps = unsafe { r.body.eps };
        if speed == 0 || n > abi::CTL_EPS || r.drop & 0b11 != 0 {
            return abi::ST_INVALID;
        }
        let mut add = 0u32;
        for e in &eps[..n] {
            // ep_ok first: the DCI is in 2..=31 then.
            if !proto::ep_ok(e, speed) {
                return abi::ST_INVALID;
            }
            let bit = 1u32 << e.dci;
            let enabled = self.slots[s].eps[e.dci as usize].state != EpState::Disabled;
            if add & bit != 0 || (enabled && r.drop & bit == 0) {
                return abi::ST_INVALID;
            }
            add |= bit;
        }
        for d in 2..32 {
            if r.drop & (1 << d) != 0 && self.slots[s].eps[d].state == EpState::Disabled {
                return abi::ST_INVALID;
            }
        }
        // New rings first: nothing changes if there are not enough.
        let mut new = [NONE; 32];
        for e in &eps[..n] {
            match self.rings.alloc(s as u8, e.dci, 0) {
                Some(ring) => new[e.dci as usize] = ring,
                None => {
                    for &ring in new.iter().filter(|&&r| r != NONE) {
                        self.rings.free(ring);
                    }
                    return abi::ST_NOSPC;
                }
            }
        }
        let dma = self.hc().dma;
        let (ictx, ipa, cs) = self.input_from_out(s);
        ictx.w32(0, r.drop);
        ictx.w32(4, add | 1);
        for e in &eps[..n] {
            let ring = new[e.dci as usize];
            self.rings.reinit(dma, ring);
            self.ep_ctx(ictx, cs, e, dma.pa(dma.ring(ring as usize)), 0);
        }
        let after = (0..32).filter(|&d| {
            (self.slots[s].eps[d].state != EpState::Disabled && r.drop & (1 << d) == 0) || add & (1 << d) != 0
        }).max().unwrap_or(1).max(1) as u32;
        let slot_ctx = Mmio(ictx.0 + cs);
        slot_ctx.w32(0, (slot_ctx.r32(0) & !(0x1f << 27)) | after << 27);
        slot_ctx.w32(12, 0);
        let res = self.command(Trb { param: ipa, status: 0, control: CMD_CONFIGURE_EP << 10 | (s as u32) << 24 });
        if !matches!(res, Some((CC_SUCCESS, _))) {
            for &ring in new.iter().filter(|&&r| r != NONE) {
                self.rings.free(ring);
            }
            return match res {
                Some((cc, _)) => cc_status(cc),
                None => abi::ST_TIMEOUT,
            };
        }
        for d in 2..32 {
            if r.drop & (1 << d) != 0 {
                self.drop_ep(s, d);
            }
        }
        for e in &eps[..n] {
            self.slots[s].eps[e.dci as usize] = Ep {
                state: EpState::Stopped, ep: *e, ring: new[e.dci as usize], streams: 0, stream_rings: [NONE; 16],
            };
        }
        abi::ST_OK
    }

    fn hub_config(&mut self, slot: u16, ports: u32, think: u32, mtt: u32) -> i32 {
        let Some(s) = self.client_slot(slot) else { return abi::ST_INVALID };
        let speed = self.slots[s].speed;
        if speed == 0 || ports > 255 || think > 3 || mtt > 1 {
            return abi::ST_INVALID;
        }
        let hci = self.hc().caps.hci_version;
        let (ictx, ipa, cs) = self.input_from_out(s);
        ictx.w32(4, 1);
        let sc = Mmio(ictx.0 + cs);
        let mut dw0 = sc.r32(0) | 1 << 26;
        if mtt != 0 {
            dw0 |= 1 << 25;
        } else if speed == abi::SPEED_FULL {
            dw0 &= !(1 << 25);
        }
        sc.w32(0, dw0);
        if hci > 0x95 {
            sc.w32(4, (sc.r32(4) & 0x00ff_ffff) | ports << 24);
            if hci < 0x100 || speed == abi::SPEED_HIGH {
                sc.w32(8, (sc.r32(8) & !(3 << 16)) | think << 16);
            }
        }
        sc.w32(12, 0);
        let ty = if hci > 0x95 { CMD_CONFIGURE_EP } else { CMD_EVALUATE_CTX };
        match self.command(Trb { param: ipa, status: 0, control: ty << 10 | (s as u32) << 24 }) {
            Some((CC_SUCCESS, _)) => abi::ST_OK,
            Some((cc, _)) => cc_status(cc),
            None => abi::ST_TIMEOUT,
        }
    }

    fn ep0_mps_set(&mut self, slot: u16, mps: u32) -> i32 {
        let Some(s) = self.client_slot(slot) else { return abi::ST_INVALID };
        let ok = match self.slots[s].speed {
            abi::SPEED_FULL => matches!(mps, 8 | 16 | 32 | 64),
            abi::SPEED_LOW => mps == 8,
            abi::SPEED_HIGH => mps == 64,
            0 => false,
            _ => mps == 512,
        };
        if !ok {
            return abi::ST_INVALID;
        }
        let hc = self.hc();
        let cs = hc.caps.ctx_size;
        let out = Mmio(hc.dma.va(hc.dma.out_ctx(s as u32)) + cs);
        let (ictx, ipa) = hc.input_ctx();
        ictx.w32(4, 0b10);
        let ep = Mmio(ictx.0 + 2 * cs);
        for w in 0..5 {
            ep.w32(4 * w, out.r32(4 * w));
        }
        ep.w32(4, (ep.r32(4) & 0xffff) | mps << 16);
        match self.command(Trb { param: ipa, status: 0, control: CMD_EVALUATE_CTX << 10 | (s as u32) << 24 }) {
            Some((CC_SUCCESS, _)) => {
                self.slots[s].eps[1].ep.max_packet = mps as u16;
                abi::ST_OK
            }
            Some((cc, _)) => cc_status(cc),
            None => abi::ST_TIMEOUT,
        }
    }

    /// Stop endpoint (slot, dci) if it runs.  Whether it is stopped.
    fn stop(&mut self, s: usize, dci: usize) -> bool {
        // A halted one is recovered first, which restarts it: Running,
        // (CSE, halted) Halted, recovered Running again.
        for _ in 0..3 {
            match self.slots[s].eps[dci].state {
                EpState::Running => {
                    let res = self.command(Trb { param: 0, status: 0, control: CMD_STOP_EP << 10 | (dci as u32) << 16 | (s as u32) << 24 });
                    // Context State Error: it had stopped of itself.
                    return match res {
                        Some((CC_SUCCESS, _)) => {
                            if self.slots[s].eps[dci].state == EpState::Running {
                                self.slots[s].eps[dci].state = EpState::Stopped;
                            }
                            true
                        }
                        Some((19, _)) if self.slots[s].eps[dci].state == EpState::Running => {
                            self.slots[s].eps[dci].state = EpState::Stopped;
                            true
                        }
                        // Halted meanwhile: its event came with the result.
                        Some((19, _)) if self.slots[s].eps[dci].state == EpState::Halted => continue,
                        _ => false,
                    };
                }
                EpState::Stopped => return true,
                EpState::Halted => self.recover_all(),
                EpState::Disabled => return false,
            }
        }
        self.slots[s].eps[dci].state == EpState::Stopped
    }

    /// Restart every ring of endpoint (slot, dci) after a stop.
    fn restart(&mut self, s: usize, dci: usize) {
        let ep = self.slots[s].eps[dci];
        if ep.state != EpState::Stopped {
            return;
        }
        if ep.streams == 0 {
            self.post_or_ring(s, dci, ep.ring);
        } else {
            for &r in &ep.stream_rings[1..ep.streams as usize] {
                self.post_or_ring(s, dci, r);
            }
        }
    }

    fn ep_busy(&self, s: usize, dci: usize) -> bool {
        let ep = &self.slots[s].eps[dci];
        let mut rings = ep.stream_rings[..ep.streams as usize].iter().copied().chain(core::iter::once(ep.ring));
        rings.any(|r| r != NONE && self.rings.get(r).head != NONE)
    }

    /// Clear the endpoint's halt and data toggle: re-add it with a fresh
    /// ring, as Linux's xhci_endpoint_reset does.  An endpoint with URBs
    /// on it is left alone.
    fn ep_reset(&mut self, slot: u16, dci: u32) -> i32 {
        let Some(s) = self.client_slot(slot) else { return abi::ST_INVALID };
        if !(1..32).contains(&dci) {
            return abi::ST_INVALID;
        }
        let d = dci as usize;
        let ep = self.slots[s].eps[d];
        if d == 1 || ep.state == EpState::Disabled || ep.streams != 0 || self.ep_busy(s, d) {
            return if ep.state == EpState::Disabled && d != 1 { abi::ST_INVALID } else { abi::ST_OK };
        }
        if !self.stop(s, d) {
            return abi::ST_IO;
        }
        let dma = self.hc().dma;
        self.rings.reinit(dma, ep.ring);
        let (ictx, ipa, cs) = self.input_from_out(s);
        ictx.w32(0, 1 << d);
        ictx.w32(4, 1 << d | 1);
        self.ep_ctx(ictx, cs, &ep.ep, dma.pa(dma.ring(ep.ring as usize)), 0);
        Mmio(ictx.0 + cs).w32(12, 0);
        match self.command(Trb { param: ipa, status: 0, control: CMD_CONFIGURE_EP << 10 | (s as u32) << 24 }) {
            Some((CC_SUCCESS, _)) => {
                self.slots[s].eps[d].state = EpState::Stopped;
                abi::ST_OK
            }
            Some((cc, _)) => cc_status(cc),
            None => abi::ST_TIMEOUT,
        }
    }

    /// Give the bulk endpoints in `mask` `count` streams (IDs 1..count-1),
    /// or with count 0 take them away: a stream context array of rings, or
    /// one ring again (Configure Endpoint, drop and add).
    fn streams(&mut self, slot: u16, mask: u32, count: u32) -> i32 {
        let Some(s) = self.client_slot(slot) else { return abi::ST_INVALID };
        let max = self.hc().caps.max_streams;
        let ss = matches!(self.slots[s].speed, abi::SPEED_SUPER | abi::SPEED_SUPER_PLUS);
        if mask & 0b11 != 0 || mask == 0 || (count != 0 && (!count.is_power_of_two() || count < 2 || count > max)) || !ss {
            return abi::ST_INVALID;
        }
        for d in (2..32).filter(|d| mask & (1 << d) != 0) {
            let ep = self.slots[s].eps[d];
            let bulk = matches!(ep.ep.ty, abi::EP_BULK_IN | abi::EP_BULK_OUT);
            if !bulk || self.ep_busy(s, d) || (count != 0) == (ep.streams != 0) {
                return abi::ST_INVALID;
            }
        }
        // All the rings first, or nothing.
        let need = mask.count_ones() as usize * if count == 0 { 1 } else { count as usize };
        if self.rings.free_count() < need {
            return abi::ST_NOSPC;
        }
        let dma = self.hc().dma;
        let mut new: [(u16, [u16; 16]); 32] = [(NONE, [NONE; 16]); 32];
        for d in (2..32).filter(|d| mask & (1 << d) != 0) {
            let main = self.rings.alloc(s as u8, d as u8, 0).unwrap();
            self.rings.reinit(dma, main);
            if count != 0 {
                // `main` holds the stream context array: entry i points at
                // stream i's ring (a primary ring, SCT 1, DCS 1).
                let arr = Mmio(dma.va(dma.ring(main as usize)));
                for id in 1..count as usize {
                    let r = self.rings.alloc(s as u8, d as u8, id as u16).unwrap();
                    self.rings.reinit(dma, r);
                    new[d].1[id] = r;
                    arr.w64(16 * id, dma.pa(dma.ring(r as usize)) | 1 << 1 | 1);
                }
            }
            new[d].0 = main;
        }
        let (ictx, ipa, cs) = self.input_from_out(s);
        ictx.w32(0, mask);
        ictx.w32(4, mask | 1);
        for d in (2..32).filter(|d| mask & (1 << d) != 0) {
            let ep = self.slots[s].eps[d].ep;
            self.ep_ctx(ictx, cs, &ep, dma.pa(dma.ring(new[d].0 as usize)), count as u16);
        }
        Mmio(ictx.0 + cs).w32(12, 0);
        let res = self.command(Trb { param: ipa, status: 0, control: CMD_CONFIGURE_EP << 10 | (s as u32) << 24 });
        let ok = matches!(res, Some((CC_SUCCESS, _)));
        for d in (2..32).filter(|d| mask & (1 << d) != 0) {
            let (main, srings) = new[d];
            if !ok {
                self.rings.free(main);
                srings.iter().filter(|&&r| r != NONE).for_each(|&r| self.rings.free(r));
                continue;
            }
            let ep = &mut self.slots[s].eps[d];
            let old = (ep.ring, ep.stream_rings, ep.streams);
            *ep = Ep { state: EpState::Stopped, ep: ep.ep, ring: main, streams: count as u16, stream_rings: srings };
            self.rings.free(old.0);
            old.1[..old.2 as usize].iter().filter(|&&r| r != NONE).for_each(|&r| self.rings.free(r));
        }
        match res {
            Some((CC_SUCCESS, _)) => abi::ST_OK,
            Some((cc, _)) => cc_status(cc),
            None => abi::ST_TIMEOUT,
        }
    }

    /// URB_CANCEL: complete the URB with CANCELLED once the controller can
    /// no longer touch its buffers.  An URB not found may still be in the
    /// transfer SQ, submitted before the cancel: take what is there first;
    /// one still there (behind a full CQ) is skipped when its turn comes
    /// and never completes (DROPPED).  One not found at all has completed.
    fn cancel(&mut self, tag: u32) -> i32 {
        if self.urbs.find(tag).is_none() {
            // Leave the entry for this request's own completion.
            self.accept_transfers(XFER_BUDGET, 1);
        }
        let Some(u) = self.urbs.find(tag) else { return self.drop_pending(tag) };
        let urb = self.urbs.get(u);
        let (s, d, r) = (urb.xfer.slot as usize, urb.xfer.dci as usize, urb.ring);
        if !urb.posted {
            self.complete_cancelled(u, s, d, r, 0);
            return abi::ST_OK;
        }
        if !self.stop(s, d) {
            // The controller is broken: its reset completes everything.
            return abi::ST_OK;
        }
        // It may have completed while the endpoint stopped.
        if self.urbs.find(tag) == Some(u) {
            if self.rings.get(r).head == u {
                // The controller is on it, or about to be: move past it.
                let actual = self.urbs.get(u).actual;
                self.complete_cancelled(u, s, d, r, actual);
                self.set_deq(s, d, r);
            } else {
                // Later on the ring, where the stopped controller has not
                // been.  Before another posted URB: it skips it as no-ops,
                // which that URB's completion frees.  After all of them:
                // the ring is wound back over it.
                let dma = self.hc().dma;
                let urb = self.urbs.get(u);
                let n = urb.next;
                if n != NONE && self.urbs.get(n).posted {
                    self.rings.noop(dma, r, urb.first, urb.ntrbs);
                } else {
                    self.rings.rewind(dma, r, urb.start);
                }
                self.complete_cancelled(u, s, d, r, 0);
            }
        }
        // Stop Endpoint stopped every stream of it: restart them all.
        self.restart(s, d);
        abi::ST_OK
    }

    /// Skip the transfer SQ record with `tag` that usbd has not taken yet:
    /// DROPPED, or OK if there is none (it completed).
    fn drop_pending(&mut self, tag: u32) -> i32 {
        let Some(cl) = self.client.as_mut() else { return abi::ST_OK };
        let n = cl.xfer.avail(cl.guest(|c| &c.xfer_sq_head)).unwrap_or(0);
        let base = (cl.area + abi::XFER_SQ_OFF) as *const XferReq;
        for k in 0..n {
            let at = cl.xfer.tail.wrapping_add(k);
            let bit = 1u128 << (at % abi::XFER_SQ_SIZE as u32);
            // Only the tag: the record is copied again, and checked, if it
            // is ever taken.
            let t = unsafe { read_volatile(addr_of!((*base.add(at as usize % abi::XFER_SQ_SIZE)).tag)) };
            if t == tag && cl.skip & bit == 0 {
                cl.skip |= bit;
                return abi::ST_DROPPED;
            }
        }
        abi::ST_OK
    }

    /// Complete cancelled URB `u`, `actual` bytes done.  Isoch: its TDs
    /// not done are cancelled, the one the controller stopped in with its
    /// bytes, and the URB's bytes are its packets'.
    fn complete_cancelled(&mut self, u: u16, s: usize, d: usize, r: u16, actual: u32) {
        let urb = self.urbs.get_mut(u);
        let mut actual = actual;
        if urb.xfer.ty == abi::XFER_ISOC {
            let n = urb.ends.len();
            // A TD failed mid TD keeps its error.
            let from = urb.td as usize + urb.mid as usize;
            for k in from..n {
                let bytes = if k == urb.stopped as usize { actual.min(urb.xfer.iso[k].1) } else { 0 };
                urb.iso[k] = abi::IsoStatus { status: abi::ST_CANCELLED, actual: bytes };
                urb.errors += 1;
            }
            actual = urb.iso[..n].iter().map(|s| s.actual).sum();
        }
        self.complete(u, abi::ST_CANCELLED, actual, s, d, r, false);
    }

    /// A transfer record: accept it, or complete it at once if it is bad.
    fn transfer(&mut self, req: &XferReq) {
        let cl = self.client.as_ref().unwrap();
        let x = match proto::check_xfer(req, &cl.pool, cl.max_transfer) {
            Ok(x) => x,
            Err(st) => return self.refuse(req.tag, st),
        };
        let Some(s) = self.client_slot(x.slot) else { return self.refuse(req.tag, abi::ST_NODEV) };
        let ep = self.slots[s].eps[x.dci as usize];
        let ty_ok = match ep.ep.ty {
            abi::EP_CONTROL => x.ty == abi::XFER_CONTROL,
            abi::EP_BULK_IN | abi::EP_BULK_OUT => x.ty == abi::XFER_BULK,
            abi::EP_INT_IN | abi::EP_INT_OUT => x.ty == abi::XFER_INT,
            abi::EP_ISOC_IN | abi::EP_ISOC_OUT => x.ty == abi::XFER_ISOC,
            _ => false,
        };
        let dir_ok = x.ty == abi::XFER_CONTROL || (ep.ep.ty >= abi::EP_ISOC_IN) == (x.flags & abi::XF_IN != 0);
        if ep.state == EpState::Disabled || !ty_ok || !dir_ok {
            return self.refuse(req.tag, abi::ST_INVALID);
        }
        let ring = if ep.streams == 0 {
            if x.stream != 0 {
                return self.refuse(req.tag, abi::ST_INVALID);
            }
            ep.ring
        } else {
            match ep.stream_rings.get(x.stream as usize) {
                Some(&r) if x.stream != 0 && (x.stream as u16) < ep.streams => r,
                _ => return self.refuse(req.tag, abi::ST_INVALID),
            }
        };
        // It must fit a ring: lay it out once now.
        let shape = proto::EpShape {
            max_packet: (ep.ep.max_packet as u32 & 0x7ff).max(8), burst: 1, mult: 1, hci_1_0: true, full_speed: false, period: 1,
            mfindex: 0, ist: 0, cfc: false,
        };
        let (mut trbs, mut ends) = (proto::Trbs::new(), proto::TdEnds::new());
        if proto::build_trbs(&x, &shape, &mut trbs, &mut ends).is_err() {
            return self.refuse(req.tag, abi::ST_INVALID);
        }
        let iso_tds = if x.ty == abi::XFER_ISOC { x.iso.len() as u32 } else { 0 };
        let cl = self.client.as_mut().unwrap();
        cl.in_flight += 1;
        cl.iso_tds += iso_tds;
        let u = self.urbs.alloc(x, ring).expect("an URB per CQ entry");
        self.rings.append(&mut self.urbs, ring, u);
        self.post(ring);
    }

    fn refuse(&mut self, tag: u32, st: i32) {
        if st == abi::ST_INVALID {
            self.refused += 1;
        }
        if let Some(c) = &mut self.client {
            c.post_cqe(&cqe(tag, abi::CQ_XFER, st));
        }
    }

    /// Take up to `budget` transfer records while the CQ has room beyond
    /// `keep` entries (and CTL_RESERVE) and the isoch TDs allow.
    fn accept_transfers(&mut self, budget: u32, keep: u32) {
        for _ in 0..budget {
            let Some(cl) = self.client.as_mut() else { return };
            if self.dead {
                return;
            }
            let head = cl.guest(|c| &c.xfer_sq_head);
            let Some(n) = cl.xfer.avail(head) else { return };
            if n == 0 {
                return;
            }
            let bit = 1u128 << (cl.xfer.tail % abi::XFER_SQ_SIZE as u32);
            if cl.skip & bit != 0 {
                // Cancelled before it was taken: no completion, no room.
                cl.skip &= !bit;
                cl.xfer.tail = cl.xfer.tail.wrapping_add(1);
                cl.publish(|i| &mut i.xfer_sq_tail, cl.xfer.tail);
                continue;
            }
            if cl.room() <= CTL_RESERVE + keep || cl.iso_tds + abi::MAX_ISO as u32 > MAX_ISO_TDS {
                cl.blocked = true;
                return;
            }
            let base = (cl.area + abi::XFER_SQ_OFF) as *const XferReq;
            let req = unsafe { proto::read_record(base, abi::XFER_SQ_SIZE as u32, cl.xfer.tail) };
            cl.xfer.tail = cl.xfer.tail.wrapping_add(1);
            cl.publish(|i| &mut i.xfer_sq_tail, cl.xfer.tail);
            self.transfer(&req);
        }
    }

    /// Serve the client's queues: a reset request, control requests, then
    /// transfers, as far as the CQ has room and this turn's budget goes.
    fn serve(&mut self) {
        let Some(cl) = &self.client else { return };
        let seq = cl.guest(|c| &c.reset_seq);
        if seq != cl.reset_seen {
            self.reset(false);
            if let Some(cl) = &mut self.client {
                cl.reset_seen = seq;
                unsafe { write_volatile(addr_of_mut!((*cl.info()).reset_done), seq) };
                cl.notify = true;
            }
        }
        if self.dead {
            return;
        }
        self.recover_all();
        self.refill();
        // Control requests complete at once, in order.
        for _ in 0..CTL_BUDGET {
            let cl = self.client.as_mut().unwrap();
            let head = cl.guest(|c| &c.ctl_sq_head);
            let Some(n) = cl.ctl.avail(head) else { break };
            if n == 0 || cl.room() == 0 {
                break;
            }
            let base = (cl.area + abi::CTL_SQ_OFF) as *const CtlReq;
            let req = unsafe { proto::read_record(base, abi::CTL_SQ_SIZE as u32, cl.ctl.tail) };
            cl.ctl.tail = cl.ctl.tail.wrapping_add(1);
            cl.publish(|i| &mut i.ctl_sq_tail, cl.ctl.tail);
            let c = self.control(&req);
            self.client.as_mut().unwrap().post_cqe(&c);
            if self.dead || self.client.is_none() {
                return;
            }
            self.refill();
        }
        self.accept_transfers(XFER_BUDGET, 0);
        self.recover_all();
        self.refill();
    }

    /// Whether the client has something for us: a request, a reset, or CQ
    /// room the transfer SQ waits for.
    fn has_work(&self) -> bool {
        let Some(cl) = &self.client else { return false };
        if self.dead {
            return false;
        }
        cl.guest(|c| &c.reset_seq) != cl.reset_seen
            || cl.ctl.avail(cl.guest(|c| &c.ctl_sq_head)).is_some_and(|n| n > 0 && cl.room() > 0)
            || cl.xfer.avail(cl.guest(|c| &c.xfer_sq_head)).is_some_and(|n| n > 0 && (cl.room() > CTL_RESERVE
                && cl.iso_tds + abi::MAX_ISO as u32 <= MAX_ISO_TDS || cl.skip & 1u128 << (cl.xfer.tail % abi::XFER_SQ_SIZE as u32) != 0))
    }

    // ---- Controller lifetime.

    /// Forget every slot and complete every URB with SHUTDOWN: the
    /// controller was reset.
    fn forget_all(&mut self, post: bool) {
        for s in 1..=proto::MAX_SLOTS as usize {
            if !self.slots[s].enabled {
                continue;
            }
            for d in 1..32 {
                if post {
                    self.drop_ep(s, d);
                } else {
                    let ep = self.slots[s].eps[d];
                    for r in ep.stream_rings[..ep.streams as usize].iter().copied().chain(core::iter::once(ep.ring)) {
                        if r != NONE {
                            while self.rings.get(r).head != NONE {
                                let u = self.rings.get(r).head;
                                self.rings.unlink(&mut self.urbs, r, u);
                                self.urbs.free(u);
                            }
                            self.rings.free(r);
                        }
                    }
                }
            }
            self.slots[s] = Slot::EMPTY;
        }
        self.recover.clear();
        if let Some(c) = &mut self.client {
            if !post {
                c.in_flight = 0;
                c.iso_tds = 0;
            }
        }
    }

    /// Reset the controller (the guest asked, or it failed) and start it
    /// again; every URB completes with SHUTDOWN first.
    fn reset(&mut self, error: bool) {
        if let Some(c) = &self.client {
            c.set_state(abi::RESETTING);
        }
        let ok = self.hc().halt_reset();
        // The controller fetches nothing now: the URBs can go.
        self.forget_all(true);
        let ok = ok && self.hc().start();
        self.resets += 1;
        let Some(c) = &mut self.client else { return };
        unsafe { write_volatile(addr_of_mut!((*c.info()).hc_resets), self.resets as u32) };
        if !ok {
            l4h_rt::log!("l4h-usbd: the controller did not restart: dead until the guest is gone");
            self.dead = true;
            c.set_state(abi::DEAD);
            c.notify = true;
            return;
        }
        if error {
            c.post_event(Event { ty: abi::EV_HC_RESET, port: 0, portsc: 0, reserved: [0; 5] });
        }
        c.set_state(abi::READY);
    }

    /// A command timed out or the controller reported an error.
    fn hc_failed(&mut self) {
        if self.dead || self.client.is_none() {
            return;
        }
        if self.errors.allow() {
            l4h_rt::log!("l4h-usbd: controller failure; resetting it");
        }
        self.reset(true);
    }

    /// Write the client's info page and start the controller.
    fn attach(&mut self, idx: usize, pool: Pool) -> u64 {
        if self.client.is_some() || idx >= proto::AREAS {
            return EBUSY;
        }
        let Some(hc) = self.hc.as_ref() else { return EIO };
        // A 32-bit controller cannot reach a pool above 4 GiB.
        if !hc.caps.ac64 && pool.paddr.checked_add(pool.size).is_none_or(|e| e > 1 << 32) {
            return EINVAL;
        }
        let area = proto::queue_va(idx);
        let irq = cap::<cap_type::Notification>(proto::USBD_SLOT_CLIENT_IRQ + idx as u64);
        let c = &hc.caps;
        let info = area as *mut Info;
        unsafe {
            core::ptr::write_bytes(area as *mut u8, 0, 4096);
            let i = &mut *info;
            i.version = abi::VERSION;
            i.features = abi::F_ISOCH | if c.max_streams != 0 { abi::F_STREAMS } else { 0 } | if c.ctx_size == 64 { abi::F_CSZ } else { 0 };
            i.max_slots = c.max_slots;
            i.max_ports = c.max_ports;
            i.usb2_ports = c.usb2;
            i.usb3_ports = c.usb3;
            i.max_streams = c.max_streams;
            i.hci_version = c.hci_version;
            i.port_proto.copy_from_slice(&c.port_proto);
            i.state = abi::RESETTING;
        }
        let max_transfer = ((pool.size / 4) as u32).min(proto::MAX_TRANSFER);
        unsafe { (*info).max_transfer = max_transfer };
        self.client = Some(Client {
            idx, area, pool, max_transfer,
            ctl: Sq { tail: 0, size: abi::CTL_SQ_SIZE as u32 },
            xfer: Sq { tail: 0, size: abi::XFER_SQ_SIZE as u32 },
            cq_head: 0, eq_head: 0, in_flight: 0, iso_tds: 0, reset_seen: 0, irq, notify: false, lost: 0, blocked: false, skip: 0,
        });
        self.dead = false;
        if !self.hc().start() {
            self.dead = true;
            self.client.as_ref().unwrap().set_state(abi::DEAD);
            return EIO;
        }
        fence(Ordering::Release);
        unsafe { write_volatile(addr_of_mut!((*info).magic), abi::MAGIC) };
        self.client.as_ref().unwrap().set_state(abi::READY);
        0
    }

    /// The client is going: stop the controller touching its pool.
    /// Root has already cut the controller off (bus mastering) and taken
    /// the notification away; it frees the area once this is done.
    fn remove(&mut self, idx: usize) -> u64 {
        if self.client.as_ref().is_some_and(|c| c.idx != idx) {
            return EINVAL;
        }
        let ok = self.hc.as_mut().is_some_and(|h| h.halt_reset());
        self.forget_all(false);
        self.client = None;
        if ok { 0 } else { EIO }
    }

    /// `claim`: take the controller from the firmware.
    fn claim(&mut self, cfg: &UsbdConfig, tsc_hz: u64) -> Result<proto::Claimed, u64> {
        if self.hc.is_some() {
            return Err(EBUSY);
        }
        let dma = Region { va: cfg.dma_va as usize, pa: cfg.dma_paddr, size: cfg.dma_size as usize };
        let Some(mut hc) = Xhci::new(cfg.bar0_va as usize, cfg.bar0_len as usize, dma, tsc_hz) else { return Err(EIO) };
        if !hc.caps.ac64 && dma.pa + dma.size as u64 > 1 << 32 {
            return Err(EIO);
        }
        if !hc.handoff(cfg.force_handoff_timeout != 0) {
            l4h_rt::log!("l4h-usbd {:#x}: legacy handoff timed out", cfg.pci_bdf);
        }
        if !hc.halt_reset() {
            return Err(EIO);
        }
        let c = &hc.caps;
        let claimed = proto::Claimed { usb2: c.usb2 as u16, usb3: c.usb3 as u16, ac64: c.ac64 };
        l4h_rt::info!("l4h-usbd {:#x}: xHCI {:x}.{:02x}, {} slots, {} USB 2 and {} USB 3 ports, {}-byte contexts",
            cfg.pci_bdf, c.hci_version >> 8, c.hci_version & 0xff, c.max_slots, c.usb2, c.usb3, c.ctx_size);
        self.hc = Some(hc);
        Ok(claimed)
    }

    /// Answer root's requests (host::mailbox).
    fn mailbox(&mut self, cfg: &UsbdConfig, tsc_hz: u64) {
        let published = l4h_rt::mailbox::published::<proto::Published>();
        published.refused.store(self.refused, Ordering::Relaxed);
        published.resets.store(self.resets, Ordering::Relaxed);
        let mut req = Requests { u: self, cfg, tsc_hz };
        let answered = l4h_rt::mailbox::serve(|label, args, out| proto::call::serve(&mut req, label, args, RootOnly::Root, out));
        if answered {
            published.resets.store(self.resets, Ordering::Relaxed);
            l4h_rt::mailbox::signal();
        }
    }

    /// Before waiting: tell the guest to kick, then look once more.
    /// Whether there is work after all (another turn, not a wait).
    fn prepare_wait(&mut self) -> bool {
        let Some(c) = &self.client else { return false };
        c.publish(|i| &mut i.usbd_waiting, 1);
        fence(Ordering::SeqCst);
        if !self.has_work() {
            return false;
        }
        c.publish(|i| &mut i.usbd_waiting, 0);
        true
    }

    /// One turn: events, root's requests, the client's queues.
    fn turn(&mut self, cfg: &UsbdConfig, tsc_hz: u64) {
        if self.hc.is_some() {
            self.events();
            if self.hc.as_ref().is_some_and(|h| h.sts() & (STS_HSE | STS_HCE) != 0 || h.sts() == u32::MAX) {
                self.hc_failed();
            }
        }
        self.mailbox(cfg, tsc_hz);
        if self.hc.is_some() {
            self.serve();
            self.flush();
        }
    }

    fn woken(&self) {
        if let Some(c) = &self.client {
            c.publish(|i| &mut i.usbd_waiting, 0);
        }
    }

    /// Signal the client's VMM once for whatever was published.
    fn flush(&mut self) {
        if let Some(c) = &mut self.client {
            // The guest extrapolates the frame number from this sample.
            let (mf, ticks) = match &self.hc {
                Some(hc) if !self.dead && !hc.broken => (hc.mfindex(), l4h_rt::host::ticks::now().max(1)),
                Some(hc) => (hc.mfindex(), 0),
                None => (0, 0),
            };
            let info = c.info();
            unsafe {
                let seq = (read_volatile(addr_of!((*info).mfindex)) >> 14).wrapping_add(1) | 1;
                write_volatile(addr_of_mut!((*info).mfindex), seq << 14);
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                write_volatile(addr_of_mut!((*info).mf_ticks), ticks);
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                write_volatile(addr_of_mut!((*info).mfindex), seq.wrapping_add(1) << 14 | mf);
            }
            if c.notify {
                c.notify = false;
                // NBSend: root may have emptied the slot (REMOVE).
                c.irq.nb_send(sel4::MessageInfo::new(0, 0, 0, 0));
            }
        }
    }
}

fn main(info: &'static l4h_rt::Info) -> ! {
    let cfg: &UsbdConfig = unsafe { info.config() };
    let tsc_hz = info.header().tsc_hz;
    let mut u = Usbd {
        hc: None,
        client: None,
        // The only reference to SLOTS.
        slots: unsafe { &mut *addr_of_mut!(SLOTS) },
        rings: Rings::new(),
        urbs: Urbs::new(),
        recover: l4h_rt::host::fixed::ArrayVec::new(),
        refill: [0; proto::USB_RINGS / 64],
        refused: 0,
        resets: 0,
        dead: false,
        errors: l4h_rt::ErrorLimit::new(),
    };
    let ep = cap::<cap_type::Endpoint>(host::SLOT_SERVICE_EP);
    let reply = cap::<cap_type::Reply>(host::SLOT_REPLY);
    let irq = cap::<cap_type::IrqHandler>(proto::USBD_SLOT_IRQ);
    // Only notifications arrive: root's requests (BADGE_CALL), the
    // interrupt and the client's kicks.
    let mut badge = ep.recv(reply).1;
    loop {
        u.turn(cfg, tsc_hz);
        if badge & proto::USBD_BADGE_IRQ != 0 {
            irq.irq_handler_ack().expect("usbd IRQ ack");
        }
        // More work: another bounded turn.  The guest kicks only once
        // usbd_waiting is set, so its kicks never pile up.
        if u.prepare_wait() {
            badge = proto::USBD_BADGE_KICK;
            continue;
        }
        badge = ep.recv(reply).1;
        u.woken();
    }
}

l4h_rt::component!(main, no_heap);
