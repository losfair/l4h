//! Channels between multikernel partitions (DESIGN.md §11.4): memory the
//! shim reserved from every partition's RAM, two message rings in each,
//! and a doorbell each way (seL4_IRQControl_SendPeer, kernel patch 0036).
//!
//! A ring has one writer and one reader, and the writer never waits: a
//! header word counts the bytes ever written, the reader keeps its own
//! count, and a reader that falls behind by a whole ring skips what it
//! lost.  A crashed partition leaves a stale ring, never a blocked writer.
//!
//! Control traffic between the primary and each secondary:
//!
//! - heartbeats, secondary to primary, every second; the primary logs a
//!   partition that stops sending them;
//! - the wall clock, primary to secondary, every ten seconds and after
//!   dom0 sets the RTC, which only the primary owns; and a secondary
//!   dom0's RTC_SET, forwarded to the primary.
//!
//! The other kinds (trustd's requests, link frames) are handed to their
//! owners through `Channels::take`.

use l4h_partition::{self as part, Channel, MSG_PAD, MSG_RING_HEADER};
use sel4::cap_type;
use sel4::init_thread::slot;

use crate::Host;
use crate::devmem::DevMem;
use crate::mem::Alloc;

/// Badge of a doorbell on the root task's bound notification.
pub const CHANNEL_BADGE: u64 = 1 << 42;

/// The largest message (a link frame with its header).
pub const MSG_MAX: usize = 9216 + 64;

const HEARTBEAT_SECS: u64 = 1;
const CLOCK_SECS: u64 = 10;
/// Heartbeats missed before the primary reports a partition.
const MISSED: u64 = 5;

/// One direction of a channel: a ring this partition writes or reads.
struct Ring {
    va: usize,
    cap: u64,
}

impl Ring {
    fn head(&self) -> u64 {
        unsafe { (self.va as *const u64).read_volatile() }
    }

    fn data(&self, off: u64) -> *mut u8 {
        (self.va + MSG_RING_HEADER + off as usize) as *mut u8
    }

    /// Write one message: never waits, never fails (a slow reader loses
    /// old messages instead).
    fn send(&self, ty: u32, payload: &[&[u8]]) {
        let n: usize = payload.iter().map(|p| p.len()).sum();
        let len = (8 + n as u64).next_multiple_of(8);
        assert!(len <= self.cap / 2, "channel message too large");
        let mut head = self.head();
        let pos = head % self.cap;
        if pos + len > self.cap {
            // The rest of the ring is padding.
            unsafe {
                (self.data(pos) as *mut u32).write_volatile((self.cap - pos) as u32);
                (self.data(pos + 4) as *mut u32).write_volatile(MSG_PAD);
            }
            head += self.cap - pos;
        }
        let pos = head % self.cap;
        unsafe {
            (self.data(pos) as *mut u32).write_volatile(len as u32);
            (self.data(pos + 4) as *mut u32).write_volatile(ty);
            let mut at = self.data(pos + 8);
            for p in payload {
                core::ptr::copy_nonoverlapping(p.as_ptr(), at, p.len());
                at = at.add(p.len());
            }
        }
        // The message before the count that covers it (x86 orders stores).
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
        unsafe { (self.va as *mut u64).write_volatile(head + len) };
    }
}

/// The reader's side of a ring.
struct Reader {
    ring: Ring,
    tail: u64,
}

impl Reader {
    /// The next message, copied into `buf`: (type, length), or None.
    fn recv(&mut self, buf: &mut [u8; MSG_MAX], lost: &mut u64) -> Option<(u32, usize)> {
        loop {
            let head = self.ring.head();
            if self.tail == head {
                return None;
            }
            if head.wrapping_sub(self.tail) > self.ring.cap {
                *lost += head - self.tail;
                self.tail = head;
                return None;
            }
            let pos = self.tail % self.ring.cap;
            let (len, ty) = unsafe {
                ((self.ring.data(pos) as *const u32).read_volatile() as u64, (self.ring.data(pos + 4) as *const u32).read_volatile())
            };
            if len < 8 || len % 8 != 0 || pos + len > self.ring.cap {
                *lost += head - self.tail;
                self.tail = head;
                return None;
            }
            let n = (len as usize - 8).min(MSG_MAX);
            if ty != MSG_PAD {
                unsafe { core::ptr::copy_nonoverlapping(self.ring.data(pos + 8), buf.as_mut_ptr(), n) };
            }
            // Overwritten while it was copied: lost.
            if self.ring.head().wrapping_sub(self.tail) > self.ring.cap {
                continue;
            }
            self.tail += len;
            if ty != MSG_PAD {
                return Some((ty, n));
            }
        }
    }
}

struct Chan {
    desc: Channel,
    tx: Ring,
    rx: Reader,
    irq: Option<sel4::cap::IrqHandler>,
    /// Ticks of the last message from the peer.
    last_heard: u64,
    /// The peer was reported stopped.
    reported: bool,
    lost: u64,
}

pub struct Channels {
    chans: l4h_host::fixed::ArrayVec<Chan, { part::MAX_CHANNELS }>,
    next_heartbeat: u64,
    next_clock: u64,
    tsc_hz: u64,
    buf: [u8; MSG_MAX],
}

impl Channels {
    /// Map this partition's channels and take their doorbells.
    pub fn new(alloc: &mut Alloc, devmem: &mut DevMem, ntfn: sel4::cap::Notification, tsc_hz: u64) -> Option<Channels> {
        let d = crate::partition::get()?;
        let mut c = Channels {
            chans: l4h_host::fixed::ArrayVec::new(),
            next_heartbeat: 0,
            next_clock: 0,
            tsc_hz,
            buf: [0; MSG_MAX],
        };
        let badged = alloc.slots.alloc();
        crate::component::abs_of(sel4::init_thread::Slot::<cap_type::Null>::from_index(badged).cap())
            .mint(&crate::component::abs_of(ntfn), sel4::CapRights::write_only(), CHANNEL_BADGE)
            .expect("doorbell badge");
        let badged = sel4::init_thread::Slot::<cap_type::Notification>::from_index(badged).cap();
        for (i, ch) in d.channels().iter().enumerate() {
            let va = crate::layout::PARTITION_CHANNELS.base + i * part::CHANNEL_SIZE as usize;
            if crate::partition::map(alloc, devmem, ch.paddr as usize, ch.size as usize, va).is_none() {
                log!("l4h-root: cannot map the channel to partition {}", ch.peer);
                continue;
            }
            let half = ch.size as usize / 2;
            let cap = (half - MSG_RING_HEADER) as u64;
            let (tx, rx) = if d.index < ch.peer { (va, va + half) } else { (va + half, va) };
            let rx = Ring { va: rx, cap };
            // Start at what the peer already wrote: a ring is never reset.
            let tail = rx.head();
            let irq_slot = alloc.slots.alloc();
            let dst = crate::component::abs_of(sel4::init_thread::Slot::<cap_type::Null>::from_index(irq_slot).cap());
            let irq = slot::IRQ_CONTROL.cap().irq_control_get_msi(0, 0, 0, 0, ch.vector as u64, &dst).ok().map(|_| {
                let irq = sel4::init_thread::Slot::<cap_type::IrqHandler>::from_index(irq_slot).cap();
                irq.irq_handler_set_notification(badged).expect("doorbell notification");
                irq
            });
            if irq.is_none() {
                log!("l4h-root: no doorbell from partition {}: polling", ch.peer);
            }
            let _ = c.chans.push(Chan {
                desc: *ch,
                tx: Ring { va: tx, cap },
                rx: Reader { ring: rx, tail },
                irq,
                last_heard: l4h_host::ticks::now(),
                reported: false,
                lost: 0,
            });
        }
        info!("l4h-root: {} channel(s) to other partitions", c.chans.len());
        Some(c)
    }

    /// Send a message to partition `peer` and ring its doorbell.
    pub fn send(&self, peer: u32, ty: u32, payload: &[&[u8]]) -> bool {
        self.push(peer, ty, payload) && self.notify(peer)
    }

    /// Send a message to partition `peer` without ringing its doorbell
    /// (`notify` rings it once for several).
    pub fn push(&self, peer: u32, ty: u32, payload: &[&[u8]]) -> bool {
        let Some(c) = self.chans.iter().find(|c| c.desc.peer == peer) else { return false };
        c.tx.send(ty, payload);
        true
    }

    pub fn notify(&self, peer: u32) -> bool {
        let Some(c) = self.chans.iter().find(|c| c.desc.peer == peer) else { return false };
        ring(c.desc.peer_slot, c.desc.peer_vector);
        true
    }

    /// The peers with a link channel (CHANNEL_LINK).
    pub fn links(&self) -> impl Iterator<Item = u32> + '_ {
        self.chans.iter().filter(|c| c.desc.kind & part::CHANNEL_LINK != 0).map(|c| c.desc.peer)
    }

    /// The partitions heard from within the last few heartbeats, a bit
    /// each.
    pub fn alive(&self) -> u64 {
        self.chans.iter().filter(|c| !c.reported).fold(0, |m, c| m | 1 << c.desc.peer)
    }

    pub fn has_peer(&self, peer: u32) -> bool {
        self.chans.iter().any(|c| c.desc.peer == peer)
    }
}

/// Ring a peer's doorbell.
fn ring(peer_slot: u32, vector: u32) {
    let ctl = slot::IRQ_CONTROL.cap();
    let err = sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_IRQControl_SendPeer(ctl.bits(), peer_slot as u64, vector as u64));
    if err != 0 {
        log!("l4h-root: doorbell to peer {} failed: {}", peer_slot, err);
    }
}

/// Handle what arrived on every channel (a doorbell rang, or the timer).
pub fn poll(h: &mut Host) {
    let Some(mut cs) = h.channels.take() else { return };
    let now = l4h_host::ticks::now();
    for i in 0..cs.chans.len() {
        let mut lost = 0;
        while let Some((ty, n)) = cs.chans[i].rx.recv(&mut cs.buf, &mut lost) {
            cs.chans[i].last_heard = now;
            if cs.chans[i].reported {
                cs.chans[i].reported = false;
                log!("l4h-root: partition {} is heard from again", cs.chans[i].desc.peer);
            }
            let peer = cs.chans[i].desc.peer;
            handle(h, &cs, peer, ty, &cs.buf[..n]);
        }
        if lost > 0 {
            cs.chans[i].lost += lost;
            log!("l4h-root: {} bytes from partition {} lost", lost, cs.chans[i].desc.peer);
        }
        if let Some(irq) = cs.chans[i].irq {
            let _ = irq.irq_handler_ack();
        }
    }
    h.channels = Some(cs);
    crate::netd::link_kick(h);
}

fn u64_at(b: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?))
}

fn handle(h: &mut Host, cs: &Channels, peer: u32, ty: u32, msg: &[u8]) {
    match ty {
        part::MSG_HEARTBEAT => {}
        part::MSG_CLOCK if crate::partition::secondary() => {
            let (Some(ns), Some(tsc)) = (u64_at(msg, 0), u64_at(msg, 8)) else { return };
            h.info.epoch_ns = ns;
            h.info.epoch_ticks = tsc;
        }
        part::MSG_RTC_SET if !crate::partition::secondary() => {
            let Some(secs) = u64_at(msg, 0) else { return };
            match h.rtc.set_secs(&mut h.wins.a, secs) {
                Ok(()) => {
                    log!("l4h-root: RTC set for partition {}", peer);
                    send_clock(h, cs);
                }
                Err(e) => log!("l4h-root: RTC set for partition {} failed: {}", peer, e),
            }
        }
        part::MSG_TPM_REQUEST | part::MSG_TPM_REPLY => crate::trustd::channel_message(h, peer, ty, msg),
        part::MSG_FRAME => crate::netd::link_frame(h, peer, msg),
        _ => {}
    }
}

/// The wall clock now, as the primary knows it, to every secondary.
fn send_clock(h: &mut Host, cs: &Channels) {
    let now = l4h_host::ticks::now();
    let ns = h.rtc.read_ns(&mut h.wins.a);
    if ns == 0 {
        return;
    }
    for c in cs.chans.iter().filter(|c| c.desc.kind & part::CHANNEL_CONTROL != 0) {
        c.tx.send(part::MSG_CLOCK, &[&ns.to_le_bytes(), &now.to_le_bytes()]);
        ring(c.desc.peer_slot, c.desc.peer_vector);
    }
}

/// The root task's timer: heartbeats, the clock, and channels whose
/// doorbell may not have rung.
pub fn tick(h: &mut Host) {
    poll(h);
    let Some(mut cs) = h.channels.take() else { return };
    let now = l4h_host::ticks::now();
    let primary = !crate::partition::secondary();
    if now >= cs.next_heartbeat {
        cs.next_heartbeat = now + HEARTBEAT_SECS * cs.tsc_hz;
        if !primary {
            for c in cs.chans.iter().filter(|c| c.desc.kind & part::CHANNEL_CONTROL != 0) {
                c.tx.send(part::MSG_HEARTBEAT, &[&now.to_le_bytes()]);
            }
        }
    }
    if primary {
        if now >= cs.next_clock {
            cs.next_clock = now + CLOCK_SECS * cs.tsc_hz;
            send_clock(h, &cs);
        }
        for c in cs.chans.iter_mut().filter(|c| c.desc.kind & part::CHANNEL_CONTROL != 0) {
            if !c.reported && now.saturating_sub(c.last_heard) > MISSED * HEARTBEAT_SECS * cs.tsc_hz {
                c.reported = true;
                log!("l4h-root: partition {} stopped: no heartbeat for {} s; it stays down until the machine reboots",
                    c.desc.peer, MISSED * HEARTBEAT_SECS);
            }
        }
    }
    h.channels = Some(cs);
}

/// dom0's RTC_SET on a secondary: the RTC is the primary's.
pub fn rtc_set(h: &mut Host, secs: u64) -> Result<(), i64> {
    let cs = h.channels.as_ref().ok_or(crate::ctl::ENOSYS)?;
    if cs.send(0, part::MSG_RTC_SET, &[&secs.to_le_bytes()]) { Ok(()) } else { Err(crate::ctl::EIO) }
}
