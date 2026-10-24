//! netd: L2 virtual switches (DESIGN.md §8.3) and the uplink NIC drivers.
//!
//! Every port belongs to one switch.  A port is either a guest vNIC (a
//! channel to that guest's l4h-vmm) or an uplink NIC (virtio-net, gVNIC,
//! ENA or X550 PCI, driven here).  Switches learn source MACs, forward known unicast to one
//! port and flood everything else within the switch.  Guest ports can be
//! locked to their configured MAC.  Nothing above L2 is looked at.
//!
//! netd has no heap (DESIGN.md §9): its tables are fixed arrays, its frame
//! buffers statics, and the frames it holds take chunks of a fixed pool
//! (pool.rs).

#![no_std]
#![no_main]

mod ena;
mod gvnic;
mod ixgbe;
mod nic;
mod offload;
mod pool;
mod virtio_net;

use core::mem::MaybeUninit;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::net::{self, NetdConfig};
use l4h_rt::sel4;
use l4h_rt::{Info, cap, host};
use sel4::cap_type;

use crate::nic::Nic;
use crate::offload::{complete_csum, is_gso};
use crate::pool::{Fifo, Frame, Pool};

/// Seconds after which a learned MAC is forgotten.
const FDB_AGE_SECS: u64 = 300;
/// Learned MACs per switch and in all.  When a table is full, expired
/// entries go; if none has, new sources are not learned (their frames are
/// still switched, by flooding).
const FDB_MAX: usize = 1024;
const FDB_MAX_TOTAL: usize = 8192;
/// Slots of the forwarding table: twice the entries, so probes stay short.
const FDB_SLOTS: usize = 2 * FDB_MAX_TOTAL;
const _: () = assert!(FDB_SLOTS.is_power_of_two() && net::MAX_SWITCHES <= u8::MAX as usize);
/// Frames held for a guest whose RX ring is full, and the pool chunks
/// they may take (all backlogs together take at most pool::BYTES).
/// Dropping them instead costs TCP a retransmission timeout whenever a
/// burst outruns the ring (24 slots); a guest that stops reading costs
/// only its own backlog.
const BACKLOG_FRAMES: usize = 512;
const BACKLOG_CHUNKS: usize = (2 << 20) / pool::CHUNK;

/// The frame being switched, and the segments of a GSO frame for a port
/// that cannot take it whole: too large for the stack.
static mut BUF: [u8; net::MAX_FRAME] = [0; net::MAX_FRAME];
static mut SEG_BUF: [u8; net::MAX_FRAME] = [0; net::MAX_FRAME];
/// Receive offload per NIC, made by main: a new Gro is not all zeros, and
/// would take its size in the image.
static mut GRO: [MaybeUninit<offload::Gro>; net::MAX_NICS] = [const { MaybeUninit::uninit() }; net::MAX_NICS];
static mut FDB_SLOTS_MEM: [FdbEntry; FDB_SLOTS] = [FdbEntry::FREE; FDB_SLOTS];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PortId {
    Guest(usize),
    Uplink(usize),
}

struct GuestPort {
    chan: *mut net::Port,
    switch: u32,
    mac: [u8; 6],
    lock: bool,
    /// An isolated port exchanges frames only with ports that are not
    /// isolated (other guests' normal ports and the uplink).
    isolated: bool,
    client: sel4::cap::Notification,
    /// The client must be told about new RX frames or freed TX slots.
    signal: bool,
    rx_frames: u64,
    tx_frames: u64,
    drops: u64,
    /// Frames for a full RX ring, oldest first.
    backlog: Fifo,
}

/// A learned MAC: the port of its switch it was last seen on, and when.
#[derive(Clone, Copy)]
struct FdbEntry {
    used: bool,
    switch: u8,
    port: u8,
    mac: [u8; 6],
    seen: u64,
}

impl FdbEntry {
    const FREE: FdbEntry = FdbEntry { used: false, switch: 0, port: 0, mac: [0; 6], seen: 0 };
}

/// The forwarding tables of all switches: one open-addressed table
/// (linear probing) keyed by switch number and MAC, and the number of
/// entries of each switch.
struct Fdb {
    slots: &'static mut [FdbEntry; FDB_SLOTS],
    /// Entries per switch and in all.
    len: [usize; net::MAX_SWITCHES],
    total: usize,
    /// Mixed into the hash, so that a guest cannot choose MACs that collide.
    seed: u64,
    /// No entry expires before this (the last sweep's oldest entry + age).
    sweep_at: u64,
}

impl Fdb {
    fn home(&self, switch: u8, mac: &[u8; 6]) -> usize {
        let k = u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], switch, 0]);
        ((k ^ self.seed).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - FDB_SLOTS.trailing_zeros())) as usize
    }

    fn find(&self, switch: u8, mac: &[u8; 6]) -> Option<usize> {
        let mut i = self.home(switch, mac);
        while self.slots[i].used {
            if self.slots[i].switch == switch && self.slots[i].mac == *mac {
                return Some(i);
            }
            i = (i + 1) % FDB_SLOTS;
        }
        None
    }

    fn has_room(&self, switch: u8) -> bool {
        self.len[switch as usize] < FDB_MAX && self.total < FDB_MAX_TOTAL
    }

    /// Learn `mac`, which is not in the table; the table has room.
    fn insert(&mut self, switch: u8, mac: [u8; 6], port: PortId, now: u64) {
        let mut i = self.home(switch, &mac);
        while self.slots[i].used {
            i = (i + 1) % FDB_SLOTS;
        }
        self.slots[i] = FdbEntry { used: true, switch, port: port.code(), mac, seen: now };
        self.len[switch as usize] += 1;
        self.total += 1;
    }

    /// Forget slot `i`'s entry.  Later entries of its probe run move back
    /// into the hole, so that no lookup stops short of them.
    fn remove(&mut self, mut i: usize) {
        self.len[self.slots[i].switch as usize] -= 1;
        self.total -= 1;
        loop {
            self.slots[i].used = false;
            let mut j = i;
            loop {
                j = (j + 1) % FDB_SLOTS;
                let e = self.slots[j];
                if !e.used {
                    return;
                }
                // Entry j can fill the hole if the hole lies between its
                // home slot and j.
                let home = self.home(e.switch, &e.mac);
                if j.wrapping_sub(home) % FDB_SLOTS >= j.wrapping_sub(i) % FDB_SLOTS {
                    break;
                }
            }
            self.slots[i] = self.slots[j];
            i = j;
        }
    }

    /// Forget the entries `f` picks.  An entry that moves back into the
    /// slot just emptied is looked at in turn.
    fn remove_if(&mut self, f: impl Fn(&FdbEntry) -> bool) {
        let mut i = 0;
        while i < FDB_SLOTS {
            if self.slots[i].used && f(&self.slots[i]) {
                self.remove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Forget the entries older than `age`, for a full table.  Until the
    /// oldest entry left can expire there is nothing to sweep, so a guest
    /// sending from ever new MACs cannot make every frame sweep.
    fn expire(&mut self, now: u64, age: u64) {
        if now < self.sweep_at {
            return;
        }
        self.remove_if(|e| now.wrapping_sub(e.seen) >= age);
        let oldest = self.slots.iter().filter(|e| e.used).map(|e| e.seen).min();
        self.sweep_at = oldest.map_or(0, |t| t.saturating_add(age));
    }
}

struct Netd {
    ports: [Option<GuestPort>; net::MAX_PORTS],
    nics: ArrayVec<Nic, { net::MAX_NICS }>,
    /// Receive offload per NIC (taken out while it emits).
    gro: [Option<&'static mut offload::Gro>; net::MAX_NICS],
    fdb: Fdb,
    /// The chunks of the frames all backlogs hold.
    pool: &'static mut Pool,
    tsc_hz: u64,
    /// Frame being switched.
    buf: &'static mut [u8],
    /// Segments of a GSO frame for a port that cannot take it whole.
    seg_buf: &'static mut [u8],
}

fn rdtsc() -> u64 {
    host::ticks::now()
}

fn mac_of(v: u64) -> [u8; 6] {
    let b = v.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}

const _: () = assert!(net::MAX_PORTS <= 0x80 && net::MAX_NICS <= 0x80);

impl PortId {
    /// The port as a forwarding table entry keeps it.
    fn code(self) -> u8 {
        match self {
            PortId::Guest(i) => i as u8,
            PortId::Uplink(n) => 0x80 | n as u8,
        }
    }

    fn of_code(c: u8) -> PortId {
        if c & 0x80 == 0 { PortId::Guest(c as usize) } else { PortId::Uplink((c & 0x7f) as usize) }
    }
}

impl Netd {
    fn switch_of(&self, p: PortId) -> Option<u32> {
        match p {
            PortId::Guest(i) => self.ports[i].as_ref().map(|g| g.switch),
            PortId::Uplink(n) => self.nics[n].switch,
        }
    }

    /// Whether port `to` takes this GSO frame whole.
    fn takes_gso(&self, to: PortId, hdr: &[u8; net::HDR_SIZE]) -> bool {
        match to {
            PortId::Guest(i) => self.ports[i]
                .as_ref()
                .is_some_and(|p| unsafe { addr_of!((*p.chan).rx_gso).read_volatile() != 0 }),
            PortId::Uplink(n) => self.nics[n].takes_gso(hdr),
        }
    }

    fn deliver(&mut self, to: PortId, frame: &mut [u8], hdr: &mut [u8; net::HDR_SIZE]) {
        if is_gso(hdr) && !self.takes_gso(to, hdr) {
            let buf = core::mem::take(&mut self.seg_buf);
            offload::segment(frame, hdr, buf, |f, h| self.deliver_one(to, f, h));
            self.seg_buf = buf;
            return;
        }
        self.deliver_one(to, frame, hdr);
    }

    fn deliver_one(&mut self, to: PortId, frame: &mut [u8], hdr: &mut [u8; net::HDR_SIZE]) {
        match to {
            PortId::Guest(i) => {
                let Some(p) = self.ports[i].as_mut() else { return };
                let rx_csum = unsafe { addr_of!((*p.chan).rx_csum).read_volatile() != 0 };
                if !rx_csum {
                    complete_csum(frame, hdr);
                    hdr[0] = 0;
                }
                // Behind a backlog, or no room: hold the frame (in order).
                if p.backlog.is_empty() && rx_put(p.chan, &*frame, hdr) {
                    p.rx_frames += 1;
                    p.signal = true;
                } else {
                    if !self.pool.push(&mut p.backlog, frame, hdr, BACKLOG_FRAMES, BACKLOG_CHUNKS) {
                        p.drops += 1;
                        return;
                    }
                    self.rx_backlog(i);
                }
            }
            PortId::Uplink(n) => {
                let nic = &mut self.nics[n];
                if !nic.csum {
                    complete_csum(frame, hdr);
                }
                nic.send(frame, hdr, self.pool);
            }
        }
    }

    /// Switch one frame that arrived on port `from`.
    fn forward(&mut self, from: PortId, frame: &mut [u8], hdr: &mut [u8; net::HDR_SIZE]) {
        if frame.len() < 14 {
            return;
        }
        let Some(switch) = self.switch_of(from) else { return };
        let dst: [u8; 6] = frame[0..6].try_into().unwrap();
        let src: [u8; 6] = frame[6..12].try_into().unwrap();
        if let PortId::Guest(i) = from {
            let p = self.ports[i].as_mut().unwrap();
            if (p.lock && src != p.mac) || !offload::sanitize(hdr, frame) {
                p.drops += 1;
                return;
            }
            p.tx_frames += 1;
        }
        let now = rdtsc();
        let age = FDB_AGE_SECS * self.tsc_hz;
        // Ports and NICs join only switches below MAX_SWITCHES.
        let sw = switch as u8;
        if src[0] & 1 == 0 {
            if let Some(i) = self.fdb.find(sw, &src) {
                let e = &mut self.fdb.slots[i];
                (e.port, e.seen) = (from.code(), now);
            } else {
                if !self.fdb.has_room(sw) {
                    self.fdb.expire(now, age);
                }
                if self.fdb.has_room(sw) {
                    self.fdb.insert(sw, src, from, now);
                }
            }
        }
        let known = if dst[0] & 1 == 0 {
            match self.fdb.find(sw, &dst) {
                Some(i) if now.wrapping_sub(self.fdb.slots[i].seen) < age => Some(PortId::of_code(self.fdb.slots[i].port)),
                Some(i) => {
                    self.fdb.remove(i);
                    None
                }
                None => None,
            }
        } else {
            None
        };
        let from_isolated = self.is_isolated(from);
        match known {
            Some(to) if to == from => {}
            Some(to) if from_isolated && self.is_isolated(to) => {}
            Some(to) if self.switch_of(to) == Some(switch) => self.deliver(to, frame, hdr),
            _ => {
                // The switch's other ports, guests' then uplinks.
                for k in 0..net::MAX_PORTS + self.nics.len() {
                    let to = if k < net::MAX_PORTS { PortId::Guest(k) } else { PortId::Uplink(k - net::MAX_PORTS) };
                    if to != from && self.switch_of(to) == Some(switch) && !(from_isolated && self.is_isolated(to)) {
                        self.deliver(to, frame, hdr);
                    }
                }
            }
        }
    }

    fn is_isolated(&self, p: PortId) -> bool {
        match p {
            PortId::Guest(i) => self.ports[i].as_ref().is_some_and(|p| p.isolated),
            PortId::Uplink(_) => false,
        }
    }

    /// Move port `i`'s backlog into its RX ring while there is room.  While
    /// frames remain, the client is asked to kick netd when it frees slots.
    fn rx_backlog(&mut self, i: usize) {
        let Some(p) = self.ports[i].as_mut() else { return };
        loop {
            while let Some(f) = self.pool.front(&p.backlog) {
                if !rx_put(p.chan, &f, &f.hdr) {
                    break;
                }
                self.pool.pop(&mut p.backlog);
                p.rx_frames += 1;
                p.signal = true;
            }
            let wanted = !p.backlog.is_empty();
            unsafe { addr_of_mut!((*p.chan).rx_wanted).write_volatile(wanted as u32) };
            if !wanted {
                return;
            }
            // The client may have freed slots before it saw rx_wanted.
            fence(Ordering::SeqCst);
            if rx_full(p.chan) {
                return;
            }
        }
    }

    /// Take the frames a guest port has queued for transmission.
    fn port_tx(&mut self, i: usize) {
        let Some(p) = self.ports[i].as_ref() else { return };
        let chan = p.chan;
        let frame = core::mem::take(&mut self.buf);
        // The indices are the client's: at most one ring's worth per kick,
        // and nothing at all from a ring that claims more.
        let pending = unsafe { addr_of!((*chan).tx.head).read_volatile().wrapping_sub(addr_of!((*chan).tx.tail).read_volatile()) };
        if pending as usize > net::RING_SIZE {
            if let Some(p) = self.ports[i].as_mut() {
                p.drops += 1;
            }
            self.buf = frame;
            return;
        }
        for _ in 0..pending {
            let (n, mut hdr) = unsafe {
                let tail = addr_of!((*chan).tx.tail).read_volatile();
                if tail == addr_of!((*chan).tx.head).read_volatile() {
                    break;
                }
                fence(Ordering::Acquire);
                let slot = addr_of!((*chan).tx_slots[tail as usize % net::RING_SIZE]);
                let n = (addr_of!((*slot).len).read_volatile() as usize).min(net::MAX_FRAME);
                core::ptr::copy_nonoverlapping(addr_of!((*slot).data) as *const u8, frame.as_mut_ptr(), n);
                let hdr = addr_of!((*slot).hdr).read_volatile();
                fence(Ordering::Release);
                addr_of_mut!((*chan).tx.tail).write_volatile(tail.wrapping_add(1));
                (n, hdr)
            };
            self.forward(PortId::Guest(i), &mut frame[..n], &mut hdr);
        }
        self.buf = frame;
        if let Some(p) = self.ports[i].as_mut() {
            p.signal = true;
        }
    }

    fn nic_rx(&mut self, n: usize) {
        let frame = core::mem::take(&mut self.buf);
        self.nics[n].rx_begin();
        loop {
            let mut hdr = [0u8; net::HDR_SIZE];
            while let Some(len) = self.nics[n].receive(frame, &mut hdr) {
                if self.nics[n].switch.is_none() {
                    continue;
                }
                if offload::sanitize_rx(&mut hdr, &frame[..len]) {
                    // Merge TCP segments into one GSO frame where possible.
                    if self.gro[n].as_mut().unwrap().add(&frame[..len], &hdr) {
                        continue;
                    }
                    self.gro_flush(n);
                    if self.gro[n].as_mut().unwrap().add(&frame[..len], &hdr) {
                        continue;
                    }
                    self.forward(PortId::Uplink(n), &mut frame[..len], &mut hdr);
                } else if is_gso(&hdr) {
                    // A large frame the device checked but did not leave
                    // a partial checksum in: forward its segments.
                    let buf = core::mem::take(&mut self.seg_buf);
                    offload::segment(&frame[..len], &hdr, buf, |f, h| self.forward(PortId::Uplink(n), f, h));
                    self.seg_buf = buf;
                }
            }
            self.gro_flush(n);
            if self.nics[n].rx_done() {
                break;
            }
        }
        self.buf = frame;
        self.nics[n].flush_tx(self.pool);
    }

    /// Forward the TCP run NIC `n`'s receive offload has built.
    fn gro_flush(&mut self, n: usize) {
        let Some(g) = self.gro[n].take() else { return };
        g.flush(|f, h| self.forward(PortId::Uplink(n), f, h));
        self.gro[n] = Some(g);
    }

    fn signal_clients(&mut self) {
        for p in self.ports.iter_mut().flatten() {
            if p.signal {
                p.signal = false;
                p.client.signal();
            }
        }
    }

    fn remove_port(&mut self, i: usize) {
        if let Some(mut p) = self.ports.get_mut(i).and_then(|p| p.take()) {
            self.pool.clear(&mut p.backlog);
            let code = PortId::Guest(i).code();
            self.fdb.remove_if(|e| e.port == code);
        }
    }
}

fn rx_full(chan: *mut net::Port) -> bool {
    unsafe {
        let head = addr_of!((*chan).rx.head).read_volatile();
        let tail = addr_of!((*chan).rx.tail).read_volatile();
        head.wrapping_sub(tail) as usize >= net::RING_SIZE
    }
}

/// Put a frame into a port's RX ring; false if it is full.
fn rx_put(chan: *mut net::Port, frame: &(impl Frame + ?Sized), hdr: &[u8; net::HDR_SIZE]) -> bool {
    if rx_full(chan) {
        return false;
    }
    unsafe {
        let head = addr_of!((*chan).rx.head).read_volatile();
        let slot = addr_of_mut!((*chan).rx_slots[head as usize % net::RING_SIZE]);
        frame.copy_to(core::slice::from_raw_parts_mut(addr_of_mut!((*slot).data) as *mut u8, frame.len()));
        addr_of_mut!((*slot).hdr).write_volatile(*hdr);
        addr_of_mut!((*slot).len).write_volatile(frame.len() as u32);
        fence(Ordering::Release);
        addr_of_mut!((*chan).rx.head).write_volatile(head.wrapping_add(1));
    }
    true
}

fn mr(i: usize) -> u64 {
    sel4::with_ipc_buffer(|b| b.msg_regs()[i])
}

fn set_mr(i: usize, v: u64) {
    sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[i] = v)
}

fn main(info: &'static Info) -> ! {
    let cfg: &NetdConfig = unsafe { info.config() };
    // The statics are taken here, once.
    let mut d = Netd {
        ports: [const { None }; net::MAX_PORTS],
        nics: ArrayVec::new(),
        gro: [const { None }; net::MAX_NICS],
        fdb: Fdb {
            slots: unsafe { &mut *addr_of_mut!(FDB_SLOTS_MEM) },
            len: [0; net::MAX_SWITCHES],
            total: 0,
            seed: rdtsc(),
            sweep_at: 0,
        },
        pool: pool::take(),
        tsc_hz: info.header().tsc_hz,
        buf: unsafe { &mut *addr_of_mut!(BUF) },
        seg_buf: unsafe { &mut *addr_of_mut!(SEG_BUF) },
    };
    let gro = unsafe { &mut *addr_of_mut!(GRO) };
    for ((n, c), g) in cfg.nics[..(cfg.nr_nics as usize).min(net::MAX_NICS)].iter().enumerate().zip(gro) {
        let _ = d.nics.push(Nic::new(n, c, d.tsc_hz));
        d.gro[n] = Some(offload::Gro::init(g));
    }
    let ep = cap::<cap_type::Endpoint>(host::SLOT_SERVICE_EP);
    let reply = cap::<cap_type::Reply>(host::SLOT_REPLY);
    l4h_rt::info!("netd: {} uplink NIC(s)", d.nics.len());

    let (mut msg, mut badge) = ep.recv(reply);
    loop {
        if badge != 0 {
            // Notification: port kicks and NIC interrupts.
            for i in 0..net::MAX_PORTS {
                if badge & (1 << i) != 0 {
                    d.port_tx(i);
                    d.rx_backlog(i);
                }
            }
            for n in 0..d.nics.len() {
                if badge & (1 << (net::NETD_BADGE_IRQ_SHIFT as usize + n)) != 0 {
                    d.nic_rx(n);
                    cap::<cap_type::IrqHandler>(net::NETD_SLOT_IRQ_BASE + n as u64)
                        .irq_handler_ack()
                        .expect("netd: IRQ ack");
                }
            }
            for nic in &mut d.nics {
                nic.kick_tx();
            }
            d.signal_clients();
            (msg, badge) = ep.recv(reply);
            continue;
        }
        // A call from l4h-root.
        let resp = match msg.label() {
            net::NETD_ADD_PORT => {
                let i = mr(0) as usize;
                if i < net::MAX_PORTS && mr(1) < net::MAX_SWITCHES as u64 {
                    d.remove_port(i);
                    let chan = net::port_va(i) as *mut net::Port;
                    let mac = mac_of(mr(2));
                    unsafe {
                        addr_of_mut!((*chan).mac).write_volatile([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 0]);
                        addr_of_mut!((*chan).link_up).write_volatile(1);
                        addr_of_mut!((*chan).rx_wanted).write_volatile(0);
                    }
                    d.ports[i] = Some(GuestPort {
                        chan,
                        switch: mr(1) as u32,
                        mac,
                        lock: mr(3) & net::NETD_PORT_MAC_LOCK != 0,
                        isolated: mr(3) & net::NETD_PORT_ISOLATED != 0,
                        client: cap::<cap_type::Notification>(net::NETD_SLOT_CLIENT_BASE + i as u64),
                        signal: false,
                        rx_frames: 0,
                        tx_frames: 0,
                        drops: 0,
                        backlog: Fifo::EMPTY,
                    });
                    0
                } else {
                    u64::MAX
                }
            }
            net::NETD_REMOVE_PORT => {
                d.remove_port(mr(0) as usize);
                0
            }
            net::NETD_ATTACH_UPLINK => {
                let (n, sw) = (mr(0) as usize, mr(1) as u32);
                match d.nics.get_mut(n).filter(|_| (sw as usize) < net::MAX_SWITCHES) {
                    Some(nic) => {
                        nic.switch = Some(sw);
                        0
                    }
                    None => u64::MAX,
                }
            }
            net::NETD_NIC_MAC => match d.nics.get(mr(0) as usize) {
                Some(n) => n.mac.iter().fold(0u64, |m, &b| (m << 8) | b as u64),
                None => u64::MAX,
            },
            net::NETD_PORT_STATS => match d.ports.get(mr(0) as usize).and_then(|p| p.as_ref()) {
                Some(p) => {
                    set_mr(1, p.tx_frames);
                    set_mr(2, p.drops);
                    p.rx_frames
                }
                None => u64::MAX,
            },
            _ => u64::MAX,
        };
        set_mr(0, resp);
        (msg, badge) = ep.reply_recv(sel4::MessageInfo::new(0, 0, 0, 3), reply);
    }
}

l4h_rt::component!(main, no_heap);
