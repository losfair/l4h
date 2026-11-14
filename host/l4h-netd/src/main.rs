//! netd: L2 virtual switches (DESIGN.md §9.3).
//!
//! Every port belongs to one switch.  A port is a guest vNIC (a channel to
//! that guest's l4h-vmm), an uplink (a channel to the nicd that drives a
//! NIC, uplink.rs: netd has no device code) or, on a multikernel machine,
//! a link to another partition's netd (link.rs).  Switches learn source MACs, forward known unicast to one
//! port and flood everything else within the switch.  Guest ports can be
//! locked to their configured MAC.  Nothing above L2 is looked at, except
//! by steering rules dom0 sets (steer.rs), which pick a port by IP address,
//! protocol and port and rewrite only MAC addresses, and by the L3 filters
//! of ports that have one (ipfilter.rs), which drop frames from addresses
//! dom0 did not give the port.
//!
//! netd has no heap (DESIGN.md §10): its tables are fixed arrays, its frame
//! buffers statics, and the frames it holds take chunks of a fixed pool
//! (pool.rs).

#![no_std]
#![no_main]

mod ipfilter;
mod link;
mod pool;
mod steer;
mod uplink;

use l4h_netcore::offload;

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_rt::host::errno::Errno;
use l4h_rt::host::net;
use l4h_rt::host::spsc::{Consumer, Producer};
use l4h_rt::sel4;
use l4h_rt::{Info, cap, host};
use sel4::cap_type;

use crate::offload::{complete_csum, is_gso};
use crate::pool::{Fifo, Frame, Pool};
use crate::steer::Steer;

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
/// they may take (all backlogs together take at most pool::BYTES, and
/// each leaves the others their reserve and a share, pool::Pool::push).
/// Dropping them instead costs TCP a retransmission timeout whenever a
/// burst outruns the ring (24 slots); a guest that stops reading costs
/// only its own backlog.
const BACKLOG_FRAMES: usize = 512;
const BACKLOG_CHUNKS: usize = (2 << 20) / pool::CHUNK;
/// Looks at a link's incoming ring before netd turns to its other work
/// (and kicks itself to come back): a flooding peer cannot starve the
/// rest.  Every look counts, whatever it gave (a frame, a record that was
/// dropped, nothing), and reads at most two records (link::Link::recv).
const LINK_BUDGET: usize = 256;
/// Looks at an uplink's channel before netd turns to its other work and
/// comes back for the rest (`Netd::uplink_rx`): a nicd that receives
/// faster than netd switches, or floods, cannot starve the ports, the
/// links and root's commands.  Every look counts, frame or drop.
const UPLINK_BUDGET: usize = 256;
/// RX backlog attempts per port and turn, including failed puts. A peer
/// can change its tail between the full check and the wakeup recheck.
const BACKLOG_BUDGET: usize = net::RING_SIZE;
/// Limit a guest's work per receive turn on a linked switch. The switch
/// flushes link notifications before coming back for the remaining slots.
const LINK_TX_BYTES: usize = 128 << 10;

/// The frame being switched, and the segments of a GSO frame for a port
/// that cannot take it whole: too large for the stack.
const FRAME_BUFFER_SIZE: usize = net::MAX_FRAME + net::HDR_SIZE + 1;
static mut BUF: [u8; FRAME_BUFFER_SIZE] = [0; FRAME_BUFFER_SIZE];
static mut SEG_BUF: [u8; net::MAX_FRAME] = [0; net::MAX_FRAME];
static mut FDB_SLOTS_MEM: [FdbEntry; FDB_SLOTS] = [FdbEntry::FREE; FDB_SLOTS];
static mut STEER: Steer = Steer::new();
static mut FILTERS: [ipfilter::Filter; net::MAX_PORTS] = [ipfilter::Filter::OFF; net::MAX_PORTS];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PortId {
    Guest(usize),
    Uplink(usize),
    Link(usize),
}

struct GuestPort {
    chan: *mut net::Port,
    switch: u32,
    mac: [u8; 6],
    lock: bool,
    alias: Option<[u8; 6]>,
    uplink: bool,
    /// An isolated port exchanges frames only with ports that are not
    /// isolated (other guests' normal ports and the uplink).
    isolated: bool,
    client: sel4::cap::Notification,
    /// Our indices of the port's rings: the client can write over the
    /// port's copies.
    tx: Consumer,
    rx: Producer,
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
    uplinks: [Option<uplink::Uplink>; net::MAX_UPLINKS],
    /// The switch of each uplink: it stays while the uplink's nicd is
    /// restarted (RemoveUplink, AddUplink).
    uplink_switch: [Option<u32>; net::MAX_UPLINKS],
    /// AddUplinks of each, which root reads to know a published state is
    /// the current channel's.
    uplink_gen: [u32; net::MAX_UPLINKS],
    links: [Option<link::Link>; net::MAX_LINKS],
    fdb: Fdb,
    /// Endpoints and steering rules.
    steer: &'static mut Steer,
    /// Each guest port's L3 filter.
    filters: &'static mut [ipfilter::Filter; net::MAX_PORTS],
    /// The chunks of the frames all backlogs hold.
    pool: &'static mut Pool,
    /// Ports with RX work left after their bounded wakeup recheck.
    deferred_ports: u64,
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

const _: () = assert!(net::MAX_PORTS <= 0x40 && net::MAX_LINKS <= 0x40 && net::MAX_UPLINKS <= 32);
// A link's channel fits where root maps it (net::link_va).
const _: () = assert!(l4h_partition::LINK_CHANNEL_SIZE as usize <= net::LINK_CHANNEL_MAX);
const _: () = assert!(
    steer::MAX_ENDPOINTS == net::MAX_STEER_ENDPOINTS
        && steer::MAX_RULES == net::MAX_STEER_RULES
        && net::MAX_PORTS <= steer::MAX_TARGETS
        && net::MAX_SWITCHES <= 64
        && ipfilter::MAX_PREFIXES == net::MAX_PORT_IPS
);

impl PortId {
    /// The port as a forwarding table entry keeps it.
    fn code(self) -> u8 {
        match self {
            PortId::Guest(i) => i as u8,
            PortId::Link(l) => 0x40 | l as u8,
            PortId::Uplink(n) => 0x80 | n as u8,
        }
    }

    fn of_code(c: u8) -> PortId {
        match c {
            0..0x40 => PortId::Guest(c as usize),
            0x40..0x80 => PortId::Link((c & 0x3f) as usize),
            _ => PortId::Uplink((c & 0x7f) as usize),
        }
    }
}

impl Netd {
    fn switch_of(&self, p: PortId) -> Option<u32> {
        match p {
            PortId::Guest(i) => self.ports[i].as_ref().map(|g| g.switch),
            PortId::Uplink(n) => self.uplinks[n].as_ref().and(self.uplink_switch[n]),
            PortId::Link(l) => self.links[l].as_ref().map(|k| k.switch),
        }
    }

    /// Whether port `to` takes this GSO frame whole.
    fn takes_gso(&self, to: PortId, len: usize, hdr: &[u8; net::HDR_SIZE]) -> bool {
        match to {
            // The flags are the client's, and can say anything: a port
            // takes large frames only if it also takes partial checksums.
            PortId::Guest(i) => self.ports[i].as_ref().is_some_and(|p| unsafe {
                offload::guest_takes_gso(
                    addr_of!((*p.chan).rx_csum).read_volatile() != 0,
                    addr_of!((*p.chan).rx_gso).read_volatile() != 0,
                )
            }),
            PortId::Uplink(n) => self.uplinks[n].as_ref().is_some_and(|u| u.takes_gso(len, hdr)),
            PortId::Link(l) => offload::link_takes_gso(hdr)
                && self.links[l].as_ref().is_some_and(|link| link.can_send_gso(len)),
        }
    }

    fn deliver(&mut self, to: PortId, frame: &mut [u8], hdr: &mut [u8; net::HDR_SIZE]) {
        if is_gso(hdr) && !self.takes_gso(to, frame.len(), hdr) {
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
                    // A GSO frame's checksum cannot be completed, and the
                    // frame may go to other ports after this one: a client
                    // that cleared rx_csum since `takes_gso` read it loses
                    // the frame.
                    if is_gso(hdr) {
                        p.drops += 1;
                        return;
                    }
                    complete_csum(frame, hdr);
                    hdr[0] = 0;
                }
                // Behind a backlog, or no room: hold the frame (in order).
                if p.backlog.is_empty() && rx_put(p, &*frame, hdr) {
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
                if let Some(u) = self.uplinks[n].as_mut() {
                    u.send(frame, hdr, self.pool);
                }
            }
            PortId::Link(l) => {
                let Some(k) = self.links[l].as_mut() else { return };
                if is_gso(hdr) {
                    k.send_gso(frame, hdr);
                } else {
                    complete_csum(frame, hdr);
                    k.send(frame);
                }
            }
        }
    }

    /// Switch (or steer) one frame that arrived on port `from`.
    fn forward(&mut self, from: PortId, frame: &mut [u8], hdr: &mut [u8; net::HDR_SIZE]) {
        if frame.len() < 14 {
            return;
        }
        let Some(switch) = self.switch_of(from) else { return };
        let src: [u8; 6] = frame[6..12].try_into().unwrap();
        // A filtered port's frame from a steered address: only a rule's
        // return path takes it.
        let mut return_only = false;
        if let PortId::Guest(i) = from {
            let p = self.ports[i].as_mut().unwrap();
            if (p.lock && src != p.mac && p.alias != Some(src)) || !offload::sanitize(hdr, frame) {
                p.drops += 1;
                return;
            }
            if self.filters[i].on {
                // A partial checksum is written where the guest said, after
                // the filter looked: complete it first.  A GSO frame's goes
                // into its TCP checksum (offload::sanitize), and its
                // segments copy the headers the filter saw.
                if !is_gso(hdr) {
                    complete_csum(frame, hdr);
                }
                // A steering rule's target may send as the rule's address.
                match ipfilter::check(&self.filters[i], frame) {
                    ipfilter::Verdict::Pass => {}
                    ipfilter::Verdict::Spoofed if self.steer.is_return(i, frame) => return_only = true,
                    _ => {
                        p.drops += 1;
                        return;
                    }
                }
            }
            p.tx_frames += 1;
        }
        // Slow Protocols belong to one physical link. Do not learn,
        // steer or flood LACP/Marker frames to ordinary guest ports.
        if frame[..6] == [0x01, 0x80, 0xc2, 0, 0, 2] {
            if frame[12..14] != [0x88, 0x09] { return; }
            match from {
                PortId::Guest(i) if self.ports[i].as_ref().is_some_and(|p| p.uplink) => {
                    if let Some(n) = self.uplink_on(switch) {
                        self.deliver(PortId::Uplink(n), frame, hdr);
                    }
                }
                PortId::Uplink(_) => {
                    if let Some(i) = self.ports.iter().position(|p| p.as_ref().is_some_and(|p| p.uplink && p.switch == switch)) {
                        self.deliver(PortId::Guest(i), frame, hdr);
                    }
                }
                _ => {}
            }
            return;
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
        let guest = match from {
            PortId::Guest(i) => Some(i),
            PortId::Uplink(_) | PortId::Link(_) => None,
        };
        if !return_only && let Some(t) = self.steer.inbound(sw, guest, frame) {
            self.deliver(PortId::Guest(t), frame, hdr);
            return;
        }
        if let Some(ep) = guest.and_then(|i| self.steer.outbound(i, frame)) {
            // Out through the endpoint's switch, never back to its owner;
            // nothing is learned, and isolation does not apply.
            let owner = self.fdb.find(ep.switch, &ep.mac).map(|i| PortId::of_code(self.fdb.slots[i].port));
            self.switch_frame(owner, false, ep.switch as u32, frame, hdr);
            return;
        }
        // is_return said outbound takes it; never switch it as it is.
        if return_only {
            if let PortId::Guest(i) = from {
                self.ports[i].as_mut().unwrap().drops += 1;
            }
            return;
        }
        let isolated = self.is_isolated(from);
        self.switch_frame(Some(from), isolated, switch, frame, hdr);
    }

    /// Send a frame on `switch` to the port its destination was learned
    /// on, or flood it, but never to `exclude`.  An `isolated` sender
    /// reaches no isolated port.
    fn switch_frame(
        &mut self,
        exclude: Option<PortId>,
        isolated: bool,
        switch: u32,
        frame: &mut [u8],
        hdr: &mut [u8; net::HDR_SIZE],
    ) {
        let dst: [u8; 6] = frame[0..6].try_into().unwrap();
        let now = rdtsc();
        let age = FDB_AGE_SECS * self.tsc_hz;
        let sw = switch as u8;
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
        match known {
            Some(to) if Some(to) == exclude => {}
            Some(to) if isolated && self.is_isolated(to) => {}
            Some(to) if self.switch_of(to) == Some(switch) => self.deliver(to, frame, hdr),
            _ => {
                // The switch's other ports: guests', uplinks, then links.
                for k in 0..net::MAX_PORTS + net::MAX_UPLINKS + net::MAX_LINKS {
                    let to = match k.checked_sub(net::MAX_PORTS) {
                        None => PortId::Guest(k),
                        Some(n) if n < net::MAX_UPLINKS => PortId::Uplink(n),
                        Some(n) => PortId::Link(n - net::MAX_UPLINKS),
                    };
                    if Some(to) != exclude && self.switch_of(to) == Some(switch) && !(isolated && self.is_isolated(to)) {
                        self.deliver(to, frame, hdr);
                    }
                }
            }
        }
    }

    fn is_isolated(&self, p: PortId) -> bool {
        match p {
            PortId::Guest(i) => self.ports[i].as_ref().is_some_and(|p| p.isolated),
            PortId::Uplink(_) | PortId::Link(_) => false,
        }
    }

    /// Switch what link `l`'s peer sent, for LINK_BUDGET looks at its
    /// ring; then, with the ring empty, ask for a doorbell (link.rs), or
    /// with the budget spent, kick netd to come back after its other work.
    fn link_rx(&mut self, l: usize) {
        let frame = core::mem::take(&mut self.buf);
        let mut budget = LINK_BUDGET;
        while let Some(k) = self.links[l].as_mut() {
            if budget == 0 {
                k.kick();
                break;
            }
            // The peer writes the ring: records netd drops, and a ring
            // that is never found empty, cost it as much as frames.
            budget -= 1;
            match k.recv(frame) {
                link::Received::Frame(frame, mut hdr) => self.forward(PortId::Link(l), frame, &mut hdr),
                link::Received::Dropped => {}
                link::Received::Empty if k.sleep() => break,
                link::Received::Empty => {}
            }
        }
        self.buf = frame;
    }

    /// Move port `i`'s backlog into its RX ring while there is room.  While
    /// frames remain, the client is asked to kick netd when it frees slots.
    fn rx_backlog(&mut self, i: usize) {
        self.deferred_ports &= !(1 << i);
        let Some(p) = self.ports[i].as_mut() else { return };
        let mut budget = BACKLOG_BUDGET;
        loop {
            while budget != 0 {
                let Some(f) = self.pool.front(&p.backlog) else { break };
                budget -= 1;
                if !rx_put(p, &f, &f.hdr) {
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
            if rx_full(p) {
                return;
            }
            if budget == 0 {
                // Room appeared before the client saw rx_wanted. Come
                // back without relying on a kick that may not arrive.
                self.deferred_ports |= 1 << i;
                return;
            }
        }
    }

    /// Take the frames a guest port has queued for transmission. Return
    /// whether the byte budget left any of this snapshot for the next turn.
    fn port_tx(&mut self, i: usize) -> bool {
        let Some(p) = self.ports[i].as_ref() else { return false };
        let (chan, mut tx) = (p.chan, p.tx);
        let limited = self.links.iter().flatten().any(|link| link.switch == p.switch);
        // The head is the client's: at most one ring's worth per kick, and
        // nothing at all from a ring that claims more.
        let Some(pending) = (unsafe { tx.pending(&(*chan).tx) }) else {
            if let Some(p) = self.ports[i].as_mut() {
                p.drops += 1;
            }
            return false;
        };
        let frame = core::mem::take(&mut self.buf);
        let mut bytes = 0;
        let mut more = false;
        for index in 0..pending {
            let (n, mut hdr) = unsafe {
                let slot = addr_of!((*chan).tx_slots[tx.slot()]);
                let n = (addr_of!((*slot).len).read_volatile() as usize).min(net::MAX_FRAME);
                core::ptr::copy_nonoverlapping(addr_of!((*slot).data) as *const u8, frame.as_mut_ptr(), n);
                let hdr = addr_of!((*slot).hdr).read_volatile();
                tx.pop(&(*chan).tx);
                (n, hdr)
            };
            self.forward(PortId::Guest(i), &mut frame[..n], &mut hdr);
            bytes += n;
            if limited && bytes >= LINK_TX_BYTES {
                more = index + 1 < pending;
                break;
            }
        }
        self.buf = frame;
        // Switching does not touch this port's TX ring.
        if let Some(p) = self.ports[i].as_mut() {
            p.tx = tx;
            p.signal = true;
        }
        more
    }

    /// The uplink on `switch` (the first, if several).
    fn uplink_on(&self, switch: u32) -> Option<usize> {
        (0..net::MAX_UPLINKS).find(|&n| self.uplinks[n].is_some() && self.uplink_switch[n] == Some(switch))
    }

    /// Switch what uplink `n`'s nicd received, UPLINK_BUDGET looks at its
    /// channel at most.  Returns whether it has frames left: the caller
    /// comes back after netd's other work.  With none left netd asks the
    /// nicd to signal when it has more.
    fn uplink_rx(&mut self, n: usize) -> bool {
        let frame = core::mem::take(&mut self.buf);
        let mut budget = UPLINK_BUDGET;
        let more = loop {
            let Some(u) = self.uplinks[n].as_mut() else { break false };
            if budget == 0 {
                break true;
            }
            budget -= 1;
            match u.recv(frame) {
                Some(Some((len, mut hdr))) => {
                    if self.uplink_switch[n].is_some() {
                        self.forward(PortId::Uplink(n), &mut frame[..len], &mut hdr);
                    }
                }
                Some(None) => {}
                None if u.sleep() => break false,
                None => {}
            }
        };
        self.buf = frame;
        more
    }

    /// Everything about uplink `n` on a turn: its offer, its frames and
    /// the room it freed.  Returns whether frames are left.
    fn uplink_turn(&mut self, n: usize) -> bool {
        let Some(u) = self.uplinks[n].as_mut() else { return false };
        if u.poll_offer() {
            self.publish_links();
        }
        let more = self.uplink_rx(n);
        if let Some(u) = self.uplinks[n].as_mut() {
            u.flush(self.pool);
        }
        more
    }

    fn publish_links(&mut self) {
        let links: [Option<(u32, net::LinkState)>; net::MAX_UPLINKS] =
            core::array::from_fn(|n| Some((self.uplink_switch[n]?, self.uplinks[n].as_ref()?.link())));
        for p in self.ports.iter_mut().flatten().filter(|p| p.uplink) {
            let link = links.iter().flatten().find(|(sw, _)| *sw == p.switch)
                .map(|&(_, l)| l).unwrap_or(net::LinkState::DOWN);
            unsafe {
                if addr_of!((*p.chan).link_state).read_volatile() != link.0 {
                    addr_of_mut!((*p.chan).link_state).write_volatile(link.0);
                    p.signal = true;
                }
            }
        }
    }

    /// Publish the counters root reports (net::Published).
    fn publish(&self, to: &net::Published) {
        for (n, (u, w)) in self.uplinks.iter().zip(&to.uplinks).enumerate() {
            let state = match u.as_ref().map(|u| u.state) {
                None => net::UPLINK_NONE,
                Some(uplink::State::Waiting) => net::UPLINK_WAITING,
                Some(uplink::State::Up) => net::UPLINK_UP,
                Some(uplink::State::Refused) => net::UPLINK_REFUSED,
                Some(uplink::State::Broken) => net::UPLINK_BROKEN,
            };
            let generation = self.uplink_gen[n] as u64 & 0xff_ffff;
            // The offer's words before the state that says they are this
            // channel's (root reads the state first, with Acquire).
            if let Some(u) = u {
                let mac = u.offer.mac6().iter().fold(0u64, |m, &b| (m << 8) | b as u64);
                w[net::UPLINK_MAC].store(mac | (u.offer.mac_mode as u64) << 48, Ordering::Relaxed);
                w[net::UPLINK_LINK].store(u.link().0 as u64, Ordering::Relaxed);
                w[net::UPLINK_RX].store(u.rx_frames, Ordering::Relaxed);
                w[net::UPLINK_TX].store(u.tx_frames, Ordering::Relaxed);
                w[net::UPLINK_DROPS].store(u.drops, Ordering::Relaxed);
            }
            w[net::UPLINK_STATE].store(state | generation << 8, Ordering::Release);
        }
        for (p, c) in self.ports.iter().zip(&to.ports) {
            let v = p.as_ref().map_or([0; 3], |p| [p.rx_frames, p.tx_frames, p.drops]);
            for (w, v) in c.iter().zip(v) {
                w.store(v, Ordering::Relaxed);
            }
        }
        for (r, c) in self.steer.rules.iter().zip(&to.rules) {
            let v = r.as_ref().map_or([0; 2], |r| [r.in_frames, r.out_frames]);
            for (w, v) in c.iter().zip(v) {
                w.store(v, Ordering::Relaxed);
            }
        }
    }

    fn signal_clients(&mut self) {
        for p in self.ports.iter_mut().flatten() {
            if p.signal {
                p.signal = false;
                l4h_rt::mailbox::notify(p.client);
            }
        }
    }

    fn remove_port(&mut self, i: usize) {
        if let Some(mut p) = self.ports.get_mut(i).and_then(|p| p.take()) {
            self.pool.clear(&mut p.backlog);
            let code = PortId::Guest(i).code();
            self.fdb.remove_if(|e| e.port == code);
            self.steer.port_removed(i);
            self.filters[i] = ipfilter::Filter::OFF;
        }
    }
}

/// Whether port `p`'s RX ring is full, or its client broke the tail.
fn rx_full(p: &GuestPort) -> bool {
    unsafe { p.rx.free(&(*p.chan).rx) == 0 }
}

/// Put a frame into a port's RX ring; false if it is full.
fn rx_put(p: &mut GuestPort, frame: &(impl Frame + ?Sized), hdr: &[u8; net::HDR_SIZE]) -> bool {
    if rx_full(p) {
        return false;
    }
    unsafe {
        let slot = addr_of_mut!((*p.chan).rx_slots[p.rx.slot()]);
        frame.copy_to(core::slice::from_raw_parts_mut(addr_of_mut!((*slot).data) as *mut u8, frame.len()));
        addr_of_mut!((*slot).hdr).write_volatile(*hdr);
        addr_of_mut!((*slot).len).write_volatile(frame.len() as u32);
        p.rx.push(&(*p.chan).rx);
    }
    true
}

use l4h_rt::host::errno::EINVAL;

/// Root's commands, as l4h_host::net::call declares them, and the ports
/// they added.
struct Commands<'a> {
    d: &'a mut Netd,
    added: u64,
    added_uplinks: u32,
}

impl net::call::Server for Commands<'_> {
    fn add_port(&mut self, _: net::Sender, i: usize, switch: usize, mac: u64, flags: u64, alias: u64) -> Result<(), Errno> {
        if i >= net::MAX_PORTS || switch >= net::MAX_SWITCHES {
            return Err(EINVAL);
        }
        let d = &mut *self.d;
        d.remove_port(i);
        let chan = net::port_va(i) as *mut net::Port;
        let mac = mac_of(mac);
        unsafe {
            addr_of_mut!((*chan).mac).write_volatile([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 0]);
            addr_of_mut!((*chan).link_state).write_volatile(net::LinkState::VIRTUAL.0);
            addr_of_mut!((*chan).rx_wanted).write_volatile(0);
        }
        let uplink = flags & net::NETD_PORT_UPLINK != 0;
        d.ports[i] = Some(GuestPort {
            chan,
            switch: switch as u32,
            mac,
            lock: flags & net::NETD_PORT_MAC_LOCK != 0,
            alias: (uplink && alias != 0).then(|| mac_of(alias)),
            uplink,
            isolated: flags & net::NETD_PORT_ISOLATED != 0,
            client: cap::<cap_type::Notification>(net::NETD_SLOT_CLIENT_BASE + i as u64),
            // Root gave fresh port memory: both rings start empty.
            tx: Consumer::new(net::RING_SIZE),
            rx: Producer::new(net::RING_SIZE),
            signal: true,
            rx_frames: 0,
            tx_frames: 0,
            drops: 0,
            backlog: Fifo::EMPTY,
        });
        d.filters[i] = ipfilter::Filter { on: flags & net::NETD_PORT_IP_FILTER != 0, ..ipfilter::Filter::OFF };
        d.publish_links();
        self.added |= 1 << i;
        Ok(())
    }

    fn remove_port(&mut self, _: net::Sender, port: usize) -> Result<(), Errno> {
        self.d.remove_port(port);
        Ok(())
    }

    fn attach_uplink(&mut self, _: net::Sender, nic: usize, switch: usize) -> Result<(), Errno> {
        if nic >= net::MAX_UPLINKS || switch >= net::MAX_SWITCHES {
            return Err(EINVAL);
        }
        self.d.uplink_switch[nic] = Some(switch as u32);
        self.d.publish_links();
        Ok(())
    }

    fn add_uplink(&mut self, _: net::Sender, nic: usize, data_bits: u32) -> Result<(), Errno> {
        let ok = nic < net::MAX_UPLINKS && self.d.uplinks[nic].is_none()
            && (l4h_rt::host::uplink::MIN_DATA_BITS..=l4h_rt::host::uplink::MAX_DATA_BITS).contains(&data_bits)
            && l4h_rt::host::uplink::channel_size(data_bits) <= net::UPLINK_CHANNEL_MAX;
        if !ok {
            return Err(EINVAL);
        }
        self.d.uplink_gen[nic] = self.d.uplink_gen[nic].wrapping_add(1);
        self.d.uplinks[nic] = Some(uplink::Uplink::new(nic, data_bits));
        self.added_uplinks |= 1 << nic;
        Ok(())
    }

    fn remove_uplink(&mut self, _: net::Sender, nic: usize) -> Result<(), Errno> {
        let d = &mut *self.d;
        if let Some(mut u) = d.uplinks.get_mut(nic).and_then(|u| u.take()) {
            u.clear(d.pool);
            d.publish_links();
        }
        Ok(())
    }

    fn ep_set(&mut self, _: net::Sender, ep: usize, switch: usize, mac: u64, peer: u64) -> Result<(), Errno> {
        if switch >= net::MAX_SWITCHES {
            return Err(EINVAL);
        }
        let e = steer::Endpoint { switch: switch as u8, mac: mac_of(mac), peer: mac_of(peer) };
        if self.d.steer.ep_set(ep, e) { Ok(()) } else { Err(EINVAL) }
    }

    fn ep_del(&mut self, _: net::Sender, ep: usize) -> Result<(), Errno> {
        self.d.steer.ep_del(ep);
        Ok(())
    }

    fn steer_set(&mut self, _: net::Sender, rule: usize, ep: usize, matches: u64, ip_hi: u64, ip_lo: u64, targets: u64)
        -> Result<(), Errno> {
        let d = &mut *self.d;
        // One target, an existing port: its MAC is the rule's.
        let t = targets.trailing_zeros() as usize;
        let mac = (targets.count_ones() == 1).then(|| d.ports.get(t)).flatten().and_then(|p| p.as_ref()).map(|p| p.mac);
        match (mac, steer::Match::from_words(matches, ip_hi, ip_lo)) {
            (Some(mac), Some(m)) if d.steer.rule_set(rule, ep, m, targets, mac) => Ok(()),
            _ => Err(EINVAL),
        }
    }

    fn steer_del(&mut self, _: net::Sender, rule: usize) -> Result<(), Errno> {
        self.d.steer.rule_del(rule);
        Ok(())
    }

    fn ip_set(&mut self, _: net::Sender, port: usize, slot: usize, prefix: u64, ip_hi: u64, ip_lo: u64) -> Result<(), Errno> {
        let d = &mut *self.d;
        let p = ipfilter::Prefix::from_words(prefix, ip_hi, ip_lo).ok_or(EINVAL)?;
        match d.filters.get_mut(port) {
            Some(f) if f.on && d.ports[port].is_some() => f.set(slot, p).then_some(()).ok_or(EINVAL),
            _ => Err(EINVAL),
        }
    }

    fn ip_del(&mut self, _: net::Sender, port: usize, slot: usize) -> Result<(), Errno> {
        if let Some(f) = self.d.filters.get_mut(port) {
            f.del(slot);
        }
        Ok(())
    }

    fn add_link(&mut self, _: net::Sender, l: usize, switch: usize, size: u64, me: u32, peer: u32) -> Result<(), Errno> {
        let d = &mut *self.d;
        // One size, as root maps it: the rings' record limits, which
        // link.rs relies on, are that size's.
        let ok = l < net::MAX_LINKS && d.links[l].is_none() && switch < net::MAX_SWITCHES
            && size == l4h_partition::LINK_CHANNEL_SIZE;
        if !ok {
            return Err(EINVAL);
        }
        d.links[l] = Some(link::Link::new(l, switch as u32, size, me, peer));
        Ok(())
    }

    fn test_panic(&mut self, _: net::Sender) -> Result<(), Errno> {
        if host::TEST_INJECT {
            panic!("injected panic");
        }
        Err(EINVAL)
    }

    fn test_hang(&mut self, _: net::Sender) -> Result<(), Errno> {
        if host::TEST_INJECT {
            l4h_rt::test_hang();
        }
        Err(EINVAL)
    }
}

fn main(info: &'static Info) -> ! {
    // The statics are taken here, once.
    let mut d = Netd {
        ports: [const { None }; net::MAX_PORTS],
        uplinks: [const { None }; net::MAX_UPLINKS],
        uplink_switch: [None; net::MAX_UPLINKS],
        uplink_gen: [0; net::MAX_UPLINKS],
        links: [const { None }; net::MAX_LINKS],
        fdb: Fdb {
            slots: unsafe { &mut *addr_of_mut!(FDB_SLOTS_MEM) },
            len: [0; net::MAX_SWITCHES],
            total: 0,
            seed: rdtsc(),
            sweep_at: 0,
        },
        steer: unsafe { &mut *addr_of_mut!(STEER) },
        filters: unsafe { &mut *addr_of_mut!(FILTERS) },
        pool: pool::take(),
        deferred_ports: 0,
        tsc_hz: info.header().tsc_hz,
        buf: unsafe { &mut *addr_of_mut!(BUF) },
        seg_buf: unsafe { &mut *addr_of_mut!(SEG_BUF) },
    };
    // Nothing calls netd: it waits on its notification, for root's
    // requests (badges::driver::CALL), its clients' kicks and its nicds'.
    let ntfn = cap::<cap_type::Notification>(host::SLOT_NTFN);
    let published = l4h_rt::mailbox::published::<net::Published>();
    published.ready.store(1, Ordering::Release);
    l4h_rt::mailbox::signal();
    let (mut deferred_tx, mut deferred_rx) = (0u64, 0u32);
    let mut badge = ntfn.wait().1;
    loop {
        // Notification: port kicks and uplink signals. Deferred slots and
        // new client kicks use the same drain path.
        let ports = badge | core::mem::take(&mut deferred_tx);
        let backlogs = ports | core::mem::take(&mut d.deferred_ports);
        for i in 0..net::MAX_PORTS {
            if ports & (1 << i) != 0 {
                if d.port_tx(i) {
                    deferred_tx |= 1 << i;
                }
            }
            if backlogs & (1 << i) != 0 {
                d.rx_backlog(i);
            }
        }
        // Uplinks: any nicd's signal, and those whose last turn left
        // frames (bit n: uplink n).  A turn takes UPLINK_BUDGET at most.
        let rx = core::mem::take(&mut deferred_rx);
        let signalled = badge & host::badges::netd::UPLINK != 0;
        for n in 0..net::MAX_UPLINKS {
            if (signalled || rx & (1 << n) != 0) && d.uplink_turn(n) {
                deferred_rx |= 1 << n;
            }
        }
        for l in 0..net::MAX_LINKS {
            if badge & host::badges::netd::LINK.nth(l) != 0 {
                if let Some(k) = d.links[l].as_ref() {
                    k.ack();
                }
                d.link_rx(l);
            }
        }
        // Once per batch, so a peer that sleeps is woken once for all.
        for u in d.uplinks.iter_mut().flatten() {
            u.notify();
        }
        for k in d.links.iter_mut().flatten() {
            k.doorbell();
        }
        if signalled {
            d.publish_links();
        }
        d.signal_clients();
        d.publish(published);
        // Root's commands (host::mailbox), even if their signal was
        // coalesced.  Root reads the answers' count only: they are done.
        let mut cmds = Commands { d: &mut d, added: 0, added_uplinks: 0 };
        if l4h_rt::mailbox::serve(|label, args, out| net::call::serve(&mut cmds, label, args, net::Sender::Root, out)) {
            l4h_rt::mailbox::signal();
        }
        let added = cmds.added;
        // A new channel's nicd may have written its offer already.
        deferred_rx |= cmds.added_uplinks;
        // Root handed out an added port's channel before netd added it:
        // its VMM may have kicked already, and read the page's link state,
        // DOWN.  Serve the port as if kicked, and signal it.
        // With slots or uplink frames deferred, poll for notifications
        // (badge zero when idle) and come back for the rest.
        badge = if added != 0 {
            added
        } else if deferred_tx != 0 || deferred_rx != 0 || d.deferred_ports != 0 {
            ntfn.poll().1
        } else {
            ntfn.wait().1
        };
    }
}

l4h_rt::component!(main, no_heap);
