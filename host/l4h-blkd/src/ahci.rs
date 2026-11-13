//! AHCI SATA controller: one blkd unit per attached ATA port.
//!
//! Requests own their DMA segment descriptions until completion. A bounded
//! software queue feeds each port's NCQ slots; non-NCQ disks use slot zero.
//! A flush drains that port and blocks later requests to it, not other ports.

use core::sync::atomic::Ordering;

use l4h_rt::host::{self, blk::{self, BlkdConfig}, fixed::{ArrayVec, StaticCell}};
use l4h_virtio::{Dma, Mmio, dma_fence};

use crate::{DevInfo, Driver, MAX_PIECES, MAX_REQUEST, Seg};

const CAP: usize = 0x00;
const GHC: usize = 0x04;
const IS: usize = 0x08;
const PI: usize = 0x0c;
const CLB: usize = 0x00;
const FB: usize = 0x08;
const PXIS: usize = 0x10;
const IE: usize = 0x14;
const CMD: usize = 0x18;
const TFD: usize = 0x20;
const SIG: usize = 0x24;
const SSTS: usize = 0x28;
const SCTL: usize = 0x2c;
const SERR: usize = 0x30;
const SACT: usize = 0x34;
const CI: usize = 0x38;
const ST: u32 = 1;
const POWER: u32 = (1 << 1) | (1 << 2);
const FRE: u32 = 1 << 4;
const FR: u32 = 1 << 14;
const CR: u32 = 1 << 15;
const ATA_BUSY: u32 = 0x80 | 0x08;
// Static ATA ports: data/host errors and any connection change are terminal.
// INFS (26) is recoverable by the HBA; bits 0..3/5 are completion notices.
const PORT_ERRORS: u32 = (1 << 31) | (1 << 30) | (1 << 29) | (1 << 28) | (1 << 27)
    | (1 << 24) | (1 << 23) | (1 << 22) | (1 << 7) | (1 << 6) | (1 << 4);
const PORT_IRQS: u32 = PORT_ERRORS | 1 | (1 << 3) | (1 << 5);
const SLOTS: usize = 32;
const REQUESTS: usize = 64;
const EMPTY: u16 = u16::MAX;
// One input segment can cross a 4 GiB DMA boundary.
const MAX_PRDS: usize = 2 * MAX_PIECES;
const TABLE_BYTES: usize = (128 + 16 * MAX_PRDS).next_power_of_two();
const _: () = assert!(MAX_REQUEST <= 65535 * 512);

struct Request {
    tag: u64,
    unit: usize,
    op: u32,
    sector: u64,
    data: ArrayVec<Seg, MAX_PIECES>,
}

static REQUEST_STORAGE: StaticCell<[Option<Request>; REQUESTS]> = StaticCell::new([const { None }; REQUESTS]);

#[derive(Clone, Copy)]
struct Identify {
    sectors: u64,
    block_size: u32,
    depth: usize,
    flush_command: u8,
}

/// Only ATA disks with LBA48 and a usable cache-flush contract are exposed.
fn identify(words: &[u16; 256], slots: usize, ncq: bool) -> Option<Identify> {
    if words[0] & 0x8000 != 0 || words[49] & (1 << 8) == 0 || words[83] & 0xc400 != 0x4400 { return None; }
    let lbas = (0..4).fold(0u64, |n, i| n | ((words[100 + i] as u64) << (16 * i)));
    if lbas == 0 || lbas > 1 << 48 { return None; }
    let block_size = if words[106] & 0xd000 == 0x5000 {
        ((words[117] as u32) | ((words[118] as u32) << 16)).checked_mul(2)?
    } else { 512 };
    if !matches!(block_size, 512 | 1024 | 2048 | 4096) { return None; }
    // Without valid enabled-feature words, a supported write cache may be
    // enabled. Do not advertise an unflushable disk as write-through.
    let cache = words[82] & (1 << 5) != 0 && (words[87] & 0xc000 != 0x4000 || words[85] & (1 << 5) != 0);
    let flush_command = if !cache { 0 } else if words[83] & (1 << 13) != 0 { 0xea }
        else if words[83] & (1 << 12) != 0 { 0xe7 } else { return None };
    let depth = if ncq && words[76] != 0xffff && words[76] & (1 << 8) != 0 {
        slots.min((words[75] as usize & 31) + 1)
    } else { 1 };
    Some(Identify { sectors: lbas * (block_size as u64 / 512), block_size, depth, flush_command })
}

struct Port {
    number: usize,
    regs: Mmio,
    headers: (usize, u64),
    tables: (usize, u64),
    info: Identify,
    ncq: bool,
    active: u32,
    /// Request index for every issued command slot.
    requests: [u16; SLOTS],
    /// A non-NCQ command cannot overlap NCQ commands on the same port.
    exclusive: bool,
    failed: bool,
}

fn wait_until(ticks_per_ms: u64, ms: u64, done: impl FnMut() -> bool) -> bool {
    wait_before(host::ticks::now().saturating_add(ms.saturating_mul(ticks_per_ms)), done)
}

fn wait_before(end: u64, mut done: impl FnMut() -> bool) -> bool {
    while !done() {
        if host::ticks::now() >= end { return false; }
        core::hint::spin_loop();
    }
    true
}

fn diagnose(number: usize, regs: Mmio, phase: &str) {
    l4h_rt::info!("ahci: port {} {}: CMD {:#x} TFD {:#x} SIG {:#x} SSTS {:#x} SCTL {:#x} SERR {:#x} IS {:#x} CI {:#x} SACT {:#x} CLB {:#x} FB {:#x}",
        number, phase, regs.r32(CMD), regs.r32(TFD), regs.r32(SIG), regs.r32(SSTS), regs.r32(SCTL),
        regs.r32(SERR), regs.r32(PXIS), regs.r32(CI), regs.r32(SACT), regs.r64(CLB), regs.r64(FB));
}

fn stop(number: usize, regs: Mmio, ticks_per_ms: u64) -> bool {
    let control = regs.r32(CMD) & (POWER | FRE);
    regs.w32(CMD, control);
    if !wait_until(ticks_per_ms, 500, || regs.r32(CMD) & CR == 0) {
        diagnose(number, regs, "command-stop timeout");
        return false;
    }
    regs.w32(CMD, control & !FRE);
    let stopped = wait_until(ticks_per_ms, 500, || regs.r32(CMD) & FR == 0);
    if !stopped { diagnose(number, regs, "FIS-stop timeout"); }
    stopped
}

fn reset_link(regs: Mmio, ticks_per_ms: u64) -> bool {
    let ctl = (regs.r32(SCTL) & 0xf0) | (3 << 8);
    regs.w32(SCTL, ctl | 1);
    let end = host::ticks::now().saturating_add(ticks_per_ms.max(1));
    while host::ticks::now() < end { core::hint::spin_loop(); }
    regs.w32(SCTL, ctl);
    let deadline = host::ticks::now().saturating_add(1000 * ticks_per_ms);
    if !wait_before(deadline, || regs.r32(SSTS) & 0xf0f == 0x103) { return false; }
    // AHCI 1.3.1 §10.4.2: clear COMRESET/COMINIT status once the link
    // is established, before waiting for the initial device FIS.
    regs.w32(SERR, u32::MAX);
    regs.w32(PXIS, u32::MAX);
    wait_before(deadline, || regs.r32(TFD) & ATA_BUSY == 0 && regs.r32(SIG) != u32::MAX)
}

/// Build one ATA Register H2D FIS. All logical-block counts are nonzero.
fn fis(command: u8, lba: u64, count: u16, slot: usize, queued: bool) -> [u8; 64] {
    let mut f = [0; 64];
    f[0] = 0x27;
    f[1] = 0x80;
    f[2] = command;
    f[7] = 1 << 6;
    for i in 0..3 { f[4 + i] = (lba >> (8 * i)) as u8; f[8 + i] = (lba >> (24 + 8 * i)) as u8; }
    if queued {
        f[3] = count as u8;
        f[11] = (count >> 8) as u8;
        f[12] = (slot << 3) as u8;
    } else {
        f[12] = count as u8;
        f[13] = (count >> 8) as u8;
    }
    f
}

impl Port {
    /// Clear the observed port cause before its controller summary. The
    /// caller reads completion state only after this two-level acknowledgement.
    fn ack_interrupt(&self, hba: Mmio, causes: u32) {
        self.regs.w32(PXIS, causes);
        hba.w32(IS, 1 << self.number);
    }

    fn new(number: usize, regs: Mmio, dma: &mut Dma, ticks_per_ms: u64) -> Option<Self> {
        if !stop(number, regs, ticks_per_ms) { panic!("ahci: port {} did not stop", number); }
        regs.w32(IE, 0);
        // Power and spin-up. Empty implemented ports must not each spend
        // the full link-reset timeout before the controller can publish.
        regs.w32(CMD, POWER);
        if !wait_until(ticks_per_ms, 100, || regs.r32(SSTS) & 0xf != 0) {
            diagnose(number, regs, "no link detected");
            return None;
        }
        let headers = dma.alloc(1024, 1024);
        let received = dma.alloc(256, 256);
        let tables = dma.alloc(TABLE_BYTES * SLOTS, 128);
        regs.w64(CLB, headers.1);
        regs.w64(FB, received.1);
        regs.w32(SERR, u32::MAX);
        regs.w32(PXIS, u32::MAX);
        regs.w32(CMD, POWER | FRE);
        // Receive the signature FIS after COMRESET before checking SIG.
        // This driver has no link power-management state machine. Keep
        // Partial and Slumber disabled while it owns the port.
        let ready = reset_link(regs, ticks_per_ms);
        // ATAPI devices and port multipliers are not block units here.
        if !ready || regs.r32(SIG) != 0x0000_0101 {
            diagnose(number, regs, if ready { "unsupported signature" } else { "device-ready timeout" });
            assert!(stop(number, regs, ticks_per_ms), "ahci: unsupported port did not stop");
            return None;
        }
        // COMRESET may have raised link-change status. It predates I/O.
        regs.w32(SERR, u32::MAX);
        regs.w32(PXIS, u32::MAX);
        regs.w32(CMD, POWER | FRE | ST);
        Some(Self { number, regs, headers, tables,
            info: Identify { sectors: 0, block_size: 512, depth: 1, flush_command: 0 }, ncq: false,
            active: 0, requests: [EMPTY; SLOTS], exclusive: false, failed: false })
    }

    /// Descriptors contain only blkd-validated DMA addresses, never guest RAM.
    fn command(&self, slot: usize, f: &[u8; 64], write: bool, data: &[Seg]) {
        let table = Mmio(self.tables.0 + slot * TABLE_BYTES);
        for i in 0..TABLE_BYTES / 4 { table.w32(i * 4, 0); }
        for (i, byte) in f.iter().enumerate() { table.w8(i, *byte); }
        let mut prds = 0;
        for piece in data {
            let (mut pa, mut left) = (piece.pa, piece.len as u64);
            while left != 0 {
                // AHCI's DBC is 22 bits. Keep each PRD inside a 4 GiB
                // DMA segment boundary, matching Linux's AHCI policy.
                let take = left.min(4 << 20).min((1u64 << 32) - (pa & 0xffff_ffff));
                let off = 128 + 16 * prds;
                table.w64(off, pa);
                table.w32(off + 12, take as u32 - 1);
                (pa, left, prds) = (pa + take, left - take, prds + 1);
            }
        }
        let header = Mmio(self.headers.0 + slot * 32);
        // D2H/SDB completion interrupts suffice; PRD interrupts add no work.
        header.w32(0, 5 | ((write as u32) << 6) | ((prds as u32) << 16));
        header.w32(4, 0);
        header.w64(8, self.tables.1 + (slot * TABLE_BYTES) as u64);
        for off in [16, 20, 24, 28] { header.w32(off, 0); }
    }

    fn identify(&mut self, buf: (usize, u64), ticks_per_ms: u64, slots: usize, ncq: bool) -> bool {
        self.command(0, &fis(0xec, 0, 0, 0, false), false, &[Seg { pa: buf.1, len: 512 }]);
        dma_fence(Ordering::Release);
        self.regs.w32(CI, 1);
        let completed = wait_until(ticks_per_ms, 5000, || self.regs.r32(CI) & 1 == 0 || self.regs.r32(PXIS) & PORT_ERRORS != 0);
        dma_fence(Ordering::Acquire);
        if !completed || self.regs.r32(TFD) & (1 | 0x20) != 0 || self.regs.r32(PXIS) & PORT_ERRORS != 0 {
            l4h_rt::info!("ahci: port {} IDENTIFY failed (completed {}, taskfile {:#x}, interrupt {:#x})",
                self.number, completed, self.regs.r32(TFD), self.regs.r32(PXIS));
            assert!(stop(self.number, self.regs, ticks_per_ms), "ahci: port did not stop after IDENTIFY failure");
            return false;
        }
        let words = core::array::from_fn(|i| Mmio(buf.0).r16(2 * i));
        let Some(info) = identify(&words, slots, ncq) else {
            l4h_rt::info!("ahci: port {} needs DMA, LBA48, 512..4096-byte sectors and a flushable cache", self.number);
            assert!(stop(self.number, self.regs, ticks_per_ms), "ahci: unsupported port did not stop");
            return false;
        };
        self.info = info;
        self.ncq = ncq && words[76] != 0xffff && words[76] & (1 << 8) != 0;
        self.regs.w32(PXIS, u32::MAX);
        self.regs.w32(IE, PORT_IRQS);
        true
    }

    fn room(&self, op: u32) -> bool {
        if self.failed || self.exclusive { return false; }
        if !self.ncq || op == blk::OP_FLUSH { self.active == 0 }
        else { self.active.count_ones() < self.info.depth as u32 }
    }

    fn issue(&mut self, index: u16, request: &Request) {
        let queued = self.ncq && request.op != blk::OP_FLUSH;
        let slot = if queued { ((!self.active) & ((u32::MAX) >> (32 - self.info.depth))).trailing_zeros() as usize } else { 0 };
        let (command, lba, count) = if request.op == blk::OP_FLUSH {
            (self.info.flush_command, 0, 0)
        } else {
            let bytes: u64 = request.data.iter().map(|s| s.len as u64).sum();
            let lba = request.sector / (self.info.block_size as u64 / 512);
            let count = (bytes / self.info.block_size as u64) as u16;
            let command = match (queued, request.op == blk::OP_WRITE) {
                (true, false) => 0x60, (true, true) => 0x61,
                (false, false) => 0x25, (false, true) => 0x35,
            };
            (command, lba, count)
        };
        self.command(slot, &fis(command, lba, count, slot, queued), request.op == blk::OP_WRITE, &request.data);
        self.requests[slot] = index;
        self.active |= 1 << slot;
        self.exclusive = !queued;
        dma_fence(Ordering::Release);
        // W1S doorbells: rewriting a completed old bit would reissue it.
        if queued { self.regs.w32(SACT, 1 << slot); }
        self.regs.w32(CI, 1 << slot);
    }
}

pub struct Ahci {
    id: u32,
    regs: Mmio,
    ports: ArrayVec<Port, { blk::MAX_UNITS }>,
    requests: &'static mut [Option<Request>; REQUESTS],
    waiting: ArrayVec<u16, REQUESTS>,
    ticks_per_ms: u64,
}

impl Ahci {
    pub fn new(id: u32, cfg: &BlkdConfig, ticks_per_sec: u64) -> Self {
        let regs = Mmio(cfg.bar0.va as usize);
        regs.w32(GHC, 1 << 31);
        let enabled = regs.r32(GHC);
        let cap = regs.r32(CAP);
        l4h_rt::info!("ahci {:#x}: CAP {:#x} CAP2 {:#x} GHC {:#x} PI {:#x}",
            id, cap, regs.r32(0x24), enabled, regs.r32(PI));
        assert!(cap & (1 << 31) != 0, "ahci: controller needs 64-bit DMA");
        let ticks_per_ms = (ticks_per_sec / 1000).max(1);
        let mut dma = Dma::new(cfg.dma_va as usize, cfg.dma_paddr, cfg.dma_size as usize);
        let identify_buf = dma.alloc(512, 512);
        let mut a = Self { id, regs, ports: ArrayVec::new(), requests: REQUEST_STORAGE.take(), waiting: ArrayVec::new(), ticks_per_ms };
        let implemented = regs.r32(PI);
        let count = ((cap & 31) + 1) as usize;
        assert!(0x100 + count * 0x80 <= cfg.bar0.len as usize, "ahci: port registers beyond BAR5");
        let slots = (((cap >> 8) & 31) + 1) as usize;
        for p in 0..count {
            if implemented & (1 << p) == 0 || a.ports.is_full() { continue; }
            let port_regs = Mmio(regs.0 + 0x100 + 0x80 * p);
            if let Some(mut port) = Port::new(p, port_regs, &mut dma, ticks_per_ms) {
                if port.identify(identify_buf, ticks_per_ms, slots, cap & (1 << 30) != 0) {
                    l4h_rt::info!("ahci {:#x}: SATA port {}, {} sectors, {}-byte blocks, depth {}", id, p,
                        port.info.sectors, port.info.block_size, port.info.depth);
                    a.ports.must_push(port);
                }
            }
        }
        regs.w32(IS, u32::MAX);
        regs.w32(GHC, (1 << 31) | 2);
        a
    }

    fn complete(&mut self, index: usize, status: u32, done: &mut dyn FnMut(u64, u32)) {
        if let Some(r) = self.requests[index].take() { done(r.tag, status); }
    }

    /// Stop both port engines before completing failed requests. A port stays
    /// failed until reboot; a stop timeout faults into root's quarantine path.
    fn fail_port(&mut self, unit: usize, status: u32, done: &mut dyn FnMut(u64, u32)) {
        let p = &mut self.ports[unit];
        p.regs.w32(IE, 0);
        assert!(stop(p.number, p.regs, self.ticks_per_ms), "ahci: failed port {} did not stop", p.number);
        l4h_rt::info!("ahci {:#x}: port {} stopped after error {:#x}", self.id, p.number, status);
        p.regs.w32(SERR, u32::MAX);
        p.ack_interrupt(self.regs, u32::MAX);
        p.failed = true;
        p.active = 0;
        p.requests = [EMPTY; SLOTS];
        for i in 0..REQUESTS {
            if self.requests[i].as_ref().is_some_and(|r| r.unit == unit) { self.complete(i, blk::STATUS_IOERR, done); }
        }
        self.waiting.retain(|&i| self.requests[i as usize].is_some());
    }
}

impl Driver for Ahci {
    fn units(&self) -> usize { self.ports.len() }

    fn info(&self, unit: usize) -> DevInfo {
        let p = &self.ports[unit];
        DevInfo { capacity: p.info.sectors, block_size: p.info.block_size, read_only: false,
            flush: p.info.flush_command != 0, address: p.number as u64, seg_max: MAX_PIECES }
    }

    fn can_start(&self) -> bool { self.requests.iter().any(Option::is_none) }

    fn start(&mut self, tag: u64, unit: usize, op: u32, sector: u64, data: &[Seg]) -> Result<(), u32> {
        let p = self.ports.get(unit).ok_or(blk::STATUS_IOERR)?;
        if p.failed { return Err(blk::STATUS_IOERR); }
        if !matches!(op, blk::OP_READ | blk::OP_WRITE | blk::OP_FLUSH) { return Err(blk::STATUS_UNSUPP); }
        let bytes: u64 = data.iter().map(|s| s.len as u64).sum();
        if op == blk::OP_FLUSH {
            if !data.is_empty() || p.info.flush_command == 0 { return Err(blk::STATUS_UNSUPP); }
        } else if data.is_empty() || data.len() > MAX_PIECES || bytes == 0 || bytes > MAX_REQUEST
            || bytes % p.info.block_size as u64 != 0 || sector % (p.info.block_size as u64 / 512) != 0
            || sector.checked_add(bytes / 512).is_none_or(|end| end > p.info.sectors)
            || data.iter().any(|s| s.len == 0 || s.len & 1 != 0 || s.pa & 1 != 0 || s.pa.checked_add(s.len as u64).is_none()) {
            return Err(blk::STATUS_IOERR);
        }
        let index = self.requests.iter().position(Option::is_none).ok_or(blk::STATUS_IOERR)?;
        let mut pieces = ArrayVec::new();
        for &s in data { pieces.must_push(s); }
        self.requests[index] = Some(Request { tag, unit, op, sector, data: pieces });
        self.waiting.must_push(index as u16);
        Ok(())
    }

    fn kick(&mut self) {
        let mut blocked = 0u32;
        let mut at = 0;
        while at < self.waiting.len() {
            let index = self.waiting[at] as usize;
            let request = self.requests[index].as_ref().unwrap();
            let port = &mut self.ports[request.unit];
            if blocked & (1 << request.unit) != 0 || !port.room(request.op) {
                blocked |= 1 << request.unit;
                at += 1;
            } else {
                port.issue(index as u16, request);
                self.waiting.remove(at);
            }
        }
    }

    fn reap(&mut self, done: &mut dyn FnMut(u64, u32)) {
        for u in 0..self.ports.len() {
            if self.ports[u].failed { continue; }
            let is = self.ports[u].regs.r32(PXIS);
            // AHCI 1.3.1 §5.5.3: acknowledge both interrupt tiers before
            // reading completion state, so a later completion stays pending.
            self.ports[u].ack_interrupt(self.regs, is);
            if is & PORT_ERRORS != 0 {
                self.fail_port(u, is, done);
                continue;
            }
            let p = &mut self.ports[u];
            let still = p.regs.r32(CI) | p.regs.r32(SACT);
            let completed = p.active & !still;
            dma_fence(Ordering::Acquire);
            let mut finished = ArrayVec::<u16, SLOTS>::new();
            for slot in 0..SLOTS {
                if completed & (1 << slot) != 0 {
                    finished.must_push(core::mem::replace(&mut p.requests[slot], EMPTY));
                }
            }
            p.active &= !completed;
            if p.active == 0 { p.exclusive = false; }
            for &index in &finished { self.complete(index as usize, blk::STATUS_OK, done); }
        }
        // A port may have gained command slots without a new client kick.
        self.kick();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{boxed::Box, vec, vec::Vec};

    fn fake() -> Ahci {
        let memory = Box::leak(vec![0u64; 0x40000 / 8].into_boxed_slice());
        let regs = Mmio(memory.as_mut_ptr() as usize);
        let mut dma = Dma::new(regs.0 + 0x2000, 0x1_0000_2000, 0x30000);
        let mut ports = ArrayVec::new();
        crate::mmio_test::register(regs.0 + IS, crate::mmio_test::Kind::Clear);
        for number in [0, 3] {
            let headers = dma.alloc(1024, 1024);
            let tables = dma.alloc(TABLE_BYTES * SLOTS, 128);
            let port = Mmio(regs.0 + 0x100 + number * 0x80);
            for offset in [CI, SACT] { crate::mmio_test::register(port.0 + offset, crate::mmio_test::Kind::Set); }
            crate::mmio_test::register(port.0 + PXIS, crate::mmio_test::Kind::Clear);
            ports.must_push(Port { number, regs: port, headers, tables,
                info: Identify { sectors: 1 << 30, block_size: 512, depth: 2, flush_command: 0xea },
                ncq: true, active: 0, requests: [EMPTY; SLOTS], exclusive: false, failed: false });
        }
        Ahci { id: 0, regs, ports, requests: Box::leak(Box::new([const { None }; REQUESTS])),
            waiting: ArrayVec::new(), ticks_per_ms: 1 }
    }

    fn data() -> [Seg; 1] { [Seg { pa: 0x2_1234_0000, len: 4096 }] }

    fn finish(a: &mut Ahci, unit: usize, done: &mut Vec<(u64, u32)>) {
        crate::mmio_test::change(a.ports[unit].regs.0 + CI, u32::MAX, 0);
        crate::mmio_test::change(a.ports[unit].regs.0 + SACT, u32::MAX, 0);
        a.reap(&mut |t, s| done.push((t, s)));
    }

    #[test]
    fn reset_clears_link_events_before_waiting_for_the_initial_device_fis() {
        let a = fake();
        let regs = a.ports[0].regs;
        crate::mmio_test::register(regs.0 + SERR, crate::mmio_test::Kind::Clear);
        // A PCH-style reset establishes PHY before posting its initial FIS.
        // The pending COMINIT event must be cleared to let reception finish.
        crate::mmio_test::after_write(regs.0 + SCTL, 0x301, regs.0 + TFD, u32::MAX, 0x80);
        crate::mmio_test::after_write(regs.0 + SCTL, 0x300, regs.0 + SSTS, u32::MAX, 0x133);
        crate::mmio_test::after_write(regs.0 + SCTL, 0x300, regs.0 + SERR, 0, 0x4050000);
        crate::mmio_test::after_write(regs.0 + SERR, u32::MAX, regs.0 + TFD, u32::MAX, 0x150);
        crate::mmio_test::after_write(regs.0 + SERR, u32::MAX, regs.0 + SIG, u32::MAX, 0x101);
        assert!(reset_link(regs, 10_000));
        assert_eq!(regs.r32(SERR), 0);
        assert_eq!(regs.r32(TFD), 0x150);
        assert_eq!(regs.r32(SIG), 0x101);
    }

    #[test]
    fn issuing_a_new_slot_cannot_reassert_a_concurrently_completed_slot() {
        let mut a = fake();
        let registers = a.ports[0].regs.0;
        crate::mmio_test::writes();
        a.start(1, 0, blk::OP_READ, 0, &data()).unwrap();
        a.kick();
        // The HBA clears slot 0 after any software read but before the next
        // doorbell write. A stale RMW would set that completed slot again.
        crate::mmio_test::before_write(registers + SACT, 1);
        crate::mmio_test::before_write(registers + CI, 1);
        a.start(2, 0, blk::OP_READ, 8, &data()).unwrap();
        a.kick();
        assert_eq!(crate::mmio_test::writes(), [(registers + SACT, 1), (registers + CI, 1),
            (registers + SACT, 2), (registers + CI, 2)]);
        let mut done = Vec::new();
        a.reap(&mut |t, s| done.push((t, s)));
        assert_eq!(done, [(1, blk::STATUS_OK)]);
        finish(&mut a, 0, &mut done);
        assert_eq!(done, [(1, blk::STATUS_OK), (2, blk::STATUS_OK)]);
    }

    #[test]
    fn a_completion_after_the_snapshot_keeps_its_new_interrupt_pending() {
        let mut a = fake();
        a.start(1, 0, blk::OP_READ, 0, &data()).unwrap();
        a.start(2, 0, blk::OP_READ, 8, &data()).unwrap();
        a.kick();
        let registers = a.ports[0].regs.0;
        crate::mmio_test::change(registers + CI, u32::MAX, 0);
        crate::mmio_test::change(registers + SACT, 1, 0);
        crate::mmio_test::change(registers + PXIS, 0, 8);
        crate::mmio_test::change(a.regs.0 + IS, 0, 1);
        // Slot 1 completes immediately after the driver reads its old active
        // bit. Its SDB interrupt must remain for the next service round.
        crate::mmio_test::after_read(registers + SACT, registers + SACT, 2, 0);
        crate::mmio_test::after_read(registers + SACT, registers + PXIS, 0, 8);
        crate::mmio_test::after_read(registers + SACT, a.regs.0 + IS, 0, 1);
        let mut done = Vec::new();
        a.reap(&mut |t, s| done.push((t, s)));
        assert_eq!(done, [(1, blk::STATUS_OK)]);
        assert_eq!(a.ports[0].regs.r32(PXIS), 8);
        assert_eq!(a.regs.r32(IS), 1);
        a.reap(&mut |t, s| done.push((t, s)));
        assert_eq!(done, [(1, blk::STATUS_OK), (2, blk::STATUS_OK)]);
    }

    #[test]
    fn flush_orders_its_disk_without_blocking_the_other_disk() {
        let mut a = fake();
        let mut done = Vec::new();
        a.start(1, 0, blk::OP_READ, 0, &data()).unwrap();
        a.start(2, 0, blk::OP_FLUSH, 0, &[]).unwrap();
        a.start(3, 0, blk::OP_WRITE, 8, &data()).unwrap();
        a.start(4, 1, blk::OP_WRITE, 0, &data()).unwrap();
        a.kick();
        assert_eq!(a.waiting.len(), 2);
        finish(&mut a, 1, &mut done);
        assert_eq!(done, [(4, blk::STATUS_OK)]);
        assert!(!a.ports[0].exclusive);
        finish(&mut a, 0, &mut done);
        assert_eq!(Mmio(a.ports[0].tables.0).r8(2), 0xea);
        assert!(a.ports[0].exclusive);
        a.start(5, 1, blk::OP_READ, 16, &data()).unwrap();
        a.kick();
        assert_ne!(a.ports[1].active, 0);
        finish(&mut a, 1, &mut done);
        assert_eq!(done.last(), Some(&(5, blk::STATUS_OK)));
        assert_eq!(a.waiting.len(), 1);
        finish(&mut a, 0, &mut done);
        assert_eq!(Mmio(a.ports[0].tables.0).r8(2), 0x61);
        assert_eq!(a.waiting.len(), 0);
        finish(&mut a, 0, &mut done);
        assert_eq!(done, [(4, 0), (1, 0), (5, 0), (2, 0), (3, 0)]);
        assert_eq!(a.info(1).address, 3);
    }

    #[test]
    fn queued_request_owns_its_dma_segments_and_uses_64_bit_addresses() {
        let mut a = fake();
        let original = data()[0];
        let mut borrowed = vec![original];
        a.start(11, 0, blk::OP_WRITE, 0x12345678, &borrowed).unwrap();
        borrowed[0].pa = 0;
        borrowed.clear();
        drop(borrowed);
        a.kick();
        let table = Mmio(a.ports[0].tables.0);
        assert_eq!(table.r64(128), original.pa);
        assert_eq!(table.r32(140) & 0x3f_ffff, original.len - 1);
        assert_eq!(table.r8(2), 0x61);
        assert_eq!([table.r8(4), table.r8(5), table.r8(6), table.r8(8)], [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(table.r8(3), 8);
        let mut done = Vec::new();
        finish(&mut a, 0, &mut done);
        assert_eq!(done, [(11, blk::STATUS_OK)]);
    }

    #[test]
    fn a_dma_segment_crossing_four_gib_becomes_two_prds() {
        let mut a = fake();
        a.start(1, 0, blk::OP_READ, 0, &[Seg { pa: 0x1_ffff_f000, len: 8192 }]).unwrap();
        a.kick();
        let p = &a.ports[0];
        let table = Mmio(p.tables.0);
        assert_eq!(Mmio(p.headers.0).r32(0) >> 16, 2);
        assert_eq!((table.r64(128), table.r32(140)), (0x1_ffff_f000, 4095));
        assert_eq!((table.r64(144), table.r32(156)), (0x2_0000_0000, 4095));
    }

    #[test]
    fn taskfile_error_or_disconnect_returns_its_buffers_and_keeps_other_port_live() {
        for fault in [1 << 30, 1 << 22, 1 << 31, 1 << 7] {
        let mut a = fake();
        let pieces = data();
        for (tag, op) in [(1, blk::OP_READ), (2, blk::OP_FLUSH), (3, blk::OP_WRITE)] {
            a.start(tag, 0, op, 0, if op == blk::OP_FLUSH { &[] } else { &pieces }).unwrap();
        }
        a.start(4, 1, blk::OP_WRITE, 0, &data()).unwrap();
        a.kick();
        a.ports[0].regs.w32(CMD, ST | FRE);
        crate::mmio_test::change(a.ports[0].regs.0 + PXIS, 0, fault);
        // A status summary can have arrived after the first acknowledge but
        // before the port interrupt mask reached the HBA.
        crate::mmio_test::after_read(a.ports[0].regs.0 + CMD, a.regs.0 + IS, 0, 1);
        let mut done = Vec::new();
        a.reap(&mut |t, s| done.push((t, s)));
        assert_eq!(done, [(1, blk::STATUS_IOERR), (2, blk::STATUS_IOERR), (3, blk::STATUS_IOERR)]);
        assert_eq!(a.ports[0].regs.r32(CMD) & (ST | FRE), 0);
        assert_eq!(a.regs.r32(IS), 0);
        assert_eq!(a.start(5, 0, blk::OP_WRITE, 0, &data()), Err(blk::STATUS_IOERR));
        assert_ne!(a.ports[1].active, 0);
        finish(&mut a, 1, &mut done);
        assert_eq!(done.last(), Some(&(4, blk::STATUS_OK)));
        }
    }

    #[test]
    fn a_read_overflow_cannot_be_reported_as_a_successful_read() {
        let mut a = fake();
        a.start(1, 0, blk::OP_READ, 0, &data()).unwrap();
        a.start(2, 0, blk::OP_FLUSH, 0, &[]).unwrap();
        a.start(3, 1, blk::OP_READ, 0, &data()).unwrap();
        a.kick();
        let port = a.ports[0].regs;
        port.w32(CMD, POWER | ST | FRE);
        // The HBA has finished a read but received more bytes than its PRDT.
        // Cleared slot bits alone must not turn this into a successful read.
        crate::mmio_test::change(port.0 + CI, u32::MAX, 0);
        crate::mmio_test::change(port.0 + SACT, u32::MAX, 0);
        crate::mmio_test::change(port.0 + PXIS, 0, 1 << 24);
        let mut done = Vec::new();
        let mut engine_states = Vec::new();
        a.reap(&mut |tag, status| {
            engine_states.push(port.r32(CMD) & (ST | FRE));
            done.push((tag, status));
        });
        assert_eq!(done, [(1, blk::STATUS_IOERR), (2, blk::STATUS_IOERR)]);
        assert!(engine_states.iter().all(|&state| state == 0));
        assert_ne!(a.ports[1].active, 0);
        finish(&mut a, 1, &mut done);
        assert_eq!(done.last(), Some(&(3, blk::STATUS_OK)));
    }

    #[test]
    fn an_engine_that_cannot_stop_never_returns_dma_buffers() {
        let mut a = fake();
        a.start(1, 0, blk::OP_WRITE, 0, &data()).unwrap();
        a.kick();
        crate::mmio_test::register(a.ports[0].regs.0 + CMD, crate::mmio_test::Kind::Control(ST | FRE | POWER));
        crate::mmio_test::change(a.ports[0].regs.0 + CMD, 0, ST | FRE | CR);
        crate::mmio_test::change(a.ports[0].regs.0 + PXIS, 0, 1 << 22);
        let mut done = Vec::new();
        let fault = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            a.reap(&mut |t, s| done.push((t, s)));
        }));
        assert!(fault.is_err());
        assert!(done.is_empty());
        assert!(a.requests.iter().any(Option::is_some));
    }

    #[test]
    fn identify_reports_4k_capacity_and_rejects_an_unflushable_write_cache() {
        let mut id = [0u16; 256];
        id[49] = 1 << 8;
        id[83] = 0x4400 | (1 << 13);
        id[82] = 1 << 5;
        id[85] = 1 << 5;
        id[87] = 0x4000;
        id[76] = 1 << 8;
        id[75] = 31;
        id[100] = 1000;
        id[106] = 0x5000;
        id[117] = 2048;
        let disk = identify(&id, 16, true).unwrap();
        assert_eq!((disk.sectors, disk.block_size, disk.depth, disk.flush_command), (8000, 4096, 16, 0xea));
        id[83] &= !(1 << 13);
        assert!(identify(&id, 16, true).is_none());
        id[85] = 0;
        assert_eq!(identify(&id, 16, false).unwrap().flush_command, 0);
        id[87] = 0; // Enabled-feature words are not valid.
        assert!(identify(&id, 16, false).is_none());
        id[83] |= 1 << 13;
        assert_eq!(identify(&id, 16, false).unwrap().flush_command, 0xea);
        id[117] = 0;
        assert!(identify(&id, 16, true).is_none());
    }

    #[test]
    fn non_ncq_disk_serializes_commands_and_queue_has_a_fixed_bound() {
        let mut a = fake();
        a.ports[0].ncq = false;
        for i in 0..REQUESTS { a.start(i as u64, 0, blk::OP_READ, 0, &data()).unwrap(); }
        assert!(!a.can_start());
        assert!(a.start(100, 0, blk::OP_READ, 0, &data()).is_err());
        a.kick();
        assert_eq!(a.ports[0].active, 1);
        assert_eq!(a.waiting.len(), REQUESTS - 1);
        assert_eq!(Mmio(a.ports[0].tables.0).r8(2), 0x25);
        let mut done = Vec::new();
        for _ in 0..REQUESTS { finish(&mut a, 0, &mut done); }
        assert_eq!(done.len(), REQUESTS);
        assert!(a.can_start());
    }
}
