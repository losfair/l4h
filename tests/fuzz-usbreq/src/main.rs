//! Feed usbd's guest-facing code (host/l4h-host/src/usb.rs, through the
//! l4h-host crate) with what a hostile guest can write: random transfer
//! records, aimed inside, at the edges of and outside a pool placed at
//! random guest-physical addresses (0 and the top of the address space
//! included), random endpoint shapes, queue indices and port features.
//!
//! It must never panic or overflow, and whatever it accepts must be
//! confined: every data pointer a TRB carries lies, with its length, in
//! the pool's physical range and within one 64 KiB page; a URB never takes
//! more than MAX_URB_TRBS; its TD ends are in order; the data TRBs add up
//! to the transfer's length; setup packets travel as immediate data; and
//! a PORTSC write touches only the bits a feature names.
//!
//! Usage: fuzz-usbreq [iterations]

#![allow(dead_code)]

use l4h_host::usb;

use l4h_abi::usb as abi;
use usb::*;

/// xorshift64*
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, n: u64) -> bool {
        self.below(n) == 0
    }
}

fn pool(rng: &mut Rng) -> Pool {
    let size = 1u64 << (20 + rng.below(9));
    let gpa = match rng.below(8) {
        0 => 0,
        1 => 0u64.wrapping_sub(size),
        _ => (1 + rng.below(1 << 14)) << 21,
    };
    // Physical addresses anywhere a 52-bit machine has them, page aligned.
    let paddr = (rng.below(1 << 40) << 12) & !(size - 1);
    Pool { gpa, paddr, size }
}

fn addr(rng: &mut Rng, p: &Pool) -> u64 {
    match rng.below(8) {
        0 => rng.next(),
        1 => p.gpa.wrapping_sub(1 + rng.below(64)),
        2 => p.gpa.wrapping_add(p.size).wrapping_sub(rng.below(64)),
        _ => p.gpa.wrapping_add(rng.below(p.size)),
    }
}

fn len(rng: &mut Rng) -> u32 {
    match rng.below(6) {
        0 => rng.next() as u32,
        1 => 0,
        2 => 1 + rng.below(64) as u32,
        3 => 1 << rng.below(20),
        _ => 1 + rng.below(256 << 10) as u32,
    }
}

fn record(rng: &mut Rng, p: &Pool) -> abi::XferReq {
    let mut r: abi::XferReq = unsafe { std::mem::zeroed() };
    if rng.chance(16) {
        // Garbage everywhere.
        let bytes = unsafe { std::slice::from_raw_parts_mut(&mut r as *mut _ as *mut u8, std::mem::size_of::<abi::XferReq>()) };
        bytes.iter_mut().for_each(|b| *b = rng.next() as u8);
        return r;
    }
    r.tag = rng.next() as u32;
    r.slot = rng.below(70) as u16;
    r.ty = if rng.chance(16) { rng.next() as u8 } else { rng.below(4) as u8 };
    r.dci = if r.ty == abi::XFER_CONTROL && !rng.chance(8) { 1 } else { rng.below(34) as u8 };
    r.flags = if rng.chance(16) { rng.next() as u32 } else { rng.below(16) as u32 };
    r.stream = rng.below(20) as u32;
    r.start_frame = rng.next() as u32;
    let n = match rng.below(16) {
        0 => rng.next() as u16,
        1..=4 => rng.below(abi::MAX_SEGS as u64 + 1) as u16,
        _ => rng.below(5) as u16,
    };
    r.n_segs = n;
    let mut total = 0u32;
    for s in r.segs.iter_mut().take((n as usize).min(abi::MAX_SEGS)) {
        *s = abi::Seg { gpa: addr(rng, p), len: len(rng), reserved: 0 };
        total = total.wrapping_add(s.len);
    }
    r.length = if rng.chance(8) { rng.next() as u32 } else { total };
    r.setup = (rng.next()).to_le_bytes();
    if rng.chance(2) {
        r.setup[6..8].copy_from_slice(&(r.length.min(0xffff) as u16).to_le_bytes());
        r.setup[0] = (r.setup[0] & 0x7f) | if r.flags & abi::XF_IN != 0 { 0x80 } else { 0 };
    }
    if r.ty == abi::XFER_ISOC || rng.chance(16) {
        let k = if rng.chance(16) { rng.next() as u16 } else { rng.below(abi::MAX_ISO as u64 + 1) as u16 };
        r.n_iso = k;
        let per = r.length / (k.max(1) as u32);
        for (i, p) in r.iso.iter_mut().take((k as usize).min(abi::MAX_ISO)).enumerate() {
            *p = if rng.chance(8) {
                abi::Iso { offset: rng.next() as u32, len: rng.next() as u32 }
            } else {
                abi::Iso { offset: per.wrapping_mul(i as u32), len: per }
            };
        }
    }
    r
}

fn shape(rng: &mut Rng) -> EpShape {
    EpShape {
        max_packet: match rng.below(4) { 0 => 0, 1 => rng.below(1 << 12) as u32, _ => 8 << rng.below(8) },
        burst: rng.below(17) as u32,
        mult: rng.below(4) as u32,
        hci_1_0: rng.chance(2),
        full_speed: rng.chance(2),
        period: 1 << rng.below(16),
        mfindex: rng.below(1 << 14) as u32,
        ist: rng.below(16) as u32,
        cfc: rng.chance(2),
    }
}

/// Every pointer `x`'s TRBs carry, checked against the pool.
fn check_trbs(x: &Xfer, p: &Pool, t: &[Trb], ends: &[u16]) {
    assert!(t.len() <= MAX_URB_TRBS);
    let mut data = 0u64;
    for trb in t {
        match trb.ty() {
            TRB_SETUP => {
                assert_eq!(trb.control & TRB_IDT, TRB_IDT, "setup without immediate data");
                assert_eq!(trb.len(), 8);
            }
            TRB_NORMAL | TRB_DATA | TRB_ISOCH => {
                let n = trb.len() as u64;
                if n > 0 {
                    assert!(trb.param >= p.paddr && trb.param + n <= p.paddr + p.size, "TRB {:#x}+{:#x} outside the pool {:#x}+{:#x}", trb.param, n, p.paddr, p.size);
                    assert_eq!(trb.param >> 16, (trb.param + n - 1) >> 16, "TRB crosses 64 KiB");
                }
                assert_eq!(trb.control & TRB_IDT, 0, "data TRB with immediate data");
                data += n;
            }
            TRB_STATUS => assert_eq!(trb.len(), 0),
            other => panic!("TRB type {other} in a transfer"),
        }
        assert_eq!(trb.control & TRB_CYCLE, 0, "cycle bits are the ring's");
    }
    if x.ty != abi::XFER_ISOC {
        assert_eq!(data, x.length as u64, "data TRBs do not add up");
        // Bulk or interrupt: a zero-length packet after the data is a TD
        // of its own.
        let zlp = ends.len() == 2 && x.ty != abi::XFER_CONTROL && x.flags & abi::XF_ZERO_PACKET != 0 && t[t.len() - 1].len() == 0;
        assert!(ends.len() == 1 || zlp);
        if zlp {
            assert_eq!(ends[0] as usize, t.len() - 2);
            assert_eq!(t[ends[0] as usize].control & (TRB_CH | TRB_IOC), 0, "data TD before the ZLP chained or with IOC");
        }
    } else {
        assert_eq!(data, x.iso.iter().map(|&(_, l)| l as u64).sum::<u64>());
        assert_eq!(ends.len(), x.iso.len());
    }
    assert!(ends.windows(2).all(|w| w[0] < w[1]), "TD ends out of order");
    assert_eq!(*ends.last().unwrap() as usize, t.len() - 1);
    for &e in &ends[ends.len() - 1..] {
        assert_eq!(t[e as usize].control & (TRB_CH | TRB_IOC), TRB_IOC, "TD end chained or without IOC");
    }
    for &e in ends.iter().take(ends.len() - 1).filter(|_| x.ty == abi::XFER_ISOC) {
        assert_eq!(t[e as usize].control & (TRB_CH | TRB_IOC), TRB_IOC, "TD end chained or without IOC");
    }
}

fn indices(rng: &mut Rng) {
    let tail = rng.next() as u32;
    let size = [32u32, 64, 128, 256][rng.below(4) as usize];
    let head = tail.wrapping_add(match rng.below(4) { 0 => rng.next() as u32, _ => rng.below(2 * size as u64) as u32 });
    let sq = Sq { tail, size };
    match sq.avail(head) {
        Some(n) => assert!(n <= size && tail.wrapping_add(n) == head),
        None => assert!(head.wrapping_sub(tail) > size),
    }
    let cq = Cq { head: tail, size };
    match cq.room(head) {
        Some(r) => assert!(r <= size),
        None => assert!(tail.wrapping_sub(head) > size),
    }
}

fn ports(rng: &mut Rng) {
    let (set, f, v, usb3) = (rng.chance(2), rng.below(10) as u32, rng.next() as u32 >> rng.below(32), rng.chance(2));
    if let Some(bits) = portsc_write(set, f, v, usb3) {
        let cur = rng.next() as u32;
        let w = portsc_value(cur, set, f, bits);
        // Nothing but the named bits and the preserved ones.
        assert_eq!(w & !(bits | PORTSC_PRESERVE), 0);
        // A write that sets no change bit clears none: change bits only
        // when they were named.
        assert_eq!(w & (0x7f << 17) & !bits, 0);
    }
}

fn main() {
    let iters: u64 = std::env::args().nth(1).map_or(200_000, |a| a.parse().expect("iterations"));
    let mut rng = Rng(0x5eed_0f05_bd17_u64);
    let (mut accepted, mut laid_out) = (0u64, 0u64);
    for _ in 0..iters {
        let p = pool(&mut rng);
        let r = record(&mut rng, &p);
        let max = [MAX_TRANSFER, (p.size / 4) as u32, rng.next() as u32][rng.below(3) as usize];
        if let Ok(x) = check_xfer(&r, &p, max) {
            accepted += 1;
            assert!(x.length <= max);
            for &(pa, n) in x.segs.iter() {
                assert!(pa >= p.paddr && pa + n as u64 <= p.paddr + p.size, "segment outside the pool");
            }
            for &(off, n) in x.iso.iter() {
                assert!(off as u64 + n as u64 <= x.length as u64);
            }
            for _ in 0..4 {
                let (mut t, mut e) = (Trbs::new(), TdEnds::new());
                if build_trbs(&x, &shape(&mut rng), &mut t, &mut e).is_ok() {
                    laid_out += 1;
                    check_trbs(&x, &p, &t, &e);
                }
            }
        }
        let ep = abi::Ep {
            dci: rng.below(40) as u8, ty: rng.below(9) as u8, interval: rng.below(20) as u8,
            burst_mult: rng.next() as u8, max_packet: rng.next() as u16, max_esit: rng.next() as u16,
        };
        if ep_ok(&ep, rng.below(7) as u32) {
            assert!((2..=31).contains(&ep.dci) && ep.interval <= 15 && ep.max_packet <= 1024);
        }
        let route = rng.next() as u32 >> rng.below(32);
        if route_ok(route) {
            assert!(route < 1 << 20);
        }
        indices(&mut rng);
        ports(&mut rng);
    }
    println!("fuzz-usbreq: {iters} records, {accepted} accepted, {laid_out} laid out: ok");
}
