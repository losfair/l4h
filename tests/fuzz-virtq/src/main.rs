//! Feed l4h-vmm's virtqueue code (host/l4h-vmm/src/virtq.rs and mem.rs,
//! compiled here unchanged) with random guest memory: queue setup, avail
//! rings and descriptor tables are all garbage, and addresses point
//! inside, at the edges of, just outside and far outside the guest's I/O
//! pool (which is all the VMM maps).  It must never touch memory outside
//! the pool, accept a buffer outside it, panic or loop forever.  Also
//! checks blk-mux's pool check (host/l4h-host/src/blk.rs, Pool), feeds
//! netd's offload code (host/l4h-netd/src/offload.rs) random virtio-net
//! headers and checks its TCP segmentation, and checks that a virtio-blk
//! reset waits for every request blkd has (host/l4h-vmm/src/blk.rs),
//! whatever the guest puts in the avail ring, and that no request with a
//! buffer outside the pool reaches blkd.

#![allow(dead_code)]

extern crate alloc;

#[path = "../../../host/l4h-vmm/src/mem.rs"]
mod mem;

/// virtq.rs uses crate::guest::GuestMem: the production one, over a
/// buffer here.
mod guest {
    pub use crate::mem::GuestMem;
}

#[path = "../../../host/l4h-vmm/src/virtq.rs"]
mod virtq;

/// The fixed-capacity containers virtq.rs and blk.rs use (as
/// l4h_rt::host::fixed).
#[path = "../../../host/l4h-host/src/fixed.rs"]
pub mod host_fixed;

#[path = "../../../host/l4h-netd/src/offload.rs"]
mod offload;

// l4h-vmm's virtio-blk backend (blk.rs), unchanged, over mocks of what it
// uses from l4h_rt and the device model; blkcheck.rs plays blkd.
extern crate self as l4h_rt;

#[path = "../../../host/l4h-host/src/blk.rs"]
pub mod host_blk;
/// What blk.rs uses from l4h_host's root.
#[path = "../../../host/l4h-host/src/handoff.rs"]
pub mod handoff;
pub const SHARED_VA: usize = 0x2000_0000_0000;
pub mod host {
    pub use crate::host_blk as blk;
    pub use crate::host_fixed as fixed;
}

pub mod sel4 {
    /// blk.rs yields while it waits for blkd: blkd runs then.
    pub fn r#yield() {
        crate::blkcheck::blkd_run();
    }
    pub mod cap {
        pub struct Notification;
        impl Notification {
            pub fn signal(&self) {}
        }
    }
}

/// The part of host/l4h-vmm/src/dev.rs that blk.rs uses.
mod dev {
    use crate::guest::GuestMem;
    use crate::virtq::Queue;
    pub const VIRTIO_RING_F_INDIRECT_DESC: u64 = 1 << 28;
    pub trait Backend {
        fn device_id(&self) -> u32;
        fn features(&self) -> u64;
        fn num_queues(&self) -> usize;
        fn queue_max(&self, q: usize) -> u32;
        fn init_config(&self, config: &mut [u8]);
        fn kick(&mut self, mem: &GuestMem, queues: &mut [Queue], q: usize) -> bool;
        fn complete(&mut self, mem: &GuestMem, queues: &mut [Queue]) -> bool;
        fn pending(&self) -> bool;
        fn drain(&mut self) {}
        fn reset(&mut self);
        fn features_accepted(&mut self, _features: u64) {}
    }
}

#[path = "../../../host/l4h-vmm/src/blk.rs"]
mod blk;

mod blkcheck;

use guest::GuestMem;

/// The longest chain a queue of 256 entries (the largest here) carries.
type Chain = host_fixed::ArrayVec<virtq::Buf, 256>;

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
}

/// Is guest-physical [a, a + n) inside the pool [gpa, gpa + size)?  An
/// independent check of GuestMem::valid and Pool::translate.
fn inside(gpa: u64, size: u64, a: u64, n: u64) -> bool {
    a >= gpa && (a - gpa) as u128 + n as u128 <= size as u128
}

/// Where a fuzzed pool sits: above some RAM, at guest-physical 0, or at the
/// very top of the address space (so that address arithmetic overflows).
fn pool_gpa(rng: &mut Rng, size: u64) -> u64 {
    match rng.below(8) {
        0 => 0,
        1 => 0u64.wrapping_sub(size),
        _ => (1 + rng.below(1 << 14)) << 21,
    }
}

/// An address a hostile guest might use: mostly in the pool, often at or
/// just past its edges, sometimes anywhere (guest RAM, garbage).
fn guest_addr(rng: &mut Rng, gpa: u64, size: u64) -> u64 {
    match rng.below(8) {
        0 => rng.next(),
        1 => gpa.wrapping_sub(1 + rng.below(64)),
        2 => gpa.wrapping_add(size).wrapping_sub(rng.below(64)),
        _ => gpa.wrapping_add(rng.below(size)),
    }
}

fn main() {
    let iterations: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let size = 64 * 1024u64;
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let (mut chains, mut refused) = (0u64, 0u64);
    let mut bufs = Chain::new();
    for _ in 0..iterations {
        let mut pool: Vec<u64> = (0..size / 8).map(|_| rng.next()).collect();
        let gpa = pool_gpa(&mut rng, size);
        let mem = GuestMem { base: pool.as_mut_ptr() as usize, gpa, size };
        // Mostly plausible queue layouts, sometimes wild ones.
        let num = 1u32 << rng.below(9);
        // Mostly aligned as required, sometimes not (setup must refuse).
        let align = |rng: &mut Rng, v: u64, a: u64| if rng.below(8) == 0 { v } else { v & !(a - 1) };
        let (desc, avail, used) = (guest_addr(&mut rng, gpa, size), guest_addr(&mut rng, gpa, size), guest_addr(&mut rng, gpa, size));
        let (desc, avail, used) = (align(&mut rng, desc, 16), align(&mut rng, avail, 2), align(&mut rng, used, 4));
        let n = num as u64;
        let rings_inside = inside(gpa, size, desc, 16 * n) && inside(gpa, size, avail, 6 + 2 * n) && inside(gpa, size, used, 6 + 8 * n);
        let aligned = desc % 16 == 0 && avail % 2 == 0 && used % 4 == 0;
        let mut q = virtq::Queue::default();
        let ok = q.setup(&mem, num, 256, desc, avail, used);
        assert_eq!(ok, rings_inside && aligned && num <= 256, "queue setup: rings {desc:#x} {avail:#x} {used:#x}, pool {gpa:#x}");
        if !ok {
            continue;
        }
        // Make chains mostly local so that they are followed for a while.
        for i in 0..n {
            if rng.below(8) != 0 {
                let d = desc + 16 * i;
                let indirect = if rng.below(8) == 0 { virtq::VIRTQ_DESC_F_INDIRECT } else { 0 };
                mem.write::<u16>(d + 12, rng.below(4) as u16 | indirect);
                mem.write::<u16>(d + 14, rng.below(n + 2) as u16);
                mem.write::<u32>(d + 8, rng.below(4096) as u32);
                let a = if rng.below(2) == 0 { gpa + rng.below(size) } else { guest_addr(&mut rng, gpa, size) };
                mem.write::<u64>(d, a);
            }
        }
        // Mostly valid chain heads in the avail ring.
        for i in 0..n {
            if rng.below(8) != 0 {
                mem.write::<u16>(avail + 4 + 2 * i, rng.below(n) as u16);
            }
        }
        for _ in 0..rng.below(2 * n) {
            let Some(head) = q.pop(&mem) else { break };
            if q.chain(&mem, head, &mut bufs).is_err() {
                refused += 1;
            } else {
                assert!(bufs.len() <= num as usize, "chain longer than the queue");
            }
            for b in &bufs {
                assert!(inside(gpa, size, b.gpa, b.len as u64), "chain buffer outside the I/O pool");
            }
            chains += 1;
            q.push(&mem, head, rng.below(1 << 16) as u32);
            let _ = q.wants_interrupt(&mem);
        }
    }
    println!("fuzz-virtq: {iterations} queues, {chains} chains parsed ({refused} refused), no violations");
    let edges = edge_check(&mut rng, iterations / 20);
    println!("fuzz-virtq: pool edges: {edges} chains at the edges of the I/O pool checked");
    let segs = pool_check(&mut rng, iterations * 4);
    println!("fuzz-virtq: blk-mux pool check: {} segments, {segs} accepted", iterations * 4);
    let segs = offload_check(&mut rng, iterations / 4);
    let merged = gro_check(&mut rng, iterations / 20);
    println!("fuzz-virtq: offload: {} frames, {segs} segments checked", iterations / 4);
    println!("fuzz-virtq: GRO: {} streams, {merged} merged frames segment back exactly", iterations / 20);
    let (reqs, bad) = blkcheck::drain_check(&mut rng, iterations / 20);
    println!("fuzz-virtq: blk: {} resets, {reqs} requests drained, {bad} chains outside the pool refused", iterations / 20);
}

/// Chains whose buffers or indirect tables end exactly at the end of the
/// pool are accepted; one byte further, or one byte below its start, they
/// are refused.
fn edge_check(rng: &mut Rng, n: u64) -> u64 {
    use virtq::{VIRTQ_DESC_F_INDIRECT, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    let size = 16 * 1024u64;
    let mut bufs = Chain::new();
    let mut checked = 0;
    for _ in 0..n {
        let mut pool = vec![0u64; size as usize / 8];
        let gpa = pool_gpa(rng, size);
        let mem = GuestMem { base: pool.as_mut_ptr() as usize, gpa, size };
        let mut q = virtq::Queue::default();
        // Rings in the middle of the pool, away from the buffers at its
        // edges, 8 entries.
        let (desc, avail, used) = (gpa + 0x2000, gpa + 0x2100, gpa + 0x2200);
        assert!(q.setup(&mem, 8, 8, desc, avail, used));
        let end = gpa.wrapping_add(size);
        let len = 1 + rng.below(512);
        // Buffer kinds: (address, length, valid).
        let cases = [
            (end.wrapping_sub(len), len, true),
            (end.wrapping_sub(len).wrapping_add(1), len, false),
            (gpa, len, true),
            (gpa.wrapping_sub(1), len, false),
            (end, 1, false),
            (gpa.wrapping_add(0x1000), u32::MAX as u64, false),
        ];
        for (k, &(addr, blen, valid)) in cases.iter().enumerate() {
            let expect = if rng.below(2) == 0 {
                // Descriptor 0 points at a one-entry indirect table that
                // ends at addr + blen: valid only if the table is inside.
                let table = (addr.wrapping_add(blen) & !15).wrapping_sub(16);
                let table_ok = inside(gpa, size, table, 16);
                mem.write::<u64>(desc, table);
                mem.write::<u32>(desc + 8, 16);
                mem.write::<u16>(desc + 12, VIRTQ_DESC_F_INDIRECT);
                if table_ok {
                    mem.write::<u64>(table, gpa + 0x2300);
                    mem.write::<u32>(table + 8, 64);
                    mem.write::<u16>(table + 12, VIRTQ_DESC_F_WRITE);
                }
                table_ok
            } else {
                // A header in the pool, then the buffer under test.
                mem.write::<u64>(desc, gpa + 0x2300);
                mem.write::<u32>(desc + 8, 16);
                mem.write::<u16>(desc + 12, VIRTQ_DESC_F_NEXT);
                mem.write::<u16>(desc + 14, 1);
                mem.write::<u64>(desc + 16, addr);
                mem.write::<u32>(desc + 24, blen.min(u32::MAX as u64) as u32);
                mem.write::<u16>(desc + 28, VIRTQ_DESC_F_WRITE);
                valid
            };
            mem.write::<u16>(avail + 4 + 2 * (k as u64 % 8), 0);
            mem.write::<u16>(avail + 2, k as u16 + 1);
            let head = q.pop(&mem).unwrap();
            assert_eq!(q.chain(&mem, head, &mut bufs).is_ok(), expect, "buffer {addr:#x}+{blen:#x}, pool {gpa:#x}");
            for b in &bufs {
                assert!(inside(gpa, size, b.gpa, b.len as u64));
            }
            q.push(&mem, head, 0);
            checked += 1;
        }
    }
    checked
}

/// blk-mux (blkd) accepts a segment only inside the client's pool and
/// translates it with one offset.
fn pool_check(rng: &mut Rng, n: u64) -> u64 {
    let mut accepted = 0;
    for _ in 0..n {
        let size = (1u64 << (20 + rng.below(9))).min(256 << 20);
        let gpa = pool_gpa(rng, size);
        let pool = host::blk::Pool { gpa, paddr: rng.below(1 << 40) << 12, size };
        let a = guest_addr(rng, gpa, size);
        let len = match rng.below(4) {
            0 => rng.next() as u32 as u64,
            1 => 0,
            _ => rng.below(1 << 17),
        };
        let want = len > 0 && inside(gpa, size, a, len);
        match pool.translate(a, len) {
            Some(pa) => {
                assert!(want, "blk-mux accepted {a:#x}+{len:#x} outside the pool at {gpa:#x}");
                assert_eq!(pa, pool.paddr + (a - gpa));
                accepted += 1;
            }
            None => assert!(!want, "blk-mux refused {a:#x}+{len:#x} inside the pool at {gpa:#x}"),
        }
    }
    accepted
}

fn csum(data: &[u8]) -> u32 {
    let mut s: u64 = 0;
    for c in data.chunks(2) {
        s += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u64;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u32
}

/// A TCP frame (IPv4 or IPv6, maybe VLAN-tagged) with a GSO header.
fn tcp_frame(rng: &mut Rng, v6: bool, vlan: bool, payload: usize, mss: usize) -> (Vec<u8>, [u8; 12]) {
    let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
    if vlan {
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0x05]);
    }
    if v6 {
        f.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0, 0, 0, 6, 64]);
        for _ in 0..32 {
            f.push(rng.next() as u8);
        }
    } else {
        f.extend_from_slice(&[0x08, 0x00, 0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, 6, 0, 0]);
        for _ in 0..8 {
            f.push(rng.next() as u8);
        }
    }
    let tcp = f.len();
    let seq = rng.next() as u32;
    f.extend_from_slice(&[0x1f, 0x90, 0xc3, 0x50]);
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 1, 0x50, 0x19 | 0x80, 0xff, 0xff, 0, 0, 0, 0]);
    for _ in 0..payload {
        f.push(rng.next() as u8);
    }
    let mut h = [0u8; 12];
    h[0] = offload::F_NEEDS_CSUM;
    h[1] = if v6 { offload::GSO_TCPV6 } else { offload::GSO_TCPV4 };
    h[4..6].copy_from_slice(&(mss as u16).to_le_bytes());
    h[6..8].copy_from_slice(&(tcp as u16).to_le_bytes());
    h[8..10].copy_from_slice(&16u16.to_le_bytes());
    (f, h)
}

/// netd's offload code: random headers and frames must not panic, and
/// segmentation of valid GSO frames must produce correct segments.
fn offload_check(rng: &mut Rng, n: u64) -> u64 {
    let mut buf = vec![0u8; 70000];
    let mut segs = 0u64;
    // A guest may send a VLAN tag cut short, with a checksum request
    // that sanitizes; the drivers must not read past it.
    for len in 14..18 {
        let mut frame = vec![0u8; len];
        frame[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        let mut hdr = [offload::F_NEEDS_CSUM, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(offload::sanitize(&mut hdr, &frame));
        assert!(offload::ethertype(&frame).is_none(), "truncated VLAN tag parsed");
    }
    for _ in 0..n {
        // Garbage.
        let len = rng.below(2000) as usize;
        let mut frame: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let mut hdr: [u8; 12] = core::array::from_fn(|_| rng.next() as u8);
        if offload::sanitize(&mut hdr, &frame) {
            if offload::is_gso(&hdr) {
                offload::segment(&frame, &hdr, &mut buf, |f, _| assert!(f.len() <= frame.len() + 1500));
            }
            offload::complete_csum(&mut frame, &mut hdr);
        }
        // Valid GSO frames.
        let (v6, vlan) = (rng.below(2) == 0, rng.below(4) == 0);
        let mss = 500 + rng.below(1000) as usize;
        let payload = rng.below(20000) as usize;
        let (frame, mut hdr) = tcp_frame(rng, v6, vlan, payload, mss);
        assert!(offload::sanitize(&mut hdr, &frame), "valid GSO frame refused");
        let t = offload::parse_tcp(&frame).unwrap();
        let mut got = Vec::new();
        let mut count = 0;
        offload::segment(&frame, &hdr, &mut buf, |f, h| {
            assert_eq!(h[1], offload::GSO_NONE);
            assert!(f.len() - t.hdrs <= mss);
            // TCP checksum: pseudo header + segment sums to 0xffff.
            let tcp_len = f.len() - t.tcp;
            let pseudo = if v6 { csum(&f[t.ip + 8..t.ip + 40]) } else { csum(&f[t.ip + 12..t.ip + 20]) };
            let total = pseudo + 6 + tcp_len as u32 + csum(&f[t.tcp..]);
            let mut s = total;
            while s >> 16 != 0 {
                s = (s & 0xffff) + (s >> 16);
            }
            assert_eq!(s, 0xffff, "bad TCP checksum");
            if !v6 {
                assert_eq!(csum(&f[t.ip..t.tcp]), 0xffff, "bad IPv4 header checksum");
                assert_eq!(u16::from_be_bytes([f[t.ip + 2], f[t.ip + 3]]) as usize, f.len() - t.ip);
            } else {
                assert_eq!(u16::from_be_bytes([f[t.ip + 4], f[t.ip + 5]]) as usize, tcp_len);
            }
            let seq = u32::from_be_bytes(f[t.tcp + 4..t.tcp + 8].try_into().unwrap());
            let seq0 = u32::from_be_bytes(frame[t.tcp + 4..t.tcp + 8].try_into().unwrap());
            assert_eq!(seq.wrapping_sub(seq0) as usize, got.len());
            got.extend_from_slice(&f[t.hdrs..]);
            count += 1;
        });
        assert_eq!(got, frame[t.hdrs..], "segments do not add up to the payload");
        segs += count;
    }
    segs
}

/// netd's receive offload: a stream of segments (as a TSO sender's NIC
/// would cut them) merges into GSO frames that segment back into exactly
/// the same frames; a corrupted segment passes alone and unchanged; a
/// segment of another flow ends the run.
fn gro_check(rng: &mut Rng, n: u64) -> u64 {
    let mut buf = vec![0u8; 70000];
    let mut gro = offload::Gro::new();
    let mut merged = 0u64;
    for _ in 0..n {
        let v6 = rng.below(2) == 0;
        let mss = 500 + rng.below(1000) as usize;
        let payload = 1 + rng.below(60000) as usize;
        let vlan = rng.below(4) == 0;
        let (mut frame, mut hdr) = tcp_frame(rng, v6, vlan, payload, mss);
        let t = offload::parse_tcp(&frame).unwrap();
        frame[t.tcp + 13] = if rng.below(2) == 0 { 0x10 } else { 0x18 };
        assert!(offload::sanitize(&mut hdr, &frame));
        let mut segs: Vec<Vec<u8>> = Vec::new();
        offload::segment(&frame, &hdr, &mut buf, |f, _| segs.push(f.to_vec()));
        // As received: no flags (checked here), or DATA_VALID.
        let mut rx = [0u8; 12];
        if rng.below(2) == 0 {
            rx[0] = offload::F_DATA_VALID;
        }
        let bad = if rx[0] == 0 && rng.below(4) == 0 { Some(rng.below(segs.len() as u64) as usize) } else { None };
        let mut input = segs.clone();
        if let Some(b) = bad {
            let l = input[b].len();
            input[b][l - 1] ^= 0x55;
        }
        let mut out: Vec<(Vec<u8>, [u8; 12])> = Vec::new();
        for f in &input {
            if !gro.add(f, &rx) {
                gro.flush(|f, h| out.push((f.to_vec(), *h)));
                if !gro.add(f, &rx) {
                    out.push((f.clone(), rx));
                }
            }
        }
        gro.flush(|f, h| out.push((f.to_vec(), *h)));
        // Segment what came out again: the original stream, but for the
        // corrupted frame, which must have passed unchanged.
        let mut again: Vec<Vec<u8>> = Vec::new();
        for (f, h) in &out {
            if offload::is_gso(h) {
                let mut h2 = *h;
                assert!(offload::sanitize(&mut h2, f), "merged frame does not sanitize");
                offload::segment(f, &h2, &mut buf, |s, _| again.push(s.to_vec()));
                merged += 1;
            } else {
                again.push(f.clone());
            }
        }
        assert_eq!(again.len(), segs.len());
        for (i, (a, b)) in again.iter().zip(input.iter()).enumerate() {
            assert_eq!(a, b, "segment {i} of {} differs after GRO (corrupted {:?})", segs.len(), bad);
        }
        // Another flow (other ports) does not merge into a run.
        let mut other = segs[0].clone();
        other[t.tcp] ^= 1;
        if segs.len() > 1 && bad.is_none() && rx[0] != 0 {
            assert!(gro.add(&segs[0], &rx));
            assert!(!gro.add(&other, &rx), "frames of two flows merged");
            gro.flush(|_, _| {});
        }
    }
    // The largest IPv6 segment (a payload length of 65535) is longer than
    // a run may grow: it does not start one, and passes unchanged.
    let (mut big, _) = tcp_frame(rng, true, true, 65535 - 20, 1000);
    let t = offload::parse_tcp(&big).unwrap();
    big[t.ip + 4..t.ip + 6].copy_from_slice(&65535u16.to_be_bytes());
    big[t.tcp + 13] = 0x10;
    let mut rx = [0u8; 12];
    rx[0] = offload::F_DATA_VALID;
    assert!(!gro.add(&big, &rx), "oversized IPv6 segment taken into a run");
    merged
}
