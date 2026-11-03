//! Production virtio-blk and split-ring code against a device enforcing limits.
#![allow(dead_code)]
extern crate self as l4h_rt;
pub use l4h_host as host;
use host::blk;
use std::{alloc::{alloc_zeroed, dealloc, Layout}, cell::RefCell};
use l4h_virtio::{legacy, Mmio, DESC_F_INDIRECT, DESC_F_NEXT, DESC_F_WRITE, F_INDIRECT_DESC};

#[macro_export]
macro_rules! info { ($($arg:tt)*) => {}; }
pub mod ioport {
    pub struct Ports { pub cap: u64, pub base: u16 }
    impl Ports {
        pub fn in32(&self, off: u16) -> u32 {
            super::DEVICE.with_borrow(|d| match off {
                super::legacy::DEVICE_FEATURES => d.features,
                o if o == super::legacy::DEVICE_CONFIG => 1 << 20,
                o if o == super::legacy::DEVICE_CONFIG + 8 => d.size_max,
                o if o == super::legacy::DEVICE_CONFIG + 12 => d.seg_max,
                o if o == super::legacy::DEVICE_CONFIG + 20 => d.block_size,
                _ => 0,
            })
        }
        pub fn in16(&self, off: u16) -> u16 {
            super::DEVICE.with_borrow(|d| if off == super::legacy::QUEUE_SIZE { d.num } else { 0 })
        }
        pub fn out8(&self, _: u16, _: u8) {}
        pub fn out16(&self, off: u16, _: u16) {
            if off == super::legacy::QUEUE_NOTIFY { super::DEVICE.with_borrow_mut(|d| d.kicks += 1); }
        }
        pub fn out32(&self, off: u16, value: u32) {
            super::DEVICE.with_borrow_mut(|d| match off {
                super::legacy::GUEST_FEATURES => d.negotiated = value,
                super::legacy::QUEUE_PFN => d.ring_pa = (value as u64) << 12,
                _ => {},
            });
        }
    }
}
#[derive(Default)]
struct Device {
    features: u32, negotiated: u32, num: u16, size_max: u32, seg_max: u32,
    block_size: u32, ring_pa: u64, kicks: usize,
}
thread_local! { static DEVICE: RefCell<Device> = RefCell::new(Device::default()); }
include!(env!("L4H_BLK_DRIVER_TEST_SRC"));
#[path = "../host/l4h-blkd/src/virtio.rs"]
mod virtio;

struct Memory(*mut u8, Layout);
impl Memory {
    fn new(bytes: usize) -> Self {
        let layout = Layout::from_size_align(bytes, 4096).unwrap();
        let p = unsafe { alloc_zeroed(layout) };
        assert!(!p.is_null());
        Self(p, layout)
    }
    fn va(&self) -> usize { self.0 as usize }
}
impl Drop for Memory { fn drop(&mut self) { unsafe { dealloc(self.0, self.1); } } }
struct Rig {
    driver: virtio::VirtioBlk, dma: Memory, msix: Memory, ring: usize,
    avail: u16, used: u16, num: u16, size_max: u32, seg_max: u32, block_size: u32,
}
struct Command { head: u16, op: u32, sector: u64, data: Vec<(u64, u32)>, status: usize }
impl Rig {
    fn new(size_max: u32, seg_max: u32, block_size: u32, num: u16, limits: bool) -> Self {
        let dma = Memory::new(256 << 10);
        let msix = Memory::new(4096);
        let mut cfg: blk::BlkdConfig = unsafe { core::mem::zeroed() };
        cfg.dma_va = dma.va() as u64;
        cfg.dma_paddr = 0x100000;
        cfg.dma_size = dma.1.size() as u64;
        cfg.msix_table.va = msix.va() as u64;
        cfg.legacy_io = 0xc000;
        let features = F_INDIRECT_DESC as u32 | (1 << 6) | (1 << 9) | if limits { (1 << 1) | (1 << 2) } else { 0 };
        DEVICE.set(Device { features, size_max, seg_max, block_size, num, ..Default::default() });
        let driver = virtio::VirtioBlk::new(1, &cfg);
        let ring = DEVICE.with_borrow(|d| {
            assert_eq!(d.negotiated, features, "segment limit features must be negotiated");
            dma.va() + (d.ring_pa - cfg.dma_paddr) as usize
        });
        Self { driver, dma, msix, ring, avail: 0, used: 0, num,
            size_max: if limits { size_max } else { u32::MAX },
            seg_max: if limits { seg_max } else { MAX_PIECES as u32 }, block_size }
    }
    fn va(&self, pa: u64) -> usize { self.dma.va() + (pa - 0x100000) as usize }
    fn command(&mut self) -> Option<Command> {
        let avail = Mmio(self.ring + 16 * self.num as usize);
        if self.avail == avail.r16(2) { return None; }
        let head = avail.r16(4 + 2 * (self.avail % self.num) as usize);
        self.avail = self.avail.wrapping_add(1);
        let indirect = Mmio(self.ring + 16 * head as usize);
        assert_eq!(indirect.r16(12), DESC_F_INDIRECT);
        let table = self.va(indirect.r64(0));
        let count = indirect.r32(8) / 16;
        assert!((2..=self.num as u32).contains(&count));
        assert!(count - 2 <= self.seg_max);
        let header = Mmio(self.va(Mmio(table).r64(0)));
        assert_eq!(Mmio(table).r32(8), 16);
        let op = header.r32(0);
        let mut data = Vec::new();
        for i in 0..count {
            let desc = Mmio(table + i as usize * 16);
            let last = i + 1 == count;
            assert_eq!(desc.r16(14), if last { 0 } else { i as u16 + 1 });
            let write = last || (i != 0 && op == blk::OP_READ);
            assert_eq!(desc.r16(12), if last { 0 } else { DESC_F_NEXT } | if write { DESC_F_WRITE } else { 0 });
            if i != 0 && !last {
                assert!((1..=self.size_max).contains(&desc.r32(8)), "descriptor exceeds size_max");
                data.push((desc.r64(0), desc.r32(8)));
            }
        }
        let status_desc = Mmio(table + (count as usize - 1) * 16);
        assert_eq!(status_desc.r32(8), 1);
        assert_eq!(data.iter().map(|s| s.1 as u64).sum::<u64>() % self.block_size as u64, 0);
        Some(Command { head, op, sector: header.r64(8), data, status: self.va(status_desc.r64(0)) })
    }
    fn complete(&mut self, cmd: &Command, status: u8) {
        Mmio(cmd.status).w8(0, status);
        let used = Mmio(self.ring + (16 * self.num as usize + 6 + 2 * self.num as usize).next_multiple_of(4096));
        used.w32(4 + 8 * (self.used % self.num) as usize, cmd.head as u32);
        used.w32(8 + 8 * (self.used % self.num) as usize, 0);
        self.used = self.used.wrapping_add(1);
        used.w16(2, self.used);
    }
}

#[test]
fn large_bounced_writes_obey_limits_until_one_final_completion() {
    for (size_max, seg_max, block_size, num, limits) in [(65536, 4, 512, 128, true), (4096, 1, 4096, 8, true),
        (1000, 16, 4096, 128, true), (65536, 128, 4096, 8, true), (0, 0, 512, 128, false)] {
        let mut r = Rig::new(size_max, seg_max, block_size, num, limits);
        let bytes = blk::MAX_REQUEST_BYTES as u32;
        r.driver.start(77, 0, blk::OP_WRITE, 8, &[Seg { pa: 0x20000000, len: bytes }]).unwrap();
        r.driver.kick();
        let mut transferred = 0;
        let mut done = Vec::new();
        let mut commands = 0;
        while let Some(cmd) = r.command() {
            commands += 1;
            assert_eq!(cmd.op, blk::OP_WRITE);
            assert_eq!(cmd.sector, 8 + transferred as u64 / 512);
            for &(pa, len) in &cmd.data {
                assert_eq!(pa, 0x20000000 + transferred as u64);
                transferred += len;
            }
            r.complete(&cmd, 0);
            r.driver.reap(&mut |tag, status| done.push((tag, status)));
            if transferred != bytes { assert!(done.is_empty(), "bounce memory must remain owned until all commands finish"); }
        }
        assert_eq!(transferred, bytes);
        assert_eq!(done, [(77, blk::STATUS_OK)]);
        assert_eq!(DEVICE.with_borrow(|d| d.kicks), commands, "continuations must notify legacy devices too");
        assert_eq!(commands == 1, !limits);
    }
}

#[test]
fn split_reads_preserve_scatter_addresses_and_whole_block_commands() {
    let mut r = Rig::new(1536, 5, 4096, 16, true);
    let data = [Seg { pa: 0x20000000, len: 17 }, Seg { pa: 0x30000000, len: 8192 }, Seg { pa: 0x40000000, len: 4079 }];
    r.driver.start(9, 0, blk::OP_READ, 16, &data).unwrap();
    let (mut segment, mut offset, mut transferred) = (0, 0, 0);
    let mut done = Vec::new();
    while let Some(cmd) = r.command() {
        assert_eq!(cmd.sector, 16 + transferred / 512);
        for (pa, len) in &cmd.data {
            assert_eq!(*pa, data[segment].pa + offset as u64);
            assert!(*len <= data[segment].len - offset);
            offset += len;
            transferred += *len as u64;
            if offset == data[segment].len { segment += 1; offset = 0; }
        }
        r.complete(&cmd, 0);
        r.driver.reap(&mut |t, s| done.push((t, s)));
    }
    assert_eq!((segment, offset, transferred), (data.len(), 0, 12288));
    assert_eq!(done, [(9, blk::STATUS_OK)]);
}

#[test]
fn continuation_errors_complete_once_and_return_the_slot_for_flush() {
    let mut r = Rig::new(4096, 1, 4096, 8, true);
    r.driver.start(7, 0, blk::OP_WRITE, 0, &[Seg { pa: 0x20000000, len: 12288 }]).unwrap();
    let mut done = Vec::new();
    for status in [0, 1] {
        let cmd = r.command().unwrap();
        r.complete(&cmd, status);
        r.driver.reap(&mut |t, s| done.push((t, s)));
    }
    assert_eq!(done, [(7, blk::STATUS_IOERR)]);
    assert!(r.command().is_none());
    for tag in 0..8 { r.driver.start(tag, 0, blk::OP_FLUSH, 0, &[]).unwrap(); }
    assert!(!r.driver.can_start());
    assert_eq!(r.driver.start(8, 0, blk::OP_FLUSH, 0, &[]), Err(blk::STATUS_IOERR));
    while let Some(cmd) = r.command() {
        assert_eq!(cmd.op, blk::OP_FLUSH);
        assert_eq!(cmd.sector, 0);
        assert!(cmd.data.is_empty());
        r.complete(&cmd, 0);
        r.driver.reap(&mut |t, s| done.push((t, s)));
    }
    assert_eq!(done.len(), 9);
    assert!(r.driver.can_start());
}

#[test]
fn an_unrepresentable_block_is_rejected_without_leaking_a_slot() {
    for (size_max, seg_max) in [(0, 1), (511, 1), (512, 0)] {
        let mut r = Rig::new(size_max, seg_max, 512, 8, true);
        assert_eq!(r.driver.start(0, 0, blk::OP_WRITE, 0, &[Seg { pa: 0x20000000, len: 512 }]), Err(blk::STATUS_IOERR));
        assert!(r.command().is_none());
        for tag in 0..8 { r.driver.start(tag, 0, blk::OP_FLUSH, 0, &[]).unwrap(); }
    }
}
