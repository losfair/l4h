//! Production AHCI queues and wire descriptors against MMIO/DMA memory.
#![allow(dead_code)]
extern crate self as l4h_rt;
extern crate self as l4h_virtio;
pub use actual_virtio::{Dma, dma_fence};

/// AHCI test MMIO: W1S doorbells, W1C interrupt status, and deterministic
/// hardware progress at an MMIO boundary. All unregistered memory is RAM.
mod mmio_test {
    use std::cell::RefCell;
    #[derive(Clone, Copy)]
    pub enum Kind { Set, Clear, Control(u32) }
    struct Register { address: usize, kind: Kind, clear_before_write: u32 }
    struct Action { on_read: usize, target: usize, clear: u32, set: u32 }
    struct WriteAction { on_write: usize, value: u32, target: usize, clear: u32, set: u32 }
    #[derive(Default)]
    struct State { registers: Vec<Register>, writes: Vec<(usize, u32)>, actions: Vec<Action>, write_actions: Vec<WriteAction> }
    thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
    pub fn register(address: usize, kind: Kind) {
        STATE.with_borrow_mut(|s| s.registers.push(Register { address, kind, clear_before_write: 0 }));
    }
    pub fn change(address: usize, clear: u32, set: u32) {
        let reg = actual_virtio::Mmio(address);
        reg.w32(0, (reg.r32(0) & !clear) | set);
    }
    pub fn before_write(address: usize, clear: u32) {
        STATE.with_borrow_mut(|s| s.registers.iter_mut().find(|r| r.address == address).unwrap().clear_before_write = clear);
    }
    pub fn after_read(on_read: usize, target: usize, clear: u32, set: u32) {
        STATE.with_borrow_mut(|s| s.actions.push(Action { on_read, target, clear, set }));
    }
    pub fn after_write(on_write: usize, value: u32, target: usize, clear: u32, set: u32) {
        STATE.with_borrow_mut(|s| s.write_actions.push(WriteAction { on_write, value, target, clear, set }));
    }
    pub fn read(address: usize) -> u32 {
        let value = actual_virtio::Mmio(address).r32(0);
        let actions = STATE.with_borrow_mut(|s| {
            let mut actions = Vec::new();
            let mut i = 0;
            while i < s.actions.len() {
                if s.actions[i].on_read == address { actions.push(s.actions.remove(i)); } else { i += 1; }
            }
            actions
        });
        for a in actions { change(a.target, a.clear, a.set); }
        value
    }
    pub fn write(address: usize, value: u32) {
        let mut output = value;
        STATE.with_borrow_mut(|s| {
            if let Some(r) = s.registers.iter_mut().find(|r| r.address == address) {
                change(address, core::mem::take(&mut r.clear_before_write), 0);
                let current = actual_virtio::Mmio(address).r32(0);
                output = match r.kind { Kind::Set => current | value, Kind::Clear => current & !value, Kind::Control(mask) => (current & !mask) | (value & mask) };
                s.writes.push((address, value));
            }
        });
        actual_virtio::Mmio(address).w32(0, output);
        let actions = STATE.with_borrow_mut(|s| {
            let mut actions = Vec::new();
            let mut i = 0;
            while i < s.write_actions.len() {
                let a = &s.write_actions[i];
                if a.on_write == address && a.value == value { actions.push(s.write_actions.remove(i)); } else { i += 1; }
            }
            actions
        });
        for a in actions { change(a.target, a.clear, a.set); }
    }
    pub fn writes() -> Vec<(usize, u32)> { STATE.with_borrow_mut(|s| core::mem::take(&mut s.writes)) }
}

#[derive(Clone, Copy)]
pub struct Mmio(pub usize);
impl Mmio {
    pub fn r8(&self, o: usize) -> u8 { actual_virtio::Mmio(self.0).r8(o) }
    pub fn r16(&self, o: usize) -> u16 { actual_virtio::Mmio(self.0).r16(o) }
    pub fn r32(&self, o: usize) -> u32 { mmio_test::read(self.0 + o) }
    pub fn r64(&self, o: usize) -> u64 { actual_virtio::Mmio(self.0).r64(o) }
    pub fn w8(&self, o: usize, v: u8) { actual_virtio::Mmio(self.0).w8(o, v) }
    pub fn w16(&self, o: usize, v: u16) { actual_virtio::Mmio(self.0).w16(o, v) }
    pub fn w32(&self, o: usize, v: u32) { mmio_test::write(self.0 + o, v) }
    pub fn w64(&self, o: usize, v: u64) { actual_virtio::Mmio(self.0).w64(o, v) }
}
pub use l4h_host as host;
#[macro_export]
macro_rules! info { ($($a:tt)*) => {{ let _ = format_args!($($a)*); }}; }
#[derive(Clone, Copy, Debug)]
pub struct Seg { pub pa: u64, pub len: u32 }
pub struct DevInfo { pub capacity: u64, pub block_size: u32, pub read_only: bool, pub flush: bool, pub address: u64, pub seg_max: usize }
pub const MAX_PIECES: usize = host::blk::MAX_SEGS;
pub const MAX_REQUEST: u64 = host::blk::MAX_REQUEST_BYTES;
pub trait Driver {
    fn units(&self) -> usize;
    fn info(&self, unit: usize) -> DevInfo;
    fn can_start(&self) -> bool;
    fn start(&mut self, tag: u64, unit: usize, op: u32, sector: u64, data: &[Seg]) -> Result<(), u32>;
    fn kick(&mut self);
    fn reap(&mut self, done: &mut dyn FnMut(u64, u32));
}
#[path = "../host/l4h-blkd/src/ahci.rs"]
mod ahci;
