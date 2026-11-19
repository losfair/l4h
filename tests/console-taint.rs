//! Production CTL_CONSOLE_READ and CTL_GPU_READ handlers with a flags
//! actor that records CONSOLE_OUT: what an answer discloses about the
//! guest's output taints, even when it copies no bytes.
#![allow(dead_code)]
use core::ptr::addr_of;
use core::sync::atomic::{Ordering, fence};
use std::cell::{Cell, RefCell};
use l4h_abi as abi;
use l4h_host as host;
use l4h_host::errno::{EAGAIN, EINVAL, ENOENT, EPERM, Errno};
use l4h_host::gpu::{DisplayHeader, IMAGE_OFFSET, image_bytes};

const MAX_GUESTS: usize = 4;
const DOM0: usize = 0;
const VM: usize = 1;
const WIDTH: u32 = 16;
const HEIGHT: u32 = 8;

struct Guest {
    id: usize,
    ring: Box<host::ConsoleRing>,
    gpu: Option<(u32, u32)>,
    display: Vec<u64>,
    ctl: Vec<u8>,
}
impl Guest {
    fn new(id: usize) -> Self {
        let display = vec![0u64; (IMAGE_OFFSET + image_bytes(WIDTH, HEIGHT)) / 8];
        DISPLAYS.with(|d| d.borrow_mut()[id] = display.as_ptr() as usize);
        Guest { id, ring: unsafe { Box::new_zeroed().assume_init() }, gpu: Some((WIDTH, HEIGHT)), display,
            ctl: vec![0; abi::CTL_LOAD_MAX as usize] }
    }
    fn console_ring(&self) -> *const host::ConsoleRing { &*self.ring }
    fn ctl_data(&self) -> Option<*const u8> { Some(self.ctl.as_ptr()) }
    fn header(&self) -> &DisplayHeader { unsafe { &*(self.display.as_ptr() as *const DisplayHeader) } }
}

thread_local! { static DISPLAYS: RefCell<[usize; MAX_GUESTS]> = const { RefCell::new([0; MAX_GUESTS]) }; }
fn self_display_va(id: usize) -> usize { DISPLAYS.with(|d| d.borrow()[id]) }

/// The host actor: refuses sealed actions, records effects (as
/// root::Flags::act with l4h_host::trust's act).
#[derive(Default)]
struct Flags { tainted: Cell<bool>, sealed: Cell<bool> }
impl Flags {
    fn act(&self, g: &Guest, caller: usize, bits: u64, effect: bool) -> Result<(), Errno> {
        assert_eq!(bits, abi::FLAG_CONSOLE_OUT);
        if g.id == caller { return Ok(()); }
        if self.sealed.get() { return Err(EPERM); }
        if effect { self.tainted.set(true); }
        Ok(())
    }
}

struct Vmmgr { flags: Option<Flags>, guests: Vec<Guest> }
impl Vmmgr {
    fn guest(&self, id: usize) -> Option<&Guest> { self.guests.get(id) }
    fn tainted(&self) -> bool { self.flags.as_ref().unwrap().tainted.get() }
}

include!(env!("L4H_CONSOLE_TAINT_TEST_SRC"));

fn host() -> Vmmgr {
    Vmmgr { flags: Some(Flags::default()), guests: vec![Guest::new(DOM0), Guest::new(VM)] }
}

fn call(h: &mut Vmmgr, op: u32, off: u64) -> (Result<(), Errno>, [u64; 6]) {
    let mut req: Box<abi::CtlReq> = unsafe { Box::new_zeroed().assume_init() };
    let mut resp: Box<abi::CtlResp> = unsafe { Box::new_zeroed().assume_init() };
    req.op = op;
    req.args[0] = VM as u64;
    req.args[1] = off;
    let r = execute(h, DOM0, &req, &mut resp);
    (r, resp.vals)
}

fn console_write(h: &mut Vmmgr, text: &[u8]) {
    let ring = &mut h.guests[VM].ring;
    let head = ring.head.load(Ordering::Relaxed) as usize;
    for (i, &b) in text.iter().enumerate() {
        ring.data[(head + i) % host::CONSOLE_RING_DATA] = b;
    }
    ring.head.store((head + text.len()) as u64, Ordering::Release);
}

#[test]
fn empty_console_reads_of_a_silent_guest_do_not_taint() {
    let mut h = host();
    for off in [0, 1, u64::MAX] {
        let (r, vals) = call(&mut h, abi::CTL_CONSOLE_READ, off);
        assert_eq!((r, vals[0], vals[1]), (Ok(()), 0, 0));
    }
    assert!(!h.tainted(), "a guest that wrote nothing was tainted");
}

#[test]
fn console_reads_past_the_output_still_taint() {
    let mut h = host();
    console_write(&mut h, b"secret\n");
    // Nothing copied, but the answer is how much the guest wrote.
    let (r, vals) = call(&mut h, abi::CTL_CONSOLE_READ, u64::MAX);
    assert_eq!((r, vals[0], vals[1]), (Ok(()), 7, 0));
    assert!(h.tainted(), "the console's head was disclosed without CONSOLE_OUT");
}

#[test]
fn console_reads_of_output_taint_and_sealed_ones_are_refused() {
    let mut h = host();
    console_write(&mut h, b"secret\n");
    let (r, vals) = call(&mut h, abi::CTL_CONSOLE_READ, 0);
    assert_eq!((r, vals[0], vals[1]), (Ok(()), 7, 7));
    assert!(h.tainted());
    let mut h = host();
    h.flags.as_ref().unwrap().sealed.set(true);
    for off in [0, u64::MAX] {
        assert_eq!(call(&mut h, abi::CTL_CONSOLE_READ, off).0, Err(EPERM));
    }
}

#[test]
fn gpu_reads_of_a_display_never_drawn_taint_only_when_they_copy() {
    let mut h = host();
    let (r, vals) = call(&mut h, abi::CTL_GPU_READ, u64::MAX);
    assert_eq!((r, vals[0], vals[4], vals[5]), (Ok(()), 0, 0, 0));
    assert!(!h.tainted(), "an empty read of a blank display was tainted");
    // Copying the (blank) image is disclosure, as before.
    let (r, vals) = call(&mut h, abi::CTL_GPU_READ, 0);
    assert_eq!((r, vals[0]), (Ok(()), image_bytes(WIDTH, HEIGHT) as u64));
    assert!(h.tainted());
}

#[test]
fn gpu_reads_past_the_image_still_taint() {
    let mut h = host();
    h.guests[VM].header().format.store(1, Ordering::Relaxed);
    h.guests[VM].header().frame.store(42, Ordering::Release);
    // Nothing copied, but the answer gives the format and frame count.
    let (r, vals) = call(&mut h, abi::CTL_GPU_READ, u64::MAX);
    assert_eq!((r, vals[0], vals[4], vals[5]), (Ok(()), 0, 1, 42));
    assert!(h.tainted(), "the display's frame counter was disclosed without CONSOLE_OUT");
}

#[test]
fn gpu_reads_during_an_update_still_taint() {
    let mut h = host();
    h.guests[VM].header().frame.store(43, Ordering::Release);
    // EAGAIN says the guest is drawing.
    assert_eq!(call(&mut h, abi::CTL_GPU_READ, u64::MAX).0, Err(EAGAIN));
    assert!(h.tainted(), "EAGAIN disclosed a drawing guest without CONSOLE_OUT");
    let mut h = host();
    h.flags.as_ref().unwrap().sealed.set(true);
    h.guests[VM].header().frame.store(43, Ordering::Release);
    assert_eq!(call(&mut h, abi::CTL_GPU_READ, u64::MAX).0, Err(EPERM));
}
