//! Root's production read of an xHCI controller's capabilities and the
//! start of `attach`: a 32-bit controller is refused a pool above 4 GiB
//! while usbd has not answered the CLAIM yet too, as usbd would refuse
//! the ATTACH and root would then quarantine the controller.
#![allow(dead_code)]
use std::ops::Range;
use l4h_host::{self as host, usb};
use l4h_host::errno::Errno;

mod ctl { pub use l4h_host::errno::{EBUSY, EINVAL, EIO, ENODEV, ENOENT, ENOSPC}; }
mod devmem { pub fn granule(slot: usize) -> usize { slot } }

const PAGE: usize = 4096;
const CAP_WAIT_MS: u64 = 5;
const DEVICE_ATTRS: () = ();

#[derive(Clone, Copy)] struct Device { bus: u8, dev: u8, func: u8 }
type BarCache = [Option<Range<usize>>; 6];
fn bar_frames(cache: &BarCache, b: u8) -> Range<usize> { cache[b as usize].clone().expect("BAR") }
fn abs_of(frame: usize) -> usize { frame }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State { Firmware, Idle, Vm(usize), Failed, Unsupported(&'static str) }
struct Ctrl { pci: Device, state: State, bars: BarCache, ac64: bool }
static mut CTRLS: Vec<Ctrl> = Vec::new();
fn ctrls() -> &'static mut Vec<Ctrl> { unsafe { &mut *(&raw mut CTRLS) } }
/// The tests share the controller table.
static TABLE: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Pci;
impl Pci { fn enable_memory(&self, _: &Device) {} }
struct Info { tsc_hz: u64 }
/// BAR 0's first page, as the window maps it.
struct Window { page: Box<[u32; 1024]> }
impl Window {
    fn with_frame_attrs<R>(&mut self, _: &usize, _: (), f: impl FnOnce(*mut u8) -> R) -> R {
        f(self.page.as_mut_ptr().cast())
    }
}
struct Wins { a: Window }
pub struct Host { pci: Pci, info: Info, wins: Wins }

struct Pool { gpa: usize, paddr: usize, size: usize }
pub struct RootGuest { id: usize, usbs: Vec<usize>, pool: Pool }
pub struct Attached;

include!(env!("L4H_USB_AC64_TEST_SRC"));

/// A ready controller's capability registers: CAPLENGTH 0x20, 32 slots,
/// 4 KiB pages, and HCCPARAMS1.AC64 as `ac64` says.
fn host(ac64: bool) -> Host {
    let mut page = Box::new([0u32; 1024]);
    page[0] = 0x0100_0020;
    page[1] = 32 | 4 << 24;
    page[4] = 1 << 2 | u32::from(ac64);
    page[(0x20 + 0x08) / 4] = 1;
    Host { pci: Pci, info: Info { tsc_hz: 1_000_000_000 }, wins: Wins { a: Window { page } } }
}

fn controller() {
    *ctrls() = vec![Ctrl { pci: Device { bus: 0, dev: 20, func: 0 }, state: State::Firmware,
        bars: [Some(0..16), None, None, None, None, None], ac64: false }];
}

fn guest(paddr: usize) -> RootGuest {
    RootGuest { id: 3, usbs: Vec::new(), pool: Pool { gpa: 1 << 40, paddr, size: 64 << 20 } }
}

#[test]
fn capabilities_say_whether_the_controller_reaches_past_4_gib() {
    let _table = TABLE.lock().unwrap();
    controller();
    for ac64 in [false, true] {
        assert_eq!(caps(&mut host(ac64), 0), Ok((32, 0, 4096, ac64)));
    }
}

#[test]
fn a_claim_in_flight_still_refuses_a_pool_the_controller_cannot_reach() {
    let _table = TABLE.lock().unwrap();
    for ac64 in [false, true] {
        let mut h = host(ac64);
        controller();
        // As `claim` does: the capabilities, then usbd's CLAIM is posted
        // and the controller is Idle before usbd has answered.
        let (.., reach) = caps(&mut h, 0).unwrap();
        ctrls()[0].ac64 = reach;
        ctrls()[0].state = State::Idle;
        let high = attach(&mut h, 0, &mut guest(6 << 30)).map(|_| ());
        assert_eq!(high, if ac64 { Ok(()) } else { Err(ctl::EINVAL) }, "AC64 {ac64}: pool above 4 GiB");
        assert_eq!(attach(&mut h, 0, &mut guest(1 << 30)).map(|_| ()), Ok(()), "AC64 {ac64}: pool below 4 GiB");
        // A pool that ends exactly at 4 GiB is reachable.
        assert_eq!(attach(&mut h, 0, &mut guest((4 << 30) - (64 << 20))).map(|_| ()), Ok(()));
    }
    ctrls().clear();
}
