// SPDX-License-Identifier: GPL-2.0-only
//! Run usbd's production reset and Disable Slot paths with narrow hardware
//! mocks. Publishing a completion transfers DMA-buffer ownership to Linux.
#![allow(dead_code)]
extern crate self as l4h_rt;
use core::ptr::{addr_of_mut, write_volatile};
use l4h_abi::usb as abi;
use abi::{Event, Info};

#[macro_export]
macro_rules! log { ($($arg:tt)*) => { println!($($arg)*) }; }

const CC_SUCCESS: u32 = 1;
const CMD_DISABLE_SLOT: u32 = 10;
fn cc_status(_: u32) -> i32 { abi::ST_IO }
struct Trb { param: u64, status: u32, control: u32 }
struct Request { slot: u16 }
#[derive(Clone, Copy)]
struct Slot { enabled: bool }
impl Slot { const EMPTY: Self = Self { enabled: false }; }

struct Hardware {
    halt_ok: bool, start_ok: bool, running: bool, dcbaa: bool,
}
impl Hardware {
    fn halt_reset(&mut self) -> bool {
        if self.halt_ok { self.running = false; }
        self.halt_ok
    }
    fn start(&mut self) -> bool {
        self.running = self.start_ok;
        self.start_ok
    }
    fn set_dcbaa(&mut self, _: u32, p: Option<u64>) {
        assert!(!self.running, "DCBAA must remain owned until disable succeeds");
        self.dcbaa = p.is_some();
    }
}
struct Client { info: Box<Info>, resets: u32, notify: bool }
impl Client {
    fn info(&self) -> *mut Info { std::ptr::from_ref(&*self.info).cast_mut() }
    fn set_state(&self, state: u32) { unsafe { (*self.info()).state = state; } }
    fn post_event(&mut self, _: Event) {}
}
struct Usbd {
    hardware: Hardware, client: Option<Client>, resets: u64, dead: bool,
    slots: [Slot; 2], disable_result: Option<(u32, u32)>, completions: usize,
}
impl Usbd {
    fn new() -> Self {
        Self {
            hardware: Hardware { halt_ok: true, start_ok: true, running: true, dcbaa: true },
            client: Some(Client { info: Box::new(unsafe { std::mem::zeroed() }), resets: 0, notify: false }),
            resets: 0, dead: false, slots: [Slot::EMPTY, Slot { enabled: true }],
            disable_result: Some((CC_SUCCESS, 1)), completions: 0,
        }
    }
    fn hc(&mut self) -> &mut Hardware { &mut self.hardware }
    fn forget_all(&mut self, post: bool) {
        assert!(post);
        self.drop_ep(1, 1);
    }
    fn drop_ep(&mut self, _: usize, dci: usize) {
        assert!(!self.hardware.running, "CQ completion would release a buffer still owned by DMA");
        if dci == 1 { self.completions += 1; }
    }
    fn client_slot(&self, s: u16) -> Option<usize> {
        (s == 1 && self.slots[1].enabled).then_some(1)
    }
    fn command(&mut self, trb: Trb) -> Option<(u32, u32)> {
        assert_eq!(trb.control, CMD_DISABLE_SLOT << 10 | 1 << 24);
        assert_eq!(self.completions, 0, "no buffer returned before Disable Slot");
        if self.disable_result.is_some_and(|(cc, _)| cc == CC_SUCCESS) {
            self.hardware.running = false;
        }
        self.disable_result
    }
}
include!(env!("L4H_USB_LIFETIME_TEST_SRC"));

#[test]
fn failed_halt_faults_before_publishing_any_completion() {
    let mut driver = Usbd::new();
    driver.hardware.halt_ok = false;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| driver.reset(true)));
    let panic = result.unwrap_err();
    let message = panic.downcast_ref::<&str>().copied().or_else(|| panic.downcast_ref::<String>().map(String::as_str)).unwrap();
    assert!(message.contains("USB reset could not halt DMA"));
    assert_eq!(driver.completions, 0);
    assert!(driver.hardware.running && driver.hardware.dcbaa);
    assert_eq!(driver.client.as_ref().unwrap().info.state, abi::RESETTING);
}

#[test]
fn a_completed_halt_returns_buffers_before_restart_even_if_restart_fails() {
    for start_ok in [true, false] {
        let mut driver = Usbd::new();
        driver.hardware.start_ok = start_ok;
        driver.reset(true);
        assert_eq!(driver.completions, 1);
        assert_eq!(driver.dead, !start_ok);
        assert_eq!(driver.client.as_ref().unwrap().info.state, if start_ok { abi::READY } else { abi::DEAD });
    }
}

#[test]
fn only_successful_disable_releases_endpoints_and_dcbaa() {
    for result in [None, Some((17, 1)), Some((CC_SUCCESS, 1))] {
        let mut driver = Usbd::new();
        driver.disable_result = result;
        let status = driver.disable(&Request { slot: 1 });
        let success = result.is_some_and(|(cc, _)| cc == CC_SUCCESS);
        assert_eq!(status, match result { None => abi::ST_TIMEOUT, Some((CC_SUCCESS, _)) => abi::ST_OK, _ => abi::ST_IO });
        assert_eq!(driver.completions, success as usize);
        assert_eq!(driver.slots[1].enabled, !success);
        assert_eq!(driver.hardware.dcbaa, !success);
    }
}
