// Execute root's production USB reply handling with
// real mailbox envelopes and a modeled controller table.
#![allow(dead_code)]
use l4h_host::{self as host, usb::call::reply, wire};
use std::collections::VecDeque;
use host::mailbox::RING;

macro_rules! log { ($($args:tt)*) => { let _ = format_args!($($args)*); }; }
#[derive(Clone, Copy, PartialEq, Eq, Debug)] enum State { Vm(usize), Failed }
#[derive(Clone, Copy)] struct Device { bus: u8, dev: u8, func: u8 }
struct Ctrl { state: State, pci: Device, driver: Option<Usbd> }
struct Usbd { mailbox: Mailbox, ops: [Option<Op>; RING], waiting: bool, comp: Component }
struct Component { tcb: Tcb }
struct Tcb;
static SUSPENDED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static DISABLED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
impl Tcb {
    fn tcb_suspend(&self) -> Result<(), ()> {
        SUSPENDED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}
struct Pci;
mod pci { pub type Pci = super::Pci; }
impl Pci {
    fn disable(&self, _: &Device) { DISABLED.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
}
enum Op { Claim, Attach, Remove(usize) }
struct Mailbox { answers: VecDeque<(u64, host::mailbox::Reply)> }
impl Mailbox {
    fn answer(&mut self) -> Option<(u64, host::mailbox::Reply)> { self.answers.pop_front() }
    fn abandon(&mut self) -> Option<u64> { self.answers.pop_front().map(|(k, _)| k) }
    fn idle(&self) -> bool { self.answers.is_empty() }
}
pub struct Host { pci: Pci }
static mut CTRLS: Vec<Ctrl> = Vec::new();
fn ctrls() -> &'static mut Vec<Ctrl> { unsafe { &mut *(&raw mut CTRLS) } }
fn claimed(_: &mut Host, _: usize, _: &[u64]) { panic!("unexpected claim"); }
fn free_area(_: &mut Host, _: &mut Usbd, _: usize) { panic!("unexpected remove"); }
fn post_attach(_: &mut Host, _: usize) { panic!("unexpected new attachment"); }
include!(env!("L4H_USB_ATTACH_TEST_SRC"));

#[test]
fn failed_usb_attachment_is_a_terminal_controller_failure() {
    // Native root responses can carry either a device errno or FAILED.
    for errno in [0, host::errno::EINVAL, host::errno::EIO, wire::FAILED] {
        let page = Box::new(unsafe { std::mem::zeroed::<host::mailbox::Mailbox>() });
        let mut client = host::mailbox::Client::<host::usb::call::Proto>::new(&page);
        client.send(&host::usb::call::Request::Attach { area: 0, gpa: 0, paddr: 1 << 32, size: 1 << 21 }).unwrap();
        page.entries[0].write_reply(&[errno]);
        page.done.store(1, std::sync::atomic::Ordering::Release);
        let answer = client.answer().unwrap();
        let mut ops = [const { None }; RING];
        ops[0] = Some(Op::Attach);
        *ctrls() = vec![Ctrl { state: State::Vm(7), pci: Device { bus: 0, dev: 1, func: 0 },
            driver: Some(Usbd { mailbox: Mailbox { answers: [answer].into() }, ops, waiting: false, comp: Component { tcb: Tcb } }) }];
        SUSPENDED.store(0, std::sync::atomic::Ordering::Relaxed);
        DISABLED.store(0, std::sync::atomic::Ordering::Relaxed);
        poll(&mut Host { pci: Pci });
        assert_eq!(ctrls()[0].state, if errno == 0 { State::Vm(7) } else { State::Failed }, "attachment failure must reach management");
        assert_eq!(SUSPENDED.load(std::sync::atomic::Ordering::Relaxed), usize::from(errno != 0));
        assert_eq!(DISABLED.load(std::sync::atomic::Ordering::Relaxed), usize::from(errno != 0));
        assert!(ctrls()[0].driver.as_ref().unwrap().ops[0].is_none(), "failure was left pending");
    }
    ctrls().clear();
}
