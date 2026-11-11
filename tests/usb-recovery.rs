// SPDX-License-Identifier: GPL-2.0-only
//! Production cancellation and endpoint recovery with controller responses
//! that leave the hardware dequeue unchanged on command rejection.
#![allow(dead_code)]
use l4h_abi::usb as abi;
use std::collections::VecDeque;
const NONE: u16 = u16::MAX;
const CC_SUCCESS: u32 = 1;
const CMD_RESET_EP: u32 = 14;
const CMD_SET_TR_DEQ: u32 = 16;
struct Trb { param: u64, status: u32, control: u32 }
#[derive(Clone, Copy)]
struct Dma;
impl Dma {
    fn pa(self, offset: usize) -> u64 { 0x1000 + offset as u64 }
    fn ring(self, _: usize) -> usize { 0 }
}
struct Hardware { dma: Dma, position: u16, running: bool, broken: bool }
struct Ring { stream: u16, deq: u16, head: u16 }
struct Rings { ring: Ring, gone: bool }
impl Rings {
    fn resume_point(&self, _: Dma, _: &Urbs, _: u16) -> (u16, bool) { (9, true) }
    fn get(&self, _: u16) -> &Ring { assert!(!self.gone); &self.ring }
    fn get_mut(&mut self, _: u16) -> &mut Ring { assert!(!self.gone); &mut self.ring }
    fn noop(&mut self, _: Dma, _: u16, _: u16, _: u16) {}
    fn rewind(&mut self, _: Dma, _: u16, _: u16) {}
}
struct Xfer { slot: u16, dci: u8 }
struct Urb { xfer: Xfer, ring: u16, posted: bool, actual: u32,
    next: u16, first: u16, ntrbs: u16, start: u16 }
struct Urbs { live: bool, urb: Urb }
impl Urbs {
    fn find(&self, tag: u32) -> Option<u16> { (self.live && tag == 7).then_some(0) }
    fn get(&self, _: u16) -> &Urb { &self.urb }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum EpState { Halted, Stopped }
#[derive(Clone, Copy)]
struct Ep { state: EpState, ring: u16, streams: u16, halted: u16, stream_rings: [u16; 2] }
#[derive(Clone, Copy)]
struct Slot { eps: [Ep; 3] }
struct Recover(VecDeque<(usize, usize)>);
impl Recover { fn pop(&mut self) -> Option<(usize, usize)> { self.0.pop_front() } }
struct Usbd {
    hc: Option<Hardware>, rings: Rings, urbs: Urbs, slots: [Slot; 2], recover: Recover,
    results: VecDeque<Option<(u32, u32)>>, commands: Vec<u32>,
    completions: usize, restarts: usize, resets: usize, halt_ok: bool,
}
impl Usbd {
    fn new(results: &[Option<(u32, u32)>]) -> Self {
        Self {
            hc: Some(Hardware { dma: Dma, position: 0, running: true, broken: false }),
            rings: Rings { ring: Ring { stream: 0, deq: 0, head: 0 }, gone: false },
            urbs: Urbs { live: true, urb: Urb { xfer: Xfer { slot: 1, dci: 2 },
                ring: 0, posted: true, actual: 0, next: 1, first: 0, ntrbs: 9, start: 0 } },
            slots: [Slot { eps: [Ep { state: EpState::Halted, ring: 0, streams: 0,
                halted: 0, stream_rings: [NONE; 2] }; 3] }; 2],
            recover: Recover([(1, 2)].into()), results: results.iter().copied().collect(),
            commands: Vec::new(), completions: 0, restarts: 0, resets: 0, halt_ok: true,
        }
    }
    fn hc(&mut self) -> &mut Hardware { self.hc.as_mut().unwrap() }
    fn command(&mut self, trb: Trb) -> Option<(u32, u32)> {
        let cmd = trb.control >> 10 & 0x3f;
        self.commands.push(cmd);
        let result = self.results.pop_front().expect("unexpected command");
        if result == Some((CC_SUCCESS, 0)) && cmd == CMD_SET_TR_DEQ { self.hc().position = 9; }
        // Production command() resets after a timeout, before returning None.
        if result.is_none() { self.hc_failed(); }
        result
    }
    fn hc_failed(&mut self) {
        self.resets += 1;
        // The actual halt/reset and quarantine ordering is in usb-lifetime.rs.
        assert!(self.halt_ok, "cannot halt: quarantine");
        self.hc().running = false;
        self.rings.gone = true;
        self.urbs.live = false;
    }
    fn stop(&mut self, _: usize, _: usize) -> bool { self.hc().running = false; true }
    fn complete_cancelled(&mut self, _: u16, _: usize, _: usize, _: u16, _: u32) {
        assert!(!self.hc().running, "completion transfers buffer ownership");
        self.urbs.live = false;
        self.completions += 1;
        self.rings.ring.head = 1; // A second posted URB still needs a restart.
    }
    fn restart(&mut self, _: usize, _: usize) {
        assert!(!self.rings.gone, "old rings cannot survive a reset");
        assert_eq!(self.hc().position, 9, "DMA must skip the released buffer");
        self.restarts += 1;
        self.hc().running = true;
    }
    fn accept_transfers(&mut self, _: u32) { unreachable!() }
    fn drop_pending(&mut self, _: u32) -> i32 { unreachable!() }
}
include!(env!("L4H_USB_RECOVERY_TEST_SRC"));

#[test]
fn cancellation_restarts_only_after_a_successful_dequeue_command() {
    for result in [Some((CC_SUCCESS, 0)), Some((17, 0)), None] {
        let mut u = Usbd::new(&[result]);
        assert_eq!(u.cancel(7), abi::ST_OK);
        assert_eq!(u.completions, 1);
        let success = result == Some((CC_SUCCESS, 0));
        assert_eq!(u.restarts, success as usize);
        assert_eq!(u.resets, !success as usize);
        assert_eq!(u.rings.ring.deq, if success { 9 } else { 0 });
    }
}

#[test]
fn a_rejected_dequeue_that_cannot_reset_never_restarts_dma() {
    let mut u = Usbd::new(&[Some((17, 0))]);
    u.halt_ok = false;
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| u.cancel(7))).is_err());
    assert_eq!(u.restarts, 0);
    assert!(!u.hc().running);
}

#[test]
fn halt_recovery_requires_both_reset_endpoint_and_set_dequeue_to_succeed() {
    for results in [
        vec![Some((17, 0))], vec![None],
        vec![Some((CC_SUCCESS, 0)), Some((17, 0))],
        vec![Some((CC_SUCCESS, 0)), None],
        vec![Some((CC_SUCCESS, 0)), Some((CC_SUCCESS, 0))],
    ] {
        let mut u = Usbd::new(&results);
        u.recover_all();
        let success = results.iter().all(|&r| r == Some((CC_SUCCESS, 0)));
        assert_eq!(u.restarts, success as usize);
        assert_eq!(u.resets, !success as usize);
        assert_eq!(u.commands.len(), results.len());
        assert_eq!(u.commands[0], CMD_RESET_EP);
    }
}
