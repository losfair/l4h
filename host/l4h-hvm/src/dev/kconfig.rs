//! The kernel configuration port (DESIGN.md §5.11, abi.h
//! L4H_KCONFIG_PORT_*): a virtio-console device with one port, named
//! "l4h.kconfig", through which the userspace of a guest that holds no
//! capability reads what the host's kernel found and chose at boot (FL4's
//! seL4_KernelConfig, DESIGN.md §10.1), one key at a time.  An unmodified
//! kernel's own driver gives it as a character device, under any lockdown.
//!
//! The port carries fixed-size requests (abi::KconfigPortReq) and their
//! answers (abi::KconfigPortResp), one at a time: a request read whole is
//! answered at once (`query`, which asks the kernel and never waits), and
//! the next is read once the answer is with the guest.  Closing or
//! opening the port starts again, as on the attestation port
//! (dev/attest.rs): what was being read or answered is dropped, with what
//! had been written when we took the driver's message and not yet read;
//! how far the queue is thrown away (`flush`) is read before that
//! message's buffer is returned, never after.
//!
//! The guest is notified of nothing but used buffers, and notifies us of
//! every buffer it adds.  A turn takes a bounded number of them
//! (`BUDGET`), and says which queues it left some in (`more`), so that a
//! guest filling its queues does not keep the I/O thread from its disks.
//! Only the I/O thread touches it.  Free of seL4.

use l4h_abi as abi;
use l4h_rt::host::fixed::ArrayVec;

use super::virtio_pci::Backend;
use crate::guest::GuestMem;
use crate::virtq::{Buf, Queue};

/// The console device type, and its feature for named ports.
const VIRTIO_ID_CONSOLE: u16 = 3;
const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1 << 1;
// Port 0's queues, then the control queues (virtio 1.x §5.3.2).
const RX: usize = 0;
const TX: usize = 1;
const CTL_RX: usize = 2;
const CTL_TX: usize = 3;
pub const QUEUE_SIZE: u16 = 64;
/// Chains one turn takes at most, over all queues.
const BUDGET: usize = QUEUE_SIZE as usize;
// Control messages: {id: u32, event: u16, value: u16}.
const CTL_LEN: usize = 8;
const DEVICE_READY: u16 = 0;
const PORT_ADD: u16 = 1;
const PORT_READY: u16 = 3;
const PORT_OPEN: u16 = 6;
const PORT_NAME: u16 = 7;
// Control messages to send (`ctl`), in this order.
const SEND_ADD: u8 = 1;
const SEND_NAME: u8 = 2;
const SEND_OPEN: u8 = 4;

const REQ: usize = core::mem::size_of::<abi::KconfigPortReq>();
const RESP: usize = core::mem::size_of::<abi::KconfigPortResp>();
const EINVAL: i32 = -22;

type Chain = ArrayVec<Buf, { QUEUE_SIZE as usize }>;

pub struct Port<F: FnMut(u64) -> Result<u64, i32>> {
    /// The kernel's value of a key, or -errno (l4h_rt::kconfig::get).
    query: F,
    config: [u8; 12],
    multiport: bool,
    /// Control messages owed to the driver (SEND_*).
    ctl: u8,
    /// The request being read.
    req: [u8; REQ],
    req_len: usize,
    /// The port's stream is no request's (a bad header, bytes after a
    /// request): nothing more is read until it is opened again.
    broken: bool,
    /// The answer being written: `resp_len` bytes (RESP, or 0 for none),
    /// `resp_done` of them with the guest.
    resp: [u8; RESP],
    resp_len: usize,
    resp_done: usize,
    /// What was written before the port was opened or closed is still to
    /// be thrown away: the chains before this avail index of TX.
    flush: Option<u16>,
    /// Chains left of this turn's BUDGET, and the queues it ran out with
    /// chains left in.
    budget: usize,
    more: u64,
}

impl<F: FnMut(u64) -> Result<u64, i32>> Port<F> {
    pub fn new(query: F) -> Self {
        // No console size; one port; no emergency write.
        let mut config = [0; 12];
        config[4..8].copy_from_slice(&1u32.to_le_bytes());
        Port {
            query, config, multiport: false, ctl: 0, req: [0; REQ], req_len: 0, broken: false, resp: [0; RESP], resp_len: 0,
            resp_done: 0, flush: None, budget: 0, more: 0,
        }
    }

    /// The stream starts again (the port was opened or closed, the device
    /// reset): no request is half read, no answer owed.
    fn restart(&mut self) {
        self.req_len = 0;
        self.broken = false;
        self.resp_len = 0;
        self.resp_done = 0;
    }

    /// The next chain of queue `n` (`q`), within this turn's budget.
    fn pop(&mut self, mem: &GuestMem, n: usize, q: &mut Queue) -> Option<u16> {
        if self.budget == 0 {
            if q.has_avail(mem) {
                self.more |= 1 << n;
            }
            return None;
        }
        let head = q.pop(mem)?;
        self.budget -= 1;
        Some(head)
    }

    /// How far the driver has filled TX (`q`): nowhere, if it has not set
    /// the queue up.
    fn written(mem: &GuestMem, q: &Queue) -> u16 {
        if q.ready { q.avail_idx(mem) } else { q.last_avail() }
    }

    /// Return the chains of TX (`q`) before its avail index `to` unread:
    /// whether any was returned, and whether that is all of them (not if
    /// the budget ran out first).
    fn discard(&mut self, mem: &GuestMem, q: &mut Queue, to: u16) -> (bool, bool) {
        let mut any = false;
        let mut all = true;
        while q.last_avail() != to {
            let Some(head) = self.pop(mem, TX, q) else {
                all = self.budget != 0 || !q.has_avail(mem);
                break;
            };
            any = true;
            q.push_deferred(mem, head, 0);
        }
        q.publish_used(mem);
        (any, all)
    }

    /// Everything there is to do, in order: the driver's control messages
    /// (an open comes before what is written after it), ours, the answer's
    /// way to the guest, the next request.  The queues used buffers went
    /// into.
    fn turn(&mut self, mem: &GuestMem, queues: &mut [Queue]) -> u64 {
        let mut used = 0;
        self.budget = BUDGET;
        self.more = 0;
        let (port, ctl) = queues.split_at_mut(CTL_RX);
        if self.control_in(mem, &mut ctl[CTL_TX - CTL_RX], &port[TX]) {
            used |= 1 << CTL_TX;
        }
        if let Some(to) = self.flush {
            let (any, all) = self.discard(mem, &mut queues[TX], to);
            if any {
                used |= 1 << TX;
            }
            if !all {
                return used;
            }
            self.flush = None;
        }
        if self.control_out(mem, &mut queues[CTL_RX]) {
            used |= 1 << CTL_RX;
        }
        // Each request is answered as it is read: its answer goes out in
        // the same turn, and the request after it is read.
        loop {
            if self.write_answer(mem, &mut queues[RX]) {
                used |= 1 << RX;
            }
            let (returned, asked) = self.read_request(mem, &mut queues[TX]);
            if returned {
                used |= 1 << TX;
            }
            if !asked || self.resp_len == 0 {
                return used;
            }
        }
    }

    /// The driver's control messages (`q`): whether any chain was
    /// returned.  `tx` is the port's queue of what userspace wrote.
    fn control_in(&mut self, mem: &GuestMem, q: &mut Queue, tx: &Queue) -> bool {
        let mut chain = Chain::new();
        let mut any = false;
        while let Some(head) = self.pop(mem, CTL_TX, q) {
            any = true;
            let mut msg = [0u8; CTL_LEN];
            let whole = q.chain(mem, head, &mut chain).is_ok() && {
                let mut n = 0;
                for b in chain.iter().filter(|b| !b.write) {
                    let take = (b.len as usize).min(CTL_LEN - n);
                    if take != 0 && mem.read_bytes(b.gpa, &mut msg[n..n + take]) {
                        n += take;
                    }
                }
                n == CTL_LEN
            };
            q.push_deferred(mem, head, 0);
            if !whole {
                continue;
            }
            let id = u32::from_le_bytes(msg[0..4].try_into().unwrap());
            let event = u16::from_le_bytes(msg[4..6].try_into().unwrap());
            let value = u16::from_le_bytes(msg[6..8].try_into().unwrap());
            let restart = match (event, id) {
                // The driver is there: it learns of the port.  Again
                // after a reset: the port starts anew.
                (DEVICE_READY, _) if value == 1 => {
                    self.ctl = SEND_ADD;
                    true
                }
                // It made the port: its name, and that our end is open.
                (PORT_READY, 0) if value == 1 => {
                    self.ctl |= SEND_NAME | SEND_OPEN;
                    false
                }
                // Userspace opened or closed it.
                (PORT_OPEN, 0) => true,
                _ => false,
            };
            if restart {
                self.restart();
                // What TX holds now was written before this message; the
                // driver, which waits for the message's buffer (published
                // below), lets nobody write more until then.
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                self.flush = Some(Self::written(mem, tx));
            }
        }
        q.publish_used(mem);
        any
    }

    /// Our control messages, as far as the driver has buffers for them.
    fn control_out(&mut self, mem: &GuestMem, q: &mut Queue) -> bool {
        let mut chain = Chain::new();
        let mut any = false;
        while self.ctl != 0 {
            let (bit, event, name) = if self.ctl & SEND_ADD != 0 {
                (SEND_ADD, PORT_ADD, &b""[..])
            } else if self.ctl & SEND_NAME != 0 {
                (SEND_NAME, PORT_NAME, abi::KCONFIG_PORT_NAME)
            } else {
                (SEND_OPEN, PORT_OPEN, &b""[..])
            };
            let mut msg = [0u8; CTL_LEN + abi::KCONFIG_PORT_NAME.len()];
            msg[4..6].copy_from_slice(&event.to_le_bytes());
            msg[6..8].copy_from_slice(&1u16.to_le_bytes());
            msg[CTL_LEN..CTL_LEN + name.len()].copy_from_slice(name);
            let msg = &msg[..CTL_LEN + name.len()];
            let Some(head) = self.pop(mem, CTL_RX, q) else { break };
            any = true;
            // A buffer too small for it, or none of RAM: the message is
            // lost with it, as the driver's own fault.
            let written = if q.chain(mem, head, &mut chain).is_ok() { Self::fill(mem, &chain, msg) } else { 0 };
            q.push_deferred(mem, head, written as u32);
            self.ctl &= !bit;
        }
        q.publish_used(mem);
        any
    }

    /// Copy `src` into the writable buffers of `chain`: how much fitted.
    fn fill(mem: &GuestMem, chain: &Chain, src: &[u8]) -> usize {
        let mut n = 0;
        for b in chain.iter().filter(|b| b.write) {
            let take = (b.len as usize).min(src.len() - n);
            if take == 0 || !mem.write_bytes(b.gpa, &src[n..n + take]) {
                break;
            }
            n += take;
        }
        n
    }

    /// The answer to the request just read: `status` and `value`.
    fn answer(&mut self, status: i32, value: u64) {
        self.resp[0..4].copy_from_slice(&abi::KCONFIG_PORT_MAGIC.to_le_bytes());
        self.resp[4..8].copy_from_slice(&status.to_le_bytes());
        self.resp[8..16].copy_from_slice(&value.to_le_bytes());
        self.resp[16..24].copy_from_slice(&0u64.to_le_bytes());
        self.resp_len = RESP;
        self.resp_done = 0;
    }

    /// Give the guest what is left of the answer, as far as it has
    /// buffers: whether any chain was returned.
    fn write_answer(&mut self, mem: &GuestMem, q: &mut Queue) -> bool {
        let mut chain = Chain::new();
        let mut any = false;
        while self.resp_done < self.resp_len {
            let Some(head) = self.pop(mem, RX, q) else { break };
            any = true;
            let n = if q.chain(mem, head, &mut chain).is_ok() { Self::fill(mem, &chain, &self.resp[self.resp_done..self.resp_len]) } else { 0 };
            q.push_deferred(mem, head, n as u32);
            self.resp_done += n;
        }
        if self.resp_done == self.resp_len {
            self.resp_len = 0;
            self.resp_done = 0;
        }
        q.publish_used(mem);
        any
    }

    /// Read the guest's next request, if no answer is being written:
    /// whether any chain was returned, and whether a request was read
    /// whole (and answered).
    fn read_request(&mut self, mem: &GuestMem, q: &mut Queue) -> (bool, bool) {
        let mut chain = Chain::new();
        let mut any = false;
        let mut asked = false;
        // One request at a time: the rest waits in the queue.
        while !asked && self.resp_len == 0 {
            let Some(head) = self.pop(mem, TX, q) else { break };
            any = true;
            if q.chain(mem, head, &mut chain).is_ok() {
                for b in chain.iter().filter(|b| !b.write) {
                    asked |= self.take_bytes(mem, b, asked);
                }
            }
            q.push_deferred(mem, head, 0);
        }
        q.publish_used(mem);
        (any, asked)
    }

    /// The next bytes of the stream, in `b` (`asked`: after a request in
    /// the same chain): whether they end a request.
    fn take_bytes(&mut self, mem: &GuestMem, b: &Buf, mut asked: bool) -> bool {
        let mut at = 0;
        while at < b.len as usize && !self.broken {
            if asked {
                // Bytes after a request, before its answer: the stream is
                // no longer one of requests.
                self.broken = true;
                break;
            }
            let take = (b.len as usize - at).min(REQ - self.req_len);
            if !mem.read_bytes(b.gpa + at as u64, &mut self.req[self.req_len..self.req_len + take]) {
                self.broken = true;
                break;
            }
            self.req_len += take;
            at += take;
            if self.req_len == REQ {
                self.submit();
                asked = true;
            }
        }
        asked
    }

    /// The request in `req` is whole: answered from the kernel, or (not a
    /// request) refused, the stream with it.
    fn submit(&mut self) {
        self.req_len = 0;
        let word = |i: usize| u32::from_le_bytes(self.req[4 * i..4 * i + 4].try_into().unwrap());
        if word(0) != abi::KCONFIG_PORT_MAGIC || word(1) != 0 {
            self.broken = true;
            return self.answer(EINVAL, 0);
        }
        let key = u64::from_le_bytes(self.req[8..16].try_into().unwrap());
        match (self.query)(key) {
            Ok(v) => self.answer(0, v),
            // An errno, or (not one) the kernel's failure.
            Err(e) if (-4095..0).contains(&e) => self.answer(e, 0),
            Err(_) => self.answer(-5, 0),
        }
    }
}

impl<F: FnMut(u64) -> Result<u64, i32>> Backend for Port<F> {
    fn device_type(&self) -> u16 {
        VIRTIO_ID_CONSOLE
    }

    fn features(&self) -> u64 {
        VIRTIO_CONSOLE_F_MULTIPORT
    }

    fn num_queues(&self) -> usize {
        4
    }

    fn queue_max(&self, _q: usize) -> u16 {
        QUEUE_SIZE
    }

    fn config(&self) -> &[u8] {
        &self.config
    }

    fn features_accepted(&mut self, features: u64) {
        self.multiport = features & VIRTIO_CONSOLE_F_MULTIPORT != 0;
    }

    fn event_idx(&self) -> bool {
        false
    }

    fn kick(&mut self, mem: &GuestMem, queues: &mut [Queue], _q: usize) -> u64 {
        // Without named ports the device is a console nobody reads: what
        // its driver writes is taken and dropped, so that it does not wait.
        if !self.multiport {
            self.budget = BUDGET;
            self.more = 0;
            let to = Self::written(mem, &queues[TX]);
            return if self.discard(mem, &mut queues[TX], to).0 { 1 << TX } else { 0 };
        }
        self.turn(mem, queues)
    }

    fn complete(&mut self, _mem: &GuestMem, _queues: &mut [Queue]) -> u64 {
        // Nothing is asked of a backend: every answer is made in a turn.
        0
    }

    fn retry(&self) -> u64 {
        self.more()
    }

    fn more(&self) -> u64 {
        // Any queue's turn is every queue's: one that has chains left,
        // which its driver therefore enabled, is asked for.
        self.more
    }

    fn reset(&mut self) {
        self.multiport = false;
        self.ctl = 0;
        self.restart();
        // The queues are gone, and what they held with them.
        self.flush = None;
        self.more = 0;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::mem::tests::fake;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::vec::Vec;

    // Each queue's rings, and where the test puts buffers.
    const RING: u64 = 0x1_0000;
    const BUFS: u64 = 0x10_0000;
    const BUF: u64 = 0x1000;

    /// The kernel's answers: key k is k * 3, keys above 0x1000 unknown;
    /// the keys asked, in order.
    fn kernel(asked: Rc<RefCell<Vec<u64>>>) -> impl FnMut(u64) -> Result<u64, i32> {
        move |k| {
            asked.borrow_mut().push(k);
            match k {
                0x7777 => Err(-38),
                0x8888 => Err(1),
                k if k > 0x1000 => Err(-2),
                k => Ok(k * 3),
            }
        }
    }

    struct Rig {
        mem: GuestMem,
        _ram: Vec<u8>,
        asked: Rc<RefCell<Vec<u64>>>,
        queues: [Queue; 4],
        avail: [u16; 4],
        used: [u16; 4],
    }

    fn rig() -> (Rig, Port<impl FnMut(u64) -> Result<u64, i32>>) {
        let (mem, ram) = fake(8 << 20, 0);
        let asked = Rc::new(RefCell::new(Vec::new()));
        let mut p = Port::new(kernel(asked.clone()));
        p.features_accepted(VIRTIO_CONSOLE_F_MULTIPORT);
        let mut queues: [Queue; 4] = Default::default();
        for (i, q) in queues.iter_mut().enumerate() {
            let base = RING + 0x4000 * i as u64;
            assert!(q.setup(&mem, QUEUE_SIZE as u32, QUEUE_SIZE as u32, base, base + 0x1000, base + 0x2000));
        }
        (Rig { mem, _ram: ram, asked, queues, avail: [0; 4], used: [0; 4] }, p)
    }

    impl Rig {
        /// How many keys the kernel was asked.
        fn nasked(&self) -> usize {
            self.asked.borrow().len()
        }
        fn ring(q: usize) -> u64 {
            RING + 0x4000 * q as u64
        }
        fn buf(q: usize, slot: u16) -> u64 {
            BUFS + (q as u64 * QUEUE_SIZE as u64 + (slot % QUEUE_SIZE) as u64) * BUF
        }
        /// Offer queue `q` a buffer of `len` bytes (`data` in it, for the
        /// device to read; empty, for it to write).
        fn offer(&mut self, q: usize, data: &[u8], len: usize) -> u64 {
            let slot = self.avail[q];
            let gpa = Self::buf(q, slot);
            assert!(self.mem.write_bytes(gpa, data));
            let d = Self::ring(q) + 16 * (slot % QUEUE_SIZE) as u64;
            self.mem.write::<u64>(d, gpa);
            self.mem.write::<u32>(d + 8, len as u32);
            self.mem.write::<u16>(d + 12, if data.is_empty() { 2 } else { 0 });
            self.mem.write::<u16>(Self::ring(q) + 0x1000 + 4 + 2 * (slot % QUEUE_SIZE) as u64, slot % QUEUE_SIZE);
            self.avail[q] = slot.wrapping_add(1);
            self.mem.write::<u16>(Self::ring(q) + 0x1000 + 2, self.avail[q]);
            gpa
        }
        /// The buffers the device returned on queue `q` since last asked:
        /// each one's bytes written.
        fn returned(&mut self, q: usize) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            let idx: u16 = self.mem.read(Self::ring(q) + 0x2000 + 2);
            while self.used[q] != idx {
                let e = Self::ring(q) + 0x2000 + 4 + 8 * (self.used[q] % QUEUE_SIZE) as u64;
                let (head, n): (u32, u32) = (self.mem.read(e), self.mem.read(e + 4));
                let mut b = std::vec![0u8; n as usize];
                assert!(self.mem.read_bytes(Self::buf(q, head as u16), &mut b));
                out.push(b);
                self.used[q] = self.used[q].wrapping_add(1);
            }
            out
        }
        fn turn(&mut self, p: &mut Port<impl FnMut(u64) -> Result<u64, i32>>) -> u64 {
            p.kick(&self.mem, &mut self.queues, 0)
        }
        fn control(&mut self, p: &mut Port<impl FnMut(u64) -> Result<u64, i32>>, event: u16, value: u16) {
            let mut m = [0u8; 8];
            m[4..6].copy_from_slice(&event.to_le_bytes());
            m[6..8].copy_from_slice(&value.to_le_bytes());
            self.offer(CTL_TX, &m, 8);
            self.turn(p);
        }
        /// The driver's side of bringing the port up, userspace's open
        /// included; buffers for answers.
        fn up(&mut self, p: &mut Port<impl FnMut(u64) -> Result<u64, i32>>) {
            for _ in 0..4 {
                self.offer(CTL_RX, &[], 64);
            }
            self.control(p, DEVICE_READY, 1);
            self.control(p, PORT_READY, 1);
            let msgs = self.returned(CTL_RX);
            assert_eq!(msgs.len(), 3);
            assert_eq!(msgs[0], [0, 0, 0, 0, 1, 0, 1, 0], "PORT_ADD");
            assert_eq!((&msgs[1][..8], &msgs[1][8..]), (&[0, 0, 0, 0, 7, 0, 1, 0][..], &b"l4h.kconfig"[..]), "PORT_NAME");
            assert_eq!(msgs[2], [0, 0, 0, 0, 6, 0, 1, 0], "PORT_OPEN");
            for _ in 0..8 {
                self.offer(RX, &[], BUF as usize);
            }
            self.control(p, PORT_OPEN, 1);
        }
        fn request(key: u64) -> Vec<u8> {
            Self::raw(abi::KCONFIG_PORT_MAGIC, 0, key)
        }
        fn raw(magic: u32, reserved: u32, key: u64) -> Vec<u8> {
            let mut r = Vec::new();
            r.extend_from_slice(&magic.to_le_bytes());
            r.extend_from_slice(&reserved.to_le_bytes());
            r.extend_from_slice(&key.to_le_bytes());
            r
        }
        /// Userspace writes `bytes`.
        fn write(&mut self, p: &mut Port<impl FnMut(u64) -> Result<u64, i32>>, bytes: &[u8]) {
            self.offer(TX, bytes, bytes.len());
            self.turn(p);
        }
        /// What userspace reads: the answers' (status, value).
        fn read(&mut self) -> Vec<(i32, u64)> {
            let stream: Vec<u8> = self.returned(RX).concat();
            assert_eq!(stream.len() % RESP, 0, "whole answers");
            stream.chunks(RESP).map(|a| {
                assert_eq!(u32::from_le_bytes(a[0..4].try_into().unwrap()), abi::KCONFIG_PORT_MAGIC);
                assert_eq!(&a[16..24], &[0; 8], "reserved");
                (i32::from_le_bytes(a[4..8].try_into().unwrap()), u64::from_le_bytes(a[8..16].try_into().unwrap()))
            }).collect()
        }
    }

    #[test]
    fn the_port_comes_up_named() {
        let (mut rig, mut p) = rig();
        assert_eq!((p.device_type(), p.num_queues(), p.features()), (3, 4, 2));
        assert_eq!(p.config(), [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        rig.up(&mut p);
        assert!(!p.event_idx());
        assert_eq!(p.complete(&rig.mem, &mut rig.queues), 0, "no backend");
        // Without named ports there is no port to use, and what its
        // console writes is dropped, not left for it to wait on.
        let (mut rig, mut p) = self::rig();
        p.features_accepted(0);
        rig.offer(CTL_RX, &[], 64);
        rig.control(&mut p, DEVICE_READY, 1);
        assert!(rig.returned(CTL_RX).is_empty());
        rig.write(&mut p, &Rig::request(1));
        assert_eq!(rig.returned(TX).len(), 1);
        assert!(rig.asked.borrow().is_empty());
    }

    #[test]
    fn requests_and_their_answers() {
        let (mut rig, mut p) = rig();
        rig.up(&mut p);
        rig.write(&mut p, &Rig::request(0x0306));
        assert_eq!(rig.read(), [(0, 0x0306 * 3)]);
        // A key the kernel does not know, a kernel without the call, and
        // what is no errno (the kernel's failure): as the host says, or EIO.
        for (key, status) in [(0x2000, -2), (0x7777, -38), (0x8888, -5)] {
            rig.write(&mut p, &Rig::request(key));
            assert_eq!(rig.read(), [(status, 0)]);
        }
        // Many in a row, each answered before the next is read.
        for k in 1..=20u64 {
            rig.offer(RX, &[], BUF as usize);
            rig.write(&mut p, &Rig::request(k));
        }
        assert_eq!(rig.read(), (1..=20u64).map(|k| (0, k * 3)).collect::<Vec<_>>());
        assert_eq!(rig.nasked(), 24);
        assert_eq!(rig.returned(TX).len(), 24);
    }

    #[test]
    fn requests_in_pieces_and_answers_in_small_buffers() {
        let (mut rig, mut p) = rig();
        for _ in 0..4 {
            rig.offer(CTL_RX, &[], 64);
        }
        rig.control(&mut p, DEVICE_READY, 1);
        rig.control(&mut p, PORT_READY, 1);
        rig.control(&mut p, PORT_OPEN, 1);
        // Three bytes at a time.
        let req = Rig::request(0x0409);
        for piece in req.chunks(3) {
            assert!(rig.asked.borrow().is_empty());
            rig.write(&mut p, piece);
        }
        assert_eq!(*rig.asked.borrow(), [0x0409]);
        // The answer, as the guest finds buffers for it: 5 bytes each.
        assert!(rig.returned(RX).is_empty());
        for _ in 0..3 {
            rig.offer(RX, &[], 5);
        }
        rig.turn(&mut p);
        // The next request waits for the answer to be with the guest.
        rig.write(&mut p, &Rig::request(5));
        assert_eq!((rig.nasked(), rig.returned(TX).len()), (1, 6));
        for _ in 0..2 {
            rig.offer(RX, &[], 5);
        }
        rig.turn(&mut p);
        assert_eq!(rig.read(), [(0, 0x0409 * 3)]);
        // The next request is read in the same turn, and its answer
        // waits for a buffer.
        assert_eq!((rig.nasked(), rig.returned(TX).len()), (2, 1));
        rig.offer(RX, &[], BUF as usize);
        rig.turn(&mut p);
        assert_eq!(rig.read(), [(0, 15)]);
    }

    #[test]
    fn what_is_no_request() {
        let (mut rig, mut p) = rig();
        rig.up(&mut p);
        // Without the magic: refused, and the stream with it, until the
        // port is opened again.
        rig.write(&mut p, &Rig::raw(0x4148_344c, 0, 1));
        assert_eq!(rig.read(), [(EINVAL, 0)]);
        rig.write(&mut p, &Rig::request(1));
        assert!(rig.read().is_empty());
        assert!(rig.asked.borrow().is_empty());
        rig.control(&mut p, PORT_OPEN, 0);
        rig.control(&mut p, PORT_OPEN, 1);
        rig.write(&mut p, &Rig::request(1));
        assert_eq!(rig.read(), [(0, 3)]);
        // Reserved bits set: the same.
        rig.write(&mut p, &Rig::raw(abi::KCONFIG_PORT_MAGIC, 1, 2));
        assert_eq!(rig.read(), [(EINVAL, 0)]);
        rig.write(&mut p, &Rig::request(2));
        assert!(rig.read().is_empty());
        rig.control(&mut p, PORT_OPEN, 1);
        // Two requests in one write: the first is answered, the stream
        // after it nobody's.
        let mut two = Rig::request(3);
        two.extend(Rig::request(4));
        rig.write(&mut p, &two);
        assert_eq!(rig.read(), [(0, 9)]);
        rig.write(&mut p, &Rig::request(5));
        assert!(rig.read().is_empty());
        assert_eq!(*rig.asked.borrow(), [1, 3]);
        // A buffer that is not RAM: returned, and nothing asked.
        rig.control(&mut p, PORT_OPEN, 1);
        let d = Rig::ring(TX) + 16 * (rig.avail[TX] % QUEUE_SIZE) as u64;
        rig.offer(TX, &[1], REQ);
        rig.mem.write::<u64>(d, 0xc000_0000);
        rig.returned(TX);
        rig.turn(&mut p);
        assert_eq!((rig.nasked(), rig.returned(TX).len()), (2, 1));
        rig.control(&mut p, PORT_OPEN, 1);
        rig.write(&mut p, &Rig::request(6));
        assert_eq!(rig.read(), [(0, 18)]);
    }

    #[test]
    fn closing_the_port_drops_what_was_asked() {
        let (mut rig, mut p) = rig();
        rig.up(&mut p);
        // An answer with no buffer to go in, then closed and opened by
        // another: not its to read.
        while rig.queues[RX].has_avail(&rig.mem) {
            rig.write(&mut p, &Rig::request(1));
        }
        rig.read();
        rig.write(&mut p, &Rig::request(7));
        rig.control(&mut p, PORT_OPEN, 0);
        rig.control(&mut p, PORT_OPEN, 1);
        rig.offer(RX, &[], BUF as usize);
        rig.write(&mut p, &Rig::request(8));
        assert_eq!(rig.read(), [(0, 24)]);
        // Half a request, then closed: the next one starts clean.
        rig.offer(RX, &[], BUF as usize);
        rig.write(&mut p, &Rig::request(9)[..10]);
        rig.control(&mut p, PORT_OPEN, 0);
        rig.control(&mut p, PORT_OPEN, 1);
        rig.write(&mut p, &Rig::request(10));
        assert_eq!(rig.read(), [(0, 30)]);
        // Written before an open and unread (an answer waiting for its
        // buffer): thrown away at the open, never read.
        rig.write(&mut p, &Rig::request(11));
        rig.write(&mut p, &Rig::request(12));
        let before = rig.nasked();
        rig.returned(TX);
        rig.control(&mut p, PORT_OPEN, 1);
        assert_eq!(rig.returned(TX).len(), 1, "thrown away at the open");
        rig.offer(RX, &[], BUF as usize);
        rig.write(&mut p, &Rig::request(13));
        assert_eq!(rig.read(), [(0, 39)]);
        assert_eq!(rig.asked.borrow()[before..], [13]);
        // The driver resets the device: the port comes up again.
        rig.write(&mut p, &Rig::request(14)[..4]);
        p.reset();
        p.features_accepted(VIRTIO_CONSOLE_F_MULTIPORT);
        rig.offer(CTL_RX, &[], 64);
        rig.offer(CTL_RX, &[], 64);
        rig.offer(CTL_RX, &[], 64);
        rig.control(&mut p, DEVICE_READY, 1);
        rig.control(&mut p, PORT_READY, 1);
        assert_eq!(rig.returned(CTL_RX).len(), 3);
        rig.control(&mut p, PORT_OPEN, 1);
        rig.offer(RX, &[], BUF as usize);
        rig.write(&mut p, &Rig::request(15));
        assert_eq!(rig.read(), [(0, 45)]);
    }

    #[test]
    fn a_turn_is_bounded() {
        let (mut rig, mut p) = rig();
        rig.up(&mut p);
        rig.returned(CTL_TX);
        // A queue full of control messages is a turn's worth: the request
        // written meanwhile is the next turn's, which `more` asks for.
        for _ in 0..QUEUE_SIZE {
            let mut m = [0u8; 8];
            m[4] = 9;
            rig.offer(CTL_TX, &m, 8);
        }
        rig.offer(TX, &Rig::request(1), REQ);
        rig.turn(&mut p);
        assert_eq!((rig.returned(CTL_TX).len(), rig.nasked()), (QUEUE_SIZE as usize, 0));
        assert_eq!((p.more(), p.retry()), (1 << TX, 1 << TX));
        rig.turn(&mut p);
        assert_eq!((p.more(), rig.nasked()), (0, 1));
        assert_eq!(rig.read(), [(0, 3)]);
    }

    #[test]
    fn an_open_drops_only_what_was_written_before_it() {
        let (mut rig, mut p) = rig();
        rig.up(&mut p);
        rig.returned(CTL_TX);
        // One's request, unread when another's open is taken at the end
        // of a turn's worth of control messages: TX is thrown away to
        // there in the next turn, before the opener's request is read.
        rig.offer(TX, &Rig::request(1), REQ);
        for _ in 1..QUEUE_SIZE {
            let mut m = [0u8; 8];
            m[4] = 9;
            rig.offer(CTL_TX, &m, 8);
        }
        rig.control(&mut p, PORT_OPEN, 1);
        assert_eq!((rig.returned(CTL_TX).len(), rig.returned(TX).len(), p.more()), (QUEUE_SIZE as usize, 0, 1 << TX));
        rig.write(&mut p, &Rig::request(2));
        assert_eq!((rig.returned(TX).len(), p.more()), (2, 0));
        assert_eq!((rig.read(), rig.asked.borrow().clone()), (std::vec![(0, 6)], std::vec![2]));
    }

    #[test]
    fn queues_the_driver_has_not_set_up() {
        // RAM away from GPA 0, and of the queues the control ones alone:
        // an open is taken, with no TX to look into.
        let base = 0x4000_0000;
        let (mem, _ram) = crate::mem::tests::fake_at(base, 8 << 20);
        let mut p = Port::new(|_| Ok(0));
        let mut queues: [Queue; 4] = Default::default();
        let ring = base + 0x1_0000;
        assert!(queues[CTL_TX].setup(&mem, 64, 64, ring, ring + 0x1000, ring + 0x2000));
        let send = |p: &mut Port<_>, queues: &mut [Queue; 4], n: u16, event: u16| {
            let mut m = [0u8; 8];
            m[4..6].copy_from_slice(&event.to_le_bytes());
            m[6] = 1;
            assert!(mem.write_bytes(base + 0x10_0000 + 16 * n as u64, &m));
            mem.write::<u64>(ring + 16 * n as u64, base + 0x10_0000 + 16 * n as u64);
            mem.write::<u32>(ring + 16 * n as u64 + 8, 8);
            mem.write::<u16>(ring + 16 * n as u64 + 12, 0);
            mem.write::<u16>(ring + 0x1000 + 4 + 2 * n as u64, n);
            mem.write::<u16>(ring + 0x1000 + 2, n + 1);
            p.kick(&mem, queues, CTL_TX)
        };
        assert_eq!(send(&mut p, &mut queues, 0, DEVICE_READY), 0);
        p.features_accepted(VIRTIO_CONSOLE_F_MULTIPORT);
        assert_eq!(send(&mut p, &mut queues, 1, DEVICE_READY), 1 << CTL_TX);
        assert_eq!(send(&mut p, &mut queues, 2, PORT_OPEN), 1 << CTL_TX);
        assert_eq!((p.flush, p.more(), mem.read::<u16>(ring + 0x2000 + 2)), (None, 0, 3));
    }
}
