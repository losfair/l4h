//! The attestation port (DESIGN.md §5.11, abi.h L4H_ATTEST_PORT_*): a
//! virtio-console device with one port, named "l4h.attest", through which
//! the userspace of a guest that holds no capability makes the requests of
//! an attestation device (abi::AttestPage, DESIGN.md §10.2).  An unmodified
//! kernel's own driver gives it as a character device, under any lockdown.
//!
//! The port carries requests and their answers, one at a time: a request
//! is a header (abi::AttestPortReq) and its data, which goes into trustd's
//! page for the guest (`host`) under a sequence number of our own, with a
//! kick; when trustd has answered (`complete`, on vmmgr's signal), the
//! answer goes back as a header (abi::AttestPortResp) and its data.  The
//! next request is read once the answer is with the guest.  Closing or
//! opening the port starts again: what was being read or answered is
//! dropped, with what had been written when we took the driver's message
//! and not yet read.  The driver's open waits for that message's buffer
//! to come back, and what is written after it is the new opener's: so
//! how far the queue is thrown away (`flush`) is read before the buffer
//! is returned, never after.
//!
//! The guest is notified of nothing but used buffers, and notifies us of
//! every buffer it adds (no event index: a request is a few buffers).  A
//! turn takes a bounded number of them (`BUDGET`), and says which queues
//! it left some in (`more`), so that a guest filling its queues does not
//! keep the I/O thread from its disks.
//!
//! The port is userspace's, so what only a guest kernel may ask is
//! refused here (flag bits 64-127, DESIGN.md §10.2).  Nothing here is
//! trusted by trustd, which reads its page as a guest's own; what is
//! copied either way is bounded by the page.  Only the I/O thread touches
//! it.  Free of seL4.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

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

const REQ: usize = core::mem::size_of::<abi::AttestPortReq>();
const RESP: usize = core::mem::size_of::<abi::AttestPortResp>();
const DATA: usize = abi::ATTEST_PAGE_DATA;
const EPERM: i32 = -1;
const EIO: i32 = -5;
const EINVAL: i32 = -22;
/// The flag bits a guest kernel acts on (abi.h: 64 + Linux's taints), as
/// bytes of a bitmap.
const KERNEL_BITS: core::ops::Range<usize> = abi::FLAG_GUEST / 8..abi::FLAG_USER / 8;

type Chain = ArrayVec<Buf, { QUEUE_SIZE as usize }>;

pub struct Port<K: FnMut()> {
    /// trustd's request page for the guest.
    host: *mut abi::AttestPage,
    /// Kick trustd.
    kick: K,
    config: [u8; 12],
    multiport: bool,
    /// Control messages owed to the driver (SEND_*).
    ctl: u8,
    /// The request being read: its header, then its data.
    req: [u8; REQ + DATA],
    req_len: usize,
    /// The port's stream is no request's (a bad header, bytes after a
    /// request): nothing more is read until it is opened again.
    broken: bool,
    /// The last sequence number given to trustd, and whether trustd has
    /// that request: its answer is the port's, or (`abandoned`) nobody's.
    host_seq: u32,
    busy: bool,
    abandoned: bool,
    /// The answer being written: `resp_len` bytes, `resp_done` of them
    /// with the guest.
    resp: [u8; RESP + DATA],
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

impl<K: FnMut()> Port<K> {
    /// `host` is trustd's page, mapped for good; `kick` signals trustd.
    pub fn new(host: *mut abi::AttestPage, kick: K) -> Self {
        // No console size; one port; no emergency write.
        let mut config = [0; 12];
        config[4..8].copy_from_slice(&1u32.to_le_bytes());
        // The first request's sequence number is past what the page has.
        let host_seq = unsafe { addr_of!((*host).seq).read_volatile() };
        Port {
            host, kick, config, multiport: false, ctl: 0, req: [0; REQ + DATA], req_len: 0, broken: false, host_seq,
            busy: false, abandoned: false, resp: [0; RESP + DATA], resp_len: 0, resp_done: 0, flush: None, budget: 0, more: 0,
        }
    }

    fn host_state(&self) -> u32 {
        unsafe { addr_of!((*self.host).state).read_volatile() }
    }

    /// The stream starts again (the port was opened or closed, the device
    /// reset): no request is half read, no answer owed.  One trustd
    /// still has is nobody's when it comes.
    fn restart(&mut self) {
        self.req_len = 0;
        self.broken = false;
        self.resp_len = 0;
        self.resp_done = 0;
        self.abandoned = self.busy;
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
    /// the queue up (it may notify another queue first, and an index is
    /// read only where the queue's rings are).
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
            // None with budget left: the driver took its index back, and
            // there is nothing before `to` to wait for.
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
    /// (an open comes before what is written after it), ours, trustd's
    /// answer, the answer's way to the guest, the next request.  The
    /// queues used buffers went into.
    fn turn(&mut self, mem: &GuestMem, queues: &mut [Queue]) -> u64 {
        let mut used = 0;
        self.budget = BUDGET;
        self.more = 0;
        let (port, ctl) = queues.split_at_mut(CTL_RX);
        if self.control_in(mem, &mut ctl[CTL_TX - CTL_RX], &port[TX]) {
            used |= 1 << CTL_TX;
        }
        // What was written before the open or close taken (in this turn
        // or an earlier one) was another's, or nobody's: all of it,
        // before anything is read, and nothing written since.
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
        self.answered();
        // An answer made here (a request refused) goes out in the same
        // turn, and the request after it is read.
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
                fence(Ordering::SeqCst);
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
                (SEND_NAME, PORT_NAME, abi::ATTEST_PORT_NAME)
            } else {
                (SEND_OPEN, PORT_OPEN, &b""[..])
            };
            let mut msg = [0u8; CTL_LEN + abi::ATTEST_PORT_NAME.len()];
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

    /// trustd may have answered: its answer becomes the port's, unless it
    /// is nobody's.
    fn answered(&mut self) {
        if !self.busy {
            return;
        }
        let h = self.host;
        let done = unsafe { addr_of!((*h).done).read_volatile() };
        fence(Ordering::Acquire);
        let state = self.host_state();
        if done != self.host_seq && state & abi::ATTEST_FAILED == 0 {
            return;
        }
        self.busy = false;
        if core::mem::take(&mut self.abandoned) {
            return;
        }
        if done != self.host_seq {
            // trustd failed, and no answer comes.
            self.answer(EIO, 0, &[]);
            return;
        }
        let (status, total, n) = unsafe {
            (addr_of!((*h).status).read_volatile(), addr_of!((*h).total).read_volatile(), addr_of!((*h).out_len).read_volatile())
        };
        let n = (n as usize).min(DATA);
        unsafe {
            let src = addr_of!((*h).data) as *const u8;
            for i in 0..n {
                self.resp[RESP + i] = src.add(i).read_volatile();
            }
        }
        self.answer_header(status, total, n);
    }

    /// The answer to the request just read is `status` and `data`.
    fn answer(&mut self, status: i32, total: u32, data: &[u8]) {
        self.resp[RESP..RESP + data.len()].copy_from_slice(data);
        self.answer_header(status, total, data.len());
    }

    /// The answer's header, its `n` bytes of data being in place.
    fn answer_header(&mut self, status: i32, total: u32, n: usize) {
        let words = [abi::ATTEST_PORT_MAGIC, status as u32, total, n as u32, self.host_state()];
        for (i, w) in words.iter().enumerate() {
            self.resp[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
        self.resp_len = RESP + n;
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

    /// Read the guest's next request, if none is being answered: whether
    /// any chain was returned, and whether a request was read whole (it
    /// is then trustd's, or answered here).
    fn read_request(&mut self, mem: &GuestMem, q: &mut Queue) -> (bool, bool) {
        let mut chain = Chain::new();
        let mut any = false;
        let mut asked = false;
        // One request at a time: the rest waits in the queue.
        while !asked && !self.busy && self.resp_len == 0 {
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
            // The header says how much follows it.
            let want = if self.req_len < REQ { REQ } else { REQ + self.in_len() };
            let take = (b.len as usize - at).min(want - self.req_len);
            if !mem.read_bytes(b.gpa + at as u64, &mut self.req[self.req_len..self.req_len + take]) {
                self.broken = true;
                break;
            }
            self.req_len += take;
            at += take;
            if self.req_len == REQ && (self.word(0) != abi::ATTEST_PORT_MAGIC || self.in_len() > DATA) {
                // Not a request, or one longer than any: answered once,
                // and nothing after it is read.
                self.req_len = 0;
                self.broken = true;
                self.answer(EINVAL, 0, &[]);
                return true;
            }
            if self.req_len >= REQ && self.req_len == REQ + self.in_len() {
                self.submit();
                asked = true;
            }
        }
        asked
    }

    /// Word `i` of the request's header.
    fn word(&self, i: usize) -> u32 {
        u32::from_le_bytes(self.req[4 * i..4 * i + 4].try_into().unwrap())
    }

    fn in_len(&self) -> usize {
        self.word(3) as usize
    }

    /// The request in `req` is whole: to trustd, or answered here.
    fn submit(&mut self) {
        let (op, offset, in_len, blob_len) = (self.word(1), self.word(2), self.in_len(), self.word(4));
        self.req_len = 0;
        // Once trustd has failed (root said so in its page, and took the
        // kick away) nothing else would ever answer.
        if self.host_state() & abi::ATTEST_FAILED != 0 {
            return self.answer(EIO, 0, &[]);
        }
        // What a guest kernel records of itself is not userspace's to say.
        let kernel = self.req[REQ..REQ + in_len].get(KERNEL_BITS).is_some_and(|k| k.iter().any(|&b| b != 0));
        if op == abi::ATTEST_ACT && kernel {
            return self.answer(EPERM, 0, &[]);
        }
        self.host_seq = match self.host_seq.wrapping_add(1) {
            0 => 1,
            s => s,
        };
        let h = self.host;
        unsafe {
            addr_of_mut!((*h).op).write_volatile(op);
            addr_of_mut!((*h).offset).write_volatile(offset);
            addr_of_mut!((*h).in_len).write_volatile(in_len as u32);
            addr_of_mut!((*h).blob_len).write_volatile(blob_len);
            let dst = addr_of_mut!((*h).data) as *mut u8;
            for (i, &b) in self.req[REQ..REQ + in_len].iter().enumerate() {
                dst.add(i).write_volatile(b);
            }
            fence(Ordering::Release);
            addr_of_mut!((*h).seq).write_volatile(self.host_seq);
        }
        self.busy = true;
        self.abandoned = false;
        (self.kick)();
    }
}

impl<K: FnMut()> Backend for Port<K> {
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

    fn complete(&mut self, mem: &GuestMem, queues: &mut [Queue]) -> u64 {
        if !self.multiport {
            return 0;
        }
        self.turn(mem, queues)
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
    use std::boxed::Box;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::vec::Vec;

    // Each queue's rings, and where the test puts buffers.
    const RING: u64 = 0x1_0000;
    const BUFS: u64 = 0x10_0000;
    const BUF: u64 = 0x1000;

    struct Rig {
        mem: GuestMem,
        _ram: Vec<u8>,
        host: Box<abi::AttestPage>,
        kicks: Rc<Cell<usize>>,
        queues: [Queue; 4],
        avail: [u16; 4],
        used: [u16; 4],
    }

    fn rig() -> (Rig, Port<impl FnMut()>) {
        let (mem, ram) = fake(8 << 20, 0);
        let mut host: Box<abi::AttestPage> = unsafe { Box::new(core::mem::zeroed()) };
        let kicks = Rc::new(Cell::new(0));
        let k = kicks.clone();
        let mut p = Port::new(&mut *host as *mut abi::AttestPage, move || k.set(k.get() + 1));
        p.features_accepted(VIRTIO_CONSOLE_F_MULTIPORT);
        let mut queues: [Queue; 4] = Default::default();
        for (i, q) in queues.iter_mut().enumerate() {
            let base = RING + 0x4000 * i as u64;
            assert!(q.setup(&mem, QUEUE_SIZE as u32, QUEUE_SIZE as u32, base, base + 0x1000, base + 0x2000));
        }
        (Rig { mem, _ram: ram, host, kicks, queues, avail: [0; 4], used: [0; 4] }, p)
    }

    impl Rig {
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
        fn turn(&mut self, p: &mut Port<impl FnMut()>) -> u64 {
            p.kick(&self.mem, &mut self.queues, 0)
        }
        fn control(&mut self, p: &mut Port<impl FnMut()>, event: u16, value: u16) {
            let mut m = [0u8; 8];
            m[4..6].copy_from_slice(&event.to_le_bytes());
            m[6..8].copy_from_slice(&value.to_le_bytes());
            self.offer(CTL_TX, &m, 8);
            self.turn(p);
        }
        /// The driver's side of bringing the port up, userspace's open
        /// included; buffers for answers.
        fn up(&mut self, p: &mut Port<impl FnMut()>) {
            for _ in 0..4 {
                self.offer(CTL_RX, &[], 64);
            }
            self.control(p, DEVICE_READY, 1);
            self.control(p, PORT_READY, 1);
            let msgs = self.returned(CTL_RX);
            assert_eq!(msgs.len(), 3);
            assert_eq!(msgs[0], [0, 0, 0, 0, 1, 0, 1, 0], "PORT_ADD");
            assert_eq!((&msgs[1][..8], &msgs[1][8..]), (&[0, 0, 0, 0, 7, 0, 1, 0][..], &b"l4h.attest"[..]), "PORT_NAME");
            assert_eq!(msgs[2], [0, 0, 0, 0, 6, 0, 1, 0], "PORT_OPEN");
            for _ in 0..8 {
                self.offer(RX, &[], BUF as usize);
            }
            self.control(p, PORT_OPEN, 1);
        }
        fn request(op: u32, offset: u32, blob_len: u32, data: &[u8]) -> Vec<u8> {
            let mut r = Vec::new();
            for w in [abi::ATTEST_PORT_MAGIC, op, offset, data.len() as u32, blob_len] {
                r.extend_from_slice(&w.to_le_bytes());
            }
            r.extend_from_slice(data);
            r
        }
        /// Userspace writes `bytes`.
        fn write(&mut self, p: &mut Port<impl FnMut()>, bytes: &[u8]) {
            self.offer(TX, bytes, bytes.len());
            self.turn(p);
        }
        /// trustd answers what its page holds with `data`.
        fn answer(&mut self, p: &mut Port<impl FnMut()>, status: i32, data: &[u8]) {
            self.host.data[..data.len()].copy_from_slice(data);
            self.host.status = status;
            self.host.total = 1000;
            self.host.out_len = data.len() as u32;
            self.host.state = abi::ATTEST_HAS_TPM;
            self.host.done = self.host.seq;
            p.complete(&self.mem, &mut self.queues);
        }
        /// What userspace reads: the answers' (status, total, state, data).
        fn read(&mut self) -> Vec<(i32, u32, u32, Vec<u8>)> {
            let stream: Vec<u8> = self.returned(RX).concat();
            let mut out = Vec::new();
            let mut at = 0;
            while at < stream.len() {
                let w = |i: usize| u32::from_le_bytes(stream[at + 4 * i..at + 4 * i + 4].try_into().unwrap());
                assert_eq!(w(0), abi::ATTEST_PORT_MAGIC);
                let n = w(3) as usize;
                out.push((w(1) as i32, w(2), w(4), stream[at + RESP..at + RESP + n].to_vec()));
                at += RESP + n;
            }
            out
        }
    }

    #[test]
    fn the_port_comes_up_named() {
        let (mut rig, mut p) = rig();
        assert_eq!((p.device_type(), p.num_queues(), p.features()), (3, 4, 2));
        assert_eq!(p.config(), [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        rig.up(&mut p);
        // The guest is told of every buffer: we never ask again.
        assert!(!p.event_idx());
        // Without named ports there is no port to use, and what its
        // console writes is dropped, not left for it to wait on.
        let (mut rig, mut p) = self::rig();
        p.features_accepted(0);
        rig.offer(CTL_RX, &[], 64);
        rig.control(&mut p, DEVICE_READY, 1);
        assert!(rig.returned(CTL_RX).is_empty());
        rig.write(&mut p, b"console output");
        assert_eq!((rig.returned(TX).len(), rig.kicks.get()), (1, 0));
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
        rig.offer(TX, &Rig::request(abi::ATTEST_EVIDENCE, 0, 0, &[]), REQ);
        rig.turn(&mut p);
        assert_eq!((rig.returned(CTL_TX).len(), rig.kicks.get()), (QUEUE_SIZE as usize, 0));
        // The queue with work left is the one asked for again: a driver
        // need not have enabled any other.
        assert_eq!((p.more(), p.retry()), (1 << TX, 1 << TX));
        rig.turn(&mut p);
        assert_eq!((p.more(), rig.kicks.get(), rig.host.op), (0, 1, abi::ATTEST_EVIDENCE));
    }

    #[test]
    fn an_open_drops_only_what_was_written_before_it() {
        let (mut rig, mut p) = rig();
        rig.up(&mut p);
        rig.returned(CTL_TX);
        // One's request, unread when another's open is taken: the open
        // ends a turn's worth of control messages, so the turn returns
        // its buffer (and the driver's open) with TX still to throw away.
        rig.offer(TX, &Rig::request(abi::ATTEST_REPORT, 0, 0, &[1; 64]), REQ + 64);
        for _ in 1..QUEUE_SIZE {
            let mut m = [0u8; 8];
            m[4] = 9;
            rig.offer(CTL_TX, &m, 8);
        }
        rig.control(&mut p, PORT_OPEN, 1);
        assert_eq!((rig.returned(CTL_TX).len(), rig.returned(TX).len(), p.more()), (QUEUE_SIZE as usize, 0, 1 << TX));
        // The opener writes at once, before our next turn: its request is
        // read, the one before the open is not.
        rig.write(&mut p, &Rig::request(abi::ATTEST_EVIDENCE, 0, 0, &[]));
        assert_eq!((rig.returned(TX).len(), rig.kicks.get(), rig.host.op, p.more()), (2, 1, abi::ATTEST_EVIDENCE, 0));
        rig.answer(&mut p, 0, b"its own");
        assert_eq!(rig.read(), [(0, 1000, abi::ATTEST_HAS_TPM, b"its own".to_vec())]);
        // Where the queue is thrown away to is read before the open's
        // buffer comes back: nothing written after that is before it.
        rig.offer(TX, &[0x41; REQ], REQ);
        let before = rig.avail[TX];
        rig.control(&mut p, PORT_OPEN, 1);
        assert_eq!((rig.returned(TX).len(), rig.queues[TX].last_avail(), rig.read().len()), (1, before, 0));
    }

    #[test]
    fn queues_the_driver_has_not_set_up() {
        // RAM as an AArch64 guest has it, away from GPA 0, and of the
        // queues the control ones alone: an open is taken, with no TX to
        // look into, and nothing is read outside RAM.
        let base = 0x4000_0000;
        let (mem, _ram) = crate::mem::tests::fake_at(base, 8 << 20);
        let mut host: Box<abi::AttestPage> = unsafe { Box::new(core::mem::zeroed()) };
        let mut p = Port::new(&mut *host as *mut abi::AttestPage, || {});
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
        // Without named ports: the console's output queue is not there.
        assert_eq!(send(&mut p, &mut queues, 0, DEVICE_READY), 0);
        p.features_accepted(VIRTIO_CONSOLE_F_MULTIPORT);
        assert_eq!(send(&mut p, &mut queues, 1, DEVICE_READY), 1 << CTL_TX);
        assert_eq!(send(&mut p, &mut queues, 2, PORT_OPEN), 1 << CTL_TX);
        assert_eq!((p.flush, p.more(), mem.read::<u16>(ring + 0x2000 + 2)), (None, 0, 3));
    }

    #[test]
    fn a_request_and_its_answer() {
        let (mut rig, mut p) = rig();
        rig.up(&mut p);
        let req = Rig::request(abi::ATTEST_REPORT, 7, 3, &[0xab; 64]);
        rig.write(&mut p, &req);
        assert_eq!(rig.kicks.get(), 1);
        assert_eq!((rig.host.seq, rig.host.op, rig.host.offset, rig.host.in_len, rig.host.blob_len), (1, abi::ATTEST_REPORT, 7, 64, 3));
        assert_eq!(rig.host.data[..64], [0xab; 64]);
        assert_eq!(rig.returned(TX).len(), 1);
        // The next request waits for the answer: in the queue.
        let next = Rig::request(abi::ATTEST_EVIDENCE, 0, 0, &[]);
        rig.write(&mut p, &next);
        assert_eq!((rig.kicks.get(), rig.returned(TX).len()), (1, 0));
        assert!(rig.read().is_empty());
        rig.answer(&mut p, 0, b"the report");
        assert_eq!(rig.read(), [(0, 1000, abi::ATTEST_HAS_TPM, b"the report".to_vec())]);
        assert_eq!((rig.kicks.get(), rig.host.seq, rig.host.op, rig.returned(TX).len()), (2, 2, abi::ATTEST_EVIDENCE, 1));
        rig.answer(&mut p, -19, &[]);
        assert_eq!(rig.read(), [(-19, 1000, abi::ATTEST_HAS_TPM, Vec::new())]);
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
        // A whole page of data, written 1000 bytes at a time.
        let req = Rig::request(abi::ATTEST_ACTIVATE, 0, 5, &[0x5a; DATA]);
        for piece in req.chunks(1000) {
            assert_eq!(rig.kicks.get(), 0);
            rig.write(&mut p, piece);
        }
        assert_eq!((rig.kicks.get(), rig.host.in_len as usize, rig.host.data[DATA - 1]), (1, DATA, 0x5a));
        // The answer, as the guest finds buffers for it: 9 bytes each.
        rig.answer(&mut p, 0, b"0123456789");
        assert!(rig.returned(RX).is_empty());
        for _ in 0..3 {
            rig.offer(RX, &[], 9);
        }
        rig.turn(&mut p);
        rig.offer(RX, &[], 9);
        rig.turn(&mut p);
        assert_eq!(rig.read(), [(0, 1000, abi::ATTEST_HAS_TPM, b"0123456789".to_vec())]);
        // trustd's lengths are not believed past the page.
        rig.write(&mut p, &Rig::request(abi::ATTEST_EVIDENCE, 0, 0, &[]));
        rig.host.out_len = u32::MAX;
        rig.host.done = rig.host.seq;
        for _ in 0..2 {
            rig.offer(RX, &[], BUF as usize);
        }
        p.complete(&rig.mem, &mut rig.queues);
        assert_eq!(rig.read()[0].3.len(), DATA);
    }

    #[test]
    fn what_is_no_request() {
        let (mut rig, mut p) = rig();
        rig.up(&mut p);
        // A kernel's flag bits are not userspace's to act on; its own are.
        let mut act = [0u8; 36];
        act[9] = 1;
        rig.write(&mut p, &Rig::request(abi::ATTEST_ACT, 0, 0, &act));
        assert_eq!(rig.read(), [(EPERM, 0, 0, Vec::new())]);
        let mut act = [0u8; 32];
        act[16] = 1;
        rig.write(&mut p, &Rig::request(abi::ATTEST_ACT, 0, 0, &act));
        assert_eq!((rig.kicks.get(), rig.host.data[16]), (1, 1));
        rig.answer(&mut p, 0, &[0; 64]);
        assert_eq!(rig.read().len(), 1);
        // More data than a page has: refused, and the stream with it,
        // until the port is opened again.
        let mut long = Rig::request(abi::ATTEST_REPORT, 0, 0, &[]);
        long[12..16].copy_from_slice(&(DATA as u32 + 1).to_le_bytes());
        rig.write(&mut p, &long);
        assert_eq!(rig.read(), [(EINVAL, 0, abi::ATTEST_HAS_TPM, Vec::new())]);
        rig.write(&mut p, &Rig::request(abi::ATTEST_EVIDENCE, 0, 0, &[]));
        assert_eq!((rig.kicks.get(), rig.read().len()), (1, 0));
        rig.control(&mut p, PORT_OPEN, 0);
        rig.control(&mut p, PORT_OPEN, 1);
        // Not a request at all.
        rig.write(&mut p, &[0x41; REQ]);
        assert_eq!(rig.read(), [(EINVAL, 0, abi::ATTEST_HAS_TPM, Vec::new())]);
        rig.control(&mut p, PORT_OPEN, 1);
        // Two requests in one write: the first is trustd's, the stream
        // after it nobody's.
        let mut two = Rig::request(abi::ATTEST_EVIDENCE, 0, 0, &[]);
        two.extend(Rig::request(abi::ATTEST_REPORT, 0, 0, &[0; 64]));
        rig.write(&mut p, &two);
        assert_eq!((rig.kicks.get(), rig.host.op), (2, abi::ATTEST_EVIDENCE));
        rig.answer(&mut p, 0, b"ev");
        assert_eq!(rig.read().len(), 1);
        rig.write(&mut p, &Rig::request(abi::ATTEST_EVIDENCE, 0, 0, &[]));
        assert_eq!(rig.kicks.get(), 2);
        // A buffer that is not RAM: returned, and nothing asked.
        rig.control(&mut p, PORT_OPEN, 1);
        let d = Rig::ring(TX) + 16 * (rig.avail[TX] % QUEUE_SIZE) as u64;
        rig.offer(TX, &[1], REQ);
        rig.mem.write::<u64>(d, 0xc000_0000);
        rig.returned(TX);
        rig.turn(&mut p);
        assert_eq!((rig.kicks.get(), rig.returned(TX).len()), (2, 1));
    }

    #[test]
    fn closing_the_port_drops_what_was_asked() {
        let (mut rig, mut p) = rig();
        rig.up(&mut p);
        rig.write(&mut p, &Rig::request(abi::ATTEST_REPORT, 0, 0, &[1; 64]));
        // Closed and opened by another: the answer is not its to read,
        // and its own request waits for trustd to be free.
        rig.control(&mut p, PORT_OPEN, 0);
        rig.control(&mut p, PORT_OPEN, 1);
        rig.write(&mut p, &Rig::request(abi::ATTEST_EVIDENCE, 0, 0, &[]));
        assert_eq!((rig.kicks.get(), rig.host.op), (1, abi::ATTEST_REPORT));
        rig.answer(&mut p, 0, b"old");
        assert!(rig.read().is_empty());
        assert_eq!((rig.kicks.get(), rig.host.seq, rig.host.op), (2, 2, abi::ATTEST_EVIDENCE));
        rig.answer(&mut p, 0, b"new");
        assert_eq!(rig.read(), [(0, 1000, abi::ATTEST_HAS_TPM, b"new".to_vec())]);
        // Half a request, then closed: the next one starts clean.
        rig.write(&mut p, &Rig::request(abi::ATTEST_REPORT, 0, 0, &[1; 64])[..30]);
        rig.control(&mut p, PORT_OPEN, 0);
        rig.control(&mut p, PORT_OPEN, 1);
        rig.write(&mut p, &Rig::request(abi::ATTEST_SEAL, 0, 0, &[0; 32]));
        assert_eq!((rig.kicks.get(), rig.host.op, rig.host.in_len), (3, abi::ATTEST_SEAL, 32));
        rig.answer(&mut p, 0, &[7; 100]);
        assert_eq!(rig.read().len(), 1);
        // What one wrote and left unread by us (trustd busy with another's)
        // is not the next one's request: its answer would be.
        rig.write(&mut p, &Rig::request(abi::ATTEST_EVIDENCE, 0, 0, &[]));
        rig.control(&mut p, PORT_OPEN, 0);
        rig.control(&mut p, PORT_OPEN, 1);
        rig.returned(TX);
        rig.write(&mut p, &Rig::request(abi::ATTEST_REPORT, 0, 0, &[9; 64]));
        assert_eq!((rig.kicks.get(), rig.returned(TX).len()), (4, 0), "it waits in the queue");
        rig.control(&mut p, PORT_OPEN, 0);
        assert_eq!(rig.returned(TX).len(), 1, "thrown away at the close");
        rig.control(&mut p, PORT_OPEN, 1);
        rig.answer(&mut p, 0, b"nobody's");
        assert!(rig.read().is_empty());
        assert_eq!((rig.kicks.get(), rig.host.op), (4, abi::ATTEST_EVIDENCE));
        rig.write(&mut p, &Rig::request(abi::ATTEST_SEAL, 0, 0, &[0; 32]));
        assert_eq!((rig.kicks.get(), rig.host.op), (5, abi::ATTEST_SEAL));
        rig.answer(&mut p, 0, &[0; 64]);
        assert_eq!(rig.read().len(), 1);
        // The driver resets the device with a request at trustd: its
        // answer is nobody's, and the device comes up again.
        rig.write(&mut p, &Rig::request(abi::ATTEST_EVIDENCE, 0, 0, &[]));
        assert_eq!(rig.kicks.get(), 6);
        p.reset();
        p.features_accepted(VIRTIO_CONSOLE_F_MULTIPORT);
        rig.host.done = rig.host.seq;
        rig.control(&mut p, DEVICE_READY, 1);
        assert!(rig.read().is_empty());
        rig.control(&mut p, PORT_READY, 1);
        rig.control(&mut p, PORT_OPEN, 1);
        rig.write(&mut p, &Rig::request(abi::ATTEST_EVIDENCE, 0, 0, &[]));
        assert_eq!((rig.kicks.get(), rig.host.seq), (7, 7));
    }

    #[test]
    fn trustd_fails() {
        let (mut rig, mut p) = rig();
        rig.up(&mut p);
        rig.write(&mut p, &Rig::request(abi::ATTEST_REPORT, 0, 0, &[1; 64]));
        // With a request outstanding: answered -EIO, the state saying why.
        rig.host.state = abi::ATTEST_FAILED;
        p.complete(&rig.mem, &mut rig.queues);
        assert_eq!(rig.read(), [(EIO, 0, abi::ATTEST_FAILED, Vec::new())]);
        // Requests from then on are answered here, trustd's kick gone.
        rig.write(&mut p, &Rig::request(abi::ATTEST_ACT, 0, 0, &[0; 32]));
        assert_eq!(rig.read(), [(EIO, 0, abi::ATTEST_FAILED, Vec::new())]);
        assert_eq!((rig.kicks.get(), rig.host.seq), (1, 1));
        // And while nothing was asked: root's notice finds no request.
        let (mut rig, mut p) = self::rig();
        rig.up(&mut p);
        rig.host.state = abi::ATTEST_FAILED;
        p.complete(&rig.mem, &mut rig.queues);
        assert!(rig.read().is_empty());
        rig.write(&mut p, &Rig::request(abi::ATTEST_REPORT, 0, 0, &[1; 64]));
        assert_eq!(rig.read(), [(EIO, 0, abi::ATTEST_FAILED, Vec::new())]);
        assert_eq!((rig.kicks.get(), rig.host.seq), (0, 0));
    }
}
