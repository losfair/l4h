//! The relay between partitions' trustds (multikernel, DESIGN.md §10.2):
//! a secondary's trustd has no TPM, so the primary's quotes its key and
//! runs its ActivateCredential.  Messages go through root and the control
//! channel, which can lose them and never wait: each request has an id,
//! the secondary sends it again until the answer with that id comes or it
//! gives up, and the primary answers a repeated id from what it kept,
//! without using the TPM again.
//!
//! A secondary never waits for an answer: it has one request out at a
//! time and goes on serving guests (the ones that need the answer wait
//! for it), and root kicks it on its timer meanwhile.  So a dead primary
//! costs only reports, after a bounded wait.

use core::sync::atomic::{Ordering, fence};

use l4h_rt::host::errno::Errno;
use l4h_rt::host::trust::{self, RELAY_HEADER, RELAY_SLOT_HEADER, RelayHeader, RelaySlot};
use l4h_rt::host;

/// What a request is for.
#[derive(Clone, Copy)]
pub enum Wait {
    /// Our key's quote: the answer is our evidence.
    Key,
    /// Guest `id` (instance `instance`) asked for ActivateCredential in
    /// its request `seq`.
    Activate { id: usize, instance: u64, seq: u32 },
}

/// The request out, at a secondary.
struct Pending {
    head: RelayHeader,
    what: Wait,
    every: u64,
    next_send: u64,
    deadline: u64,
}

pub struct Relay {
    /// This partition.
    pub index: u32,
    pub count: u32,
    next_id: u64,
    pending: Option<Pending>,
    /// Per inbox slot: its seq when last read.
    seen: [u32; trust::MAX_PARTITIONS],
    /// A message read from the inbox.
    buf: [u8; trust::RELAY_MSG_MAX],
}

/// A message read from the inbox: its header and payload.
pub struct Msg<'a> {
    pub head: RelayHeader,
    pub data: &'a [u8],
}

fn outbox() -> &'static RelaySlot {
    unsafe { &*(trust::RELAY_VA as *const RelaySlot) }
}

impl Relay {
    pub fn new(index: u32, count: u32) -> Option<Relay> {
        (count > 1 && index < count && count as usize <= trust::MAX_PARTITIONS).then(|| Relay {
            index,
            count,
            next_id: 1,
            pending: None,
            seen: [0; trust::MAX_PARTITIONS],
            buf: [0; trust::RELAY_MSG_MAX],
        })
    }

    pub fn primary(&self) -> bool {
        self.index == 0
    }

    /// A request is out.
    pub fn busy(&self) -> bool {
        self.pending.is_some()
    }

    /// The outbox's payload, after the message header: where a request or
    /// answer is built.  Not while a request is out (it is sent again).
    pub fn out_data() -> &'static mut [u8] {
        let at = trust::RELAY_VA + RELAY_SLOT_HEADER + RELAY_HEADER;
        unsafe { core::slice::from_raw_parts_mut(at as *mut u8, trust::RELAY_MSG_MAX - RELAY_HEADER) }
    }

    /// Send the outbox, with `head` and its first `head.len` payload
    /// bytes, to partition `to`.  False if root could not.
    pub fn send(&mut self, to: u32, head: RelayHeader) -> bool {
        unsafe { ((trust::RELAY_VA + RELAY_SLOT_HEADER) as *mut RelayHeader).write_volatile(head) };
        use l4h_rt::host::root::call::Client;
        l4h_rt::ipc::Endpoint::of(&l4h_rt::host::wiring::TRUSTD_ROOT, l4h_rt::host::wiring::p::Trustd, 0)
            .relay(to, RELAY_HEADER + head.len as usize)
            .is_ok()
    }

    /// What partition `from` sent since the last call, if anything (and
    /// root is not writing it just now: then its kick comes again).
    pub fn recv(&mut self, from: u32) -> Option<Msg<'_>> {
        let va = trust::relay_slot_va(from as usize);
        let slot = unsafe { &*(va as *const RelaySlot) };
        let seq = slot.seq.load(Ordering::Acquire);
        if seq == self.seen[from as usize] || seq & 1 != 0 {
            return None;
        }
        let len = (slot.len.load(Ordering::Relaxed) as usize).min(trust::RELAY_MSG_MAX);
        let data = (va + RELAY_SLOT_HEADER) as *const u8;
        for i in 0..len {
            self.buf[i] = unsafe { data.add(i).read_volatile() };
        }
        fence(Ordering::Acquire);
        if slot.seq.load(Ordering::Relaxed) != seq {
            return None;
        }
        self.seen[from as usize] = seq;
        if len < RELAY_HEADER {
            return None;
        }
        let head = unsafe { (self.buf.as_ptr() as *const RelayHeader).read_unaligned() };
        let n = (head.len as usize).min(len - RELAY_HEADER);
        Some(Msg { head, data: &self.buf[RELAY_HEADER..RELAY_HEADER + n] })
    }

    /// Ask the primary: request `op` with the first `len` bytes of
    /// out_data(), sent every `every_ms` until the answer comes (poll), at
    /// most `tries` times.  Only when not busy.
    pub fn start(&mut self, op: u32, len: usize, hz: u64, every_ms: u64, tries: u32, what: Wait) {
        let head = RelayHeader { id: self.next_id, op, status: 0, len: len as u32, _pad: 0 };
        self.next_id += 1;
        let every = hz * every_ms / 1000;
        let now = host::ticks::now();
        self.pending = Some(Pending { head, what, every, next_send: now + every, deadline: now + every * tries as u64 });
        outbox().wake.store(1, Ordering::Relaxed);
        // Root refuses only while it has no channel yet: as if lost.
        let _ = self.send(0, head);
    }

    /// The request out, if it is done: what it was for, and the answer's
    /// payload or -errno (ETIMEDOUT when none came).  Sends it again when
    /// it is time.
    pub fn poll(&mut self) -> Option<(Wait, Result<&[u8], Errno>)> {
        let p = self.pending.as_ref()?;
        let (head, what) = (p.head, p.what);
        let now = host::ticks::now();
        // Whatever is in the inbox: only the answer to this request counts.
        let answered = match self.recv(0) {
            Some(m) if m.head.id == head.id && m.head.op == head.op => Some((m.head.status, m.data.len())),
            _ => None,
        };
        if answered.is_none() {
            let p = self.pending.as_mut()?;
            if now < p.deadline {
                if now >= p.next_send {
                    p.next_send = now + p.every;
                    let _ = self.send(0, head);
                }
                return None;
            }
        }
        self.pending = None;
        outbox().wake.store(0, Ordering::Relaxed);
        Some((what, match answered {
            None => Err(crate::ETIMEDOUT),
            Some((0, n)) => Ok(&self.buf[RELAY_HEADER..RELAY_HEADER + n]),
            Some((status, _)) => Err(l4h_rt::host::errno::of_status(status as i64)),
        }))
    }
}

/// Per partition, at the primary: the last request answered, so that a
/// repeated one gets the same answer.
#[derive(Clone, Copy)]
pub struct Served {
    pub id: u64,
    pub op: u32,
    pub status: i32,
    pub len: usize,
    /// An ActivateCredential's answer (a key's is rebuilt).
    pub data: [u8; 128],
}

impl Default for Served {
    fn default() -> Self {
        Served { id: 0, op: 0, status: 0, len: 0, data: [0; 128] }
    }
}
