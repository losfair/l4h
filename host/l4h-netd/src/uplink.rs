//! Uplinks: channels to NIC drivers (nicds, l4h_host::uplink).  netd
//! trusts nothing a nicd writes: it copies each frame out before it looks
//! at it, checks its headers as a partition link's (MIN_MSS: it cuts no
//! frame into more segments than a guest could make it), refuses an offer
//! outside what it can do itself, and stops reading a channel whose
//! producer breaks the protocol.  A flooding nicd gets UPLINK_BUDGET
//! frames a turn, as a partition link does.

use core::sync::atomic::Ordering;

use l4h_rt::host::net;
use l4h_rt::host::uplink::{self, Channel, Next, Offer, Reader, Writer};
use l4h_rt::{cap, sel4};
use sel4::cap_type;

use crate::offload;
use crate::pool::{Fifo, Frame, Pool};

/// Frames waiting for room in the channel, and the pool chunks they may
/// take: the guests' backlogs take from the same pool.
const TX_BACKLOG_FRAMES: usize = 512;
const TX_BACKLOG_CHUNKS: usize = (4 << 20) / crate::pool::CHUNK;

/// The channel sides, one per uplink: too large for the stack, and
/// re-made for each AddUplink.
static mut WRITERS: [Writer; net::MAX_UPLINKS] = [const { Writer::new() }; net::MAX_UPLINKS];
static mut READERS: [Reader; net::MAX_UPLINKS] = [const { Reader::new() }; net::MAX_UPLINKS];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// The nicd has not written its offer yet.
    Waiting,
    Up,
    /// Its offer was refused, or it broke the channel: netd does not
    /// touch the channel again until root adds it anew.
    Refused,
    Broken,
}

pub struct Uplink {
    n: usize,
    chan: Channel,
    tx: &'static mut Writer,
    rx: &'static mut Reader,
    pub state: State,
    pub offer: Offer,
    /// Frames for a channel without room, oldest first.
    backlog: Fifo,
    /// The nicd must be signalled at the end of this turn.
    signal: bool,
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub drops: u64,
}

impl Uplink {
    /// Uplink n's channel, which root mapped (fresh) at uplink_va(n).
    pub fn new(n: usize, data_bits: u32) -> Self {
        let chan = unsafe { Channel::new(net::uplink_va(n) as *mut u8, data_bits) };
        let (tx, rx) = unsafe {
            let w = &mut (*core::ptr::addr_of_mut!(WRITERS))[n];
            let r = &mut (*core::ptr::addr_of_mut!(READERS))[n];
            *w = Writer::new();
            *r = Reader::new();
            (w, r)
        };
        Uplink {
            n,
            chan,
            tx,
            rx,
            state: State::Waiting,
            offer: Offer::default(),
            backlog: Fifo::EMPTY,
            signal: false,
            rx_frames: 0,
            tx_frames: 0,
            drops: 0,
        }
    }

    pub fn up(&self) -> bool {
        self.state == State::Up
    }

    /// Take the nicd's offer if it has written it.  Whether the uplink's
    /// state changed.
    pub fn poll_offer(&mut self) -> bool {
        if self.state != State::Waiting {
            return false;
        }
        let Some(o) = self.chan.header().read_offer() else { return false };
        match o.checked() {
            Some(o) => {
                self.offer = o;
                self.state = State::Up;
                l4h_rt::info!(
                    "netd: uplink {}: up, mac {:02x?}, offloads tx{}{} rx{}",
                    self.n, o.mac6(), if o.tx_csum != 0 { " csum" } else { "" },
                    if o.tx_gso_mask != 0 { " tso" } else { "" }, if o.rx_gso != 0 { " gso" } else { "" },
                );
            }
            None => {
                l4h_rt::log!("netd: uplink {}: offer refused (ABI {})", self.n, o.abi);
                self.state = State::Refused;
            }
        }
        true
    }

    /// The nicd's link state: DOWN unless the uplink is up.
    pub fn link(&self) -> net::LinkState {
        if !self.up() {
            return net::LinkState::DOWN;
        }
        net::LinkState(self.chan.header().link_state.load(Ordering::Acquire))
    }

    /// Whether the device takes this GSO frame whole.
    pub fn takes_gso(&self, len: usize, hdr: &[u8; net::HDR_SIZE]) -> bool {
        self.up() && self.offer.takes_gso(len, hdr)
    }

    /// Send a frame within the offer, or hold it until the channel has
    /// room: a dropped frame costs TCP a retransmission timeout.
    pub fn send(&mut self, frame: &mut [u8], hdr: &mut [u8; net::HDR_SIZE], pool: &mut Pool) {
        if !self.up() {
            return;
        }
        if self.offer.tx_csum == 0 {
            offload::complete_csum(frame, hdr);
        }
        let gso = offload::is_gso(hdr);
        let len = frame.len();
        if (!gso && !(self.offer.tx_frame_min as usize..=self.offer.tx_frame_max as usize).contains(&len))
            || (gso && !self.offer.takes_gso(len, hdr))
        {
            self.drops += 1;
            return;
        }
        let tx = self.chan.tx();
        if self.backlog.is_empty() && self.tx.write(&tx, frame, hdr) {
            self.tx_frames += 1;
            self.signal = true;
            return;
        }
        if !pool.push(&mut self.backlog, frame, hdr, TX_BACKLOG_FRAMES, TX_BACKLOG_CHUNKS) {
            self.drops += 1;
            return;
        }
        self.flush(pool);
    }

    /// Move held frames into the channel while it has room.  While some
    /// remain, netd asks the nicd to signal when it frees room.
    pub fn flush(&mut self, pool: &mut Pool) {
        let tx = self.chan.tx();
        // A few looks: a nicd that flips its tail between full and free
        // cannot hold netd here (it signals again when it frees room).
        for _ in 0..4 {
            while let Some(f) = pool.front(&self.backlog) {
                let Some(buf) = self.tx.reserve(&tx, f.len()) else { break };
                f.copy_to(buf);
                let (len, hdr) = (f.len(), f.hdr);
                self.tx.commit(&tx, len, &hdr);
                pool.pop(&mut self.backlog);
                self.tx_frames += 1;
                self.signal = true;
            }
            if self.backlog.is_empty() {
                return;
            }
            let w = &*self.tx;
            let need = pool.front(&self.backlog).map_or(1, |f| f.len());
            if uplink::arm(&self.chan.header().tx_full, || w.fits(&tx, need)) {
                return;
            }
        }
        // Room keeps appearing: come back on the nicd's next signal, or
        // this uplink's next turn.
        self.signal = true;
    }

    /// Forget the frames held (the uplink goes).
    pub fn clear(&mut self, pool: &mut Pool) {
        pool.clear(&mut self.backlog);
    }

    /// The next frame the nicd received, copied into `buf`: its length and
    /// checked header.  None when the ring is empty (asking the nicd to
    /// signal) or broken; Some(None) for a frame dropped.
    pub fn recv(&mut self, buf: &mut [u8]) -> Option<Option<(usize, [u8; net::HDR_SIZE])>> {
        if !self.up() {
            return None;
        }
        let rx = self.chan.rx();
        match self.rx.next(&rx) {
            Next::Frame(f, mut hdr) => {
                // A copy first: the nicd can write the area while netd reads.
                let len = f.len();
                buf[..len].copy_from_slice(f);
                self.rx.release(&rx);
                self.signal = true;
                if len < 14 || !offload::sanitize_rx(&mut hdr, &buf[..len], offload::MIN_MSS) {
                    self.drops += 1;
                    return Some(None);
                }
                self.rx_frames += 1;
                Some(Some((len, hdr)))
            }
            Next::Dropped => {
                self.drops += 1;
                self.signal = true;
                Some(None)
            }
            Next::Empty => None,
            Next::Broken => {
                l4h_rt::log!("netd: uplink {}: its nicd broke the channel", self.n);
                self.state = State::Broken;
                None
            }
        }
    }

    /// Ask the nicd to signal when it has frames; false if it has some
    /// already (come back).
    pub fn sleep(&mut self) -> bool {
        let rx = self.chan.rx();
        let r = &*self.rx;
        !self.up() || uplink::arm(&self.chan.header().rx_idle, || r.has_next(&rx))
    }

    /// Signal the nicd if this turn gave it frames or room it waits for.
    pub fn notify(&mut self) {
        if !core::mem::take(&mut self.signal) || !self.up() {
            return;
        }
        let h = self.chan.header();
        if uplink::take_waiter(&h.tx_idle) | uplink::take_waiter(&h.rx_full) {
            l4h_rt::mailbox::notify(cap::<cap_type::Notification>(net::NETD_SLOT_UPLINK_BASE + self.n as u64));
        }
    }
}
