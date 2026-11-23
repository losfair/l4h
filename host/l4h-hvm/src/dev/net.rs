//! virtio-net over a netd port for an HVM guest (DESIGN.md §5.11): as
//! l4h-vmm's (l4h-vmm/src/net.rs), frames and their virtio-net headers are
//! copied between the guest's buffers, here in its RAM, and the port's
//! slots, the offloads (checksum, TSO) passing through; a receive queue
//! (0) and a transmit queue (1).  Free of seL4 but the kick.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::gpu::copy_volatile;
use l4h_rt::host::net::{self, Port};
use l4h_rt::host::spsc::{Consumer, Producer};

use super::virtio_pci::Backend;
use crate::guest::GuestMem;
use crate::virtq::{Buf, Queue};
use crate::Kick;

const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
const VIRTIO_NET_F_MTU: u64 = 1 << 3;
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;
const VIRTIO_NET_F_HOST_TSO4: u64 = 1 << 11;
const VIRTIO_NET_F_HOST_TSO6: u64 = 1 << 12;
const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;
const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
const VIRTIO_NET_F_SPEED_DUPLEX: u64 = 1 << 63;
const VIRTIO_NET_S_LINK_UP: u16 = 1;
const HDR: usize = net::HDR_SIZE;
const RX: usize = 0;
const TX: usize = 1;
pub const QUEUE_SIZE: u16 = 256;
/// Chains a queue takes in one turn: another guest's vCPU may keep adding.
const BATCH: usize = 32;

type Chain = ArrayVec<Buf, { QUEUE_SIZE as usize }>;

pub struct Net {
    chan: *mut Port,
    tx: Producer,
    rx: Consumer,
    kick: Kick,
    link: net::LinkState,
    tx_blocked: bool,
    /// Queues whose turn ended with chains left.
    more: u64,
    /// VIRTIO_NET_F_MRG_RXBUF: a frame may span several receive chains.
    mrg: bool,
    config: [u8; 32],
}

impl Net {
    pub fn new(chan_va: usize, kick: Kick, mac: [u8; 6]) -> Self {
        let chan = chan_va as *mut Port;
        let link = net::LinkState(unsafe { addr_of!((*chan).link_state).read_volatile() });
        let mut config = [0u8; 32];
        config[0..6].copy_from_slice(&mac);
        config[10..12].copy_from_slice(&((net::MTU_FRAME - 14) as u16).to_le_bytes());
        let mut n = Net { chan, tx: Producer::new(net::RING_SIZE), rx: Consumer::new(net::RING_SIZE), kick, link, tx_blocked: false, more: 0, mrg: false, config };
        n.link_config();
        n
    }

    fn link_config(&mut self) {
        let status = if self.link.up() { VIRTIO_NET_S_LINK_UP } else { 0 };
        self.config[6..8].copy_from_slice(&status.to_le_bytes());
        self.config[12..16].copy_from_slice(&self.link.speed().to_le_bytes());
        self.config[16] = self.link.duplex();
    }

    fn tx_full(&self) -> bool {
        unsafe { self.tx.free(&(*self.chan).tx) == 0 }
    }

    /// Guest -> port: whether chains were returned, and frames queued.
    fn transmit(&mut self, mem: &GuestMem, q: &mut Queue) -> (bool, bool) {
        let (mut returned, mut queued) = (false, false);
        self.tx_blocked = false;
        self.more &= !(1 << TX);
        let mut left = BATCH;
        // No notifications while we take what is there: one ends the run.
        q.disable_notify(mem);
        while left != 0 {
            if self.tx_full() {
                self.tx_blocked = true;
                break;
            }
            let Some(head) = q.pop(mem) else {
                if q.enable_notify(mem) {
                    q.disable_notify(mem);
                    continue;
                }
                break;
            };
            left -= 1;
            let mut bufs = Chain::new();
            if q.chain(mem, head, &mut bufs).is_ok() {
                unsafe {
                    let slot = addr_of_mut!((*self.chan).tx_slots[self.tx.slot()]);
                    let hdr = addr_of_mut!((*slot).hdr) as *mut u8;
                    let data = addr_of_mut!((*slot).data) as *mut u8;
                    let (mut off, mut n, mut ok) = (0usize, 0usize, true);
                    for b in bufs.iter().filter(|b| !b.write) {
                        let src = mem.bytes(b.gpa, b.len as usize);
                        let (mut len, mut s) = (b.len as usize, 0);
                        if off < HDR {
                            let h = (HDR - off).min(len);
                            copy_volatile(src, hdr.add(off), h);
                            off += h;
                            s = h;
                            len -= h;
                        }
                        if n + len > net::MAX_FRAME {
                            ok = false;
                            break;
                        }
                        copy_volatile(src.add(s), data.add(n), len);
                        n += len;
                    }
                    if ok && off == HDR && n >= 14 {
                        addr_of_mut!((*slot).len).write_volatile(n as u32);
                        self.tx.push(&(*self.chan).tx);
                        queued = true;
                    }
                }
            }
            q.push(mem, head, 0);
            returned = true;
        }
        if left == 0 || self.tx_blocked {
            // Back for more (complete, retry) without a notification:
            // ask for one all the same, in case that never comes.
            if left == 0 {
                self.more |= 1 << TX;
            }
            q.enable_notify(mem);
        }
        (returned, queued)
    }

    /// Port -> guest, while both have entries.
    fn receive(&mut self, mem: &GuestMem, q: &mut Queue) -> bool {
        let mut returned = false;
        self.more &= !(1 << RX);
        let mut left = BATCH;
        while left != 0 {
            if unsafe { self.rx.ready(&(*self.chan).rx) } == 0 {
                break;
            }
            left -= 1;
            // The frame goes into one chain, or with mergeable buffers
            // into as many as it takes (num_buffers in its header), all
            // published together: the driver takes num_buffers entries.
            let mut heads = ArrayVec::<(u16, u32), { QUEUE_SIZE as usize }>::new();
            let (done, ok) = unsafe {
                let slot = addr_of!((*self.chan).rx_slots[self.rx.slot()]);
                let len = (addr_of!((*slot).len).read_volatile() as usize).min(net::MAX_FRAME);
                let data = addr_of!((*slot).data) as *const u8;
                let mut hdr = addr_of!((*slot).hdr).read_volatile();
                hdr[10] = 1;
                hdr[11] = 0;
                let total = HDR + len;
                let mut written = 0usize;
                // Where num_buffers went, to be set once it is known.
                let mut nb: [*mut u8; 2] = [core::ptr::null_mut(); 2];
                let mut ok = true;
                while written < total {
                    let Some(head) = q.pop(mem) else { break };
                    let mut bufs = Chain::new();
                    let mut n_head = 0usize;
                    if q.chain(mem, head, &mut bufs).is_err() {
                        ok = false;
                    } else {
                        for b in bufs.iter().filter(|b| b.write) {
                            let n = (b.len as usize).min(total - written);
                            let dst = mem.bytes(b.gpa, n);
                            let mut i = 0;
                            while i < n && written + i < HDR {
                                if written + i == 10 || written + i == 11 {
                                    nb[written + i - 10] = dst.add(i);
                                }
                                dst.add(i).write_volatile(hdr[written + i]);
                                i += 1;
                            }
                            if i < n {
                                copy_volatile(data.add(written + i - HDR), dst.add(i), n - i);
                            }
                            written += n;
                            n_head += n;
                            if written == total {
                                break;
                            }
                        }
                    }
                    heads.must_push((head, n_head as u32));
                    if !ok || !self.mrg || heads.is_full() {
                        break;
                    }
                }
                if ok && written == total && heads.len() > 1 {
                    let c = (heads.len() as u16).to_le_bytes();
                    for (p, v) in nb.iter().zip(c) {
                        if !p.is_null() {
                            p.write_volatile(v);
                        }
                    }
                }
                (written == total, ok)
            };
            if !done && ok && !heads.is_full() && (self.mrg || heads.is_empty()) {
                // Out of buffers with the frame waiting: give back what it
                // took and ask for a notification when the driver adds
                // more (the event index would leave refills unannounced),
                // unless it already has.
                q.unpop(heads.len() as u16);
                if q.enable_notify_more(mem) {
                    left += 1;
                    continue;
                }
                break;
            }
            // Delivered, or dropped (a bad chain, or one chain too small
            // without mergeable buffers): those then complete empty.
            for &(head, n) in &heads {
                q.push_deferred(mem, head, if done && ok { n } else { 0 });
            }
            unsafe { self.rx.pop(&(*self.chan).rx) };
            returned = true;
        }
        q.publish_used(mem);
        if left == 0 {
            self.more |= 1 << RX;
        }
        // netd holds frames for this port until we free slots: tell it.
        if returned {
            fence(Ordering::SeqCst);
            if unsafe { addr_of!((*self.chan).rx_wanted).read_volatile() } != 0 {
                self.kick.signal();
            }
        }
        returned
    }
}

impl Backend for Net {
    fn device_type(&self) -> u16 {
        1
    }

    fn features(&self) -> u64 {
        VIRTIO_NET_F_MAC | VIRTIO_NET_F_SPEED_DUPLEX | VIRTIO_NET_F_STATUS | VIRTIO_NET_F_MTU | VIRTIO_NET_F_CSUM
            | VIRTIO_NET_F_GUEST_CSUM | VIRTIO_NET_F_HOST_TSO4 | VIRTIO_NET_F_HOST_TSO6 | VIRTIO_NET_F_GUEST_TSO4
            | VIRTIO_NET_F_GUEST_TSO6 | VIRTIO_NET_F_MRG_RXBUF
    }

    fn num_queues(&self) -> usize {
        2
    }

    fn queue_max(&self, _: usize) -> u16 {
        QUEUE_SIZE
    }

    fn config(&self) -> &[u8] {
        &self.config
    }

    fn features_accepted(&mut self, f: u64) {
        self.mrg = f & VIRTIO_NET_F_MRG_RXBUF != 0;
        let gso = f & (VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6) == (VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6);
        unsafe {
            addr_of_mut!((*self.chan).rx_csum).write_volatile((f & VIRTIO_NET_F_GUEST_CSUM != 0) as u32);
            addr_of_mut!((*self.chan).rx_gso).write_volatile((gso && f & VIRTIO_NET_F_GUEST_CSUM != 0) as u32);
        }
    }

    fn kick(&mut self, mem: &GuestMem, queues: &mut [Queue], q: usize) -> u64 {
        match q {
            TX => {
                let (returned, queued) = self.transmit(mem, &mut queues[TX]);
                if queued {
                    self.kick.signal();
                }
                if returned { 1 << TX } else { 0 }
            }
            RX if self.receive(mem, &mut queues[RX]) => 1 << RX,
            _ => 0,
        }
    }

    fn complete(&mut self, mem: &GuestMem, queues: &mut [Queue]) -> u64 {
        let mut used = 0;
        if queues[RX].ready && self.receive(mem, &mut queues[RX]) {
            used |= 1 << RX;
        }
        if queues[TX].ready && (self.tx_blocked || self.more & (1 << TX) != 0) {
            let (returned, queued) = self.transmit(mem, &mut queues[TX]);
            if queued {
                self.kick.signal();
            }
            if returned {
                used |= 1 << TX;
            }
        }
        used
    }

    fn retry(&self) -> u64 {
        self.more
    }

    fn more(&self) -> u64 {
        self.more
    }

    fn config_changed(&mut self) -> bool {
        let link = net::LinkState(unsafe { addr_of!((*self.chan).link_state).read_volatile() });
        if link == self.link {
            return false;
        }
        self.link = link;
        self.link_config();
        true
    }

    fn reset(&mut self) {
        // Nothing of the guest's is with netd: frames are copied.
        self.tx_blocked = false;
        self.more = 0;
        unsafe {
            addr_of_mut!((*self.chan).rx_csum).write_volatile(0);
            addr_of_mut!((*self.chan).rx_gso).write_volatile(0);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::mem::tests::fake;

    #[test]
    fn transmit_and_receive() {
        let (mem, _buf) = fake(1 << 20, 0);
        // Too large for the stack: zeroed on the heap.
        let port: &'static mut Port = unsafe { &mut *(std::alloc::alloc_zeroed(std::alloc::Layout::new::<Port>()) as *mut Port) };
        let mut n = Net::new(port as *mut Port as usize, Kick, [2, 0, 0, 0, 0, 1]);
        assert_eq!(&n.config()[..6], &[2, 0, 0, 0, 0, 1]);
        let mut qs: [Queue; 2] = Default::default();
        assert!(qs[RX].setup(&mem, 16, 256, 0x1000, 0x2000, 0x3000));
        assert!(qs[TX].setup(&mem, 16, 256, 0x4000, 0x5000, 0x6000));
        // Transmit: a header buffer and a 60-byte frame.
        mem.write_bytes(0x8000, &[0; HDR]);
        mem.write_bytes(0x9000, &[0x11; 60]);
        let d = |at: u64, gpa: u64, len: u32, flags: u16, next: u16| {
            mem.write::<u64>(at, gpa);
            mem.write::<u32>(at + 8, len);
            mem.write::<u16>(at + 12, flags);
            mem.write::<u16>(at + 14, next);
        };
        d(0x4000, 0x8000, HDR as u32, 1, 1);
        d(0x4010, 0x9000, 60, 0, 0);
        mem.write::<u16>(0x5004, 0);
        mem.write::<u16>(0x5002, 1);
        assert_eq!(n.kick(&mem, &mut qs, TX), 1 << TX);
        assert_eq!(port.tx.head.load(Ordering::Relaxed), 1);
        assert_eq!(port.tx_slots[0].len, 60);
        assert_eq!(port.tx_slots[0].data[59], 0x11);
        // Receive a frame of 100 bytes into one 2 KiB buffer.
        port.rx_slots[0].len = 100;
        port.rx_slots[0].data[..100].fill(0x22);
        port.rx.head.store(1, Ordering::Release);
        d(0x1000, 0xa000, 2048, 2, 0);
        mem.write::<u16>(0x2004, 0);
        mem.write::<u16>(0x2002, 1);
        assert_eq!(n.kick(&mem, &mut qs, RX), 1 << RX);
        assert_eq!(mem.read::<u32>(0x3008), (HDR + 100) as u32);
        assert_eq!(mem.read::<u8>(0xa000 + 10), 1, "num_buffers");
        assert_eq!(mem.read::<u8>(0xa000 + HDR as u64 + 99), 0x22);
        // A link change is a configuration change.
        assert!(!n.config_changed());
        port.link_state = 1;
        assert!(n.config_changed());
    }

    /// A guest's queues name only its RAM: rings and buffers anywhere else
    /// (the hole, the I/O pool's GPA, past its RAM, wrapping) are refused,
    /// and nothing outside its RAM is read or written.
    #[test]
    fn hostile_queue_addresses() {
        let (mem, _buf) = fake(1 << 20, 0);
        let port: &'static mut Port = unsafe { &mut *(std::alloc::alloc_zeroed(std::alloc::Layout::new::<Port>()) as *mut Port) };
        let mut n = Net::new(port as *mut Port as usize, Kick, [2, 0, 0, 0, 0, 1]);
        let mut qs: [Queue; 2] = Default::default();
        // Rings outside RAM, or running off its end.
        for bad in [1u64 << 40, l4h_rt::host::hvm::IO_POOL_GPA, l4h_rt::host::hvm::PCI_MMIO_BASE, (1 << 20) - 8, u64::MAX - 7] {
            assert!(!qs[TX].setup(&mem, 16, 256, bad, 0x5000, 0x6000), "descriptors at {bad:#x}");
            assert!(!qs[TX].setup(&mem, 16, 256, 0x4000, bad, 0x6000), "available ring at {bad:#x}");
            assert!(!qs[TX].setup(&mem, 16, 256, 0x4000, 0x5000, bad), "used ring at {bad:#x}");
        }
        assert!(qs[RX].setup(&mem, 16, 256, 0x1000, 0x2000, 0x3000));
        assert!(qs[TX].setup(&mem, 16, 256, 0x4000, 0x5000, 0x6000));
        let d = |at: u64, gpa: u64, len: u32, flags: u16, next: u16| {
            mem.write::<u64>(at, gpa);
            mem.write::<u32>(at + 8, len);
            mem.write::<u16>(at + 12, flags);
            mem.write::<u16>(at + 14, next);
        };
        // Frames whose data lies outside RAM: none reaches netd.
        mem.write_bytes(0x8000, &[0; HDR]);
        let bad = [1u64 << 40, l4h_rt::host::hvm::IO_POOL_GPA, (1 << 20) - 30, u64::MAX - 15];
        for (i, &gpa) in bad.iter().enumerate() {
            let at = 0x4000 + 32 * i as u64;
            d(at, 0x8000, HDR as u32, 1, 2 * i as u16 + 1);
            d(at + 16, gpa, 60, 0, 0);
            mem.write::<u16>(0x5004 + 2 * i as u64, 2 * i as u16);
        }
        mem.write::<u16>(0x5002, bad.len() as u16);
        n.kick(&mem, &mut qs, TX);
        assert_eq!(port.tx.head.load(Ordering::Relaxed), 0, "a frame from outside RAM reached netd");
        // A receive buffer outside RAM: the frame is not written there.
        port.rx_slots[0].len = 100;
        port.rx.head.store(1, Ordering::Release);
        d(0x1000, 1 << 40, 2048, 2, 0);
        mem.write::<u16>(0x2004, 0);
        mem.write::<u16>(0x2002, 1);
        n.kick(&mem, &mut qs, RX);
        assert_eq!(mem.read::<u32>(0x3008), 0, "nothing written for it");
    }
}
