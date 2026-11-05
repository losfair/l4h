//! Exercise the real link writer and rings. The notification double
//! records when the sleeping peer would be woken.
#![allow(dead_code, unused_attributes)]
#[path = "../host/l4h-partition/src/lib.rs"]
mod part;
pub use part::*;
extern crate self as l4h_partition;
extern crate self as l4h_rt;
use std::sync::atomic::{AtomicUsize, Ordering};
static BASE: AtomicUsize = AtomicUsize::new(0);
static SIGNALS: AtomicUsize = AtomicUsize::new(0);
pub fn cap<T: Default>(_: u64) -> T {
    T::default()
}
pub mod sel4 {
    pub mod cap {
        #[derive(Default)]
        pub struct Notification;
        impl Notification {
            pub fn signal(&self) {
                crate::SIGNALS.fetch_add(1, crate::Ordering::SeqCst);
            }
        }
        #[derive(Default)]
        pub struct IrqHandler;
        impl IrqHandler {
            pub fn irq_handler_ack(&self) -> Result<(), ()> {
                Ok(())
            }
        }
    }
    pub mod cap_type {
        pub use super::cap::{IrqHandler, Notification};
    }
}
pub mod host {
    pub mod net {
        pub const HDR_SIZE: usize = 12;
        pub const MAX_FRAME: usize = 68 * 1024 - 32;
        pub const NETD_SLOT_LINK_IRQ_BASE: u64 = 1;
        pub const NETD_SLOT_LINK_RING_BASE: u64 = 2;
        pub const NETD_SLOT_LINK_KICK_BASE: u64 = 3;
        pub fn link_va(_: usize) -> usize {
            crate::BASE.load(crate::Ordering::SeqCst)
        }
    }
}
#[path = "../host/l4h-netd/src/offload.rs"]
mod offload;
#[path = "../host/l4h-netd/src/link.rs"]
mod link;

#[test]
fn a_large_batch_wakes_a_sleeping_peer_before_the_end_of_the_poll() {
    let mut memory = vec![0u64; LINK_CHANNEL_SIZE as usize / 8];
    BASE.store(memory.as_mut_ptr() as usize, Ordering::SeqCst);
    SIGNALS.store(0, Ordering::SeqCst);
    let (_, peer_rx) = MsgRing::pair(memory.as_mut_ptr() as usize, LINK_CHANNEL_SIZE, 1, 0);
    let mut peer = MsgReader::new(peer_rx);
    assert!(peer.arm());
    let mut link = link::Link::new(0, 0, LINK_CHANNEL_SIZE, 0, 1);
    let mut frame = [0x42; 1500];
    for seq in 0..100u64 {
        frame[..8].copy_from_slice(&seq.to_le_bytes());
        link.send(&frame);
    }
    // One wake is enough until the peer drains its ring and arms again.
    assert_eq!(SIGNALS.load(Ordering::SeqCst), 1);
    let mut received = [0u8; 1500];
    let mut lost = 0;
    for seq in 0..100u64 {
        assert_eq!(peer.recv(&mut received, &mut lost), Some((MSG_FRAME, 1500)));
        assert_eq!(&received[..8], &seq.to_le_bytes());
        assert!(received[8..].iter().all(|b| *b == 0x42));
    }
    assert_eq!(lost, 0);
    assert!(peer.arm());
    link.send(&frame);
    link.doorbell();
    assert_eq!(SIGNALS.load(Ordering::SeqCst), 2);

    // A maximum-sized IPv4 TCP packet plus its offload header must fit
    // in one link record and retain the bytes the receiver will segment.
    let mut receiver = link::Link::new(0, 0, LINK_CHANNEL_SIZE, 1, 0);
    let mut frame = vec![0x42; 14 + 65535];
    frame[..54].fill(0);
    frame[12..14].copy_from_slice(&[8, 0]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&65535u16.to_be_bytes());
    frame[23] = 6;
    frame[46] = 0x50;
    let mut hdr = [0; offload::HDR_SIZE];
    hdr[0] = offload::F_NEEDS_CSUM;
    hdr[1] = offload::GSO_TCPV4;
    hdr[4..6].copy_from_slice(&1448u16.to_le_bytes());
    hdr[6..8].copy_from_slice(&34u16.to_le_bytes());
    hdr[8..10].copy_from_slice(&16u16.to_le_bytes());
    assert!(offload::sanitize(&mut hdr, &frame));
    assert!(link.can_send_gso(frame.len()));
    link.send_gso(&frame, &hdr);
    let mut buf = vec![0; host::net::MAX_FRAME + host::net::HDR_SIZE + 1];
    let (received, received_hdr) = receiver.recv(&mut buf).unwrap();
    assert_eq!(received, frame);
    assert_eq!(received_hdr, hdr);
    assert_eq!(receiver.lost, 0);

    hdr[6..8].copy_from_slice(&0u16.to_le_bytes());
    link.send_gso(&frame, &hdr);
    assert!(receiver.recv(&mut buf).is_none());
    assert_eq!(receiver.drops, 1);
}
