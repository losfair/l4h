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
/// BASE and SIGNALS are one test's at a time.
static ONE_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());
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
#[path = "../host/l4h-netcore/src/offload.rs"]
mod offload;
#[path = "../host/l4h-netd/src/link.rs"]
mod link;

#[test]
fn a_large_batch_wakes_a_sleeping_peer_before_the_end_of_the_poll() {
    let _one = ONE_TEST.lock().unwrap_or_else(|e| e.into_inner());
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
    let link::Received::Frame(received, received_hdr) = receiver.recv(&mut buf) else { panic!("no frame") };
    assert_eq!(received, frame);
    assert_eq!(received_hdr, hdr);
    assert_eq!(receiver.lost, 0);

    hdr[6..8].copy_from_slice(&0u16.to_le_bytes());
    link.send_gso(&frame, &hdr);
    assert!(matches!(receiver.recv(&mut buf), link::Received::Dropped));
    assert_eq!(receiver.drops, 1);
    assert!(matches!(receiver.recv(&mut buf), link::Received::Empty));
}

/// One look at the ring takes one record, whatever it is: netd counts its
/// looks, so records it drops cost a peer as much budget as frames.
#[test]
fn a_look_takes_one_record_whether_it_is_dropped_or_not() {
    let _one = ONE_TEST.lock().unwrap_or_else(|e| e.into_inner());
    let mut memory = vec![0u64; LINK_CHANNEL_SIZE as usize / 8];
    BASE.store(memory.as_mut_ptr() as usize, Ordering::SeqCst);
    let (peer_tx, _) = MsgRing::pair(memory.as_mut_ptr() as usize, LINK_CHANNEL_SIZE, 1, 0);
    let mut link = link::Link::new(0, 0, LINK_CHANNEL_SIZE, 0, 1);
    let mut buf = vec![0; host::net::MAX_FRAME + host::net::HDR_SIZE + 1];
    // Records of an unknown type, a frame too short to be one, an offload
    // header with no GSO type, then a frame.
    for _ in 0..100 {
        peer_tx.send(99, &[]);
    }
    peer_tx.send(MSG_FRAME, &[&[0u8; 13]]);
    peer_tx.send(MSG_FRAME_GSO, &[&[0u8; 12 + 60]]);
    peer_tx.send(MSG_FRAME, &[&[0x42u8; 60]]);
    for dropped in 1..=102 {
        assert!(matches!(link.recv(&mut buf), link::Received::Dropped));
        assert_eq!(link.drops, dropped);
    }
    let link::Received::Frame(frame, hdr) = link.recv(&mut buf) else { panic!("no frame") };
    assert_eq!((frame.len(), hdr), (60, [0; host::net::HDR_SIZE]));
    assert!(matches!(link.recv(&mut buf), link::Received::Empty));
    assert_eq!((link.drops, link.rx_frames, link.lost), (102, 1, 0));
}
