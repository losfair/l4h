// SPDX-License-Identifier: GPL-2.0-only
//! Production backlog drain with a peer changing its RX tail between loads.
#![allow(dead_code)]
extern crate self as l4h_rt;
pub use l4h_host as host;
use host::{net, spsc::Producer};
use core::ptr::addr_of_mut;
use core::sync::atomic::{Ordering, fence};
use std::cell::Cell;
mod offload { pub const HDR_SIZE: usize = 12; }
#[path = "../host/l4h-netd/src/pool.rs"] mod pool;
use pool::{Fifo, Frame, Pool};
struct GuestPort { chan: *mut net::Port, rx: Producer, backlog: Fifo,
    rx_frames: u64, signal: bool }
struct Netd { ports: [Option<GuestPort>; 1], pool: &'static mut Pool, deferred_ports: u64 }
thread_local! {
    static LOADS: Cell<usize> = const { Cell::new(0) };
    static PEER: Cell<Peer> = const { Cell::new(Peer::Alternating) };
}
#[derive(Clone, Copy)]
enum Peer { Alternating, Full, Consuming }
fn peer_before_load(p: &GuestPort) {
    let n = LOADS.get();
    LOADS.set(n + 1);
    assert!(n < BACKLOG_BUDGET * 4, "backlog never returned to the main loop");
    let tail = match PEER.get() {
        Peer::Alternating => if n % 2 == 0 { 0 } else { net::RING_SIZE as u32 },
        Peer::Full => 0,
        Peer::Consuming => p.rx.head,
    };
    unsafe { (*p.chan).rx.tail.store(tail, Ordering::Release); }
}
include!(env!("L4H_NET_BACKLOG_TEST_SRC"));

#[test]
fn backlog_attempts_yield_and_resume_without_a_new_client_kick() {
    // Pool::take owns a single static, so keep all scenarios in one test.
    let layout = std::alloc::Layout::new::<net::Port>();
    let chan = unsafe { std::alloc::alloc_zeroed(layout).cast::<net::Port>() };
    assert!(!chan.is_null());
    let pool = pool::take();
    let p = GuestPort { chan, rx: Producer::at(net::RING_SIZE, net::RING_SIZE as u64),
        backlog: Fifo::EMPTY, rx_frames: 0, signal: false };
    let mut d = Netd { ports: [Some(p)], pool, deferred_ports: 0 };
    for _ in 0..BACKLOG_BUDGET + 3 {
        assert!(d.pool.push(&mut d.ports[0].as_mut().unwrap().backlog, &[1; 64], &[0; 12], 512, 1024));
    }
    d.rx_backlog(0);
    assert_eq!(LOADS.get(), BACKLOG_BUDGET * 2);
    assert_eq!(d.deferred_ports, 1, "wakeup recheck found room: must not wait for a lost kick");
    assert_eq!(d.ports[0].as_ref().unwrap().rx_frames, 0);
    assert_eq!(unsafe { (*chan).rx_wanted }, 1);

    // A full ring can sleep after the wanted/recheck handshake.
    LOADS.set(0);
    PEER.set(Peer::Full);
    d.rx_backlog(0);
    assert_eq!(LOADS.get(), 2);
    assert_eq!(d.deferred_ports, 0);
    assert_eq!(unsafe { (*chan).rx_wanted }, 1);

    // Even a peer consuming every frame cannot make one drain unbounded.
    LOADS.set(0);
    PEER.set(Peer::Consuming);
    d.rx_backlog(0);
    assert_eq!(d.ports[0].as_ref().unwrap().rx_frames, BACKLOG_BUDGET as u64);
    assert_eq!(d.deferred_ports, 1);
    LOADS.set(0);
    d.rx_backlog(0);
    let p = d.ports[0].as_ref().unwrap();
    assert!(p.backlog.is_empty() && p.signal);
    assert_eq!(p.rx_frames, (BACKLOG_BUDGET + 3) as u64);
    assert_eq!(d.deferred_ports, 0);
    assert_eq!(unsafe { (*chan).rx_wanted }, 0);
    unsafe { std::alloc::dealloc(chan.cast(), layout); }
}
