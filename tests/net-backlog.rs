// SPDX-License-Identifier: GPL-2.0-only
//! Production backlog drain with a peer changing its RX tail between loads.
#![allow(dead_code)]
extern crate self as l4h_rt;
pub use l4h_host as host;
use host::{net, spsc::Producer};
use core::ptr::addr_of_mut;
use core::sync::atomic::{Ordering, fence};
use std::cell::Cell;
#[path = "../host/l4h-netcore/src/offload.rs"] mod offload;
#[path = "../host/l4h-netd/src/pool.rs"] mod pool;
#[path = "../host/l4h-netd/src/turns.rs"] mod turns;
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

/// Ports with work take turns going first, however sparse their numbers.
#[test]
fn ports_with_work_take_turns_going_first() {
    let n = net::MAX_PORTS;
    for (a, b) in [(0, 1), (0, n - 1), (5, 30)] {
        let served = 1u64 << a | 1u64 << b;
        let mut cursor = 0;
        let mut first = Vec::new();
        for _ in 0..6 {
            let f = (0..n).map(|k| turns::nth(cursor, k, n)).find(|&i| served & (1 << i) != 0).unwrap();
            first.push(f);
            cursor = turns::next(cursor, served, n);
        }
        let want: Vec<_> = (0..6).map(|t| if t % 2 == 0 { a } else { b }).collect();
        assert_eq!(first, want, "ports {a} and {b}");
    }
    assert_eq!(turns::next(7, 0, n), 7, "nothing served: where it was");
    // Three ports: each first in turn.
    let served = 1u64 << 2 | 1u64 << 9 | 1u64 << 40;
    let mut cursor = 0;
    let mut first = Vec::new();
    for _ in 0..6 {
        first.push((0..n).map(|k| turns::nth(cursor, k, n)).find(|&i| served & (1 << i) != 0).unwrap());
        cursor = turns::next(cursor, served, n);
    }
    assert_eq!(first, [2, 9, 40, 2, 9, 40]);
}

/// Transmits and receive backlogs take turns apart, as netd's loop keeps
/// a cursor for each: ports 0 and 1 transmitting, port 2 with only a
/// backlog, and 0 and 1 still go first equally often (one shared cursor,
/// moved on by the backlogs, would give 0 the first turn 32 times in 48).
#[test]
fn backlogs_do_not_skew_whose_transmit_goes_first() {
    let n = net::MAX_PORTS;
    let first = |cursor: usize, mask: u64| (0..n).map(|k| turns::nth(cursor, k, n)).find(|&i| mask & (1 << i) != 0).unwrap();
    let (ports, backlogs) = (0b011u64, 0b111u64);
    let (mut tx, mut rx) = (0, 0);
    let mut firsts = [0; 2];
    for _ in 0..48 {
        firsts[first(tx, ports)] += 1;
        tx = turns::next(tx, ports, n);
        rx = turns::next(rx, backlogs, n);
    }
    assert_eq!(firsts, [24, 24]);
    // The shared cursor this replaces.
    let mut shared = 0;
    let mut skewed = [0; 2];
    for _ in 0..48 {
        skewed[first(shared, ports)] += 1;
        shared = turns::next(shared, ports | backlogs, n);
    }
    assert_eq!(skewed, [32, 16]);
    let _ = rx;
    // A kick for room to receive (port 2 here) transmits nothing: the TX
    // cursor moves on by the ports that sent, so 0 and 1 stay even.
    let (kicked, sent) = (0b111u64, 0b011u64);
    let (mut tx, mut firsts) = (0, [0; 3]);
    for _ in 0..48 {
        firsts[first(tx, kicked & sent)] += 1;
        tx = turns::next(tx, sent, n);
    }
    assert_eq!(firsts, [24, 24, 0]);
    let (mut tx, mut skewed) = (0, [0; 3]);
    for _ in 0..48 {
        skewed[first(tx, kicked & sent)] += 1;
        tx = turns::next(tx, kicked, n);
    }
    assert_ne!(skewed[0], skewed[1], "moved on by the kicks, it would skew");
}
