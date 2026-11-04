// SPDX-License-Identifier: GPL-2.0-only
//! Exercise the production C writer and Rust consumer together, including
//! deterministic publication races, missing sequences and timer expiry.
extern crate self as l4h_rt;
pub mod host {
    pub use l4h_host::*;
    pub mod ticks {
        pub fn now() -> u64 { crate::NOW.load(crate::Ordering::Relaxed) }
    }
}

use core::ptr::{addr_of, addr_of_mut};
use l4h_abi as abi;
use std::sync::{Mutex, MutexGuard, Once};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static LOCK: Mutex<()> = Mutex::new(());
static MAP: Once = Once::new();
static EVENTS: AtomicUsize = AtomicUsize::new(0);
static NOW: AtomicU64 = AtomicU64::new(1000);
static TIMER: AtomicU64 = AtomicU64::new(0);
static ARMS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
const VCPUS: usize = 2;
const EVENT: u32 = 7;

pub mod sel4 {
    pub mod cap_type { pub struct Tcb; }
    pub struct Cap<T>(pub u64, pub core::marker::PhantomData<T>);
    impl<T> Cap<T> { pub fn bits(&self) -> u64 { self.0 } }
    pub struct IpcBuffer;
    impl IpcBuffer {
        pub fn inner_mut(&mut self) -> &mut Self { self }
        #[allow(non_snake_case)]
        pub fn seL4_TCB_SetTimer(&mut self, tcb: u64, deadline: u64, badge: u64) -> u64 {
            assert_eq!((tcb, badge), (crate::host::SLOT_TCB, crate::host::VMM_BADGE_CONSOLE));
            crate::TIMER.store(deadline, crate::Ordering::Relaxed);
            crate::ARMS.lock().unwrap().push(deadline);
            0
        }
    }
    pub fn with_ipc_buffer_mut<R>(f: impl FnOnce(&mut IpcBuffer) -> R) -> R { f(&mut IpcBuffer) }
}
pub fn cap<T>(bits: u64) -> sel4::Cap<T> { sel4::Cap(bits, core::marker::PhantomData) }
mod guest {
    pub struct Vcpus { pub n: usize }
    impl Vcpus {
        pub fn raise(&self, v: usize, event: u32) {
            assert_eq!((v, event), (0, crate::EVENT));
            crate::EVENTS.fetch_add(1, crate::Ordering::Relaxed);
        }
    }
}
#[path = "../host/l4h-vmm/src/console.rs"]
mod console;

unsafe extern "C" {
    fn mmap(a: usize, n: usize, prot: i32, flags: i32, fd: i32, off: usize) -> usize;
    fn console_test_select(page: *mut abi::EventPage);
    fn console_test_reset();
    fn console_test_sequence(seq: u32);
    fn console_test_kicks() -> u32;
    fn l4h_console_try_write(s: *const u8, n: u32) -> u32;
}
fn page(v: usize) -> *mut abi::EventPage { host::vmm_event_page_va(v) as *mut _ }
fn out(v: usize) -> *mut abi::ConsoleOut { unsafe { addr_of_mut!((*page(v)).console) } }
fn head(v: usize) -> u32 { unsafe { addr_of!((*out(v)).head).read_volatile() } }
fn tail(v: usize) -> u32 { unsafe { addr_of!((*out(v)).tail).read_volatile() } }
fn write(v: usize, bytes: &[u8]) -> usize {
    unsafe {
        console_test_select(page(v));
        l4h_console_try_write(bytes.as_ptr(), bytes.len() as u32) as usize
    }
}
fn sequence(seq: u32) { unsafe { console_test_sequence(seq) }; }
fn expire_timer() {
    let deadline = TIMER.swap(0, Ordering::Relaxed);
    assert_ne!(deadline, 0, "a gap must have a wakeup even without another kick");
    NOW.store(deadline, Ordering::Relaxed);
}
fn output() -> Vec<u8> {
    let r = host::VMM_CONSOLE_RING_VA as *const host::ConsoleRing;
    unsafe {
        let n = addr_of!((*r).head).read_volatile() as usize;
        assert!(n <= host::CONSOLE_RING_DATA);
        (&(*r).data)[..n].to_vec()
    }
}
struct Fixture { _lock: MutexGuard<'static, ()>, console: console::Console, vcpus: guest::Vcpus }
impl Fixture {
    fn new() -> Self {
        let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        MAP.call_once(|| {
            for (a, n) in [(host::vmm_event_page_va(0), VCPUS * 4096), (host::VMM_CONSOLE_RING_VA, 4 * 4096)] {
                assert_eq!(unsafe { mmap(a, n, 3, 0x100022, -1, 0) }, a);
            }
        });
        unsafe {
            core::ptr::write_bytes(page(0) as *mut u8, 0, VCPUS * 4096);
            core::ptr::write_bytes(host::VMM_CONSOLE_RING_VA as *mut u8, 0, 4 * 4096);
            console_test_reset();
        }
        EVENTS.store(0, Ordering::Relaxed);
        NOW.store(1000, Ordering::Relaxed);
        TIMER.store(0, Ordering::Relaxed);
        ARMS.lock().unwrap().clear();
        Self { _lock: lock, console: console::Console::new(false, None, EVENT, 1000), vcpus: guest::Vcpus { n: VCPUS } }
    }
    fn drain(&mut self) -> bool { self.console.drain(&self.vcpus) }
}
#[test]
fn roundtrip_and_cursor_wrap_preserve_unread_records() {
    let mut f = Fixture::new();
    let full = vec![b'a'; abi::CONSOLE_OUT_SIZE - 8];
    assert_eq!(write(0, &full), full.len());
    assert!(!f.drain());
    let next = vec![b'b'; abi::CONSOLE_OUT_SIZE - 128 - 8];
    assert_eq!(write(0, &next), next.len());
    assert!(!f.drain());
    assert_eq!(head(0), abi::CONSOLE_OUT_WRAP - 128);
    let mut expected = output();
    for i in 0..14 {
        let data = vec![b'A' + i; 256];
        assert_eq!(write(0, &data), data.len());
        expected.extend(data);
    }
    assert!(head(0) < tail(0), "cursor must wrap at a multiple of the ring size");
    assert!(!f.drain());
    assert_eq!(output(), expected);
    assert_eq!(head(0), tail(0));
}

#[test]
fn continuous_producer_cannot_extend_a_drain_without_limit() {
    let mut f = Fixture::new();
    assert_eq!(write(0, &[0]), 1);
    assert_eq!(write(1, &[1]), 1);
    let mut printed = 0;
    f.console.after_put = Some(Box::new(move |c| {
        printed += 1;
        // Stop eventually even on the old consumer, to fail instead of hang.
        if printed < 100_000 {
            let v = (1 - c) as usize;
            if head(v) == tail(v) { assert_eq!(write(v, &[v as u8]), 1); }
        }
    }));
    assert!(f.drain());
    assert!(output().len() <= abi::CONSOLE_OUT_SIZE / 9);
    f.console.after_put = None;
    f.console.flush(&f.vcpus);
    assert_eq!(head(0), tail(0));
    assert_eq!(head(1), tail(1));
}

#[test]
fn refilled_nonempty_ring_is_carried_to_next_batch_without_a_kick() {
    let mut f = Fixture::new();
    let n = abi::CONSOLE_OUT_SIZE / 2 - 8;
    assert_eq!(write(0, &vec![b'a'; n]), n);
    assert_eq!(write(0, &vec![b'b'; n]), n);
    let mut refilled = false;
    f.console.after_put = Some(Box::new(move |c| {
        if c == b'b' && !refilled {
            refilled = true;
            assert_eq!(write(0, &vec![b'c'; n]), n);
        }
    }));
    assert!(f.drain());
    assert_eq!(unsafe { console_test_kicks() }, 1);
    assert!(!f.drain());
    assert_eq!(output(), [vec![b'a'; n], vec![b'b'; n], vec![b'c'; n]].concat());
}

#[test]
fn full_ring_wakes_writer_after_space_is_freed() {
    let mut f = Fixture::new();
    assert_eq!(write(0, &vec![b'x'; abi::CONSOLE_OUT_SIZE - 8]), abi::CONSOLE_OUT_SIZE - 8);
    assert_eq!(write(0, b"retry"), 0);
    assert_eq!(EVENTS.load(Ordering::Relaxed), 0);
    assert!(!f.drain());
    assert_eq!(EVENTS.load(Ordering::Relaxed), 1);
    assert_eq!(write(0, b"retry"), 5);
    assert!(!f.drain());
    assert!(output().ends_with(b"retry"));
}

#[test]
fn budget_does_not_announce_space_in_an_undrained_ring() {
    let mut f = Fixture::new();
    let data = vec![b'x'; abi::CONSOLE_OUT_SIZE - 8];
    assert_eq!(write(0, &data), data.len());
    assert_eq!(write(1, &data), data.len());
    assert_eq!(write(1, b"retry"), 0);
    assert!(f.drain());
    assert_eq!(EVENTS.load(Ordering::Relaxed), 0);
    assert!(!f.drain());
    assert_eq!(EVENTS.load(Ordering::Relaxed), 1);
}

#[test]
fn invalid_guest_cursor_or_record_is_skipped() {
    let mut f = Fixture::new();
    unsafe { addr_of_mut!((*out(0)).head).write_volatile(u32::MAX); }
    assert!(!f.drain());
    assert!(tail(0) < abi::CONSOLE_OUT_WRAP);
    unsafe { addr_of_mut!((*out(0)).head).write_volatile(tail(0)); }
    assert_eq!(write(0, b"bad"), 3);
    unsafe {
        for i in 0..4 { (*out(0)).data[(tail(0) as usize + 4 + i) % abi::CONSOLE_OUT_SIZE] = 0xff; }
    }
    assert!(!f.drain());
    assert_eq!(head(0), tail(0));
    assert_eq!(write(0, b"good"), 4);
    assert!(!f.drain());
    assert!(output().is_empty());
    expire_timer();
    assert!(!f.drain());
    assert_eq!(output(), b"[l4h: skipped 1 missing console records]\ngood");
}

#[test]
fn publication_between_head_samples_is_rescanned_in_sequence_order() {
    let mut f = Fixture::new();
    f.console.after_head = Some(|v| {
        assert_eq!(v, 0);
        // CPU 0 was sampled empty, then two fully ordered writes arrive.
        assert_eq!(write(0, b"A"), 1);
        assert_eq!(write(1, b"B"), 1);
    });
    assert!(!f.drain());
    assert_eq!(output(), b"AB");
    assert!(ARMS.lock().unwrap().is_empty());
}

#[test]
fn unpublished_reservation_waits_without_polling_and_publication_cancels_timer() {
    let mut f = Fixture::new();
    sequence(1); // CPU 0 reserved sequence 0, but has not published it.
    assert_eq!(write(1, b"B"), 1);
    assert!(!f.drain(), "the event loop must sleep or serve other work while waiting");
    assert!(output().is_empty());
    assert_eq!(TIMER.load(Ordering::Relaxed), 1100);

    NOW.store(1099, Ordering::Relaxed);
    sequence(0); // The delayed producer publishes its already-reserved 0.
    let kicks = unsafe { console_test_kicks() };
    assert_eq!(write(0, b"A"), 1);
    assert_eq!(unsafe { console_test_kicks() }, kicks + 1);
    assert!(!f.drain());
    assert_eq!(output(), b"AB");
    assert_eq!(*ARMS.lock().unwrap(), [1100, 0]);
}

#[test]
fn kicks_do_not_extend_a_gap_and_expiry_discards_late_records() {
    let mut f = Fixture::new();
    sequence(1);
    assert_eq!(write(1, b"B"), 1);
    assert!(!f.drain());
    NOW.store(1050, Ordering::Relaxed);
    assert_eq!(write(1, b"C"), 1);
    assert!(!f.drain());
    NOW.store(1099, Ordering::Relaxed);
    assert!(!f.drain());
    assert_eq!(*ARMS.lock().unwrap(), [1100]);
    // No further guest kick: the one-shot timer alone makes progress.
    expire_timer();
    assert!(!f.drain());
    let expected = b"[l4h: skipped 1 missing console records]\nBC";
    assert_eq!(output(), expected);

    // Late output is dropped, but frees the ring and wakes its writer.
    sequence(0);
    let late = vec![b'A'; abi::CONSOLE_OUT_SIZE - 8];
    assert_eq!(write(0, &late), late.len());
    assert_eq!(write(0, b"retry"), 0);
    assert!(!f.drain());
    assert_eq!(output(), expected);
    assert_eq!(head(0), tail(0));
    assert_eq!(EVENTS.load(Ordering::Relaxed), 1);
    sequence(3);
    assert_eq!(write(0, b"D"), 1);
    assert!(!f.drain());
    assert!(output().ends_with(b"BCD"));
}

#[test]
fn notification_rebind_rearms_a_timer_lost_while_unbound() {
    let mut f = Fixture::new();
    sequence(1);
    assert_eq!(write(1, b"B"), 1);
    assert!(!f.drain());
    // seL4 consumes the expired timer even if its TCB has no bound
    // notification. Rearming the original (now past) deadline wakes it.
    expire_timer();
    f.console.rearm_timer();
    assert_eq!(TIMER.load(Ordering::Relaxed), 1100);
    assert_eq!(*ARMS.lock().unwrap(), [1100, 1100]);
    expire_timer();
    assert!(!f.drain());
    assert_eq!(output(), b"[l4h: skipped 1 missing console records]\nB");
}

#[test]
fn late_records_still_obey_the_drain_budget() {
    let mut f = Fixture::new();
    sequence(2);
    assert_eq!(write(1, b"current"), 7);
    assert!(!f.drain());
    expire_timer();
    assert!(!f.drain());
    let expected = output();
    sequence(0);
    let late = vec![b'x'; abi::CONSOLE_OUT_SIZE - 8];
    assert_eq!(write(0, &late), late.len());
    assert_eq!(write(1, &late), late.len());
    assert!(f.drain());
    assert_eq!(head(0), tail(0));
    assert_ne!(head(1), tail(1));
    assert!(!f.drain());
    assert_eq!(head(1), tail(1));
    assert_eq!(output(), expected);
}

#[test]
fn sequence_wrap_preserves_order() {
    let mut f = Fixture::new();
    // Advance in two steps within the signed comparison window, rather
    // than generating four billion records to reach the wrap boundary.
    for seq in [0x7fff_fffe, 0xffff_fffc] {
        sequence(seq);
        assert_eq!(write(0, b"anchor\n"), 7);
        assert!(!f.drain());
        expire_timer();
        assert!(!f.drain());
    }
    assert_eq!(write(0, b"A"), 1); // fffffffd
    assert_eq!(write(1, b"B"), 1); // fffffffe
    assert_eq!(write(0, b"C"), 1); // ffffffff
    assert_eq!(write(1, b"D"), 1); // 0
    assert!(!f.drain());
    assert!(output().ends_with(b"ABCD"));
    assert_eq!(TIMER.load(Ordering::Relaxed), 0);
}

#[test]
fn a_gap_crossing_sequence_wrap_counts_and_discards_skipped_records() {
    let mut f = Fixture::new();
    for seq in [0x7fff_fffe, 0xffff_fffd] {
        sequence(seq);
        assert_eq!(write(0, b"anchor\n"), 7);
        assert!(!f.drain());
        expire_timer();
        assert!(!f.drain());
    }
    // Missing fffffffe, ffffffff, 0: sequence 1 is ahead across wrap.
    sequence(1);
    assert_eq!(write(1, b"B"), 1);
    assert!(!f.drain());
    expire_timer();
    assert!(!f.drain());
    let expected = output();
    assert!(expected.ends_with(b"[l4h: skipped 3 missing console records]\nB"));
    for seq in [u32::MAX - 1, u32::MAX, 0] {
        sequence(seq);
        assert_eq!(write(0, b"late"), 4);
    }
    assert!(!f.drain());
    assert_eq!(output(), expected);
    assert_eq!(head(0), tail(0));
}

#[test]
fn poweroff_flush_skips_a_gap_without_waiting() {
    let mut f = Fixture::new();
    sequence(2);
    assert_eq!(write(1, b"crash report"), 12);
    assert!(!f.drain());
    f.console.flush(&f.vcpus);
    assert_eq!(output(), b"[l4h: skipped 2 missing console records]\ncrash report");
    assert_eq!(TIMER.load(Ordering::Relaxed), 0);
    assert_eq!(head(1), tail(1));
}

/// What reaches the serial ring, as the port would show it.
struct Serial(host::serial::Merge);

impl Serial {
    fn new() -> Self {
        // Too large for a test thread's stack; all zeroes is Ring::new().
        let ring: &'static host::serial::Ring =
            unsafe { &*std::alloc::alloc_zeroed(std::alloc::Layout::new::<host::serial::Ring>()).cast() };
        host::serial::init(ring, 0);
        Self(host::serial::Merge::new(ring, 0))
    }
    fn read(&mut self) -> String {
        let (mut s, mut line) = (String::new(), host::serial::Line::new());
        self.0.begin_pass();
        while self.0.next(u64::MAX, &mut line) {
            s.push_str(std::str::from_utf8(line.bytes()).unwrap());
            self.0.commit();
        }
        s
    }
}

fn serial_fixture(prefix: Option<u32>) -> (Fixture, Serial) {
    let mut f = Fixture::new();
    f.console = console::Console::new(true, prefix, EVENT, 1000);
    (f, Serial::new())
}

#[test]
fn serial_gets_whole_lines_with_the_guest_marked() {
    let (mut f, mut s) = serial_fixture(Some(3));
    write(0, b"one\r\ntw");
    write(1, b"o\nthree\n");
    assert!(!f.drain());
    assert_eq!(s.read(), "[vm3] one\r\n[vm3] two\r\n[vm3] three\r\n");
    assert_eq!(*ARMS.lock().unwrap(), Vec::<u64>::new());
}

#[test]
fn dom0_has_no_prefix() {
    let (mut f, mut s) = serial_fixture(None);
    write(0, b"dom0\n");
    assert!(!f.drain());
    assert_eq!(s.read(), "dom0\r\n");
}

#[test]
fn part_of_a_line_goes_out_after_the_gap_timer_and_the_line_goes_on() {
    let (mut f, mut s) = serial_fixture(Some(1));
    write(0, b"login: ");
    assert!(!f.drain());
    assert_eq!(s.read(), "");
    assert_eq!(TIMER.load(Ordering::Relaxed), 1100);
    NOW.store(1100, Ordering::Relaxed);
    assert!(!f.drain());
    assert_eq!(s.read(), "[vm1] login: ");
    assert_eq!(TIMER.load(Ordering::Relaxed), 0);
    write(0, b"root\n");
    assert!(!f.drain());
    assert_eq!(s.read(), "root\r\n");
}

#[test]
fn a_line_longer_than_the_buffer_stays_one_line() {
    let (mut f, mut s) = serial_fixture(None);
    let long = vec![b'x'; 1500];
    write(0, &long);
    write(0, b"\n");
    assert!(!f.drain());
    assert_eq!(s.read(), format!("{}\r\n", "x".repeat(1500)));
}

#[test]
fn flush_sends_a_partial_line_and_cancels_its_timer() {
    let (mut f, mut s) = serial_fixture(None);
    write(0, b"last words");
    assert!(!f.drain());
    assert_eq!(TIMER.load(Ordering::Relaxed), 1100);
    f.console.flush(&f.vcpus);
    assert_eq!(s.read(), "last words");
    assert_eq!(TIMER.load(Ordering::Relaxed), 0);
}

#[test]
fn a_rebound_notification_rearms_the_line_timer() {
    let (mut f, _s) = serial_fixture(None);
    write(0, b"part");
    assert!(!f.drain());
    TIMER.store(0, Ordering::Relaxed);
    f.console.rearm_timer();
    assert_eq!(TIMER.load(Ordering::Relaxed), 1100);
}
