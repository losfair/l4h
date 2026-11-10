//! The actual driver mailbox transport and root's shared client. Only
//! seL4 notification invocations are mocked; requests, replies and lengths
//! cross the production ring and protocol codecs unchanged.
#![allow(dead_code)]

pub use l4h_host as host;
use host::{blk, mailbox as mb, wire};
use std::sync::atomic::{AtomicUsize, Ordering};

pub mod sel4 {
    pub mod cap_type { pub struct Notification; }
    pub mod cap { pub type Notification = super::Cap<super::cap_type::Notification>; }
    pub struct MessageInfo;
    impl MessageInfo { pub fn new(_: u64, _: u64, _: u64, _: usize) -> Self { Self } }
    pub struct Cap<T>(pub std::marker::PhantomData<T>);
    impl<T> Cap<T> {
        pub fn signal(&self) { crate::SIGNALS.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
        pub fn nb_send(&self, _: MessageInfo) {}
    }
}
pub fn cap<T>(_: u64) -> sel4::Cap<T> { sel4::Cap(std::marker::PhantomData) }
#[path = "../host/l4h-rt/src/mailbox.rs"]
mod driver;

static SIGNALS: AtomicUsize = AtomicUsize::new(0);
unsafe extern "C" {
    fn mmap(addr: usize, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> usize;
    fn munmap(addr: usize, len: usize) -> i32;
}

#[test]
fn protocol_lengths_survive_the_mailbox_and_bad_lengths_are_refused() {
    // MAP_FIXED_NOREPLACE, so no unrelated mapping is overwritten.
    let bytes = mb::MAILBOX_PAGES * 4096;
    assert_eq!(unsafe { mmap(mb::MAILBOX_VA, bytes, 3, 0x100022, -1, 0) }, mb::MAILBOX_VA);
    let shared = unsafe { &*(mb::MAILBOX_VA as *const mb::Mailbox) };
    let mut client = mb::Client::<blk::call::Proto>::new(shared);
    let request = blk::call::Request::Check { unit: 2, start: 8, sectors: 64, read_only: true, dom0: false, n: 0 };
    // Run the driver's real loop, then read its reply as root does. Each
    // reply length is tested with stale nonzero padding in the same entry.
    for length in [4, 1, 0, mb::ANSWER + 1, usize::MAX] {
        let k = client.send(&request).unwrap();
        let entry = &shared.entries[k as usize % mb::RING];
        entry.answer.iter().for_each(|w| w.store(99, Ordering::Relaxed));
        assert!(driver::serve(|label, args, out| {
            assert_eq!(args, &[2, 8, 64, 1, 0, 0]);
            assert!(matches!(blk::call::Request::decode(label, args, blk::Sender::Root), Ok(blk::call::Request::Check { .. })));
            out[..4].copy_from_slice(&[0, 7, 64, 1]);
            Some(length)
        }));
        let (answered, reply) = client.answer().unwrap();
        assert_eq!(answered, k);
        let decoded = wire::reply::<blk::call::reply::Check>(&reply);
        if length == 4 {
            assert_eq!(decoded, Ok(blk::Checked { slot: 7, sectors: 64, read_only: true }));
        } else {
            assert_eq!(decoded, Err(wire::FAILED), "length {length}");
        }
    }

    // The driver sees a short request as short, with no zero padding to
    // make its missing fields look like valid arguments.
    for length in [1, mb::ARGS + 1, usize::MAX] {
        let k = client.send(&request).unwrap();
        shared.entries[k as usize % mb::RING].args_len.store(length as u64, Ordering::Relaxed);
        let mut called = false;
        assert!(driver::serve(|label, args, out| {
            called = true;
            assert_eq!(args.len(), 1);
            out[0] = blk::call::Request::decode(label, args, blk::Sender::Root).unwrap_err();
            Some(1)
        }));
        assert_eq!(called, length == 1);
        let (_, reply) = client.answer().unwrap();
        assert_eq!(wire::reply::<blk::call::reply::Check>(&reply), Err(host::errno::EINVAL));
    }

    // An untrusted driver's length never selects memory outside its entry.
    let k = client.send(&request).unwrap();
    assert!(driver::serve(|_, _, _| None));
    shared.entries[k as usize % mb::RING].answer_len.store(u64::MAX, Ordering::Relaxed);
    assert_eq!(wire::reply::<()>(&client.answer().unwrap().1), Err(wire::FAILED));

    // A variable-length value carries its actual item count, not padding.
    client.send(&request).unwrap();
    assert!(driver::serve(|_, _, out| { out[..3].copy_from_slice(&[0, 8, 9]); Some(3) }));
    let (_, reply) = client.answer().unwrap();
    assert_eq!(wire::reply::<wire::Tail<u64, 4>>(&reply).unwrap().0.as_slice(), &[8, 9]);

    client.send(&blk::call::Request::Extent { client: 3, k: 9 }).unwrap();
    assert!(driver::serve(|label, args, out| {
        assert_eq!(args, &[3, 9]);
        assert!(matches!(blk::call::Request::decode(label, args, blk::Sender::Root), Ok(blk::call::Request::Extent { client: 3, k: 9 })));
        out[..3].copy_from_slice(&[0, 80, 64]);
        Some(3)
    }));
    assert_eq!(wire::reply::<blk::call::reply::Extent>(&client.answer().unwrap().1), Ok((80, 64)));

    // The counts a peer overwrites cannot make root reuse an entry that
    // still has a request in it, or manufacture replies it never posted.
    let before = shared.posted.load(Ordering::Relaxed);
    for i in 0..mb::RING {
        assert_eq!(client.send(&request), Some(before + i as u64));
    }
    shared.posted.store(u64::MAX, Ordering::Relaxed);
    shared.done.store(u64::MAX, Ordering::Relaxed);
    assert!(!client.room());
    assert!(client.send(&request).is_none());
    assert!(client.answer().is_none());
    shared.posted.store(before + mb::RING as u64, Ordering::Release);
    shared.done.store(before, Ordering::Release);
    assert!(driver::serve(|_, _, out| { out[0] = host::errno::EIO; Some(1) }));
    for i in 0..mb::RING {
        let (k, reply) = client.answer().unwrap();
        assert_eq!(k, before + i as u64);
        assert_eq!(wire::reply::<()>(&reply), Err(host::errno::EIO));
    }
    assert!(client.idle());
    assert!(!driver::serve(|_, _, _| panic!("no request")));
    let k = client.send(&request).unwrap();
    assert_eq!(client.abandon(), Some(k));
    assert!(client.abandon().is_none());
    assert!(client.idle());
    driver::signal();
    assert_eq!(SIGNALS.load(Ordering::Relaxed), 1);
    assert_eq!(unsafe { munmap(mb::MAILBOX_VA, bytes) }, 0);
}
