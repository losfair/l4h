//! Production IPC/control boundaries clear request storage on all paths.
#![allow(dead_code)]
use l4h_abi as abi;
use l4h_host as host;
use std::cell::RefCell;
thread_local! {
    static IPC: RefCell<sel4::IpcBuffer> = const { RefCell::new(sel4::IpcBuffer([0; 120])) };
    static STATUS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static LENGTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
fn mr(i: usize) -> u64 { IPC.with_borrow(|b| b.0[i]) }
fn set_mr(i: usize, v: u64) { IPC.with_borrow_mut(|b| b.0[i] = v); }
mod sel4 {
    pub struct IpcBuffer(pub [u64; 120]);
    impl IpcBuffer { pub fn msg_regs_mut(&mut self) -> &mut [u64] { &mut self.0 } }
    pub fn with_ipc_buffer_mut<R>(f: impl FnOnce(&mut IpcBuffer) -> R) -> R { super::IPC.with_borrow_mut(f) }
    pub struct MessageInfo(usize);
    impl MessageInfo {
        pub fn new(_: u64, _: usize, _: usize, len: usize) -> Self { Self(len) }
        pub fn length(&self) -> usize { self.0 }
    }
}
mod client {
    use super::*;
    use host::fixed::ArrayVec;
    use host::vmmgr::VMMGR_DISK_ATTACH;
    mod ctl { pub const EIO: i64 = 5; }
    pub struct Alloc;
    pub enum Backend { Blk { chan: ArrayVec<u64, { host::blk::CHANNEL_PAGES }>, kick: u64 } }
    fn take(_: &mut Alloc, i: usize) -> u64 { i as u64 }
    struct Endpoint;
    fn ep() -> Endpoint { Endpoint }
    impl Endpoint {
        fn call(&self, _: sel4::MessageInfo) -> sel4::MessageInfo {
            let len = LENGTH.get();
            if len != 0 { set_mr(0, STATUS.get()); }
            for i in 1..len { set_mr(i, i as u64); }
            sel4::MessageInfo::new(0, 0, 0, len)
        }
    }
    include!(env!("L4H_ROOT_CLIENT_TEST_SRC"));
    #[test]
    fn only_received_values_are_copied_and_request_reply_storage_is_erased() {
        for args_len in [1, 14] {
            for len in [0, 1, 2, 7] {
                for status in [0, 95] {
                    LENGTH.set(len);
                    STATUS.set(status);
                    IPC.with_borrow_mut(|b| b.0.fill(0xfeedface));
                    let result = call(123, &vec![0xdeadbeef; args_len]);
                    let values = core::array::from_fn(|i| if i + 1 < len { i as u64 + 1 } else { 0 });
                    assert_eq!(result, if len == 0 { Err(5) } else if status == 0 { Ok(values) } else { Err(status as i64) });
                    IPC.with_borrow(|b| {
                        assert!(b.0[..args_len.max(len)].iter().all(|&w| w == 0));
                        assert!(b.0[args_len.max(len)..].iter().all(|&w| w == 0xfeedface));
                    });
                }
            }
        }
    }
    #[test]
    fn disk_attach_propagates_root_flags_and_treats_missing_flags_as_zero() {
        STATUS.set(0);
        for len in [1, 2] {
            LENGTH.set(len);
            // Device index 4 leaves the encrypt bit in MR1 if a short
            // reply is incorrectly read beyond its reported length.
            let (_, applied) = disk_attach(&mut Alloc, 1, 4, 2, abi::BLK_ENCRYPT, 8, 16, &[0x12; 64]).unwrap();
            assert_eq!(applied, if len == 2 { 1 } else { 0 }); // The mock replies MR1 = 1.
        }
    }
}
mod server {
    use super::*;
    use host::vmmgr as proto;
    type Vals = host::fixed::ArrayVec<u64, 6>;
    const RESULT_VA: usize = 0; // HOST_OP isn't exercised here.
    pub struct Host { calls: usize }
    mod ctl {
        pub const ENOSYS: i64 = 38;
        pub const EINVAL: i64 = 22;
        pub fn host_op(_: &mut super::Host, _: u32, _: &[u64; 6], _: &mut [u8; super::abi::CTL_DATA_MAX]) -> Result<[u64; 6], i64> { unreachable!() }
    }
    fn nested(h: &mut Host) -> Result<Vals, i64> {
        IPC.with_borrow(|b| {
            assert!(b.0[..LENGTH.get()].iter().all(|&w| w == 0), "requests must be cleared before nested IPC");
            assert!(b.0[LENGTH.get()..].iter().all(|&w| w == 0x1212121212121212));
        });
        h.calls += 1;
        for i in 0..3 { set_mr(i, 0xbad); } // A nested non-secret reply.
        if STATUS.get() == 0 { Ok([77, 88].into_iter().collect()) } else { Err(STATUS.get() as i64) }
    }
    fn check_args(a: &[u64]) {
        assert!(a[..LENGTH.get()].iter().all(|&w| w == 0x1212121212121212));
        assert!(a[LENGTH.get()..].iter().all(|&w| w == 0), "stale IPC words must not become arguments");
    }
    fn guest_new(h: &mut Host, a: &[u64]) -> Result<Vals, i64> { check_args(a); nested(h) }
    fn guest_del(h: &mut Host, _: usize) -> Result<Vals, i64> { nested(h) }
    fn nic_add(h: &mut Host, _: &[u64]) -> Result<Vals, i64> { nested(h) }
    fn trust_register(h: &mut Host, _: &[u64]) -> Result<Vals, i64> { nested(h) }
    fn disk_attach(h: &mut Host, a: &[u64], key: &[u8; 64]) -> Result<Vals, i64> {
        check_args(a);
        assert_eq!(key, if LENGTH.get() == 14 { &[0x12; 64] } else { &[0; 64] });
        nested(h)
    }
    include!(env!("L4H_ROOT_SERVER_TEST_SRC"));
    #[test]
    fn dispatch_preserves_arguments_and_clears_words_after_success_and_errors() {
        for (label, request_len) in [(proto::VMMGR_DISK_ATTACH, 14), (proto::VMMGR_DISK_ATTACH, 6),
            (proto::VMMGR_GUEST_NEW, 4), (proto::VMMGR_GUEST_DEL, 1), (u64::MAX, 2), (proto::VMMGR_GUEST_NEW, 16)] {
            for status in [0, 95] {
                STATUS.set(status);
                LENGTH.set(request_len);
                IPC.with_borrow_mut(|b| b.0.fill(0x1212121212121212));
                let mut h = Host { calls: 0 };
                let len = call(&mut h, label, request_len);
                let error = if request_len > 14 { 22 } else if label == u64::MAX { 38 } else { status };
                assert_eq!(mr(0), error);
                assert_eq!(len, if error == 0 { 3 } else { 1 });
                if error == 0 { assert_eq!([mr(1), mr(2)], [77, 88]); }
                IPC.with_borrow(|b| assert!(b.0[request_len.max(3)..].iter().all(|&w| w == 0x1212121212121212)));
            }
        }
    }
}
mod control {
    use super::*;
    const EINVAL: i64 = 22;
    struct Guest(*mut u8);
    impl Guest { fn ctl_page(&self) -> Option<*mut u8> { Some(self.0) } }
    pub struct Vmmgr { guest: Guest, fail: bool }
    impl Vmmgr { fn guest(&self, _: usize) -> Option<&Guest> { Some(&self.guest) } }
    fn execute(h: &mut Vmmgr, _: usize, req: &abi::CtlReq, resp: &mut abi::CtlResp) -> Result<(), i64> {
        assert_eq!(req.args, [0x12345678; 6]);
        assert_eq!(req.data, [0x5a; abi::CTL_DATA_MAX]);
        resp.vals[0] = req.args[0];
        if h.fail { Err(95) } else { Ok(()) }
    }
    include!(env!("L4H_CONTROL_HANDLE_TEST_SRC"));
    #[test]
    fn every_control_payload_is_erased_without_touching_header_sync_or_response() {
        for op in [abi::CTL_BLK_ATTACH, abi::CTL_GPU_READ, 999] {
            for (version, fail) in [(abi::CTL_VERSION, false), (abi::CTL_VERSION, true), (abi::CTL_VERSION + 1, false)] {
                let mut page = Box::new([0xabababababababab_u64; 512]);
                let ptr = page.as_mut_ptr().cast::<u8>();
                unsafe { ptr.cast::<abi::CtlReq>().write(abi::CtlReq { op, version, args: [0x12345678; 6], data: [0x5a; abi::CTL_DATA_MAX] }); }
                handle(&mut Vmmgr { guest: Guest(ptr), fail }, 0);
                let bytes = unsafe { std::slice::from_raw_parts(ptr, abi::CTL_RESP_OFF) };
                assert_eq!(&bytes[..4], &op.to_ne_bytes(), "the guest driver reads op after completion");
                assert_eq!(&bytes[4..8], &version.to_ne_bytes());
                assert!(bytes[8..abi::CTL_SYNC_OFF].iter().all(|&b| b == 0));
                assert!(bytes[abi::CTL_SYNC_OFF..].iter().all(|&b| b == 0xab));
                let resp = unsafe { &*ptr.add(abi::CTL_RESP_OFF).cast::<abi::CtlResp>() };
                assert_eq!(resp.status, if version != abi::CTL_VERSION { -22 } else if fail { -95 } else { 0 });
                if version == abi::CTL_VERSION { assert_eq!(resp.vals[0], 0x12345678); }
            }
        }
    }
}

mod attach_reply {
    use super::*;
    const EINVAL: i64 = 22;
    fn vm_arg(id: u64) -> Result<usize, i64> { Ok(id as usize) }
    struct Vmmgr { applied: u64 }
    impl Vmmgr {
        fn attach_disk(&mut self, _: usize, _: usize, _: u64, _: u64, _: u64, _: &[u8; 64]) -> Result<u64, i64> {
            Ok(self.applied)
        }
    }
    include!(env!("L4H_CONTROL_ATTACH_TEST_SRC"));
    #[test]
    fn control_reports_applied_flags_even_when_they_differ_from_requested_flags() {
        for applied in [0, abi::BLK_ENCRYPT] {
            let req = abi::CtlReq { op: abi::CTL_BLK_ATTACH, version: abi::CTL_VERSION,
                args: [1, 2, abi::BLK_ENCRYPT, 8, 16, 0], data: [0x12; abi::CTL_DATA_MAX] };
            let mut resp: abi::CtlResp = unsafe { core::mem::zeroed() };
            execute_attach(&mut Vmmgr { applied }, 0, &req, &mut resp).unwrap();
            assert_eq!(resp.vals[0], applied);
        }
    }
}
