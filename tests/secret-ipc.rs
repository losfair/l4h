//! Production IPC/control boundaries clear request storage on all paths.
#![allow(dead_code)]
use l4h_abi as abi;
use l4h_host as host;
use std::cell::RefCell;
thread_local! {
    static IPC: RefCell<sel4::IpcBuffer> = const { RefCell::new(sel4::IpcBuffer([0; 120])) };
    static STATUS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
fn mr(i: usize) -> u64 { IPC.with_borrow(|b| b.0[i]) }
fn set_mr(i: usize, v: u64) { IPC.with_borrow_mut(|b| b.0[i] = v); }
mod sel4 {
    pub struct IpcBuffer(pub [u64; 120]);
    impl IpcBuffer { pub fn msg_regs_mut(&mut self) -> &mut [u64] { &mut self.0 } }
    pub fn with_ipc_buffer_mut<R>(f: impl FnOnce(&mut IpcBuffer) -> R) -> R { super::IPC.with_borrow_mut(f) }
    pub struct MessageInfo;
    impl MessageInfo { pub fn new(_: u64, _: usize, _: usize, _: usize) -> Self { Self } }
}
mod client {
    use super::*;
    struct Endpoint;
    fn ep() -> Endpoint { Endpoint }
    impl Endpoint {
        fn call(&self, _: sel4::MessageInfo) {
            IPC.with_borrow_mut(|b| b.0.fill(0xfeedface));
            set_mr(0, STATUS.get());
            for i in 1..7 { set_mr(i, i as u64); }
        }
    }
    include!(env!("L4H_ROOT_CLIENT_TEST_SRC"));
    #[test]
    fn replies_are_copied_before_all_ipc_words_are_erased() {
        for status in [0, 95] {
            STATUS.set(status);
            let result = call(123, &[0xdeadbeef; 15]);
            assert_eq!(result, if status == 0 { Ok([1, 2, 3, 4, 5, 6]) } else { Err(status as i64) });
            IPC.with_borrow(|b| assert!(b.0.iter().all(|&w| w == 0)));
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
        pub fn host_op(_: &mut super::Host, _: u32, _: &[u64; 6], _: &mut [u8; super::abi::CTL_DATA_MAX]) -> Result<[u64; 6], i64> { unreachable!() }
    }
    fn nested(h: &mut Host) -> Result<Vals, i64> {
        IPC.with_borrow(|b| assert!(b.0.iter().all(|&w| w == 0), "requests must be cleared before nested IPC"));
        h.calls += 1;
        IPC.with_borrow_mut(|b| b.0.fill(0xbad));
        if STATUS.get() == 0 { Ok([77, 88].into_iter().collect()) } else { Err(STATUS.get() as i64) }
    }
    fn guest_new(h: &mut Host, _: &[u64]) -> Result<Vals, i64> { nested(h) }
    fn guest_del(h: &mut Host, _: usize) -> Result<Vals, i64> { nested(h) }
    fn nic_add(h: &mut Host, _: &[u64]) -> Result<Vals, i64> { nested(h) }
    fn trust_register(h: &mut Host, _: &[u64]) -> Result<Vals, i64> { nested(h) }
    fn disk_attach(h: &mut Host, a: &[u64], key: &[u8; 64]) -> Result<Vals, i64> {
        assert!(a.iter().all(|&w| w == 0x1212121212121212));
        assert_eq!(key, &[0x12; 64]);
        nested(h)
    }
    include!(env!("L4H_ROOT_SERVER_TEST_SRC"));
    #[test]
    fn dispatch_preserves_arguments_and_clears_words_after_success_and_errors() {
        for label in [proto::VMMGR_DISK_ATTACH, proto::VMMGR_GUEST_NEW, u64::MAX] {
            for status in [0, 95] {
                STATUS.set(status);
                IPC.with_borrow_mut(|b| b.0.fill(0x1212121212121212));
                let mut h = Host { calls: 0 };
                let len = call(&mut h, label);
                let error = if label == u64::MAX { 38 } else { status };
                assert_eq!(mr(0), error);
                assert_eq!(len, if error == 0 { 3 } else { 1 });
                if error == 0 { assert_eq!([mr(1), mr(2)], [77, 88]); }
                IPC.with_borrow(|b| assert!(b.0[len..].iter().all(|&w| w == 0)));
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
    fn every_control_request_is_erased_without_touching_sync_or_response() {
        for op in [abi::CTL_BLK_ATTACH, 999] {
            for (version, fail) in [(abi::CTL_VERSION, false), (abi::CTL_VERSION, true), (abi::CTL_VERSION + 1, false)] {
                let mut page = Box::new([0xabababababababab_u64; 512]);
                let ptr = page.as_mut_ptr().cast::<u8>();
                unsafe { ptr.cast::<abi::CtlReq>().write(abi::CtlReq { op, version, args: [0x12345678; 6], data: [0x5a; abi::CTL_DATA_MAX] }); }
                handle(&mut Vmmgr { guest: Guest(ptr), fail }, 0);
                let bytes = unsafe { std::slice::from_raw_parts(ptr, abi::CTL_RESP_OFF) };
                assert!(bytes[..abi::CTL_SYNC_OFF].iter().all(|&b| b == 0));
                assert!(bytes[abi::CTL_SYNC_OFF..].iter().all(|&b| b == 0xab));
                let resp = unsafe { &*ptr.add(abi::CTL_RESP_OFF).cast::<abi::CtlResp>() };
                assert_eq!(resp.status, if version != abi::CTL_VERSION { -22 } else if fail { -95 } else { 0 });
                if version == abi::CTL_VERSION { assert_eq!(resp.vals[0], 0x12345678); }
            }
        }
    }
}
