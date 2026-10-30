//! Production CLI request/attach methods against a mock ioctl transport.
#![allow(dead_code)]
use l4h_abi::{CTL_VERSION, CTL_DATA_MAX, CTL_NAME_MAX, CTL_HOST_VERSION, CTL_BLK_ATTACH, BLK_ENCRYPT,
    CTL_VM_CREATE, CTL_VM_START, CTL_VM_DESTROY, CTL_NIC_CREATE, CTL_GPU_ATTACH};
use std::{cell::RefCell, io};
#[path = "../host/l4h-host/src/wipe.rs"]
mod wipe;
#[derive(Debug)] struct Error(String);
type Result<T> = std::result::Result<T, Error>;
fn err<T>(message: impl Into<String>) -> Result<T> { Err(Error(message.into())) }
fn errno_name(_: i64) -> &'static str { "not supported" }
const CTL_CONSOLE_READ: u32 = 8;
const CTL_CONSOLE_WRITE: u32 = 9;
const CTL_GPU_READ: u32 = 27;
const L4HCTL_IOC_CALL: u64 = 1;
struct Dev;
impl Dev { fn as_raw_fd(&self) -> i32 { 0 } }
struct Ctl { dev: Dev }
struct DiskKey([u8; 64]);
struct VmSpec<'a> {
    name: &'a str, mem: u64, vcpus: u64, initrd: &'a [u8], cmdline: &'a str,
    disks: Vec<(u64, u64, u64, u64)>, io_pool: u64, nics: Vec<(u64, u64, u64)>, gpu: Option<(u64, u64)>,
}
fn gpu_io_pool(_: u64, _: u64) -> u64 { unreachable!() }
fn load(_: &Ctl, _: u64, _: u64, _: &[u8]) -> Result<()> { unreachable!() }
#[repr(C)]
struct Req { op: u32, version: u32, args: [u64; 6], data: [u8; CTL_DATA_MAX] }
impl Drop for Req {
    fn drop(&mut self) { SERVER.with_borrow_mut(|s| s.wiped.push(self.args.iter().all(|&w| w == 0) && self.data.iter().all(|&b| b == 0))); }
}
type Resp = l4h_abi::CtlResp;
struct Call { req: u64, resp: u64, buf: u64, len: u64 }
#[derive(Default)]
struct Server {
    flags: Option<u64>, applied: Option<u64>, destroy_error: i64, attach_error: i64,
    fail_ioctl: bool, calls: Vec<u32>, wiped: Vec<bool>, attached: usize,
}
thread_local! { static SERVER: RefCell<Server> = RefCell::new(Server::default()); }
unsafe fn ioctl(_: i32, _: u64, call: *const Call) -> i32 {
    let call = unsafe { &*call };
    let req = unsafe { &*(call.req as *const Req) };
    let resp = unsafe { &mut *(call.resp as *mut Resp) };
    SERVER.with_borrow_mut(|s| {
        s.calls.push(req.op);
        if s.fail_ioctl { return -1; }
        match req.op {
            CTL_HOST_VERSION => match s.flags { Some(flags) => resp.vals[1] = flags, None => resp.status = -38 },
            CTL_BLK_ATTACH => {
                resp.status = s.attach_error;
                if resp.status == 0 { s.attached += 1; }
                resp.vals[0] = s.applied.unwrap_or(req.args[2] & s.flags.unwrap_or(0));
            }
            CTL_VM_CREATE => resp.vals[0] = 1,
            CTL_VM_DESTROY => {
                assert_eq!(req.args[0], 1);
                resp.status = s.destroy_error;
                if resp.status == 0 { s.attached = 0; }
            }
            _ => resp.status = -38,
        }
        0
    })
}
include!(env!("L4H_CTL_ENCRYPT_TEST_SRC"));

#[test]
fn unsupported_hosts_never_receive_a_keyed_attach() {
    let c = Ctl { dev: Dev };
    for flags in [None, Some(0)] {
        SERVER.set(Server { flags, ..Default::default() });
        assert!(c.blk_attach(1, 2, 0, 8, 16, Some(&[0x5a; 64])).is_err());
        SERVER.with_borrow(|s| {
            assert_eq!(s.attached, 0, "unsupported hosts must not receive an attach");
            assert_eq!(s.calls, [CTL_HOST_VERSION]);
        });
    }
    SERVER.set(Server { flags: Some(BLK_ENCRYPT), ..Default::default() });
    c.blk_attach(1, 2, 0, 8, 16, Some(&[0x5a; 64])).unwrap();
    SERVER.with_borrow(|s| { assert_eq!(s.calls, [CTL_HOST_VERSION, CTL_BLK_ATTACH]); assert!(s.wiped.iter().all(|&w| w)); });
    SERVER.set(Server::default());
    c.blk_attach(1, 2, 0, 8, 16, None).unwrap();
    SERVER.with_borrow(|s| assert_eq!(s.calls, [CTL_BLK_ATTACH], "plain attaches keep working on older hosts"));
}

#[test]
fn every_request_is_wiped_on_success_host_error_and_ioctl_error() {
    let c = Ctl { dev: Dev };
    for (op, fail_ioctl) in [(CTL_BLK_ATTACH, false), (999, false), (999, true)] {
        SERVER.set(Server { fail_ioctl, ..Default::default() });
        let _ = c.call(op, &[0x12345678; 6], &[0x5a; 64], &[]);
        SERVER.with_borrow(|s| assert_eq!(s.wiped, [true]));
    }
}

#[test]
fn unconfirmed_attach_destroys_the_vm_once_and_reports_cleanup_failure() {
    let c = Ctl { dev: Dev };
    let spec = VmSpec { name: "test", mem: 256 << 20, vcpus: 1, initrd: &[], cmdline: "", disks: vec![(2, 0, 8, 16)],
        io_pool: 0, nics: vec![], gpu: None };
    for creating in [false, true] {
        for destroy_error in [0, -5] {
            SERVER.set(Server { flags: Some(BLK_ENCRYPT), applied: Some(0), destroy_error, ..Default::default() });
            let error = if creating {
                c.create_vm_with_keys(&spec, &[Some(DiskKey([0x5a; 64]))]).unwrap_err()
            } else {
                c.blk_attach(1, 2, 0, 8, 16, Some(&[0x5a; 64])).unwrap_err()
            };
            assert!(error.0.contains("host did not confirm disk encryption"));
            if destroy_error != 0 { assert!(error.0.contains("failed to destroy VM 1")); }
            else if !creating { assert!(error.0.contains("VM 1 destroyed")); }
            SERVER.with_borrow(|s| {
                let expected = if creating { vec![CTL_VM_CREATE, CTL_HOST_VERSION, CTL_BLK_ATTACH, CTL_VM_DESTROY] }
                    else { vec![CTL_HOST_VERSION, CTL_BLK_ATTACH, CTL_VM_DESTROY] };
                assert_eq!(s.calls, expected, "cleanup belongs to exactly one caller, and must precede any VM start");
                assert_eq!(s.attached, usize::from(destroy_error != 0));
                assert!(s.wiped.iter().all(|&w| w));
            });
        }
    }
}

#[test]
fn rejected_standalone_attach_does_not_destroy_the_vm() {
    SERVER.set(Server { flags: Some(BLK_ENCRYPT), attach_error: -16, ..Default::default() });
    let c = Ctl { dev: Dev };
    assert!(c.blk_attach(1, 2, 0, 8, 16, Some(&[0x5a; 64])).is_err());
    SERVER.with_borrow(|s| { assert_eq!(s.calls, [CTL_HOST_VERSION, CTL_BLK_ATTACH]); assert_eq!(s.attached, 0); });
}
