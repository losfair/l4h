//! The I/O thread's loop (io.rs): the vCPU threads' calls, and the
//! signals on its notification (KICK, DONE, CTL, CONSOLE, ATTEST).

use l4h_rt::host::badges::hvm as recv;
use l4h_rt::host::hvm::{self as hv, call};
use l4h_rt::host::{self, errno};
use l4h_rt::ipc;
use l4h_rt::{cap, sel4};
use sel4::cap_type;

use crate::io;

struct Server;

impl call::Server for Server {
    fn access(&mut self, _: hv::Sender, _vcpu: usize, space: u32, addr: u64, size: u8, write: bool, value: u64) -> Result<u64, errno::Errno> {
        Ok(io::access(space, addr, size, write, value))
    }

    fn map(&mut self, _: hv::Sender, block: usize) -> Result<(), errno::Errno> {
        if crate::ept::map_block(block) { Ok(()) } else { Err(errno::EINVAL) }
    }
}

struct Loop;

/// How long the I/O thread spins between kernel turns while it polls.
const POLL_SPIN_US: u64 = 10;

impl ipc::Server for Loop {
    const SIGNALS: u64 = recv::SIGNALS;
    type Sender = hv::Sender;

    fn notification(&self) -> Option<ipc::Bound> {
        Some(ipc::Bound::new(cap::<cap_type::Tcb>(host::SLOT_TCB), cap::<cap_type::Notification>(host::SLOT_NTFN)))
    }

    fn rebound(&mut self) {
        let t = io::timer();
        if t != 0 {
            crate::sys::io_timer(t);
        }
    }

    fn signal(&mut self, badge: u64) {
        if badge & recv::CTL != 0 {
            io::control();
        }
        if badge & recv::DONE != 0 {
            io::completed();
        }
        if badge & recv::ATTEST != 0 {
            io::attested();
        }
        // Notified, or polled for work left (badge 0).
        io::kicked();
        if badge & recv::CONSOLE != 0 || io::timer() != 0 {
            io::console_turn();
        }
    }

    fn call(&mut self, from: hv::Sender, _: u64, info: &sel4::MessageInfo) -> Option<sel4::MessageInfo> {
        ipc::serve::<call::Proto>(info, |label, args, out| call::serve(&mut Server, label, args, from, out))
    }

    fn next(&mut self) -> ipc::Next {
        if io::more() {
            // Work left at a batch's end: another turn at once, as
            // l4h-vmm takes one.
            ipc::Next::Poll
        } else if io::polling() {
            // Queues that ran dry, polled for a while (only where vmmgr
            // allows it: an uncapped monitor alone on its core, boosted):
            // spin on them alone (each turn through the kernel takes its
            // lock, which every core's exits and IPC want), then look at
            // the endpoint.  No seL4_Yield: under a limited scheduling
            // context it would give up the rest of the budget's refill,
            // and at PRIO_VMM it lets no lower priority run anyway.
            io::poll_spin(crate::vm::vm().tsc_hz / 1_000_000 * POLL_SPIN_US);
            ipc::Next::Poll
        } else {
            ipc::Next::Wait
        }
    }
}

/// Serve, for good.
pub fn serve() -> ! {
    let ep = cap::<cap_type::Endpoint>(host::SLOT_SERVICE_EP);
    let reply = cap::<cap_type::Reply>(host::SLOT_REPLY);
    ipc::run(ep, reply, &mut Loop)
}
