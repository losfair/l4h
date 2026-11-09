//! Fixed-size, single-writer flags service. No heap, TPM, AML or calls
//! back to root: a caller donates only the time for this one request.

use l4h_rt::host::errno::Errno;
use l4h_rt::host::trust::call::{self, Client as _};
use l4h_rt::{cap, host::trust::{self, Flags, Sender, FlagsEntry}, sel4};
use sel4::cap_type;

pub fn read(id: usize, instance: u64) -> Flags {
    unsafe { &*(trust::FLAGS_VA as *const FlagsEntry).add(id) }.read().for_instance(instance)
}

/// Act on or seal (trust::FLAGS_ACT, FLAGS_SEAL) guest `id`'s flags,
/// through the flags thread: its flags, or a positive errno.
pub fn call(op: u64, id: usize, instance: u64, bits: [u64; 4], flags: u64) -> Result<Flags, Errno> {
    let ep = l4h_rt::ipc::Endpoint(cap::<cap_type::Endpoint>(trust::SLOT_FLAGS_CALL));
    let r = if op == trust::FLAGS_SEAL { ep.seal(id, instance, bits, flags) } else { ep.act(id, instance, bits, flags) };
    l4h_rt::host::wire::eio_if_failed(r)
}

/// The calls, as trust::call declares them.
struct Entries;

/// Guest `id`'s entry, which only this thread writes.
fn entry(id: usize) -> Result<&'static FlagsEntry, Errno> {
    if id >= trust::MAX_RECORDS {
        return Err(22);
    }
    Ok(unsafe { &*(trust::FLAGS_WRITE_VA as *const FlagsEntry).add(id) })
}

impl call::Server for Entries {
    fn ready(&mut self, _: Sender) -> Result<(), Errno> {
        Ok(())
    }

    fn act(&mut self, from: Sender, guest: usize, instance: u64, bits: [u64; 4], flags: u64) -> Result<Flags, Errno> {
        unsafe { entry(guest)?.update(from, trust::FLAGS_ACT, instance, bits, flags) }
    }

    fn seal(&mut self, from: Sender, guest: usize, instance: u64, bits: [u64; 4], flags: u64) -> Result<Flags, Errno> {
        unsafe { entry(guest)?.update(from, trust::FLAGS_SEAL, instance, bits, flags) }
    }
}

extern "C" fn serve() -> ! {
    unsafe { sel4::set_ipc_buffer(&mut *(trust::FLAGS_IPCBUF_VA as *mut sel4::IpcBuffer)) };
    let ep = cap::<cap_type::Endpoint>(trust::SLOT_FLAGS_EP);
    let reply = cap::<cap_type::Reply>(trust::SLOT_FLAGS_REPLY);
    l4h_rt::ipc::run(ep, reply, &mut Entries)
}

/// The flags thread: the calls, and nothing bound to it.
impl l4h_rt::ipc::Server for Entries {
    const SIGNALS: u64 = 0;
    type Sender = Sender;

    fn call(&mut self, from: Sender, _: u64, info: &sel4::MessageInfo) -> Option<sel4::MessageInfo> {
        l4h_rt::ipc::serve(info, |label, args, out| call::serve(self, label, args, from, out))
    }
}

pub fn start() {
    unsafe { l4h_rt::start_secondary(trust::SLOT_FLAGS_TCB, trust::FLAGS_STACK_TOP, serve) };
}
