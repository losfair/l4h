//! The flags: trustd's main thread reads them and calls the flags server,
//! which is this image again, started by root as a component of its own
//! (host::KIND_FLAGS): its own CSpace and VSpace, the only writable
//! mapping of the flags, and a keeper that answers its callers if it
//! fails.  No heap, TPM, AML or calls back to root: a caller donates only
//! the time for this one request.

use l4h_rt::host::errno::Errno;
use l4h_rt::host::trust::call::{self, Client as _};
use l4h_rt::{cap, host, host::trust::{self, Flags, Sender, FlagsEntry}, sel4};
use sel4::cap_type;

pub fn read(id: usize, instance: u64) -> Flags {
    unsafe { &*(trust::FLAGS_VA as *const FlagsEntry).add(id) }.read().for_instance(instance)
}

/// Act on or seal (trust::FLAGS_ACT, FLAGS_SEAL) guest `id`'s flags,
/// through the flags server: its flags, or a positive errno.
pub fn call(op: u64, id: usize, instance: u64, bits: [u64; 4], flags: u64) -> Result<Flags, Errno> {
    let ep = l4h_rt::ipc::Endpoint::of(&l4h_rt::host::wiring::TRUSTD_FLAGS, l4h_rt::host::wiring::p::Trustd, 0);
    let r = if op == trust::FLAGS_SEAL { ep.seal(id, instance, bits, flags) } else { ep.act(id, instance, bits, flags) };
    l4h_rt::host::wire::eio_if_failed(r)
}

/// The calls, as trust::call declares them.
struct Entries;

/// Guest `id`'s entry, which only this server writes, and the instance
/// the registry has for it.
fn entry(id: usize) -> Result<(&'static FlagsEntry, u64), Errno> {
    if id >= trust::MAX_RECORDS {
        return Err(l4h_rt::host::errno::EINVAL);
    }
    let registered = unsafe { trust::registered(trust::REGISTRY_VA, id) };
    Ok((unsafe { &*(trust::FLAGS_VA as *const FlagsEntry).add(id) }, registered))
}

impl call::Server for Entries {
    fn ready(&mut self, _: Sender) -> Result<(), Errno> {
        Ok(())
    }

    fn act(&mut self, from: Sender, guest: usize, instance: u64, bits: [u64; 4], flags: u64) -> Result<Flags, Errno> {
        let (e, registered) = entry(guest)?;
        unsafe { e.update(from, trust::FLAGS_ACT, instance, registered, bits, flags) }
    }

    fn seal(&mut self, from: Sender, guest: usize, instance: u64, bits: [u64; 4], flags: u64) -> Result<Flags, Errno> {
        let (e, registered) = entry(guest)?;
        unsafe { e.update(from, trust::FLAGS_SEAL, instance, registered, bits, flags) }
    }
}

/// The flags server: the calls, and nothing bound to it.
impl l4h_rt::ipc::Server for Entries {
    const SIGNALS: u64 = 0;
    type Sender = Sender;

    fn call(&mut self, from: Sender, _: u64, info: &sel4::MessageInfo) -> Option<sel4::MessageInfo> {
        l4h_rt::ipc::serve::<call::Proto>(info, |label, args, out| call::serve(self, label, args, from, out))
    }
}

/// The flags server's main thread (host::KIND_FLAGS).  Root unbinds its
/// scheduling context once it waits (the Ready handshake): from then on
/// it runs only on its callers'.
pub fn serve() -> ! {
    let ep = cap::<cap_type::Endpoint>(host::SLOT_SERVICE_EP);
    let reply = cap::<cap_type::Reply>(host::SLOT_REPLY);
    l4h_rt::ipc::run(ep, reply, &mut Entries)
}
