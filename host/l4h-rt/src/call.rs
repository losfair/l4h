//! Calls over an endpoint, for the clients `l4h_host::protocol!` generates.

use crate::host::wire::Call;
use crate::sel4;

/// An endpoint capability whose calls carry a protocol's words.
#[derive(Clone, Copy)]
pub struct Endpoint(pub sel4::cap::Endpoint);

impl Call for Endpoint {
    fn ipc(&self, label: u64, args: &[u64], reply: &mut [u64]) -> usize {
        sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[..args.len()].copy_from_slice(args));
        let info = self.0.call(sel4::MessageInfo::new(label, 0, 0, args.len()));
        let n = info.length().min(reply.len());
        sel4::with_ipc_buffer(|b| reply[..n].copy_from_slice(&b.msg_regs()[..n]));
        n
    }
}
