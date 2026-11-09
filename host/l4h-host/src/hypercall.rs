//! The guest's hypercalls (include/l4h/abi.h, enum l4h_hypercall),
//! served by l4h-vmm on its endpoint (badges::vmm::HYPERCALL).  abi.h is
//! the guest's side of this declaration, and says the same: a reply's MR0
//! is 0 or an errno, its value follows in MR1.

use l4h_abi as abi;

/// Who makes a hypercall: the guest, whose capability to the VMM's
/// endpoint vmmgr badges HYPERCALL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    Guest,
}

crate::protocol! {
    /// The hypercalls (crate::wire::protocol).
    pub mod call (from: Sender) {
        /// Power off, reboot or crash (abi::POWER_*).  l4h-vmmgr stops the
        /// vCPUs, which cancels the call: no reply.
        Power / power = 2 from [Guest] (how: u64) -> ();
        /// A device op (abi::VIRTIO_OP_*, abi::USB_DEVOP_*) on device
        /// `device`, with arguments a and b: what the op returns.
        DevWrite / dev_write = 3 from [Guest] (device: usize, op: u64, a: u64, b: u64) -> u64;
        /// The wall clock, in ns since the epoch.
        GetTime / get_time = 6 from [Guest] () -> u64;
    }
}
const _: () = assert!(abi::HC_POWER == 2 && abi::HC_DEV_WRITE == 3 && abi::HC_GET_TIME == 6);
