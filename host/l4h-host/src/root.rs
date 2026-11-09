//! l4h-root's endpoint (crate::wire::protocol): the calls trustd and
//! vmmgr make to it, which share its labels.  Their faults arrive there
//! too (badges::root::FAULT) and are no call.
//!
//! vmmgr's calls pass capabilities in its exchange slots
//! (vmmgr::SLOT_XCHG), which the calls below name.  A call that waits for
//! a driver, which root never does in a call, is answered later
//! (Later::Token): root sets the token's bit in vmmgr::Events::ops_done
//! and signals badges::vmmgr::ROOT_EVENT once it has the answer, which
//! `result` gives.

use crate::fixed::ArrayVec;
use crate::wire::{Tail, Wire};

/// trustd's component id; its flags thread's is FLAGS_ID.
pub const TRUSTD_ID: u32 = 0x300;
pub const FLAGS_ID: u32 = 0x301;

use crate::badges::root as recv;

crate::senders! {
    /// Who calls root, by the badge l4h_task gives a component's calls
    /// (badges::root, COMPONENT | ID).
    pub enum Sender in recv {
        Trustd: [COMPONENT] ID = TRUSTD_ID;
        Vmmgr: [COMPONENT] ID = crate::vmmgr::VMMGR_ID;
    }
}

/// An answer now, or later: the token to take it with `result`, below
/// vmmgr::MAX_PENDING.  A tag word (0: now, 1: later), then the value or
/// the token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Later<T> {
    Now(T),
    Token(usize),
}

impl<T> Later<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Later<U> {
        match self {
            Later::Now(v) => Later::Now(f(v)),
            Later::Token(t) => Later::Token(t),
        }
    }
}

impl<T: Wire> Wire for Later<T> {
    const MAX_WORDS: usize = 1 + if T::MAX_WORDS > 1 { T::MAX_WORDS } else { 1 };
    fn put(&self, out: &mut [u64]) -> usize {
        match self {
            Later::Now(v) => {
                out[0] = 0;
                1 + v.put(&mut out[1..])
            }
            Later::Token(t) => {
                out[0] = 1;
                out[1] = *t as u64;
                2
            }
        }
    }
    fn get(words: &[u64]) -> Option<(Self, usize)> {
        match *words.first()? {
            0 => T::get(&words[1..]).map(|(v, n)| (Later::Now(v), 1 + n)),
            1 => {
                let (t, n) = usize::get(&words[1..])?;
                (t < crate::vmmgr::MAX_PENDING).then_some((Later::Token(t), 1 + n))
            }
            _ => None,
        }
    }
}

/// Up to six values of a control op.
pub type Vals = Tail<u64, 6>;

crate::wire_struct! {
    /// What root made for a new guest.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NewGuest {
        pub instance: u64,
        /// Whether it has an attestation device.
        pub attest: bool,
    }
}

crate::protocol! {
    /// The calls on root's endpoint.  A reply's first word is 0 or an
    /// errno (abi CTL errnos), its value follows.
    pub mod call (from: Sender) {
        /// An access the firmware's AML makes outside trustd's own ranges
        /// (trust::HW_*): `addr` is a physical address, I/O port or PCI
        /// function (bus << 8 | device << 3 | function), `off` a PCI config
        /// offset, `width` in bytes, `value` the value to write.  The value
        /// read; root refuses RAM, memory and ports in use, and the config
        /// space of the PCI functions the host drives (reads give all
        /// ones, writes are dropped).
        Hw / hw = 5 from [Trustd] (op: u64, addr: usize, off: usize, width: usize, value: u64) -> u64;
        /// trustd answered guest `guest`'s request: raise its device's
        /// event.
        AttestDone / attest_done = 6 from [Trustd] (guest: usize) -> ();
        /// Send trustd's relay outbox, `len` bytes, to partition `peer`'s
        /// trustd (trust::RELAY_*).
        Relay / relay = 7 from [Trustd] (peer: u32, len: usize) -> ();

        /// Make guest `guest`'s I/O pool, `pool` bytes (a power of two) at
        /// `gpa`, and its l4h-vmm's notification, which backends signal
        /// (root's, so that it is one).  Exchange slot 0 = the CNode of
        /// the pool's frames (radix: the pool's pages), slot 3 = the
        /// notification, and with an attestation device slot 1 its page and
        /// slot 2 its kick capability (badged).
        GuestNew / guest_new = 0x100 from [Vmmgr] (guest: usize, pool: usize, gpa: usize, dom0: bool) -> NewGuest;
        /// The guest is stopped and torn down by vmmgr: drain its disks,
        /// remove its ports, forget it in trustd, revoke its pool.  The
        /// bytes of pool kept out of use (a disk could not be stopped).
        GuestDel / guest_del = 0x101 from [Vmmgr] (guest: usize) -> u64;
        /// Host disk `disk` for the guest's device `dev`, with abi::BLK_*
        /// `flags`: sectors [lba_start, lba_start + lba_count) of it (0: to
        /// the end), or if n is not 0 the n extents (start, sectors) at
        /// offset `list` of dom0's control data area, which blkd reads (root
        /// copies them unread).  Exchange slots [0, blk::CHANNEL_PAGES) = the
        /// channel frames, the next = blkd's kick.  Answered later.
        DiskAttach / disk_attach = 0x102 from [Vmmgr]
            (guest: usize, dev: usize, disk: usize, flags: u64, lba_start: u64, lba_count: u64, n: usize, list: u64) -> Later<()>;
        /// A port of `switch` for the guest's device `dev`, with MAC `mac`
        /// (0: choose).  Exchange slot 0 = the CNode of the port's frames
        /// (radix vmmgr::PORT_RADIX), slot 1 = netd's kick.  The MAC.
        NicAdd / nic_add = 0x103 from [Vmmgr] (guest: usize, dev: usize, switch: u32, mac: u64, lock: bool, isolated: bool) -> u64;
        /// The guest starts, with `ram` bytes, `vcpus` and its launch
        /// digest: its reports describe it from now on.  Whether it is
        /// dom0 is root's to say.
        TrustRegister / trust_register = 0x104 from [Vmmgr] (guest: usize, ram: u64, vcpus: u32, launch: [u64; 4]) -> ();
        /// A control op that root serves (abi::CTL_*: host, disks,
        /// switches, NICs): its vals; its data is in the result page.  The
        /// data area of dom0's control device is the source of
        /// CTL_BLK_WRITE.  BLK_WRITE and BLK_INFO are answered later.
        HostOp / host_op = 0x105 from [Vmmgr] (op: u32, args: [u64; 6]) -> Later<Vals>;
        /// The answer of a request answered later, which frees its token:
        /// as the request would have given it (exchange slots too).
        /// EAGAIN if root has not answered yet.
        Result / result = 0x106 from [Vmmgr] (token: usize) -> Vals;
        /// USB controller `ctrl` (CTL_USB_INFO index) for the guest's
        /// device `dev`.  Root claims it if the firmware still has it (a
        /// claim posted to its usbd, not waited for), and makes the queue
        /// area.  Exchange slot 0 = the CNode of its frames (radix
        /// vmmgr::USB_QUEUE_RADIX in root), slot 1 = usbd's kick.  The
        /// guest's USB number n: the VMM raises the device's event on
        /// badges::vmm::USB bit n.
        UsbAttach / usb_attach = 0x107 from [Vmmgr] (guest: usize, dev: usize, ctrl: usize) -> u64;
    }
}

impl Vals {
    pub fn of(v: &[u64]) -> Vals {
        let mut a = ArrayVec::new();
        let _ = a.extend_from_slice(v);
        Tail(a)
    }

    /// Value i, 0 past the last.
    pub fn at(&self, i: usize) -> u64 {
        self.0.get(i).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later() {
        let mut w = [0; 8];
        let n = Later::Now(Vals::of(&[1, 2])).put(&mut w);
        assert_eq!(&w[..n], &[0, 1, 2]);
        assert_eq!(Later::<Vals>::get(&w[..n]).unwrap().0, Later::Now(Vals::of(&[1, 2])));
        let n = Later::<Vals>::Token(9).put(&mut w);
        assert_eq!(&w[..n], &[1, 9]);
        assert_eq!(Later::<()>::get(&[1, 9]).unwrap().0, Later::Token(9));
        assert!(Later::<()>::get(&[1, crate::vmmgr::MAX_PENDING as u64]).is_none());
        assert!(Later::<()>::get(&[2]).is_none());
        assert_eq!(call::Request::MAX_REPLY_WORDS, 1 + 1 + 6);
        assert_eq!(Sender::of_badge(recv::COMPONENT | TRUSTD_ID as u64), Some(Sender::Trustd));
        assert_eq!(Sender::of_badge(recv::COMPONENT | crate::vmmgr::VMMGR_ID as u64), Some(Sender::Vmmgr));
        assert_eq!(Sender::of_badge(recv::COMPONENT | FLAGS_ID as u64), None);
        // A fault is no call.
        assert_eq!(Sender::of_badge(recv::COMPONENT | recv::FAULT | TRUSTD_ID as u64), None);
    }
}
