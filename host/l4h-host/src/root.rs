//! l4h-root's endpoint (crate::wire::protocol): the calls trustd and
//! vmmgr make to it, which share its labels.  Their faults arrive there
//! too (badges::root::FAULT) and are no call.
//!
//! vmmgr's calls pass capabilities in its exchange area (vmmgr::SLOT_XCHG,
//! XCHG_SLOTS of them), as each call declares (`call::caps`).  A call that waits for
//! a driver, which root never does in a call, is answered later
//! (Later::Token): root posts vmmgr::call::op_done in vmmgr's mailbox
//! once it has the answer, which `result` gives.

use crate::fixed::ArrayVec;
use crate::wire::{Tail, Wire};

/// trustd's component id; its flags server's (a component of its own) is
/// FLAGS_ID.
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
    pub mod call (from: Sender, xchg: crate::vmmgr::XCHG_SLOTS) {
        /// An access the firmware's AML makes outside trustd's own ranges
        /// (trust::HW_*): `addr` is a physical address, I/O port or PCI
        /// function (bus << 8 | device << 3 | function), `off` a PCI config
        /// offset, `width` in bytes, `value` the value to write.  The value
        /// read (all ones if refused).  Root refuses RAM, memory and ports
        /// in use, the BARs of the PCI functions it manages, and writes
        /// to those functions' configuration space, by the configuration
        /// mechanism or ECAM (reads are served); only for the ACPI start
        /// method.
        Hw / hw = 5 from [Trustd] (op: u64, addr: usize, off: usize, width: usize, value: u64) -> u64;
        /// trustd answered guest `guest`'s request: raise its device's
        /// event.
        AttestDone / attest_done = 6 from [Trustd] (guest: usize) -> ();
        /// Send trustd's relay outbox, `len` bytes, to partition `peer`'s
        /// trustd (trust::RELAY_*).
        Relay / relay = 7 from [Trustd] (peer: u32, len: usize) -> ();

        /// Make guest `guest`'s I/O pool, `pool` bytes (a power of two) at
        /// `gpa`, and its l4h-vmm's notification, which backends signal
        /// (root's, so that it is one): the CNode of the pool's frames
        /// (radix: the pool's pages), the notification, and with an
        /// attestation device its page and kick capability (badged).
        GuestNew / guest_new = 0x100 from [Vmmgr] (guest: usize, pool: usize, gpa: usize, dom0: bool)
            caps {
                Out POOL_FRAMES: CNode [0; 1],
                Out ATTEST_PAGE: Granule [1; 1],
                Out ATTEST_KICK: Notification [2; 1],
                Out VMM_NTFN: Notification [3; 1],
            } -> NewGuest;
        /// The guest is stopped and torn down by vmmgr: drain its disks,
        /// remove its ports, forget it in trustd, revoke its pool, and
        /// answer ENOENT for its requests answered later (their tokens are
        /// free once vmmgr has taken that and the driver has answered).
        /// The bytes of pool kept out of use for good (no device could be
        /// cut off from it), as root knows now: with removals to wait for,
        /// 0, and root logs what they keep once the drivers have answered.
        GuestDel / guest_del = 0x101 from [Vmmgr] (guest: usize) -> u64;
        /// Host disk `disk` for the guest, with abi::BLK_* `flags`:
        /// sectors [lba_start, lba_start + lba_count) of it (0: to the end),
        /// which root checks against the disk's capacity, or if n is not 0
        /// the n extents (start, sectors) at offset `list` of dom0's control
        /// data area, which blkd reads and checks (root copies them unread).
        /// Always answered later (Later::Token): `result` gives the channel.
        DiskAttach / disk_attach = 0x102 from [Vmmgr]
            (guest: usize, disk: usize, flags: u64, lba_start: u64, lba_count: u64, n: usize, list: u64) -> Later<()>;
        /// A port of `switch` for the guest, with MAC `mac` (0: choose; else
        /// 48 bits, not multicast): the CNode of the port's frames (radix
        /// vmmgr::PORT_RADIX) and netd's kick.  The MAC.  EIO once netd
        /// has failed.
        NicAdd / nic_add = 0x103 from [Vmmgr] (guest: usize, switch: u32, mac: u64, lock: bool, isolated: bool)
            caps { Out PORT_FRAMES: CNode [0; 1], Out KICK: Notification [1; 1] } -> u64;
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
        /// its vals, and for DiskAttach the channel's frames and blkd's
        /// kick.  EAGAIN if root has not answered yet.
        Result / result = 0x106 from [Vmmgr] (token: usize)
            caps {
                Out CHANNEL: Granule [0; crate::blk::CHANNEL_PAGES],
                Out KICK: Notification [crate::blk::CHANNEL_PAGES; 1],
            } -> Vals;
        /// USB controller `ctrl` (CTL_USB_INFO index) for the guest.  Root
        /// checks the guest has room for it, then claims it if the firmware
        /// still has it (a claim posted to its usbd, not waited for), and
        /// makes the queue area: the CNode of its frames (radix
        /// vmmgr::USB_QUEUE_RADIX in root) and usbd's kick.  The guest's USB
        /// number n: the VMM raises the device's event on badges::vmm::USB
        /// bit n.
        UsbAttach / usb_attach = 0x107 from [Vmmgr] (guest: usize, ctrl: usize)
            caps { Out QUEUE_FRAMES: CNode [0; 1], Out KICK: Notification [1; 1] } -> u64;
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

    #[test]
    fn disk_caps_come_with_result() {
        use crate::wire::Cap;
        // DiskAttach is always answered later: its channel and kick come
        // with Result, which declares them.
        assert!(call::caps::disk_attach::ALL.is_empty());
        assert_eq!(call::caps::result::ALL.len(), 2);
        assert_eq!(call::caps::result::KICK.passed_out(0, Cap::Notification), crate::blk::CHANNEL_PAGES);
        assert_eq!(call::caps::result::CHANNEL.passed_out(crate::blk::CHANNEL_PAGES - 1, Cap::Granule), crate::blk::CHANNEL_PAGES - 1);
    }
}
