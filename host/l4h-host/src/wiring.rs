//! The wiring: every capability by which one party can call, signal or
//! fault to another, declared once (DESIGN.md §10, "Wiring declarations").
//! Each edge is typed by its holder, target, object and protocol (E), a
//! capability's minter makes it from its edge and an object of the
//! target's (l4h_task::edge: slot, rights and badge come from here, the
//! object's type must be the edge's), a client calls an endpoint made from
//! a call edge (l4h_ipc::Endpoint<P>), and the checks
//! at the bottom hold at compile time: no two capabilities share a slot or
//! a notification bit unless declared `shared`, every call's badge is a
//! sender its protocol accepts, every signal's bit is in its receiver's
//! badge space, root calls no driver and no VMM, and exactly the
//! components callers block on have a keeper (host::has_keeper).
//!
//! Capabilities that pass resources (CNodes, frames, IRQ handlers, I/O
//! ports, TCBs) are no IPC and are not here; nor are a guest's own vCPUs'
//! (the guest ABI, abi.h).

use crate::badges;
use crate::wire::{Bits, Protocol};
use core::marker::PhantomData;
use crate::{blk, mailbox, net, trust, usb, vmmgr};
use l4h_abi as abi;

/// Who holds a capability, or is its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Party {
    Root,
    Vmmgr,
    Memd,
    Trustd,
    Blkd,
    Netd,
    Usbd,
    Logd,
    Vmm,
    Guest,
    /// An IRQ handler (a device's interrupt or another partition's
    /// doorbell), which signals the notification it is bound to.
    Irq,
}

impl Party {
    /// The component kind (host::KIND_*), if the party is one.
    pub const fn kind(self) -> Option<u32> {
        Some(match self {
            Party::Vmmgr => crate::KIND_VMMGR,
            Party::Memd => crate::KIND_MEMD,
            Party::Trustd => crate::KIND_TRUSTD,
            Party::Blkd => crate::KIND_BLKD,
            Party::Netd => crate::KIND_NETD,
            Party::Usbd => crate::KIND_USBD,
            Party::Logd => crate::KIND_LOGD,
            Party::Vmm => crate::KIND_VMM,
            Party::Root | Party::Guest | Party::Irq => return None,
        })
    }
}

/// Which object of the target a capability names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Object {
    /// Its endpoint: a component's service endpoint, root's or vmmgr's,
    /// a VMM's hypercall endpoint.
    Endpoint,
    /// The notification bound to its thread.
    Notification,
    /// trustd's kick notification (trust::SLOT_KICK).
    Kick,
    /// trustd's flags endpoint (trust::call).
    Flags,
    /// A guest vCPU's notification (abi::BADGE_*).
    Vcpu,
}

/// What the holder can do with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rights {
    /// Call the endpoint (write, grant reply).
    Call,
    /// Signal the notification (write).
    Signal,
    /// Bind the notification to an IRQ handler (all rights).
    Bind,
    /// Receive the holder's main thread's faults (the TCB's fault
    /// endpoint).
    Fault,
    /// Receive its keeper thread's faults (host::has_keeper), which nothing
    /// answers.
    KeeperFault,
}

/// Where the holder has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    /// Slots [base, base + len) of the holder's CSpace; instance i in base
    /// + i (or base, if len is 1).
    Slots(u64, usize),
    /// A slot the minter chooses: its own, or a guest's device CNode.
    Chosen,
    /// Bound to an IRQ handler.
    Bound,
    /// The holder's TCB's fault endpoint.
    Fault,
}

/// The badge: one value, a value with a field (instance i: base |
/// field.put(i)), or one bit of a range of signals (instance i: the
/// range's bit i).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Badge {
    Fixed(u64),
    Field(u64, Bits),
    Bit(Bits),
}

impl Badge {
    pub const fn at(self, i: usize) -> u64 {
        match self {
            Badge::Fixed(b) => b,
            Badge::Field(base, f) => base | f.put(i as u64),
            Badge::Bit(r) => r.nth(i),
        }
    }

    /// Every bit any instance can have.
    pub const fn mask(self) -> u64 {
        match self {
            Badge::Fixed(b) => b,
            Badge::Field(base, f) => base | f.mask(),
            Badge::Bit(r) => r.mask(),
        }
    }
}

/// One capability (of as many instances as `instances`).
#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub name: &'static str,
    pub holder: Party,
    pub at: At,
    pub target: Party,
    pub object: Object,
    pub rights: Rights,
    pub badge: Badge,
    /// Instances: the badge's index runs below it.
    pub instances: usize,
    pub minted_by: Party,
    /// A call's protocol (wire::Protocol::NAME; "" for no call), from E.
    pub protocol: &'static str,
    /// It shares slots or notification bits with other `shared` edges, by
    /// design (a device's kick slot holds one of several kicks; a bit two
    /// sources signal the same news on).
    pub shared: bool,
    pub what: &'static str,
}

impl Edge {
    /// Slot of instance i in the holder's CSpace.
    pub const fn slot(&self, i: usize) -> u64 {
        match self.at {
            At::Slots(base, 1) => base,
            At::Slots(base, len) => {
                assert!(i < len, "edge slot out of range");
                base + i as u64
            }
            _ => panic!("the edge is not in a slot of its holder's"),
        }
    }

    /// The badge of instance i (any i, for a fixed badge: a component's
    /// whose id is its instance).
    pub const fn badge(&self, i: usize) -> u64 {
        assert!(matches!(self.badge, Badge::Fixed(_)) || i < self.instances, "edge instance out of range");
        self.badge.at(i)
    }
}

/// The parties as types, for E and the objects it mints from
/// (l4h_task::edge::Obj).
pub mod p {
    use super::Party;

    /// A party, as a type.
    pub trait IsParty: Copy {
        const PARTY: Party;
    }

    macro_rules! parties {
        ($($p:ident),*) => {$(
            #[derive(Clone, Copy, Debug)]
            pub struct $p;
            impl IsParty for $p {
                const PARTY: Party = Party::$p;
            }
        )*};
    }
    parties!(Root, Vmmgr, Memd, Trustd, Blkd, Netd, Usbd, Logd, Vmm, Guest, Irq);
}

/// The objects as types.
pub mod o {
    use super::Object;

    /// An object, as a type.
    pub trait IsObject: Copy {
        const OBJECT: Object;
    }

    macro_rules! objects {
        ($($o:ident),*) => {$(
            #[derive(Clone, Copy, Debug)]
            pub struct $o;
            impl IsObject for $o {
                const OBJECT: Object = Object::$o;
            }
        )*};
    }
    objects!(Endpoint, Notification, Kick, Flags, Vcpu);
}

/// An edge with its holder H, its target T's object O and, for a call,
/// its protocol P as types, which E::new checks against the edge at
/// compile time: what is minted from it must be T's O
/// (l4h_task::edge::Obj<T, O>), and an endpoint called through it serves P
/// (l4h_ipc::Endpoint<P>).
pub struct E<H, T, O, P = ()>(pub Edge, PhantomData<(H, T, O, P)>);

impl<H, T, O, P> Clone for E<H, T, O, P> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<H, T, O, P> Copy for E<H, T, O, P> {}

impl<H, T, O, P> core::ops::Deref for E<H, T, O, P> {
    type Target = Edge;
    fn deref(&self) -> &Edge {
        &self.0
    }
}

impl<H: p::IsParty, T: p::IsParty, O: o::IsObject, P: Protocol> E<H, T, O, P> {
    pub const fn new(e: Edge) -> Self {
        assert!(
            e.holder as u8 == H::PARTY as u8 && e.target as u8 == T::PARTY as u8 && e.object as u8 == O::OBJECT as u8,
            "an edge's type names another holder, target or object"
        );
        let served = match e.rights {
            Rights::Call => served(e.target, e.object),
            _ => "",
        };
        assert!(same_str(P::NAME, served), "an edge's protocol is not its target's");
        E(Edge { protocol: P::NAME, ..e }, PhantomData)
    }
}

/// The protocol the target's object serves.
const fn served(target: Party, object: Object) -> &'static str {
    match (target, object) {
        (Memd, Endpoint) => <crate::memd::call::Proto as Protocol>::NAME,
        (Root, Endpoint) => <crate::root::call::Proto as Protocol>::NAME,
        (Vmmgr, Endpoint) => <vmmgr::call::Proto as Protocol>::NAME,
        (Trustd, Flags) => <trust::call::Proto as Protocol>::NAME,
        (Vmm, Endpoint) => <crate::hypercall::call::Proto as Protocol>::NAME,
        _ => "none",
    }
}

const fn same_str(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn edge(name: &'static str, holder: Party, at: At, target: Party, object: Object, rights: Rights, badge: Badge,
    instances: usize, minted_by: Party, what: &'static str) -> Edge {
    Edge { name, holder, at, target, object, rights, badge, instances, minted_by, protocol: "", shared: false, what }
}

const fn shared(e: Edge) -> Edge {
    Edge { shared: true, ..e }
}

use At::{Bound, Chosen, Fault as AtFault, Slots};
use Badge::{Bit, Field, Fixed};
use Object::{Endpoint, Flags, Kick, Notification, Vcpu};
use Party::*;
use Rights::{Bind, Call, Fault, KeeperFault, Signal};

const MAX_GUESTS: usize = crate::memd::MAX_GUESTS;
const COMPONENT_FAULT: u64 = badges::parent::COMPONENT | badges::parent::FAULT;
const fn id_fixed(id: u32) -> Badge {
    Fixed(COMPONENT_FAULT | id as u64)
}

// ---- Calls.
pub const ROOT_MEMD: E<p::Root, p::Memd, o::Endpoint, crate::memd::call::Proto> = E::new(edge("ROOT_MEMD", Root, Chosen, Memd, Endpoint, Call,
    Fixed(crate::memd::Sender::Root.badge()), 1, Root, "root's own memory (memd::call)"));
pub const VMMGR_MEMD: E<p::Vmmgr, p::Memd, o::Endpoint, crate::memd::call::Proto> = E::new(edge("VMMGR_MEMD", Vmmgr, Slots(vmmgr::SLOT_MEMD_EP, 1), Memd, Endpoint, Call,
    Fixed(crate::memd::Sender::Vmmgr.badge()), 1, Root, "vmmgr's memory and guests' RAM"));
pub const VMMGR_VMM_MEMD: E<p::Vmmgr, p::Memd, o::Endpoint, crate::memd::call::Proto> = E::new(edge("VMMGR_VMM_MEMD", Vmmgr, Slots(vmmgr::SLOT_VMM_MEMD_EP, MAX_GUESTS), Memd, Endpoint, Call,
    Field(badges::memd::VMM, badges::memd::GUEST), MAX_GUESTS, Root,
    "guest g's VMM's, which vmmgr cannot mint and copies to it (VMM_MEMD)"));
pub const VMM_MEMD: E<p::Vmm, p::Memd, o::Endpoint, crate::memd::call::Proto> = E::new(edge("VMM_MEMD", Vmm, Slots(crate::VMM_SLOT_MEMD_EP, 1), Memd, Endpoint, Call,
    Field(badges::memd::VMM, badges::memd::GUEST), MAX_GUESTS, Root, "a VMM's memory hotplug (VMMGR_VMM_MEMD's copy)"));
pub const TRUSTD_ROOT: E<p::Trustd, p::Root, o::Endpoint, crate::root::call::Proto> = E::new(edge("TRUSTD_ROOT", Trustd, Slots(crate::SLOT_ROOT_EP, 1), Root, Endpoint, Call,
    Fixed(crate::root::Sender::Trustd.badge()), 1, Root, "trustd's calls to root (root::call)"));
pub const VMMGR_ROOT: E<p::Vmmgr, p::Root, o::Endpoint, crate::root::call::Proto> = E::new(edge("VMMGR_ROOT", Vmmgr, Slots(crate::SLOT_ROOT_EP, 1), Root, Endpoint, Call,
    Fixed(crate::root::Sender::Vmmgr.badge()), 1, Root, "vmmgr's calls to root (root::call)"));
pub const VMM_VMMGR: E<p::Vmm, p::Vmmgr, o::Endpoint, vmmgr::call::Proto> = E::new(edge("VMM_VMMGR", Vmm, Slots(crate::SLOT_ROOT_EP, 1), Vmmgr, Endpoint, Call,
    Field(badges::vmmgr::COMPONENT, badges::vmmgr::ID), MAX_GUESTS, Vmmgr, "a VMM's calls to vmmgr (vmmgr::call)"));
pub const ROOT_FLAGS: E<p::Root, p::Trustd, o::Flags, trust::call::Proto> = E::new(edge("ROOT_FLAGS", Root, Chosen, Trustd, Flags, Call,
    Fixed(trust::Sender::Root.badge()), 1, Root, "the host's flags (trust::call), root's start-up handshake"));
pub const VMMGR_FLAGS: E<p::Vmmgr, p::Trustd, o::Flags, trust::call::Proto> = E::new(edge("VMMGR_FLAGS", Vmmgr, Slots(vmmgr::SLOT_FLAGS_EP, 1), Trustd, Flags, Call,
    Fixed(trust::Sender::Root.badge()), 1, Root, "the host's flags for the console (ROOT_FLAGS's copy)"));
pub const TRUSTD_FLAGS: E<p::Trustd, p::Trustd, o::Flags, trust::call::Proto> = E::new(edge("TRUSTD_FLAGS", Trustd, Slots(trust::SLOT_FLAGS_CALL, 1), Trustd, Flags, Call,
    Fixed(trust::Sender::Trustd.badge()), 1, Root, "trustd's main thread's for guests"));
pub const GUEST_VMM: E<p::Guest, p::Vmm, o::Endpoint, crate::hypercall::call::Proto> = E::new(edge("GUEST_VMM", Guest, Slots(abi::SLOT_HYP_EP as u64, 1), Vmm, Endpoint, Call,
    Fixed(crate::hypercall::Sender::Guest.badge()), 1, Vmmgr, "the guest's hypercalls (hypercall::call)"));

// ---- Faults.
pub const TRUSTD_FAULT: E<p::Trustd, p::Root, o::Endpoint> = E::new(edge("TRUSTD_FAULT", Trustd, AtFault, Root, Endpoint, Fault,
    id_fixed(crate::root::TRUSTD_ID), 1, Root, "trustd's main thread's faults"));
pub const FLAGS_FAULT: E<p::Trustd, p::Root, o::Endpoint> = E::new(edge("FLAGS_FAULT", Trustd, AtFault, Root, Endpoint, Fault,
    id_fixed(crate::root::FLAGS_ID), 1, Root, "trustd's flags thread's faults, which stop the host"));
pub const BLKD_FAULT: E<p::Blkd, p::Root, o::Endpoint> = E::new(edge("BLKD_FAULT", Blkd, AtFault, Root, Endpoint, Fault,
    Field(COMPONENT_FAULT, badges::parent::ID), 1 << 16, Root, "a blkd's faults: root quarantines it"));
pub const NETD_FAULT: E<p::Netd, p::Root, o::Endpoint> = E::new(edge("NETD_FAULT", Netd, AtFault, Root, Endpoint, Fault,
    Field(COMPONENT_FAULT, badges::parent::ID), 1 << 16, Root, "netd's faults: root suspends it"));
pub const USBD_FAULT: E<p::Usbd, p::Root, o::Endpoint> = E::new(edge("USBD_FAULT", Usbd, AtFault, Root, Endpoint, Fault,
    Field(COMPONENT_FAULT, badges::parent::ID), 1 << 16, Root, "a usbd's faults: root quarantines it"));
pub const LOGD_FAULT: E<p::Logd, p::Root, o::Endpoint> = E::new(edge("LOGD_FAULT", Logd, AtFault, Root, Endpoint, Fault,
    Field(COMPONENT_FAULT, badges::parent::ID), 1 << 16, Root, "logd's faults"));
pub const VMM_FAULT: E<p::Vmm, p::Vmmgr, o::Endpoint> = E::new(edge("VMM_FAULT", Vmm, AtFault, Vmmgr, Endpoint, Fault,
    Field(COMPONENT_FAULT, badges::parent::ID), MAX_GUESTS, Vmmgr, "a VMM's faults"));
pub const MEMD_KEEPER_FAULT: E<p::Memd, p::Root, o::Endpoint> = E::new(edge("MEMD_KEEPER_FAULT", Memd, AtFault, Root, Endpoint, KeeperFault,
    Field(COMPONENT_FAULT, badges::parent::ID), 1 << 16, Root, "memd's keeper's faults"));
pub const VMMGR_KEEPER_FAULT: E<p::Vmmgr, p::Root, o::Endpoint> = E::new(edge("VMMGR_KEEPER_FAULT", Vmmgr, AtFault, Root, Endpoint, KeeperFault,
    Field(COMPONENT_FAULT, badges::parent::ID), 1 << 16, Root, "vmmgr's keeper's faults"));
/// Guest g's vCPU v: ID and VCPU are adjacent, one field.
const GUEST_VCPU: Bits = Bits::new(badges::vmmgr::ID.lo, badges::vmmgr::VCPU.hi);
pub const GUEST_FAULT: E<p::Guest, p::Vmmgr, o::Endpoint> = E::new(edge("GUEST_FAULT", Guest, AtFault, Vmmgr, Endpoint, Fault,
    Field(badges::vmmgr::FAULT, GUEST_VCPU), abi::MAX_VCPUS << badges::vmmgr::ID.width(), Vmmgr,
    "guest g's vCPU v's kernel's faults (instance guest_fault(g, v))"));

/// GUEST_FAULT's instance for guest g's vCPU v.
pub const fn guest_fault(g: usize, v: usize) -> usize {
    assert!(g < MAX_GUESTS && v < abi::MAX_VCPUS);
    v << badges::vmmgr::ID.width() | g
}
const _: () = assert!(badges::vmmgr::ID.hi == badges::vmmgr::VCPU.lo);

// ---- Mailboxes (crate::mailbox).
pub const ROOT_BLKD_CALL: E<p::Root, p::Blkd, o::Notification> = E::new(edge("ROOT_BLKD_CALL", Root, Chosen, Blkd, Notification, Signal,
    Fixed(badges::driver::CALL), 1, Root, "root posted in blkd's mailbox (blk::call)"));
pub const ROOT_NETD_CALL: E<p::Root, p::Netd, o::Notification> = E::new(edge("ROOT_NETD_CALL", Root, Chosen, Netd, Notification, Signal,
    Fixed(badges::driver::CALL), 1, Root, "root posted in netd's mailbox (net::call)"));
pub const ROOT_USBD_CALL: E<p::Root, p::Usbd, o::Notification> = E::new(edge("ROOT_USBD_CALL", Root, Chosen, Usbd, Notification, Signal,
    Fixed(badges::driver::CALL), 1, Root, "root posted in usbd's mailbox (usb::call)"));
pub const ROOT_VMMGR_CALL: E<p::Root, p::Vmmgr, o::Notification> = E::new(edge("ROOT_VMMGR_CALL", Root, Chosen, Vmmgr, Notification, Signal,
    Fixed(badges::vmmgr::MAILBOX), 1, Root, "root posted notices in vmmgr's mailbox (vmmgr::call)"));
pub const BLKD_DONE: E<p::Blkd, p::Root, o::Notification> = E::new(shared(edge("BLKD_DONE", Blkd, Slots(mailbox::SLOT_MAILBOX_DONE, 1), Root, Notification, Signal,
    Fixed(badges::root::MAILBOX), 1, Root, "blkd answered in its mailbox (root polls every mailbox on the bit)")));
pub const NETD_DONE: E<p::Netd, p::Root, o::Notification> = E::new(shared(edge("NETD_DONE", Netd, Slots(mailbox::SLOT_MAILBOX_DONE, 1), Root, Notification, Signal,
    Fixed(badges::root::MAILBOX), 1, Root, "netd answered in its mailbox")));
pub const USBD_DONE: E<p::Usbd, p::Root, o::Notification> = E::new(shared(edge("USBD_DONE", Usbd, Slots(mailbox::SLOT_MAILBOX_DONE, 1), Root, Notification, Signal,
    Fixed(badges::root::MAILBOX), 1, Root, "usbd answered in its mailbox")));
pub const VMMGR_DONE: E<p::Vmmgr, p::Root, o::Notification> = E::new(shared(edge("VMMGR_DONE", Vmmgr, Slots(mailbox::SLOT_MAILBOX_DONE, 1), Root, Notification, Signal,
    Fixed(badges::root::MAILBOX), 1, Root, "vmmgr took root's notices")));

// ---- Device data paths: a VMM's kicks to its backends, and theirs back.
const VMM_KICKS: At = Slots(crate::VMM_KICK_SLOT_BASE, crate::MAX_GUEST_DEVICES);
pub const VMM_BLKD_KICK: E<p::Vmm, p::Blkd, o::Notification> = E::new(shared(edge("VMM_BLKD_KICK", Vmm, VMM_KICKS, Blkd, Notification, Signal,
    Fixed(badges::blkd::KICK), 1, Root, "a disk channel has requests (in its device's kick slot)")));
pub const VMM_NETD_KICK: E<p::Vmm, p::Netd, o::Notification> = E::new(shared(edge("VMM_NETD_KICK", Vmm, VMM_KICKS, Netd, Notification, Signal,
    Bit(badges::netd::PORT), net::MAX_PORTS, Root, "port p has frames to send (in its device's kick slot)")));
pub const VMM_USBD_KICK: E<p::Vmm, p::Usbd, o::Notification> = E::new(shared(edge("VMM_USBD_KICK", Vmm, Chosen, Usbd, Notification, Signal,
    Fixed(badges::usbd::KICK), 1, Root, "the guest's USB queues have requests (the guest's, in its device CNode)")));
pub const BLKD_VMM_DONE: E<p::Blkd, p::Vmm, o::Notification> = E::new(shared(edge("BLKD_VMM_DONE", Blkd, Slots(blk::BLKD_SLOT_CLIENT_DONE, blk::MAX_CLIENTS), Vmm,
    Notification, Signal, Fixed(badges::vmm::DONE), 1, Root, "client i's channel has completions")));
pub const NETD_VMM_DONE: E<p::Netd, p::Vmm, o::Notification> = E::new(shared(edge("NETD_VMM_DONE", Netd, Slots(net::NETD_SLOT_CLIENT_BASE, net::MAX_PORTS), Vmm,
    Notification, Signal, Fixed(badges::vmm::DONE), 1, Root, "port p has frames or room")));
pub const USBD_VMM: E<p::Usbd, p::Vmm, o::Notification> = E::new(edge("USBD_VMM", Usbd, Slots(usb::USBD_SLOT_CLIENT_IRQ, usb::AREAS), Vmm, Notification, Signal,
    Bit(badges::vmm::USB), usb::MAX_GUEST_USB, Root, "the guest's USB controller n has completions"));

// ---- Interrupts and doorbells.
pub const IRQ_BLKD: E<p::Irq, p::Blkd, o::Notification> = E::new(edge("IRQ_BLKD", Irq, Bound, Blkd, Notification, Bind,
    Fixed(badges::blkd::IRQ), 1, Root, "its controller's interrupt"));
pub const IRQ_NETD: E<p::Irq, p::Netd, o::Notification> = E::new(edge("IRQ_NETD", Irq, Bound, Netd, Notification, Bind,
    Bit(badges::netd::IRQ), net::MAX_NICS, Root, "uplink NIC n's interrupt"));
pub const IRQ_USBD: E<p::Irq, p::Usbd, o::Notification> = E::new(edge("IRQ_USBD", Irq, Bound, Usbd, Notification, Bind,
    Fixed(badges::usbd::IRQ), 1, Root, "its xHCI's interrupt"));
pub const IRQ_MONITOR: E<p::Irq, p::Root, o::Notification> = E::new(edge("IRQ_MONITOR", Irq, Bound, Root, Notification, Signal,
    Fixed(badges::root::MONITOR), 1, Root, "the serial monitor's input"));
pub const DOORBELL_ROOT: E<p::Irq, p::Root, o::Notification> = E::new(edge("DOORBELL_ROOT", Irq, Bound, Root, Notification, Signal,
    Fixed(badges::root::CHANNEL), 1, Root, "another partition rang (its control channel)"));
pub const DOORBELL_NETD: E<p::Irq, p::Netd, o::Notification> = E::new(shared(edge("DOORBELL_NETD", Irq, Bound, Netd, Notification, Signal,
    Bit(badges::netd::LINK), net::MAX_LINKS, Root, "link l's peer rang")));
pub const NETD_LINK_SELF: E<p::Netd, p::Netd, o::Notification> = E::new(shared(edge("NETD_LINK_SELF", Netd, Slots(net::NETD_SLOT_LINK_KICK_BASE, net::MAX_LINKS), Netd,
    Notification, Signal, Bit(badges::netd::LINK), net::MAX_LINKS, Root, "netd's reminder to read link l again (as its doorbell)")));
pub const NETD_LINK_RING: E<p::Netd, p::Root, o::Notification> = E::new(edge("NETD_LINK_RING", Netd, Slots(net::NETD_SLOT_LINK_RING_BASE, net::MAX_LINKS), Root,
    Notification, Signal, Bit(badges::root::LINK), net::MAX_LINKS, Root, "ring link l's peer's doorbell (only root holds IRQControl)"));

// ---- Attestation.
pub const GUEST_TRUSTD: E<p::Guest, p::Trustd, o::Kick> = E::new(shared(edge("GUEST_TRUSTD", Guest, Chosen, Trustd, Kick, Signal,
    Bit(badges::trustd_kick::GUEST), trust::MAX_RECORDS, Root, "guest g made a request in its attestation page")));
pub const ROOT_TRUSTD_RELAY: E<p::Root, p::Trustd, o::Kick> = E::new(shared(edge("ROOT_TRUSTD_RELAY", Root, Chosen, Trustd, Kick, Signal,
    Fixed(trust::RELAY_BADGE), 1, Root, "another partition's trustd answered or asked (guest 63's bit too)")));

// ---- vmmgr, the VMMs and the guests.
pub const GUEST_CTL: E<p::Guest, p::Vmmgr, o::Notification> = E::new(edge("GUEST_CTL", Guest, Chosen, Vmmgr, Notification, Signal,
    Fixed(badges::vmmgr::CTL_KICK), 1, Vmmgr, "dom0 made a control request (its control device's kick)"));
pub const GUEST_VMM_KICK: E<p::Guest, p::Vmm, o::Notification> = E::new(edge("GUEST_VMM_KICK", Guest, Chosen, Vmm, Notification, Signal,
    Fixed(badges::vmm::KICK), 1, Vmmgr, "a guest device was kicked (its device CNode)"));
pub const GUEST_VMM_MEM: E<p::Guest, p::Vmm, o::Notification> = E::new(edge("GUEST_VMM_MEM", Guest, Chosen, Vmm, Notification, Signal,
    Fixed(badges::vmm::MEM_REQ), 1, Vmmgr, "a hotplug request in the memory device page"));
pub const GUEST_VMM_CONSOLE: E<p::Guest, p::Vmm, o::Notification> = E::new(edge("GUEST_VMM_CONSOLE", Guest, Slots(abi::SLOT_CONSOLE_KICK as u64, 1), Vmm,
    Notification, Signal, Fixed(badges::vmm::CONSOLE), 1, Vmmgr, "the guest wrote to its console ring"));
pub const VMMGR_VMM: E<p::Vmmgr, p::Vmm, o::Notification> = E::new(edge("VMMGR_VMM", Vmmgr, Chosen, Vmm, Notification, Signal,
    Fixed(badges::vmm::MEM), 1, Vmmgr, "the guest's hotplug target changed"));
pub const VMM_VCPU: E<p::Vmm, p::Guest, o::Vcpu> = E::new(shared(edge("VMM_VCPU", Vmm, Slots(crate::VCPU_NTFN_SLOT_BASE, abi::MAX_VCPUS), Guest, Vcpu, Signal,
    Fixed(abi::BADGE_EVENT), 1, Vmmgr, "raise device events on vCPU v")));
pub const GUEST_IPI: E<p::Guest, p::Guest, o::Vcpu> = E::new(edge("GUEST_IPI", Guest, Chosen, Guest, Vcpu, Signal,
    Fixed(abi::BADGE_IPI), 1, Vmmgr, "a guest's IPIs to its own vCPUs (abi::VCPU_IPI of each)"));
pub const VMMGR_VCPU: E<p::Vmmgr, p::Guest, o::Vcpu> = E::new(shared(edge("VMMGR_VCPU", Vmmgr, Chosen, Guest, Vcpu, Signal,
    Fixed(abi::BADGE_EVENT), 1, Vmmgr, "raise events vmmgr serves (attestation, control) on vCPU 0")));

/// Every edge.
pub const EDGES: &[Edge] = &[
    ROOT_MEMD.0, VMMGR_MEMD.0, VMMGR_VMM_MEMD.0, VMM_MEMD.0, TRUSTD_ROOT.0, VMMGR_ROOT.0, VMM_VMMGR.0, ROOT_FLAGS.0, VMMGR_FLAGS.0,
    TRUSTD_FLAGS.0, GUEST_VMM.0,
    TRUSTD_FAULT.0, FLAGS_FAULT.0, BLKD_FAULT.0, NETD_FAULT.0, USBD_FAULT.0, LOGD_FAULT.0, VMM_FAULT.0, MEMD_KEEPER_FAULT.0,
    VMMGR_KEEPER_FAULT.0, GUEST_FAULT.0,
    ROOT_BLKD_CALL.0, ROOT_NETD_CALL.0, ROOT_USBD_CALL.0, ROOT_VMMGR_CALL.0, BLKD_DONE.0, NETD_DONE.0, USBD_DONE.0, VMMGR_DONE.0,
    VMM_BLKD_KICK.0, VMM_NETD_KICK.0, VMM_USBD_KICK.0, BLKD_VMM_DONE.0, NETD_VMM_DONE.0, USBD_VMM.0,
    IRQ_BLKD.0, IRQ_NETD.0, IRQ_USBD.0, IRQ_MONITOR.0, DOORBELL_ROOT.0, DOORBELL_NETD.0, NETD_LINK_SELF.0, NETD_LINK_RING.0,
    GUEST_TRUSTD.0, ROOT_TRUSTD_RELAY.0,
    GUEST_CTL.0, GUEST_VMM_KICK.0, GUEST_VMM_MEM.0, GUEST_VMM_CONSOLE.0, VMMGR_VMM.0, VMM_VCPU.0, GUEST_IPI.0, VMMGR_VCPU.0,
];

/// The edge by which a component of `kind` calls its parent, if it does:
/// only those get a capability to the parent's endpoint.
pub const fn parent_call(kind: u32) -> Option<&'static Edge> {
    let mut i = 0;
    while i < EDGES.len() {
        let e = &EDGES[i];
        if matches!(e.rights, Rights::Call) && matches!(e.at, At::Slots(crate::SLOT_ROOT_EP, 1)) {
            if let Some(k) = e.holder.kind() {
                if k == kind {
                    return Some(e);
                }
            }
        }
        i += 1;
    }
    None
}

/// The edge by which a component of `kind`'s main thread faults to its
/// parent, if it has no keeper (FLAGS_FAULT, trustd's second thread's,
/// aside).
pub const fn parent_fault(kind: u32) -> Option<&'static Edge> {
    fault_of(kind, Rights::Fault)
}

/// The edge by which a component of `kind`'s keeper faults to its parent,
/// if it has one.
pub const fn keeper_fault(kind: u32) -> Option<&'static Edge> {
    fault_of(kind, Rights::KeeperFault)
}

const fn fault_of(kind: u32, rights: Rights) -> Option<&'static Edge> {
    let mut i = 0;
    while i < EDGES.len() {
        let e = &EDGES[i];
        if e.rights as u8 == rights as u8 && !matches!(e.badge, Badge::Fixed(b) if b == COMPONENT_FAULT | crate::root::FLAGS_ID as u64) {
            if let Some(k) = e.holder.kind() {
                if k == kind {
                    return Some(e);
                }
            }
        }
        i += 1;
    }
    None
}

// ---- The checks.

/// The badge space of an object, if the host declares one.
const fn space(target: Party, object: Object) -> Option<(&'static [Bits], u64)> {
    Some(match (target, object) {
        (Root, Endpoint | Notification) => (badges::root::OWN, badges::root::SIGNALS),
        (Vmmgr, Endpoint | Notification) => (badges::vmmgr::OWN, badges::vmmgr::SIGNALS),
        (Memd, Endpoint | Notification) => (badges::memd::OWN, badges::memd::SIGNALS),
        (Blkd, Notification) => (badges::blkd::OWN, badges::blkd::SIGNALS),
        (Netd, Notification) => (badges::netd::OWN, badges::netd::SIGNALS),
        (Usbd, Notification) => (badges::usbd::OWN, badges::usbd::SIGNALS),
        (Vmm, Endpoint | Notification) => (badges::vmm::OWN, badges::vmm::SIGNALS),
        (Trustd, Notification) => (badges::trustd::OWN, badges::trustd::SIGNALS),
        (Trustd, Kick) => (badges::trustd_kick::OWN, badges::trustd_kick::SIGNALS),
        (Trustd, Flags) => (badges::flags::OWN, badges::flags::SIGNALS),
        (Logd, Notification) => (badges::logd::OWN, badges::logd::SIGNALS),
        _ => return None,
    })
}

/// Whether the protocol of a call's target accepts the badge as a sender.
const fn accepts(target: Party, object: Object, badge: u64) -> bool {
    match (target, object) {
        (Root, Endpoint) => crate::root::Sender::of_badge(badge).is_some(),
        (Vmmgr, Endpoint) => crate::vmmgr::Sender::of_badge(badge).is_some(),
        (Memd, Endpoint) => crate::memd::Sender::of_badge(badge).is_some(),
        (Trustd, Flags) => trust::Sender::of_badge(badge).is_some(),
        (Vmm, Endpoint) => crate::hypercall::Sender::of_badge(badge).is_some(),
        _ => false,
    }
}

const fn same(a: Party, b: Party) -> bool {
    a as u8 == b as u8
}

const fn same_object(a: &Edge, b: &Edge) -> bool {
    same(a.target, b.target) && a.object as u8 == b.object as u8
}

const fn check(edges: &[Edge]) -> Result<(), &'static str> {
    let mut i = 0;
    while i < edges.len() {
        let e = &edges[i];
        let last = e.instances - 1;
        match e.rights {
            Rights::Call => {
                if !accepts(e.target, e.object, e.badge.at(0)) || !accepts(e.target, e.object, e.badge.at(last)) {
                    return Err(e.name);
                }
                // Root never waits on a driver, nor on vmmgr or a VMM.
                if same(e.holder, Root) && matches!(e.target, Blkd | Netd | Usbd | Vmmgr | Vmm) {
                    return Err(e.name);
                }
            }
            Rights::Signal | Rights::Bind => match space(e.target, e.object) {
                Some((_, signals)) => {
                    if e.badge.mask() & !signals != 0 {
                        return Err(e.name);
                    }
                }
                None => {}
            },
            Rights::Fault | Rights::KeeperFault => {
                if e.badge.mask() & badges::parent::FAULT == 0 {
                    return Err(e.name);
                }
            }
        }
        let mut j = i + 1;
        while j < edges.len() {
            let f = &edges[j];
            let both_shared = e.shared && f.shared;
            // No two capabilities in the same slots of the same holder.
            if let (At::Slots(a, n), At::Slots(b, m)) = (e.at, f.at) {
                if same(e.holder, f.holder) && a < b + m as u64 && b < a + n as u64 && !both_shared {
                    return Err(e.name);
                }
            }
            // No two signals on the same bits of the same notification.
            let signals = matches!(e.rights, Rights::Signal | Rights::Bind) && matches!(f.rights, Rights::Signal | Rights::Bind);
            if signals && same_object(e, f) && e.badge.mask() & f.badge.mask() != 0 && !both_shared {
                return Err(e.name);
            }
            // No two calls with the same badge on the same endpoint.
            if matches!(e.rights, Rights::Call) && matches!(f.rights, Rights::Call) && same_object(e, f)
                && matches!((e.badge, f.badge), (Badge::Fixed(x), Badge::Fixed(y)) if x == y)
                && !matches!(e.holder, Vmmgr) && !matches!(f.holder, Vmmgr) {
                // vmmgr holds a copy of root's flags capability (VMMGR_FLAGS).
                return Err(e.name);
            }
            j += 1;
        }
        i += 1;
    }
    Ok(())
}

/// Whether a host component calls into `p` (so a caller blocks on it).
const fn called(p: Party) -> bool {
    let mut i = 0;
    while i < EDGES.len() {
        let e = &EDGES[i];
        if matches!(e.rights, Rights::Call) && same(e.target, p) && !same(e.holder, p) && !matches!(e.holder, Guest) {
            return true;
        }
        i += 1;
    }
    false
}

/// The keeper rule (host::has_keeper): a component host callers block on
/// has a keeper to answer them if it fails, and has no fault edge to its
/// parent; one they do not, faults to its parent.  trustd is called (its
/// flags thread) and has none: a flags thread that faults stops the host.
const fn keepers() -> Result<(), &'static str> {
    let kinds = [Vmmgr, Memd, Trustd, Blkd, Netd, Usbd, Logd, Vmm];
    let mut i = 0;
    while i < kinds.len() {
        let p = kinds[i];
        let Some(kind) = p.kind() else { return Err("party without a kind") };
        let keeper = crate::has_keeper(kind);
        if keeper != (called(p) && !matches!(p, Trustd)) || keeper == parent_fault(kind).is_some()
            || keeper != keeper_fault(kind).is_some() {
            return Err("host::has_keeper does not follow the wiring");
        }
        i += 1;
    }
    Ok(())
}

const _: () = match check(EDGES) {
    Ok(()) => {}
    Err(_) => panic!("the wiring does not check: an edge's slot, badge or rights"),
};
const _: () = match keepers() {
    Ok(()) => {}
    Err(e) => panic!("{}", e),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edges_check() {
        assert_eq!(check(EDGES), Ok(()));
        assert_eq!(keepers(), Ok(()));
        // Who calls its parent: trustd and vmmgr root, the VMMs vmmgr.
        assert!(parent_call(crate::KIND_TRUSTD).is_some() && parent_call(crate::KIND_VMMGR).is_some()
            && parent_call(crate::KIND_VMM).is_some());
        for k in [crate::KIND_MEMD, crate::KIND_BLKD, crate::KIND_NETD, crate::KIND_USBD, crate::KIND_LOGD] {
            assert!(parent_call(k).is_none());
        }
        assert_eq!(VMM_VMMGR.badge(7), badges::parent::COMPONENT | 7);
        assert_eq!(VMMGR_VMM_MEMD.slot(3), vmmgr::SLOT_VMM_MEMD_EP + 3);
    }

    #[test]
    fn checks_refuse() {
        // Two edges in one slot, a call no sender matches, root calling a
        // driver, a signal outside its space.
        let mut twice = VMMGR_MEMD.0;
        twice.name = "TWICE";
        assert_eq!(check(&[VMMGR_MEMD.0, twice]), Err("VMMGR_MEMD"));
        let mut stranger = TRUSTD_ROOT.0;
        stranger.badge = Fixed(badges::root::COMPONENT | 0x123);
        assert!(check(&[stranger]).is_err());
        let mut to_driver = ROOT_MEMD.0;
        to_driver.target = Blkd;
        assert!(check(&[to_driver]).is_err());
        let mut odd = IRQ_BLKD.0;
        odd.badge = Fixed(1 << 50);
        assert!(check(&[odd]).is_err());
    }

    #[test]
    fn types_must_match() {
        extern crate std;
        // Another target, or another protocol, than the edge's.
        assert!(std::panic::catch_unwind(|| E::<p::Root, p::Vmmgr, o::Endpoint, crate::memd::call::Proto>::new(ROOT_MEMD.0)).is_err());
        assert!(std::panic::catch_unwind(|| E::<p::Root, p::Memd, o::Endpoint, crate::root::call::Proto>::new(ROOT_MEMD.0)).is_err());
        assert!(std::panic::catch_unwind(|| E::<p::Root, p::Memd, o::Endpoint>::new(ROOT_MEMD.0)).is_err());
        assert_eq!(VMMGR_ROOT.protocol, <crate::root::call::Proto as Protocol>::NAME);
    }
}
