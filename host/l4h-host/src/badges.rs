//! The badge spaces of host receivers (crate::wire::badge_space): every
//! badge bit an endpoint, with the notification bound to its thread, can
//! see, declared once.  Whoever mints a capability to the receiver and the
//! receiver's serve loop both use these, and a space does not compile if
//! two of its ranges overlap.

crate::badge_space! {
    /// What a parent sees on its endpoint from the components it spawned
    /// (l4h_task::component): their calls, badged COMPONENT | ID, and their
    /// faults, badged COMPONENT | FAULT | ID.  Both root's and vmmgr's
    /// spaces include it.
    pub mod parent {
        /// The component's id.
        field ID: 0..16;
        /// A fault message.  A failed parent's keeper leaves faults
        /// unanswered: the thread would only fault again.
        flag FAULT: 24;
        /// A component's call or fault.
        flag COMPONENT: 25;
    }
}

crate::badge_space! {
    /// l4h-root's serve loop: calls and faults of its components (trustd,
    /// vmmgr) on its endpoint, and signals on its bound notification.
    pub mod root: super::parent {
        /// Its deadline timer (seL4_TCB_SetTimer).
        signal TIMER: 40;
        /// The serial monitor's interrupt.
        signal MONITOR: 41;
        /// A doorbell from another partition (l4h-root's channel.rs).
        signal CHANNEL: 42;
        /// A driver answered in its mailbox (crate::mailbox).
        signal MAILBOX: 43;
        /// netd asks root to ring the doorbell of link l's peer: bit l.
        signals LINK: 44..44 + crate::net::MAX_LINKS as u32;
    }
}

crate::badge_space! {
    /// l4h-vmmgr's serve loop: calls and faults of guests' l4h-vmms, faults
    /// of guest kernels, and signals on its bound notification.
    pub mod vmmgr: super::parent {
        /// A guest kernel's fault is FAULT | VCPU | ID (its guest), without
        /// COMPONENT.
        field VCPU: 16..24;
        /// Its deadline timer (seL4_TCB_SetTimer).
        signal TIMER: 40;
        /// dom0 made a control request in its device page (abi::CtlSync).
        signal CTL_KICK: 41;
        /// Root's signal: the events page has news (crate::vmmgr::Events).
        signal ROOT_EVENT: 42;
    }
}

/// A guest kernel vCPU's fault badge on vmmgr's endpoint.
pub const fn guest_fault(guest: usize, vcpu: usize) -> u64 {
    vmmgr::FAULT | vmmgr::ID.put(guest as u64) | vmmgr::VCPU.put(vcpu as u64)
}

crate::badge_space! {
    /// l4h-memd's service endpoint (crate::memd::call).  l4h-root calls
    /// with an unbadged capability.
    pub mod memd {
        /// A guest's l4h-vmm: VMM | GUEST.
        flag VMM: 62;
        /// The VMM's guest.
        field GUEST: 0..16;
        /// l4h-vmmgr.
        flag VMMGR: 61;
        /// memd's deadline timer, on its bound notification.
        signal TIMER: 40;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values these replace, from before the spaces existed.
    #[test]
    fn unchanged() {
        assert_eq!(parent::FAULT, 1 << 24);
        assert_eq!(parent::COMPONENT, 1 << 25);
        assert_eq!(root::SIGNALS, (1 << 40) | (1 << 41) | (1 << 42) | (1 << 43) | (((1 << crate::net::MAX_LINKS) - 1) << 44));
        assert_eq!(vmmgr::SIGNALS, (1 << 40) | (1 << 41) | (1 << 42));
        assert_eq!(guest_fault(3, 5), (1 << 24) | 3 | (5 << 16));
        assert_eq!(memd::VMM | memd::GUEST.put(7), (1 << 62) | 7);
        assert_eq!(memd::VMMGR, 1 << 61);
    }
}
