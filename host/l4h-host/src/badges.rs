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
        /// Root posted in vmmgr's mailbox (crate::vmmgr::call).
        signal MAILBOX: 42;
    }
}

crate::badge_space! {
    /// What every driver with a mailbox (crate::mailbox: blkd, netd,
    /// usbd, nicd) sees on its bound notification from root.  Their spaces
    /// include it.
    pub mod driver {
        /// Root posted requests in the mailbox.
        signal CALL: 62;
    }
}

crate::badge_space! {
    /// l4h-blkd's bound notification.
    pub mod blkd: super::driver {
        /// A client kicked its channel.
        signal KICK: 0;
        /// The controller's interrupt.
        signal IRQ: 1;
    }
}

crate::badge_space! {
    /// l4h-netd's bound notification.
    pub mod netd: super::driver {
        /// Port p's client kicked: bit p.
        signals PORT: 0..crate::net::MAX_PORTS as u32;
        /// A nicd produced frames or freed room in its uplink channel
        /// (crate::uplink): netd looks at every uplink.
        signal UPLINK: 48;
        /// Link l's doorbell, and netd's own kick to read it later: bit l.
        signals LINK: 52..52 + crate::net::MAX_LINKS as u32;
    }
}

crate::badge_space! {
    /// A nicd's bound notification.
    pub mod nicd: super::driver {
        /// Its device's interrupt.
        signal IRQ: 0;
        /// netd sent frames or freed room in the uplink channel.
        signal NETD: 1;
        /// Root's periodic tick, for a driver whose manifest has F_TIMER.
        signal TIMER: 2;
    }
}

crate::badge_space! {
    /// l4h-usbd's bound notification.
    pub mod usbd: super::driver {
        /// The controller's interrupt.
        signal IRQ: 0;
        /// The client kicked.
        signal KICK: 1;
    }
}

crate::badge_space! {
    /// The flags server's endpoint (crate::trust::call).
    pub mod flags {
        /// l4h-root's capability (its start-up handshake).
        flag ROOT: 0;
        /// trustd's main thread's (guests' requests).
        flag TRUSTD: 1;
        /// vmmgr's (the host actor's).
        flag VMMGR: 2;
    }
}

crate::badge_space! {
    /// A guest's l4h-vmm: hypercalls on its endpoint, and signals on its
    /// bound notification, which say what kind of source signalled, not
    /// which device: the VMM checks each device's kick word and backend
    /// ring, which is a load or two for an idle one.
    pub mod vmm {
        /// A hypercall (crate::hypercall): the guest's capability to the
        /// endpoint has it, notification badges never.
        flag HYPERCALL: 63;
        /// A guest device was kicked.
        signal KICK: 0;
        /// A device backend (blkd, netd) has completions or room.
        signal DONE: 1;
        /// From l4h-vmmgr: the guest's hotplug target changed.
        signal MEM: 2;
        /// The guest wrote to its console output ring; also the console's
        /// deadline timer.
        signal CONSOLE: 3;
        /// The guest made a hotplug request in its memory device page.
        signal MEM_REQ: 4;
        /// usbd has completions for the guest's USB controller n: bit n,
        /// n < usb::MAX_GUEST_USB.
        signals USB: 8..8 + crate::usb::MAX_GUEST_USB as u32;
    }
}

crate::badge_space! {
    /// trustd's bound notification.
    pub mod trustd {
        /// Its deadline timer, which nothing else signals.
        signal TIMER: 0;
    }
}

crate::badge_space! {
    /// trustd's kick notification (trust::SLOT_KICK).
    pub mod trustd_kick {
        /// Guest g kicked its attestation device: bit g.  The relay shares
        /// guest 63's bit (trust::RELAY_BADGE): kicks are only hints, so
        /// trustd looks at both.
        signals GUEST: 0..crate::trust::MAX_RECORDS as u32;
    }
}

crate::badge_space! {
    /// l4h-logd's bound notification.
    pub mod logd {
        /// Its deadline timer.
        signal TIMER: 0;
    }
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
        let fault = crate::wiring::GUEST_FAULT.badge(crate::wiring::guest_fault(3, 5));
        assert_eq!(fault, (1 << 24) | 3 | (5 << 16));
        assert_eq!((vmmgr::ID.get(fault), vmmgr::VCPU.get(fault)), (3, 5));
        assert_eq!(memd::VMM | memd::GUEST.put(7), (1 << 62) | 7);
        assert_eq!(memd::VMMGR, 1 << 61);
    }
}
