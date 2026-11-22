//! The interrupt messages between an HVM guest's interrupt sources (its
//! local APICs' IPIs, the I/O APIC, MSI) and its local APICs, which any
//! thread of l4h-hvm sends: a fixed interrupt is a bit set in the target's
//! IRR, an NMI, INIT or SIPI a flag, and the target's thread is woken
//! (`Wake`) when it was not set before.  Each local APIC's other state is
//! its vCPU thread's (lapic.rs).  Free of seL4.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

/// Delivery modes (ICR, I/O APIC redirection entries and MSI data).
pub const DM_FIXED: u8 = 0;
pub const DM_LOWEST: u8 = 1;
#[cfg(test)]
pub const DM_SMI: u8 = 2;
pub const DM_NMI: u8 = 4;
pub const DM_INIT: u8 = 5;
pub const DM_SIPI: u8 = 6;

/// What a vCPU has pending besides fixed interrupts (`Shared::flags`).
pub const PENDING_NMI: u32 = 1 << 0;
pub const PENDING_INIT: u32 = 1 << 1;
pub const PENDING_SIPI: u32 = 1 << 2;

/// A local APIC's state that other threads read or write.
pub struct Shared {
    /// Its APIC ID (the vCPU's number).
    pub id: u32,
    /// Fixed interrupts requested: vector v is bit v % 64 of irr[v / 64].
    pub irr: [AtomicU64; 4],
    /// Those of them that are level-triggered, whose EOI the I/O APIC
    /// wants to hear about.
    pub level: [AtomicU64; 4],
    /// PENDING_*.
    pub flags: AtomicU32,
    /// The vector of the last SIPI.
    pub sipi: AtomicU8,
    /// Its logical destination: xAPIC LDR bits 31:24, or x2APIC's LDR.
    pub ldr: AtomicU32,
    /// xAPIC DFR's model: 0xf flat, 0x0 cluster.
    pub dfr_model: AtomicU8,
    /// In x2APIC mode.
    pub x2apic: AtomicBool,
    /// Software-enabled (SVR bit 8): a target of lowest-priority messages.
    pub enabled: AtomicBool,
}

impl Shared {
    pub const fn new(id: u32) -> Self {
        Shared {
            id,
            irr: [const { AtomicU64::new(0) }; 4],
            level: [const { AtomicU64::new(0) }; 4],
            flags: AtomicU32::new(0),
            sipi: AtomicU8::new(0),
            ldr: AtomicU32::new(0),
            dfr_model: AtomicU8::new(0xf),
            x2apic: AtomicBool::new(false),
            enabled: AtomicBool::new(false),
        }
    }

    /// Request fixed interrupt `vector` (level-triggered if `level`):
    /// whether the target should be woken.
    pub fn request(&self, vector: u8, level: bool) -> bool {
        let (w, bit) = ((vector / 64) as usize, 1u64 << (vector % 64));
        if level {
            self.level[w].fetch_or(bit, Ordering::SeqCst);
        }
        self.irr[w].fetch_or(bit, Ordering::SeqCst) & bit == 0
    }

    /// Drop every fixed interrupt requested so far: at INIT, and while
    /// it waits for SIPI (those are of a run that is over).
    pub fn clear_requests(&self) {
        for w in 0..4 {
            self.irr[w].store(0, Ordering::SeqCst);
            self.level[w].store(0, Ordering::SeqCst);
        }
    }

    fn flag(&self, f: u32) -> bool {
        self.flags.fetch_or(f, Ordering::SeqCst) & f == 0
    }

    /// Whether logical destination `dest` names this APIC.
    fn logical_match(&self, dest: u32) -> bool {
        let ldr = self.ldr.load(Ordering::Relaxed);
        if self.x2apic.load(Ordering::Relaxed) {
            // Cluster in bits 31:16, a bit per member in 15:0.
            return dest == u32::MAX || ((dest >> 16) == (ldr >> 16) && dest & ldr & 0xffff != 0);
        }
        let dest = dest & 0xff;
        if dest == 0xff {
            return true;
        }
        let ldr = ldr & 0xff;
        if self.dfr_model.load(Ordering::Relaxed) == 0xf {
            dest & ldr != 0
        } else {
            (dest >> 4) == (ldr >> 4) && dest & ldr & 0xf != 0
        }
    }

    fn physical_match(&self, dest: u32) -> bool {
        if self.x2apic.load(Ordering::Relaxed) {
            dest == u32::MAX || dest == self.id
        } else {
            let dest = dest & 0xff;
            dest == 0xff || dest == self.id
        }
    }
}

/// Destination shorthands (ICR bits 19:18).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shorthand {
    None,
    SelfOnly,
    All,
    AllButSelf,
}

/// An interrupt message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub dest: u32,
    pub logical: bool,
    pub shorthand: Shorthand,
    pub mode: u8,
    pub vector: u8,
    pub level: bool,
}

impl Message {
    /// An MSI: address 0xfee0_0000 with the destination in bits 19:12 and
    /// DM in bit 2, data with the vector, delivery mode and trigger mode.
    /// None for an address outside the interrupt range.
    pub fn msi(addr: u64, data: u32) -> Option<Message> {
        if addr >> 20 != 0xfee {
            return None;
        }
        Some(Message {
            dest: ((addr >> 12) & 0xff) as u32,
            logical: addr & (1 << 2) != 0,
            shorthand: Shorthand::None,
            mode: ((data >> 8) & 7) as u8,
            vector: data as u8,
            level: data & (1 << 15) != 0,
        })
    }
}

/// Deliver `m`, from vCPU `from` (for shorthands), to the local APICs in
/// `apics`; `wake(v)` for each vCPU v that got something new.
pub fn deliver(apics: &[Shared], m: &Message, from: Option<usize>, mut wake: impl FnMut(usize)) {
    let targets = |v: usize, a: &Shared| match m.shorthand {
        Shorthand::SelfOnly => Some(v) == from,
        Shorthand::All => true,
        Shorthand::AllButSelf => Some(v) != from,
        Shorthand::None => if m.logical { a.logical_match(m.dest) } else { a.physical_match(m.dest) },
    };
    if m.mode == DM_LOWEST {
        // To one of them: the first enabled one (the APICs' priorities
        // are not compared; the guest cannot tell the difference).
        let pick = apics.iter().enumerate().filter(|&(v, a)| targets(v, a))
            .find(|(_, a)| a.enabled.load(Ordering::Relaxed))
            .or_else(|| apics.iter().enumerate().find(|&(v, a)| targets(v, a)));
        if let Some((v, a)) = pick
            && a.request(m.vector, m.level)
        {
            wake(v);
        }
        return;
    }
    for (v, a) in apics.iter().enumerate().filter(|&(v, a)| targets(v, a)) {
        let new = match m.mode {
            DM_FIXED => a.request(m.vector, m.level),
            DM_NMI => a.flag(PENDING_NMI),
            DM_INIT => a.flag(PENDING_INIT),
            DM_SIPI => {
                a.sipi.store(m.vector, Ordering::SeqCst);
                a.flag(PENDING_SIPI)
            }
            // No SMM (DM_SMI); no 8259 to take an ExtINT's vector from.
            _ => false,
        };
        if new {
            wake(v);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn apics(n: u32) -> Vec<Shared> {
        (0..n).map(Shared::new).collect()
    }

    fn woken(apics: &[Shared], m: Message, from: Option<usize>) -> Vec<usize> {
        let mut w = Vec::new();
        deliver(apics, &m, from, |v| w.push(v));
        w
    }

    const FIXED: Message = Message { dest: 0, logical: false, shorthand: Shorthand::None, mode: DM_FIXED, vector: 0x31, level: false };

    #[test]
    fn physical_logical_and_shorthands() {
        let a = apics(4);
        assert_eq!(woken(&a, Message { dest: 2, ..FIXED }, None), [2]);
        assert!(a[2].irr[0].load(Ordering::Relaxed) & (1 << 0x31) != 0);
        // Already pending: no second wake.
        assert_eq!(woken(&a, Message { dest: 2, ..FIXED }, None), [] as [usize; 0]);
        assert_eq!(woken(&a, Message { dest: 0xff, vector: 0x40, ..FIXED }, None), [0, 1, 2, 3]);
        // Flat logical: LDR bits.
        for (i, x) in a.iter().enumerate() {
            x.ldr.store(1 << i, Ordering::Relaxed);
        }
        assert_eq!(woken(&a, Message { dest: 0b1010, logical: true, vector: 0x50, ..FIXED }, None), [1, 3]);
        // Cluster model: cluster 1, members 0 and 1.
        for (i, x) in a.iter().enumerate() {
            x.dfr_model.store(0, Ordering::Relaxed);
            x.ldr.store(0x10 | (1 << (i % 2)), Ordering::Relaxed);
        }
        assert_eq!(woken(&a, Message { dest: 0x12, logical: true, vector: 0x51, ..FIXED }, None), [1, 3]);
        // Shorthands.
        let ipi = Message { vector: 0x60, ..FIXED };
        assert_eq!(woken(&a, Message { shorthand: Shorthand::AllButSelf, ..ipi }, Some(1)), [0, 2, 3]);
        assert_eq!(woken(&a, Message { shorthand: Shorthand::SelfOnly, vector: 0x61, ..ipi }, Some(1)), [1]);
        // x2APIC: 32-bit IDs and clustered logical IDs.
        a[3].x2apic.store(true, Ordering::Relaxed);
        a[3].ldr.store((0 << 16) | (1 << 3), Ordering::Relaxed);
        assert_eq!(woken(&a, Message { dest: 3, vector: 0x70, ..FIXED }, None), [3]);
        assert_eq!(woken(&a, Message { dest: 0x8, logical: true, vector: 0x71, ..FIXED }, None), [3]);
    }

    #[test]
    fn modes_and_msi() {
        let a = apics(2);
        a[1].enabled.store(true, Ordering::Relaxed);
        // Lowest priority goes to one enabled target.
        assert_eq!(woken(&a, Message { dest: 0xff, mode: DM_LOWEST, ..FIXED }, None), [1]);
        // INIT, SIPI with its vector, NMI.
        assert_eq!(woken(&a, Message { dest: 1, mode: DM_INIT, ..FIXED }, None), [1]);
        assert_eq!(woken(&a, Message { dest: 1, mode: DM_SIPI, vector: 0x9a, ..FIXED }, None), [1]);
        assert_eq!(a[1].sipi.load(Ordering::Relaxed), 0x9a);
        assert_eq!(a[1].flags.load(Ordering::Relaxed), PENDING_INIT | PENDING_SIPI);
        assert_eq!(woken(&a, Message { dest: 0, mode: DM_NMI, ..FIXED }, None), [0]);
        // SMI and ExtINT are dropped.
        assert_eq!(woken(&a, Message { dest: 0, mode: DM_SMI, ..FIXED }, None), [] as [usize; 0]);
        // A level-triggered message marks the vector for EOI.
        woken(&a, Message { dest: 0, level: true, vector: 0x91, ..FIXED }, None);
        assert!(a[0].level[2].load(Ordering::Relaxed) & (1 << (0x91 - 128)) != 0);
        // MSI decoding.
        let m = Message::msi(0xfee0_1004, 0x4041).unwrap();
        assert_eq!((m.dest, m.logical, m.vector, m.mode, m.level), (1, true, 0x41, DM_FIXED, false));
        assert_eq!(Message::msi(0x1000, 0x41), None);
    }
}
