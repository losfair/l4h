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
    /// Fixed interrupts requested, two bits a vector, so that a request
    /// and its trigger mode are set, taken and cleared at once: vector v's
    /// are bits 2 (v % 32) (requested) and 2 (v % 32) + 1 (level-triggered:
    /// the I/O APIC wants to hear of its EOI) of req[v / 32].
    req: [AtomicU64; 8],
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

/// Bits 0, 2, .., 62 of `x` as bits 0..32 (the requested bits of a `req`
/// word, without their trigger modes): every vCPU entry and halt poll
/// looks at the IRR.
fn even_bits(x: u64) -> u64 {
    let mut x = x & 0x5555_5555_5555_5555;
    x = (x | x >> 1) & 0x3333_3333_3333_3333;
    x = (x | x >> 2) & 0x0f0f_0f0f_0f0f_0f0f;
    x = (x | x >> 4) & 0x00ff_00ff_00ff_00ff;
    x = (x | x >> 8) & 0x0000_ffff_0000_ffff;
    (x | x >> 16) & 0xffff_ffff
}

impl Shared {
    pub const fn new(id: u32) -> Self {
        Shared {
            id,
            req: [const { AtomicU64::new(0) }; 8],
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
        let (w, shift) = ((vector / 32) as usize, 2 * (vector % 32) as u32);
        let bits = if level { 0b11 } else { 0b01 };
        self.req[w].fetch_or(bits << shift, Ordering::SeqCst) & (1 << shift) == 0
    }

    /// Take request `vector`: whether it was requested, and level-triggered.
    pub fn take(&self, vector: u8) -> Option<bool> {
        let (w, shift) = ((vector / 32) as usize, 2 * (vector % 32) as u32);
        let old = self.req[w].fetch_and(!(0b11 << shift), Ordering::SeqCst) >> shift;
        (old & 1 != 0).then_some(old & 2 != 0)
    }

    /// The IRR: vector v is bit v % 64 of word v / 64.
    pub fn irr(&self) -> [u64; 4] {
        let mut irr = [0u64; 4];
        for (w, r) in self.req.iter().enumerate() {
            let r = r.load(Ordering::Acquire);
            if r != 0 {
                irr[w / 2] |= even_bits(r) << (32 * (w % 2));
            }
        }
        irr
    }

    /// Drop every fixed interrupt requested so far, with its trigger mode
    /// (each word at once): at INIT, and while it waits for SIPI (those
    /// are of a run that is over).
    pub fn clear_requests(&self) {
        for w in &self.req {
            w.store(0, Ordering::SeqCst);
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

    #[test]
    fn even_bits_takes_every_other_bit() {
        for x in [0u64, 1, 2, 3, u64::MAX, 0x5555_5555_5555_5555, 0xaaaa_aaaa_aaaa_aaaa, 0x8000_0000_0000_0001, 0x1234_5678_9abc_def0] {
            let want = (0..32).fold(0u64, |m, i| m | ((x >> (2 * i)) & 1) << i);
            assert_eq!(even_bits(x), want, "{x:#x}");
        }
    }
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
        assert!(a[2].irr()[0] & (1 << 0x31) != 0);
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

    /// A request and its trigger mode go together: cleared at once, and
    /// taken at once, never one without the other.
    #[test]
    fn requests_with_their_trigger_mode() {
        let a = Shared::new(0);
        for v in [0x20u8, 0x5f, 0x60, 0xff] {
            assert!(a.request(v, true));
            assert!(!a.request(v, true), "already requested");
        }
        assert!(a.request(0x21, false));
        assert_eq!(a.irr()[0] & (1 << 0x20 | 1 << 0x21), 1 << 0x20 | 1 << 0x21);
        a.clear_requests();
        assert_eq!(a.irr(), [0; 4]);
        for v in [0x20u8, 0x5f, 0x60, 0xff] {
            assert_eq!(a.take(v), None, "no trigger mode left behind for {v:#x}");
        }
        // An edge request after a level one of the same vector, cleared:
        // edge again.
        a.request(0x40, true);
        a.clear_requests();
        a.request(0x40, false);
        assert_eq!(a.take(0x40), Some(false));
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
        assert!(a[0].irr()[2] & (1 << (0x91 - 128)) != 0);
        assert_eq!(a[0].take(0x91), Some(true));
        assert_eq!(a[0].take(0x91), None, "taken");
        // MSI decoding.
        let m = Message::msi(0xfee0_1004, 0x4041).unwrap();
        assert_eq!((m.dest, m.logical, m.vector, m.mode, m.level), (1, true, 0x41, DM_FIXED, false));
        assert_eq!(Message::msi(0x1000, 0x41), None);
    }
}
