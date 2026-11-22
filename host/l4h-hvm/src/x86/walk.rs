//! The guest's own paging, walked in software: what l4h-hvm reads of an
//! instruction it emulates, and the string operands of MOVS and STOS,
//! are at linear addresses the guest's page tables translate.  Covers no
//! paging (real mode, and protected mode without CR0.PG), 32-bit paging
//! (with 4 MiB pages), PAE and 4-level paging (with 2 MiB and 1 GiB pages),
//! with the present, write, user and execute-disable checks and accessed
//! and dirty bits that the CPU applies.  5-level paging is not offered
//! to guests (CPUID LA57), as FL4 pages with 4 levels.  Free of seL4.

pub const CR0_PE: u64 = 1 << 0;
pub const CR0_WP: u64 = 1 << 16;
pub const CR0_PG: u64 = 1 << 31;
pub const CR4_PSE: u64 = 1 << 4;
pub const CR4_PAE: u64 = 1 << 5;
pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;
pub const EFER_LME: u64 = 1 << 8;
pub const EFER_LMA: u64 = 1 << 10;
pub const EFER_NXE: u64 = 1 << 11;

const P: u64 = 1 << 0;
const RW: u64 = 1 << 1;
const US: u64 = 1 << 2;
const A: u64 = 1 << 5;
const D: u64 = 1 << 6;
const PS: u64 = 1 << 7;
const XD: u64 = 1 << 63;
/// Bits 51:12 of an entry: the next table, or the frame.
const ADDR: u64 = 0x000f_ffff_ffff_f000;

/// The registers paging depends on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Paging {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
}

/// What an access is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Access {
    pub write: bool,
    /// From CPL 3.
    pub user: bool,
    /// An instruction fetch.
    pub fetch: bool,
    /// RFLAGS.AC, which lets a supervisor data access reach user pages
    /// under SMAP.
    pub ac: bool,
}

/// A page fault, with the error code the CPU would push.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageFault {
    pub error: u32,
}

const PF_P: u32 = 1 << 0;
const PF_W: u32 = 1 << 1;
const PF_U: u32 = 1 << 2;
const PF_I: u32 = 1 << 4;

/// Guest-physical memory as the walker sees it.
pub trait Tables {
    /// The entry of `bytes` (4 or 8) at `gpa`, or None if `gpa` is no RAM
    /// (the CPU would not find a table there either: the walk stops).
    fn entry(&mut self, gpa: u64, bytes: u8) -> Option<u64>;
    /// Set `bits` in the entry at `gpa` (accessed, dirty), atomically.
    fn set(&mut self, gpa: u64, bytes: u8, bits: u64);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Fault(PageFault),
    /// A table was outside RAM.
    BadTable,
}

/// The guest-physical address of `linear` for `access`, setting accessed
/// (and, for a write, dirty) bits as the CPU does.
pub fn translate(p: &Paging, linear: u64, access: Access, mem: &mut impl Tables) -> Result<u64, Error> {
    if p.cr0 & CR0_PG == 0 {
        // Linear addresses are 32 bits wide without paging (outside
        // IA-32e mode, which needs paging).
        return Ok(linear & 0xffff_ffff);
    }
    let fault = |present: bool| {
        let mut e = if present { PF_P } else { 0 };
        if access.write {
            e |= PF_W;
        }
        if access.user {
            e |= PF_U;
        }
        if access.fetch {
            e |= PF_I;
        }
        Error::Fault(PageFault { error: e })
    };
    // (address of the entry, its size) at each level, with what the
    // entries allow so far.
    let (mut table, levels, bytes): (u64, u32, u8) = if p.efer & EFER_LMA != 0 {
        (p.cr3 & ADDR, 4, 8)
    } else if p.cr4 & CR4_PAE != 0 {
        // The PDPTEs: the CPU loads them with CR3; read them now.
        let pdpte_at = (p.cr3 & 0xffff_ffe0) + ((linear >> 30) & 3) * 8;
        let pdpte = mem.entry(pdpte_at, 8).ok_or(Error::BadTable)?;
        if pdpte & P == 0 {
            return Err(fault(false));
        }
        (pdpte & ADDR, 2, 8)
    } else {
        (p.cr3 & 0xffff_f000, 2, 4)
    };
    let nx = p.efer & EFER_NXE != 0;
    let (mut writable, mut user_ok, mut exec_ok) = (true, true, true);
    let mut level = levels;
    loop {
        // Index bits of this level.
        let (shift, index_bits) = if bytes == 4 { (12 + 10 * (level - 1), 10) } else { (12 + 9 * (level - 1), 9) };
        let index = (linear >> shift) & ((1 << index_bits) - 1);
        let at = table + index * bytes as u64;
        let e = mem.entry(at, bytes).ok_or(Error::BadTable)?;
        if e & P == 0 {
            return Err(fault(false));
        }
        writable &= e & RW != 0;
        user_ok &= e & US != 0;
        if nx && bytes == 8 {
            exec_ok &= e & XD == 0;
        }
        // A large page: PS at the PD level (4 MiB with 32-bit paging and
        // CR4.PSE, 2 MiB otherwise), and the PDPT level in 4-level paging
        // (1 GiB).
        let large = level > 1 && e & PS != 0 && (level == 2 || (levels == 4 && level == 3)) && (bytes == 8 || p.cr4 & CR4_PSE != 0);
        if level == 1 || large {
            // Permission checks, as the CPU's (supervisor writes honour
            // read-only pages with CR0.WP; SMEP and SMAP for supervisor
            // accesses to user pages, SMAP but for RFLAGS.AC).
            let denied = (access.write && !writable && (access.user || p.cr0 & CR0_WP != 0))
                || (access.user && !user_ok)
                || (access.fetch && !exec_ok)
                || (!access.user && user_ok && access.fetch && p.cr4 & CR4_SMEP != 0)
                || (!access.user && user_ok && !access.fetch && !access.ac && p.cr4 & CR4_SMAP != 0);
            if denied {
                return Err(fault(true));
            }
            mem.set(at, bytes, if access.write { A | D } else { A });
            let page_bits = shift as u64;
            let frame = if large {
                if bytes == 4 {
                    // 4 MiB page: bits 31:22, and 39:32 from bits 20:13.
                    (e & 0xffc0_0000) | ((e >> 13) & 0xff) << 32
                } else {
                    e & ADDR & !((1u64 << page_bits) - 1)
                }
            } else {
                e & if bytes == 4 { 0xffff_f000 } else { ADDR }
            };
            return Ok(frame | (linear & ((1u64 << page_bits) - 1)));
        }
        if e & A == 0 {
            mem.set(at, bytes, A);
        }
        table = e & if bytes == 4 { 0xffff_f000 } else { ADDR };
        level -= 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::collections::BTreeMap;

    struct Mem(BTreeMap<u64, u64>);

    impl Tables for Mem {
        fn entry(&mut self, gpa: u64, _bytes: u8) -> Option<u64> {
            if gpa >= 1 << 32 {
                return None;
            }
            Some(*self.0.get(&gpa).unwrap_or(&0))
        }
        fn set(&mut self, gpa: u64, _bytes: u8, bits: u64) {
            *self.0.entry(gpa).or_insert(0) |= bits;
        }
    }

    const R: Access = Access { write: false, user: false, fetch: false, ac: false };
    const W: Access = Access { write: true, user: false, fetch: false, ac: false };

    fn long_mode() -> (Mem, Paging) {
        let mut m = Mem(BTreeMap::new());
        // PML4 at 0x1000, PDPT at 0x2000, PD at 0x3000, PT at 0x4000.
        m.0.insert(0x1000, 0x2000 | P | RW);
        m.0.insert(0x2000, 0x3000 | P | RW);
        m.0.insert(0x2008, 0x4000_0000 | P | RW | PS); // 1 GiB at 1 GiB
        m.0.insert(0x3000, 0x4000 | P | RW);
        m.0.insert(0x3008, 0x0060_0000 | P | PS); // 2 MiB at 2 MiB, read-only
        m.0.insert(0x4000 + 5 * 8, 0x9000 | P | RW | XD); // 4 KiB at 0x5000
        (m, Paging { cr0: CR0_PE | CR0_PG | CR0_WP, cr3: 0x1000, cr4: CR4_PAE, efer: EFER_LME | EFER_LMA | EFER_NXE })
    }

    #[test]
    fn four_level() {
        let (mut m, p) = long_mode();
        assert_eq!(translate(&p, 0x5123, R, &mut m), Ok(0x9123));
        assert!(m.0[&0x4028] & A != 0 && m.0[&0x4028] & D == 0);
        assert_eq!(translate(&p, 0x5000, W, &mut m), Ok(0x9000));
        assert!(m.0[&0x4028] & D != 0);
        assert_eq!(translate(&p, 0x20_1234, R, &mut m), Ok(0x60_1234));
        assert_eq!(translate(&p, 0x4000_0000 + 0x12_3456, R, &mut m), Ok(0x4012_3456));
        // Read-only with WP, not present, execute-disabled, user.
        assert_eq!(translate(&p, 0x20_0000, W, &mut m), Err(Error::Fault(PageFault { error: PF_P | PF_W })));
        assert_eq!(translate(&p, 0x6000, R, &mut m), Err(Error::Fault(PageFault { error: 0 })));
        let f = Access { fetch: true, ..R };
        assert_eq!(translate(&p, 0x5000, f, &mut m), Err(Error::Fault(PageFault { error: PF_P | PF_I })));
        let u = Access { user: true, ..R };
        assert_eq!(translate(&p, 0x5000, u, &mut m), Err(Error::Fault(PageFault { error: PF_P | PF_U })));
        // Without WP a supervisor write to a read-only page goes through.
        let p2 = Paging { cr0: p.cr0 & !CR0_WP, ..p };
        assert_eq!(translate(&p2, 0x20_0000, W, &mut m), Ok(0x60_0000));
        // A table outside RAM.
        m.0.insert(0x1008, (1 << 33) | P);
        assert_eq!(translate(&p, 1 << 39, R, &mut m), Err(Error::BadTable));
    }

    /// SMAP refuses a supervisor data access to a user page, unless
    /// RFLAGS.AC; SMEP a supervisor fetch from one.
    #[test]
    fn smap_and_ac() {
        let (mut m, p) = long_mode();
        for e in [0x1000, 0x2000, 0x3000, 0x4028] {
            *m.0.get_mut(&e).unwrap() |= US;
        }
        let p = Paging { cr4: p.cr4 | CR4_SMAP | CR4_SMEP, ..p };
        assert_eq!(translate(&p, 0x5010, R, &mut m), Err(Error::Fault(PageFault { error: PF_P })));
        assert_eq!(translate(&p, 0x5010, W, &mut m), Err(Error::Fault(PageFault { error: PF_P | PF_W })));
        assert_eq!(translate(&p, 0x5010, Access { ac: true, ..R }, &mut m), Ok(0x9010));
        assert_eq!(translate(&p, 0x5010, Access { ac: true, ..W }, &mut m), Ok(0x9010));
        // AC does not let a supervisor fetch from it, and a user access
        // needs none.
        let f = Access { fetch: true, ac: true, ..R };
        assert!(translate(&Paging { efer: p.efer & !EFER_NXE, ..p }, 0x5010, f, &mut m).is_err());
        assert_eq!(translate(&p, 0x5010, Access { user: true, ..R }, &mut m), Ok(0x9010));
    }

    #[test]
    fn legacy_modes() {
        let mut m = Mem(BTreeMap::new());
        // No paging: the low 32 bits.
        let none = Paging { cr0: CR0_PE, ..Default::default() };
        assert_eq!(translate(&none, 0x1_2345_6789, R, &mut m), Ok(0x2345_6789));
        assert_eq!(translate(&Paging::default(), 0xb8000, R, &mut m), Ok(0xb8000));
        // 32-bit paging: PD at 0x1000, a 4 MiB page and a PT.
        m.0.insert(0x1000, 0x2000 | P | RW | US);
        m.0.insert(0x1004, 0x0080_0000 | P | RW | PS | (0x3 << 13)); // 4 MiB at 0x3_0080_0000
        m.0.insert(0x2000 + 3 * 4, 0x7000 | P | RW | US);
        let p32 = Paging { cr0: CR0_PE | CR0_PG, cr3: 0x1000, cr4: CR4_PSE, efer: 0 };
        assert_eq!(translate(&p32, 0x3abc, R, &mut m), Ok(0x7abc));
        assert_eq!(translate(&p32, 0x40_0010, R, &mut m), Ok(0x3_0080_0010));
        // Without PSE the PS bit means nothing: entry 1 is a table.
        let nopse = Paging { cr4: 0, ..p32 };
        assert_eq!(translate(&nopse, 0x40_0010, R, &mut m), Err(Error::Fault(PageFault { error: 0 })));
        // PAE: the PDPTE from CR3 (32-byte aligned), 2 MiB and 4 KiB pages.
        let mut m = Mem(BTreeMap::new());
        m.0.insert(0x5020, 0x6000 | P);
        m.0.insert(0x5028, 0x7000 | P);
        m.0.insert(0x6000, 0x8000 | P | RW);
        m.0.insert(0x8000 + 8, 0xa000 | P | RW);
        m.0.insert(0x7000, 0x0040_0000 | P | RW | PS);
        let pae = Paging { cr0: CR0_PE | CR0_PG, cr3: 0x5020, cr4: CR4_PAE, efer: 0 };
        assert_eq!(translate(&pae, 0x1234, R, &mut m), Ok(0xa234));
        assert_eq!(translate(&pae, 0x4000_0000 + 0x1_2345, R, &mut m), Ok(0x41_2345));
        assert_eq!(translate(&pae, 0x8000_0000, R, &mut m), Err(Error::Fault(PageFault { error: 0 })));
    }
}
