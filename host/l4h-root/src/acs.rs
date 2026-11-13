//! PCIe Access Control Services (DESIGN.md §9.5, "Peer-to-peer and
//! requester spoofing").  Without ACS a switch routes a request from one
//! of its downstream ports to a sibling's BARs directly, and a root port
//! may route one to another root port inside the root complex: neither
//! request reaches the IOMMU, so a device could write another device's
//! registers whatever its domain maps.  Nor does a port check that a
//! request's requester ID is one behind it, so a device could take
//! another's ID and with it the other's domain and interrupt entries.
//!
//! Root therefore turns on, in every function that has the capability,
//! each of these the function implements, as Linux does
//! (pci_std_enable_acs, with ATS disabled):
//!
//! - Source Validation: a downstream port drops requests whose requester
//!   bus is not behind it;
//! - Translation Blocking: ports drop requests marked translated (ATS),
//!   which would bypass the I/O page tables (root enables ATS nowhere);
//! - P2P Request and Completion Redirect: peer requests and completions go
//!   up to the root complex, and through the IOMMU, instead of across;
//! - Upstream Forwarding: a switch port sends them on upstream rather than
//!   back down.
//!
//! Egress Control and Direct Translated P2P are left as they are.
//!
//! Extended configuration space is reached through ECAM only (pci.rs);
//! the reads and writes are the caller's, so that tests/acs.rs can run
//! this against a model.

/// ACS control (and capability) bits.
pub const SV: u16 = 1 << 0;
pub const TB: u16 = 1 << 1;
pub const RR: u16 = 1 << 2;
pub const CR: u16 = 1 << 3;
pub const UF: u16 = 1 << 4;
/// What root enables, of what a function implements.
pub const ENABLE: u16 = SV | TB | RR | CR | UF;
/// What isolates the functions below a port from each other (Linux's
/// REQ_ACS_FLAGS), of what the port implements: the specification has a
/// port that cannot route peer requests leave Redirect unimplemented.
pub const ISOLATE: u16 = SV | RR | CR | UF;

const EXT_ACS: u32 = 0x000d;
const CAP_PCIE: u8 = 0x10;
/// PCI Express Capabilities register, Device/Port Type.
pub const ROOT_PORT: u8 = 4;
pub const DOWNSTREAM_PORT: u8 = 6;

/// Configuration space of segment 0 functions, `bdf` as bus << 8 |
/// device << 3 | function.
pub trait Config {
    /// A dword of the first 256 bytes; all ones if there is no function.
    fn read(&self, bdf: u16, off: u8) -> u32;
    /// A dword of extended configuration space (0x100..0x1000), if it can
    /// be reached.
    fn read_ext(&self, bdf: u16, off: u16) -> Option<u32>;
    /// Write one; false if the function's space cannot be written.
    fn write_ext(&self, bdf: u16, off: u16, val: u32) -> bool;
}

/// The function's PCI Express capability: its Device/Port Type, if it
/// has one.  A list that loops or points into the header is not followed.
pub fn pcie_type(c: &impl Config, bdf: u16) -> Option<u8> {
    if c.read(bdf, 4) & (1 << 20) == 0 {
        return None;
    }
    let mut cap = (c.read(bdf, 0x34) & 0xfc) as u8;
    let mut seen = 0u64;
    while cap != 0 {
        if cap < 0x40 || seen & (1 << (cap / 4)) != 0 {
            return None;
        }
        seen |= 1 << (cap / 4);
        let header = c.read(bdf, cap);
        if header as u8 == CAP_PCIE {
            return Some((header >> 20 & 0xf) as u8);
        }
        cap = (header >> 8 & 0xfc) as u8;
    }
    None
}

/// The offset of extended capability `id`, if the function has it.  Every
/// header is in [0x100, 0x1000) and dword aligned; a list that loops ends.
fn find_ext(c: &impl Config, bdf: u16, id: u32) -> Option<u16> {
    let mut off = 0x100u16;
    let mut seen = [0u64; 16];
    loop {
        let i = off as usize / 4;
        if seen[i / 64] & (1 << (i % 64)) != 0 {
            return None;
        }
        seen[i / 64] |= 1 << (i % 64);
        let header = c.read_ext(bdf, off)?;
        if header == 0 || header == u32::MAX {
            return None;
        }
        if header & 0xffff == id {
            return Some(off);
        }
        let next = (header >> 20) as u16 & 0xffc;
        if next < 0x100 {
            return None;
        }
        off = next;
    }
}

/// What `enable` found and did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acs {
    /// Extended configuration space cannot be reached, or written.
    Unreachable,
    /// The function has no ACS capability.
    Absent,
    /// The capability's bits, the control before, and as read back after
    /// root's write.
    Present { cap: u16, before: u16, after: u16 },
}

impl Acs {
    /// Whether a port with this isolates the functions below it.
    pub fn isolates(self) -> bool {
        match self {
            Acs::Present { cap, after, .. } => after & cap & ISOLATE == cap & ISOLATE,
            _ => false,
        }
    }
}

/// The ACS capability's offset and its capability and control registers.
fn read_acs(c: &impl Config, bdf: u16) -> Result<(u16, u16, u16), Acs> {
    if c.read_ext(bdf, 0x100).is_none() {
        return Err(Acs::Unreachable);
    }
    let off = find_ext(c, bdf, EXT_ACS).ok_or(Acs::Absent)?;
    // The capability register, then control, in one dword (off <= 0xffc).
    let regs = c.read_ext(bdf, off + 4).ok_or(Acs::Unreachable)?;
    Ok((off, regs as u16, (regs >> 16) as u16))
}

/// What function `bdf` has, without changing it (a bridge another
/// partition owns, which root maps read-only).
pub fn state(c: &impl Config, bdf: u16) -> Acs {
    match read_acs(c, bdf) {
        Ok((_, cap, ctrl)) => Acs::Present { cap, before: ctrl, after: ctrl },
        Err(r) => r,
    }
}

/// Turn on the ENABLE bits function `bdf` implements, keeping the others.
pub fn enable(c: &impl Config, bdf: u16) -> Acs {
    let (off, cap, before) = match read_acs(c, bdf) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let want = before | (cap & ENABLE);
    if want != before && !c.write_ext(bdf, off + 4, (want as u32) << 16 | cap as u32) {
        return Acs::Unreachable;
    }
    let after = c.read_ext(bdf, off + 4).map_or(before, |r| (r >> 16) as u16);
    Acs::Present { cap, before, after }
}

/// The blocks that map [start, end) (page aligned) at virtual addresses
/// `start - base` on (`base` the window's, its bus 0), largest first:
/// 2^bits bytes at each address, aligned to that both physically and
/// virtually, and of at most 2^limit(at) bytes (the free device Untyped
/// `at` is in).  They are of 2 MiB frames where bits >= 21, else of
/// 4 KiB ones.  An ECAM window of whole 2 MiB-aligned buses is a few
/// carves of 2 MiB frames: one device Untyped split a few times, and a
/// slot per 2 MiB, where a page per function would split the device
/// memory table into hundreds of pieces (devmem.rs).  A block of fewer
/// than 12 bits (no free memory at `at`, or a range not page aligned)
/// ends the list: the caller refuses the window.
pub fn blocks(start: u64, end: u64, base: u64, limit: impl Fn(u64) -> u32) -> impl Iterator<Item = (u64, u32)> {
    let mut at = start;
    core::iter::from_fn(move || {
        if at >= end {
            return None;
        }
        // A window is at most 256 MiB (256 buses); 1 GiB bounds the shift.
        let bits = at.trailing_zeros()
            .min(at.wrapping_sub(base).trailing_zeros())
            .min(63 - (end - at).leading_zeros())
            .min(limit(at))
            .min(30);
        let block = (at, bits);
        at = if bits < 12 { end } else { at + (1 << bits) };
        Some(block)
    })
}

/// Whether bridge `bdf` has a function on its secondary bus.
pub fn has_children(c: &impl Config, bdf: u16) -> bool {
    let buses = c.read(bdf, 0x18);
    let secondary = (buses >> 8) as u8;
    // A disabled bridge, or one that names its own bus.
    if secondary == 0 || secondary as u16 == bdf >> 8 {
        return false;
    }
    // Every function: a partition may see a device's function 1 but not 0.
    (0..256u16).any(|devfn| c.read((secondary as u16) << 8 | devfn, 0) & 0xffff != 0xffff)
}

/// The functions of `functions` (every one root found, as bus << 8 |
/// device << 3 | function) that DMA from function `me` may reach without
/// passing the IOMMU, each given to `add` (`me` among them, some more
/// than once): the other functions of its device, unless ACS on `me`
/// isolates them, and, up the tree, everything below each bridge that
/// does not isolate the ports under it.  A device's other functions are
/// those found in its slot: only function 0 need say it has several.
pub fn group<I: Iterator<Item = u16>>(c: &impl Config, functions: impl Fn() -> I, me: u16, mut add: impl FnMut(u16)) {
    let header = |b: u16| (c.read(b, 0x0c) >> 16) as u8;
    let buses = |b: u16| {
        let r = c.read(b, 0x18);
        ((r >> 8) as u8, (r >> 16) as u8)
    };
    let below = |sec: u8, sub: u8, add: &mut dyn FnMut(u16)| {
        if sec != 0 {
            for f in functions().filter(|&f| (sec..=sub).contains(&((f >> 8) as u8)) && header(f) & 0x7f == 0) {
                add(f);
            }
        }
    };
    add(me);
    if !state(c, me).isolates() {
        for f in functions().filter(|&f| f >> 3 == me >> 3) {
            add(f);
        }
    }
    let mut bus = (me >> 8) as u8;
    for _ in 0..256 {
        // The bridge whose secondary bus this is: the immediate parent,
        // then its parent, and so on (one higher up that isolates does
        // not keep peers below a lower one apart).
        let Some(bridge) = functions().find(|&f| header(f) & 0x7f == 1 && {
            let (sec, _) = buses(f);
            sec != 0 && sec == bus
        }) else {
            break;
        };
        if !(pcie_type(c, bridge).is_some() && state(c, bridge).isolates()) {
            let (sec, sub) = buses(bridge);
            below(sec, sub, &mut add);
            // A bridge without ACS may route to its sibling functions'
            // buses too.
            for sib in functions().filter(|&f| f >> 3 == bridge >> 3 && f != bridge && header(f) & 0x7f == 1) {
                let (s2, e2) = buses(sib);
                below(s2, e2, &mut add);
            }
        }
        if (bridge >> 8) as u8 >= bus {
            break;
        }
        bus = (bridge >> 8) as u8;
    }
}

/// The names of the bits set in `bits`, for the log.
pub struct Bits(pub u16);

impl core::fmt::Display for Bits {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut first = true;
        for (bit, name) in [(SV, "SV"), (TB, "TB"), (RR, "RR"), (CR, "CR"), (UF, "UF"), (1 << 5, "EC"), (1 << 6, "DT")] {
            if self.0 & bit != 0 {
                write!(f, "{}{}", if first { "" } else { " " }, name)?;
                first = false;
            }
        }
        if first {
            f.write_str("none")?;
        }
        Ok(())
    }
}
