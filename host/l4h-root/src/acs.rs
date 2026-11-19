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
/// Direct Translated P2P: the function routes translated requests
/// between its own functions, so it has peer paths inside it.
pub const DT: u16 = 1 << 6;
/// PCI Express Capabilities register, Device/Port Type.
pub const ENDPOINT: u8 = 0;
pub const LEGACY_ENDPOINT: u8 = 1;
pub const ROOT_PORT: u8 = 4;
pub const UPSTREAM_PORT: u8 = 5;
pub const DOWNSTREAM_PORT: u8 = 6;
pub const RC_ENDPOINT: u8 = 9;

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
    /// Whether a function of Device/Port Type `ty` (pcie_type) with this
    /// keeps what it routes apart: a port the functions below it, an
    /// endpoint (one of several in a device) its sibling functions.  What
    /// the type must implement is required, not only what it happens to:
    /// a capability that implements none of the bits is no isolation.
    ///
    /// - A root port must validate sources (SV); it has nothing above it
    ///   to forward to (no UF) and may leave Redirect unimplemented if it
    ///   cannot route peer requests at all.
    /// - A switch downstream port must validate sources and forward
    ///   upstream (SV and UF).
    /// - An endpoint has no SV; one that routes between its functions
    ///   (DT) must redirect (RR and CR), and one that implements neither
    ///   says it has no path between them.
    /// - A switch upstream port has no ACS and routes nothing between
    ///   branches itself (its downstream ports do: group walks past it);
    ///   PCI bridges and every other type never isolate.
    ///
    /// Every bit it implements of those that matter must also be on.
    pub fn isolates(self, ty: Option<u8>) -> bool {
        let Acs::Present { cap, after, .. } = self else {
            return false;
        };
        let on = |bits: u16| after & cap & bits == cap & bits;
        match ty {
            Some(ROOT_PORT) => cap & SV == SV && on(ISOLATE),
            Some(DOWNSTREAM_PORT) => cap & (SV | UF) == SV | UF && on(ISOLATE),
            Some(ENDPOINT | LEGACY_ENDPOINT | RC_ENDPOINT) =>
                (cap & DT == 0 || cap & (RR | CR) == RR | CR) && on(RR | CR | UF),
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
/// passing the IOMMU, or that may reach `me` so, each given to `add`
/// (`me` among them, some more than once):
///
/// - the other functions of its device (and what is below those that are
///   bridges), unless every function of the device isolates with ACS:
///   one that does not reaches its siblings whatever their own ACS says.
///   A device's other functions are those found in its slot: only
///   function 0 need say it has several;
/// - up the tree, everything below each bridge that does not isolate the
///   ports under it, and the same for the other functions of each
///   bridge's device;
/// - where such a bridge is a root port (any bridge on a root bus) or a
///   switch downstream port, a peer request from below it crosses the
///   bus the bridge is on, so everything on that bus and below each
///   bridge on it: and, the other way, everything below such a bridge on
///   any bus the walk passes, as it reaches `me` in turn.
///
/// A switch upstream port is walked past: it routes nothing between the
/// downstream ports on its secondary bus, which decide that themselves.
/// This is one step: a caller wanting every function a group's members
/// reach takes its closure.
pub fn group<I: Iterator<Item = u16>>(c: &impl Config, functions: impl Fn() -> I, me: u16, mut add: impl FnMut(u16)) {
    let header = |b: u16| (c.read(b, 0x0c) >> 16) as u8;
    let is_bridge = |b: u16| header(b) & 0x7f == 1;
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
    let below_bridge = |b: u16, add: &mut dyn FnMut(u16)| {
        let (sec, sub) = buses(b);
        below(sec, sub, add);
    };
    let isolates = |f: u16| state(c, f).isolates(pcie_type(c, f));
    // The bridge whose secondary bus is `bus`, if any (none: a root bus).
    let above = |bus: u8| functions().find(|&f| is_bridge(f) && {
        let (sec, _) = buses(f);
        sec != 0 && sec == bus
    });
    // The other functions of `f`'s device, and below those that are
    // bridges, if there are any and one of the device's functions does
    // not isolate.
    let slot = |f: u16, add: &mut dyn FnMut(u16)| {
        let sibs = || functions().filter(move |&s| s >> 3 == f >> 3 && s != f);
        if sibs().next().is_none() || (isolates(f) && sibs().all(isolates)) {
            return;
        }
        // A host bridge can occupy function zero beside independent root
        // ports. Keep the branches apart when each port redirects traffic
        // and owns a distinct bus range.
        let first = f & !7;
        let bus = (f >> 8) as u8;
        if c.read(first, 8) >> 8 == 0x060000
            && header(first) & 0x7f == 0
            && c.read(first, 4) & (1 << 20) == 0
            && above(bus).is_none()
        {
            let mut routed = [false; 256];
            let mut ports = sibs().chain(core::iter::once(f)).filter(|&b| b != first);
            if ports.all(|b| {
                let (sec, sub) = buses(b);
                if !is_bridge(b)
                    || c.read(b, 8) >> 8 != 0x060400
                    || pcie_type(c, b) != Some(ROOT_PORT)
                    || c.read(b, 0x18) as u8 != bus
                    || sec <= bus
                    || sub < sec
                    || !matches!(state(c, b), Acs::Present { cap, after, .. }
                        if cap & ISOLATE == ISOLATE && after & ISOLATE == ISOLATE)
                {
                    return false;
                }
                let range = &mut routed[sec as usize..=sub as usize];
                if range.contains(&true) {
                    return false;
                }
                range.fill(true);
                true
            }) {
                return;
            }
        }
        for sib in sibs() {
            add(sib);
            if is_bridge(sib) {
                below_bridge(sib, add);
            }
        }
    };
    // Whether a peer request from below bridge `b` may cross the bus `b`
    // is on: it does not isolate, and is a root port or other bridge on a
    // root bus, or a switch downstream port.
    let crosses = |b: u16| {
        let ty = pcie_type(c, b);
        ty != Some(UPSTREAM_PORT) && !isolates(b)
            && (ty == Some(DOWNSTREAM_PORT) || above((b >> 8) as u8).is_none())
    };
    // Everything on `bus`, and below each bridge on it.
    let across = |bus: u8, add: &mut dyn FnMut(u16)| {
        for f in functions().filter(|&f| (f >> 8) as u8 == bus) {
            if is_bridge(f) {
                below_bridge(f, add);
            } else if header(f) & 0x7f == 0 {
                add(f);
            }
        }
    };
    // What reaches across `bus` from below its bridges reaches `me`.
    let crossing = |bus: u8, add: &mut dyn FnMut(u16)| {
        for b in functions().filter(|&f| (f >> 8) as u8 == bus && is_bridge(f) && crosses(f)) {
            below_bridge(b, add);
        }
    };
    add(me);
    slot(me, &mut add);
    let mut bus = (me >> 8) as u8;
    crossing(bus, &mut add);
    for _ in 0..256 {
        // The bridge whose secondary bus this is: the immediate parent,
        // then its parent, and so on (one higher up that isolates does
        // not keep peers below a lower one apart).
        let Some(bridge) = above(bus) else {
            break;
        };
        slot(bridge, &mut add);
        if pcie_type(c, bridge) != Some(UPSTREAM_PORT) && !isolates(bridge) {
            below_bridge(bridge, &mut add);
            if crosses(bridge) {
                across((bridge >> 8) as u8, &mut add);
            }
        }
        if (bridge >> 8) as u8 >= bus {
            break;
        }
        bus = (bridge >> 8) as u8;
        crossing(bus, &mut add);
    }
}

/// Function `me`'s isolation group, into `out`: the closure, over every
/// member, of what it reaches past the IOMMU (`group`) and of the
/// functions the IOMMU translates as its requester (`requester`), which
/// share its domain whatever ACS does.  A peer may itself share another's
/// domain, or reach further.  The number of members, or None if more than
/// `out` holds.
pub fn closure<I: Iterator<Item = u16>>(c: &impl Config, functions: impl Fn() -> I + Copy,
    requester: impl Fn(u16) -> u16, me: u16, out: &mut [u16]) -> Option<usize> {
    let mut len = 0;
    let mut full = false;
    let mut add = |out: &mut [u16], len: &mut usize, b: u16| {
        if !out[..*len].contains(&b) {
            match out.get_mut(*len) {
                Some(slot) => { *slot = b; *len += 1; }
                None => full = true,
            }
        }
    };
    add(out, &mut len, me);
    let mut i = 0;
    while i < len {
        let m = out[i];
        i += 1;
        group(c, functions, m, |b| add(out, &mut len, b));
        let r = requester(m);
        for f in functions().filter(|&f| requester(f) == r) {
            add(out, &mut len, f);
        }
    }
    (!full).then_some(len)
}

/// A member of `me`'s isolation group (`closure`) that `owner` gives to
/// another partition than `me`'s, if any: the multikernel shim refuses
/// such a split, as a device could then reach another partition's
/// devices past the IOMMU, or share a domain with them.  Bridges, which
/// take no part in DMA, are no members here.  Err if the group has more
/// members than `out` holds.  The shim's (boot/l4h-mkshim), not root's.
#[allow(dead_code)]
pub fn other_owner<I: Iterator<Item = u16>>(c: &impl Config, functions: impl Fn() -> I + Copy,
    requester: impl Fn(u16) -> u16, owner: impl Fn(u16) -> u8, me: u16, out: &mut [u16]) -> Result<Option<u16>, ()> {
    let n = closure(c, functions, requester, me, out).ok_or(())?;
    let endpoint = |b: u16| (c.read(b, 0x0c) >> 16) as u8 & 0x7f == 0;
    Ok(out[..n].iter().copied().find(|&f| endpoint(f) && owner(f) != owner(me)))
}

/// What a member of a NIC's isolation group is to root, for
/// `confined_group`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// The NIC itself.
    Me,
    /// Another NIC root drives: whether it may share the group with this
    /// one's driver (it has no driver, or the same one).
    Nic(bool),
    /// Any other function root found, with its header type (offset 0x0e).
    Other(u8),
    /// A function root did not find.
    Unknown,
}

/// Whether a NIC whose isolation group (`closure`; u16::MAX for one too
/// large to check) is `group` is confined: every member is the NIC, a NIC
/// that may share it, or a bridge.  Bridges take no part in DMA (as for
/// `other_owner`): they are members only as `group` walks the path.  Any
/// other function may be a target of the NIC's peer-to-peer requests, or
/// share its IOMMU domain, whoever owns it: one root left as the firmware
/// set it up, or found too late to be driven, may decode its BARs and
/// master the bus all the same.  One root does not know is refused too.
pub fn confined_group(group: &[u16], peer: impl Fn(u16) -> Peer) -> bool {
    !group.is_empty()
        && group.iter().all(|&f| {
            f != u16::MAX
                && match peer(f) {
                    Peer::Me => true,
                    Peer::Nic(ok) => ok,
                    Peer::Other(header) => header & 0x7f == 1,
                    Peer::Unknown => false,
                }
        })
}

/// The names of the bits set in `bits`, for the log.
pub struct Bits(pub u16);

impl core::fmt::Display for Bits {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut first = true;
        for (bit, name) in [(SV, "SV"), (TB, "TB"), (RR, "RR"), (CR, "CR"), (UF, "UF"), (1 << 5, "EC"), (DT, "DT")] {
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

/// Alias entries of an AMD IVRS, at most: one per PCI(-X) bridge that
/// takes its functions' requests as its own.
#[allow(dead_code)]
pub const MAX_IVRS_ALIASES: usize = 64;

/// The requester IDs an AMD IVRS gives functions in place of their own:
/// IVHD device entries 0x42 (one function) and 0x43..0x04 (a range), of
/// the IVHD root reads for each IOMMU (amdvi.rs `parse`: the highest type
/// known, PCI segment 0).  Root translates a function's DMA in its
/// alias's domain, so the shim (boot/l4h-mkshim) groups the functions
/// that share one (`closure`'s `requester`): the firmware may alias what
/// the bridges' types do not show.  A later entry for an ID that names no
/// alias is not taken off: grouping more refuses splits root would allow,
/// never the other way.  The shim's, not root's.
#[allow(dead_code)]
pub struct IvrsAliases {
    /// (first, last, alias), in table order: the last that covers an ID
    /// wins, as in root's table.
    ranges: [(u16, u16, u16); MAX_IVRS_ALIASES],
    len: usize,
}

#[allow(dead_code)]
impl IvrsAliases {
    /// Read them from `ivrs`, the whole table.  None if it is malformed or
    /// has more than MAX_IVRS_ALIASES.
    pub fn parse(ivrs: &[u8]) -> Option<IvrsAliases> {
        let u16_at = |b: &[u8], o: usize| -> Option<u16> { Some(u16::from_le_bytes([*b.get(o)?, *b.get(o + 1)?])) };
        // The table its header says, and every block in it whole: the
        // walk below then never stops short of an alias.
        if ivrs.get(..4)? != b"IVRS" {
            return None;
        }
        let len = u32::from_le_bytes(ivrs.get(4..8)?.try_into().ok()?) as usize;
        let ivrs = ivrs.get(..len).filter(|t| t.len() >= 48)?;
        let mut at = 48;
        while at < ivrs.len() {
            let len = u16_at(ivrs, at + 2)? as usize;
            if len < 4 || len > ivrs.len() - at {
                return None;
            }
            at += len;
        }
        let blocks = || {
            let mut at = 48;
            core::iter::from_fn(move || {
                let len = u16_at(ivrs, at + 2)? as usize;
                let block = ivrs.get(at..at + len).filter(|_| len >= 4)?;
                at += len;
                Some(block)
            })
        };
        let ivhd = |b: &[u8]| matches!(b[0], 0x10 | 0x11 | 0x40) && b.len() >= 24 && u16_at(b, 16) == Some(0);
        let mut me = IvrsAliases { ranges: [(0, 0, 0); MAX_IVRS_ALIASES], len: 0 };
        for b in blocks().filter(|b| ivhd(b)) {
            // Root reads one IVHD per IOMMU: the highest type.
            let id = u16_at(b, 4);
            if blocks().any(|o| ivhd(o) && u16_at(o, 4) == id && o[0] > b[0]) {
                continue;
            }
            let header = if b[0] == 0x10 { 24 } else { 40 };
            let mut e = b.get(header..)?;
            let mut range: Option<(u16, Option<u16>)> = None;
            while let Some(&kind) = e.first() {
                let len = match kind {
                    0..=0x7f => 4 << (kind >> 6),
                    0xf0 => *e.get(21)? as usize + 22,
                    // Root skips the rest of the IVHD: an alias could
                    // follow, unread.  Refused.
                    _ => return None,
                };
                let ent = e.get(..len)?;
                e = &e[len..];
                let id = u16_at(ent, 1)?;
                match kind {
                    // A range starts inside none, and ends up from its start.
                    0x03 | 0x47 | 0x43 if range.is_some() => return None,
                    0x03 | 0x47 => range = Some((id, None)),
                    0x43 => range = Some((id, Some(u16_at(ent, 5)?))),
                    0x04 => {
                        let (first, alias) = range.take()?;
                        if first > id {
                            return None;
                        }
                        if let Some(alias) = alias {
                            me.push(first, id, alias)?;
                        }
                    }
                    0x42 => me.push(id, id, u16_at(ent, 5)?)?,
                    _ => {}
                }
            }
            if range.is_some() {
                return None;
            }
        }
        Some(me)
    }

    fn push(&mut self, first: u16, last: u16, alias: u16) -> Option<()> {
        *self.ranges.get_mut(self.len)? = (first, last, alias);
        self.len += 1;
        Some(())
    }

    /// The requester ID function `bdf`'s DMA reaches the IOMMU with.
    pub fn requester(&self, bdf: u16) -> u16 {
        self.ranges[..self.len].iter().rev().find(|r| (r.0..=r.1).contains(&bdf)).map_or(bdf, |r| r.2)
    }
}
