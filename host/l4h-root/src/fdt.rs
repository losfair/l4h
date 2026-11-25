//! Flattened device tree (FDT) parsing for AArch64 (the DTB passed in
//! `SEL4_BOOTINFO_HEADER_FDT`, chunk id 6):
//! - `has_qemu_gicv2m`: whether QEMU virt's GICv2m frame is present and enabled.
//! - `parse` / `ArmHw`: runtime AArch64 hardware discovery (UART, RTC, PCI ECAM,
//!   PCI MMIO32 window, GICv2m, and PCI INTx interrupt-map).
//!
//! Every read is bounds-checked, nothing is allocated: a truncated or corrupt
//! tree is rejected. Pure byte-slice parsing is architecture-independent so host
//! unit tests (`tests/fdt.rs`) exercise both parsers on x86_64 as well.

const MAGIC: u32 = 0xd00d_feed;
const BEGIN_NODE: u32 = 1;
const END_NODE: u32 = 2;
const PROP: u32 = 3;
const NOP: u32 = 4;
const END: u32 = 9;
/// Deeper trees are refused (QEMU virt's GICv2m is at depth 3).
const MAX_DEPTH: usize = 16;
const MAX_INTC: usize = 16;
pub const MAX_INTX: usize = 64;

/// QEMU virt's GICv2m frame, whose SPIs 80-143 root uses for MSIs
/// (pci::msi_irq).
pub const QEMU_V2M_BASE: u64 = 0x0802_0000;
const QEMU_V2M_SPI_BASE: u32 = 80;
const QEMU_V2M_SPIS: u32 = 64;

fn be32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}

/// A NUL-terminated string at `off` in `b`, without its NUL.
fn cstr(b: &[u8], off: usize) -> Option<&[u8]> {
    let s = b.get(off..)?;
    Some(&s[..s.iter().position(|&c| c == 0)?])
}

/// What one node, on the path being walked, has said so far.
#[derive(Clone, Copy)]
struct Node {
    /// Its children's reg cells.
    address_cells: u32,
    size_cells: u32,
    /// An empty `ranges`: its children's addresses are its own (without
    /// one they are not CPU addresses at all).
    ranges_identity: bool,
    v2m: bool,
    msi_controller: bool,
    enabled: bool,
    spis_ok: bool,
    /// Its `reg` value, as (offset, length) in the tree.
    reg: Option<(usize, usize)>,
}

impl Node {
    const NEW: Node = Node {
        address_cells: 2,
        size_cells: 1,
        ranges_identity: false,
        v2m: false,
        msi_controller: false,
        enabled: true,
        spis_ok: true,
        reg: None,
    };
}

/// A `cells`-cell big-endian number at `off`.
fn cells(b: &[u8], off: usize, cells: u32) -> Option<u64> {
    match cells {
        1 => be32(b, off).map(u64::from),
        2 => Some((be32(b, off)? as u64) << 32 | be32(b, off.checked_add(4)?)? as u64),
        _ => None,
    }
}

/// Whether `dtb`, a whole well-formed tree, has an enabled
/// `arm,gic-v2m-frame` MSI controller under enabled parents at QEMU virt's
/// address (its first `reg`, through empty `ranges` only) that gives root
/// QEMU virt's SPIs 80-143, where it says.
pub fn has_qemu_gicv2m(dtb: &[u8]) -> bool {
    walk(dtb).unwrap_or(false)
}

fn walk(dtb: &[u8]) -> Option<bool> {
    if be32(dtb, 0)? != MAGIC {
        return Some(false);
    }
    let total = be32(dtb, 4)? as usize;
    let (off_struct, off_strings) = (be32(dtb, 8)? as usize, be32(dtb, 12)? as usize);
    // size_dt_strings and size_dt_struct: from version 3 and 17.
    let version = be32(dtb, 20)?;
    let (size_strings, size_struct) = (be32(dtb, 32)? as usize, be32(dtb, 36)? as usize);
    if version < 17 || total > dtb.len() {
        return Some(false);
    }
    let dtb = &dtb[..total];
    let strct = dtb.get(off_struct..off_struct.checked_add(size_struct)?)?;
    let strings = dtb.get(off_strings..off_strings.checked_add(size_strings)?)?;

    let mut path = [Node::NEW; MAX_DEPTH + 1];
    let mut depth = 0usize;
    let mut pos = 0usize;
    let mut found = false;
    loop {
        let token = be32(strct, pos)?;
        pos += 4;
        match token {
            BEGIN_NODE => {
                let name = cstr(strct, pos)?;
                pos = (pos + name.len() + 1).checked_add(3)? & !3;
                depth += 1;
                if depth > MAX_DEPTH {
                    return None;
                }
                path[depth] = Node::NEW;
            }
            END_NODE => {
                if depth == 0 {
                    return None;
                }
                // The root's reg is no device's; a node's reg is in its
                // parent's cells, and an address in the CPU's only through
                // empty ranges up to the root; a disabled parent disables
                // it.  Counted once the whole tree has been read.
                if depth >= 2 && is_qemu_v2m(strct, &path[depth], &path[depth - 1])
                    && path[2..depth].iter().all(|n| n.ranges_identity)
                    && path[1..depth].iter().all(|n| n.enabled)
                {
                    found = true;
                }
                depth -= 1;
            }
            PROP => {
                let len = be32(strct, pos)? as usize;
                let name = cstr(strings, be32(strct, pos + 4)? as usize)?;
                let at = pos + 8;
                let value = strct.get(at..at.checked_add(len)?)?;
                pos = (at + len).checked_add(3)? & !3;
                if depth == 0 {
                    return None;
                }
                let n = &mut path[depth];
                let word = || (len == 4).then(|| be32(value, 0)).flatten();
                match name {
                    b"#address-cells" => n.address_cells = word()?,
                    b"#size-cells" => n.size_cells = word()?,
                    b"ranges" => n.ranges_identity = len == 0,
                    b"compatible" => n.v2m = value.split(|&c| c == 0).any(|s| s == b"arm,gic-v2m-frame")
                        && value.last() == Some(&0),
                    b"msi-controller" => n.msi_controller = true,
                    b"status" => n.enabled = value == b"okay\0" || value == b"ok\0",
                    b"reg" => n.reg = Some((at, len)),
                    b"arm,msi-base-spi" => n.spis_ok &= word() == Some(QEMU_V2M_SPI_BASE),
                    b"arm,msi-num-spis" => n.spis_ok &= word().is_some_and(|s| s >= QEMU_V2M_SPIS),
                    _ => {}
                }
            }
            NOP => {}
            END => return Some(found && depth == 0),
            _ => return None,
        }
    }
}

fn is_qemu_v2m(strct: &[u8], n: &Node, parent: &Node) -> bool {
    if !(n.v2m && n.msi_controller && n.enabled && n.spis_ok) {
        return false;
    }
    let Some((at, len)) = n.reg else { return false };
    let (a, s) = (parent.address_cells, parent.size_cells);
    if !(1..=2).contains(&a) || !(1..=2).contains(&s) || len < 4 * (a + s) as usize {
        return false;
    }
    let base = cells(strct, at, a);
    let size = cells(strct, at + 4 * a as usize, s);
    base == Some(QEMU_V2M_BASE) && size.is_some_and(|s| s >= 0x1000)
}

/// AArch64 platform hardware addresses and interrupt routing discovered at
/// runtime from the FDT, or QEMU `virt` defaults when no FDT chunk is present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmHw {
    pub pl011_base: Option<usize>,
    pub pl031_base: Option<usize>,
    pub pci_ecam: (usize, usize),
    pub pci_mmio32: (u64, u64),
    pub gicv2m: Option<(u64, u32)>,
    pub intx_mask: (u32, u32),
    pub intx_map: [(u32, u32, u32); MAX_INTX],
    pub n_intx: usize,
}

impl ArmHw {
    /// Defaults for QEMU `virt` (`highmem-ecam=off,highmem-mmio=off`, GICv2m).
    pub const fn qemu_virt_default() -> Self {
        Self {
            pl011_base: Some(0x0900_0000),
            pl031_base: Some(0x0901_0000),
            pci_ecam: (0x3f00_0000, 1 << 24),
            pci_mmio32: (0x1000_0000, 0x3eff_0000),
            gicv2m: Some((QEMU_V2M_BASE, QEMU_V2M_SPI_BASE)),
            intx_mask: (0, 0),
            intx_map: [(0, 0, 0); MAX_INTX],
            n_intx: 0,
        }
    }

    /// Resolve a PCI device's legacy INTx pin (1 = INTA .. 4 = INTD) to a GIC
    /// INTID using the parsed PCI `interrupt-map`. Falls back to `64 + dev`
    /// when no `interrupt-map` entry matches.
    pub fn pci_intx_intid(&self, dev: u8, pin: u8) -> u64 {
        let want_hi = ((dev as u32) << 11) & self.intx_mask.0;
        let want_pin = (pin as u32) & self.intx_mask.1;
        for &(hi, p, intid) in &self.intx_map[..self.n_intx] {
            if hi == want_hi && p == want_pin {
                return intid as u64;
            }
        }
        64 + dev as u64
    }
}

fn compat_contains(val: &[u8], needle: &[u8]) -> bool {
    val.split(|&b| b == 0).any(|s| s == needle)
}

fn status_okay(status: Option<&[u8]>) -> bool {
    let Some(s) = status else { return true };
    let s = s.split(|&b| b == 0).next().unwrap_or(b"");
    s.is_empty() || s == b"okay" || s == b"ok"
}

fn read_cells(val: &[u8], off: usize, n_cells: u32) -> Option<u64> {
    match n_cells {
        0 => Some(0),
        1 | 2 => cells(val, off, n_cells),
        _ => None,
    }
}

fn read_reg_first(val: &[u8], ac: u32, sc: u32) -> Option<(u64, u64)> {
    let addr = read_cells(val, 0, ac)?;
    let size_off = (ac as usize).checked_mul(4)?;
    let size = read_cells(val, size_off, sc)?;
    Some((addr, size))
}

#[derive(Clone, Copy)]
struct IntcInfo {
    phandle: u32,
    addr_cells: u32,
    irq_cells: u32,
}

struct NodeProps<'a> {
    compatible: Option<&'a [u8]>,
    status: Option<&'a [u8]>,
    reg: Option<&'a [u8]>,
    ranges: Option<&'a [u8]>,
    msi_base_spi: Option<u32>,
    int_map: Option<&'a [u8]>,
    int_map_mask: Option<&'a [u8]>,
    phandle: Option<u32>,
    explicit_ac: Option<u32>,
    explicit_sc: Option<u32>,
    explicit_ic: Option<u32>,
    processed: bool,
}

impl<'a> NodeProps<'a> {
    const fn empty() -> Self {
        Self {
            compatible: None,
            status: None,
            reg: None,
            ranges: None,
            msi_base_spi: None,
            int_map: None,
            int_map_mask: None,
            phandle: None,
            explicit_ac: None,
            explicit_sc: None,
            explicit_ic: None,
            processed: false,
        }
    }
}

struct FdtBlocks<'a> {
    structs: &'a [u8],
    strings: &'a [u8],
}

fn fdt_blocks(dtb: &[u8]) -> Option<FdtBlocks<'_>> {
    if dtb.len() < 40 || be32(dtb, 0)? != MAGIC {
        return None;
    }
    let total = be32(dtb, 4)? as usize;
    let version = be32(dtb, 20)?;
    if version < 17 || total < 40 || total > dtb.len() {
        return None;
    }
    let dtb = &dtb[..total];
    let off_struct = be32(dtb, 8)? as usize;
    let off_strings = be32(dtb, 12)? as usize;
    let size_strings = be32(dtb, 32)? as usize;
    let size_struct = be32(dtb, 36)? as usize;
    if off_struct < 40 || off_strings < 40 {
        return None;
    }
    let structs = dtb.get(off_struct..off_struct.checked_add(size_struct)?)?;
    let strings = dtb.get(off_strings..off_strings.checked_add(size_strings)?)?;
    Some(FdtBlocks { structs, strings })
}

fn walk_nodes<'a>(blocks: &FdtBlocks<'a>, mut on_node: impl FnMut(&NodeProps<'a>, u32, u32)) -> Option<()> {
    let mut off = 0usize;
    let mut depth = 0usize;
    let mut stack = [const { NodeProps::empty() }; MAX_DEPTH];
    // (addr_cells, size_cells) that apply to children of each level.
    let mut child_cells = [(2u32, 1u32); MAX_DEPTH];

    loop {
        let tok = be32(blocks.structs, off)?;
        off = off.checked_add(4)?;
        match tok {
            BEGIN_NODE => {
                // Finalize parent node before descending into its children.
                if depth > 0 && depth <= MAX_DEPTH && !stack[depth - 1].processed {
                    let parent_idx = depth - 1;
                    let (pac, psc) = if parent_idx > 0 { child_cells[parent_idx - 1] } else { (2, 1) };
                    if let Some(ac) = stack[parent_idx].explicit_ac {
                        child_cells[parent_idx].0 = ac;
                    }
                    if let Some(sc) = stack[parent_idx].explicit_sc {
                        child_cells[parent_idx].1 = sc;
                    }
                    on_node(&stack[parent_idx], pac, psc);
                    stack[parent_idx].processed = true;
                }
                // Skip NUL-terminated node name, aligned to 4 bytes.
                let name = cstr(blocks.structs, off)?;
                off = off.checked_add(name.len())?.checked_add(1)?.checked_add(3)? & !3;
                if depth < MAX_DEPTH {
                    stack[depth] = NodeProps::empty();
                    child_cells[depth] = if depth > 0 { child_cells[depth - 1] } else { (2, 1) };
                }
                depth = depth.checked_add(1)?;
            }
            END_NODE => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth < MAX_DEPTH && !stack[depth].processed {
                    let (pac, psc) = if depth > 0 { child_cells[depth - 1] } else { (2, 1) };
                    if let Some(ac) = stack[depth].explicit_ac {
                        child_cells[depth].0 = ac;
                    }
                    if let Some(sc) = stack[depth].explicit_sc {
                        child_cells[depth].1 = sc;
                    }
                    on_node(&stack[depth], pac, psc);
                    stack[depth].processed = true;
                }
            }
            PROP => {
                let len = be32(blocks.structs, off)? as usize;
                let nameoff = be32(blocks.structs, off.checked_add(4)?)? as usize;
                off = off.checked_add(8)?;
                let val = blocks.structs.get(off..off.checked_add(len)?)?;
                off = off.checked_add(len)?.checked_add(3)? & !3;
                if depth == 0 {
                    return None;
                }
                if depth > MAX_DEPTH {
                    continue;
                }
                let name = cstr(blocks.strings, nameoff)?;
                let cur = &mut stack[depth - 1];
                match name {
                    b"compatible" => cur.compatible = Some(val),
                    b"status" => cur.status = Some(val),
                    b"reg" => cur.reg = Some(val),
                    b"ranges" => cur.ranges = Some(val),
                    b"arm,msi-base-spi" => cur.msi_base_spi = be32(val, 0),
                    b"interrupt-map" => cur.int_map = Some(val),
                    b"interrupt-map-mask" => cur.int_map_mask = Some(val),
                    b"phandle" | b"linux,phandle" => cur.phandle = be32(val, 0),
                    b"#address-cells" => cur.explicit_ac = be32(val, 0),
                    b"#size-cells" => cur.explicit_sc = be32(val, 0),
                    b"#interrupt-cells" => cur.explicit_ic = be32(val, 0),
                    _ => {}
                }
            }
            NOP => {}
            END => return (depth == 0).then_some(()),
            _ => return None,
        }
    }
}

/// Compute an ECAM mapping size that is a power of two in `[1 MiB, 16 MiB]`
/// and divides `ecam_pa` (required by `DevMem::frames` alignment invariant).
fn aligned_ecam_size(ecam_pa: u64, ecam_len: u64) -> usize {
    let max_aligned = if ecam_pa == 0 {
        1usize << 20
    } else {
        1usize << (ecam_pa.trailing_zeros().min(24))
    };
    let raw_cap = (ecam_len.min(1 << 24) as usize).min(max_aligned);
    if raw_cap < (1 << 20) {
        1 << 20
    } else {
        1usize << (usize::BITS - 1 - raw_cap.leading_zeros())
    }
}

fn parse_pci_mmio32(ranges: &[u8], child_ac: u32, parent_ac: u32, child_sc: u32) -> Option<(u64, u64)> {
    if child_ac != 3 {
        return None;
    }
    let stride = child_ac.checked_add(parent_ac)?.checked_add(child_sc)?.checked_mul(4)? as usize;
    if stride == 0 {
        return None;
    }
    let mut best: Option<(u64, u64, bool)> = None; // (start, end, is_prefetch)
    let mut off = 0usize;
    while off.checked_add(stride).is_some_and(|end| end <= ranges.len()) {
        let phys_hi = be32(ranges, off)?;
        let pci_addr = read_cells(ranges, off.checked_add(4)?, 2)?;
        let cpu_addr = read_cells(ranges, off.checked_add(12)?, parent_ac)?;
        let size_off = off.checked_add(12)?.checked_add((parent_ac as usize).checked_mul(4)?)?;
        let size = read_cells(ranges, size_off, child_sc)?;
        off += stride;

        let space = (phys_hi >> 24) & 0x3;
        let prefetch = (phys_hi & 0x4000_0000) != 0;
        if (space == 0x2 || space == 0x3)
            && cpu_addr >= 0x1000
            && cpu_addr < 0x8000_0000
            && pci_addr == cpu_addr
            && size > 0
        {
            let bar_start = cpu_addr;
            let bar_end = cpu_addr.saturating_add(size).min(0x8000_0000);
            if bar_end > bar_start {
                match best {
                    None => best = Some((bar_start, bar_end, prefetch)),
                    Some((_, _, prev_pref)) if prev_pref && !prefetch => {
                        best = Some((bar_start, bar_end, prefetch));
                    }
                    _ => {}
                }
            }
        }
    }
    best.map(|(s, e, _)| (s, e))
}

/// Parse an FDT blob into `ArmHw`. Returns `None` if `dtb` is not a valid FDT.
pub fn parse(dtb: &[u8]) -> Option<ArmHw> {
    let blocks = fdt_blocks(dtb)?;

    // Pass 1: collect interrupt controller phandles and their explicit
    // #address-cells (default 0 per Devicetree spec §2.4.3) and #interrupt-cells.
    let mut intcs = [IntcInfo { phandle: 0, addr_cells: 0, irq_cells: 3 }; MAX_INTC];
    let mut n_intc = 0usize;
    walk_nodes(&blocks, |node, _pac, _psc| {
        if let Some(ph) = node.phandle {
            if n_intc < MAX_INTC && (node.explicit_ic.is_some() || node.explicit_ac.is_some()) {
                intcs[n_intc] = IntcInfo {
                    phandle: ph,
                    addr_cells: node.explicit_ac.unwrap_or(0),
                    irq_cells: node.explicit_ic.unwrap_or(3),
                };
                n_intc += 1;
            }
        }
    })?;

    let mut hw = ArmHw {
        pl011_base: None,
        pl031_base: None,
        pci_ecam: (0x3f00_0000, 1 << 24),
        pci_mmio32: (0x1000_0000, 0x3eff_0000),
        gicv2m: None,
        intx_mask: (0, 0),
        intx_map: [(0, 0, 0); MAX_INTX],
        n_intx: 0,
    };
    let mut found_pci = false;

    // Pass 2: discover UART, RTC, GICv2m, and PCI ECAM / MMIO / INTx map.
    walk_nodes(&blocks, |node, pac, psc| {
        if !status_okay(node.status) {
            return;
        }
        let Some(compat) = node.compatible else { return };

        if hw.pl011_base.is_none()
            && (compat_contains(compat, b"arm,pl011") || compat_contains(compat, b"arm,sbsa-uart"))
        {
            if let Some(reg) = node.reg {
                if let Some((addr, _)) = read_reg_first(reg, pac, psc) {
                    hw.pl011_base = Some(addr as usize);
                }
            }
        }

        if hw.pl031_base.is_none() && compat_contains(compat, b"arm,pl031") {
            if let Some(reg) = node.reg {
                if let Some((addr, _)) = read_reg_first(reg, pac, psc) {
                    hw.pl031_base = Some(addr as usize);
                }
            }
        }

        if hw.gicv2m.is_none() && compat_contains(compat, b"arm,gic-v2m-frame") {
            if let Some(reg) = node.reg {
                if let Some((addr, _)) = read_reg_first(reg, pac, psc) {
                    let base_intid = node.msi_base_spi.map_or(QEMU_V2M_SPI_BASE, |spi| spi + 32);
                    hw.gicv2m = Some((addr, base_intid));
                }
            }
        }

        if !found_pci && compat_contains(compat, b"pci-host-ecam-generic") {
            found_pci = true;
            if let Some(reg) = node.reg {
                if let Some((ecam_pa, ecam_len)) = read_reg_first(reg, pac, psc) {
                    let map_size = aligned_ecam_size(ecam_pa, ecam_len);
                    hw.pci_ecam = (ecam_pa as usize, map_size);
                }
            }
            if let Some(ranges) = node.ranges {
                let child_ac = node.explicit_ac.unwrap_or(3);
                let child_sc = node.explicit_sc.unwrap_or(2);
                if let Some(mmio) = parse_pci_mmio32(ranges, child_ac, pac, child_sc) {
                    hw.pci_mmio32 = mmio;
                }
            }
            if let (Some(map), Some(mask)) = (node.int_map, node.int_map_mask) {
                if let (Some(mask_hi), Some(mask_pin)) = (be32(mask, 0), be32(mask, 12)) {
                    hw.intx_mask = (mask_hi, mask_pin);
                    let mut off = 0usize;
                    while off.checked_add(20).is_some_and(|end| end <= map.len()) {
                        let Some(entry_hi) = be32(map, off) else { break };
                        let Some(entry_pin) = be32(map, off + 12) else { break };
                        let Some(phandle) = be32(map, off + 16) else { break };
                        off += 20;

                        let (intc_ac, intc_ic) = intcs[..n_intc]
                            .iter()
                            .find(|c| c.phandle == phandle)
                            .map_or((0, 3), |c| (c.addr_cells, c.irq_cells));
                        let Some(skip_bytes) = (intc_ac as usize).checked_mul(4) else { break };
                        let Some(irq_bytes) = (intc_ic as usize).checked_mul(4) else { break };
                        let Some(irq_off) = off.checked_add(skip_bytes) else { break };
                        let Some(next_off) = irq_off.checked_add(irq_bytes) else { break };
                        if next_off > map.len() {
                            break;
                        }
                        if intc_ic >= 2 {
                            if let (Some(gic_type), Some(irq_num)) =
                                (be32(map, irq_off), be32(map, irq_off + 4))
                            {
                                if gic_type == 0 && hw.n_intx < MAX_INTX {
                                    hw.intx_map[hw.n_intx] =
                                        (entry_hi & mask_hi, entry_pin & mask_pin, irq_num + 32);
                                    hw.n_intx += 1;
                                }
                            }
                        }
                        off = next_off;
                    }
                }
            }
        }
    })?;

    Some(hw)
}

/// QEMU virt's PL011, where cloud Arm VMs (GCE's C4A) have theirs too.
pub const QEMU_VIRT_UART: usize = 0x0900_0000;

/// A machine with ACPI and no device tree (FL4 under UEFI): the console
/// from the SPCR and PCI's ECAM from the MCFG (the tables, if found, whole
/// or as much as was read).  QEMU virt's other defaults (the PL031, the
/// PCI MMIO aperture) are kept only where the console is virt's: on other
/// machines, bare metal ones, they could name another device, and the
/// aperture root moves BARs into would be no bridge's.  Its ECAM is then
/// none either, without an MCFG.
pub fn from_acpi(spcr: Option<&[u8]>, mcfg: Option<&[u8]>) -> ArmHw {
    let mut hw = ArmHw::qemu_virt_default();
    if let Some(t) = spcr {
        hw.pl011_base = spcr_uart(t);
    }
    let virt = hw.pl011_base == Some(QEMU_VIRT_UART);
    if !virt {
        hw.pl031_base = None;
        hw.pci_mmio32 = (0, 0);
        hw.gicv2m = None;
        hw.pci_ecam = (0, 0);
    }
    if let Some(e) = mcfg.and_then(mcfg_ecam) {
        hw.pci_ecam = e;
    }
    hw
}

/// The SPCR's console, if it is a PL011 or an SBSA generic UART in memory
/// space (ACPI 6.5 SPCR: interface type at 36, its address at 40).
fn spcr_uart(t: &[u8]) -> Option<usize> {
    const PL011: u8 = 0x03;
    const SBSA_32BIT: u8 = 0x0d;
    const SBSA: u8 = 0x0e;
    let ty = *t.get(36)?;
    let space = *t.get(40)?;
    let addr = u64::from_le_bytes(t.get(44..52)?.try_into().ok()?);
    (matches!(ty, PL011 | SBSA_32BIT | SBSA) && space == 0 && addr != 0 && addr % 4096 == 0).then_some(addr as usize)
}

/// Segment 0's ECAM from the MCFG, if its window starts at bus 0: (address,
/// size), at most the 16 buses root maps (layout::ECAM).
fn mcfg_ecam(t: &[u8]) -> Option<(usize, usize)> {
    const MAX_BUSES: usize = 16;
    let mut off = 44;
    while let Some(e) = t.get(off..off + 16) {
        let base = u64::from_le_bytes(e[..8].try_into().ok()?);
        let segment = u16::from_le_bytes([e[8], e[9]]);
        let (start, end) = (e[10] as usize, e[11] as usize);
        if segment == 0 && start == 0 && end >= start && base != 0 && base % 4096 == 0 {
            return Some((base as usize, (end + 1).min(MAX_BUSES) << 20));
        }
        off += 16;
    }
    None
}

#[cfg(all(target_arch = "aarch64", not(test)))]
mod runtime {
    use super::{ArmHw, parse};

    // Single-threaded l4h-root writes HW in init() before any reader.
    static mut HW: ArmHw = ArmHw::qemu_virt_default();

    /// What the device tree says, or with none what the ACPI tables do
    /// (`super::from_acpi`), read through `phys`.
    pub fn init(bootinfo: &sel4::BootInfoPtr, phys: &mut crate::acpi::Phys) {
        // SEL4_BOOTINFO_HEADER_FDT
        const FDT_CHUNK: u64 = 6;
        let fdt = l4h_task::bootinfo::extra_chunk(bootinfo, FDT_CHUNK).and_then(parse);
        let hw = fdt.unwrap_or_else(|| {
            let (mut spcr, mut mcfg) = ([0; 80], [0; 44 + 16 * 4]);
            let spcr = crate::acpi::find(bootinfo, phys, b"SPCR", &mut spcr);
            let mcfg = crate::acpi::find(bootinfo, phys, b"MCFG", &mut mcfg);
            super::from_acpi(spcr.map(|t| &*t), mcfg.map(|t| &*t))
        });
        unsafe { HW = hw };
        info!(
            "l4h-root: fdt: ecam {:#x}+{:#x}, mmio {:#x}..{:#x}, msi {:?}, uart {:?}, rtc {:?}",
            hw.pci_ecam.0,
            hw.pci_ecam.1,
            hw.pci_mmio32.0,
            hw.pci_mmio32.1,
            hw.gicv2m,
            hw.pl011_base,
            hw.pl031_base,
        );
    }

    pub fn hw() -> &'static ArmHw {
        unsafe { &*(&raw const HW) }
    }
}

#[cfg(all(target_arch = "aarch64", not(test)))]
pub use runtime::{hw, init};

#[cfg(test)]
mod tests {
    use super::*;

    struct FdtBuilder {
        structs: Vec<u8>,
        strings: Vec<u8>,
    }

    impl FdtBuilder {
        fn new() -> Self {
            Self { structs: Vec::new(), strings: Vec::new() }
        }

        fn push_u32(&mut self, v: u32) {
            self.structs.extend_from_slice(&v.to_be_bytes());
        }

        fn intern(&mut self, name: &str) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(name.as_bytes());
            self.strings.push(0);
            off
        }

        fn begin_node(&mut self, name: &str) {
            self.push_u32(BEGIN_NODE);
            self.structs.extend_from_slice(name.as_bytes());
            self.structs.push(0);
            while self.structs.len() % 4 != 0 {
                self.structs.push(0);
            }
        }

        fn end_node(&mut self) {
            self.push_u32(END_NODE);
        }

        fn prop(&mut self, name: &str, data: &[u8]) {
            let noff = self.intern(name);
            self.push_u32(PROP);
            self.push_u32(data.len() as u32);
            self.push_u32(noff);
            self.structs.extend_from_slice(data);
            while self.structs.len() % 4 != 0 {
                self.structs.push(0);
            }
        }

        fn prop_u32(&mut self, name: &str, vals: &[u32]) {
            let mut b = Vec::with_capacity(vals.len() * 4);
            for &v in vals {
                b.extend_from_slice(&v.to_be_bytes());
            }
            self.prop(name, &b);
        }

        fn prop_u64(&mut self, name: &str, vals: &[u64]) {
            let mut b = Vec::with_capacity(vals.len() * 8);
            for &v in vals {
                b.extend_from_slice(&v.to_be_bytes());
            }
            self.prop(name, &b);
        }

        fn prop_strs(&mut self, name: &str, strs: &[&str]) {
            let mut b = Vec::new();
            for s in strs {
                b.extend_from_slice(s.as_bytes());
                b.push(0);
            }
            self.prop(name, &b);
        }

        fn finish(mut self) -> Vec<u8> {
            self.push_u32(END);
            let off_rsv = 40u32;
            let rsv_len = 16u32; // empty memreserve terminator
            let off_struct = off_rsv + rsv_len;
            let size_struct = self.structs.len() as u32;
            let off_strings = off_struct + size_struct;
            let size_strings = self.strings.len() as u32;
            let total = off_strings + size_strings;

            let mut out = Vec::with_capacity(total as usize);
            for v in [
                MAGIC, total, off_struct, off_strings, off_rsv, 17, 16, 0, size_strings,
                size_struct,
            ] {
                out.extend_from_slice(&v.to_be_bytes());
            }
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&self.structs);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    #[test]
    fn parses_qemu_virt_gicv2m() {
        let def = ArmHw::qemu_virt_default();
        assert_eq!(def.pl011_base, Some(0x0900_0000));
        assert_eq!(def.gicv2m, Some((QEMU_V2M_BASE, QEMU_V2M_SPI_BASE)));

        let mut b = FdtBuilder::new();
        b.begin_node("");
        b.prop_u32("#address-cells", &[2]);
        b.prop_u32("#size-cells", &[2]);

        // GICv2 + v2m child (with explicit #address-cells = 2 on intc, like QEMU virt)
        b.begin_node("intc@8000000");
        b.prop_strs("compatible", &["arm,cortex-a15-gic"]);
        b.prop_u32("#address-cells", &[2]);
        b.prop_u32("#size-cells", &[2]);
        b.prop_u32("#interrupt-cells", &[3]);
        b.prop_u32("phandle", &[0x8001]);
        b.begin_node("v2m@8020000");
        b.prop_strs("compatible", &["arm,gic-v2m-frame"]);
        b.prop_u64("reg", &[0x0802_0000, 0x1000]);
        b.end_node();
        b.end_node();

        b.begin_node("pl011@9000000");
        b.prop_strs("compatible", &["arm,pl011", "arm,primecell"]);
        b.prop_u64("reg", &[0x0900_0000, 0x1000]);
        b.end_node();

        b.begin_node("pl031@9010000");
        b.prop_strs("compatible", &["arm,pl031", "arm,primecell"]);
        b.prop_u64("reg", &[0x0901_0000, 0x1000]);
        b.end_node();

        b.begin_node("pcie@3f000000");
        b.prop_strs("compatible", &["pci-host-ecam-generic"]);
        b.prop_u32("#address-cells", &[3]);
        b.prop_u32("#size-cells", &[2]);
        b.prop_u64("reg", &[0x3f00_0000, 0x0100_0000]);
        b.prop_u32("ranges", &[
            0x0100_0000, 0, 0, 0, 0x3eff_0000, 0, 0x1_0000,
            0x0200_0000, 0, 0x1000_0000, 0, 0x1000_0000, 0, 0x2eff_0000,
        ]);
        b.prop_u32("interrupt-map-mask", &[0x1800, 0, 0, 0x7]);
        // parent intc has #address-cells = 2 -> 2 zeros between phandle and GIC 3-cell irq
        b.prop_u32("interrupt-map", &[
            0x0000, 0, 0, 1, 0x8001, 0, 0, 0, 3, 4,
            0x0800, 0, 0, 1, 0x8001, 0, 0, 0, 4, 4,
            0x1000, 0, 0, 1, 0x8001, 0, 0, 0, 5, 4,
            0x1800, 0, 0, 1, 0x8001, 0, 0, 0, 6, 4,
        ]);
        b.end_node();

        b.end_node();
        let hw = parse(&b.finish()).unwrap();
        assert_eq!(hw.pl011_base, Some(0x0900_0000));
        assert_eq!(hw.pl031_base, Some(0x0901_0000));
        assert_eq!(hw.pci_ecam, (0x3f00_0000, 1 << 24));
        assert_eq!(hw.pci_mmio32, (0x1000_0000, 0x3eff_0000));
        assert_eq!(hw.gicv2m, Some((0x0802_0000, 80)));
        assert_eq!(hw.pci_intx_intid(0, 1), 35);
        assert_eq!(hw.pci_intx_intid(1, 1), 36);
        assert_eq!(hw.pci_intx_intid(2, 1), 37);
        assert_eq!(hw.pci_intx_intid(5, 1), 36); // swizzled mod 4
    }

    #[test]
    fn parses_apple_vz_gicv3_no_pl011_no_v2m() {
        let mut b = FdtBuilder::new();
        b.begin_node("");
        b.prop_u32("#address-cells", &[2]);
        b.prop_u32("#size-cells", &[2]);

        // GICv3 with NO #address-cells (default 0 per Devicetree spec §2.4.3)
        b.begin_node("intc@10000000");
        b.prop_strs("compatible", &["arm,gic-v3"]);
        b.prop_u32("#interrupt-cells", &[3]);
        b.prop_u32("phandle", &[1]);
        b.end_node();

        // Disabled PL011 must be ignored
        b.begin_node("uart@9000000");
        b.prop_strs("compatible", &["arm,pl011"]);
        b.prop_u64("reg", &[0x0900_0000, 0x1000]);
        b.prop_strs("status", &["disabled"]);
        b.end_node();

        b.begin_node("rtc@20050000");
        b.prop_strs("compatible", &["arm,pl031"]);
        b.prop_u64("reg", &[0x2005_0000, 0x1000]);
        b.end_node();

        b.begin_node("pci@40000000");
        b.prop_strs("compatible", &["pci-host-ecam-generic"]);
        b.prop_u32("#address-cells", &[3]);
        b.prop_u32("#size-cells", &[2]);
        b.prop_u64("reg", &[0x4000_0000, 0x1000_0000]);
        b.prop_u32("ranges", &[
            0x0200_0000, 0, 0x5000_0000, 0, 0x5000_0000, 0, 0x2000_0000,
        ]);
        b.prop_u32("interrupt-map-mask", &[0xf800, 0, 0, 0x7]);
        // parent intc has #address-cells = 0 -> no parent unit address cells
        b.prop_u32("interrupt-map", &[
            0x0800, 0, 0, 1, 1, 0, 0x21, 4,
            0x1000, 0, 0, 1, 1, 0, 0x22, 4,
        ]);
        b.end_node();

        b.end_node();
        let hw = parse(&b.finish()).unwrap();
        assert_eq!(hw.pl011_base, None);
        assert_eq!(hw.pl031_base, Some(0x2005_0000));
        assert_eq!(hw.pci_ecam, (0x4000_0000, 1 << 24));
        assert_eq!(hw.pci_mmio32, (0x5000_0000, 0x7000_0000));
        assert_eq!(hw.gicv2m, None);
        assert_eq!(hw.pci_intx_intid(1, 1), 65);
        assert_eq!(hw.pci_intx_intid(2, 1), 66);
        assert_eq!(hw.pci_intx_intid(3, 1), 67); // fallback
    }

    #[test]
    fn ecam_alignment_invariant_holds() {
        // 0x4020_0000 is 2 MiB aligned, length 16 MiB -> capped to 2 MiB so paddr % size == 0.
        assert_eq!(aligned_ecam_size(0x4020_0000, 0x100_0000), 1 << 21);
        // 0x3f00_0000 is 16 MiB aligned, length 16 MiB -> 16 MiB.
        assert_eq!(aligned_ecam_size(0x3f00_0000, 0x100_0000), 1 << 24);
        // Non-power-of-two length 6 MiB -> largest power of two <= 6 MiB = 4 MiB.
        assert_eq!(aligned_ecam_size(0x4000_0000, 6 << 20), 4 << 20);
        // Invalid FDT rejected cleanly.
        assert!(parse(&[0u8; 64]).is_none());
    }
}
