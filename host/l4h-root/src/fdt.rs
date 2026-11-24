//! What root reads of a flattened device tree (the DTB FL4 passes in its
//! extra BootInfo): whether QEMU virt's GICv2m frame is there and enabled.
//! Every read is bounds-checked, nothing is allocated: a truncated or
//! corrupt tree is no GICv2m.  Host tests: tests/fdt.rs.

const MAGIC: u32 = 0xd00d_feed;
const BEGIN_NODE: u32 = 1;
const END_NODE: u32 = 2;
const PROP: u32 = 3;
const NOP: u32 = 4;
const END: u32 = 9;
/// Deeper trees are refused (QEMU virt's GICv2m is at depth 3).
const MAX_DEPTH: usize = 16;

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
        2 => Some((be32(b, off)? as u64) << 32 | be32(b, off + 4)? as u64),
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
