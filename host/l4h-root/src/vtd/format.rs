//! VT-d legacy table and invalidation formats (Intel VT-d spec, §§6,9,11).

pub const ADDR: u64 = 0x000f_ffff_ffff_f000;
pub const PRESENT: u64 = 1;
pub const READ: u64 = 1;
pub const WRITE: u64 = 2;
pub const SNOOP: u64 = 1 << 11;
pub const IR_ENTRIES: usize = 256;
pub const IR_SIZE: u64 = 7; // 2^(S+1) entries, one page

pub fn levels(cap: u64) -> Option<u8> {
    if cap & (1 << 10) != 0 { Some(4) }
    else if cap & (1 << 9) != 0 { Some(3) }
    else { None }
}

pub fn context(root: usize, domain: u16, levels: u8) -> [u64; 2] {
    [root as u64 | PRESENT, (domain as u64) << 8 | (levels - 2) as u64]
}

/// Interrupt remapping tables shared by several partitions (one per unit,
/// each partition using its share of the entries): 2^(S+1) entries.
pub const IR_SHARED_ENTRIES: usize = 2048;
pub const IR_SHARED_SIZE: u64 = 10;

/// Fixed, edge-triggered, physical delivery to xAPIC ID `dest` (the
/// partition's first CPU, else 0), with exact requester-ID validation
/// (SVT=01, SQ=00). No posted interrupts.
pub fn irte(sid: u16, vector: u8, dest: u32) -> [u64; 2] {
    [PRESENT | (vector as u64) << 16 | (dest as u64 & 0xff) << 40, (1 << 18) | sid as u64]
}

/// Remappable-format MSI, handle in the address, SHV=0, data reserved.
pub fn msi(index: u16) -> (u64, u32) {
    (0xfee0_0010 | ((index as u64 & 0x7fff) << 5) | ((index as u64 >> 15) << 2), 0)
}

pub fn invalidate_context() -> [u64; 2] { [1 | (1 << 4), 0] }
pub fn invalidate_iotlb(domain: Option<u16>, drain: u64) -> [u64; 2] {
    [2 | domain.map_or(1 << 4, |d| (2 << 4) | (d as u64) << 16) | drain, 0]
}
/// Device-selective: requester `sid`'s entries tagged `domain`.
pub fn invalidate_context_device(sid: u16, domain: u16) -> [u64; 2] {
    [1 | (3 << 4) | (domain as u64) << 16 | (sid as u64) << 32, 0]
}
pub fn invalidate_interrupts() -> [u64; 2] { [4, 0] }
pub fn invalidate_interrupt(index: u16) -> [u64; 2] { [4 | (1 << 4) | (index as u64) << 32, 0] }
pub fn wait(address: usize, seq: u32) -> [u64; 2] {
    [5 | (1 << 5) | (1 << 6) | (seq as u64) << 32, address as u64]
}

/// Reject overflow and out-of-width IOVAs before walking: truncating
/// upper bits would otherwise alias a completely different DMA page.
pub fn range(pa: usize, len: usize, width: u8) -> Option<core::ops::Range<usize>> {
    let end = pa.checked_add(len)?;
    (pa & 4095 == 0 && len & 4095 == 0 && end as u64 <= 1u64 << width).then_some(pa..end)
}
