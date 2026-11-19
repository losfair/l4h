//! Untyped capabilities delivered to the initial seL4 task.

use sel4::BootInfoPtr;

use crate::mem::Untyped;

/// The contents of the extra BootInfo chunk with this ID, after its header.
pub fn extra_chunk(bootinfo: &BootInfoPtr, id: u64) -> Option<&'static [u8]> {
    // rust-sel4's extra() skips IDs it does not know.
    let granule = sel4::FrameObjectType::GRANULE.bytes();
    let extra = unsafe {
        core::slice::from_raw_parts(bootinfo.ptr().cast::<u8>().add(granule), bootinfo.footprint_size() - granule)
    };
    let word = |i: usize| u64::from_le_bytes(extra[i..i + 8].try_into().unwrap());
    let mut off = 0;
    while off + 16 <= extra.len() {
        let (chunk, len) = (word(off), word(off + 8) as usize);
        if len < 16 || len > extra.len() - off {
            break;
        }
        if chunk == id {
            return Some(&extra[off + 16..off + len]);
        }
        off += len;
    }
    None
}

pub fn untypeds(bootinfo: &BootInfoPtr) -> impl Iterator<Item = Untyped> + '_ {
    let base = bootinfo.untyped_list().iter().enumerate().map(|(i, desc)| Untyped {
        cap: bootinfo.untyped().index(i).cap(),
        paddr: desc.paddr(),
        size_bits: desc.size_bits(),
        is_device: desc.is_device(),
    });
    // SEL4_BOOTINFO_HEADER_X86_EXTRA_UNTYPEDS. The x86 kernel writes
    // seL4_UntypedDesc values here with no alignment padding between them.
    let extra = extra_chunk(bootinfo, 10).unwrap_or_default();
    let overflow = extra.chunks_exact(16).enumerate().map(move |(i, desc)| Untyped {
        cap: crate::cap_at(bootinfo.untyped().range().end + i),
        paddr: u64::from_le_bytes(desc[..8].try_into().unwrap()) as usize,
        size_bits: desc[8] as usize,
        is_device: desc[9] != 0,
    });
    base.chain(overflow)
}
