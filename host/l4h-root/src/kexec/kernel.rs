//! The seL4 ELF in an l4h EFI application. Unlike the component ELF loader,
//! this parser treats its input as untrusted and uses physical addresses.

use l4h_host::fixed::ArrayVec;

use super::pe::{u16_at, u32_at, u64_at, usize_at};

pub const LOAD_MIN: u64 = 1 << 20;
pub const LOAD_MAX: u64 = 16 << 20;
pub const VARIANT_NOTE_NAME: &[u8] = b".note.l4h-kexec";
pub const VARIANT_X2APIC: u64 = 1 << 0;
pub const VARIANT_PCID: u64 = 1 << 1;
const MAX_LOADS: usize = 16;

#[derive(Clone, Copy)]
pub struct LoadSegment<'a> {
    pub physical: u64,
    pub memory_size: u64,
    pub data: &'a [u8],
}

pub struct KernelImage<'a> {
    pub entry: u64,
    pub segments: ArrayVec<LoadSegment<'a>, MAX_LOADS>,
    /// Bits VARIANT_X2APIC and VARIANT_PCID, from .note.l4h-kexec.
    pub variant: Option<u64>,
}

fn checked_range(
    data: &[u8],
    offset: u64,
    size: u64,
) -> Result<core::ops::Range<usize>, &'static str> {
    let offset = usize::try_from(offset).map_err(|_| "ELF offset does not fit the host")?;
    let size = usize::try_from(size).map_err(|_| "ELF size does not fit the host")?;
    let end = offset.checked_add(size).ok_or("ELF offset overflow")?;
    if end > data.len() {
        return Err("ELF offset outside the file");
    }
    Ok(offset..end)
}

fn multiboot2(data: &[u8]) -> Result<(), &'static str> {
    let limit = data.len().min(32768);
    let mut found = None;
    for offset in (0..limit.saturating_sub(23)).step_by(8) {
        if u32_at(data, offset)? == 0xe85250d6 {
            if found.replace(offset).is_some() {
                return Err("multiple multiboot2 headers");
            }
        }
    }
    let offset = found.ok_or("seL4 has no multiboot2 header")?;
    if u32_at(data, offset + 4)? != 0 {
        return Err("multiboot2 header is not for x86");
    }
    let length = u32_at(data, offset + 8)? as usize;
    let checksum = u32_at(data, offset + 12)?;
    let magic = 0xe85250d6u32;
    if length < 24 || length % 8 != 0 || offset + length > limit {
        return Err("bad multiboot2 header length");
    }
    if magic
        .wrapping_add(u32_at(data, offset + 4)?)
        .wrapping_add(length as u32)
        .wrapping_add(checksum)
        != 0
    {
        return Err("bad multiboot2 header checksum");
    }
    let mut at = offset + 16;
    loop {
        if at + 8 > offset + length {
            return Err("truncated multiboot2 header tag");
        }
        let kind = u16_at(data, at)?;
        let size = u32_at(data, at + 4)? as usize;
        if size < 8 || at + size > offset + length {
            return Err("bad multiboot2 header tag");
        }
        at = (at + size).next_multiple_of(8);
        if at > offset + length {
            return Err("bad multiboot2 header tag padding");
        }
        if kind == 0 {
            if size != 8 || at != offset + length {
                return Err("bad multiboot2 end tag");
            }
            return Ok(());
        }
    }
}

fn variant(
    data: &[u8],
    shoff: usize,
    shentsize: usize,
    shnum: usize,
    shstrndx: usize,
) -> Result<Option<u64>, &'static str> {
    if shnum == 0 {
        return Ok(None);
    }
    if shentsize < 64 || shstrndx >= shnum {
        return Err("bad ELF section headers");
    }
    let table_size = shentsize.checked_mul(shnum).ok_or("ELF section overflow")?;
    checked_range(data, shoff as u64, table_size as u64)?;
    let strings_header = shoff + shstrndx * shentsize;
    let strings = &data[checked_range(
        data,
        u64_at(data, strings_header + 24)?,
        u64_at(data, strings_header + 32)?,
    )?];
    let string_at = |offset: usize| -> Result<&[u8], &'static str> {
        if offset >= strings.len() {
            return Err("bad ELF section name");
        }
        let tail = &strings[offset..];
        let len = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or("unterminated ELF section name")?;
        Ok(&tail[..len])
    };
    let mut variant = None;
    for i in 0..shnum {
        let at = shoff + i * shentsize;
        if string_at(u32_at(data, at)? as usize)? != VARIANT_NOTE_NAME {
            continue;
        }
        let notes = &data[checked_range(data, u64_at(data, at + 24)?, u64_at(data, at + 32)?)?];
        let mut offset = 0;
        while offset < notes.len() {
            let namesz = u32_at(notes, offset)? as usize;
            let descsz = u32_at(notes, offset + 4)? as usize;
            let kind = u32_at(notes, offset + 8)?;
            let name = offset.checked_add(12).ok_or("ELF note overflow")?;
            let desc = name
                .checked_add(namesz.next_multiple_of(4))
                .ok_or("ELF note overflow")?;
            let next = desc
                .checked_add(descsz.next_multiple_of(4))
                .ok_or("ELF note overflow")?;
            if next > notes.len() || namesz == 0 {
                return Err("bad ELF note");
            }
            if &notes[name..name + namesz] == b"l4h\0" && kind == 1 {
                if descsz != 8 || variant.is_some() {
                    return Err("bad or duplicate l4h variant note");
                }
                variant = Some(u64_at(notes, desc)?);
            }
            offset = next;
        }
    }
    Ok(variant)
}

/// The bytes seL4 loads an ELF root task into, as its elf_getMemoryBounds
/// sees them: every program header with memory, at the Elf64_Phdr stride,
/// the end rounded up to a page.
pub fn image_span(data: &[u8]) -> Result<u64, &'static str> {
    if data.len() < 64 || &data[..4] != b"\x7fELF" || data[4] != 2 {
        return Err("root task is not an ELF64 file");
    }
    let phoff = usize_at(data, 32)?;
    let (mut start, mut end) = (u64::MAX, 0);
    for i in 0..u16_at(data, 56)? as usize {
        let at = phoff.checked_add(i * 56).ok_or("bad root task program headers")?;
        let memsz = u64_at(data, at + 40)?;
        if memsz == 0 {
            continue;
        }
        let vaddr = u64_at(data, at + 16)?;
        let seg_end = vaddr.checked_add(memsz).ok_or("root task segment overflow")?;
        (start, end) = (start.min(vaddr), end.max(seg_end));
    }
    if end == 0 {
        return Err("root task has no load segments");
    }
    end.checked_next_multiple_of(4096).map(|end| end - start).ok_or("root task segment overflow")
}

impl<'a> KernelImage<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < 64 || &data[..4] != b"\x7fELF" || data[4] != 2 || data[5] != 1 {
            return Err("seL4 is not a little-endian ELF64 file");
        }
        if u16_at(data, 16)? != 2 || u16_at(data, 18)? != 62 {
            return Err("seL4 is not an x86_64 executable");
        }
        let entry = u64_at(data, 24)?;
        let phoff = usize_at(data, 32)?;
        let shoff = usize_at(data, 40)?;
        let phentsize = u16_at(data, 54)? as usize;
        let phnum = u16_at(data, 56)? as usize;
        if phentsize < 56 || phnum == 0 || phnum > 64 {
            return Err("bad seL4 program headers");
        }
        checked_range(data, phoff as u64, (phentsize * phnum) as u64)?;
        multiboot2(data)?;

        let mut result = Self {
            entry,
            segments: ArrayVec::new(),
            variant: variant(
                data,
                shoff,
                u16_at(data, 58)? as usize,
                u16_at(data, 60)? as usize,
                u16_at(data, 62)? as usize,
            )?,
        };
        for i in 0..phnum {
            let at = phoff + i * phentsize;
            if u32_at(data, at)? != 1 {
                continue;
            }
            let offset = u64_at(data, at + 8)?;
            let physical = u64_at(data, at + 24)?;
            let file_size = u64_at(data, at + 32)?;
            let memory_size = u64_at(data, at + 40)?;
            let end = physical
                .checked_add(memory_size)
                .ok_or("seL4 load address overflow")?;
            if memory_size == 0 || file_size > memory_size || physical < LOAD_MIN || end > LOAD_MAX
            {
                return Err("seL4 load segment is outside [1 MiB, 16 MiB)");
            }
            let bytes = checked_range(data, offset, file_size)?;
            if result.segments.iter().any(|s| physical < s.physical + s.memory_size && s.physical < end) {
                return Err("overlapping seL4 load segments");
            }
            result.segments
                .push(LoadSegment { physical, memory_size, data: &data[bytes] })
                .map_err(|_| "too many seL4 load segments")?;
        }
        if result.segments.is_empty() {
            return Err("seL4 has no load segments");
        }
        if !result.segments.iter().any(|s| s.physical <= entry && entry < s.physical + s.data.len() as u64) {
            return Err("seL4 entry is not in loaded file data");
        }
        Ok(result)
    }

    pub fn loads(&self) -> impl Iterator<Item = &LoadSegment<'a>> {
        self.segments.iter()
    }
}
