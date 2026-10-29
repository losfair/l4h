//! Multiboot2 information for the next seL4, built from the current boot's
//! x86 extra bootinfo rather than from root's view of free memory.

use core::ops::Range;

pub const MAX_MMAP_ENTRIES: usize = 50;
pub const MMAP_TRUNCATED: u32 = 1 << 31;
pub const MBI_MAX: usize = 4096;

#[derive(Clone, Copy, Default)]
pub struct MapEntry {
    pub base: u64,
    pub length: u64,
    pub kind: u32,
}

#[derive(Clone, Copy)]
pub struct FirmwareMap {
    pub entries: [MapEntry; MAX_MMAP_ENTRIES],
    pub count: usize,
}

impl FirmwareMap {
    /// The content of SEL4_BOOTINFO_HEADER_X86_MBMMAP.
    pub fn parse(content: &[u8]) -> Result<Self, &'static str> {
        if content.len() < 4 {
            return Err("truncated firmware memory map");
        }
        let length = u32::from_le_bytes(content[..4].try_into().unwrap());
        if length & MMAP_TRUNCATED != 0 {
            return Err("the running seL4 truncated the firmware memory map");
        }
        let length = length as usize;
        if length == 0
            || length % 24 != 0
            || length / 24 > MAX_MMAP_ENTRIES
            || length > content.len() - 4
        {
            return Err("bad firmware memory map length");
        }
        let mut map = Self {
            entries: [MapEntry::default(); MAX_MMAP_ENTRIES],
            count: length / 24,
        };
        for i in 0..map.count {
            let at = 4 + i * 24;
            let entry = MapEntry {
                base: u64::from_le_bytes(content[at + 4..at + 12].try_into().unwrap()),
                length: u64::from_le_bytes(content[at + 12..at + 20].try_into().unwrap()),
                kind: u32::from_le_bytes(content[at + 20..at + 24].try_into().unwrap()),
            };
            if entry.length == 0 || entry.base.checked_add(entry.length).is_none() {
                return Err("bad firmware memory map entry");
            }
            map.entries[i] = entry;
        }
        // Coverage checks sum per-entry overlap, and reserve splits a single
        // usable entry: both assume disjoint entries. Kexec is unavailable
        // on a map that overlaps rather than trusting either reading of it.
        for i in 0..map.count {
            let a = map.entries[i];
            for b in &map.entries[i + 1..map.count] {
                if a.base < b.base + b.length && b.base < a.base + a.length {
                    return Err("overlapping firmware memory map entries");
                }
            }
        }
        Ok(map)
    }

    pub fn usable(&self) -> impl Iterator<Item = &MapEntry> {
        self.entries[..self.count].iter().filter(|e| e.kind == 1)
    }

    /// Whether usable firmware RAM covers the whole range, including ranges
    /// that span adjacent usable entries.
    pub fn covers_usable(&self, range: Range<u64>) -> bool {
        self.covers_kinds(range, &[1])
    }

    /// Whether RAM covers a seL4 PT_LOAD range. ACPI reclaim and NVS entries
    /// are RAM too: cold boot already loads seL4 over those fixed addresses.
    pub fn covers_boot_ram(&self, range: Range<u64>) -> bool {
        self.covers_kinds(range, &[1, 3, 4])
    }

    fn covers_kinds(&self, range: Range<u64>, kinds: &[u32]) -> bool {
        if range.start >= range.end {
            return false;
        }
        let mut covered = 0;
        for entry in &self.entries[..self.count] {
            if !kinds.contains(&entry.kind) {
                continue;
            }
            let start = range.start.max(entry.base);
            let stop = range.end.min(entry.base + entry.length);
            if start < stop {
                covered += stop - start;
            }
        }
        covered == range.end - range.start
    }

    /// Mark a range reserved in the map passed to the next kernel, splitting
    /// usable entries as needed. The whole range must be usable firmware RAM.
    pub fn reserve(&mut self, range: Range<u64>) -> Result<(), &'static str> {
        if range.start >= range.end {
            return Err("empty reserved physical range");
        }
        if !self.covers_usable(range.clone()) {
            return Err("control block is not covered by usable firmware RAM");
        }
        let old = *self;
        let mut entries = [MapEntry::default(); MAX_MMAP_ENTRIES];
        let mut count = 0;
        let mut push = |entry| -> Result<(), &'static str> {
            if count == MAX_MMAP_ENTRIES {
                return Err("too many firmware memory map entries");
            }
            entries[count] = entry;
            count += 1;
            Ok(())
        };
        let mut covered = 0;
        for entry in &old.entries[..old.count] {
            let end = entry.base + entry.length;
            let start = range.start.max(entry.base);
            let stop = range.end.min(end);
            if entry.kind != 1 || start >= stop {
                push(*entry)?;
                continue;
            }
            if entry.base < start {
                push(MapEntry { base: entry.base, length: start - entry.base, kind: 1 })?;
            }
            push(MapEntry { base: start, length: stop - start, kind: 2 })?;
            if stop < end {
                push(MapEntry { base: stop, length: end - stop, kind: 1 })?;
            }
            covered += stop - start;
        }
        if covered != range.end - range.start {
            return Err("control block is not covered by usable firmware RAM");
        }
        self.entries = entries;
        self.count = count;
        self.coalesce_usable();
        Ok(())
    }

    /// Make a previous handoff's control block usable again. Reserved entries
    /// must cover the range exactly; anything else is a map/log mismatch.
    pub fn unreserve(&mut self, range: Range<u64>) -> Result<(), &'static str> {
        if range.start >= range.end {
            return Err("empty previous control range");
        }
        let mut covered = 0;
        for entry in &mut self.entries[..self.count] {
            let end = entry.base + entry.length;
            let start = range.start.max(entry.base);
            let stop = range.end.min(end);
            if start >= stop {
                continue;
            }
            if entry.kind != 2 || entry.base < start || end > stop {
                return Err("previous control range differs from the memory map");
            }
            entry.kind = 1;
            covered += stop - start;
        }
        if covered != range.end - range.start {
            return Err("previous control range is not reserved in the memory map");
        }
        self.coalesce_usable();
        Ok(())
    }

    /// Coalesce adjacent usable entries so reserve/unreserve cycles do not
    /// grow the map or lose memory across a kexec chain.
    fn coalesce_usable(&mut self) {
        if self.count == 0 {
            return;
        }
        let mut out = 0;
        for i in 1..self.count {
            let entry = self.entries[i];
            if self.entries[out].kind == 1 && entry.kind == 1 &&
                self.entries[out].base + self.entries[out].length == entry.base
            {
                self.entries[out].length += entry.length;
            } else {
                out += 1;
                self.entries[out] = entry;
            }
        }
        self.count = out + 1;
    }
}

#[derive(Clone, Copy)]
pub struct BootTags {
    pub map: FirmwareMap,
    /// seL4's packed multiboot2_fb structure, without the tag header.
    pub framebuffer: Option<[u8; 22]>,
    /// ACPI 1 (20 bytes) or ACPI 2 (36 bytes) RSDP.
    pub acpi: Option<([u8; 36], usize)>,
}

pub struct Module<'a> {
    pub start: u64,
    pub size: usize,
    pub command: &'a [u8],
}

pub struct MbiBuilder {
    bytes: [u8; MBI_MAX],
    len: usize,
}

impl MbiBuilder {
    pub fn new() -> Self {
        Self {
            bytes: [0; MBI_MAX],
            len: 8,
        }
    }

    /// Append a tag whose body is `parts`, padded to 8 bytes. The buffer
    /// starts zeroed and only grows, so padding needs no writes.
    fn tag(&mut self, kind: u32, parts: &[&[u8]]) -> Result<(), &'static str> {
        let size = 8 + parts.iter().map(|p| p.len()).sum::<usize>();
        let at = self.len;
        let end = at + size.next_multiple_of(8);
        if end > self.bytes.len() {
            return Err("MBI does not fit in its page");
        }
        let mut next = at;
        for part in [&kind.to_le_bytes()[..], &(size as u32).to_le_bytes()].into_iter().chain(parts.iter().copied()) {
            self.bytes[next..next + part.len()].copy_from_slice(part);
            next += part.len();
        }
        self.len = end;
        Ok(())
    }

    pub fn command_line(&mut self, line: &[u8]) -> Result<(), &'static str> {
        if line.contains(&0) {
            return Err("NUL in the seL4 command line");
        }
        self.tag(1, &[line, &[0]])
    }

    pub fn module(&mut self, module: &Module<'_>) -> Result<(), &'static str> {
        if module.size == 0 || module.command.contains(&0) {
            return Err("empty module or NUL in its command string");
        }
        let end = module
            .start
            .checked_add(module.size as u64)
            .ok_or("module address overflow")?;
        if module.start >= u32::MAX as u64 || end >= 1 << 32 {
            return Err("module is not below 4 GiB");
        }
        let (start, end) = ((module.start as u32).to_le_bytes(), (end as u32).to_le_bytes());
        self.tag(3, &[&start, &end, module.command, &[0]])
    }

    pub fn firmware_map(&mut self, map: &FirmwareMap) -> Result<(), &'static str> {
        let mut entries = [0; MAX_MMAP_ENTRIES * 24];
        for (i, entry) in map.entries[..map.count].iter().enumerate() {
            let e = &mut entries[i * 24..];
            e[..8].copy_from_slice(&entry.base.to_le_bytes());
            e[8..16].copy_from_slice(&entry.length.to_le_bytes());
            e[16..20].copy_from_slice(&entry.kind.to_le_bytes());
        }
        // Entry size 24, entry version 0.
        self.tag(6, &[&24u32.to_le_bytes(), &[0; 4], &entries[..map.count * 24]])
    }

    pub fn framebuffer(&mut self, fb: &[u8; 22]) -> Result<(), &'static str> {
        self.tag(8, &[fb])
    }

    pub fn acpi(&mut self, rsdp: &([u8; 36], usize)) -> Result<(), &'static str> {
        let (bytes, len) = rsdp;
        let kind = match *len {
            20 => 14,
            36 => 15,
            _ => return Err("unsupported ACPI RSDP size"),
        };
        self.tag(kind, &[&bytes[..*len]])
    }

    /// The finished MBI, with its end tag and total size.
    pub fn finish(&mut self) -> Result<&[u8], &'static str> {
        self.tag(0, &[])?;
        self.bytes[..4].copy_from_slice(&(self.len as u32).to_le_bytes());
        Ok(&self.bytes[..self.len])
    }
}
