//! Minimal ELF64 little-endian parser, enough to load static executables.

pub struct Elf<'a> {
    data: &'a [u8],
    pub entry: u64,
    phoff: usize,
    phentsize: usize,
    phnum: usize,
}

pub struct Segment<'a> {
    pub vaddr: u64,
    pub memsz: u64,
    pub data: &'a [u8],
    pub writable: bool,
}

const PT_LOAD: u32 = 1;
const PF_W: u32 = 2;

fn u16_at(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(d[o..o + 2].try_into().unwrap())
}
fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < 64 || &data[0..4] != b"\x7fELF" {
            return Err("not an ELF file");
        }
        if data[4] != 2 || data[5] != 1 {
            return Err("not a little-endian ELF64 file");
        }
        #[cfg(target_arch = "x86_64")]
        const MACHINE: u16 = 62;
        #[cfg(target_arch = "aarch64")]
        const MACHINE: u16 = 183;
        if u16_at(data, 18) != MACHINE {
            return Err("ELF architecture does not match the host");
        }
        let phoff = u64_at(data, 32) as usize;
        let phentsize = u16_at(data, 54) as usize;
        let phnum = u16_at(data, 56) as usize;
        if phentsize < 56 || phoff + phentsize * phnum > data.len() {
            return Err("bad program headers");
        }
        Ok(Self { data, entry: u64_at(data, 24), phoff, phentsize, phnum })
    }

    pub fn segments(&self) -> impl Iterator<Item = Segment<'a>> + '_ {
        (0..self.phnum).filter_map(move |i| {
            let o = self.phoff + i * self.phentsize;
            let d = self.data;
            if u32_at(d, o) != PT_LOAD {
                return None;
            }
            let flags = u32_at(d, o + 4);
            let offset = u64_at(d, o + 8) as usize;
            let vaddr = u64_at(d, o + 16);
            let filesz = u64_at(d, o + 32) as usize;
            let memsz = u64_at(d, o + 40);
            Some(Segment {
                vaddr,
                memsz,
                data: &d[offset..offset + filesz],
                writable: flags & PF_W != 0,
            })
        })
    }

    /// Lowest and highest (exclusive) virtual address of loadable segments.
    #[allow(dead_code)] // vmmgr's kimage.rs
    pub fn bounds(&self) -> (u64, u64) {
        let mut lo = u64::MAX;
        let mut hi = 0;
        for s in self.segments() {
            lo = lo.min(s.vaddr);
            hi = hi.max(s.vaddr + s.memsz);
        }
        (lo, hi)
    }
}
