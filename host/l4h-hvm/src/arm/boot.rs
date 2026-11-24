//! Booting an unmodified arm64 Linux (DESIGN.md §5.11, Documentation/arch/
//! arm64/booting.rst): what dom0 loaded, an `Image` or an ELF `vmlinux`,
//! goes where it runs, and a device tree (fdt.rs) in the first block of
//! RAM.  vCPU 0 starts at the image with x0 at the tree, its MMU and caches
//! off.  Free of seL4.

use l4h_rt::host::hvm::arm::RAM_BASE;

use super::fdt;
use crate::guest::GuestMem;

const BLOCK: u64 = 2 << 20;
/// `ARM\x64` at offset 56 of an Image.
const IMAGE_MAGIC: u32 = 0x644d_5241;
const IMAGE_HEADER: u64 = 64;
/// An Image's flags: big-endian kernel.
const FLAG_BE: u64 = 1;
/// The Image's page size (0: unspecified, 1: 4 KiB).
const FLAG_PAGE_SHIFT: u32 = 1;
const FLAG_PAGE_MASK: u64 = 3;
/// Where an old Image with no size says it fits.
const OLD_IMAGE_SIZE: u64 = 64 << 20;
/// The device tree's room: the first block.
pub const FDT_MAX: usize = 1 << 20;

const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const GIB: u64 = 1 << 30;
/// Where arm64/booting.rst lets an initrd be, from a 1 GiB boundary.
const INITRD_WINDOW: u64 = 32 << 30;
const MAX_SEGMENTS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not where it was said to be, or cut short.
    Truncated,
    /// Neither an arm64 Image nor an AArch64 ELF.
    BadFormat,
    /// Big-endian, or for a page size this host does not run.
    Unsupported,
    /// The kernel, the initrd and the tree do not fit in RAM.
    NoRoom,
    /// The device tree is too large.
    Fdt,
}

/// Where vCPU 0 starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub pc: u64,
    pub fdt: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Segment {
    /// Offset in the file, in the image as it runs, bytes in each.
    file: u64,
    at: u64,
    filesz: u64,
    memsz: u64,
}

/// A parsed kernel image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kernel {
    /// Bytes from the 2 MiB-aligned load base to the image.
    text_offset: u64,
    /// Bytes it takes where it runs, from its first.
    size: u64,
    /// Offset of its entry point from its first byte.
    entry: u64,
    segments: [Segment; MAX_SEGMENTS],
    nsegs: usize,
    /// Bytes of the file, as dom0 staged it.
    file_len: u64,
}

fn bytes<const N: usize>(mem: &GuestMem, gpa: u64, off: u64) -> Result<[u8; N], Error> {
    let mut b = [0u8; N];
    let at = gpa.checked_add(off).ok_or(Error::Truncated)?;
    if mem.read_bytes(at, &mut b) { Ok(b) } else { Err(Error::Truncated) }
}

fn u16_at(mem: &GuestMem, gpa: u64, off: u64) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(bytes(mem, gpa, off)?))
}

fn u32_at(mem: &GuestMem, gpa: u64, off: u64) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(bytes(mem, gpa, off)?))
}

fn u64_at(mem: &GuestMem, gpa: u64, off: u64) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(bytes(mem, gpa, off)?))
}

impl Kernel {
    /// The kernel of `len` bytes at `gpa`.
    pub fn parse(mem: &GuestMem, gpa: u64, len: u64) -> Result<Kernel, Error> {
        if len < IMAGE_HEADER {
            return Err(Error::Truncated);
        }
        if bytes::<4>(mem, gpa, 0)? == *b"\x7fELF" {
            return Self::parse_elf(mem, gpa, len);
        }
        if u32_at(mem, gpa, 56)? != IMAGE_MAGIC {
            return Err(Error::BadFormat);
        }
        let (text_offset, image_size, flags) = (u64_at(mem, gpa, 8)?, u64_at(mem, gpa, 16)?, u64_at(mem, gpa, 24)?);
        // Before Linux 3.17 image_size is zero, and the text offset is 512 KiB.
        let (text_offset, size) = if image_size == 0 { (0x8_0000, OLD_IMAGE_SIZE.max(len)) } else { (text_offset, image_size) };
        if flags & FLAG_BE != 0 || !matches!((flags >> FLAG_PAGE_SHIFT) & FLAG_PAGE_MASK, 0 | 1) {
            return Err(Error::Unsupported);
        }
        if !text_offset.is_multiple_of(4096) || text_offset >= BLOCK {
            return Err(Error::BadFormat);
        }
        let mut segments = [Segment { file: 0, at: 0, filesz: 0, memsz: 0 }; MAX_SEGMENTS];
        segments[0] = Segment { file: 0, at: 0, filesz: len.min(size), memsz: size };
        Ok(Kernel { text_offset, size, entry: 0, segments, nsegs: 1, file_len: len })
    }

    /// An ELF `vmlinux`: its PT_LOAD segments, laid out as their addresses
    /// are from the lowest, and its entry relative to that.
    fn parse_elf(mem: &GuestMem, gpa: u64, len: u64) -> Result<Kernel, Error> {
        let ident: [u8; 8] = bytes(mem, gpa, 0)?;
        if ident[4] != 2 || ident[5] != 1 || u16_at(mem, gpa, 18)? != EM_AARCH64 {
            return Err(Error::BadFormat);
        }
        let (entry, phoff) = (u64_at(mem, gpa, 24)?, u64_at(mem, gpa, 32)?);
        let (phentsize, phnum) = (u16_at(mem, gpa, 54)? as u64, u16_at(mem, gpa, 56)? as u64);
        if phentsize < 56 || phoff.checked_add(phentsize * phnum).is_none_or(|e| e > len) {
            return Err(Error::Truncated);
        }
        let mut segs = [Segment { file: 0, at: 0, filesz: 0, memsz: 0 }; MAX_SEGMENTS];
        let (mut n, mut low, mut high) = (0, u64::MAX, 0u64);
        let mut entry_runs = false;
        for i in 0..phnum {
            let ph = phoff + i * phentsize;
            if u32_at(mem, gpa, ph)? != PT_LOAD {
                continue;
            }
            let flags = u32_at(mem, gpa, ph + 4)?;
            let (file, vaddr, filesz, memsz) = (u64_at(mem, gpa, ph + 8)?, u64_at(mem, gpa, ph + 16)?, u64_at(mem, gpa, ph + 32)?, u64_at(mem, gpa, ph + 40)?);
            if memsz == 0 {
                continue;
            }
            if n == MAX_SEGMENTS || filesz > memsz || file.checked_add(filesz).is_none_or(|e| e > len) {
                return Err(Error::BadFormat);
            }
            let end = vaddr.checked_add(memsz).ok_or(Error::BadFormat)?;
            entry_runs |= flags & PF_X != 0 && (vaddr..end).contains(&entry);
            segs[n] = Segment { file, at: vaddr, filesz, memsz };
            n += 1;
            low = low.min(vaddr);
            high = high.max(end);
        }
        if n == 0 {
            return Err(Error::BadFormat);
        }
        // An instruction, in a segment that can be executed.
        // Where it runs is `entry - low` past a 4 KiB-aligned load address.
        if !entry_runs || entry & 3 != 0 || (entry - low) & 3 != 0 {
            return Err(Error::BadFormat);
        }
        for s in &mut segs[..n] {
            s.at -= low;
        }
        Ok(Kernel { text_offset: 0, size: high - low, entry: entry - low, segments: segs, nsegs: n, file_len: len })
    }
}

/// Copy `len` bytes in guest RAM, which may overlap.
fn move_ram(mem: &GuestMem, dst: u64, src: u64, len: u64) -> Result<(), Error> {
    if len == 0 {
        return Ok(());
    }
    if !mem.valid(dst, len) || !mem.valid(src, len) {
        return Err(Error::NoRoom);
    }
    unsafe { core::ptr::copy(mem.bytes(src, len as usize), mem.bytes(dst, len as usize), len as usize) };
    Ok(())
}

fn zero_ram(mem: &GuestMem, at: u64, len: u64) -> Result<(), Error> {
    if len == 0 {
        return Ok(());
    }
    if !mem.valid(at, len) {
        return Err(Error::NoRoom);
    }
    unsafe { core::ptr::write_bytes(mem.bytes(at, len as usize), 0, len as usize) };
    Ok(())
}

/// What `load` was given, and put: the ranges of RAM the guest reads with
/// its caches off, for the caller to make coherent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loaded {
    pub entry: Entry,
    pub kernel: (u64, u64),
    pub fdt_size: u64,
}

/// Put `k`, staged at `staged` by dom0, where it runs (from RAM_BASE + 2 MiB,
/// clear of block 0's tree), and write the tree of `machine` to block 0
/// with `fdt_buf` as its scratch space.
pub fn load(mem: &GuestMem, k: &Kernel, staged: u64, initrd: (u64, u64), machine: &fdt::Machine, fdt_buf: &mut [u8])
    -> Result<Loaded, Error> {
    let ram_end = RAM_BASE + mem.low;
    let load = RAM_BASE + BLOCK + k.text_offset;
    if load.wrapping_add(k.entry) & 3 != 0 {
        return Err(Error::BadFormat);
    }
    let end = load.checked_add(k.size).ok_or(Error::NoRoom)?;
    if end > ram_end {
        return Err(Error::NoRoom);
    }
    // One piece moves as memmove does; of several, one may land on what
    // another is still to be read from (dom0 stages above where it runs).
    if k.nsegs > 1 && staged < end && staged.saturating_add(k.file_len) > load {
        return Err(Error::NoRoom);
    }
    if initrd.1 != 0 {
        let i_end = initrd.0.checked_add(initrd.1).ok_or(Error::NoRoom)?;
        if initrd.0 < end || i_end > ram_end {
            return Err(Error::NoRoom);
        }
        // arm64/booting.rst: within the 1 GiB-aligned 32 GiB window that
        // has the kernel's start.
        let window = load & !(GIB - 1);
        if initrd.0 < window || i_end > window + INITRD_WINDOW {
            return Err(Error::NoRoom);
        }
    }
    // Lowest first, each moved down over what is already copied (dom0
    // staged the file above where it runs); ELF segments may be sparse.
    let mut order = [0usize; MAX_SEGMENTS];
    for (i, o) in order.iter_mut().enumerate().take(k.nsegs) {
        *o = i;
    }
    order[..k.nsegs].sort_unstable_by_key(|&i| k.segments[i].at);
    for &i in &order[..k.nsegs] {
        let s = &k.segments[i];
        let at = load + s.at;
        move_ram(mem, at, staged + s.file, s.filesz)?;
        zero_ram(mem, at + s.filesz, s.memsz - s.filesz)?;
    }
    let n = fdt::build(fdt_buf, machine).map_err(|_| Error::Fdt)?;
    if n > FDT_MAX || !mem.write_bytes(RAM_BASE, &fdt_buf[..n]) {
        return Err(Error::Fdt);
    }
    Ok(Loaded { entry: Entry { pc: load + k.entry, fdt: RAM_BASE }, kernel: (load, k.size), fdt_size: n as u64 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arm::fdt::tests::{parse, prop};
    use core::sync::atomic::AtomicU64;
    use std::vec;
    use std::vec::Vec;

    const RAM: u64 = 64 << 20;
    static MAPPED: [AtomicU64; 1] = [AtomicU64::new(u64::MAX)];

    fn mem(buf: &mut Vec<u8>) -> GuestMem {
        buf.resize(RAM as usize, 0);
        GuestMem { base: buf.as_ptr() as usize - RAM_BASE as usize, ram_base: RAM_BASE, low: RAM, high: 0, mapped: &MAPPED, map: |_| false }
    }

    /// p_flags: read and execute; read and write.
    const RX: u64 = 5;
    const RW: u64 = 6;

    fn image(text: u64, size: u64, flags: u64, body: &[u8]) -> Vec<u8> {
        let mut k = vec![0u8; 64];
        k[8..16].copy_from_slice(&text.to_le_bytes());
        k[16..24].copy_from_slice(&size.to_le_bytes());
        k[24..32].copy_from_slice(&flags.to_le_bytes());
        k[56..60].copy_from_slice(&IMAGE_MAGIC.to_le_bytes());
        k.extend_from_slice(body);
        k
    }

    fn elf(entry: u64, segs: &[(u64, u64, &[u8], u64)]) -> Vec<u8> {
        let mut k = vec![0u8; 64 + 56 * segs.len()];
        k[0..4].copy_from_slice(b"\x7fELF");
        k[4] = 2;
        k[5] = 1;
        k[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        k[24..32].copy_from_slice(&entry.to_le_bytes());
        k[32..40].copy_from_slice(&64u64.to_le_bytes());
        k[54..56].copy_from_slice(&56u16.to_le_bytes());
        k[56..58].copy_from_slice(&(segs.len() as u16).to_le_bytes());
        for (i, &(vaddr, flags, data, memsz)) in segs.iter().enumerate() {
            let file = k.len() as u64;
            let ph = 64 + 56 * i;
            k[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            k[ph + 4..ph + 8].copy_from_slice(&(flags as u32).to_le_bytes());
            k[ph + 8..ph + 16].copy_from_slice(&file.to_le_bytes());
            k[ph + 16..ph + 24].copy_from_slice(&vaddr.to_le_bytes());
            k[ph + 32..ph + 40].copy_from_slice(&(data.len() as u64).to_le_bytes());
            k[ph + 40..ph + 48].copy_from_slice(&memsz.to_le_bytes());
            k.extend_from_slice(data);
        }
        k
    }

    fn m<'a>(cmdline: &'a [u8], initrd: Option<(u64, u64)>) -> fdt::Machine<'a> {
        fdt::Machine { vcpus: 2, gicv3: true, ram_base: RAM_BASE, ram: RAM, cmdline, initrd }
    }

    #[test]
    fn an_image_goes_to_its_text_offset() {
        let mut buf = Vec::new();
        let g = mem(&mut buf);
        let k = image(0x8_0000, 4 << 20, 2, b"KERNEL!!");
        let staged = RAM_BASE + (16 << 20);
        assert!(g.write_bytes(staged, &k));
        let p = Kernel::parse(&g, staged, k.len() as u64).unwrap();
        let mut scratch = vec![0u8; 1 << 16];
        let l = load(&g, &p, staged, (RAM_BASE + (32 << 20), 4096), &m(b"root=x\0", Some((RAM_BASE + (32 << 20), RAM_BASE + (32 << 20) + 4096))), &mut scratch).unwrap();
        assert_eq!(l.entry, Entry { pc: 0x4020_0000 + 0x8_0000, fdt: RAM_BASE });
        assert_eq!(l.kernel, (0x4028_0000, 4 << 20));
        let mut got = [0u8; 8];
        assert!(g.read_bytes(l.entry.pc + 64, &mut got));
        assert_eq!(&got, b"KERNEL!!");
        // The tree is in block 0.
        let t = parse(&buf[..l.fdt_size as usize]);
        assert_eq!(prop(&t, "chosen", "bootargs").unwrap(), b"root=x\0");
        assert_eq!(prop(&t, "chosen", "linux,initrd-start").unwrap(), (RAM_BASE + (32 << 20)).to_be_bytes());
    }

    #[test]
    fn staged_over_where_it_runs() {
        // dom0 may stage it so that it overlaps its destination.
        let mut buf = Vec::new();
        let g = mem(&mut buf);
        let body: Vec<u8> = (0..1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let k = image(0, 8 << 20, 0, &body);
        let staged = RAM_BASE + (2 << 20) + 4096;
        assert!(g.write_bytes(staged, &k));
        let p = Kernel::parse(&g, staged, k.len() as u64).unwrap();
        let l = load(&g, &p, staged, (0, 0), &m(b"\0", None), &mut vec![0u8; 1 << 16]).unwrap();
        let mut got = vec![0u8; body.len()];
        assert!(g.read_bytes(l.entry.pc + 64, &mut got));
        assert_eq!(got, body);
    }

    #[test]
    fn an_elf_is_laid_out_from_its_lowest_address() {
        let mut buf = Vec::new();
        let g = mem(&mut buf);
        let base = 0xffff_8000_8000_0000u64;
        let k = elf(base + 0x800, &[(base, RX, b"TEXT", 0x1000), (base + 0x2_0000, RW, b"DATA", 0x1_0000)]);
        let staged = RAM_BASE + (16 << 20);
        assert!(g.write_bytes(staged, &k));
        // What is past DATA's file bytes is BSS.
        assert!(g.write_bytes(RAM_BASE + (2 << 20) + 0x2_0004, &[0xaa; 16]));
        let p = Kernel::parse(&g, staged, k.len() as u64).unwrap();
        let l = load(&g, &p, staged, (0, 0), &m(b"\0", None), &mut vec![0u8; 1 << 16]).unwrap();
        assert_eq!(l.entry.pc, 0x4020_0000 + 0x800);
        let mut b = [0u8; 4];
        assert!(g.read_bytes(0x4020_0000, &mut b));
        assert_eq!(&b, b"TEXT");
        assert!(g.read_bytes(0x4020_0000 + 0x2_0000, &mut b));
        assert_eq!(&b, b"DATA");
        assert!(g.read_bytes(0x4020_0000 + 0x2_0004, &mut b));
        assert_eq!(b, [0; 4], "BSS is cleared");
        assert_eq!(l.kernel.1, 0x3_0000);
    }

    #[test]
    fn a_staged_elf_over_where_it_runs_is_refused() {
        let mut buf = Vec::new();
        let g = mem(&mut buf);
        let base = 0xffff_8000_8000_0000u64;
        let k = elf(base, &[(base, RX, b"TEXT", 0x1000), (base + 0x2_0000, RW, b"DATA", 0x1_0000)]);
        let staged = RAM_BASE + (2 << 20) + 0x1000;
        assert!(g.write_bytes(staged, &k));
        let p = Kernel::parse(&g, staged, k.len() as u64).unwrap();
        assert_eq!(load(&g, &p, staged, (0, 0), &m(b"\0", None), &mut vec![0u8; 1 << 16]), Err(Error::NoRoom));
    }

    #[test]
    fn refused_images() {
        let mut buf = Vec::new();
        let g = mem(&mut buf);
        let at = RAM_BASE + (16 << 20);
        let try_k = |k: &[u8]| {
            assert!(g.write_bytes(at, k));
            Kernel::parse(&g, at, k.len() as u64)
        };
        assert_eq!(try_k(&[0u8; 8]), Err(Error::Truncated));
        assert_eq!(try_k(&[0u8; 128]), Err(Error::BadFormat), "no magic");
        assert_eq!(try_k(&image(0, 1 << 20, FLAG_BE, b"")), Err(Error::Unsupported));
        assert_eq!(try_k(&image(0, 1 << 20, 2 << FLAG_PAGE_SHIFT, b"")), Err(Error::Unsupported), "16 KiB pages");
        assert_eq!(try_k(&image(0x123, 1 << 20, 0, b"")), Err(Error::BadFormat), "unaligned");
        let mut e = elf(0x1000, &[(0x1000, RX, b"x", 16)]);
        e[18] = 62;
        assert_eq!(try_k(&e), Err(Error::BadFormat), "x86-64");
        assert_eq!(try_k(&elf(0x9000, &[(0x1000, RX, b"x", 16)])), Err(Error::BadFormat), "entry outside it");
        assert_eq!(try_k(&elf(0x1000, &[(0x1000, RW, b"x", 16)])), Err(Error::BadFormat), "entry in a segment that does not execute");
        assert_eq!(try_k(&elf(0x1002, &[(0x1000, RX, b"x", 16)])), Err(Error::BadFormat), "entry not an instruction's address");
        // Between two segments: inside their span, in neither.
        assert_eq!(try_k(&elf(0x1800, &[(0x1000, RX, b"x", 16), (0x2000, RW, b"y", 16)])), Err(Error::BadFormat), "entry in the gap");
        assert_eq!(try_k(&elf(0x2000, &[(0x1000, RX, b"x", 16), (0x2000, RW, b"y", 16)])), Err(Error::BadFormat), "entry in the data");
        assert!(try_k(&elf(0x1004, &[(0x1000, RX, b"x", 16), (0x2000, RW, b"y", 16)])).is_ok(), "entry in the text");
        // Aligned as linked, but not once laid out from its lowest address.
        assert_eq!(try_k(&elf(0x1004, &[(0x1001, RX, b"x", 16)])), Err(Error::BadFormat), "entry unaligned where it runs");
        let mut e = elf(0x1000, &[(0x1000, RX, b"x", 16)]);
        e[64 + 32] = 0xff;
        assert_eq!(try_k(&e), Err(Error::BadFormat), "filesz past memsz");
        // What does not fit.
        let k = image(0, RAM, 0, b"");
        let p = try_k(&k).unwrap();
        assert_eq!(load(&g, &p, at, (0, 0), &m(b"\0", None), &mut vec![0u8; 1 << 16]), Err(Error::NoRoom));
        let k = image(0, 4 << 20, 0, b"");
        let p = try_k(&k).unwrap();
        assert_eq!(load(&g, &p, at, (RAM_BASE, 4096), &m(b"\0", None), &mut vec![0u8; 1 << 16]), Err(Error::NoRoom), "initrd under the kernel");
        assert_eq!(load(&g, &p, at, (RAM_BASE + RAM - 4096, 8192), &m(b"\0", None), &mut vec![0u8; 1 << 16]), Err(Error::NoRoom), "initrd past RAM");
    }

    #[test]
    fn the_initrd_stays_in_the_kernels_32_gib_window() {
        let mut buf = Vec::new();
        let g = mem(&mut buf);
        // As much RAM as it takes to go past the window; nothing is written there.
        let g = GuestMem { low: 64 << 30, ..g };
        let at = RAM_BASE + (16 << 20);
        let k = image(0, 4 << 20, 0, b"");
        assert!(g.write_bytes(at, &k));
        let p = Kernel::parse(&g, at, k.len() as u64).unwrap();
        let end = RAM_BASE + (32 << 30);
        let try_at = |i: (u64, u64)| load(&g, &p, at, i, &m(b"\0", None), &mut vec![0u8; 1 << 16]).map(|_| ());
        assert_eq!(try_at((end - 4096, 4096)), Ok(()), "up to its end");
        assert_eq!(try_at((end - 4096, 8192)), Err(Error::NoRoom), "across it");
        assert_eq!(try_at((end, 4096)), Err(Error::NoRoom), "past it");
    }
}
