//! Booting an unmodified x86-64 Linux kernel directly, as a boot loader
//! would (DESIGN.md §5.11): the image dom0 loaded is a bzImage (64-bit boot
//! protocol, 2.12 or later, XLF_KERNEL_64) or an ELF vmlinux.  We put the
//! kernel where it runs, write the boot parameters (the zero page: its
//! setup header, the E820 map, the command line, the initrd and the ACPI
//! RSDP), a GDT and page tables mapping the first 4 GiB 1:1, and the vCPU
//! enters at the 64-bit entry point in long mode with RSI pointing at the
//! boot parameters.  Below 1 MiB is ours: the zero page, GDT, tables,
//! command line and, from 0xe0000, the ACPI tables (acpi.rs).  Free of
//! seL4.

use crate::guest::GuestMem;

pub const GDT: u64 = 0x500;
pub const ZERO_PAGE: u64 = 0x7000;
pub const PML4: u64 = 0x9000;
pub const CMDLINE: u64 = 0x2_0000;
pub const CMDLINE_MAX: usize = 2048;
/// The BIOS area the ACPI tables go in (reserved in the E820 map).
pub const ACPI_BASE: u64 = 0xe_0000;
pub const ACPI_END: u64 = 0x10_0000;
/// What the boot structures take: the first MiB, which nothing loaded may
/// overlap.
pub const LOW_END: u64 = 0x10_0000;
/// The GDT's selectors, as Linux's boot protocol wants them.
pub const BOOT_CS: u16 = 0x10;
pub const BOOT_DS: u16 = 0x18;
pub const GDT_LIMIT: u16 = 4 * 8 - 1;
/// Where a non-relocatable kernel goes, and the default alignment.
const LOAD_DEFAULT: u64 = 0x100_0000;

const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;
const E820_MAX: usize = 128;

// The zero page (struct boot_params) and its setup header.
const BP_ACPI_RSDP: usize = 0x070;
const BP_EXT_RAMDISK_IMAGE: usize = 0x0c0;
const BP_EXT_RAMDISK_SIZE: usize = 0x0c4;
const BP_EXT_CMD_LINE_PTR: usize = 0x0c8;
const BP_E820_ENTRIES: usize = 0x1e8;
const HDR: usize = 0x1f1;
const HDR_SETUP_SECTS: usize = 0x1f1;
const HDR_BOOT_FLAG: usize = 0x1fe;
const HDR_JUMP: usize = 0x200;
const HDR_MAGIC: usize = 0x202;
const HDR_VERSION: usize = 0x206;
const HDR_TYPE_OF_LOADER: usize = 0x210;
const HDR_LOADFLAGS: usize = 0x211;
const HDR_RAMDISK_IMAGE: usize = 0x218;
const HDR_RAMDISK_SIZE: usize = 0x21c;
const HDR_HEAP_END: usize = 0x224;
const HDR_CMD_LINE_PTR: usize = 0x228;
const HDR_INITRD_ADDR_MAX: usize = 0x22c;
const HDR_KERNEL_ALIGNMENT: usize = 0x230;
const HDR_RELOCATABLE: usize = 0x234;
const HDR_XLOADFLAGS: usize = 0x236;
const HDR_CMDLINE_SIZE: usize = 0x238;
const HDR_PREF_ADDRESS: usize = 0x258;
const HDR_INIT_SIZE: usize = 0x260;
const BP_E820_TABLE: usize = 0x2d0;

const LOADED_HIGH: u8 = 1 << 0;
const CAN_USE_HEAP: u8 = 1 << 7;
const XLF_KERNEL_64: u16 = 1 << 0;
const XLF_CAN_BE_LOADED_ABOVE_4G: u16 = 1 << 1;
const HDRS: u32 = 0x5372_6448;

/// Where the vCPU starts, in 64-bit mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub rip: u64,
    /// The zero page (the 64-bit boot protocol's RSI).
    pub rsi: u64,
    pub cr3: u64,
    pub gdt: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Neither a bzImage with a 64-bit entry nor an x86-64 ELF.
    Format,
    /// Its boot protocol is older than 2.12.
    Version,
    /// It or the initrd does not fit, overlaps the other, or the first MiB.
    Layout,
}

fn le(b: &[u8], off: usize, n: usize) -> u64 {
    (0..n).fold(0, |v, i| v | (*b.get(off + i).unwrap_or(&0) as u64) << (8 * i))
}

fn put(b: &mut [u8], off: usize, n: usize, v: u64) {
    for i in 0..n {
        b[off + i] = (v >> (8 * i)) as u8;
    }
}

fn overlap(a: (u64, u64), b: (u64, u64)) -> bool {
    // In 128 bits: ranges that run past 2^64 are compared as they are.
    let end = |r: (u64, u64)| r.0 as u128 + r.1 as u128;
    a.1 != 0 && b.1 != 0 && (a.0 as u128) < end(b) && (b.0 as u128) < end(a)
}

/// What the image is, from its first bytes (dom0 loaded it into RAM at
/// `image`).
pub struct Kernel {
    /// Where its pieces come from and go: (source gpa, destination gpa,
    /// bytes to copy, bytes it takes there, zeroed after the copy).
    pieces: [(u64, u64, u64, u64); 16],
    nr: usize,
    entry: u64,
    /// The bzImage's setup header (from HDR), or None for an ELF.
    setup: Option<[u8; 0x300]>,
}

impl Kernel {
    /// Parse the image of `len` bytes at `gpa` in `mem`.
    pub fn parse(mem: &GuestMem, gpa: u64, len: u64) -> Result<Kernel, Error> {
        let mut head = [0u8; 0x300];
        let n = len.min(head.len() as u64) as usize;
        if !mem.read_bytes(gpa, &mut head[..n]) {
            return Err(Error::Layout);
        }
        if head[..4] == *b"\x7fELF" {
            return Self::elf(mem, gpa, len, &head);
        }
        if le(&head, HDR_MAGIC, 4) as u32 != HDRS || le(&head, HDR_BOOT_FLAG, 2) != 0xaa55 {
            return Err(Error::Format);
        }
        if le(&head, HDR_VERSION, 2) < 0x020c {
            return Err(Error::Version);
        }
        if le(&head, HDR_XLOADFLAGS, 2) as u16 & XLF_KERNEL_64 == 0 {
            return Err(Error::Format);
        }
        let sects = match head[HDR_SETUP_SECTS] {
            0 => 4,
            s => s as u64,
        };
        let setup_len = (sects + 1) * 512;
        if setup_len >= len {
            return Err(Error::Format);
        }
        let load = load_address(head[HDR_RELOCATABLE] != 0, le(&head, HDR_PREF_ADDRESS, 8), le(&head, HDR_KERNEL_ALIGNMENT, 4));
        let payload = len - setup_len;
        let size = le(&head, HDR_INIT_SIZE, 4).max(payload);
        // Where it runs, and its window there, must be addresses.
        let entry = load.checked_add(0x200).filter(|_| load.checked_add(size).is_some()).ok_or(Error::Layout)?;
        let src = gpa.checked_add(setup_len).ok_or(Error::Layout)?;
        let mut k = Kernel { pieces: [(0, 0, 0, 0); 16], nr: 1, entry, setup: Some(head) };
        k.pieces[0] = (src, load, payload, size);
        Ok(k)
    }

    fn elf(mem: &GuestMem, gpa: u64, len: u64, h: &[u8]) -> Result<Kernel, Error> {
        // ELF64, little-endian, x86-64.
        if h[4] != 2 || h[5] != 1 || le(h, 18, 2) != 62 {
            return Err(Error::Format);
        }
        let (phoff, phentsize, phnum) = (le(h, 32, 8), le(h, 54, 2), le(h, 56, 2));
        if phentsize < 56 || phnum == 0 || phnum > 64 {
            return Err(Error::Format);
        }
        let mut k = Kernel { pieces: [(0, 0, 0, 0); 16], nr: 0, entry: le(h, 24, 8), setup: None };
        for i in 0..phnum {
            let off = i
                .checked_mul(phentsize)
                .and_then(|o| phoff.checked_add(o))
                .filter(|o| o.checked_add(56).is_some_and(|e| e <= len))
                .ok_or(Error::Format)?;
            let mut ph = [0u8; 56];
            if !mem.read_bytes(gpa.checked_add(off).ok_or(Error::Layout)?, &mut ph) {
                return Err(Error::Layout);
            }
            // PT_LOAD: offset, physical address, file and memory sizes.
            if le(&ph, 0, 4) != 1 {
                continue;
            }
            let (offset, paddr, filesz, memsz) = (le(&ph, 8, 8), le(&ph, 24, 8), le(&ph, 32, 8), le(&ph, 40, 8));
            if filesz > memsz || offset.checked_add(filesz).is_none_or(|e| e > len) || k.nr == k.pieces.len() {
                return Err(Error::Format);
            }
            if paddr.checked_add(memsz).is_none() {
                return Err(Error::Layout);
            }
            k.pieces[k.nr] = (gpa.checked_add(offset).ok_or(Error::Layout)?, paddr, filesz, memsz);
            k.nr += 1;
        }
        if k.nr == 0 {
            return Err(Error::Format);
        }
        Ok(k)
    }

    /// Where the kernel goes, and what it takes there.
    fn pieces(&self) -> &[(u64, u64, u64, u64)] {
        &self.pieces[..self.nr]
    }
}

/// Where a bzImage's kernel runs, and decompresses itself (init_size
/// from there): its preferred address, which a kernel that cannot be
/// relocated (`relocatable` false) must have, and a relocatable one gets
/// if it is aligned as it asks; 16 MiB without one.  tools/l4hctl places
/// the image and the initrd above it by the same rule (hvm_layout).
pub fn load_address(relocatable: bool, pref: u64, align: u64) -> u64 {
    match pref {
        0 => LOAD_DEFAULT,
        p if !relocatable || p.is_multiple_of(align.max(1)) => p,
        _ => LOAD_DEFAULT,
    }
}

/// The E820 map of a guest with `low` and `high` bytes of RAM below and
/// above the hole: (start, size, type), in order.
pub fn e820(low: u64, high: u64, out: &mut [(u64, u64, u32); 8]) -> usize {
    let mut n = 0;
    let mut add = |e: (u64, u64, u32)| {
        out[n] = e;
        n += 1;
    };
    add((0, 0x9fc00, E820_RAM));
    add((0x9fc00, 0x400, E820_RESERVED));
    add((ACPI_BASE, ACPI_END - ACPI_BASE, E820_RESERVED));
    if low > LOW_END {
        add((LOW_END, low - LOW_END, E820_RAM));
    }
    // ECAM, which the MCFG names: reserved, so that Linux uses it.
    add((crate::dev::pci::ECAM_BASE, crate::dev::pci::ECAM_SIZE, E820_RESERVED));
    if high != 0 {
        add((HIGH_RAM_BASE, high, E820_RAM));
    }
    n
}

const HIGH_RAM_BASE: u64 = crate::mem::HIGH_RAM_BASE;

/// Load `kernel` (parsed from the image at `image`) and `initrd`, both
/// (gpa, len), and write the boot structures, with `cmdline` and the RSDP
/// at `rsdp`.  The first MiB must hold nothing loaded.
pub fn load(mem: &GuestMem, kernel: &Kernel, image: (u64, u64), initrd: (u64, u64), cmdline: &[u8], rsdp: u64) -> Result<Entry, Error> {
    let low = (0, LOW_END);
    if overlap(image, low) || overlap(initrd, low) || (initrd.1 != 0 && !mem.is_ram(initrd.0, initrd.1)) {
        return Err(Error::Layout);
    }
    for &(_, dst, _, size) in kernel.pieces() {
        // Where it goes: RAM, clear of the first MiB and of the initrd, and
        // of the image unless it moves within it (a bzImage's payload,
        // which memmove copies whichever way it moves).
        if !mem.is_ram(dst, size) || overlap((dst, size), low) || overlap((dst, size), initrd)
            || (overlap((dst, size), image) && kernel.setup.is_none())
        {
            return Err(Error::Layout);
        }
    }
    if let Some(setup) = &kernel.setup {
        // The initrd: below the kernel's limit unless it can be above 4 GiB.
        let max = le(setup, HDR_INITRD_ADDR_MAX, 4);
        let above_4g = le(setup, HDR_XLOADFLAGS, 2) as u16 & XLF_CAN_BE_LOADED_ABOVE_4G != 0;
        if initrd.1 != 0 && !above_4g && initrd.0.checked_add(initrd.1 - 1).is_none_or(|last| last > max) {
            return Err(Error::Layout);
        }
    }
    for &(src, dst, copy, size) in kernel.pieces() {
        if !mem.valid(src, copy) || !mem.valid(dst, size) {
            return Err(Error::Layout);
        }
        // Down within the image, or elsewhere: memmove's order is right.
        unsafe { core::ptr::copy(mem.bytes(src, copy as usize), mem.bytes(dst, copy as usize), copy as usize) };
        unsafe { core::ptr::write_bytes(mem.bytes(dst + copy, (size - copy) as usize), 0, (size - copy) as usize) };
    }

    // ---- The zero page.
    let mut bp = [0u8; 4096];
    match &kernel.setup {
        Some(setup) => {
            // The setup header as the image has it, up to its end.
            let end = (HDR_JUMP + 2 + setup[HDR_JUMP + 1] as usize).min(0x300);
            bp[HDR..end].copy_from_slice(&setup[HDR..end]);
        }
        None => {
            put(&mut bp, HDR_BOOT_FLAG, 2, 0xaa55);
            put(&mut bp, HDR_MAGIC, 4, HDRS as u64);
            put(&mut bp, HDR_VERSION, 2, 0x020f);
            put(&mut bp, HDR_KERNEL_ALIGNMENT, 4, LOAD_DEFAULT);
            put(&mut bp, HDR_CMDLINE_SIZE, 4, CMDLINE_MAX as u64 - 1);
        }
    }
    bp[HDR_TYPE_OF_LOADER] = 0xff;
    bp[HDR_LOADFLAGS] |= LOADED_HIGH | CAN_USE_HEAP;
    put(&mut bp, HDR_HEAP_END, 2, 0xfe00);
    let room = match le(&bp, HDR_CMDLINE_SIZE, 4) as usize {
        0 => 255,
        n => n,
    };
    let n = cmdline.iter().position(|&c| c == 0).unwrap_or(cmdline.len()).min(room).min(CMDLINE_MAX - 1);
    let mut line = [0u8; CMDLINE_MAX];
    line[..n].copy_from_slice(&cmdline[..n]);
    if !mem.write_bytes(CMDLINE, &line[..n + 1]) {
        return Err(Error::Layout);
    }
    put(&mut bp, HDR_CMD_LINE_PTR, 4, CMDLINE);
    put(&mut bp, BP_EXT_CMD_LINE_PTR, 4, CMDLINE >> 32);
    if initrd.1 != 0 {
        put(&mut bp, HDR_RAMDISK_IMAGE, 4, initrd.0 & 0xffff_ffff);
        put(&mut bp, HDR_RAMDISK_SIZE, 4, initrd.1 & 0xffff_ffff);
        put(&mut bp, BP_EXT_RAMDISK_IMAGE, 4, initrd.0 >> 32);
        put(&mut bp, BP_EXT_RAMDISK_SIZE, 4, initrd.1 >> 32);
    }
    put(&mut bp, BP_ACPI_RSDP, 8, rsdp);
    let mut map = [(0, 0, 0); 8];
    let entries = e820(mem.low, mem.high, &mut map);
    assert!(entries <= E820_MAX);
    bp[BP_E820_ENTRIES] = entries as u8;
    for (i, &(start, size, ty)) in map[..entries].iter().enumerate() {
        let at = BP_E820_TABLE + 20 * i;
        put(&mut bp, at, 8, start);
        put(&mut bp, at + 8, 8, size);
        put(&mut bp, at + 16, 4, ty as u64);
    }
    if !mem.write_bytes(ZERO_PAGE, &bp) {
        return Err(Error::Layout);
    }

    // ---- GDT: null, null, 64-bit code (BOOT_CS), data (BOOT_DS).
    let gdt: [u64; 4] = [0, 0, 0x00af_9b00_0000_ffff, 0x00cf_9300_0000_ffff];
    let mut g = [0u8; 32];
    for (i, d) in gdt.iter().enumerate() {
        put(&mut g, 8 * i, 8, *d);
    }
    if !mem.write_bytes(GDT, &g) {
        return Err(Error::Layout);
    }

    // ---- Page tables: the first 4 GiB 1:1 in 2 MiB pages (PML4, PDPT,
    // and four directories after them).
    let mut table = [0u8; 4096];
    put(&mut table, 0, 8, (PML4 + 0x1000) | 0x3);
    let ok = mem.write_bytes(PML4, &table);
    table.fill(0);
    for i in 0..4 {
        put(&mut table, 8 * i, 8, (PML4 + 0x2000 + 0x1000 * i as u64) | 0x3);
    }
    let mut ok = ok && mem.write_bytes(PML4 + 0x1000, &table);
    for d in 0..4u64 {
        for i in 0..512u64 {
            put(&mut table, 8 * i as usize, 8, ((d << 30) + (i << 21)) | 0x83);
        }
        ok &= mem.write_bytes(PML4 + 0x2000 + 0x1000 * d, &table);
    }
    if !ok {
        return Err(Error::Layout);
    }
    Ok(Entry { rip: kernel.entry, rsi: ZERO_PAGE, cr3: PML4, gdt: GDT })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::tests::fake;

    fn bzimage(mem: &GuestMem, at: u64, payload: &[u8], init_size: u32) -> u64 {
        let mut h = [0u8; 0x600];
        h[HDR_SETUP_SECTS] = 1;
        put(&mut h, HDR_BOOT_FLAG, 2, 0xaa55);
        h[HDR_JUMP] = 0xeb;
        h[HDR_JUMP + 1] = 0x6a;
        put(&mut h, HDR_MAGIC, 4, HDRS as u64);
        put(&mut h, HDR_VERSION, 2, 0x020f);
        put(&mut h, HDR_INITRD_ADDR_MAX, 4, 0x7fff_ffff);
        put(&mut h, HDR_KERNEL_ALIGNMENT, 4, 0x20_0000);
        h[HDR_RELOCATABLE] = 1;
        put(&mut h, HDR_XLOADFLAGS, 2, (XLF_KERNEL_64 | XLF_CAN_BE_LOADED_ABOVE_4G) as u64);
        put(&mut h, HDR_CMDLINE_SIZE, 4, 2047);
        put(&mut h, HDR_PREF_ADDRESS, 8, 0x40_0000);
        put(&mut h, HDR_INIT_SIZE, 4, init_size as u64);
        assert!(mem.write_bytes(at, &h[..1024]));
        assert!(mem.write_bytes(at + 1024, payload));
        1024 + payload.len() as u64
    }

    #[test]
    fn bzimage_boot() {
        let (mem, _buf) = fake(16 << 20, 0);
        let len = bzimage(&mem, 0x80_0000, b"payload!", 0x1000);
        let k = Kernel::parse(&mem, 0x80_0000, len).unwrap();
        mem.write_bytes(0xc0_0000, b"initrd");
        let e = load(&mem, &k, (0x80_0000, len), (0xc0_0000, 6), b"console=ttyS0\0junk", 0xe0000).unwrap();
        assert_eq!(e, Entry { rip: 0x40_0200, rsi: ZERO_PAGE, cr3: PML4, gdt: GDT });
        let mut b = [0u8; 8];
        mem.read_bytes(0x40_0000, &mut b);
        assert_eq!(&b, b"payload!");
        // The rest of init_size is zeroed.
        assert_eq!(mem.read::<u64>(0x40_0008), 0);
        let mut bp = [0u8; 4096];
        mem.read_bytes(ZERO_PAGE, &mut bp);
        assert_eq!(le(&bp, HDR_MAGIC, 4) as u32, HDRS);
        assert_eq!(bp[HDR_TYPE_OF_LOADER], 0xff);
        assert_eq!(le(&bp, HDR_RAMDISK_IMAGE, 4), 0xc0_0000);
        assert_eq!(le(&bp, HDR_RAMDISK_SIZE, 4), 6);
        assert_eq!(le(&bp, HDR_CMD_LINE_PTR, 4), CMDLINE);
        assert_eq!(le(&bp, BP_ACPI_RSDP, 8), 0xe0000);
        let mut line = [0u8; 14];
        mem.read_bytes(CMDLINE, &mut line);
        assert_eq!(&line, b"console=ttyS0\0");
        // E820: RAM below 640 KiB, reserved holes, RAM from 1 MiB, ECAM.
        assert_eq!(bp[BP_E820_ENTRIES], 5);
        assert_eq!(le(&bp, BP_E820_TABLE + 3 * 20, 8), LOW_END);
        assert_eq!(le(&bp, BP_E820_TABLE + 3 * 20 + 8, 8), (16 << 20) - LOW_END);
        // Page tables: 1:1, 2 MiB pages.
        assert_eq!(mem.read::<u64>(PML4) & !0xfff, PML4 + 0x1000);
        assert_eq!(mem.read::<u64>(PML4 + 0x2000 + 8 * 3), (3 << 21) | 0x83);
        assert_eq!(mem.read::<u64>(PML4 + 0x5000 + 8 * 511), (3 << 30) + (511 << 21) | 0x83);
        assert_eq!(mem.read::<u64>(GDT + 16), 0x00af_9b00_0000_ffff);
    }

    #[test]
    fn bzimage_refusals() {
        let (mem, _buf) = fake(16 << 20, 0);
        let len = bzimage(&mem, 0x80_0000, b"payload!", 0x1000);
        // Older protocol; not 64-bit; not an image at all.
        mem.write::<u16>(0x80_0000 + HDR_VERSION as u64, 0x020b);
        assert_eq!(Kernel::parse(&mem, 0x80_0000, len).err(), Some(Error::Version));
        mem.write::<u16>(0x80_0000 + HDR_VERSION as u64, 0x020f);
        mem.write::<u16>(0x80_0000 + HDR_XLOADFLAGS as u64, 0);
        assert_eq!(Kernel::parse(&mem, 0x80_0000, len).err(), Some(Error::Format));
        assert_eq!(Kernel::parse(&mem, 0x90_0000, len).err(), Some(Error::Format));
        let len = bzimage(&mem, 0x80_0000, b"payload!", 0x1000);
        let k = Kernel::parse(&mem, 0x80_0000, len).unwrap();
        // The initrd in the kernel's way, or in the first MiB.
        assert_eq!(load(&mem, &k, (0x80_0000, len), (0x40_0800, 6), b"", 0).err(), Some(Error::Layout));
        assert_eq!(load(&mem, &k, (0x80_0000, len), (0x1000, 6), b"", 0).err(), Some(Error::Layout));
        // An image past the end of RAM.
        assert_eq!(Kernel::parse(&mem, (16 << 20) - 16, len).err(), Some(Error::Layout));
        // A kernel too large for RAM.
        let len = bzimage(&mem, 0x80_0000, b"payload!", 0x7f0_0000);
        let k = Kernel::parse(&mem, 0x80_0000, len).unwrap();
        assert_eq!(load(&mem, &k, (0x80_0000, len), (0, 0), b"", 0).err(), Some(Error::Layout));
    }

    #[test]
    fn elf_boot() {
        let (mem, _buf) = fake(16 << 20, 0);
        let mut e = [0u8; 0x200];
        e[..4].copy_from_slice(b"\x7fELF");
        e[4] = 2;
        e[5] = 1;
        put(&mut e, 18, 2, 62);
        put(&mut e, 24, 8, 0x20_0000);
        put(&mut e, 32, 8, 64);
        put(&mut e, 54, 2, 56);
        put(&mut e, 56, 2, 2);
        // A PT_NOTE, then a PT_LOAD of 4 bytes into 16 at 2 MiB.
        put(&mut e, 64, 4, 4);
        let ph = 64 + 56;
        put(&mut e, ph, 4, 1);
        put(&mut e, ph + 8, 8, 0x100);
        put(&mut e, ph + 24, 8, 0x20_0000);
        put(&mut e, ph + 32, 8, 4);
        put(&mut e, ph + 40, 8, 16);
        e[0x100..0x104].copy_from_slice(b"ELF!");
        mem.write_bytes(0x80_0000, &e);
        mem.write::<u64>(0x20_0008, u64::MAX);
        let k = Kernel::parse(&mem, 0x80_0000, 0x200).unwrap();
        let entry = load(&mem, &k, (0x80_0000, 0x200), (0, 0), b"ro", 0).unwrap();
        assert_eq!(entry.rip, 0x20_0000);
        assert_eq!(mem.read::<u32>(0x20_0000), u32::from_le_bytes(*b"ELF!"));
        assert_eq!(mem.read::<u64>(0x20_0008), 0, "bss cleared");
        let mut bp = [0u8; 0x300];
        mem.read_bytes(ZERO_PAGE, &mut bp);
        assert_eq!(le(&bp, HDR_MAGIC, 4) as u32, HDRS);
        // Not x86-64.
        mem.write::<u16>(0x80_0000 + 18, 3);
        assert_eq!(Kernel::parse(&mem, 0x80_0000, 0x200).err(), Some(Error::Format));
    }

    /// A kernel that cannot be relocated runs at its preferred address,
    /// whatever its alignment; the initrd must stay clear of its window.
    #[test]
    fn non_relocatable_bzimage_at_its_preferred_address() {
        assert_eq!(load_address(false, 0x30_0000, 0x20_0000), 0x30_0000);
        assert_eq!(load_address(true, 0x30_0000, 0x20_0000), LOAD_DEFAULT, "relocatable, misaligned");
        assert_eq!(load_address(true, 0x40_0000, 0x20_0000), 0x40_0000);
        assert_eq!(load_address(false, 0, 0x20_0000), LOAD_DEFAULT);
        let (mem, _buf) = fake(16 << 20, 0);
        let len = bzimage(&mem, 0x80_0000, b"fixed!!!", 0x20_0000);
        mem.write::<u8>(0x80_0000 + HDR_RELOCATABLE as u64, 0);
        mem.write::<u64>(0x80_0000 + HDR_PREF_ADDRESS as u64, 0x30_0000);
        let k = Kernel::parse(&mem, 0x80_0000, len).unwrap();
        // An initrd in [pref, pref + init_size) is refused; past it, fine.
        assert_eq!(load(&mem, &k, (0x80_0000, len), (0x40_0000, 6), b"", 0xe0000).err(), Some(Error::Layout));
        mem.write_bytes(0xc0_0000, b"initrd");
        let e = load(&mem, &k, (0x80_0000, len), (0xc0_0000, 6), b"", 0xe0000).unwrap();
        assert_eq!(e.rip, 0x30_0200);
        let mut b = [0u8; 8];
        mem.read_bytes(0x30_0000, &mut b);
        assert_eq!(&b, b"fixed!!!");
        mem.read_bytes(0xc0_0000, &mut b[..6]);
        assert_eq!(&b[..6], b"initrd");
    }

    /// The image below where the kernel goes, which nothing mapped yet:
    /// loading maps those blocks as it writes them (before the machine
    /// exists), and the bytes are right.
    #[test]
    fn loading_maps_blocks_it_first_touches() {
        use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        static MAPPED: [AtomicU64; 1] = [AtomicU64::new(0)];
        static MAPS: AtomicUsize = AtomicUsize::new(0);
        fn map(b: usize) -> bool {
            MAPS.fetch_add(1, Ordering::SeqCst);
            MAPPED[0].fetch_or(1 << b, Ordering::SeqCst);
            true
        }
        let buf = std::vec![0u8; 32 << 20];
        let mem = GuestMem { base: buf.as_ptr() as usize, low: 32 << 20, high: 0, mapped: &MAPPED, map };
        // vmmgr filled the blocks up to the image (0 to 4 MiB): block 0,
        // the image's at 2 MiB.
        MAPPED[0].store(0b11, Ordering::SeqCst);
        let mut e = [0u8; 0x200];
        e[..4].copy_from_slice(b"\x7fELF");
        e[4] = 2;
        e[5] = 1;
        put(&mut e, 18, 2, 62);
        put(&mut e, 24, 8, 0x100_0000);
        put(&mut e, 32, 8, 64);
        put(&mut e, 54, 2, 56);
        put(&mut e, 56, 2, 1);
        put(&mut e, 64, 4, 1);
        put(&mut e, 64 + 8, 8, 0x100);
        put(&mut e, 64 + 24, 8, 0x100_0000);
        put(&mut e, 64 + 32, 8, 8);
        put(&mut e, 64 + 40, 8, 0x40_0000);
        e[0x100..0x108].copy_from_slice(b"low src!");
        assert!(mem.write_bytes(0x20_0000, &e));
        let k = Kernel::parse(&mem, 0x20_0000, 0x200).unwrap();
        let entry = load(&mem, &k, (0x20_0000, 0x200), (0, 0), b"", 0xe0000).unwrap();
        assert_eq!(entry.rip, 0x100_0000);
        assert_eq!(mem.read::<u64>(0x100_0000), u64::from_le_bytes(*b"low src!"));
        assert_eq!(mem.read::<u64>(0x13f_fff8), 0, "the rest zeroed");
        let m = MAPPED[0].load(Ordering::SeqCst);
        assert_eq!(m & (0b11 << 8), 0b11 << 8, "blocks 8 and 9 mapped as written");
        assert!(MAPS.load(Ordering::SeqCst) >= 2);
    }

    /// Program headers anywhere a hostile image puts them: refused.
    #[test]
    fn elf_program_headers_out_of_bounds() {
        let (mem, _buf) = fake(16 << 20, 0);
        let mut e = [0u8; 0x200];
        e[..4].copy_from_slice(b"\x7fELF");
        e[4] = 2;
        e[5] = 1;
        put(&mut e, 18, 2, 62);
        put(&mut e, 54, 2, 56);
        put(&mut e, 56, 2, 2);
        for (phoff, phentsize) in [(u64::MAX - 8, 56), (u64::MAX - 100, 0xffff), (0x1f0, 56), (1 << 40, 56)] {
            put(&mut e, 32, 8, phoff);
            put(&mut e, 54, 2, phentsize);
            assert!(mem.write_bytes(0x80_0000, &e));
            assert_eq!(Kernel::parse(&mem, 0x80_0000, 0x200).err(), Some(Error::Format), "{phoff:#x} {phentsize}");
        }
    }

    /// Addresses that do not fit in 64 bits are refused, not wrapped.
    #[test]
    fn layouts_past_the_address_space() {
        let (mem, _buf) = fake(16 << 20, 0);
        let len = bzimage(&mem, 0x80_0000, b"payload!", 0x1000);
        mem.write::<u8>(0x80_0000 + HDR_RELOCATABLE as u64, 0);
        for pref in [u64::MAX - 0x100, u64::MAX - 0x800] {
            mem.write::<u64>(0x80_0000 + HDR_PREF_ADDRESS as u64, pref);
            assert_eq!(Kernel::parse(&mem, 0x80_0000, len).err(), Some(Error::Layout), "{pref:#x}");
        }
        mem.write::<u64>(0x80_0000 + HDR_PREF_ADDRESS as u64, 0x40_0000);
        let k = Kernel::parse(&mem, 0x80_0000, len).unwrap();
        assert_eq!(load(&mem, &k, (0x80_0000, len), (u64::MAX - 2, 6), b"", 0xe0000).err(), Some(Error::Layout));
        assert!(!overlap((u64::MAX - 1, 4), (0, 1)) && overlap((u64::MAX - 1, 4), (u64::MAX, 1)));
    }

    #[test]
    fn e820_high_ram() {
        let mut map = [(0, 0, 0); 8];
        let n = e820(3 << 30, 5 << 30, &mut map);
        assert_eq!(map[n - 1], (4 << 30, 5 << 30, E820_RAM));
        assert_eq!(map[n - 2].0, crate::dev::pci::ECAM_BASE);
    }
}
