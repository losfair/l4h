//! Reading ACPI tables (x86): seL4 parses the ones it needs itself and
//! passes us a copy of the RSDP; the tables lie outside RAM, in device
//! memory.  Nothing here allocates: tables are read into the caller's
//! buffers, a part at a time, and the frames carved for them are kept in
//! one fixed table.

use core::sync::atomic::{AtomicBool, Ordering};

use sel4::cap;

use l4h_host::fixed::ArrayVec;

use crate::component::abs_of;
use crate::devmem::{self, DevMem};
use crate::mem::Alloc;
use crate::trustd::AML_MAX;
use crate::window::Window;

const PAGE: usize = 4096;

/// Device pages carved for ACPI, at most: the tables read at boot (the AML
/// trustd runs is at most AML_MAX bytes, plus a page per table that does
/// not start on one, and the few others), the TPM's ranges, and the pages
/// trustd's AML touches at run time.  Beyond it, accesses to new pages are
/// refused: the firmware's AML could otherwise make root carve every page
/// of a large MMIO window.
pub const TRUSTD_MAX_PAGES: usize = AML_MAX / PAGE + 1024;

/// The FADT's size in ACPI 6 (revision 6); older ones are shorter.  Enough
/// for every field root reads.
pub const FADT_LEN: usize = 276;

/// Carved frames as (page, frame), sorted by page.
type PageTable = ArrayVec<(usize, cap::Granule), TRUSTD_MAX_PAGES>;

/// The table lives in .bss: at 16 bytes an entry it is too large for the
/// root task's stack, where `Host` and trustd's state are.
static mut PAGES: PageTable = ArrayVec::new();
static PAGES_TAKEN: AtomicBool = AtomicBool::new(false);

/// Frames of physical memory outside RAM, carved on first use, by page.
pub struct Frames {
    pages: &'static mut PageTable,
    /// The table was found full (reported once).
    full: bool,
}

impl Frames {
    /// The table, empty: there is one, taken once at boot.
    pub fn new() -> Self {
        assert!(!PAGES_TAKEN.swap(true, Ordering::Relaxed), "ACPI frame table taken twice");
        // The flag gives out the only reference; the root task is
        // single-threaded.
        Frames { pages: unsafe { &mut *(&raw mut PAGES) }, full: false }
    }

    /// The frame of `page`, if it was carved (`Phys::frame`).
    pub fn get(&self, page: usize) -> Option<cap::Granule> {
        let i = self.pages.binary_search_by_key(&page, |&(p, _)| p).ok()?;
        Some(self.pages[i].1)
    }
}

/// Physical memory outside RAM, read and written through the window.
pub struct Phys<'a> {
    pub alloc: &'a mut Alloc,
    pub devmem: &'a mut DevMem,
    pub win: &'a mut Window,
    pub frames: &'a mut Frames,
}

impl<'a> Phys<'a> {
    pub fn new(alloc: &'a mut Alloc, devmem: &'a mut DevMem, win: &'a mut Window, frames: &'a mut Frames) -> Self {
        Phys { alloc, devmem, win, frames }
    }

    /// The frame of the page at `paddr`, carved on first use: None for
    /// RAM, for device memory already given to something else, and for a
    /// new page once TRUSTD_MAX_PAGES are carved.
    pub fn frame(&mut self, paddr: usize) -> Option<cap::Granule> {
        let page = paddr & !(PAGE - 1);
        let pages = &mut *self.frames.pages;
        let i = match pages.binary_search_by_key(&page, |&(p, _)| p) {
            Ok(i) => return Some(pages[i].1),
            Err(i) => i,
        };
        if pages.is_full() {
            if !self.frames.full {
                self.frames.full = true;
                log!("l4h-root: {} ACPI device pages in use, refusing more", TRUSTD_MAX_PAGES);
            }
            return None;
        }
        let (alloc, devmem) = (&mut *self.alloc, &mut *self.devmem);
        let f = devmem::granule(alloc.slots.global(|slots| devmem.frames(slots, page, PAGE))?.start);
        let _ = pages.insert(i, (page, f));
        Some(f)
    }

    /// `buf.len()` bytes at `paddr`, read with mapping attributes `attrs`.
    pub fn read_into_attrs(&mut self, paddr: usize, buf: &mut [u8], attrs: sel4::VmAttributes) -> Option<()> {
        let mut done = 0;
        while done < buf.len() {
            let at = paddr + done;
            let n = (PAGE - at % PAGE).min(buf.len() - done);
            let f = self.frame(at)?;
            let dst = &mut buf[done..done + n];
            self.win.with_frame_attrs(&abs_of(f), attrs, |p| unsafe {
                let src = p.add(at % PAGE);
                for (i, b) in dst.iter_mut().enumerate() {
                    *b = src.add(i).read_volatile();
                }
            });
            done += n;
        }
        Some(())
    }

    pub fn read_into(&mut self, paddr: usize, buf: &mut [u8]) -> Option<()> {
        self.read_into_attrs(paddr, buf, sel4::VmAttributes::DEFAULT)
    }

    /// One naturally aligned access of `width` bytes (1, 2, 4 or 8) at
    /// `paddr`, mapped uncached: writes `value` if `write`, returns what
    /// it read otherwise.
    pub fn access(&mut self, paddr: usize, width: usize, write: bool, value: u64) -> Option<u64> {
        if !matches!(width, 1 | 2 | 4 | 8) || paddr % width != 0 {
            return None;
        }
        let f = self.frame(paddr)?;
        let off = paddr % PAGE;
        Some(self.win.with_frame_attrs(&abs_of(f), crate::blkd::DEVICE_ATTRS, |p| unsafe {
            let p = p.add(off);
            match (width, write) {
                (1, false) => (p as *const u8).read_volatile() as u64,
                (2, false) => (p as *const u16).read_volatile() as u64,
                (4, false) => (p as *const u32).read_volatile() as u64,
                (_, false) => (p as *const u64).read_volatile(),
                (1, true) => {
                    (p as *mut u8).write_volatile(value as u8);
                    0
                }
                (2, true) => {
                    (p as *mut u16).write_volatile(value as u16);
                    0
                }
                (4, true) => {
                    (p as *mut u32).write_volatile(value as u32);
                    0
                }
                (_, true) => {
                    (p as *mut u64).write_volatile(value);
                    0
                }
            }
        }))
    }
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}

/// The length of the table at `pa`, from its header.
fn table_len(phys: &mut Phys, pa: usize) -> Option<usize> {
    let mut hdr = [0; 36];
    phys.read_into(pa, &mut hdr)?;
    let len = u32_at(&hdr, 4) as usize;
    (36..=AML_MAX).contains(&len).then_some(len)
}

/// The tables the XSDT (or, for ACPI 1.0, the RSDT) lists, read from it an
/// entry at a time.
pub struct Tables {
    root: usize,
    wide: bool,
    count: usize,
}

impl Tables {
    pub fn new(bootinfo: &sel4::BootInfoPtr, phys: &mut Phys) -> Tables {
        // SEL4_BOOTINFO_HEADER_X86_ACPI_RSDP
        const ACPI_RSDP: u64 = 3;
        let none = Tables { root: 0, wide: false, count: 0 };
        let Some(rsdp) = crate::bootmod::extra_chunk(bootinfo, ACPI_RSDP) else { return none };
        if rsdp.len() < 20 || &rsdp[..8] != b"RSD PTR " {
            return none;
        }
        let (root, wide) = if rsdp[15] >= 2 && rsdp.len() >= 32 && u64_at(rsdp, 24) != 0 {
            (u64_at(rsdp, 24) as usize, true)
        } else {
            (u32_at(rsdp, 16) as usize, false)
        };
        let Some(len) = table_len(phys, root) else { return none };
        Tables { root, wide, count: (len - 36) / if wide { 8 } else { 4 } }
    }

    /// The address of the `i`th table listed.
    pub fn get(&self, phys: &mut Phys, i: usize) -> Option<usize> {
        let mut e = [0; 8];
        if self.wide {
            phys.read_into(self.root + 36 + 8 * i, &mut e)?;
            Some(u64_at(&e, 0) as usize)
        } else {
            phys.read_into(self.root + 36 + 4 * i, &mut e[..4])?;
            Some(u32_at(&e, 0) as usize)
        }
    }
}

/// The address and length of the first table with signature `sig`.
fn find_table(bootinfo: &sel4::BootInfoPtr, phys: &mut Phys, sig: &[u8; 4]) -> Option<(usize, usize)> {
    let tables = Tables::new(bootinfo, phys);
    for i in 0..tables.count {
        let pa = tables.get(phys, i)?;
        let mut s = [0; 4];
        phys.read_into(pa, &mut s)?;
        if &s == sig {
            return table_len(phys, pa).map(|len| (pa, len));
        }
    }
    None
}

/// The first table with signature `sig`, header included, read into `buf`:
/// as much of it as fits.
pub fn find<'b>(bootinfo: &sel4::BootInfoPtr, phys: &mut Phys, sig: &[u8; 4], buf: &'b mut [u8]) -> Option<&'b [u8]> {
    let (pa, len) = find_table(bootinfo, phys, sig)?;
    let n = len.min(buf.len());
    let t = &mut buf[..n];
    phys.read_into(pa, t)?;
    Some(t)
}

/// The AML trustd runs (trust::TrustdConfig::aml_size): the FADT, the
/// DSDT it names and every SSDT, back to back with their headers.  Calls
/// `each` with the address and length of each, in that order, and returns
/// the total length: None if a table cannot be read, if `each` fails, or
/// once the total would pass AML_MAX.
pub fn aml_tables(
    bootinfo: &sel4::BootInfoPtr,
    phys: &mut Phys,
    mut each: impl FnMut(&mut Phys, usize, usize) -> Option<()>,
) -> Option<usize> {
    let (fadt, fadt_len) = find_table(bootinfo, phys, b"FACP")?;
    let mut buf = [0; 148];
    let f = &mut buf[..fadt_len.min(148)];
    phys.read_into(fadt, f)?;
    let x_dsdt = if f.len() >= 148 { u64_at(f, 140) as usize } else { 0 };
    let dsdt = if x_dsdt != 0 { x_dsdt } else { u32_at(f.get(..44)?, 40) as usize };
    let mut total = 0;
    let mut add = |phys: &mut Phys, pa: usize, len: usize| {
        total += len;
        if total > AML_MAX {
            return None;
        }
        each(phys, pa, len)
    };
    add(phys, fadt, fadt_len)?;
    let len = table_len(phys, dsdt)?;
    add(phys, dsdt, len)?;
    let tables = Tables::new(bootinfo, phys);
    for i in 0..tables.count {
        let pa = tables.get(phys, i)?;
        let mut sig = [0; 4];
        phys.read_into(pa, &mut sig)?;
        if &sig == b"SSDT" {
            let len = table_len(phys, pa)?;
            add(phys, pa, len)?;
        }
    }
    Some(total)
}
