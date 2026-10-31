//! The guest kernel and its module image, dom0's initramfs and the host
//! settings, as named modules (`guest-kernel`, `guest-kmods`, `dom0-initrd`,
//! `l4h-config`; DESIGN.md §10.1), from:
//!
//! - the boot loader (x86): GRUB reads them from the EFI system partition,
//!   or QEMU's -initrd lists them after root.  seL4 keeps them intact as
//!   device memory and lists them in the bootinfo (patch 0021); root maps
//!   them for good, since restarting dom0 loads its images again.
//! - root's own image (x86 and aarch64): tools/add-modules.py appends them
//!   to a built l4h-root.elf as one more loadable segment and records it
//!   in `ANCHOR`, so the kernel or the loader maps them with the rest of
//!   root.
//!
//! The boot loader's modules come first: they win over appended ones of
//! the same name.
//!
//! Either way each page of a module is a frame root holds a capability
//! to, so guests can map read-only copies of a module's pages instead of
//! copies of its bytes (`ModuleFrames`, kimage.rs).

use l4h_host::fixed::{ArrayVec, StaticCell};

use crate::devmem::DevMem;
use crate::mem::{Alloc, Slot};

#[derive(Clone, Copy)]
pub struct Module {
    /// For a boot loader module, the last word of its string, which names
    /// its role (GRUB passes the words after the file name, QEMU the whole
    /// -initrd item).
    pub name: &'static str,
    pub data: &'static [u8],
}

/// Modules kept, at most (there are four roles); more are reported and
/// ignored.
pub const MAX_MODULES: usize = 16;

/// Runs of module pages whose frames are in consecutive root slots, at
/// most.  A boot loader module is carved in aligned chunks of at most
/// RETYPE_FAN_OUT frames (64 MiB), each a run unless it continues the
/// last: the MODULES region holds 1024 whole chunks, and the unaligned
/// ends of each module add a few dozen more.  The appended segment is one
/// run.  Pages past them have no known frame, and guests get no shared
/// copy of them.
const MAX_RUNS: usize = 2048;

/// Pages [va, va + 4096 * pages) of the root task, whose frames are root
/// slots [slot, slot + pages).
#[derive(Clone, Copy)]
struct Run {
    va: usize,
    slot: Slot,
    pages: usize,
}

/// In .bss: the root task's stack, where `Modules` is, has no room.
static RUNS: StaticCell<ArrayVec<Run, MAX_RUNS>> = StaticCell::new(ArrayVec::new());

fn add_run(runs: &mut ArrayVec<Run, MAX_RUNS>, va: usize, slot: Slot, pages: usize) {
    if let Some(r) = runs.last_mut() {
        if r.va + r.pages * 4096 == va && r.slot + r.pages == slot {
            r.pages += pages;
            return;
        }
    }
    if runs.push(Run { va, slot, pages }).is_err() {
        log!("l4h-root: module frames past {:#x} not recorded, guests get no shared copy", va);
    }
}

/// The frames of the modules' pages, for as long as root runs.
#[derive(Clone, Copy)]
pub struct ModuleFrames(&'static ArrayVec<Run, MAX_RUNS>);

impl ModuleFrames {
    /// The root slot of the frame of the module page at `va` (page
    /// aligned), if it is known.  The frame is mapped read-only in the
    /// root task; guests can map copies of it.
    pub fn get(&self, va: usize) -> Option<Slot> {
        let r = self.0.iter().find(|r| r.va <= va && va < r.va + r.pages * 4096)?;
        Some(r.slot + (va - r.va) / 4096)
    }
}

/// The modules found, in order, and the frames of their pages.
pub struct Modules {
    list: [Option<Module>; MAX_MODULES],
    frames: Option<ModuleFrames>,
}

impl Modules {
    pub fn frames(&self) -> ModuleFrames {
        self.frames.expect("module frames")
    }

    fn push(&mut self, m: Module) {
        match self.list.iter_mut().find(|s| s.is_none()) {
            Some(s) => *s = Some(m),
            None => log!("l4h-root: more than {} modules, '{}' ignored", MAX_MODULES, m.name),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Module> {
        self.list.iter().flatten()
    }
}

/// Where tools/add-modules.py records the segment it appended (it finds
/// the anchor by its magic and fills in `va` and `size` in the file).
#[repr(C)]
struct Anchor {
    magic: [u8; 16],
    va: u64,
    size: u64,
}

#[used]
static ANCHOR: Anchor = Anchor { magic: *b"l4h-modules-v1\0\0", va: 0, size: 0 };

/// The appended segment: this header, `count` entries, then the files.
const TABLE_MAGIC: &[u8; 8] = b"L4HMODS1";
/// An entry: a NUL-padded name, and the file's offset (from the start of
/// the segment) and size.
const NAME_LEN: usize = 64;
const ENTRY: usize = NAME_LEN + 16;

/// All modules: the boot loader's, then root's appended ones.
pub fn load(bootinfo: &sel4::BootInfoPtr, alloc: &mut Alloc, devmem: &mut DevMem) -> Modules {
    let runs = RUNS.take();
    let mut out = Modules { list: [None; MAX_MODULES], frames: None };
    loader_modules(bootinfo, alloc, devmem, &mut out, runs);
    appended(bootinfo, &mut out, runs);
    out.frames = Some(ModuleFrames(runs));
    for m in out.iter() {
        info!("l4h-root: module '{}', {} KiB", m.name, m.data.len() >> 10);
    }
    out
}

/// The modules appended to root's image.  Their frames are among the
/// image frames seL4 gives the root task (layout::image_base).
fn appended(bootinfo: &sel4::BootInfoPtr, out: &mut Modules, runs: &mut ArrayVec<Run, MAX_RUNS>) {
    // Volatile: the file is edited after the build.
    let (va, size) = unsafe {
        (core::ptr::read_volatile(&ANCHOR.va) as usize, core::ptr::read_volatile(&ANCHOR.size) as usize)
    };
    if size < 16 {
        return;
    }
    let seg = unsafe { core::slice::from_raw_parts(va as *const u8, size) };
    let word = |i: usize| u64::from_le_bytes(seg[i..i + 8].try_into().unwrap()) as usize;
    if &seg[..8] != TABLE_MAGIC {
        log!("l4h-root: appended modules: bad table, ignored");
        return;
    }
    let frames = bootinfo.user_image_frames();
    let (first, pages) = ((va - crate::layout::image_base()) / 4096, size.div_ceil(4096));
    if va % 4096 == 0 && first + pages <= frames.len() {
        add_run(runs, va, frames.start() + first, pages);
    }
    let count = word(8).min((size - 16) / ENTRY);
    for i in 0..count {
        let e = 16 + i * ENTRY;
        let raw = &seg[e..e + NAME_LEN];
        let raw = &raw[..raw.iter().position(|&b| b == 0).unwrap_or(NAME_LEN)];
        let (off, len) = (word(e + NAME_LEN), word(e + NAME_LEN + 8));
        let (Ok(name), Some(end)) = (core::str::from_utf8(raw), off.checked_add(len)) else { continue };
        if end > size {
            log!("l4h-root: appended module '{}' out of bounds, ignored", name);
            continue;
        }
        out.push(Module { name, data: &seg[off..end] });
    }
}

/// The contents of the extra bootinfo chunk `id`, after its header.
pub fn extra_chunk(bootinfo: &sel4::BootInfoPtr, id: u64) -> Option<&'static [u8]> {
    // rust-sel4's extra() skips IDs it does not know: walk the chunks here.
    let granule = sel4::FrameObjectType::GRANULE.bytes();
    let extra: &'static [u8] = unsafe {
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

#[cfg(not(target_arch = "x86_64"))]
fn loader_modules(
    _bootinfo: &sel4::BootInfoPtr,
    _alloc: &mut Alloc,
    _devmem: &mut DevMem,
    _out: &mut Modules,
    _runs: &mut ArrayVec<Run, MAX_RUNS>,
) {
}

/// Map the boot loader's modules listed in the bootinfo.
#[cfg(target_arch = "x86_64")]
fn loader_modules(
    bootinfo: &sel4::BootInfoPtr,
    alloc: &mut Alloc,
    devmem: &mut DevMem,
    out: &mut Modules,
    runs: &mut ArrayVec<Run, MAX_RUNS>,
) {
    use sel4::init_thread::slot;
    use sel4::{CapRights, VmAttributes};

    use crate::mem::ObjCtx;
    use crate::vspace::map_frame;

    // Where the modules are mapped in the root task, one after another.
    let region = &crate::layout::MODULES;
    // SEL4_BOOTINFO_HEADER_X86_BOOT_MODULES: a count, then entries of
    // paddr, size and a 64-byte name (seL4_X86_BootModules_t).
    const BOOT_MODULES: u64 = 8;
    const ENTRY: usize = 16 + 64;
    let Some(c) = extra_chunk(bootinfo, BOOT_MODULES) else { return };
    let word = |i: usize| u64::from_le_bytes(c[i..i + 8].try_into().unwrap()) as usize;
    let count = if c.len() >= 8 { word(0).min((c.len() - 8) / ENTRY) } else { 0 };
    let mut va = region.base;
    for i in 0..count {
        let e = 8 + i * ENTRY;
        let (paddr, size) = (word(e), word(e + 8));
        let raw = &c[e + 16..e + ENTRY];
        let raw = &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())];
        let name = core::str::from_utf8(raw).unwrap_or("").split_whitespace().last().unwrap_or("");
        let pages = size.div_ceil(4096);
        // Each page keeps a root slot: the modules may take at most half
        // of the root CNode, the rest is for guests and components.
        if va + pages * 4096 > region.end() || alloc.slots.available() < pages + crate::CNODE_SLOTS / 2 {
            log!("l4h-root: boot module '{}' of {} MiB does not fit, ignored", name, size >> 20);
            continue;
        }
        // The frames are mapped as they are carved, a chunk at a time.
        let mut at = va;
        let carved = devmem.frames_range(alloc, paddr, pages * 4096, |alloc, frames| {
            add_run(runs, at, frames.start, frames.len());
            alloc.global(|alloc| {
                for s in frames {
                    let f = crate::devmem::granule(s);
                    map_frame(&mut ObjCtx::global(alloc), slot::VSPACE.cap(), f, at, CapRights::read_only(), VmAttributes::DEFAULT);
                    at += 4096;
                }
            })
        });
        if carved.is_none() {
            log!("l4h-root: boot module '{}' at {:#x} is not device memory, ignored", name, paddr);
            // Past whatever of it was mapped before carving failed.
            va = at;
            continue;
        }
        let data = unsafe { core::slice::from_raw_parts(va as *const u8, size) };
        out.push(Module { name, data });
        va += pages * 4096;
    }
}
