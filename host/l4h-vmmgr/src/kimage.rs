//! The guest kernel l4h ships, which every guest runs (the boot module
//! `guest-kernel`), and its module tree (`guest-kmods`): an EROFS image of
//! its /lib/modules, with its modules and the tree to build more against,
//! which every guest maps read-only (DESIGN.md §5.6).
//!
//! Both are shared: guests map read-only copies of the boot module's own
//! frames rather than copies of its bytes.  Root maps the modules into
//! vmmgr, and gives it a CNode of their frames (`Modules`).  Of the kernel,
//! that is the RAM blocks of its image that lie wholly in read-only
//! segments (text and rodata): those blocks have no memory of the guest's
//! behind them.

use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap_type};

use l4h_abi as abi;

use l4h_host::vmmgr as proto;

use crate::elf::Elf;
use crate::guest::{BLOCK, Guest, abs, self_cap};
use crate::mem::{Alloc, Slot};
use crate::vspace::map_frame;

const PAGE: usize = 4096;

/// The boot modules root mapped at MODULES_VA, page after page, and the
/// CNode of their frames (SLOT_MODULES): frame i is the page at
/// MODULES_VA + 4096 i.
#[derive(Clone, Copy)]
pub struct Modules {
    radix: usize,
    pages: usize,
}

impl Modules {
    pub fn new(radix: usize, pages: usize) -> Self {
        Self { radix, pages }
    }

    /// The frame of the module page at `va` (page aligned), if root
    /// mapped it.
    fn get(&self, va: usize) -> Option<sel4::AbsoluteCPtr> {
        let i = va.checked_sub(proto::MODULES_VA)? / PAGE;
        (va % PAGE == 0 && i < self.pages).then(|| {
            self_cap::<cap_type::CNode>(proto::SLOT_MODULES as Slot).absolute_cptr_from_bits_with_depth(i as u64, self.radix)
        })
    }
}

/// Copy module frame `from`, read-only, into slot `to`.
fn copy_read_only(from: &sel4::AbsoluteCPtr, to: Slot) {
    abs(self_cap::<cap_type::Null>(to)).copy(from, CapRights::read_only()).expect("shared frame copy");
}

pub struct Kernel {
    pub elf: Elf<'static>,
    /// The VA of guest-physical address 0: where the image starts.
    pub ram_base: usize,
    /// End of the image in guest RAM, page aligned.
    pub end: usize,
    /// Blocks of the image every guest shares (bit b: GPA block b): all
    /// their pages are boot module pages in read-only segments.
    pub shared: u64,
    frames: Modules,
}

impl Kernel {
    pub fn parse(data: &'static [u8], modules: &Modules) -> Result<Self, &'static str> {
        let elf = Elf::parse(data)?;
        let (lo, hi) = elf.bounds();
        if lo >= hi {
            return Err("no loadable segments");
        }
        let ram_base = lo as usize & !(PAGE - 1);
        let end = (hi as usize - ram_base).next_multiple_of(PAGE);
        let mut k = Self { elf, ram_base, end, shared: 0, frames: *modules };
        k.share();
        Ok(k)
    }

    /// The frame of the boot module page holding the whole page at `gpa`,
    /// if that page lies in the file data of a read-only segment.  Pages
    /// a segment covers only in part keep the zeros around it private, as
    /// a guest loads them.
    fn module_frame(&self, gpa: usize) -> Option<sel4::AbsoluteCPtr> {
        let va = self.ram_base + gpa;
        let seg = self.elf.segments().find(|s| {
            let at = s.vaddr as usize;
            !s.writable && at <= va && va + PAGE <= at + s.data.len()
        })?;
        let file = seg.data.as_ptr() as usize + (va - seg.vaddr as usize);
        if file % PAGE != 0 {
            return None;
        }
        self.frames.get(file)
    }

    /// Find the blocks guests can share.
    fn share(&mut self) {
        let blocks = (self.end / BLOCK).min(u64::BITS as usize);
        for b in 0..blocks {
            if (0..BLOCK / PAGE).all(|i| self.module_frame(b * BLOCK + i * PAGE).is_some()) {
                self.shared |= 1 << b;
            }
        }
        info!(
            "l4h-vmmgr: guest kernel: {} of {} MiB shared by all guests",
            self.shared.count_ones() as usize * BLOCK >> 20,
            self.end.div_ceil(1 << 20)
        );
    }

    /// Copy the frame of shared guest-physical page `gpa` into slot `to`,
    /// read-only.
    pub fn copy_frame(&self, gpa: usize, to: Slot) {
        copy_read_only(&self.module_frame(gpa).expect("shared page without a frame"), to);
    }

    /// The lowest guest-physical address of an initrd.
    pub fn initrd_gpa(&self) -> usize {
        self.end + (1 << 20)
    }
}

/// The module image: its boot module's pages, which each guest maps
/// copies of.
pub struct Kmods {
    data: &'static [u8],
    frames: Modules,
}

impl Kmods {
    /// The image in boot module `data`.  Root checked that guests may map
    /// its last page whole (it cleared what follows the image in it).
    pub fn new(modules: &Modules, data: &'static [u8]) -> Option<Self> {
        let start = data.as_ptr() as usize;
        if data.is_empty() || data.len() as u64 > abi::KMOD_MAX || (start..start + data.len()).step_by(PAGE).any(|va| modules.get(va).is_none()) {
            l4h_rt::log!("l4h-vmmgr: module image at {:#x} of {} bytes ignored", start, data.len());
            return None;
        }
        Some(Self { data, frames: *modules })
    }

    fn pages(&self) -> usize {
        self.data.len().div_ceil(PAGE)
    }

    fn radix(&self) -> usize {
        self.pages().next_power_of_two().trailing_zeros() as usize
    }

    /// Host memory a guest's mapping of the image takes: the CNode of its
    /// frames and the page tables (and a directory per GiB) mapping them.
    pub fn bytes(&self) -> usize {
        (32 << self.radix()) + (self.pages().div_ceil(512) + self.pages().div_ceil(512 * 512) + 1) * PAGE
    }

    /// Map the image read-only at KMOD_VA in guest `g`, and record it for
    /// the boot info.  The frame copies are kept in a CNode of the guest's
    /// arena, so destroying the guest deletes them.
    pub fn map(&self, g: &mut Guest, alloc: &mut Alloc) {
        let radix = self.radix();
        let keep = g.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: radix });
        let tmp = alloc.slots.alloc();
        for i in 0..self.pages() {
            let from = self.frames.get(self.data.as_ptr() as usize + i * PAGE).expect("module image frame");
            copy_read_only(&from, tmp);
            let frame = self_cap::<cap_type::Granule>(tmp);
            let (vspace, va) = (g.vspace, abi::KMOD_VA as usize + i * PAGE);
            map_frame(&mut g.ctx(alloc), vspace, frame, va, CapRights::read_only(), VmAttributes::DEFAULT);
            keep.absolute_cptr_from_bits_with_depth(i as u64, radix).move_(&abs(frame)).expect("keep module image mapping");
        }
        alloc.slots.free(tmp);
        g.kmod_size = self.data.len();
    }
}
