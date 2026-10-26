//! The guest kernel l4h ships, which every guest runs (the boot module
//! `guest-kernel`), and its module tree (`guest-kmods`): an EROFS image of
//! its /lib/modules, with its modules and the tree to build more against,
//! which every guest maps read-only (DESIGN.md §5.6).
//!
//! Both are shared: guests map read-only copies of the boot module's own
//! frames (bootmod.rs) rather than copies of its bytes.  Of the kernel,
//! that is the RAM blocks of its image that lie wholly in read-only
//! segments (text and rodata): those blocks have no memory of the guest's
//! behind them.

use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap_type};

use l4h_abi as abi;

use crate::bootmod::{ModuleFrames, Modules};
use crate::elf::Elf;
use crate::guest::{BLOCK, Guest, abs, root_cap};
use crate::mem::{Alloc, Slot};
use crate::vspace::map_frame;
use crate::window::Window;

const PAGE: usize = 4096;

/// Copy module frame `from`, read-only, into root slot `to`.
fn copy_read_only(from: Slot, to: Slot) {
    abs(root_cap::<cap_type::Null>(to))
        .copy(&abs(root_cap::<cap_type::Granule>(from)), CapRights::read_only())
        .expect("shared frame copy");
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
    frames: ModuleFrames,
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
        let mut k = Self { elf, ram_base, end, shared: 0, frames: modules.frames() };
        k.share();
        Ok(k)
    }

    /// The frame of the boot module page holding the whole page at `gpa`,
    /// if that page lies in the file data of a read-only segment.  Pages
    /// a segment covers only in part keep the zeros around it private, as
    /// a guest loads them.
    fn module_frame(&self, gpa: usize) -> Option<Slot> {
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
            "l4h-root: guest kernel: {} of {} MiB shared by all guests",
            self.shared.count_ones() as usize * BLOCK >> 20,
            self.end.div_ceil(1 << 20)
        );
    }

    /// Copy the frame of shared guest-physical page `gpa` into root slot
    /// `to`, read-only.
    pub fn copy_frame(&self, gpa: usize, to: Slot) {
        copy_read_only(self.module_frame(gpa).expect("shared page without a frame"), to);
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
    frames: ModuleFrames,
}

impl Kmods {
    /// The image in boot module `data`.  Guests map its last page whole,
    /// so root clears what follows the image in it (a boot loader leaves
    /// whatever was in memory there) before any guest exists.
    pub fn new(modules: &Modules, win: &mut Window, data: &'static [u8]) -> Option<Self> {
        if data.is_empty() || data.len() as u64 > abi::KMOD_MAX {
            sel4::debug_println!("l4h-root: module image of {} bytes ignored", data.len());
            return None;
        }
        let frames = modules.frames();
        let (start, end) = (data.as_ptr() as usize, data.as_ptr() as usize + data.len());
        if start % PAGE != 0 || (start..end).step_by(PAGE).any(|va| frames.get(va).is_none()) {
            sel4::debug_println!("l4h-root: module image at {:#x}: not in whole pages of its boot module, ignored", start);
            return None;
        }
        let rest = end.next_multiple_of(PAGE) - end;
        // Mapped in the root task with the rest of the module's last page.
        let tail = unsafe { core::slice::from_raw_parts(end as *const u8, rest) };
        if tail.iter().any(|&b| b != 0) {
            // Another module there would be lost, or leak to every guest.
            let there = modules.iter().any(|m| {
                let p = m.data.as_ptr() as usize;
                p < end + rest && end < p + m.data.len()
            });
            if there {
                sel4::debug_println!("l4h-root: module image at {:#x} shares its last page, ignored", start);
                return None;
            }
            let last = frames.get(end & !(PAGE - 1)).expect("module image frame");
            win.with_frame(&abs(root_cap::<cap_type::Granule>(last)), |p| unsafe {
                core::ptr::write_bytes(p.add(PAGE - rest), 0, rest)
            });
        }
        Some(Self { data, frames })
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
            copy_read_only(from, tmp);
            let frame = root_cap::<cap_type::Granule>(tmp);
            let (vspace, va) = (g.vspace, abi::KMOD_VA as usize + i * PAGE);
            map_frame(&mut g.ctx(alloc), vspace, frame, va, CapRights::read_only(), VmAttributes::DEFAULT);
            keep.absolute_cptr_from_bits_with_depth(i as u64, radix).move_(&abs(frame)).expect("keep module image mapping");
        }
        alloc.slots.free(tmp);
        g.kmod_size = self.data.len();
    }
}
