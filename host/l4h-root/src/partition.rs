//! Multikernel partitions (DESIGN.md §11.4): when l4h-mkshim booted this
//! kernel as one of several on the machine, the `l4h-partition` boot
//! module describes this partition, and root restricts itself to it:
//! only its PCI functions (through ECAM, never the shared 0xcf8 ports),
//! MSIs to its own first CPU, and the machine-global devices (I/O APICs,
//! serial port, RTC, reset, TPM, framebuffer, balloon) only in partition
//! 0, the primary.  What other partitions print, their kernels included,
//! reaches the serial port through rings the primary's logd reads (`Rings`).
//!
//! Without the module root is the only kernel on the machine.

use core::ops::Range;
use core::sync::atomic::{AtomicPtr, Ordering};

use l4h_host::serial;
use l4h_partition::{Descriptor, MAX_PARTITIONS, Ring};
use sel4::{CapRights, VmAttributes};
use sel4::init_thread::slot;

use crate::devmem::{self, DevMem};
use crate::mem::{Alloc, ObjCtx, Slot};

static DESC: AtomicPtr<Descriptor> = AtomicPtr::new(core::ptr::null_mut());

/// Take the descriptor from the boot module, if there is one.
pub fn init(module: Option<&'static [u8]>) {
    let Some(m) = module else { return };
    match Descriptor::from_bytes(m) {
        Some(d) => {
            DESC.store(d as *const Descriptor as *mut Descriptor, Ordering::Relaxed);
            log!(
                "l4h-root: partition {} of {} ({}), {} PCI function(s), first CPU APIC ID {}",
                d.index, d.count, if d.is_primary() { "primary" } else { "secondary" }, d.nfuncs, d.boot_apic
            );
        }
        None => panic!("l4h-partition: not a descriptor this build understands"),
    }
}

pub fn get() -> Option<&'static Descriptor> {
    let p = DESC.load(Ordering::Relaxed);
    // Set once at boot, to a module mapped for good.
    unsafe { p.as_ref() }
}

/// One of several partitions, and not partition 0: the machine-global
/// devices are not ours.
pub fn secondary() -> bool {
    get().is_some_and(|d| !d.is_primary())
}

/// The APIC ID MSIs go to: this partition's first CPU, where root runs.
pub fn msi_dest() -> u32 {
    get().map_or(0, |d| d.boot_apic)
}

/// The partition that owns PCI function `bdf`, as far as this partition
/// knows: the primary has the whole table, a secondary only its own.
pub fn owner(bdf: u16) -> Option<u32> {
    let d = get()?;
    if d.funcs().iter().any(|f| f.bdf == bdf) {
        return Some(d.index);
    }
    d.owners().iter().find(|o| o.bdf == bdf).map(|o| o.partition as u32)
}

/// Whether this partition sets up the IOMMU entry of requester `bdf`: its
/// own functions, and for the primary every ID no other partition owns
/// (unassigned IDs, I/O APICs, firmware's).
pub fn iommu_mine(bdf: u16) -> bool {
    match get() {
        None => true,
        Some(d) if d.is_primary() => owner(bdf).is_none_or(|p| p == d.index),
        Some(d) => d.funcs().iter().any(|f| f.bdf == bdf),
    }
}

/// In partition 0: whether another partition has a function that reaches
/// the IOMMU as requester `req` (`alias` gives a function's requester).
/// That requester's domain is the other partition's, even when partition
/// 0 has a bridge behind the same aliasing bridge (bridges are always
/// partition 0's, and the shim gives every function below an aliasing
/// bridge to one partition).
pub fn foreign_requester(req: u16, alias: impl Fn(u16) -> u16) -> bool {
    get().filter(|d| d.is_primary())
        .is_some_and(|d| d.owners().iter().any(|o| o.partition as u32 != d.index && alias(o.bdf) == req))
}

/// The wall clock at boot from the shim's reading, advanced to now.
pub fn epoch_ns(tsc_hz: u64) -> u64 {
    let Some(d) = get() else { return 0 };
    if d.epoch_ns == 0 || tsc_hz == 0 {
        return 0;
    }
    let ticks = l4h_host::ticks::now().saturating_sub(d.epoch_tsc);
    d.epoch_ns + (ticks as u128 * 1_000_000_000 / tsc_hz as u128) as u64
}

/// Map [paddr, paddr + len) (memory every partition's map reserves) at
/// `va` in root, read-write and cached.
pub fn map(alloc: &mut Alloc, devmem: &mut DevMem, paddr: usize, len: usize, va: usize) -> Option<()> {
    map_rights(alloc, devmem, paddr, len, va, CapRights::read_write())
}

/// `map` with the given rights.
pub fn map_rights(alloc: &mut Alloc, devmem: &mut DevMem, paddr: usize, len: usize, va: usize, rights: CapRights) -> Option<()> {
    let mut done = 0;
    while done < len {
        let at = paddr + done;
        let mut chunk = 1usize << at.trailing_zeros().min(30);
        while chunk > len - done {
            chunk >>= 1;
        }
        let chunk = chunk.max(4096);
        let frames = alloc.slots.global(|slots| devmem.frames(slots, at, chunk))?;
        alloc.global(|alloc| {
            for (i, s) in frames.enumerate() {
                crate::vspace::map_frame(&mut ObjCtx::global(alloc), slot::VSPACE.cap(), devmem::granule(s),
                    va + done + i * 4096, rights.clone(), VmAttributes::DEFAULT);
            }
        });
        done += chunk;
    }
    Some(())
}

/// The rings partition 0 reads of the other partitions, as frames in
/// consecutive root slots.
pub struct Rings {
    serial: [Option<Range<Slot>>; MAX_PARTITIONS],
    kernel: [Option<Range<Slot>>; MAX_PARTITIONS],
}

impl Rings {
    /// Map them: root reads them when logd cannot.
    pub fn new(alloc: &mut Alloc, devmem: &mut DevMem) -> Rings {
        const NONE: Option<Range<Slot>> = None;
        let mut r = Rings { serial: [NONE; MAX_PARTITIONS], kernel: [NONE; MAX_PARTITIONS] };
        let Some(d) = get().filter(|d| d.is_primary() && d.count > 1) else { return r };
        for (k, p) in d.parts().iter().enumerate() {
            if p.serial.size != 0 {
                r.serial[k] = map_ring(alloc, devmem, p.serial, crate::layout::PARTITION_SERIAL.base + k * serial::PAGES * 4096);
                if r.serial[k].is_none() {
                    log!("l4h-root: cannot map partition {}'s serial ring", k);
                }
            }
            if p.console.size != 0 {
                r.kernel[k] = map_ring(alloc, devmem, p.console, crate::layout::PARTITION_CONSOLES.base + k * serial::KERNEL_RING_STRIDE);
                if r.kernel[k].is_none() {
                    log!("l4h-root: cannot map partition {}'s console ring", k);
                }
            }
        }
        r
    }

    pub fn serial(&self, k: usize) -> Option<Range<Slot>> {
        self.serial[k].clone()
    }

    pub fn kernel(&self, k: usize) -> Option<Range<Slot>> {
        self.kernel[k].clone()
    }

    pub fn serial_mask(&self) -> u32 {
        (0..MAX_PARTITIONS).filter(|&k| self.serial[k].is_some()).fold(0, |m, k| m | 1 << k)
    }

    pub fn kernel_mask(&self) -> u32 {
        (0..MAX_PARTITIONS).filter(|&k| self.kernel[k].is_some()).fold(0, |m, k| m | 1 << k)
    }
}

fn map_ring(alloc: &mut Alloc, devmem: &mut DevMem, ring: Ring, va: usize) -> Option<Range<Slot>> {
    let frames = alloc.slots.global(|slots| devmem.frames(slots, ring.paddr as usize, ring.size as usize))?;
    alloc.global(|alloc| {
        for (i, s) in frames.clone().enumerate() {
            let copy = alloc.slots.alloc();
            let f = devmem::granule(copy);
            crate::component::abs_of(f).copy(&crate::component::abs_of(devmem::granule(s)), CapRights::all()).expect("ring frame");
            crate::vspace::map_frame(&mut ObjCtx::global(alloc), slot::VSPACE.cap(), f, va + i * 4096,
                CapRights::read_write(), VmAttributes::DEFAULT);
        }
    });
    Some(frames)
}

/// In a secondary partition: print to the ring partition 0 reads from now
/// on, with what `early` holds, and return its frames.
pub fn serial_ring(alloc: &mut Alloc, devmem: &mut DevMem, early: &'static serial::Ring) -> Option<Range<Slot>> {
    let d = get().filter(|d| !d.is_primary() && d.serial.size != 0)?;
    let frames = map_ring(alloc, devmem, d.serial, crate::layout::SERIAL.base)?;
    // Mapped for good, and the shim cleared it.
    let ring = unsafe { &*(crate::layout::SERIAL.base as *const serial::Ring) };
    early.copy_to(ring);
    serial::init(ring, 0);
    Some(frames)
}
