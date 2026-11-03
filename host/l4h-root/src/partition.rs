//! Multikernel partitions (DESIGN.md §11.4): when l4h-mkshim booted this
//! kernel as one of several on the machine, the `l4h-partition` boot
//! module describes this partition, and root restricts itself to it:
//! only its PCI functions (through ECAM, never the shared 0xcf8 ports),
//! MSIs to its own first CPU, and the machine-global devices (I/O APICs,
//! serial port, RTC, reset, TPM, framebuffer, balloon) only in partition
//! 0, the primary.  The primary also copies what the other kernels print
//! to their console rings to the serial port (`Relay`).
//!
//! Without the module root is the only kernel on the machine.

use core::sync::atomic::{AtomicPtr, Ordering};

use l4h_partition::{CONSOLE_RING_HEADER, Descriptor};
use sel4::{CapRights, VmAttributes};
use sel4::init_thread::slot;

use crate::devmem::{self, DevMem};
use crate::mem::{Alloc, ObjCtx};

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

/// A kernel console ring another partition's kernel prints to.
struct RingReader {
    partition: u32,
    va: usize,
    size: usize,
    tail: u64,
    line: [u8; 160],
    len: usize,
}

/// The primary's copy of the other kernels' consoles to its own.
pub struct Relay {
    rings: [Option<RingReader>; l4h_partition::MAX_PARTITIONS],
}

impl Relay {
    pub fn new(alloc: &mut Alloc, devmem: &mut DevMem) -> Option<Relay> {
        let d = get().filter(|d| d.is_primary() && d.count > 1)?;
        let mut r = Relay { rings: [const { None }; l4h_partition::MAX_PARTITIONS] };
        let region = &crate::layout::PARTITION_RINGS;
        for (k, p) in d.parts().iter().enumerate() {
            if p.console.size == 0 {
                continue;
            }
            let va = region.base + k * l4h_partition::CONSOLE_RING_SIZE as usize;
            if map(alloc, devmem, p.console.paddr as usize, p.console.size as usize, va).is_none() {
                log!("l4h-root: cannot map partition {}'s console ring", k);
                continue;
            }
            r.rings[k] = Some(RingReader { partition: k as u32, va, size: p.console.size as usize, tail: 0, line: [0; 160], len: 0 });
        }
        Some(r)
    }

    /// Print what the other kernels printed since the last call, a line
    /// at a time, each with its partition.
    pub fn drain(&mut self) {
        for r in self.rings.iter_mut().flatten() {
            let head = unsafe { (r.va as *const u64).read_volatile() };
            let cap = (r.size - CONSOLE_RING_HEADER) as u64;
            if head.wrapping_sub(r.tail) > cap {
                sel4::debug_println!("[p{}] ({} bytes lost)", r.partition, head - r.tail - cap);
                r.tail = head - cap;
            }
            while r.tail < head {
                let c = unsafe { ((r.va + CONSOLE_RING_HEADER + (r.tail % cap) as usize) as *const u8).read_volatile() };
                r.tail += 1;
                if c == b'\r' {
                    continue;
                }
                if c == b'\n' || r.len == r.line.len() {
                    let s = core::str::from_utf8(&r.line[..r.len]).unwrap_or("(not text)");
                    sel4::debug_println!("[p{}] {}", r.partition, s);
                    r.len = 0;
                    if c == b'\n' {
                        continue;
                    }
                }
                r.line[r.len] = c;
                r.len += 1;
            }
        }
    }
}
