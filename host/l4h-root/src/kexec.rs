//! Host kexec loading. dom0 streams the EFI and optional ESP files through
//! the control data area. Each byte is copied once into private source
//! frames; a final commit parses that view and builds the physical handoff.

mod grub;
mod image;
mod kernel;
mod log;
mod mbi;
mod pe;
mod stage;

use core::ops::Range;

use l4h_host::fixed::ArrayVec;
use sel4::CapRights;
use sha2::{Digest, Sha256};

use crate::component::abs_of;
use crate::mem::{Alloc, Arena, Dest, ObjCtx, UtRegion};
use crate::vspace::{LARGE_PAGE_BP, map_large_page};
use crate::{Host, ctl};

pub const COMMIT: u64 = 3;

const PAGE: usize = 4096;
const BLOCK_BITS: usize = 21;
const BLOCK: usize = 1 << BLOCK_BITS;
const MAX_EFI: usize = 64 << 20;
const MAX_INITRD: usize = 64 << 20;
const MAX_CONFIG: usize = 1 << 20;
const FILE_STRIDE: usize = 64 << 20;
const MAX_FILE_BLOCKS: usize = MAX_EFI / BLOCK;
const MAX_BLOCKS: usize = 80;
const LOW_DEST: Range<usize> = (1 << 20)..(16 << 20);
/// Source blocks: every 2 MiB block below LOW_DEST.end overlaps the fixed
/// seL4 destinations.
const SOURCES: Range<usize> = LOW_DEST.end..usize::MAX;

pub struct SourceBlock {
    pub file: u64,
    pub offset: usize,
    pub paddr: usize,
}

#[derive(Clone)]
struct PeDigest {
    layout: pe::PeLayout,
    hash: Sha256,
    cursor: pe::RangeCursor,
}

impl PeDigest {
    fn new(layout: pe::PeLayout) -> Self {
        Self { layout, hash: Sha256::new(), cursor: pe::RangeCursor::default() }
    }

    fn update(&mut self, data: &[u8]) {
        let hash = &mut self.hash;
        self.layout.stream(&mut self.cursor, data, |chunk| hash.update(chunk));
    }

    fn finalize(self) -> [u8; 32] {
        self.hash.finalize().into()
    }
}

struct LoadFile {
    total: usize,
    received: usize,
    /// Blocks of `regions` mapped as one 2 MiB frame each, in `frame_slots`.
    mapped: usize,
    frame_slots: Range<usize>,
    regions: ArrayVec<UtRegion, MAX_FILE_BLOCKS>,
}

impl LoadFile {
    fn va(file: usize) -> usize {
        crate::layout::KEXEC_LOAD.base + file * FILE_STRIDE
    }

    fn data(&self, file: usize) -> &[u8] {
        assert_eq!(self.received, self.total);
        unsafe { core::slice::from_raw_parts(Self::va(file) as *const u8, self.total) }
    }

    fn frame(&self, block: usize) -> sel4::cap::LargePage {
        sel4::init_thread::Slot::<sel4::cap_type::LargePage>::from_index(self.frame_slots.start + block).cap()
    }

    fn unmap(&mut self, alloc: &mut Alloc) {
        for block in 0..self.mapped {
            let frame = self.frame(block);
            frame.frame_unmap().expect("kexec source unmap");
            abs_of(frame).delete().expect("kexec source delete");
        }
        for slot in self.frame_slots.clone() {
            alloc.slots.free(slot);
        }
        self.frame_slots = 0..0;
        self.mapped = 0;
    }
}

pub struct Loading {
    files: [Option<LoadFile>; 3],
    next: usize,
    extra: Arena,
    pe: Option<PeDigest>,
    pe_error: bool,
    initrd_hash: Option<Sha256>,
    config_hash: Option<Sha256>,
}

impl Loading {
    fn new() -> Self {
        Self {
            files: [None, None, None],
            next: 0,
            extra: Arena::new(),
            pe: None,
            pe_error: false,
            initrd_hash: None,
            config_hash: None,
        }
    }

    fn source_blocks(&self) -> Result<ArrayVec<SourceBlock, MAX_BLOCKS>, i64> {
        let mut blocks = ArrayVec::new();
        for (file, load) in self.files.iter().enumerate() {
            let Some(load) = load else { continue };
            for (i, region) in load.regions.iter().enumerate() {
                blocks
                    .push(SourceBlock {
                        file: file as u64,
                        offset: i * BLOCK,
                        paddr: region.paddr,
                    })
                    .map_err(|_| ctl::ENOMEM)?;
            }
        }
        Ok(blocks)
    }

    fn into_arena(self) -> Arena {
        let Loading {
            mut files,
            mut extra,
            ..
        } = self;
        let mut arena = Arena::new();
        for load in files.iter_mut().flatten() {
            while let Some(region) = load.regions.pop() {
                arena_push(&mut arena, region).unwrap_or_else(|_| panic!("kexec arena capacity"));
            }
        }
        while let Some(region) = extra.pool.regions.pop() {
            arena_push(&mut arena, region).unwrap_or_else(|_| panic!("kexec arena capacity"));
        }
        arena
    }
}

pub struct Staged {
    pub arena: Arena,
    pub control: u64,
    pub event_digest: [u8; 32],
}

pub struct Kexec {
    boot: Result<mbi::BootTags, &'static str>,
    staged: Option<Staged>,
    loading: Option<Loading>,
    previous_log: &'static [u8],
}

impl Kexec {
    pub fn new(bootinfo: &sel4::BootInfoPtr, previous_log: &'static [u8]) -> Self {
        let boot = (|| {
            let map = mbi::FirmwareMap::parse(
                crate::bootmod::extra_chunk(bootinfo, sel4::sys::seL4_BootInfoID::SEL4_BOOTINFO_HEADER_X86_MBMMAP as u64)
                    .ok_or("no firmware memory map in bootinfo")?,
            )?;
            let framebuffer = match crate::bootmod::extra_chunk(bootinfo, sel4::sys::seL4_BootInfoID::SEL4_BOOTINFO_HEADER_X86_FRAMEBUFFER as u64) {
                None => None,
                Some(content) if content.len() == 22 || content.len() == 24 => {
                    Some(content[..22].try_into().unwrap())
                }
                Some(_) => return Err("bad framebuffer bootinfo"),
            };
            let acpi = match crate::bootmod::extra_chunk(bootinfo, sel4::sys::seL4_BootInfoID::SEL4_BOOTINFO_HEADER_X86_ACPI_RSDP as u64) {
                None => None,
                Some(content) if content.len() == 20 || content.len() == 36 => {
                    let len = if content[15] == 0 { 20 } else { 36 };
                    if content.len() < len {
                        return Err("short ACPI RSDP in bootinfo");
                    }
                    let mut bytes = [0; 36];
                    bytes[..len].copy_from_slice(&content[..len]);
                    Some((bytes, len))
                }
                Some(_) => return Err("bad ACPI RSDP bootinfo"),
            };
            Ok(mbi::BootTags {
                map,
                framebuffer,
                acpi,
            })
        })();
        Self {
            boot,
            staged: None,
            loading: None,
            previous_log,
        }
    }
}

fn io(what: &'static str) -> i64 {
    log!("l4h-root: kexec LOAD: {}", what);
    ctl::EIO
}

/// Allocate a block in the physical `window`.
fn alloc_block(alloc: &mut Alloc, window: Range<usize>) -> Result<UtRegion, i64> {
    let slot = alloc.slots.try_alloc_range(1).ok_or(ctl::ENOMEM)?.start;
    let Some(region) = alloc.split_in(BLOCK_BITS, slot, window) else {
        alloc.slots.free(slot);
        return Err(ctl::ENOMEM);
    };
    Ok(region)
}

fn arena_push(arena: &mut Arena, region: UtRegion) -> Result<(), i64> {
    arena.own(region.cap.bits() as usize, region.paddr, region.size_bits);
    arena.pool.add(region).map_err(|_| ctl::ENOMEM)
}

/// Map whole blocks of `file` until its first `end` bytes are mapped.
fn map_blocks(alloc: &mut Alloc, load: &mut Loading, file: usize, end: usize) -> Result<(), i64> {
    let f = load.files[file].as_mut().ok_or(ctl::EINVAL)?;
    while f.mapped * BLOCK < end {
        let block = f.mapped;
        f.regions.must_push(alloc_block(alloc, SOURCES)?);
        let region = &mut f.regions[block];
        let paddr = region
            .retype(&LARGE_PAGE_BP, 1, Dest::new(crate::slot::CNODE.cap(), f.frame_slots.start + block))
            .ok_or(ctl::ENOMEM)?;
        if paddr != region.paddr {
            abs_of(f.frame(block)).delete().expect("delete bad kexec source frame");
            return Err(io("source frame address mismatch"));
        }
        map_large_page(&mut ObjCtx::global(alloc), sel4::init_thread::slot::VSPACE.cap(), f.frame(block),
            LoadFile::va(file) + block * BLOCK, CapRights::read_write());
        f.mapped += 1;
    }
    Ok(())
}

fn begin_file(h: &mut Host, file: usize, total: usize) -> Result<(), i64> {
    let max = [MAX_EFI, MAX_INITRD, MAX_CONFIG][file];
    if total == 0 || total > max {
        return Err(ctl::EINVAL);
    }
    if h.kexec.loading.is_none() {
        if file != 0 {
            return Err(ctl::EINVAL);
        }
        h.kexec.loading = Some(Loading::new());
    }
    let loading = h.kexec.loading.as_mut().unwrap();
    if file < loading.next
        || loading.files[..file]
            .iter()
            .flatten()
            .any(|f| f.received != f.total)
    {
        return Err(ctl::EINVAL);
    }
    let slots = h.alloc.slots.try_alloc_range(total.div_ceil(BLOCK)).ok_or(ctl::ENOMEM)?;
    loading.files[file] = Some(LoadFile {
        total,
        received: 0,
        mapped: 0,
        frame_slots: slots,
        regions: ArrayVec::new(),
    });
    loading.next = file;
    match file {
        0 => {
            loading.pe = None;
            loading.pe_error = false;
        }
        1 => loading.initrd_hash = Some(Sha256::new()),
        2 => loading.config_hash = Some(Sha256::new()),
        _ => unreachable!(),
    }
    Ok(())
}

fn chunk(h: &mut Host, args: &[u64; 6]) -> Result<(), i64> {
    let file = usize::try_from(args[0]).map_err(|_| ctl::EINVAL)?;
    if file >= 3 {
        return Err(ctl::EINVAL);
    }
    let offset = usize::try_from(args[1]).map_err(|_| ctl::EINVAL)?;
    let total = usize::try_from(args[2]).map_err(|_| ctl::EINVAL)?;
    let len = usize::try_from(args[3]).map_err(|_| ctl::EINVAL)?;
    if args[4] != 0
        || args[5] != 0
        || len == 0
        || len > abi_load_max()
        || offset.checked_add(len).is_none_or(|end| end > total)
    {
        return Err(ctl::EINVAL);
    }
    if file == 0 && offset == 0 {
        // A new stream also abandons an interrupted earlier transaction.
        abort(h);
    }
    if offset == 0
        && h.kexec
            .loading
            .as_ref()
            .is_none_or(|l| l.files[file].is_none())
    {
        begin_file(h, file, total)?;
    }
    let from = crate::vmmgr::CTL_DATA_VA as *const u8;
    let loading = h.kexec.loading.as_mut().ok_or(ctl::EINVAL)?;
    if file != loading.next {
        return Err(ctl::EINVAL);
    }
    let f = loading.files[file].as_ref().ok_or(ctl::EINVAL)?;
    if f.total != total || f.received != offset {
        return Err(ctl::EINVAL);
    }
    let end = offset + len;
    map_blocks(&mut h.alloc, loading, file, end)?;
    unsafe { core::ptr::copy_nonoverlapping(from, (LoadFile::va(file) + offset) as *mut u8, len) };
    let f = loading.files[file].as_mut().unwrap();
    f.received = end;
    let data = unsafe { core::slice::from_raw_parts(LoadFile::va(file) as *const u8, end) };
    if file == 0 {
        if loading.pe.is_none() && !loading.pe_error {
            match pe::Pe::parse_layout(data, total) {
                Ok(layout) => loading.pe = Some(PeDigest::new(layout)),
                Err(pe::PeLayoutError::Incomplete) => {}
                Err(pe::PeLayoutError::Invalid) => loading.pe_error = true,
            }
        }
        if let Some(pe) = &mut loading.pe {
            pe.update(data);
        }
    } else {
        let hash = if file == 1 { &mut loading.initrd_hash } else { &mut loading.config_hash };
        if let Some(hash) = hash {
            hash.update(&data[offset..end]);
        }
    }
    if end == total {
        loading.next += 1;
    }
    Ok(())
}

const fn abi_load_max() -> usize {
    l4h_abi::CTL_LOAD_MAX as usize
}

fn abort(h: &mut Host) {
    let Some(mut loading) = h.kexec.loading.take() else {
        return;
    };
    for load in loading.files.iter_mut().flatten() {
        load.unmap(&mut h.alloc);
    }
    h.alloc.release(loading.into_arena());
}

/// CTL_HOST_KEXEC_LOAD. The three files are streamed in order (the optional
/// ones may be omitted), then file 3 commits. Any error other than EAGAIN
/// aborts only the new transaction; the previously committed image stays
/// available, and EXEC discards an incomplete transaction before continuing.
pub fn load(h: &mut Host, args: &[u64; 6]) -> Result<(), i64> {
    let result = if args[0] == COMMIT {
        if args[1..].iter().any(|&a| a != 0) {
            Err(ctl::EINVAL)
        } else {
            commit(h)
        }
    } else {
        chunk(h, args)
    };
    if result.is_err_and(|e| e != ctl::EAGAIN) {
        abort(h);
    }
    result
}

fn commit(h: &mut Host) -> Result<(), i64> {
    let boot = h.kexec.boot.clone().map_err(|e| {
        log!("l4h-root: kexec: {}", e);
        ctl::EINVAL
    })?;
    let mut loading = h.kexec.loading.take().ok_or(ctl::EINVAL)?;
    let result = stage::commit(h, &mut loading, boot);
    match result {
        Ok(staged) => {
            if let Some(old) = h.kexec.staged.replace(staged) {
                h.alloc.release(old.arena);
            }
            Ok(())
        }
        Err(e) => {
            h.kexec.loading = Some(loading);
            Err(e)
        }
    }
}

pub fn preflight(h: &mut Host) -> Result<(), i64> {
    if h.kexec.loading.is_some() {
        abort(h);
    }
    if h.kexec.staged.is_none() {
        return Err(ctl::ENOENT);
    }
    // EXEC must not destroy guests while trustd is still initializing, or
    // without trustd to tell whether there is a TPM to measure with.
    h.trustd.as_ref().ok_or(ctl::ENODEV)?.kexec_key()?;
    Ok(())
}

/// Hand off to the staged image: returns only when none is staged.
pub fn exec(h: &mut Host) -> Result<(), i64> {
    if h.kexec.loading.is_some() {
        abort(h);
    }
    let staged = h.kexec.staged.as_ref().ok_or(ctl::ENOENT)?;
    stage::exec(h, staged.control)
}

/// vmmgr calls this if guest teardown fails after destruction has started.
pub fn fail(h: &mut Host) -> ! {
    stage::exec_failed(h, "guest teardown failed")
}
