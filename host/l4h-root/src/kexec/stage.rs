//! Turn a complete loading transaction into physical copy runs, an MBI and
//! the control pages consumed by seL4_X86_Kexec.

use core::ops::Range;

use l4h_host::fixed::ArrayVec;
use sel4::VmAttributes;
use sha2::{Digest, Sha256};

use super::image::Image;
use super::log::Event;
use super::kernel::{VARIANT_PCID, VARIANT_X2APIC};
use super::mbi::{BootTags, MbiBuilder, Module};
use super::{
    BLOCK, Loading, MAX_BLOCKS, PAGE, SOURCES, SourceBlock, Staged, alloc_block, arena_push, io,
};
use crate::component::abs_of;
use crate::mem::{Arena, Dest};
use crate::{Host, ctl};

const MAX_LOADS: usize = 16;

/// A physical copy run, or a zero fill when `src` is u64::MAX.
#[repr(C)]
#[derive(Clone, Copy)]
struct Run {
    src: u64,
    dst: u64,
    len: u64,
}
const _: () = assert!(core::mem::size_of::<Run>() == 24 && cfg!(target_endian = "little"));
const MAX_MODULES: usize = 6;
const MAX_RUNS: usize = 512;
const MAX_RANGE_POINTS: usize = 2 * MAX_BLOCKS + 2 * MAX_MODULES + 1;
const MAX_REGIONS: usize = MAX_RANGE_POINTS;
const MAX_BLOCK_PAGES: usize = BLOCK / PAGE;
const CONTROL_VERSION: u64 = 1;
const LOW4G: u64 = 1 << 32;

#[derive(Clone, Copy)]
struct KernelPart {
    file_offset: usize,
    file_size: usize,
    memory_size: usize,
    destination: u64,
}

#[derive(Clone, Copy)]
struct ModulePlan {
    file: u64,
    file_offset: usize,
    size: usize,
    destination: u64,
    command: &'static [u8],
}

struct Prepared {
    entry: u64,
    kernel: ArrayVec<KernelPart, MAX_LOADS>,
    modules: ArrayVec<ModulePlan, MAX_MODULES>,
    command: ArrayVec<u8, 96>,
    /// The bytes of the root task's image as seL4 loads it.
    root_span: u64,
    /// The measured event; commit fills in the key and control block.
    event: Event,
}

fn invalid(error: &'static str) -> i64 {
    log!("l4h-root: kexec LOAD: {}", error);
    ctl::EINVAL
}

fn prepare(loading: &mut Loading, map: &super::mbi::FirmwareMap) -> Result<Prepared, i64> {
    if loading.files[0]
        .as_ref()
        .is_none_or(|f| f.received != f.total)
        || loading.files[1..]
            .iter()
            .flatten()
            .any(|f| f.received != f.total)
    {
        return Err(invalid("incomplete file set"));
    }
    // The complete EFI resolved its PE prefix, one way or the other. The
    // streamed states stay in `loading` for a commit retried on EAGAIN.
    let authenticode = match &loading.pe {
        Some(pe) if !loading.pe_error => pe.clone().finalize(),
        _ => return Err(invalid("bad PE prefix")),
    };
    let digest = |state: &Option<Sha256>| state.clone().unwrap_or_default().finalize().into();
    let (initrd_digest, config_digest) = (digest(&loading.initrd_hash), digest(&loading.config_hash));
    let efi = loading.files[0].as_ref().unwrap().data(0);
    let initrd = loading.files[1].as_ref().map(|f| f.data(1));
    let config = loading.files[2].as_ref().map(|f| f.data(2));
    let image = Image::parse(efi).map_err(invalid)?;
    let running = if sel4::sel4_cfg_bool!(X2APIC) {
        VARIANT_X2APIC
    } else {
        0
    } | if sel4::sel4_cfg_bool!(SUPPORT_PCID) {
        VARIANT_PCID
    } else {
        0
    };
    if image.kernel.variant != Some(running) {
        return Err(invalid(
            "kernel APIC/PCID variant differs or has no l4h note",
        ));
    }
    let overrides = crate::config::kexec_overrides(config).map_err(invalid)?;
    let serial = match overrides.serial_port {
        Some(port) => super::grub::SerialPort::parse(port).map_err(invalid)?,
        None => image.grub.serial_port,
    };
    let fb_console = match overrides.fb_console {
        Some("0") => false,
        Some("1") => true,
        Some(_) => return Err(invalid("bad fb_console in l4h.conf")),
        None => image.grub.fb_console,
    };
    let mut command = ArrayVec::new();
    for part in [
        &b"console_port="[..],
        serial.text(),
        b" debug_port=",
        serial.text(),
        if fb_console { b" fb_console" } else { b"" },
    ] {
        command
            .extend_from_slice(part)
            .map_err(|_| invalid("seL4 command line is too long"))?;
    }

    let pe_base = efi.as_ptr() as usize;
    let offset = |data: &[u8]| -> Result<usize, i64> {
        let at = data.as_ptr() as usize;
        if at < pe_base || at - pe_base > efi.len() || data.len() > efi.len() - (at - pe_base) {
            Err(io("module is outside its staged EFI"))
        } else {
            Ok(at - pe_base)
        }
    };
    let mut kernel_parts = ArrayVec::new();
    for segment in image.kernel.loads() {
        if !map.covers_boot_ram(segment.physical..segment.physical + segment.memory_size) {
            return Err(invalid("seL4 load segment is not in firmware RAM"));
        }
        kernel_parts
            .push(KernelPart {
                file_offset: offset(segment.data)?,
                file_size: segment.data.len(),
                memory_size: segment.memory_size as usize,
                destination: segment.physical,
            })
            .map_err(|_| invalid("too many kernel segments"))?;
    }
    let mut modules = ArrayVec::new();
    let mut add_module = |file, data: &[u8], command| -> Result<(), i64> {
        let file_offset = if file == 0 { offset(data)? } else { 0 };
        modules
            .push(ModulePlan {
                file,
                file_offset,
                size: data.len(),
                destination: 0,
                command,
            })
            .map_err(|_| ctl::ENOMEM)
    };
    add_module(0, image.root, b"(memdisk)/boot/l4h-root.elf")?;
    add_module(
        0,
        image.guest_kernel,
        b"(memdisk)/boot/vmlinux guest-kernel",
    )?;
    if let Some(data) = image.guest_kmods {
        add_module(0, data, b"(memdisk)/boot/kmods.erofs guest-kmods")?;
    }
    if let Some(data) = initrd {
        add_module(1, data, b"/l4h/dom0/initrd dom0-initrd")?;
    }
    if let Some(data) = config {
        add_module(2, data, b"/l4h/l4h.conf l4h-config")?;
    }
    // The seL4 command line, then each module's, length-prefixed.
    let mut strings = Sha256::new();
    for line in core::iter::once(&command[..]).chain(modules.iter().map(|m| m.command)) {
        strings.update((line.len() as u32).to_le_bytes());
        strings.update(line);
    }
    let boot_strings: [u8; 32] = strings.finalize().into();
    let flags = (if initrd.is_some() { super::log::FLAG_INITRD } else { 0 })
        | (if config.is_some() { super::log::FLAG_CONFIG } else { 0 });
    Ok(Prepared {
        entry: image.kernel.entry,
        kernel: kernel_parts,
        modules,
        command,
        root_span: super::kernel::image_span(image.root).map_err(invalid)?,
        event: Event {
            previous_key: [0; 32],
            authenticode,
            initrd: initrd_digest,
            config: config_digest,
            boot_strings,
            flags,
            control: 0,
        },
    })
}

fn align_page(value: u64) -> u64 {
    value.next_multiple_of(PAGE as u64)
}

/// Where the next seL4's find_load_paddr puts `size` bytes at or above
/// `min`: the first RAM entry, as seL4 reads `map`, with room below 4 GiB.
fn find_load_paddr(map: &super::mbi::FirmwareMap, min: u64, size: u64) -> Option<u64> {
    map.usable()
        .filter(|e| e.base >= 1 << 20 && e.length >= PAGE as u64)
        .find_map(|e| {
            let start = align_page(min.max(align_page(e.base)));
            let end = ((e.base + e.length) & !(PAGE as u64 - 1)).min(1 << 32);
            (start < end && end - start >= size).then_some(start)
        })
}

fn place_modules(
    modules: &mut [ModulePlan],
    boot: &BootTags,
    reserved: &[Range<u64>],
) -> Result<(), i64> {
    let mut next: u64 = 16 << 20;
    for module in modules {
        if module.size == 0 {
            module.destination = 0;
            continue;
        }
        let reserve = align_page(module.size as u64);
        module.destination = loop {
            if reserve == 0 || next.checked_add(reserve).is_none_or(|end| end >= LOW4G) {
                return Err(invalid("no low firmware RAM for the boot modules"));
            }
            let end = next + reserve;
            let Some(ram) = boot
                .map
                .usable()
                .find(|e| e.base <= next && next < e.base + e.length)
            else {
                next = match boot
                    .map
                    .usable()
                    .filter(|e| e.base > next)
                    .map(|e| align_page(e.base))
                    .min()
                {
                    Some(base) => base,
                    None => return Err(invalid("no low firmware RAM for the boot modules")),
                };
                continue;
            };
            if end > ram.base + ram.length {
                next = align_page(ram.base + ram.length);
                continue;
            }
            if let Some(r) = reserved.iter().find(|r| next < r.end && r.start < end) {
                next = align_page(r.end);
                continue;
            }
            if let Some(r) = boot.map.entries[..boot.map.count]
                .iter()
                .find(|e| e.kind != 1 && next < e.base + e.length && e.base < end)
            {
                next = align_page(r.base + r.length);
                continue;
            }
            break next;
        };
        next = module.destination + reserve;
    }
    Ok(())
}

fn add_file_runs(
    runs: &mut ArrayVec<Run, MAX_RUNS>,
    sources: &[SourceBlock],
    file: u64,
    offset: usize,
    destination: u64,
    len: usize,
) -> Result<(), i64> {
    let mut done = 0;
    while done < len {
        let at = offset + done;
        let block = sources
            .iter()
            .find(|b| b.file == file && b.offset <= at && at < b.offset + BLOCK)
            .ok_or_else(|| io("file run has no source block"))?;
        let within = at - block.offset;
        let n = (len - done).min(BLOCK - within);
        runs.push(Run {
            src: (block.paddr + within) as u64,
            dst: destination + done as u64,
            len: n as u64,
        })
        .map_err(|_| ctl::ENOMEM)?;
        done += n;
    }
    Ok(())
}

/// Write pages from the start of the arena's block at `paddr`. The frame
/// capabilities are dropped afterwards, whether or not `f` succeeds.
fn with_block(
    h: &mut Host,
    arena: &mut Arena,
    paddr: usize,
    f: impl FnOnce(&mut BlockBuilder) -> Result<(), i64>,
) -> Result<(), i64> {
    let region = arena
        .pool
        .regions
        .iter_mut()
        .find(|r| r.paddr == paddr)
        .ok_or_else(|| io("block missing from arena"))?;
    let mut builder = BlockBuilder { h, region, next: 0, slots: ArrayVec::new() };
    let result = f(&mut builder);
    builder.clear();
    result
}

fn identity_regions(
    reserved: &[Range<u64>],
    modules: &[ModulePlan],
) -> Result<ArrayVec<u64, MAX_REGIONS>, i64> {
    let mut all: ArrayVec<u64, MAX_RANGE_POINTS> = ArrayVec::new();
    all.push(0).map_err(|_| ctl::ENOMEM)?;
    for range in reserved {
        all.push(range.start >> 30).map_err(|_| ctl::ENOMEM)?;
        all.push((range.end - 1) >> 30).map_err(|_| ctl::ENOMEM)?;
    }
    for module in modules {
        if module.size == 0 {
            continue;
        }
        let end = module.destination + align_page(module.size as u64);
        all.push(module.destination >> 30)
            .map_err(|_| ctl::ENOMEM)?;
        all.push((end - 1) >> 30).map_err(|_| ctl::ENOMEM)?;
    }
    all.sort_unstable();
    let mut unique: ArrayVec<u64, MAX_REGIONS> = ArrayVec::new();
    for &region in &all {
        if unique.last() != Some(&region) {
            unique.push(region).map_err(|_| ctl::ENOMEM)?;
        }
    }
    Ok(unique)
}

struct BlockBuilder<'a> {
    h: &'a mut Host,
    region: &'a mut crate::mem::UtRegion,
    next: usize,
    /// Every page stays alive until the whole block is built.
    slots: ArrayVec<usize, MAX_BLOCK_PAGES>,
}

impl BlockBuilder<'_> {
    fn clear(&mut self) {
        while let Some(slot) = self.slots.pop() {
            let frame = crate::devmem::granule(slot);
            let _ = abs_of(frame).delete();
            self.h.alloc.slots.free(slot);
        }
    }

    /// The next page: `bytes`, then zeros.
    fn page(&mut self, bytes: &[u8]) -> Result<(), i64> {
        if bytes.len() > PAGE {
            return Err(io("oversized block page"));
        }
        if self.slots.is_full() {
            return Err(ctl::ENOMEM);
        }
        let paddr = self.region.paddr + self.next * PAGE;
        let slot = self
            .h
            .alloc
            .slots
            .try_alloc_range(1)
            .ok_or(ctl::ENOMEM)?
            .start;
        self.slots.must_push(slot);
        let at = self
            .region
            .retype(&crate::vspace::FRAME_BP, 1, Dest::new(crate::slot::CNODE.cap(), slot))
            .ok_or(ctl::ENOMEM)?;
        if at != paddr {
            return Err(io("block frame address mismatch"));
        }
        let frame = crate::devmem::granule(slot);
        self.h
            .wins
            .a
            .with_frame_attrs(&abs_of(frame), VmAttributes::DEFAULT, |p| unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
                core::ptr::write_bytes(p.add(bytes.len()), 0, PAGE - bytes.len());
            });
        self.next += 1;
        Ok(())
    }

    /// The next pages: `data`, then zeros to a page boundary; at least one.
    fn bytes(&mut self, data: &[u8]) -> Result<(), i64> {
        if data.is_empty() {
            return self.page(&[]);
        }
        data.chunks(PAGE).try_for_each(|chunk| self.page(chunk))
    }
}

fn put64(page: &mut [u8; PAGE], offset: usize, value: u64) {
    page[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

unsafe extern "C" {
    #[link_name = "seL4_X86_KexecTrampoline"]
    static TRAMPOLINE: u8;
    #[link_name = "seL4_X86_KexecTrampolineEnd"]
    static TRAMPOLINE_END: u8;
    #[link_name = "seL4_X86_KexecPark"]
    static PARK: u8;
    #[link_name = "seL4_X86_KexecParkEnd"]
    static PARK_END: u8;
}

unsafe fn blob<'a>(start: &'a u8, end: &'a u8) -> &'a [u8] {
    unsafe {
        core::slice::from_raw_parts(
            start,
            (end as *const u8 as usize) - (start as *const u8 as usize),
        )
    }
}

fn build_control(
    h: &mut Host,
    arena: &mut Arena,
    control: usize,
    entry: u64,
    mbi: &[u8],
    runs: &[Run],
    regions: &[u64],
) -> Result<(), i64> {
    let mut groups: ArrayVec<u64, MAX_REGIONS> = ArrayVec::new();
    for group in regions.iter().map(|r| r >> 9) {
        if groups.last() != Some(&group) {
            groups.push(group).map_err(|_| ctl::ENOMEM)?;
        }
    }
    if groups.iter().any(|&g| g >= 256) {
        return Err(invalid("physical source cannot be identity mapped"));
    }
    let segment_pages = (runs.len() * 24).max(1).div_ceil(PAGE);
    let segments_at = 5;
    let mbi_at = segments_at + segment_pages;
    let pdpt_at = mbi_at + 1;
    let pd_at = pdpt_at + groups.len();
    if pd_at + regions.len() > BLOCK / PAGE {
        return Err(ctl::ENOMEM);
    }
    let pml4 = (control + PAGE) as u64;
    let trampoline = (control + 2 * PAGE) as u64;
    let parking = (control + 3 * PAGE) as u64;
    let stack = (control + 4 * PAGE) as u64;
    let segments = (control + segments_at * PAGE) as u64;
    let mbi_paddr = (control + mbi_at * PAGE) as u64;
    let mut control_page = [0; PAGE];
    for (offset, value) in [
        (0, CONTROL_VERSION),
        (8, pml4),
        (16, trampoline),
        (24, parking),
        (32, stack),
        (40, segments),
        (48, runs.len() as u64),
        (56, entry),
        (64, mbi_paddr),
        (72, 0),
    ] {
        put64(&mut control_page, offset, value);
    }
    let mut pml4_page = [0; PAGE];
    for (i, group) in groups.iter().enumerate() {
        put64(
            &mut pml4_page,
            *group as usize * 8,
            (control + (pdpt_at + i) * PAGE) as u64 | 3,
        );
    }

    // The runs as seL4_X86_KexecSegment_t: three little-endian words each.
    let run_bytes = unsafe { core::slice::from_raw_parts(runs.as_ptr() as *const u8, runs.len() * 24) };
    let (trampoline, parking) = unsafe { (blob(&TRAMPOLINE, &TRAMPOLINE_END), blob(&PARK, &PARK_END)) };
    with_block(h, arena, control, |builder| {
        builder.page(&control_page)?;
        builder.page(&pml4_page)?;
        builder.page(trampoline)?;
        builder.page(parking)?;
        builder.page(&[])?;
        builder.bytes(run_bytes)?;
        builder.page(mbi)?;
        for group in &groups {
            let mut page = [0; PAGE];
            for (j, region) in regions
                .iter()
                .enumerate()
                .filter(|(_, r)| **r >> 9 == *group)
            {
                put64(
                    &mut page,
                    (*region & 511) as usize * 8,
                    (control + (pd_at + j) * PAGE) as u64 | 3,
                );
            }
            builder.page(&page)?;
        }
        for region in regions {
            let mut page = [0; PAGE];
            for i in 0..512 {
                put64(&mut page, i * 8, ((region * 512 + i as u64) << 21) | 0x83);
            }
            builder.page(&page)?;
        }
        if builder.next != pd_at + regions.len() {
            return Err(io("control page count mismatch"));
        }
        Ok(())
    })
}

pub fn commit(h: &mut Host, loading: &mut Loading, boot: BootTags) -> Result<Staged, i64> {
    let previous_key = h.trustd.as_ref().ok_or(ctl::ENODEV)?.kexec_key()?.unwrap_or([0; 32]);
    let mut prepared = prepare(loading, &boot.map)?;
    let mut sources = loading.source_blocks()?;
    let previous_log = h.kexec.previous_log;
    let mut reserved: ArrayVec<Range<u64>, MAX_BLOCKS> = sources
        .iter()
        .map(|b| b.paddr as u64..(b.paddr + BLOCK) as u64)
        .collect();
    let log_region = alloc_block(&mut h.alloc, SOURCES)?;
    let log_paddr = log_region.paddr;
    arena_push(&mut loading.extra, log_region)?;
    reserved
        .push(log_paddr as u64..(log_paddr + BLOCK) as u64)
        .map_err(|_| ctl::ENOMEM)?;
    sources
        .push(SourceBlock {
            file: 3,
            offset: 0,
            paddr: log_paddr,
        })
        .map_err(|_| ctl::ENOMEM)?;
    // The log's size does not depend on the control block's address.
    prepared.event.previous_key = previous_key;
    let log_len = super::log::build(previous_log, &prepared.event).map_err(invalid)?.len();
    prepared
        .modules
        .push(ModulePlan {
            file: 3,
            file_offset: 0,
            size: log_len,
            destination: 0,
            command: b"kexec-log",
        })
        .map_err(|_| ctl::ENOMEM)?;
    place_modules(&mut prepared.modules, &boot, &reserved)?;

    // The next seL4 loads the root task at the first RAM that fits above
    // the last module, then moves it down to the end of its own image
    // without checking the memory map. With RAM right after the modules,
    // both stay below `landing`, and so must stay clear of the control
    // block, where the APs are parked.
    let mods_end = align_page(prepared.modules.iter().map(|m| m.destination + m.size as u64).max().unwrap_or(0));
    let landing = mods_end.checked_add(prepared.root_span).ok_or_else(|| invalid("root task too large"))?;
    let control_region = alloc_block(&mut h.alloc, landing.next_multiple_of(BLOCK as u64) as usize..1 << 32)?;
    let control = control_region.paddr;
    arena_push(&mut loading.extra, control_region)?;
    reserved
        .push(control as u64..(control + BLOCK) as u64)
        .map_err(|_| ctl::ENOMEM)?;
    prepared.event.control = control as u32;
    let log = super::log::build(previous_log, &prepared.event).map_err(invalid)?;
    with_block(h, &mut loading.extra, log_paddr, |b| b.bytes(&log))?;
    let mut runs = ArrayVec::new();
    for part in &prepared.kernel {
        add_file_runs(
            &mut runs,
            &sources,
            0,
            part.file_offset,
            part.destination,
            part.file_size,
        )?;
        if part.memory_size > part.file_size {
            runs.push(Run {
                src: u64::MAX,
                dst: part.destination + part.file_size as u64,
                len: (part.memory_size - part.file_size) as u64,
            })
            .map_err(|_| ctl::ENOMEM)?;
        }
    }
    for module in &prepared.modules {
        add_file_runs(
            &mut runs,
            &sources,
            module.file,
            module.file_offset,
            module.destination,
            module.size,
        )?;
    }
    let regions = identity_regions(&reserved, &prepared.modules)?;

    let mut mbi = MbiBuilder::new();
    mbi.command_line(&prepared.command).map_err(invalid)?;
    for module in &prepared.modules {
        if module.size != 0 {
            mbi.module(&Module {
                start: module.destination,
                size: module.size,
                command: module.command,
            })
            .map_err(invalid)?;
        }
    }
    let mut map = boot.map;
    if let Some(previous) = super::log::previous_control(previous_log) {
        map.unreserve(previous..previous + BLOCK as u64)
            .map_err(invalid)?;
    }
    map.reserve(control as u64..control as u64 + BLOCK as u64)
        .map_err(invalid)?;
    if find_load_paddr(&map, mods_end, prepared.root_span) != Some(mods_end) {
        return Err(invalid("no RAM right after the boot modules for the root task"));
    }
    // Then seL4 copies the other modules, together, above the root task.
    let extras = prepared.modules.iter().skip(1).map(|m| align_page(m.size as u64)).sum();
    if find_load_paddr(&map, landing, extras).is_none() {
        return Err(invalid("no RAM below 4 GiB for the next seL4 to keep the boot modules"));
    }
    mbi.firmware_map(&map).map_err(invalid)?;
    if let Some(fb) = &boot.framebuffer {
        mbi.framebuffer(fb).map_err(invalid)?;
    }
    if let Some(acpi) = &boot.acpi {
        mbi.acpi(acpi).map_err(invalid)?;
    }
    let mbi = mbi.finish().map_err(invalid)?;
    build_control(
        h,
        &mut loading.extra,
        control,
        prepared.entry,
        mbi,
        &runs,
        &regions,
    )?;

    for load in loading.files.iter_mut().flatten() {
        load.unmap(&mut h.alloc);
    }
    let loading = core::mem::replace(loading, Loading::new());
    let arena = loading.into_arena();
    info!(
        "l4h-root: kexec image staged: {} copy runs, control at {:#x}",
        runs.len(),
        control
    );
    Ok(Staged {
        arena,
        control: control as u64,
        event_digest: prepared.event.digest(),
    })
}

pub(super) fn exec_failed(h: &mut Host, why: &str) -> ! {
    log!("l4h-root: kexec: {}: resetting", why);
    let _ = crate::reset::reboot(h, "kexec");
    log!("l4h-root: kexec and reset both failed");
    loop {
        core::hint::spin_loop();
    }
}

pub fn exec(h: &mut Host, control: u64) -> ! {
    let digest = h.kexec.staged.as_ref().expect("staged kexec image").event_digest;
    if let Err(e) = crate::trustd::measure(h, digest) {
        log!("l4h-root: kexec: TPM measurement failed: {}", e);
        exec_failed(h, "TPM measurement failed");
    }
    // The invocation is BSP-only. A scheduler failure after measurement
    // takes the cold-reset path rather than returning through a deleted page.
    if h.info
        .sched_control(0)
        .sched_control_configure_flags(
            sel4::init_thread::slot::SC.cap(),
            h.info.timeslice_us,
            h.info.timeslice_us,
            0,
            0,
            0,
        )
        .is_err()
    {
        exec_failed(h, "scheduler configuration failed");
    }
    let mut quiet = true;
    for disk in 0..h.disks.len() {
        let dk = &h.disks[disk];
        if h.ctrls[dk.ctrl].failed || dk.capacity == 0 || dk.read_only {
            continue;
        }
        if let Err(e) = crate::blkd::flush(h, disk) {
            log!("l4h-root: kexec: disk {} flush failed: {}", disk, e);
            quiet = false;
        }
    }
    for controller in h.ctrls.iter_mut() {
        if !crate::blkd::shutdown(controller, &h.pci, &mut h.alloc, &mut h.devmem, &mut h.wins.a, h.info.tsc_hz / 1000) {
            log!("l4h-root: kexec: disk controller shutdown failed");
            quiet = false;
        }
    }
    if let Err(e) = crate::netd::reset(h) {
        log!("l4h-root: kexec: NIC reset failed: {}", e);
        quiet = false;
    }
    for device in h.pci.functions() {
        h.pci.quiesce(&device);
    }
    if !h.iommu.shutdown() {
        log!("l4h-root: kexec: IOMMU shutdown failed");
        quiet = false;
    }
    if !quiet {
        exec_failed(h, "device shutdown failed");
    }
    log!("l4h-root: kexec EXEC at {:#x}", control);
    crate::set_mr(0, control);
    let reply = sel4::init_thread::slot::IRQ_CONTROL
        .cap()
        .call(sel4::MessageInfo::new(
            sel4::sys::invocation_label::X86IRQControlKexec.into(),
            0,
            0,
            1,
        ));
    log!("l4h-root: kexec invocation returned error {}", reply.label());
    exec_failed(h, "the kernel rejected the handoff")
}
