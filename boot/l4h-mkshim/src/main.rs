//! l4h-mkshim: boots several seL4 kernels on one x86_64 machine, each
//! with its own CPUs, RAM and PCI functions (DESIGN.md §11.4).
//!
//! The boot loader (GRUB, multiboot2; or QEMU's -kernel, multiboot1) loads
//! the shim with these modules, each named by the last word of its string:
//!
//! - `kernel-s0` … `kernel-s7`: seL4 built for each slot (L4H_KERNEL_SLOT);
//! - `l4h-root`: the root task, the same in every partition;
//! - `l4h-mk.conf`: the split (conf.rs);
//! - `guest-kernel`, `guest-kmods`, `dom0-initrd`, `l4h-config`: as for a
//!   single kernel, for every partition; `pN:ROLE` replaces ROLE for
//!   partition N alone.
//!
//! The shim runs once on the boot CPU.  It splits the CPUs, RAM and PCI
//! functions, measures the clocks with the PIT, and gives each partition
//! its kernel at the kernel's address, copies of the modules, an ACPI copy
//! whose MADT lists only its CPUs, a multiboot2 information structure, and
//! a descriptor (the `l4h-partition` module).  It then starts each
//! secondary partition's first CPU in a page below 1 MiB that leads to the
//! kernel's multiboot entry, and finally enters partition 0's kernel on
//! the boot CPU.  Nothing of the shim runs after that.

#![no_std]
#![no_main]

mod acpi;
mod boot;
mod conf;
mod cpu;
mod entry;
mod io;
mod mem;
mod pci;

use core::fmt::Write as _;

use l4h_partition::{self as part, Descriptor, MAX_PARTITIONS};

use crate::boot::{BootInfo, E820_RAM, E820_RESERVED, Module};
use crate::conf::{Conf, Cpus};
use crate::io::{Str, Vec, align_up, phys, phys_mut, rd16, rd32, rd64};
use crate::mem::{Range, Ranges};

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
/// seL4 x86_64 maps physical memory up to here (PADDR_TOP).
const PADDR_TOP: u64 = 512 * GIB;
const FOUR_GIB: u64 = 4 * GIB;

/// User vector of the doorbell from partition p (pci.rs leaves 96.. free).
const DOORBELL_VECTOR_BASE: u32 = 96;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("panic: {}", info);
    halt()
}

pub fn fail(args: core::fmt::Arguments) -> ! {
    println!("cannot boot: {}", args);
    halt()
}

fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("cli; hlt") };
    }
}

unsafe extern "C" {
    static __shim_start: u8;
    static __shim_end: u8;
}

#[repr(C, align(4096))]
struct Page([u64; 512]);

static mut PML4: Page = Page([0; 512]);
static mut PDPT_WB: Page = Page([0; 512]);
static mut PDPT_UC: Page = Page([0; 512]);
static mut PD_WB: [Page; 4] = [const { Page([0; 512]) }; 4];
static mut PD_UC: [Page; 4] = [const { Page([0; 512]) }; 4];

/// Identity map physical memory write-back, and again uncached at
/// pci::UC_ALIAS for devices: all of the kernel window with 1 GiB pages,
/// or the first 4 GiB where the CPU has none.
fn map_memory() {
    let gib_pages = io::cpuid(0x8000_0001, 0)[3] & (1 << 26) != 0;
    unsafe {
        let (pml4, wb, uc) = (&raw mut PML4, &raw mut PDPT_WB, &raw mut PDPT_UC);
        if gib_pages {
            for i in 0..512u64 {
                (*wb).0[i as usize] = i << 30 | 0x83;
                (*uc).0[i as usize] = i << 30 | 0x83 | 0x18;
            }
        } else {
            for d in 0..4usize {
                let (pdw, pdu) = (&raw mut PD_WB[d], &raw mut PD_UC[d]);
                for i in 0..512u64 {
                    let pa = (d as u64) << 30 | i << 21;
                    (*pdw).0[i as usize] = pa | 0x83;
                    (*pdu).0[i as usize] = pa | 0x83 | 0x18;
                }
                (*wb).0[d] = pdw as u64 | 3;
                (*uc).0[d] = pdu as u64 | 3;
            }
        }
        (*pml4).0[0] = wb as u64 | 3;
        (*pml4).0[1] = uc as u64 | 3;
        core::arch::asm!("mov cr3, {}", in(reg) pml4 as u64);
    }
}

/// A partition being put together.
#[derive(Clone, Copy)]
struct Plan {
    /// Indexes into the MADT's CPUs; the first is the partition's boot CPU.
    cpus: Vec<usize, 256>,
    ram: Ranges,
    slot: Range,
    low: Range,
    funcs: Vec<usize, { part::MAX_FUNCS }>,
    /// Modules for its kernel, in order (the first is root).
    mods: Vec<(Str<32>, &'static [u8]), 8>,
    /// Where the descriptor, multiboot information, ACPI copy and console
    /// ring go (`OUT_BLOCK` bytes).
    block: u64,
    channels: Vec<part::Channel, { part::MAX_CHANNELS }>,
    /// APIC IDs for the kernel's peers= list.
    peers: Vec<u32, { part::MAX_CHANNELS }>,
    /// The NUMA node of its boot CPU.
    node: u32,
}

/// Per partition: [0, 64K) multiboot information, [64K, 192K) ACPI copy,
/// [192K, 256K) console ring, [256K, ...) descriptor.
const OUT_BLOCK: u64 = MIB;
const OUT_MBI: u64 = 0;
const OUT_ACPI: u64 = 64 << 10;
const OUT_RING: u64 = 192 << 10;
const OUT_DESC: u64 = 256 << 10;

static mut DESCS: [Descriptor; MAX_PARTITIONS] = [const { Descriptor::zeroed() }; MAX_PARTITIONS];

#[unsafe(no_mangle)]
extern "C" fn shim_main(magic: u32, info: u64) -> ! {
    map_memory();
    let mut bi = BootInfo::parse(magic, info);
    let port = opt(bi.cmdline.as_str(), "console_port").and_then(num).unwrap_or(0x3f8);
    io::serial_init(port as u16);
    println!("starting ({})", bi.cmdline.as_str());

    let conf_mod = bi.module("l4h-mk.conf").unwrap_or_else(|| fail(format_args!("no l4h-mk.conf module")));
    let conf = Conf::parse(conf_mod.bytes());
    let n = conf.partitions;
    let acpi = acpi::Acpi::new(bi.rsdp.unwrap_or_else(|| fail(format_args!("no ACPI RSDP"))));
    let cpus = acpi.cpus();
    let bsp = cpu::apic_id();
    let Some(bsp_index) = cpus.iter().position(|c| c.apic_id == bsp) else {
        fail(format_args!("the boot CPU (APIC ID {}) is not in the MADT", bsp))
    };
    let pci = pci::Pci::new(acpi.ecam());
    if n > 1 && acpi.ecam().is_none() {
        fail(format_args!("no MCFG: partitions need PCI ECAM"));
    }
    let funcs = pci.scan();

    let mut plans: Vec<Plan, MAX_PARTITIONS> = Vec::new();
    for _ in 0..n {
        let none = Range::new(0, 0);
        if !plans.push(Plan {
            cpus: Vec::new(),
            ram: Ranges::new(),
            slot: none,
            low: none,
            funcs: Vec::new(),
            mods: Vec::new(),
            block: 0,
            channels: Vec::new(),
            peers: Vec::new(),
            node: 0,
        }) {
            unreachable!();
        }
    }
    assign_cpus(&conf, &cpus, bsp_index, &mut plans);
    assign_funcs(&conf, &funcs, &mut plans);

    // Clocks, once, before any kernel runs: no kernel touches the PIT.
    cpu::mask_pic();
    let tsc_khz = cpu::tsc_khz();
    let apic_khz = if cpu::tsc_deadline() { 0 } else { cpu::apic_khz() };
    let epoch_tsc = io::rdtsc();
    let epoch_ns = cpu::rtc_ns(acpi.century());
    println!("TSC {} kHz, APIC timer {}, wall clock {} s", tsc_khz,
        if apic_khz == 0 { 0 } else { apic_khz }, epoch_ns / 1_000_000_000);

    // Modules for each partition: their sizes size the low chunks, and
    // place_memory may move a module out of a kernel slot, so the bytes
    // are taken again after it.
    let root_memsz = {
        let root = bi.module("l4h-root").unwrap_or_else(|| fail(format_args!("no l4h-root module")));
        elf_span(root.bytes()).1
    };
    collect_modules(&bi, &mut plans);
    let out = place_memory(&mut bi, &conf, &acpi, &mut plans, root_memsz);
    collect_modules(&bi, &mut plans);
    println!("shared region {:#x}-{:#x}", out.start, out.end);

    // Channels: the primary and each secondary, and the configured links
    // (a link to the primary rides on the control channel).
    let mut next_channel = out.start + part::IOMMU_REGION_SIZE + OUT_BLOCK * MAX_PARTITIONS as u64;
    let mut pairs: Vec<(usize, usize, u32), 64> = Vec::new();
    for k in 1..n {
        let link = conf.links.iter().any(|&(a, b)| a == 0 && b as usize == k);
        pairs.must_push((0, k, part::CHANNEL_CONTROL | if link { part::CHANNEL_LINK } else { 0 }));
    }
    for &(a, b) in conf.links.iter() {
        if a != 0 {
            pairs.must_push((a as usize, b as usize, part::CHANNEL_LINK));
        }
    }
    for &(a, b, kind) in pairs.iter() {
        let paddr = next_channel;
        next_channel += part::CHANNEL_SIZE;
        unsafe { phys_mut(paddr, part::CHANNEL_SIZE as usize).fill(0) };
        for (me, peer) in [(a, b), (b, a)] {
            let peer_apic = cpus[plans[peer].cpus[0]].apic_id;
            let p = &mut plans[me];
            let slot = p.peers.len() as u32;
            p.peers.must_push(peer_apic);
            p.channels.must_push(part::Channel {
                paddr,
                size: part::CHANNEL_SIZE,
                peer: peer as u32,
                kind,
                vector: DOORBELL_VECTOR_BASE + peer as u32,
                peer_slot: slot,
                peer_vector: DOORBELL_VECTOR_BASE + me as u32,
                _pad: 0,
            });
        }
    }
    if next_channel > out.end {
        fail(format_args!("too many channels"));
    }

    // The shared IOMMU region starts zeroed: the primary's root marks it
    // ready (DESIGN.md §11.4).
    unsafe { phys_mut(out.start, part::IOMMU_REGION_SIZE as usize).fill(0) };

    // Descriptors.
    let ecam = acpi.ecam().unwrap_or((0, 0, 0));
    let mut parts_info = [part::PartInfo::default(); MAX_PARTITIONS];
    for (k, p) in plans.iter_mut().enumerate() {
        p.block = out.start + part::IOMMU_REGION_SIZE + k as u64 * OUT_BLOCK;
        unsafe { phys_mut(p.block, OUT_BLOCK as usize).fill(0) };
        parts_info[k] = part::PartInfo {
            boot_apic: cpus[p.cpus[0]].apic_id,
            cpus: p.cpus.len() as u32,
            mem_mib: p.ram.total() >> 20,
            console: if k == 0 { part::Ring::default() } else { part::Ring { paddr: p.block + OUT_RING, size: part::CONSOLE_RING_SIZE } },
        };
    }
    for (k, p) in plans.iter().enumerate() {
        let d = unsafe { &mut (*(&raw mut DESCS))[k] };
        d.magic = part::MAGIC;
        d.version = part::VERSION;
        d.size = core::mem::size_of::<Descriptor>() as u32;
        d.index = k as u32;
        d.count = n as u32;
        d.flags = if k == 0 { part::FLAG_PRIMARY } else { 0 };
        d.boot_apic = parts_info[k].boot_apic;
        d.tsc_khz = tsc_khz;
        d.apic_khz = apic_khz;
        d.epoch_ns = epoch_ns;
        d.epoch_tsc = epoch_tsc;
        d.ecam_base = ecam.0;
        d.ecam_bus_start = ecam.1;
        d.ecam_bus_end = ecam.2;
        d.mem_base = p.ram.list[0].start;
        d.console = parts_info[k].console;
        d.iommu = part::Iommu { paddr: out.start, size: part::IOMMU_REGION_SIZE, share: k as u32, shares: n as u32, _pad: [0; 2] };
        for (i, c) in p.channels.iter().enumerate() {
            d.channels[i] = *c;
        }
        d.nchannels = p.channels.len() as u32;
        d.parts = parts_info;
        for (i, &f) in p.funcs.iter().enumerate() {
            let f = &funcs[f];
            d.funcs[i] = part::Func {
                bdf: f.bdf,
                header: f.header,
                _pad: 0,
                vendor: f.vendor,
                device: f.device,
                class: f.class,
                _pad2: 0,
                bars: f.bars,
            };
        }
        d.nfuncs = p.funcs.len() as u32;
        if k == 0 {
            let mut o = 0;
            for (kk, pp) in plans.iter().enumerate() {
                for &f in pp.funcs.iter() {
                    d.owners[o] = part::Owner { bdf: funcs[f].bdf, partition: kk as u8, _pad: 0 };
                    o += 1;
                }
            }
            d.nowners = o as u32;
        }
    }

    // Kernels, modules, ACPI copies and multiboot information.
    let mut entries = [0u64; MAX_PARTITIONS];
    let mut mbis = [0u64; MAX_PARTITIONS];
    for k in 0..n {
        let mut name: Str<16> = Str::new();
        let _ = write!(name, "kernel-s{}", k);
        let kmod = bi.module(name.as_str()).unwrap_or_else(|| fail(format_args!("no {} module", name.as_str())));
        entries[k] = load_kernel(kmod, plans[k].slot);
        let desc_bytes = unsafe {
            core::slice::from_raw_parts((&raw const DESCS[k]) as *const u8, core::mem::size_of::<Descriptor>())
        };
        plans[k].mods[1].1 = desc_bytes;
        let rsdp = build_acpi(&acpi, &cpus, &plans[k], k);
        mbis[k] = build_mbi(&bi, &plans[k], k, &plans, &cpus, rsdp, tsc_khz, apic_khz, port);
    }
    report(&plans, &cpus, &funcs);

    // Secondaries first, one at a time; each starts in its own page.
    for k in 1..n {
        let page = part::ap_boot_page(k);
        let len = unsafe { (&raw const entry::ap_tramp_end) as usize - (&raw const entry::ap_tramp_start) as usize };
        unsafe {
            core::ptr::copy_nonoverlapping(&raw const entry::ap_tramp_start, page as *mut u8, len);
            (&raw mut entry::ap_entry).write_volatile(entries[k] as u32);
            (&raw mut entry::ap_mbi).write_volatile(mbis[k] as u32);
        }
        let before = unsafe { (&raw const entry::ap_ack).read_volatile() };
        let apic = cpus[plans[k].cpus[0]].apic_id;
        cpu::start_cpu(apic, page);
        let deadline = io::rdtsc() + tsc_khz * 1000;
        while unsafe { (&raw const entry::ap_ack).read_volatile() } == before {
            if io::rdtsc() > deadline {
                fail(format_args!("partition {}'s first CPU (APIC ID {}) did not start", k, apic));
            }
            io::pause();
        }
        println!("partition {} started on APIC ID {}", k, apic);
    }
    println!("entering partition 0");
    unsafe { entry::enter_kernel(entries[0], mbis[0]) }
}

/// Each partition's modules, root first, then a placeholder for its
/// descriptor, then the roles it has (its own `pN:ROLE` or the shared one).
fn collect_modules(bi: &BootInfo, plans: &mut [Plan]) {
    let Some(root) = bi.module("l4h-root") else { fail(format_args!("no l4h-root module")) };
    for (k, p) in plans.iter_mut().enumerate() {
        p.mods.clear();
        p.mods.must_push((Str::from("l4h-root"), root.bytes()));
        p.mods.must_push((Str::from("l4h-partition"), &[]));
        for role in ["guest-kernel", "guest-kmods", "dom0-initrd", "l4h-config"] {
            let mut own: Str<32> = Str::new();
            let _ = write!(own, "p{}:{}", k, role);
            if let Some(m) = bi.module(own.as_str()).or_else(|| bi.module(role)) {
                p.mods.must_push((Str::from(role), m.bytes()));
            }
        }
    }
}

/// The value of `key=` on a command line.
fn opt<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline.split_whitespace().find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
}

fn num(s: &str) -> Option<u64> {
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Split the CPUs: as configured, partition 0 always with the boot CPU,
/// the rest evenly in APIC ID order (which keeps SMT siblings together).
fn assign_cpus(conf: &Conf, cpus: &[acpi::Cpu], bsp: usize, plans: &mut [Plan]) {
    let n = plans.len();
    let mut owner = [u8::MAX; 1024];
    for (k, p) in plans.iter_mut().enumerate() {
        let want = |i: usize| -> bool {
            match conf.parts[k].cpus {
                Cpus::Default | Cpus::Count(_) => false,
                Cpus::Range(a, b) => (a as usize..=b as usize).contains(&i),
                Cpus::Node(node) => cpus[i].node == node,
                Cpus::Apic(ref l) => l.contains(&cpus[i].apic_id),
            }
        };
        for i in 0..cpus.len() {
            if want(i) {
                if owner[i] != u8::MAX {
                    fail(format_args!("CPU {} (APIC ID {}) is in p{} and p{}", i, cpus[i].apic_id, owner[i], k));
                }
                owner[i] = k as u8;
                p.cpus.must_push(i);
            }
        }
    }
    // Counts and defaults from what is left, in APIC ID order.
    let mut order: Vec<usize, 1024> = Vec::new();
    for i in 0..cpus.len() {
        if owner[i] == u8::MAX {
            order.must_push(i);
        }
    }
    order.sort_unstable_by_key(|&i| (i != bsp, cpus[i].apic_id));
    let defaults = (0..n).filter(|&k| matches!(conf.parts[k].cpus, Cpus::Default)).count();
    let counted: usize = (0..n).map(|k| match conf.parts[k].cpus { Cpus::Count(c) => c as usize, _ => 0 }).sum();
    if counted > order.len() {
        fail(format_args!("{} CPUs asked for, {} left", counted, order.len()));
    }
    let share = if defaults > 0 { (order.len() - counted) / defaults } else { 0 };
    let mut next = 0;
    // Partition 0 first, so that it gets the boot CPU if it is left.
    for k in 0..n {
        let count = match conf.parts[k].cpus {
            Cpus::Count(c) => c as usize,
            Cpus::Default => if k == 0 { share + (order.len() - counted) % defaults.max(1) } else { share },
            _ => 0,
        };
        for _ in 0..count {
            plans[k].cpus.must_push(order[next]);
            next += 1;
        }
    }
    for (k, p) in plans.iter_mut().enumerate() {
        if p.cpus.is_empty() {
            fail(format_args!("partition {} has no CPU", k));
        }
        // The boot CPU leads partition 0; any CPU leads the others.
        if let Some(i) = p.cpus.iter().position(|&c| c == bsp) {
            if k != 0 {
                fail(format_args!("the boot CPU is in partition {}, not 0", k));
            }
            let c = p.cpus.remove(i);
            p.cpus.insert(0, c);
        } else if k == 0 {
            fail(format_args!("partition 0 does not have the boot CPU (APIC ID {})", cpus[bsp].apic_id));
        }
        p.node = cpus[p.cpus[0]].node;
    }
}

/// Give each function to the partition that lists it, the rest to
/// partition 0, and check the result.
fn assign_funcs(conf: &Conf, funcs: &[pci::Func], plans: &mut [Plan]) {
    let n = plans.len();
    let mut owner: Vec<u8, 1024> = Vec::new();
    for _ in funcs {
        owner.must_push(0);
    }
    for k in 1..n {
        for &bdf in conf.parts[k].pci.iter() {
            let Some(i) = funcs.iter().position(|f| f.bdf == bdf) else {
                fail(format_args!("p{}.pci: no PCI function {}", k, pci::fmt_bdf(bdf)))
            };
            if owner[i] != 0 {
                fail(format_args!("PCI function {} is in p{} and p{}", pci::fmt_bdf(bdf), owner[i], k));
            }
            if funcs[i].header != 0 {
                fail(format_args!("PCI function {} is a bridge", pci::fmt_bdf(bdf)));
            }
            owner[i] = k as u8;
        }
    }
    for &bdf in conf.parts[0].pci.iter() {
        if !funcs.iter().any(|f| f.bdf == bdf) {
            fail(format_args!("p0.pci: no PCI function {}", pci::fmt_bdf(bdf)));
        }
    }
    // Functions behind an aliasing bridge share one requester ID, and so
    // one IOMMU domain: one partition must have them all.
    for b in funcs.iter().filter(|f| f.header == 1 && f.aliasing && f.secondary != 0) {
        let below = |f: &pci::Func| {
            let bus = (f.bdf >> 8) as u8;
            f.header == 0 && bus >= b.secondary && bus <= b.subordinate
        };
        let mut first: Option<u8> = None;
        for (i, f) in funcs.iter().enumerate() {
            if below(f) {
                match first {
                    None => first = Some(owner[i]),
                    Some(o) if o != owner[i] => fail(format_args!(
                        "functions behind bridge {} share a requester ID but are in p{} and p{}",
                        pci::fmt_bdf(b.bdf), o, owner[i])),
                    _ => {}
                }
            }
        }
    }
    for (i, &k) in owner.iter().enumerate() {
        plans[k as usize].funcs.must_push(i);
    }
    for (k, p) in plans.iter().enumerate() {
        if !p.funcs.iter().any(|&i| funcs[i].is_disk()) {
            fail(format_args!("partition {} has no disk controller", k));
        }
    }
}

/// The physical span of an ELF's loadable segments: (lowest address,
/// size in memory).
fn elf_span(elf: &[u8]) -> (u64, u64) {
    if elf.len() < 64 || &elf[..4] != b"\x7fELF" {
        fail(format_args!("not an ELF file"));
    }
    let (lo, hi) = segments(elf).fold((u64::MAX, 0), |(lo, hi), s| (lo.min(s.paddr), hi.max(s.paddr + s.memsz)));
    (lo, hi.saturating_sub(lo))
}

#[derive(Clone, Copy)]
struct Segment {
    paddr: u64,
    offset: u64,
    filesz: u64,
    memsz: u64,
}

fn segments(elf: &[u8]) -> impl Iterator<Item = Segment> + '_ {
    let is64 = elf[4] == 2;
    let (phoff, phentsize, phnum) = if is64 {
        (rd64(elf, 32), rd16(elf, 54) as u64, rd16(elf, 56) as u64)
    } else {
        (rd32(elf, 28) as u64, rd16(elf, 42) as u64, rd16(elf, 44) as u64)
    };
    (0..phnum).filter_map(move |i| {
        let h = &elf[(phoff + i * phentsize) as usize..];
        if rd32(h, 0) != 1 {
            return None;
        }
        Some(if is64 {
            Segment { offset: rd64(h, 8), paddr: rd64(h, 24), filesz: rd64(h, 32), memsz: rd64(h, 40) }
        } else {
            Segment { offset: rd32(h, 4) as u64, paddr: rd32(h, 12) as u64, filesz: rd32(h, 16) as u64, memsz: rd32(h, 20) as u64 }
        })
    })
}

/// Load a kernel's segments at their physical addresses, within its slot;
/// returns its (physical) entry point.
fn load_kernel(m: &Module, slot: Range) -> u64 {
    let elf = m.bytes();
    let (lo, size) = elf_span(elf);
    if lo < slot.start || lo + size > slot.end {
        fail(format_args!("{} at {:#x}-{:#x} is not built for slot {:#x}-{:#x}",
            m.name.as_str(), lo, lo + size, slot.start, slot.end));
    }
    for s in segments(elf) {
        let dst = unsafe { phys_mut(s.paddr, s.memsz as usize) };
        dst[..s.filesz as usize].copy_from_slice(&elf[s.offset as usize..(s.offset + s.filesz) as usize]);
        dst[s.filesz as usize..].fill(0);
    }
    if elf[4] == 2 { rd64(elf, 24) } else { rd32(elf, 24) as u64 }
}

/// Decide where everything goes: each partition's kernel slot, a low
/// chunk for its modules, and the rest of its RAM; and the shared region
/// (returned) for the IOMMU, the per-partition blocks and the channels.
fn place_memory(bi: &mut BootInfo, conf: &Conf, acpi: &acpi::Acpi, plans: &mut [Plan], root_memsz: u64) -> Range {
    let n = plans.len();
    let mut free = Ranges::new();
    for e in bi.mmap.iter().filter(|e| e.kind == E820_RAM) {
        free.add(Range::new(align_up(e.base, 4096).max(MIB), (io::align_down(e.base + e.len, 4096)).min(PADDR_TOP)));
    }
    let above = bi.mmap.iter().filter(|e| e.kind == E820_RAM && e.base + e.len > PADDR_TOP)
        .map(|e| e.base + e.len - e.base.max(PADDR_TOP)).sum::<u64>();
    if above > 0 {
        println!("{} MiB of RAM above 512 GiB stays unused", above >> 20);
    }
    let shim = Range::new(unsafe { &raw const __shim_start } as u64, unsafe { &raw const __shim_end } as u64);
    free.remove(shim);
    let mut slots = Ranges::new();
    for (k, p) in plans.iter_mut().enumerate() {
        p.slot = Range::new(part::SLOT_BASE + k as u64 * part::SLOT_STRIDE, part::SLOT_BASE + (k as u64 + 1) * part::SLOT_STRIDE);
        slots.add(p.slot);
    }
    // The boot loader's modules stay where they are, unless one is in a
    // slot: that one moves out of the way first.
    let mut originals = Ranges::new();
    for m in bi.mods.iter() {
        let r = Range::new(io::align_down(m.start, 4096), align_up(m.end, 4096));
        free.remove(r);
    }
    for m in bi.mods.iter_mut() {
        let r = Range::new(m.start, m.end);
        if slots.overlaps(r) {
            let mut avoid = free;
            for s in slots.list.iter() {
                avoid.remove(*s);
            }
            let Some(dst) = avoid.take(align_up(r.len(), 4096), 4096, MIB, FOUR_GIB, true) else {
                fail(format_args!("no room to move module {} out of the kernel slots", m.name.as_str()))
            };
            free.remove(Range::new(dst, dst + align_up(r.len(), 4096)));
            unsafe { core::ptr::copy(m.start as *const u8, dst as *mut u8, r.len() as usize) };
            m.start = dst;
            m.end = dst + r.len();
            // Its old place is RAM again (the slot it was in).
            free.add(Range::new(io::align_down(r.start, 4096), align_up(r.end, 4096)));
        } else {
            originals.add(Range::new(io::align_down(m.start, 4096), align_up(m.end, 4096)));
        }
    }
    for p in plans.iter() {
        if !free.contains(p.slot) {
            for e in bi.mmap.iter().filter(|e| e.base < p.slot.end && p.slot.start < e.base + e.len) {
                println!("memory map: {:#x}-{:#x} type {}", e.base, e.base + e.len, e.kind);
            }
            for m in bi.mods.iter().filter(|m| m.start < p.slot.end && p.slot.start < m.end) {
                println!("module {} at {:#x}-{:#x}", m.name.as_str(), m.start, m.end);
            }
            fail(format_args!("kernel slot {:#x}-{:#x} is not free RAM", p.slot.start, p.slot.end));
        }
        free.remove(p.slot);
    }
    // The shared region: below 4 GiB, which the kernels' boot page tables
    // map (their console rings must be there).
    let out_size = part::IOMMU_REGION_SIZE + OUT_BLOCK * MAX_PARTITIONS as u64 + 32 * part::CHANNEL_SIZE;
    let Some(out) = free.take(out_size, 2 * MIB, MIB, FOUR_GIB, true) else {
        fail(format_args!("no {} MiB below 4 GiB for the shared region", out_size >> 20))
    };
    // Each partition's low chunk: its modules, then room for its kernel to
    // load root above them and copy the modules again (seL4's boot_sys).
    for p in plans.iter_mut() {
        let mods: u64 = p.mods.iter().map(|(_, b)| align_up(b.len().max(1) as u64, 4096)).sum::<u64>()
            + align_up(core::mem::size_of::<Descriptor>() as u64, 4096);
        let size = align_up(2 * mods + root_memsz + 16 * MIB, 2 * MIB);
        let Some(at) = free.take(size, 2 * MIB, MIB, FOUR_GIB, false) else {
            fail(format_args!("no {} MiB below 4 GiB for a partition's modules", size >> 20))
        };
        p.low = Range::new(at, at + size);
        p.ram.add(p.slot);
        p.ram.add(p.low);
    }
    // The rest: secondaries first, each its configured size or an even
    // share, preferring its CPUs' NUMA node; partition 0 the remainder.
    let affinity = acpi.mem_affinity();
    let total = free.total() + plans.iter().map(|p| p.ram.total()).sum::<u64>();
    for k in (1..n).chain(core::iter::once(0)) {
        let p = &mut plans[k];
        let target = match conf.parts[k].mem {
            Some(m) => m,
            None if k == 0 => u64::MAX,
            None => total / n as u64,
        };
        let have = p.ram.total();
        if target != u64::MAX && target < have {
            fail(format_args!("p{}.mem: at least {} MiB", k, have >> 20));
        }
        let want = target.saturating_sub(have);
        let node = p.node;
        let in_node = |r: Range| {
            affinity.is_empty() || affinity.iter().any(|a| a.node == node && a.base <= r.start && r.end <= a.base + a.len)
        };
        let mut got = free.take_pieces(want, 2 * MIB, MIB, PADDR_TOP, &mut p.ram, in_node);
        if got < want {
            let more = free.take_pieces(want - got, 2 * MIB, MIB, PADDR_TOP, &mut p.ram, |_| true);
            if more > 0 && !affinity.is_empty() {
                println!("partition {}: {} MiB of RAM off its NUMA node", k, more >> 20);
            }
            got += more;
        }
        if got < want && target != u64::MAX {
            fail(format_args!("p{}.mem: {} MiB short", k, (want - got) >> 20));
        }
    }
    // The modules the boot loader loaded are dead once copied: partition 0
    // gets their memory.
    for r in originals.list.iter() {
        plans[0].ram.add(*r);
    }
    Range::new(out, out + out_size)
}

/// The partition's ACPI copy: the firmware's tables, but a MADT of its
/// own CPUs (and, for partition 0, the I/O APICs), and for the others no
/// TPM.  Returns the new RSDP's address.
fn build_acpi(a: &acpi::Acpi, cpus: &[acpi::Cpu], p: &Plan, k: usize) -> u64 {
    let base = p.block + OUT_ACPI;
    let rsdp = base;
    let rsdt = base + 64;
    let xsdt = base + 1024;
    let madt = base + 4096;
    // The MADT.
    let Some(orig) = a.find(b"APIC") else { unreachable!() };
    let t = acpi::table(orig);
    let m = unsafe { phys_mut(madt, 120 << 10) };
    m[..44].copy_from_slice(&t[..44]);
    if k != 0 {
        // No dual 8259s (PCAT_COMPAT).
        let flags = rd32(m, 40) & !1;
        m[40..44].copy_from_slice(&flags.to_le_bytes());
    }
    let mut len = 44;
    let mut put = |e: &[u8], len: &mut usize| {
        if *len + e.len() > m.len() {
            fail(format_args!("MADT copy too large"));
        }
        m[*len..*len + e.len()].copy_from_slice(e);
        *len += e.len();
    };
    for &c in p.cpus.iter() {
        let c = &cpus[c];
        put(&c.entry[..c.entry_len as usize], &mut len);
    }
    let mut off = 44;
    while off + 2 <= t.len() {
        let (ty, l) = (t[off], t[off + 1] as usize);
        if l < 2 || off + l > t.len() {
            break;
        }
        let keep = match ty {
            0 | 9 => false,
            // I/O APIC, interrupt source override, NMI source, I/O SAPIC.
            1 | 2 | 3 | 6 => k == 0,
            _ => true,
        };
        if keep {
            put(&t[off..off + l], &mut len);
        }
        off += l;
    }
    m[4..8].copy_from_slice(&(len as u32).to_le_bytes());
    m[9] = 0;
    m[9] = acpi::checksum(&m[..len]);
    // RSDT and XSDT: every table but the MADT (replaced) and, outside
    // partition 0, the TPM's.
    let mut list: Vec<u64, 128> = Vec::new();
    list.must_push(madt);
    for &tpa in a.tables.iter() {
        if tpa == 0 {
            continue;
        }
        let sig = &acpi::header(tpa)[..4];
        if sig == b"APIC" || (k != 0 && (sig == b"TPM2" || sig == b"TCPA")) {
            continue;
        }
        list.must_push(tpa);
    }
    let hdr = |dst: &mut [u8], sig: &[u8; 4], len: usize| {
        dst[..36].copy_from_slice(acpi::header(a.tables.iter().copied().find(|&t| t != 0).unwrap_or(orig)));
        dst[..4].copy_from_slice(sig);
        dst[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        dst[8] = 1;
    };
    let rl = 36 + 4 * list.iter().filter(|&&t| t < FOUR_GIB).count();
    let r = unsafe { phys_mut(rsdt, rl) };
    hdr(r, b"RSDT", rl);
    let mut i = 36;
    for &t in list.iter().filter(|&&t| t < FOUR_GIB) {
        r[i..i + 4].copy_from_slice(&(t as u32).to_le_bytes());
        i += 4;
    }
    r[9] = 0;
    r[9] = acpi::checksum(r);
    let xl = 36 + 8 * list.len();
    let x = unsafe { phys_mut(xsdt, xl) };
    hdr(x, b"XSDT", xl);
    for (i, &t) in list.iter().enumerate() {
        x[36 + 8 * i..44 + 8 * i].copy_from_slice(&t.to_le_bytes());
    }
    x[9] = 0;
    x[9] = acpi::checksum(x);
    let rp = unsafe { phys_mut(rsdp, 36) };
    rp[..20].copy_from_slice(&a.rsdp[..20]);
    rp[15] = 2;
    rp[16..20].copy_from_slice(&(rsdt as u32).to_le_bytes());
    rp[20..24].copy_from_slice(&36u32.to_le_bytes());
    rp[24..32].copy_from_slice(&xsdt.to_le_bytes());
    rp[32..36].fill(0);
    rp[8] = 0;
    rp[8] = acpi::checksum(&rp[..20]);
    rp[32] = acpi::checksum(&rp[..36]);
    rsdp
}

/// The partition's multiboot2 information, in its block; copies its
/// modules into its low chunk.  Returns the address.
#[allow(clippy::too_many_arguments)]
fn build_mbi(bi: &BootInfo, p: &Plan, k: usize, plans: &[Plan], cpus: &[acpi::Cpu], rsdp: u64,
    tsc_khz: u64, apic_khz: u64, port: u64) -> u64 {
    let base = p.block + OUT_MBI;
    let buf = unsafe { phys_mut(base, (OUT_ACPI - OUT_MBI) as usize) };
    let mut off = 8;
    let mut tag = |ty: u32, body: &[&[u8]], off: &mut usize| {
        let len = 8 + body.iter().map(|b| b.len()).sum::<usize>();
        if *off + align_up(len as u64, 8) as usize > buf.len() {
            fail(format_args!("multiboot information too large"));
        }
        buf[*off..*off + 4].copy_from_slice(&ty.to_le_bytes());
        buf[*off + 4..*off + 8].copy_from_slice(&(len as u32).to_le_bytes());
        let mut i = *off + 8;
        for b in body {
            buf[i..i + b.len()].copy_from_slice(b);
            i += b.len();
        }
        *off += align_up(len as u64, 8) as usize;
    };
    // The command line first: the kernel prints from the moment it has
    // parsed it.
    let mut cmd: Str<1024> = Str::new();
    if k == 0 {
        // Partition 0 keeps what the boot loader gave the shim.
        for w in bi.cmdline.as_str().split_whitespace().skip(if bi.cmdline.as_str().starts_with('/') { 1 } else { 0 }) {
            let _ = write!(cmd, "{} ", w);
        }
        if opt(bi.cmdline.as_str(), "console_port").is_none() {
            let _ = write!(cmd, "console_port={:#x} debug_port={:#x} ", port, port);
        }
    } else {
        let _ = write!(cmd, "console_port=0 debug_port=0 no_legacy_irq console_ring={:#x},{:#x} ",
            p.block + OUT_RING, part::CONSOLE_RING_SIZE);
    }
    let _ = write!(cmd, "ap_boot_page={:#x} tsc_mhz={}", part::ap_boot_page(k), tsc_khz / 1000);
    if apic_khz != 0 {
        let _ = write!(cmd, " apic_khz={}", apic_khz);
    }
    if !p.peers.is_empty() {
        let _ = write!(cmd, " peers=");
        for (i, a) in p.peers.iter().enumerate() {
            let _ = write!(cmd, "{}{}", if i > 0 { "," } else { "" }, a);
        }
    }
    let _ = (plans, cpus);
    tag(1, &[cmd.as_str().as_bytes(), &[0]], &mut off);
    // Modules, copied into the low chunk.
    let mut at = p.low.start;
    for (name, bytes) in p.mods.iter() {
        let len = bytes.len().max(1) as u64;
        if at + len > p.low.end {
            fail(format_args!("partition {}'s modules do not fit", k));
        }
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), at as *mut u8, bytes.len());
        }
        let (s, e) = ((at as u32).to_le_bytes(), ((at + len) as u32).to_le_bytes());
        tag(3, &[&s, &e, name.as_str().as_bytes(), &[0]], &mut off);
        at = align_up(at + len, 4096);
    }
    // The memory map: the firmware's, with only this partition's RAM
    // available (and conventional memory below 1 MiB, for the APs' boot
    // page); everyone else's RAM is reserved.
    let mut entries: Vec<[u8; 24], 1024> = Vec::new();
    let mut push = |b: u64, e: u64, ty: u32| {
        if b < e {
            let mut x = [0u8; 24];
            x[..8].copy_from_slice(&b.to_le_bytes());
            x[8..16].copy_from_slice(&(e - b).to_le_bytes());
            x[16..20].copy_from_slice(&ty.to_le_bytes());
            entries.must_push(x);
        }
    };
    let mut sorted: Vec<boot::E820, 256> = bi.mmap;
    sorted.sort_unstable_by_key(|e| e.base);
    for e in sorted.iter() {
        let (b, end) = (e.base, e.base + e.len);
        if e.kind != E820_RAM {
            push(b, end, e.kind);
            continue;
        }
        let mut cur = b;
        if cur < MIB {
            push(cur, end.min(MIB), E820_RAM);
            cur = end.min(MIB).max(cur);
        }
        for r in p.ram.list.iter() {
            let (s, t) = (r.start.max(cur), r.end.min(end));
            if s >= t {
                continue;
            }
            push(cur, s, E820_RESERVED);
            push(s, t, E820_RAM);
            cur = t;
        }
        push(cur, end, E820_RESERVED);
    }
    let mut mm: Vec<u8, 24576> = Vec::new();
    for x in [24u32.to_le_bytes(), 0u32.to_le_bytes()] {
        for b in x {
            mm.must_push(b);
        }
    }
    for e in entries.iter() {
        for &b in e {
            mm.must_push(b);
        }
    }
    tag(6, &[&mm], &mut off);
    // ACPI: the partition's copy.
    let rp = unsafe { phys(rsdp, 36) };
    tag(15, &[rp], &mut off);
    if k == 0 && bi.fb_tag.len() > 8 {
        tag(8, &[&bi.fb_tag[8..]], &mut off);
    }
    tag(0, &[], &mut off);
    buf[..4].copy_from_slice(&(off as u32).to_le_bytes());
    buf[4..8].fill(0);
    base
}

fn report(plans: &[Plan], cpus: &[acpi::Cpu], funcs: &[pci::Func]) {
    for (k, p) in plans.iter().enumerate() {
        let mut ids: Str<512> = Str::new();
        for &c in p.cpus.iter() {
            let _ = write!(ids, "{} ", cpus[c].apic_id);
        }
        println!("p{}: {} CPU(s) (APIC IDs {}), {} MiB RAM from {:#x}, kernel at {:#x}",
            k, p.cpus.len(), ids.as_str().trim_end(), p.ram.total() >> 20, p.ram.list[0].start, p.slot.start);
        for &f in p.funcs.iter() {
            let f = &funcs[f];
            if f.is_disk() || f.is_nic() || k != 0 {
                println!("p{}:   {} {:04x}:{:04x} class {:06x}", k, pci::fmt_bdf(f.bdf), f.vendor, f.device, f.class);
            }
        }
    }
}
