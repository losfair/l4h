//! l4h-hvm: an HVM guest's machine monitor (DESIGN.md §5.11, l4h_host::hvm).
//! It boots an unmodified x86-64 Linux kernel in VT-x or AMD-V guest mode
//! on seL4 VCPUs, and gives it a PC: local APICs, an I/O APIC, a UART, an
//! RTC, a PIT, ACPI, and virtio-blk and virtio-net devices on PCI over
//! blkd and netd.  Its main thread is the I/O thread (io.rs); each vCPU has
//! a thread of its own (vcpu.rs).  No heap.

#![no_std]
#![no_main]
#![feature(thread_local)]

mod acpi;
mod boot;
mod console;
mod dev;
mod ept;
mod hw;
mod io;
mod iopool;
mod mem;
mod serve;
mod sync;
mod sys;
mod vcpu;
mod vm;
mod x86;

/// l4h-vmm's virtqueues (l4h-vmm/src/virtq.rs), over guest RAM here: as
/// l4h-vmm has them (its style is l4h-vmm's).
#[path = "../../l4h-vmm/src/virtq.rs"]
#[allow(clippy::manual_is_multiple_of)]
mod virtq;

/// What virtq.rs takes guest memory from.
mod guest {
    pub use crate::mem::GuestMem;
}

use core::sync::atomic::{AtomicU64, Ordering};

use l4h_abi as abi;
use l4h_rt::host::hvm::{self as hv, HvmConfig};
use l4h_rt::host::vmmgr::call::Client as _;
use l4h_rt::host::{self, wiring};
use l4h_rt::ipc::Endpoint;
use l4h_rt::{Info, cap, sel4};
use sel4::cap_type;


/// A backend's kick: a notification of blkd or netd.
pub type Kick = sel4::cap::Notification;

pub fn yield_now() {
    sel4::r#yield();
}

/// Which blocks are mapped (mem.rs), a bit each.
static MAPPED: [AtomicU64; abi::MAX_BLOCKS / 64] = [const { AtomicU64::new(0) }; abi::MAX_BLOCKS / 64];

fn stop(why: core::fmt::Arguments) -> ! {
    l4h_rt::log!("l4h-hvm: {}", why);
    sys::power(abi::POWER_CRASH)
}

fn main(info: &'static Info) -> ! {
    let cfg: &'static HvmConfig = unsafe { info.config() };
    let tsc_hz = info.header().tsc_hz;
    let vcpus = (cfg.nr_vcpus as usize).clamp(1, hv::MAX_VCPUS);
    let blocks = ((cfg.low_ram + cfg.high_ram) >> abi::BLOCK_SHIFT) as usize;
    for b in 0..(cfg.boot_blocks as usize).min(blocks) {
        MAPPED[b / 64].fetch_or(1 << (b % 64), Ordering::Relaxed);
    }
    let mem = guest::GuestMem { base: hv::RAM_VA, low: cfg.low_ram, high: cfg.high_ram, mapped: &MAPPED, map: sys::map };
    // Mapping works before the machine is made: loading the kernel maps.
    ept::init(mem, cfg.block_radix, cfg.guest_id);
    vcpu::read_host_cpuid();
    let mut host = vm::Host::of(&vcpu::host_cpuid);
    host.xcr0 = hw::probe_xcr0(hv::SLOT_VCPU_OBJ, host.xcr0);
    let amd = host.amd;
    // The kernel, its boot parameters and the ACPI tables.
    if let Err(e) = vm::build(cfg, tsc_hz, mem, host) {
        stop(format_args!("guest {}: kernel image at {:#x}: {:?}", cfg.guest_id, cfg.kernel_gpa, e));
    }
    l4h_rt::info!("l4h-hvm: guest {}: {} vCPU(s) on {}, entry {:#x}", cfg.guest_id, vcpus, if amd { "AMD-V" } else { "VT-x" }, vm::vm().entry.rip);

    // Disk channels announce themselves ready (their capacity known), as
    // to a VMM.
    let ntfn = cap::<cap_type::Notification>(host::SLOT_NTFN);
    let devices = &cfg.devices[..cfg.nr_devices as usize];
    while !devices.iter().filter(|d| d.kind == host::VDEV_BLK)
        .all(|d| unsafe { core::ptr::addr_of!((*(d.chan_va as *const host::blk::Channel)).ready).read_volatile() } != 0)
    {
        ntfn.wait();
    }
    io::init();

    // vmmgr starts the guest: then our vCPU threads.
    let vmmgr = Endpoint::of(&wiring::HVM_VMMGR, wiring::p::Hvm, 0);
    if vmmgr.vmm_ready().is_err() {
        stop(format_args!("guest {}: vmmgr did not start it", cfg.guest_id));
    }
    for v in 0..vcpus {
        let tls = l4h_rt::TlsRegion::new(hv::vcpu_tls_va(v) as *mut u8, hv::VCPU_TLS_SIZE);
        unsafe { l4h_rt::start_thread(hv::SLOT_VCPU_TCB + v as u64, hv::vcpu_stack_top(v), tls, vcpu::entry, v) };
    }
    serve::serve()
}

l4h_rt::component!(main, no_heap);
