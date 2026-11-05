//! Spawning l4h-logd, the only host writer to the serial port (DESIGN.md
//! §10.4): root hands it the UART and the partitions' rings, and prints
//! nothing itself. If logd faults, serial output stops.

use core::ops::Range;

use l4h_host as host;
use l4h_host::serial::{self, LogdConfig};
use sel4::cap_type;

use crate::{AsidPools, Host, HostInfo};
use crate::component::{self, Component, SpawnArgs, abs_of};
use crate::devmem::DevMem;
use crate::mem::{Alloc, Arena, Slot};
use crate::window::Window;

pub const LOGD_ID: u32 = 0x600;
static LOGD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-logd.elf"));

/// logd's share of a core: a VM's UART takes output as fast as it comes.
const BUDGET_US: u64 = 1000;
const PERIOD_US: u64 = 5000;
const PAGE: usize = 4096;
/// How long a reset waits for logd, which may be dead or far behind.
const DRAIN_SECS: u64 = 2;
const DRAIN_POLL_MS: u64 = 10;

/// The UART: an I/O port capability each for the monitor and logd on x86,
/// the frame of its registers on aarch64.
pub struct Uart {
    pub monitor: u64,
    out: u64,
    out_base: u16,
}

#[cfg(target_arch = "x86_64")]
fn issue(alloc: &mut Alloc, base: u16) -> Option<u64> {
    let s = alloc.slots.alloc();
    let dst = abs_of(sel4::init_thread::Slot::<cap_type::Null>::from_index(s).cap());
    sel4::init_thread::slot::IO_PORT_CONTROL.cap().ioport_control_issue(base as u64, base as u64 + 7, &dst).ok()?;
    Some(s as u64)
}

#[cfg(target_arch = "x86_64")]
fn present(port: u64, base: u16) -> bool {
    sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_X86_IOPort_In8(port, base + 5).result as u8) != 0xff
}

/// The port at `base`. With an absent UART, logd prints on COM1, where the
/// kernel prints unless told otherwise: the setting is the monitor's too,
/// and one can be wrong without losing the log.
#[cfg(target_arch = "x86_64")]
pub fn init_uart(alloc: &mut Alloc, _devmem: &mut DevMem, base: u16) -> Option<Uart> {
    const COM1: u16 = 0x3f8;
    let monitor = issue(alloc, base)?;
    if !present(monitor, base) && base != COM1 {
        if let Some(out) = issue(alloc, COM1).filter(|&p| present(p, COM1)) {
            return Some(Uart { monitor, out, out_base: COM1 });
        }
    }
    Some(Uart { monitor, out: monitor, out_base: base })
}

/// The PL011 of QEMU's virt machine.
#[cfg(target_arch = "aarch64")]
pub fn init_uart(alloc: &mut Alloc, devmem: &mut DevMem, _base: u16) -> Option<Uart> {
    const PL011: usize = 0x0900_0000;
    let frame = devmem.frames(&mut alloc.slots, PL011, PAGE)?.start as u64;
    Some(Uart { monitor: frame, out: frame, out_base: 0 })
}

/// logd as root keeps it.
pub struct Logd {
    comp: Component,
    _arena: Arena,
}

/// The part of the framebuffer logd draws on: the frames, at most a
/// console's, in consecutive root slots.
pub struct FbArea {
    pub frames: Range<Slot>,
    pub offset: usize,
    pub pitch: usize,
    pub width: usize,
    pub height: usize,
}

/// Spawn logd: partition 0's serial output from now on. This is the first
/// component, so that a panic in the rest of root's boot is printed: root
/// outranks it, and it runs once root stops or waits.
pub fn spawn(
    alloc: &mut Alloc,
    win: &mut Window,
    asids: &mut AsidPools,
    info: &HostInfo,
    uart: &Uart,
    rings: &crate::partition::Rings,
    fb: Option<FbArea>,
) -> Option<Logd> {
    if LOGD_ELF.is_empty() {
        return None;
    }
    let fb_pages = fb.as_ref().map_or(0, |f| f.frames.len());
    let ring_pages = serial::MAX_RINGS * (serial::PAGES + l4h_partition::CONSOLE_RING_SIZE as usize / PAGE);
    let pages = fb_pages + ring_pages + 1;
    let keep_bits = pages.next_power_of_two().trailing_zeros() as usize;
    let mut arena = alloc
        .arena((4 << 20) + (32 << keep_bits) + (pages / 512 + 8) * PAGE)
        .expect("memory for logd");
    let mut cfg = LogdConfig {
        tsc_hz: info.tsc_hz,
        uart_base: uart.out_base,
        _pad: 0,
        rings: rings.serial_mask(),
        kernel_rings: rings.kernel_mask(),
        kernel_ring_size: l4h_partition::CONSOLE_RING_SIZE as u32,
        kernel_ring_header: l4h_partition::CONSOLE_RING_HEADER as u32,
        fb_pitch: 0,
        fb_width: 0,
        fb_height: 0,
        fb_offset: 0,
    };
    if let Some(f) = &fb {
        cfg.fb_pitch = f.pitch as u32;
        cfg.fb_width = f.width as u32;
        cfg.fb_height = f.height as u32;
        cfg.fb_offset = f.offset as u64;
    }
    let cfg_bytes = unsafe {
        core::slice::from_raw_parts(&cfg as *const LogdConfig as *const u8, core::mem::size_of::<LogdConfig>())
    };
    let args = SpawnArgs {
        id: LOGD_ID,
        kind: host::KIND_LOGD,
        elf: LOGD_ELF,
        prio: host::PRIO_LOGD,
        budget_us: BUDGET_US,
        period_us: PERIOD_US,
        config: cfg_bytes,
        ntfn: None,
        service_ep: None,
        cnode: None,
        cnode_bits: None,
    };
    let comp = component::create(
        &args, alloc, &mut arena, win,
        &mut |alloc, vspace| asids.assign(alloc, vspace), &info.spawn_context(0),
    );
    #[cfg(target_arch = "x86_64")]
    comp.give(serial::SLOT_UART, crate::component::root_cap::<cap_type::Unspecified>(uart.out as usize), sel4::CapRights::all());
    let keep = arena.object_cap::<cap_type::CNode>(alloc, sel4::ObjectBlueprint::CNode { size_bits: keep_bits });
    let mut next = 0;
    let mut map = |alloc: &mut Alloc, arena: &mut Arena, frames: Range<Slot>, va: usize, attrs| {
        for (i, s) in frames.enumerate() {
            let k = keep.absolute_cptr_from_bits_with_depth(next, keep_bits);
            next += 1;
            comp.map_copy(alloc, arena, &abs_of(crate::devmem::granule(s)), va + i * PAGE,
                sel4::CapRights::read_write(), attrs, k);
        }
    };
    for k in 1..serial::MAX_RINGS {
        if let Some(f) = rings.serial(k) {
            map(alloc, &mut arena, f, serial::RINGS_VA + k * serial::PAGES * PAGE, sel4::VmAttributes::DEFAULT);
        }
        if let Some(f) = rings.kernel(k) {
            map(alloc, &mut arena, f, serial::KERNEL_RINGS_VA + k * serial::KERNEL_RING_STRIDE, sel4::VmAttributes::DEFAULT);
        }
    }
    if let Some(f) = fb {
        map(alloc, &mut arena, f.frames, serial::FB_VA, crate::dashboard::write_combining());
    }
    #[cfg(target_arch = "aarch64")]
    map(alloc, &mut arena, uart.out as Slot..uart.out as Slot + 1, serial::UART_VA, sel4::VmAttributes::EXECUTE_NEVER);
    component::start(&comp);
    Some(Logd { comp, _arena: arena })
}

/// The machine is about to reset: let logd finish what is in the ring. Root
/// outranks it on this core, so this sleeps, on the timer the main loop uses.
pub fn before_reset(h: &Host) {
    if h.logd.is_none() {
        return;
    }
    let tick = h.info.tsc_hz / 1000 * DRAIN_POLL_MS;
    let end = host::ticks::now() + h.info.tsc_hz * DRAIN_SECS;
    while !crate::SERIAL.is_drained() && host::ticks::now() < end {
        crate::set_timer(host::ticks::now() + tick);
        h.ntfn.wait();
    }
}

/// Fault logd, for tests/run-logdtest.sh.
pub fn inject_fault(h: &Host) {
    if let Some(l) = &h.logd {
        let mut regs = sel4::UserContext::default();
        let _ = l.comp.tcb.tcb_write_all_registers(true, &mut regs);
    }
}
