//! l4h-logd, the only host writer to the serial port (DESIGN.md §10.4):
//! the UART's port capability, spawning it, and printing in its place.
//!
//! Root is logd's fault handler, and the way out when it cannot print:
//! when root itself panics or the machine is about to reset, root stops
//! logd and prints what it had not; if logd faults, root prints from where
//! it left off, a little on every timer tick.
//!
//! Only partition 0 has the port. Other partitions' host code prints to
//! rings that partition 0's logd reads, kernels' console rings included.

use core::ops::Range;
use core::sync::atomic::{AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use l4h_host as host;
use l4h_host::serial::{self, Line, LogdConfig, Merge};
use sel4::cap_type;
use sel4::init_thread::slot;

use crate::Host;
use crate::component::{self, Component, SpawnArgs, abs_of, root_cap};
use crate::mem::{Arena, Slot};

pub const LOGD_ID: u32 = 0x600;
static LOGD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-logd.elf"));

const COM1: u16 = 0x3f8;
const LSR: u16 = 5;
const LSR_THRE: u8 = 0x20;
/// What a thread about to stop the machine prints of a ring, at most: about
/// a second of the port, if the lines are short.
const FLUSH_RECORDS: u64 = 256;
/// logd's share of a core: a VM's UART takes output as fast as it comes.
const BUDGET_US: u64 = 1000;
const PERIOD_US: u64 = 5000;
const PAGE: usize = 4096;
/// A timer tick's worth of printing for a dead logd.
const TAKEOVER_US: u64 = 1000;

/// The empty slots `reserve` kept for the port capabilities.
static SLOTS: AtomicUsize = AtomicUsize::new(0);
/// The capability and base of the port host output goes to: 0 if none.
static PORT: AtomicU64 = AtomicU64::new(0);
static BASE: AtomicU16 = AtomicU16::new(0);
/// Root's IPC buffer. A panic can come while the safe way to it is held.
static IPC: AtomicPtr<sel4::IpcBuffer> = AtomicPtr::new(core::ptr::null_mut());
static LOGD_TCB: AtomicU64 = AtomicU64::new(0);
static RINGS: AtomicU32 = AtomicU32::new(0);
static KERNEL_RINGS: AtomicU32 = AtomicU32::new(0);

/// Note root's IPC buffer, and keep two slots out of `empty`: a panic may
/// come before there is an allocator. Returns the slots left.
pub fn reserve(bootinfo: &sel4::BootInfoPtr, empty: Range<usize>) -> Range<usize> {
    IPC.store(bootinfo.ipc_buffer(), Ordering::Relaxed);
    SLOTS.store(empty.start, Ordering::Relaxed);
    empty.start + 2..empty.end
}

fn ipc() -> &'static mut sel4::IpcBuffer {
    // Set first thing, and the root task is single-threaded: at worst this
    // overlaps a borrow that a panic interrupted, which is done with.
    unsafe { &mut *IPC.load(Ordering::Relaxed) }
}

#[cfg(target_arch = "x86_64")]
fn inb(port: u64, at: u16) -> u8 {
    ipc().inner_mut().seL4_X86_IOPort_In8(port, at).result as u8
}

#[cfg(target_arch = "x86_64")]
fn outb(port: u64, at: u16, v: u8) {
    ipc().inner_mut().seL4_X86_IOPort_Out8(port, at as u64, v as u64);
}

#[cfg(target_arch = "x86_64")]
fn issue(slot_index: usize, base: u16) -> Option<u64> {
    let dst = abs_of(sel4::init_thread::Slot::<cap_type::Null>::from_index(slot_index).cap());
    slot::IO_PORT_CONTROL.cap().ioport_control_issue(base as u64, base as u64 + 7, &dst).ok()?;
    Some(slot_index as u64)
}

/// The port at `base`, which the serial monitor also uses (`port`, `base`
/// of what this returns), as host output's. With an absent UART, host output
/// goes to COM1, where the kernel prints unless told otherwise: the setting
/// is the monitor's too, and one can be wrong without losing the log.
#[cfg(target_arch = "x86_64")]
pub fn init_uart(base: u16) -> Option<u64> {
    let slots = SLOTS.load(Ordering::Relaxed);
    let port = issue(slots, base)?;
    let (mut out, mut out_base) = (port, base);
    if inb(port, base + LSR) == 0xff && base != COM1 {
        if let Some(com1) = issue(slots + 1, COM1).filter(|&p| inb(p, COM1 + LSR) != 0xff) {
            (out, out_base) = (com1, COM1);
        }
    }
    BASE.store(out_base, Ordering::Relaxed);
    PORT.store(out, Ordering::Relaxed);
    Some(port)
}

#[cfg(not(target_arch = "x86_64"))]
pub fn init_uart(_base: u16) -> Option<u64> {
    Some(0)
}

/// Print on the port directly, whatever else wants the CPU.
#[cfg(target_arch = "x86_64")]
fn put(bytes: &[u8]) {
    let (port, base) = (PORT.load(Ordering::Relaxed), BASE.load(Ordering::Relaxed));
    if port == 0 {
        return;
    }
    for &c in bytes {
        // A stuck UART must not stop what comes after printing.
        for _ in 0..100_000 {
            if inb(port, base + LSR) & LSR_THRE != 0 {
                break;
            }
        }
        outb(port, base, c);
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn put(_bytes: &[u8]) {}

fn merge(grace: u64) -> Merge {
    let mut m = Merge::new(&crate::SERIAL, grace);
    config(0).add_inputs(&mut m, crate::layout::PARTITION_SERIAL.base, crate::layout::PARTITION_CONSOLES.base);
    m
}

fn config(tsc_hz: u64) -> LogdConfig {
    LogdConfig {
        tsc_hz,
        uart_base: BASE.load(Ordering::Relaxed),
        _pad: 0,
        rings: RINGS.load(Ordering::Relaxed),
        kernel_rings: KERNEL_RINGS.load(Ordering::Relaxed),
        kernel_ring_size: l4h_partition::CONSOLE_RING_SIZE as u32,
        kernel_ring_header: l4h_partition::CONSOLE_RING_HEADER as u32,
        fb_pitch: 0,
        fb_width: 0,
        fb_height: 0,
        fb_offset: 0,
    }
}

/// Stop logd, and print what is left of the rings here and now.
fn flush() {
    let tcb = LOGD_TCB.load(Ordering::Relaxed);
    if tcb != 0 {
        ipc().inner_mut().seL4_TCB_Suspend(tcb);
    }
    let mut m = merge(0);
    m.resume(FLUSH_RECORDS);
    // logd may have stopped in the middle of a line, which comes again.
    put(b"\r\n");
    let mut line = Line::new();
    for _ in 0..serial::MAX_RINGS {
        m.begin_pass();
        while m.next(host::ticks::now(), &mut line) {
            put(line.bytes());
            m.commit();
        }
    }
}

/// Root panicked: `log!` put the message in the ring, and this is the last
/// thing that runs. There may be no port capability yet, if the panic came
/// before the setting that says which port it is.
pub fn panicked() {
    if !host::serial::LOGD || crate::partition::secondary() {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    if PORT.load(Ordering::Relaxed) == 0 {
        if let Some(port) = issue(SLOTS.load(Ordering::Relaxed), COM1) {
            BASE.store(COM1, Ordering::Relaxed);
            PORT.store(port, Ordering::Relaxed);
        }
    }
    flush();
}

/// logd as root keeps it.
pub struct Logd {
    comp: Component,
    _arena: Arena,
    /// logd faulted: what root prints in its place.
    takeover: Option<Takeover>,
}

struct Takeover {
    merge: Merge,
    line: Line,
    sent: usize,
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

/// Spawn logd: partition 0's serial output from now on.
pub fn spawn(h: &mut Host, port: Option<u64>, rings: &crate::partition::Rings, fb: Option<FbArea>) {
    if !host::serial::LOGD || LOGD_ELF.is_empty() {
        return;
    }
    let Some(port) = port else {
        log!("l4h-root: no serial port: nothing prints the host's output");
        return;
    };
    let fb_pages = fb.as_ref().map_or(0, |f| f.frames.len());
    let ring_pages = serial::MAX_RINGS * (serial::PAGES + l4h_partition::CONSOLE_RING_SIZE as usize / PAGE);
    let keep_bits = (fb_pages + ring_pages).next_power_of_two().trailing_zeros() as usize;
    let mut arena = h.alloc
        .arena((4 << 20) + (32 << keep_bits) + ((fb_pages + ring_pages) / 512 + 8) * PAGE)
        .expect("memory for logd");
    RINGS.store(rings.serial_mask(), Ordering::Relaxed);
    KERNEL_RINGS.store(rings.kernel_mask(), Ordering::Relaxed);
    let mut cfg = config(h.info.tsc_hz);
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
        &args, &mut h.alloc, &mut arena, &mut h.wins.a,
        &mut |alloc, vspace| h.asids.assign(alloc, vspace), &h.info.spawn_context(0),
    );
    comp.give(serial::SLOT_UART, root_cap::<cap_type::Unspecified>(port as usize), sel4::CapRights::all());
    let keep = arena.object_cap::<cap_type::CNode>(&mut h.alloc, sel4::ObjectBlueprint::CNode { size_bits: keep_bits });
    let mut next = 0;
    let mut map = |h: &mut Host, arena: &mut Arena, frames: Range<Slot>, va: usize, attrs| {
        for (i, s) in frames.enumerate() {
            let k = keep.absolute_cptr_from_bits_with_depth(next, keep_bits);
            next += 1;
            comp.map_copy(&mut h.alloc, arena, &abs_of(crate::devmem::granule(s)), va + i * PAGE,
                sel4::CapRights::read_write(), attrs, k);
        }
    };
    for k in 1..serial::MAX_RINGS {
        if let Some(f) = rings.serial(k) {
            map(h, &mut arena, f, serial::RINGS_VA + k * serial::PAGES * PAGE, sel4::VmAttributes::DEFAULT);
        }
        if let Some(f) = rings.kernel(k) {
            map(h, &mut arena, f, serial::KERNEL_RINGS_VA + k * serial::KERNEL_RING_STRIDE, sel4::VmAttributes::DEFAULT);
        }
    }
    if let Some(f) = fb {
        map(h, &mut arena, f.frames, serial::FB_VA, crate::dashboard::write_combining());
    }
    component::start(&comp);
    LOGD_TCB.store(comp.tcb.bits(), Ordering::Relaxed);
    h.logd = Some(Logd { comp, _arena: arena, takeover: None });
}

/// Component `id` faulted. If that was logd, root prints from now on.
pub fn fault(h: &mut Host, id: u32) {
    if id != LOGD_ID {
        return;
    }
    LOGD_TCB.store(0, Ordering::Relaxed);
    if let Some(l) = &mut h.logd {
        let mut merge = merge(h.info.tsc_hz / 10);
        merge.resume(u64::MAX);
        l.takeover = Some(Takeover { merge, line: Line::new(), sent: 0 });
    }
}

/// On every timer tick: print for a dead logd, for a bounded time, since
/// this is root's main loop.
pub fn tick(h: &mut Host) {
    let hz = h.info.tsc_hz;
    let Some(t) = h.logd.as_mut().and_then(|l| l.takeover.as_mut()) else { return };
    let end = host::ticks::now() + hz / 1_000_000 * TAKEOVER_US;
    t.merge.begin_pass();
    while host::ticks::now() < end {
        if t.sent == t.line.bytes().len() {
            t.merge.commit();
            t.sent = 0;
            if !t.merge.next(host::ticks::now(), &mut t.line) {
                t.line = Line::new();
                return;
            }
        }
        put(&t.line.bytes()[t.sent..t.sent + 1]);
        t.sent += 1;
    }
}

/// The machine is about to reset: everything on the wire first.
pub fn before_reset() {
    if host::serial::LOGD {
        flush();
    }
}

/// The reset did not happen.
pub fn after_failed_reset(h: &Host) {
    if let Some(l) = h.logd.as_ref().filter(|l| l.takeover.is_none()) {
        let _ = l.comp.tcb.tcb_resume();
    }
}

/// Fault logd, for tests/run-logdtest.sh.
pub fn inject_fault(h: &Host) {
    if let Some(l) = &h.logd {
        let mut regs = sel4::UserContext::default();
        let _ = l.comp.tcb.tcb_write_all_registers(true, &mut regs);
    }
}
