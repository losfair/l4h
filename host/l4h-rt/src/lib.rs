//! Runtime for l4h host components spawned by root or vmmgr.
//!
//! A component provides `fn component_main(info: &'static Info) -> !` and
//! invokes `l4h_rt::component!(component_main, no_heap)` (or `heap_size = N`
//! where an allocator is truly needed, DESIGN.md §10).  Its parent starts the
//! component at its ELF entry with the stack set up (see l4h-host for the
//! address-space layout).
//!
//! This crate owns entry, TLS and IPC-buffer setup, panic handling, keeper
//! threads, the optional heap, and common runtime conveniences. Protocols
//! and layouts belong in `l4h-host`. Components that allocate kernel objects,
//! construct address spaces, or load tasks can also use `l4h-task`; the two
//! libraries are independent. See DESIGN.md §10 for the shared crate boundaries.

#![no_std]
#![feature(thread_local)]

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

// Each thread has its own TLS image. Panic recovery must use the TCB
// actually executing it, including a keeper that panics during handoff.
#[thread_local]
static THREAD_TCB: core::cell::Cell<u64> = core::cell::Cell::new(host::SLOT_TCB);

pub use l4h_host as host;
pub use l4h_ipc as ipc;
pub use sel4;

#[doc(hidden)]
pub use one_shot_mutex;
#[doc(hidden)]
pub use sel4_dlmalloc;
#[doc(hidden)]
pub use sel4_panicking;
#[doc(hidden)]
pub use sel4_panicking_env;
#[doc(hidden)]
pub use sel4_runtime_common;

mod failure;
pub mod ioport;
pub mod mailbox;

pub use failure::{FailureHandler, set_failure_handler};

/// Limits a recurring critical error (such as failed I/O) to its first few
/// prints: the serial port is slow.
pub struct ErrorLimit(u32);

impl ErrorLimit {
    const MAX: u32 = 8;

    pub const fn new() -> Self {
        ErrorLimit(0)
    }

    /// Whether to print this occurrence; the last one printed says so.
    pub fn allow(&mut self) -> bool {
        self.0 = self.0.saturating_add(1);
        if self.0 == Self::MAX {
            log!("(further errors of this kind are not printed)");
        }
        self.0 <= Self::MAX
    }
}

/// An informational message: retained and queued for logd in every build.
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::print_log(format_args!($($arg)*))
    };
}

/// A critical diagnostic: retained and also printed to serial.
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { $crate::print_log(format_args!($($arg)*)) };
}

#[doc(hidden)]
pub fn print_log(args: core::fmt::Arguments<'_>) {
    host::log::record(args);
    host::serial::record(args);
}

/// Text panicking prints outside `log!`, gathered by line: a thread that
/// panics while another does can only garble this text.
static PANIC_LINE: [AtomicU8; 120] = [const { AtomicU8::new(0) }; 120];
static PANIC_LEN: AtomicUsize = AtomicUsize::new(0);

fn panic_flush() {
    let n = PANIC_LEN.swap(0, Ordering::Relaxed).min(PANIC_LINE.len());
    let line: [u8; 120] = core::array::from_fn(|i| PANIC_LINE[i].load(Ordering::Relaxed));
    host::serial::write(0, &line[..n], false);
}

/// What the panic machinery prints with.
#[doc(hidden)]
pub fn panic_put_char(c: u8) {
    if c == b'\n' {
        return panic_flush();
    }
    let n = PANIC_LEN.fetch_add(1, Ordering::Relaxed);
    if n < PANIC_LINE.len() {
        PANIC_LINE[n].store(c, Ordering::Relaxed);
    }
    if n + 1 >= PANIC_LINE.len() {
        panic_flush();
    }
}

use l4h_host::{CONFIG_OFFSET, INFO_MAGIC, INFO_VA, IPCBUF_VA, InfoHeader};

/// The component info page.
pub struct Info {
    _private: (),
}

impl Info {
    pub fn header(&self) -> &InfoHeader {
        unsafe { &*(INFO_VA as *const InfoHeader) }
    }

    /// Kind-specific configuration.
    ///
    /// # Safety
    /// `T` must be the configuration type l4h-root wrote for this kind.
    pub unsafe fn config<T>(&self) -> &T {
        unsafe { &*((INFO_VA + CONFIG_OFFSET) as *const T) }
    }
}

static INFO: Info = Info { _private: () };

/// A deadline `ms` milliseconds from now, by the host's tick counter
/// (host::ticks, at the rate root gave this component): the closure says
/// whether it has passed.  For a driver's wait on its device, which must
/// end whatever the device does.  An unknown rate is taken as 1 GHz, so
/// that the wait stays finite.
pub fn timeout_ms(ms: u64) -> impl FnMut() -> bool {
    let hz = match INFO.header().tsc_hz {
        0 => 1_000_000_000,
        hz => hz,
    };
    let end = host::ticks::now().saturating_add((hz / 1000).max(1).saturating_mul(ms));
    move || host::ticks::now() > end
}

#[doc(hidden)]
pub fn init() -> &'static Info {
    unsafe {
        sel4::set_ipc_buffer((IPCBUF_VA as *mut sel4::IpcBuffer).as_mut().unwrap());
    }
    assert_eq!(INFO.header().magic, INFO_MAGIC, "bad component info page");
    // The lanes the parent mapped at log::VA and serial::VA, and their sizes.
    let (log, serial) = host::log::info_records(INFO.header().reserved[host::log::LANES_INFO]);
    host::log::init_lane(log);
    host::serial::init_lane(serial);
    sel4_panicking::set_hook(&|info| log!("l4h-rt: component {:#x}: {}", INFO.header().id, info));
    audit(INFO.header().kind);
    if host::has_keeper(INFO.header().kind) {
        start_keeper();
    }
    &INFO
}

/// Stop if this component holds a capability that calls or signals which
/// the wiring does not give it, or of another type (debug builds: seL4's
/// DebugCapIdentify; DESIGN.md §10, "Wiring declarations").  The slots of
/// the layout are looked at: memd's and vmmgr's larger CNodes hold memory
/// above them.
fn audit(kind: u32) {
    sel4::sel4_cfg_if! {
        if #[sel4_cfg(DEBUG_BUILD)] {
            // The parent checks VMM copies and edges while installing
            // them: the CPU guard may revoke our debug authority even
            // before this startup audit would finish.
            if !host::AUDIT || kind == host::KIND_VMM {
                return;
            }
            for slot in 0..1u64 << host::CNODE_BITS {
                let tag = cap::<sel4::cap_type::Null>(slot).debug_identify();
                if let Err(why) = host::wiring::audit(kind, slot, tag) {
                    panic!("wiring audit: slot {} holds a capability (tag {}) {}", slot, tag, why);
                }
            }
        } else {
            let _ = kind;
        }
    }
}

#[repr(align(64))]
struct KeeperTlsAlign;

static KEEPER_TLS: sel4_initialize_tls::StaticTlsAllocation<4096, KeeperTlsAlign> =
    sel4_initialize_tls::StaticTlsAllocation::new();

/// Start the keeper (host::SLOT_KEEPER) on its own stack (at
/// host::KEEPER_STACK_TOP, which l4h-root maps), TLS and IPC buffer: it
/// shares nothing with this thread.
fn start_keeper() {
    unsafe { start_secondary(host::SLOT_KEEPER, host::KEEPER_STACK_TOP, keeper) };
}

/// Start the component's one secondary thread on its own TLS and stack.
///
/// # Safety
/// Call only once, with a suspended TCB and a mapped stack. The entry
/// must install that thread's IPC buffer before making any seL4 call.
pub unsafe fn start_secondary(slot: u64, top: usize, entry: extern "C" fn() -> !) {
    let phdr = sel4_phdrs::locate_phdrs()
        .ok()
        .and_then(|p| p.find_by_type(sel4_phdrs::PT_TLS))
        .expect("keeper: no TLS image");
    let image = sel4_initialize_tls::UncheckedTlsImage {
        vaddr: phdr.p_vaddr,
        filesz: phdr.p_filesz,
        memsz: phdr.p_memsz,
        align: phdr.p_align,
    }
    .check()
    .expect("keeper: bad TLS image");
    let tp = unsafe { image.initialize_inexact_reservation_region(&KEEPER_TLS.region()) }.expect("keeper TLS space");
    let k = cap::<sel4::cap_type::Tcb>(slot);
    let mut regs = sel4::UserContext::default();
    *regs.pc_mut() = entry as *const () as u64;
    // As if called: x86-64 expects a return address pushed.
    *regs.sp_mut() = (if cfg!(target_arch = "x86_64") { top - 8 } else { top }) as u64;
    k.tcb_write_all_registers(false, &mut regs).expect("keeper registers");
    // After the registers, which include the TLS base.
    k.tcb_set_tls_base(tp as u64).expect("keeper TLS");
    k.tcb_resume().expect("keeper start");
}

/// The keeper: wait for the main thread to fault (its fault is never
/// answered), and answer for it.  It receives one fault, and serves
/// nothing: no l4h_ipc::run.
#[allow(clippy::disallowed_methods)]
extern "C" fn keeper() -> ! {
    THREAD_TCB.set(host::SLOT_KEEPER);
    unsafe {
        sel4::set_ipc_buffer((host::KEEPER_IPCBUF_VA as *mut sel4::IpcBuffer).as_mut().unwrap());
    }
    let reply = cap::<sel4::cap_type::Reply>(host::SLOT_KEEPER_REPLY);
    let (info, _) = cap::<sel4::cap_type::Endpoint>(host::SLOT_FAULT_EP).recv(reply);
    let fault = sel4::with_ipc_buffer(|b| sel4::Fault::new(b, &info));
    log!("l4h-rt: component {:#x} fault: {:x?}", INFO.header().id, fault);
    failure::answer_failed(host::SLOT_KEEPER)
}

pub fn cap<T: sel4::CapType>(slot: u64) -> sel4::Cap<T> {
    sel4::Cap::from_bits(slot)
}

/// Stop for good, without failing: for tests of what waits for a
/// component that does not answer.  The thread suspends itself, so it
/// takes no CPU time either.
pub fn test_hang() -> ! {
    log!("l4h-rt: component {:#x} hangs (injected)", INFO.header().id);
    let _ = cap::<sel4::cap_type::Tcb>(host::SLOT_TCB).tcb_suspend();
    unreachable!("a suspended thread ran");
}

/// Where an aborted component ends.  l4h-root calls memd and guests' VMMs
/// call vmmgr, and could not wait for their faults to be reported: one of
/// those that has failed keeps answering on its service endpoint (a fault,
/// its keeper does).  Any other component faults, which its parent
/// handles.
#[doc(hidden)]
pub fn abort_trap() -> ! {
    let h = INFO.header();
    panic_flush();
    log!("l4h-rt: component {:#x} aborted", h.id);
    if h.magic == INFO_MAGIC && host::has_keeper(h.kind) {
        failure::answer_failed(THREAD_TCB.get());
    }
    loop {
        unsafe {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("ud2");
            #[cfg(target_arch = "aarch64")]
            core::arch::asm!("udf #0");
        }
    }
}

/// The allocator of a component without a heap (`component!(main,
/// no_heap)`): every allocation fails, which aborts.  The component
/// itself cannot allocate, since it does not link `alloc`; this only
/// satisfies the runtime's crates.
#[doc(hidden)]
pub struct NoHeap;

unsafe impl core::alloc::GlobalAlloc for NoHeap {
    unsafe fn alloc(&self, _: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {}
}

#[macro_export]
macro_rules! component {
    (@entry $main:path) => {
        $crate::sel4_panicking_env::register_debug_put_char!($crate::panic_put_char);
        $crate::sel4_panicking_env::register_abort_trap!($crate::abort_trap);

        // The stack l4h-root maps, with a guard below it, rather than one
        // in .bss (declare_stack!): the entry point loads this word.
        #[unsafe(no_mangle)]
        static __sel4_runtime_common__stack_bottom: usize = $crate::host::STACK_TOP;
        $crate::sel4_runtime_common::declare_entrypoint_with_stack_init!();
        $crate::sel4_runtime_common::declare_rust_entrypoint! {
            __l4h_component_entrypoint()
        }

        fn __l4h_component_entrypoint() -> ! {
            let info = $crate::init();
            match $crate::sel4_panicking::catch_unwind(|| $main(info)) {
                #[allow(unreachable_patterns)]
                Ok(never) => never,
                Err(_) => $crate::sel4_panicking_env::abort!("component main() panicked"),
            }
        }
    };
    ($main:path, no_heap) => {
        #[global_allocator]
        static GLOBAL_ALLOCATOR: $crate::NoHeap = $crate::NoHeap;

        $crate::component!(@entry $main);
    };
    ($main:path, heap_size = $heap:expr) => {
        const _: () = {
            use $crate::sel4_dlmalloc::{StaticDlmalloc, StaticHeap};

            const HEAP_SIZE: usize = $heap;
            static STATIC_HEAP: StaticHeap<HEAP_SIZE> = StaticHeap::new();

            #[global_allocator]
            static GLOBAL_ALLOCATOR: StaticDlmalloc<
                $crate::one_shot_mutex::sync::RawOneShotMutex,
            > = StaticDlmalloc::new(STATIC_HEAP.bounds());
        };

        $crate::component!(@entry $main);
    };
}
