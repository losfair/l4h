//! Runtime for l4h host components spawned by root or vmmgr.
//!
//! A component provides `fn component_main(info: &'static Info) -> !` and
//! invokes `l4h_rt::component!(component_main, no_heap)` (or `heap_size = N`
//! where an allocator is truly needed, DESIGN.md §9).  Its parent starts the
//! component at its ELF entry with the stack set up (see l4h-host for the
//! address-space layout).
//!
//! This crate owns entry, TLS and IPC-buffer setup, panic handling, keeper
//! threads, the optional heap, and common runtime conveniences. Protocols
//! and layouts belong in `l4h-host`. Components that allocate kernel objects,
//! construct address spaces, or load tasks can also use `l4h-task`; the two
//! libraries are independent. See DESIGN.md §9 for the shared crate boundaries.

#![no_std]

pub use l4h_host as host;
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

pub mod ioport;

/// Limits a recurring critical error (such as failed I/O) to its first few
/// prints: each one is a synchronous kernel print (see `host::VERBOSE`).
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
            sel4::debug_println!("(further errors of this kind are not printed)");
        }
        self.0 <= Self::MAX
    }
}

/// An informational message: printed only when `host::VERBOSE` (not in
/// release builds).  Use `sel4::debug_println!` for critical errors only.
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        if $crate::host::VERBOSE {
            $crate::sel4::debug_println!($($arg)*);
        }
    };
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

#[doc(hidden)]
pub fn init() -> &'static Info {
    unsafe {
        sel4::set_ipc_buffer((IPCBUF_VA as *mut sel4::IpcBuffer).as_mut().unwrap());
    }
    assert_eq!(INFO.header().magic, INFO_MAGIC, "bad component info page");
    if host::has_keeper(INFO.header().kind) {
        start_keeper();
    }
    &INFO
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
/// answered), and answer for it.
extern "C" fn keeper() -> ! {
    unsafe {
        sel4::set_ipc_buffer((host::KEEPER_IPCBUF_VA as *mut sel4::IpcBuffer).as_mut().unwrap());
    }
    let reply = cap::<sel4::cap_type::Reply>(host::SLOT_KEEPER_REPLY);
    let (info, _) = cap::<sel4::cap_type::Endpoint>(host::SLOT_FAULT_EP).recv(reply);
    let fault = sel4::with_ipc_buffer(|b| sel4::Fault::new(b, &info));
    sel4::debug_println!("l4h-rt: component {:#x} fault: {:x?}", INFO.header().id, fault);
    answer_failed()
}

/// Answer the callers of a failed component: u64::MAX and zeros to every
/// call, the one the main thread's reply object holds (if any) first.
/// Faults sent to it (vmmgr's guests' and VMMs') stay unanswered.
fn answer_failed() -> ! {
    let ep = cap::<sel4::cap_type::Endpoint>(host::SLOT_SERVICE_EP);
    let reply = cap::<sel4::cap_type::Reply>(host::SLOT_REPLY);
    let mut answer = true;
    loop {
        let (_, badge) = if answer {
            sel4::with_ipc_buffer_mut(|b| {
                let m = b.msg_regs_mut();
                m[0] = u64::MAX;
                m[1..8].fill(0);
            });
            ep.reply_recv(sel4::MessageInfo::new(0, 0, 0, 8), reply)
        } else {
            ep.recv(reply)
        };
        answer = badge & host::BADGE_FAULT == 0;
    }
}

pub fn cap<T: sel4::CapType>(slot: u64) -> sel4::Cap<T> {
    sel4::Cap::from_bits(slot)
}

/// Where an aborted component ends.  l4h-root calls blkd, netd and memd
/// synchronously, and guests' VMMs call vmmgr, and could not wait for
/// their faults to be reported: one that has failed keeps answering on its
/// service endpoint (a fault, its keeper does).  Any other component
/// faults, which root handles.
#[doc(hidden)]
pub fn abort_trap() -> ! {
    let h = INFO.header();
    if h.magic == INFO_MAGIC && host::has_keeper(h.kind) {
        answer_failed();
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
        $crate::sel4_panicking_env::register_debug_put_char!($crate::sel4::debug_put_char);
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
