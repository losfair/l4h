//! The machine l4h-hvm's threads share (DESIGN.md §5.11): guest RAM, the
//! local APICs' requests (lock-free), the I/O APIC and the legacy devices
//! (under locks only vCPU threads take), the ACPI fixed hardware and the
//! virtio notifications (lock-free), and the console's output ring.
//!
//! Interrupt lines are levels in an atomic word (`lines`).  A vCPU thread
//! that changes one applies it to the I/O APIC at once; the I/O thread,
//! which takes no lock (sync.rs), marks the I/O APIC out of date and wakes
//! vCPU 0, which applies it at its next turn, as it does input for the
//! UART.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use l4h_rt::host::hvm::{self as hv, HvmConfig};

use crate::console::Output;
use crate::dev::apic::{self, Message};
use crate::dev::ioapic::IoApic;
use crate::dev::pit::Pit;
use crate::dev::pm::Pm;
use crate::dev::rtc::Rtc;
use crate::dev::uart::Uart;
use crate::dev::virtio_pci::Kicks;
use crate::guest::GuestMem;
use crate::sync::{Global, SpinLock};
pub use crate::sys::{me, now, set_me, signal_io};

pub struct Vm {
    pub cfg: &'static HvmConfig,
    pub tsc_hz: u64,
    pub vcpus: usize,
    /// AMD-V rather than VT-x (the host CPU's vendor, as seL4 chooses).
    pub amd: bool,
    pub mem: GuestMem,
    pub apics: [apic::Shared; hv::MAX_VCPUS],
    pub kicks: Kicks,
    /// Each PCI slot's BAR0 while its memory decoding is on (0: off), as
    /// the I/O thread last saw it: where vCPUs find notifications.
    pub bar0: [AtomicU64; 32],
    pub ioapic: SpinLock<IoApic>,
    pub lines: AtomicU32,
    pub ioapic_stale: AtomicBool,
    pub uart: SpinLock<Uart>,
    pub uart_stale: AtomicBool,
    pub pit: SpinLock<Pit>,
    pub rtc: SpinLock<Rtc>,
    pub pm: Pm,
    /// The legacy PCI configuration address (0xcf8).
    pub cf8: AtomicU32,
    pub console: Output,
    /// Where vCPU 0 starts (boot.rs), once the I/O thread loaded the kernel.
    pub entry: crate::boot::Entry,
    pub xcr0: u64,
    pub invpcid: AtomicBool,
}

pub static VM: Global<Vm> = Global::new();

/// The ACPI tables, written into guest RAM at boot.
static ACPI: crate::sync::Owned<[u8; (crate::acpi::END - crate::acpi::RSDP) as usize]> =
    crate::sync::Owned::new([0; (crate::acpi::END - crate::acpi::RSDP) as usize]);

/// Why the machine cannot be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// The kernel image is none we boot.
    Kernel(crate::boot::Error),
    /// No RAM for the ACPI tables.
    Acpi,
    /// Its pieces, the initrd and the boot structures do not fit.
    Load(crate::boot::Error),
}

/// Make the machine (once, on the I/O thread, before any vCPU runs): load
/// the kernel dom0 put in RAM with its boot parameters, write the ACPI
/// tables, and publish the shared state as VM.
pub fn build(cfg: &'static HvmConfig, tsc_hz: u64, mem: GuestMem, amd: bool, xcr0: u64) -> Result<(), BuildError> {
    let vcpus = (cfg.nr_vcpus as usize).clamp(1, hv::MAX_VCPUS);
    let kernel = crate::boot::Kernel::parse(&mem, cfg.kernel_gpa, cfg.kernel_size).map_err(BuildError::Kernel)?;
    let tables = unsafe { ACPI.get() };
    crate::acpi::build(vcpus, tables);
    if !mem.write_bytes(crate::acpi::RSDP, &tables[..]) {
        return Err(BuildError::Acpi);
    }
    let entry = crate::boot::load(&mem, &kernel, (cfg.kernel_gpa, cfg.kernel_size), (cfg.initrd_gpa, cfg.initrd_size), &cfg.cmdline,
        crate::acpi::RSDP).map_err(BuildError::Load)?;
    VM.set(Vm {
        cfg,
        tsc_hz,
        vcpus,
        amd,
        mem,
        apics: core::array::from_fn(|v| apic::Shared::new(v as u32)),
        kicks: Kicks::new(),
        bar0: [const { AtomicU64::new(0) }; 32],
        ioapic: SpinLock::new(IoApic::new()),
        lines: AtomicU32::new(0),
        ioapic_stale: AtomicBool::new(false),
        uart: SpinLock::new(Uart::new()),
        uart_stale: AtomicBool::new(false),
        pit: SpinLock::new(Pit::new(tsc_hz)),
        rtc: SpinLock::new(Rtc::new(cfg.epoch_ns, cfg.epoch_ticks, tsc_hz)),
        pm: Pm::new(),
        cf8: AtomicU32::new(0),
        console: Output::new(),
        entry,
        xcr0,
        invpcid: AtomicBool::new(false),
    });
    Ok(())
}

pub fn vm() -> &'static Vm {
    VM.get()
}

/// Wake vCPU `v`'s thread: out of seL4_VMEnter, or out of HLT.
pub fn wake(v: usize) {
    if me() != Some(v) {
        crate::sys::wake(v);
    }
}

impl Vm {
    /// Deliver an interrupt message.
    pub fn deliver(&self, m: &Message) {
        apic::deliver(&self.apics[..self.vcpus], m, me(), wake);
    }

    /// Set interrupt line (I/O APIC pin) `pin` to `level`.
    pub fn set_line(&self, pin: usize, level: bool) {
        let bit = 1u32 << pin;
        let old = if level { self.lines.fetch_or(bit, Ordering::SeqCst) } else { self.lines.fetch_and(!bit, Ordering::SeqCst) };
        if (old & bit != 0) == level {
            return;
        }
        self.ioapic_stale.store(true, Ordering::SeqCst);
        match me() {
            Some(_) => self.sync_ioapic(),
            None => wake(0),
        }
    }

    /// Bring the I/O APIC up to date with the lines (a vCPU thread).
    pub fn sync_ioapic(&self) {
        if !self.ioapic_stale.swap(false, Ordering::SeqCst) {
            return;
        }
        let mut io = self.ioapic.lock();
        io.set_lines(self.lines.load(Ordering::SeqCst), &mut |m| self.deliver(&m));
    }

    /// A local APIC ended level-triggered interrupt `vector`.
    pub fn eoi(&self, vector: u8) {
        let mut io = self.ioapic.lock();
        io.eoi(vector, &mut |m| self.deliver(&m));
    }

    /// The UART's interrupt line, after its state or input changed (a vCPU
    /// thread).
    pub fn sync_uart(&self) {
        self.uart_stale.store(false, Ordering::SeqCst);
        let level = {
            let mut u = self.uart.lock();
            u.irq(&mut crate::console::Input)
        };
        self.set_line(crate::dev::uart::IRQ, level);
    }

    /// What the I/O thread left for a vCPU (vCPU 0).
    pub fn pending_work(&self) {
        if self.uart_stale.load(Ordering::SeqCst) {
            self.sync_uart();
        }
        self.sync_ioapic();
    }

    /// The SCI's level, after the ACPI registers changed.
    pub fn sync_sci(&self) {
        self.set_line(crate::dev::pm::SCI_IRQ, self.pm.sci());
    }
}
