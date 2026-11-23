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

/// Where the PCI devices' BARs start.
pub const PCI_MMIO_BASE: u64 = hv::PCI_MMIO_BASE;

/// What the host CPU gives the guest, as its CPUID shows it.
#[derive(Clone, Copy, Debug)]
pub struct Host {
    /// AMD-V rather than VT-x (the vendor, as seL4 chooses).
    pub amd: bool,
    /// The XCR0 features the guest may enable.
    pub xcr0: u64,
    /// PCIDs (CPUID 1 ECX bit 17), which CR4.PCIDE needs.
    pub pcid: bool,
    /// Physical-address bits (CPUID 0x8000_0008, x86::cpuid's clamp).
    pub phys_bits: u32,
    /// AMD's Automatic IBRS (CPUID 0x8000_0021 EAX bit 8): a guest may set
    /// EFER.AIBRSE, which the VMCB holds for it.
    pub auto_ibrs: bool,
}

impl Host {
    /// From the host's CPUID.
    pub fn of(cpuid: &impl Fn(u32, u32) -> [u32; 4]) -> Host {
        let ext = cpuid(0x8000_0000, 0)[0];
        let phys = if ext >= 0x8000_0008 { cpuid(0x8000_0008, 0)[0] & 0xff } else { 36 };
        Host {
            amd: cpuid(0, 0)[1] == u32::from_le_bytes(*b"Auth"),
            xcr0: crate::x86::cpuid::xcr0_supported(cpuid),
            pcid: cpuid(1, 0)[2] & (1 << 17) != 0,
            phys_bits: phys.min(crate::x86::cpuid::MAX_PHYS_BITS),
            auto_ibrs: ext >= 0x8000_0021 && cpuid(0x8000_0021, 0)[0] & crate::x86::cpuid::AUTO_IBRS != 0,
        }
    }
}

pub struct Vm {
    pub cfg: &'static HvmConfig,
    pub host: Host,
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
    /// The slots asserting INTA#, a bit each (the I/O thread's only).
    intx: AtomicU32,
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
    /// The guest has PCIDs (CPUID 1 ECX bit 17: the host's).
    pub pcid: AtomicBool,
    /// kvmclock (x86/pvclock.rs): its time 0 in the host's TSC, the scale
    /// to nanoseconds, and the wall time then (ns since 1970).
    pub clock_base: u64,
    pub clock_scale: (u32, i8),
    pub wall_base_ns: u64,
    /// The version of kvmclock's wall clock, one for the VM as Linux has
    /// one structure (vcpu.rs, publish_wall_clock).
    pub wall_version: SpinLock<u32>,
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

/// The wall time at host TSC `t`, in ns since 1970: `epoch_ns` at TSC
/// `epoch_ticks` (0 if unknown: 2000-01-01, as the RTC has it).
pub fn wall_ns(epoch_ns: u64, epoch_ticks: u64, tsc_hz: u64, t: u64) -> u64 {
    let epoch = if epoch_ns == 0 { 946_684_800_000_000_000 } else { epoch_ns as i128 };
    let d = (t as i128 - epoch_ticks as i128) * 1_000_000_000 / tsc_hz.max(1) as i128;
    (epoch as i128 + d).max(0) as u64
}

/// Make the machine (once, on the I/O thread, before any vCPU runs): load
/// the kernel dom0 put in RAM with its boot parameters, write the ACPI
/// tables, and publish the shared state as VM.
pub fn build(cfg: &'static HvmConfig, tsc_hz: u64, mem: GuestMem, host: Host) -> Result<(), BuildError> {
    let (amd, xcr0) = (host.amd, host.xcr0);
    let vcpus = (cfg.nr_vcpus as usize).clamp(1, hv::MAX_VCPUS);
    let kernel = crate::boot::Kernel::parse(&mem, cfg.kernel_gpa, cfg.kernel_size).map_err(BuildError::Kernel)?;
    let tables = unsafe { ACPI.get() };
    crate::acpi::build(vcpus, tables);
    if !mem.write_bytes(crate::acpi::RSDP, &tables[..]) {
        return Err(BuildError::Acpi);
    }
    let entry = crate::boot::load(&mem, &kernel, (cfg.kernel_gpa, cfg.kernel_size), (cfg.initrd_gpa, cfg.initrd_size), &cfg.cmdline,
        crate::acpi::RSDP).map_err(BuildError::Load)?;
    let t0 = now();
    VM.set(Vm {
        cfg,
        host,
        tsc_hz,
        vcpus,
        amd,
        mem,
        apics: core::array::from_fn(|v| apic::Shared::new(v as u32)),
        kicks: Kicks::new(),
        bar0: [const { AtomicU64::new(0) }; 32],
        ioapic: SpinLock::new(IoApic::new()),
        lines: AtomicU32::new(0),
        intx: AtomicU32::new(0),
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
        clock_base: t0,
        clock_scale: crate::x86::pvclock::time_scale(tsc_hz),
        wall_base_ns: wall_ns(cfg.epoch_ns, cfg.epoch_ticks, tsc_hz, t0),
        wall_version: SpinLock::new(0),
        pcid: AtomicBool::new(host.pcid),
    });
    Ok(())
}

pub fn vm() -> &'static Vm {
    VM.get()
}

/// What the guest runs on, for the log.
pub fn platform() -> &'static str {
    if vm().amd { "AMD-V" } else { "VT-x" }
}

/// Where vCPU 0 starts, for the log.
pub fn entry_pc() -> u64 {
    vm().entry.rip
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

    /// An MSI-X message a device sent (the I/O thread).
    pub fn msi(&self, addr: u64, data: u32) {
        if let Some(m) = Message::msi(addr, data) {
            self.deliver(&m);
        }
    }

    /// Slot `slot`'s INTA#, which shares a GSI with others (the I/O thread).
    pub fn set_intx(&self, slot: usize, level: bool) {
        let bit = 1u32 << slot;
        let asserted = if level { self.intx.fetch_or(bit, Ordering::Relaxed) | bit } else { self.intx.fetch_and(!bit, Ordering::Relaxed) & !bit };
        let gsi = crate::dev::pci::intx_gsi(slot, 1);
        self.set_line(gsi, crate::dev::pci::intx_level(asserted, gsi));
    }

    /// dom0 asked to shut the guest down: its ACPI does when it sees the
    /// power button (it sees it once it enables the event).
    pub fn power_button(&self) {
        if self.pm.power_button() {
            self.sync_sci();
        }
    }

    /// vmmgr wrote console input: vCPU 0 gives it to the UART.
    pub fn console_input(&self) {
        self.uart_stale.store(true, Ordering::SeqCst);
        wake(0);
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

    /// The UART's interrupt line, after its input changed (a vCPU thread).
    pub fn sync_uart(&self) {
        self.uart(|_, _| ());
    }

    /// Use the UART (a vCPU thread), and set its interrupt line as its
    /// state is then: under its lock, so that lines follow states in
    /// order (the lock order is the UART's, then the I/O APIC's; the I/O
    /// thread takes neither).
    pub fn uart<R>(&self, f: impl FnOnce(&mut Uart, &mut crate::console::Input) -> R) -> R {
        let mut u = self.uart.lock();
        self.uart_stale.store(false, Ordering::SeqCst);
        let r = f(&mut u, &mut crate::console::Input);
        let level = u.irq(&mut crate::console::Input);
        self.set_line(crate::dev::uart::IRQ, level);
        r
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
