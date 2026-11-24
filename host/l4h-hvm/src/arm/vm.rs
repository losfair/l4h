//! The machine l4h-hvm's threads share on AArch64 (DESIGN.md §5.11): guest
//! RAM, the GIC (atomic: the I/O thread raises interrupts), the power state
//! of each vCPU, the PrimeCell devices under locks only vCPU threads take,
//! the virtio notifications (lock-free), and the console's output ring.
//! What the I/O thread has for a device under a lock (console input, the
//! power button) it leaves to vCPU 0.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use l4h_rt::host::hvm::{self as hv, HvmConfig, arm};

use super::boot::{self, Entry, Kernel};
use super::fdt::Machine;
use super::pl011::Pl011;
use super::pl031::Pl031;
use super::pl061::{PIN_POWER, Pl061};
use super::psci::Power;
use super::vgic::Vgic;
use crate::console::Output;
use crate::dev::virtio_pci::Kicks;
use crate::guest::GuestMem;
use crate::sync::{Global, Owned, SpinLock};
pub use crate::sys::{me, now, set_me, signal_io};

/// Where the PCI devices' BARs start.
pub const PCI_MMIO_BASE: u64 = arm::PCI_MMIO_BASE;

pub struct Vm {
    pub cfg: &'static HvmConfig,
    /// The counter's frequency.
    pub tsc_hz: u64,
    pub vcpus: usize,
    pub mem: GuestMem,
    pub vgic: Vgic,
    pub power: [Power; hv::MAX_VCPUS],
    pub kicks: Kicks,
    /// Each PCI slot's BAR0 while its memory decoding is on (0: off), as
    /// the I/O thread last saw it: where vCPUs find notifications.
    pub bar0: [AtomicU64; 32],
    /// The slots asserting INTA#, a bit each (the I/O thread's only).
    intx: AtomicU32,
    pub uart: SpinLock<Pl011>,
    pub uart_stale: AtomicBool,
    pub rtc: SpinLock<Pl031>,
    pub gpio: SpinLock<Pl061>,
    /// dom0 asked for the power button (the I/O thread, for vCPU 0).
    pub button: AtomicBool,
    pub console: Output,
    /// Where vCPU 0 starts.
    pub entry: Entry,
}

pub static VM: Global<Vm> = Global::new();

/// The device tree, while it is written.
static FDT: Owned<[u8; boot::FDT_MAX]> = Owned::new([0; boot::FDT_MAX]);

/// Why the machine cannot be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// The kernel image is none we boot.
    Kernel(boot::Error),
    /// Its pieces, the initrd and the device tree do not fit.
    Load(boot::Error),
    /// RAM could not be made coherent for the guest.
    Cache,
}

/// Make the machine (once, on the I/O thread, before any vCPU runs): load
/// the kernel dom0 put in RAM, write its device tree, and publish the
/// shared state as VM.
pub fn make(cfg: &'static HvmConfig, tsc_hz: u64, mem: GuestMem) -> Result<(), BuildError> {
    let vcpus = (cfg.nr_vcpus as usize).clamp(1, hv::MAX_VCPUS);
    let gicv3 = cfg.arm_virt.gic_version == 3;
    let kernel = Kernel::parse(&mem, cfg.kernel_gpa, cfg.kernel_size).map_err(BuildError::Kernel)?;
    let initrd = (cfg.initrd_size != 0).then_some((cfg.initrd_gpa, cfg.initrd_gpa + cfg.initrd_size));
    let machine = Machine { vcpus, gicv3, ram_base: arm::RAM_BASE, ram: cfg.low_ram, cmdline: &cfg.cmdline, initrd };
    let buf = unsafe { FDT.get() };
    let loaded = boot::load(&mem, &kernel, cfg.kernel_gpa, (cfg.initrd_gpa, cfg.initrd_size), &machine, &mut buf[..])
        .map_err(BuildError::Load)?;
    for (gpa, len) in [(arm::RAM_BASE, loaded.fdt_size), loaded.kernel, (cfg.initrd_gpa, cfg.initrd_size)] {
        if let Err(e) = crate::sys::clean_range(gpa, len) {
            l4h_rt::log!("l4h-hvm: guest {}: cleaning {:#x}+{:#x}: {:?}", cfg.guest_id, gpa, len, e);
            return Err(BuildError::Cache);
        }
    }
    VM.set(Vm {
        cfg,
        tsc_hz,
        vcpus,
        mem,
        vgic: Vgic::new(gicv3, vcpus),
        power: core::array::from_fn(|v| Power::new(v == 0)),
        kicks: Kicks::new(),
        bar0: [const { AtomicU64::new(0) }; 32],
        intx: AtomicU32::new(0),
        uart: SpinLock::new(Pl011::new()),
        uart_stale: AtomicBool::new(false),
        rtc: SpinLock::new(Pl031::new(cfg.epoch_ns, cfg.epoch_ticks, tsc_hz)),
        gpio: SpinLock::new(Pl061::new()),
        button: AtomicBool::new(false),
        console: Output::new(),
        entry: loaded.entry,
    });
    Ok(())
}

pub fn vm() -> &'static Vm {
    VM.get()
}

/// What the guest runs on, for the log.
pub fn platform() -> &'static str {
    if vm().vgic.v3() { "FL4 EL2, GICv3" } else { "FL4 EL2, GICv2" }
}

/// Where vCPU 0 starts, for the log.
pub fn entry_pc() -> u64 {
    vm().entry.pc
}

/// Wake vCPU `v`'s thread: out of seL4_ARM_VCPU_Run, or out of its wait.
pub fn wake(v: usize) {
    if me() != Some(v) {
        crate::sys::wake(v);
    }
}

impl Vm {
    /// An MSI-X message a device sent (the I/O thread).
    pub fn msi(&self, addr: u64, data: u32) {
        if let Some(t) = self.vgic.msi(addr, data) {
            wake(t);
        }
    }

    /// Slot `slot`'s INTA#, which shares a line with others': the slots
    /// on a line are wired-OR (the I/O thread).
    pub fn set_intx(&self, slot: usize, level: bool) {
        let bit = 1u32 << slot;
        let asserted = if level { self.intx.fetch_or(bit, Ordering::Relaxed) | bit } else { self.intx.fetch_and(!bit, Ordering::Relaxed) & !bit };
        let line = intx_line(slot);
        let high = (0..32).any(|s| asserted & (1 << s) != 0 && intx_line(s) == line);
        self.set_spi(arm::PCI_INTX_SPI + line, high);
    }

    /// SPI `spi`'s line.
    pub fn set_spi(&self, spi: u32, level: bool) {
        if let Some(t) = self.vgic.set_spi_line(32 + spi, level) {
            wake(t);
        }
    }

    /// dom0 asked to shut the guest down: vCPU 0 presses its power button.
    pub fn power_button(&self) {
        self.button.store(true, Ordering::SeqCst);
        wake(0);
    }

    /// vmmgr wrote console input: vCPU 0 gives it to the UART.
    pub fn console_input(&self) {
        self.uart_stale.store(true, Ordering::SeqCst);
        wake(0);
    }

    /// Use the UART (a vCPU thread), and set its line as its state is then:
    /// under its lock, so that lines follow states in order.
    pub fn uart<R>(&self, f: impl FnOnce(&mut Pl011, &mut crate::console::Input) -> R) -> R {
        let mut u = self.uart.lock();
        self.uart_stale.store(false, Ordering::SeqCst);
        let r = f(&mut u, &mut crate::console::Input);
        let level = u.irq(&mut crate::console::Input);
        self.set_spi(arm::UART_SPI, level);
        r
    }

    /// Use the GPIO controller (a vCPU thread), as `uart`.
    pub fn gpio<R>(&self, f: impl FnOnce(&mut Pl061) -> R) -> R {
        let mut g = self.gpio.lock();
        let r = f(&mut g);
        self.set_spi(arm::GPIO_SPI, g.irq());
        r
    }

    /// Use the RTC (a vCPU thread), as `uart`.
    pub fn rtc<R>(&self, f: impl FnOnce(&mut Pl031) -> R) -> R {
        let t = now();
        let (r, moved) = {
            let mut c = self.rtc.lock();
            let before = c.deadline(t);
            let r = f(&mut c);
            self.set_spi(arm::RTC_SPI, c.irq());
            (r, c.deadline(t) != before)
        };
        // vCPU 0 watches the match: it may be waiting for the old one.
        if moved {
            wake(0);
        }
        r
    }

    /// What the I/O thread left for a vCPU, and the RTC's match (vCPU 0).
    pub fn pending_work(&self) {
        if self.uart_stale.load(Ordering::SeqCst) {
            self.uart(|_, _| ());
        }
        if self.button.swap(false, Ordering::SeqCst) {
            // A new edge each time, and pressed when the guest reads it.
            self.gpio(|g| {
                g.set_input(PIN_POWER, false);
                g.set_input(PIN_POWER, true);
            });
        }
        self.rtc(|r| r.poll(now()));
    }
}

/// The line (of PCI_INTX_LINES) slot `slot`'s INTA# is swizzled onto, as
/// the device tree's interrupt-map has it.
pub const fn intx_line(slot: usize) -> u32 {
    slot as u32 % arm::PCI_INTX_LINES
}
