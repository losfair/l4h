//! Host reboot, for dom0's L4H_CTL_HOST_REBOOT (DESIGN.md §10.1): reset the
//! machine as Linux does: the FADT's reset register, then the PCI reset
//! control register (0xcf9), then the keyboard controller.  Nothing is
//! flushed: a guest's flush reaches the disk before it completes, so what
//! dom0 synced is safe, and the other guests stop with the host anyway.

#[cfg(target_arch = "x86_64")]
use sel4::cap;

use crate::Host;
#[cfg(target_arch = "x86_64")]
use crate::component::abs_of;

/// FADT: Flags, RESET_REG (a Generic Address Structure) and RESET_VALUE.
#[cfg(target_arch = "x86_64")]
const FADT_FLAGS: usize = 112;
#[cfg(target_arch = "x86_64")]
const FADT_RESET_REG: usize = 116;
#[cfg(target_arch = "x86_64")]
const FADT_RESET_VALUE: usize = 128;
/// Flags: RESET_REG_SUP.
#[cfg(target_arch = "x86_64")]
const RESET_REG_SUP: u32 = 1 << 10;
#[cfg(target_arch = "x86_64")]
const PCI_RESET: u16 = 0xcf9;
#[cfg(target_arch = "x86_64")]
const KBD_STATUS: u16 = 0x64;
/// How long each method gets to take effect.
#[cfg(target_arch = "x86_64")]
const WAIT_MS: u64 = 100;

/// The FADT's reset register, found at boot, with what it needs to be
/// written: its page or I/O port capability, so that nothing has to be
/// carved or issued when the host is about to go down.
#[cfg(target_arch = "x86_64")]
enum Reg {
    /// SystemIO; `cap` None: a PCI configuration port, through root's.
    Io { port: u16, cap: Option<cap::Null> },
    /// SystemMemory.
    Mem { frame: cap::Granule, off: usize },
    /// PCI configuration space of a function on bus 0.
    Pci { dev: u8, func: u8, off: u8 },
}

#[derive(Default)]
pub struct Reset {
    #[cfg(target_arch = "x86_64")]
    reg: Option<(Reg, u8)>,
}

impl Reset {
    /// The reset register, if the FADT has one.
    #[cfg(target_arch = "x86_64")]
    pub fn find(bootinfo: &sel4::BootInfoPtr, phys: &mut crate::acpi::Phys) -> Reset {
        let mut fadt = [0; crate::acpi::FADT_LEN];
        let Some(t) = crate::acpi::find(bootinfo, phys, b"FACP", &mut fadt).filter(|t| t.len() > FADT_RESET_VALUE) else {
            return Reset::default();
        };
        let flags = u32::from_le_bytes(t[FADT_FLAGS..FADT_FLAGS + 4].try_into().unwrap());
        let (space, addr) = (t[FADT_RESET_REG], u64::from_le_bytes(t[FADT_RESET_REG + 4..FADT_RESET_REG + 12].try_into().unwrap()));
        if flags & RESET_REG_SUP == 0 || addr == 0 {
            return Reset::default();
        }
        let reg = match space {
            0 => phys.frame(addr as usize).map(|frame| Reg::Mem { frame, off: addr as usize % 4096 }),
            1 if (0xcf8..0xd00).contains(&addr) => Some(Reg::Io { port: addr as u16, cap: None }),
            1 if addr < 0x1_0000 => crate::pci::io_ports(phys.alloc, addr as u16, 1).map(|c| Reg::Io { port: addr as u16, cap: Some(c) }),
            // The address is device << 32 | function << 16 | offset.
            2 => Some(Reg::Pci { dev: (addr >> 32) as u8, func: (addr >> 16) as u8, off: addr as u8 }),
            _ => None,
        };
        info!("l4h-root: ACPI reset register: space {} at {:#x}{}", space, addr, if reg.is_none() { ", unusable" } else { "" });
        Reset { reg: reg.map(|r| (r, t[FADT_RESET_VALUE])) }
    }
}

/// Reset the machine.  Returns only if every method failed: -EIO
/// (-ENOSYS on aarch64, which has none yet).
pub fn reboot(h: &mut Host, by: &str) -> i64 {
    if cfg!(not(target_arch = "x86_64")) {
        return crate::ctl::ENOSYS;
    }
    log!("l4h-root: host reboot ({})", by);
    reset(h);
    log!("l4h-root: host reboot failed: the machine did not reset");
    crate::ctl::EIO
}

#[cfg(target_arch = "x86_64")]
fn reset(h: &mut Host) {
    let wait = |h: &Host| {
        let end = l4h_host::ticks::now() + WAIT_MS * (h.info.tsc_hz / 1000);
        while l4h_host::ticks::now() < end {
            core::hint::spin_loop();
        }
    };
    if let Some((reg, value)) = &h.reset.reg {
        match reg {
            Reg::Io { port, cap: None } => h.pci.out8(*port, *value),
            Reg::Io { port, cap: Some(c) } => crate::pci::out8(*c, *port, *value),
            Reg::Mem { frame, off } => h.wins.a.with_frame_attrs(&abs_of(*frame), crate::blkd::DEVICE_ATTRS, |p| unsafe {
                (p.add(*off) as *mut u8).write_volatile(*value)
            }),
            Reg::Pci { dev, func, off } => {
                let (word, shift) = (off & !3, (off % 4) * 8);
                let old = h.pci.read32(0, *dev, *func, word);
                h.pci.write32(0, *dev, *func, word, (old & !(0xff << shift)) | (*value as u32) << shift);
            }
        }
        wait(h);
    }
    // A hard reset through the reset control register, as Linux's
    // reboot=pci: the reset type first, then the reset.
    h.pci.out8(PCI_RESET, 0x02);
    wait(h);
    h.pci.out8(PCI_RESET, 0x06);
    wait(h);
    // Pulse the CPU reset line through the keyboard controller.
    if let Some(c) = crate::pci::io_ports(&mut h.alloc, KBD_STATUS, 1) {
        crate::pci::out8(c, KBD_STATUS, 0xfe);
        wait(h);
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn reset(_h: &mut Host) {}
