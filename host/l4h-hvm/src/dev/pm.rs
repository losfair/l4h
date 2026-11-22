//! ACPI fixed hardware (the FADT's blocks, acpi.rs): the PM1a event block
//! (status and enable) at 0x600, the PM1a control block at 0x604, the
//! 32-bit PM timer at 0x608, and the reset register at 0xcf9.  The power
//! button is its one event: vmmgr's shutdown request (CTL_VM_SHUTDOWN)
//! presses it, which raises the SCI (IRQ 9) if the guest enabled it; the
//! guest's ACPI then writes S5 (\_S5, SLP_TYP 5) with SLP_EN.  Lock-free:
//! the I/O thread presses the button, vCPU threads read and write the
//! registers.  Free of seL4.

use core::sync::atomic::{AtomicU16, Ordering};

pub const PM1_EVT: u16 = 0x600;
pub const PM1_CNT: u16 = 0x604;
pub const PM_TMR: u16 = 0x608;
pub const RESET: u16 = 0xcf9;
pub const SCI_IRQ: usize = 9;
/// SLP_TYP of S5, as the DSDT's \_S5 says.
pub const SLP_TYP_S5: u16 = 5;
pub const TIMER_HZ: u64 = 3_579_545;

/// The power button's status and enable bits.
const PWRBTN: u16 = 1 << 8;
const TMR: u16 = 1 << 0;
const WAK: u16 = 1 << 15;
const SCI_EN: u16 = 1 << 0;
const SLP_EN: u16 = 1 << 13;

/// What a write asks of the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    PowerOff,
    Reset,
    /// The SCI's level may have changed.
    Sci,
}

pub struct Pm {
    sts: AtomicU16,
    en: AtomicU16,
    cnt: AtomicU16,
}

impl Default for Pm {
    fn default() -> Self {
        Self::new()
    }
}

impl Pm {
    /// ACPI is on from the start (the FADT has no SMI command port).
    pub const fn new() -> Self {
        Pm { sts: AtomicU16::new(0), en: AtomicU16::new(0), cnt: AtomicU16::new(SCI_EN) }
    }

    /// Press the power button: whether the SCI rises.
    pub fn power_button(&self) -> bool {
        self.sts.fetch_or(PWRBTN, Ordering::SeqCst);
        self.sci()
    }

    /// The SCI's level.
    pub fn sci(&self) -> bool {
        self.cnt.load(Ordering::SeqCst) & SCI_EN != 0
            && self.sts.load(Ordering::SeqCst) & self.en.load(Ordering::SeqCst) & (PWRBTN | TMR) != 0
    }

    /// Read `size` bytes at `port` (in one of the blocks).
    pub fn read(&self, port: u16, size: u8, tsc: u64, tsc_hz: u64) -> u32 {
        let v = match port & !1 {
            PM1_EVT => self.sts.load(Ordering::SeqCst) as u32 | (self.en.load(Ordering::SeqCst) as u32) << 16,
            0x602 => self.en.load(Ordering::SeqCst) as u32,
            PM1_CNT => self.cnt.load(Ordering::SeqCst) as u32,
            PM_TMR | 0x60a => {
                let t = (tsc as u128 * TIMER_HZ as u128 / tsc_hz.max(1) as u128) as u32;
                if port & !1 == PM_TMR { t } else { t >> 16 }
            }
            _ => 0,
        };
        let v = if port & 1 != 0 { v >> 8 } else { v };
        match size {
            1 => v & 0xff,
            2 => v & 0xffff,
            _ => v,
        }
    }

    pub fn write(&self, port: u16, size: u8, val: u32) -> Action {
        match (port, size) {
            (PM1_EVT, 4) => {
                self.sts.fetch_and(!(val as u16), Ordering::SeqCst);
                self.en.store((val >> 16) as u16 & (PWRBTN | TMR), Ordering::SeqCst);
                Action::Sci
            }
            // Status bits clear where 1 is written.
            (PM1_EVT, _) => {
                self.sts.fetch_and(!(val as u16), Ordering::SeqCst);
                Action::Sci
            }
            (0x602, _) => {
                self.en.store(val as u16 & (PWRBTN | TMR), Ordering::SeqCst);
                Action::Sci
            }
            (PM1_CNT, _) => {
                let v = val as u16;
                // SCI_EN is the firmware's: it stays.
                self.cnt.store((v & !SLP_EN) | SCI_EN, Ordering::SeqCst);
                if v & SLP_EN != 0 {
                    if (v >> 10) & 7 == SLP_TYP_S5 {
                        return Action::PowerOff;
                    }
                    // Another sleep state: we wake at once.
                    self.sts.fetch_or(WAK, Ordering::SeqCst);
                }
                Action::Sci
            }
            // RST_CPU: a reset.
            (RESET, 1) if val & 4 != 0 => Action::Reset,
            _ => Action::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_sleep_reset_timer() {
        let pm = Pm::new();
        assert!(!pm.power_button(), "not enabled: no SCI");
        assert_eq!(pm.read(PM1_EVT, 2, 0, 1), PWRBTN as u32);
        pm.write(0x602, 2, PWRBTN as u32);
        assert!(pm.sci());
        pm.write(PM1_EVT, 2, PWRBTN as u32);
        assert!(!pm.sci(), "status cleared");
        assert!(pm.power_button());
        assert_eq!(pm.write(PM1_CNT, 2, (SLP_TYP_S5 << 10 | SLP_EN) as u32), Action::PowerOff);
        assert_eq!(pm.write(PM1_CNT, 2, (1 << 10 | SLP_EN) as u32), Action::Sci);
        assert!(pm.read(PM1_EVT, 2, 0, 1) & WAK as u32 != 0);
        assert_eq!(pm.read(PM1_CNT, 2, 0, 1) & SCI_EN as u32, SCI_EN as u32);
        assert_eq!(pm.write(RESET, 1, 0x06), Action::Reset);
        assert_eq!(pm.write(RESET, 1, 0x02), Action::None);
        // One second of a 2 GHz TSC.
        assert_eq!(pm.read(PM_TMR, 4, 2_000_000_000, 2_000_000_000), TIMER_HZ as u32);
    }
}
