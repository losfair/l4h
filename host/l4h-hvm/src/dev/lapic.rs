//! A vCPU's local APIC (DESIGN.md §5.11), which its own thread runs: the
//! xAPIC registers at 0xfee0_0000 and the x2APIC MSRs (0x800-0x8ff), task
//! and processor priority, in-service and trigger-mode registers, EOI
//! (which a level-triggered interrupt's source hears of), IPIs through
//! the ICR, and the timer in one-shot, periodic and TSC-deadline mode.
//! Requests (IRR) and NMI, INIT and SIPI come through apic::Shared, from
//! any thread.  The timer runs on the TSC: its deadline is what the vCPU
//! thread arms seL4_TCB_SetTimer with.  Free of seL4.

use core::sync::atomic::Ordering;

use super::apic::{self, Message, Shared, Shorthand};

/// The APIC timer's input clock, which CPUID leaf 0x15 says is the
/// crystal's: 1 GHz, so that a count is a nanosecond.
pub const TIMER_HZ: u64 = 1_000_000_000;

/// IA32_APIC_BASE: the BSP flag, x2APIC mode, global enable.
pub const BASE_BSP: u64 = 1 << 8;
pub const BASE_EXTD: u64 = 1 << 10;
pub const BASE_ENABLE: u64 = 1 << 11;
pub const BASE_ADDR: u64 = 0xfee0_0000;

pub const MSR_APIC_BASE: u32 = 0x1b;
pub const MSR_TSC_DEADLINE: u32 = 0x6e0;

// Register offsets (xAPIC MMIO; x2APIC MSR 0x800 + offset / 16).
const ID: u32 = 0x20;
const VERSION: u32 = 0x30;
const TPR: u32 = 0x80;
const APR: u32 = 0x90;
const PPR: u32 = 0xa0;
const EOI: u32 = 0xb0;
const RRD: u32 = 0xc0;
const LDR: u32 = 0xd0;
const DFR: u32 = 0xe0;
const SVR: u32 = 0xf0;
const ISR: u32 = 0x100;
const TMR: u32 = 0x180;
const IRR: u32 = 0x200;
const ESR: u32 = 0x280;
const LVT_CMCI: u32 = 0x2f0;
const ICR_LO: u32 = 0x300;
const ICR_HI: u32 = 0x310;
const LVT_TIMER: u32 = 0x320;
// LVT_THERMAL 0x330, LVT_PERF 0x340, LVT_LINT0 0x350 and LVT_LINT1 0x360
// lie between the two.
const LVT_ERROR: u32 = 0x370;
const TIMER_INIT: u32 = 0x380;
const TIMER_CUR: u32 = 0x390;
const TIMER_DIV: u32 = 0x3e0;
const SELF_IPI: u32 = 0x3f0;

const LVT_MASKED: u32 = 1 << 16;
const SVR_ENABLE: u32 = 1 << 8;
/// Six LVT entries (LVT_CMCI and the five in order from LVT_TIMER) and
/// the number of entries VERSION reports.
const NR_LVT: usize = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimerMode {
    OneShot,
    Periodic,
    Deadline,
}

/// What a register access asks of the vCPU thread besides the APIC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Effects {
    /// An interrupt message to deliver (an IPI).
    pub send: Option<Message>,
    /// The end of a level-triggered interrupt with this vector, for the
    /// I/O APIC.
    pub eoi_level: Option<u8>,
    /// The timer's deadline changed: arm the thread's timer again.
    pub timer: bool,
    /// TPR changed (AMD-V keeps it in the VMCB too).
    pub tpr: bool,
}

pub struct Lapic {
    id: u32,
    base: u64,
    tpr: u32,
    svr: u32,
    ldr: u32,
    dfr: u32,
    isr: [u64; 4],
    tmr: [u64; 4],
    icr: u64,
    /// LVT_CMCI, TIMER, THERMAL, PERF, LINT0, LINT1, ERROR.
    lvt: [u32; NR_LVT],
    timer_init: u32,
    timer_div: u32,
    /// TSC-deadline MSR.
    tsc_deadline: u64,
    /// When the timer next fires (TSC), 0 if it does not; its period in
    /// TSC ticks for a periodic timer, and the TSC it last started at.
    deadline: u64,
    period: u64,
    start: u64,
    tsc_hz: u64,
}

impl Lapic {
    pub fn new(id: u32, bsp: bool, tsc_hz: u64) -> Self {
        let mut l = Lapic {
            id,
            base: 0,
            tpr: 0,
            svr: 0xff,
            ldr: 0,
            dfr: u32::MAX,
            isr: [0; 4],
            tmr: [0; 4],
            icr: 0,
            lvt: [LVT_MASKED; NR_LVT],
            timer_init: 0,
            timer_div: 0,
            tsc_deadline: 0,
            deadline: 0,
            period: 0,
            start: 0,
            tsc_hz: tsc_hz.max(1),
        };
        l.base = BASE_ADDR | BASE_ENABLE | if bsp { BASE_BSP } else { 0 };
        l
    }

    /// INIT: the APIC's registers as at reset, but its ID and mode.
    pub fn init(&mut self, shared: &Shared) {
        let base = self.base;
        *self = Lapic::new(self.id, base & BASE_BSP != 0, self.tsc_hz);
        self.base = base;
        self.publish(shared);
    }

    pub fn x2apic(&self) -> bool {
        self.base & BASE_EXTD != 0
    }

    /// Software- and globally enabled.
    fn enabled(&self) -> bool {
        self.svr & SVR_ENABLE != 0 && self.base & BASE_ENABLE != 0
    }

    fn lvt_index(off: u32) -> Option<usize> {
        match off {
            LVT_CMCI => Some(0),
            LVT_TIMER..=LVT_ERROR if off.is_multiple_of(16) => Some(1 + ((off - LVT_TIMER) / 16) as usize),
            _ => None,
        }
    }

    fn timer_lvt(&self) -> u32 {
        self.lvt[1]
    }

    fn timer_mode(&self) -> TimerMode {
        match (self.timer_lvt() >> 17) & 3 {
            1 => TimerMode::Periodic,
            2 => TimerMode::Deadline,
            _ => TimerMode::OneShot,
        }
    }

    fn divisor(&self) -> u64 {
        let v = (self.timer_div & 3) | ((self.timer_div >> 1) & 4);
        if v == 7 { 1 } else { 2 << v }
    }

    /// TSC ticks of `count` timer ticks.
    fn ticks(&self, count: u64) -> u64 {
        let t = count as u128 * self.divisor() as u128 * self.tsc_hz as u128 / TIMER_HZ as u128;
        u64::try_from(t).unwrap_or(u64::MAX).max(1)
    }

    /// The highest bit of a 256-bit register, as a vector.
    fn highest(r: &[u64; 4]) -> Option<u8> {
        (0..4).rev().find(|&w| r[w] != 0).map(|w| (w * 64 + 63 - r[w].leading_zeros() as usize) as u8)
    }

    fn ppr(&self) -> u32 {
        let isrv = Self::highest(&self.isr).map_or(0, |v| v as u32);
        if (self.tpr & 0xf0) >= (isrv & 0xf0) { self.tpr & 0xff } else { isrv & 0xf0 }
    }

    /// The interrupt the APIC would deliver now: the highest requested
    /// vector of a higher priority class than PPR.
    pub fn pending(&self, shared: &Shared) -> Option<u8> {
        if !self.enabled() {
            return None;
        }
        let irr: [u64; 4] = core::array::from_fn(|i| shared.irr[i].load(Ordering::Acquire));
        let v = Self::highest(&irr)?;
        ((v as u32 & 0xf0) > (self.ppr() & 0xf0)).then_some(v)
    }

    /// The CPU takes interrupt `v` (pending()): it moves from IRR to ISR.
    pub fn accept(&mut self, shared: &Shared, v: u8) {
        let (w, bit) = ((v / 64) as usize, 1u64 << (v % 64));
        shared.irr[w].fetch_and(!bit, Ordering::AcqRel);
        self.isr[w] |= bit;
        if shared.level[w].fetch_and(!bit, Ordering::AcqRel) & bit != 0 {
            self.tmr[w] |= bit;
        } else {
            self.tmr[w] &= !bit;
        }
    }

    fn eoi(&mut self, fx: &mut Effects) {
        if let Some(v) = Self::highest(&self.isr) {
            let (w, bit) = ((v / 64) as usize, 1u64 << (v % 64));
            self.isr[w] &= !bit;
            if self.tmr[w] & bit != 0 {
                self.tmr[w] &= !bit;
                fx.eoi_level = Some(v);
            }
        }
    }

    /// Read register `off` (16-byte aligned; xAPIC layout).
    pub fn read(&self, shared: &Shared, now: u64, off: u32) -> u32 {
        match off {
            ID => if self.x2apic() { self.id } else { self.id << 24 },
            // Version 0x14, its LVT count, and no EOI-broadcast suppression.
            VERSION => 0x14 | ((NR_LVT as u32 - 1) << 16),
            TPR => self.tpr,
            APR => 0,
            PPR => self.ppr(),
            LDR => if self.x2apic() { self.x2apic_ldr() } else { self.ldr },
            DFR => if self.x2apic() { 0 } else { self.dfr },
            SVR => self.svr,
            ISR..=0x170 => self.word(&self.isr, off - ISR),
            TMR..=0x1f0 => self.word(&self.tmr, off - TMR),
            IRR..=0x270 => {
                let irr: [u64; 4] = core::array::from_fn(|i| shared.irr[i].load(Ordering::Acquire));
                self.word(&irr, off - IRR)
            }
            ESR => 0,
            ICR_LO => self.icr as u32,
            ICR_HI => (self.icr >> 32) as u32,
            TIMER_INIT => self.timer_init,
            TIMER_CUR => self.current_count(now),
            TIMER_DIV => self.timer_div,
            _ => match Self::lvt_index(off) {
                Some(i) => self.lvt[i],
                None => 0,
            },
        }
    }

    fn word(&self, r: &[u64; 4], rel: u32) -> u32 {
        let i = (rel / 16) as usize;
        (r[i / 2] >> (32 * (i % 2))) as u32
    }

    fn x2apic_ldr(&self) -> u32 {
        ((self.id >> 4) << 16) | (1 << (self.id & 0xf))
    }

    fn current_count(&self, now: u64) -> u32 {
        if self.deadline == 0 || self.timer_mode() == TimerMode::Deadline || now >= self.deadline {
            return 0;
        }
        let left = (self.deadline - now) as u128 * TIMER_HZ as u128 / (self.tsc_hz as u128 * self.divisor() as u128);
        left.min(self.timer_init as u128) as u32
    }

    /// Write `val` to register `off`; what else it does is in the result.
    pub fn write(&mut self, shared: &Shared, now: u64, off: u32, val: u32) -> Effects {
        let mut fx = Effects::default();
        match off {
            // Read-only in x2APIC mode; xAPIC's ID is the vCPU's, too.
            ID | VERSION | PPR | APR | RRD | ISR..=0x170 | TMR..=0x1f0 | IRR..=0x270 | TIMER_CUR => {}
            TPR => {
                self.tpr = val & 0xff;
                fx.tpr = true;
            }
            EOI => self.eoi(&mut fx),
            LDR if !self.x2apic() => self.ldr = val & 0xff00_0000,
            DFR if !self.x2apic() => self.dfr = val | 0x0fff_ffff,
            SVR => {
                self.svr = val & 0x1ff;
                if self.svr & SVR_ENABLE == 0 {
                    // Software disable masks every LVT entry.
                    for l in self.lvt.iter_mut() {
                        *l |= LVT_MASKED;
                    }
                }
            }
            ESR => {}
            ICR_LO => {
                self.icr = (self.icr & !0xffff_ffff) | (val & !(1 << 12)) as u64;
                fx.send = self.ipi(self.icr);
            }
            ICR_HI if !self.x2apic() => self.icr = (self.icr & 0xffff_ffff) | ((val as u64) << 32),
            TIMER_INIT => {
                self.timer_init = val;
                if self.timer_mode() != TimerMode::Deadline {
                    self.start_timer(now);
                    fx.timer = true;
                }
            }
            TIMER_DIV => self.timer_div = val & 0xb,
            SELF_IPI if self.x2apic() => {
                fx.send = Some(Message { dest: self.id, logical: false, shorthand: Shorthand::SelfOnly, mode: apic::DM_FIXED,
                    vector: val as u8, level: false });
            }
            _ => {
                if let Some(i) = Self::lvt_index(off) {
                    let mut v = val & 0x0003_17ff;
                    if i == 1 {
                        let old_mode = self.timer_mode();
                        v = val & 0x0007_10ff;
                        self.lvt[1] = if self.svr & SVR_ENABLE == 0 { v | LVT_MASKED } else { v };
                        // A mode change stops the timer.
                        if self.timer_mode() != old_mode {
                            self.deadline = 0;
                            self.tsc_deadline = 0;
                            fx.timer = true;
                        }
                        return fx;
                    }
                    if self.svr & SVR_ENABLE == 0 {
                        v |= LVT_MASKED;
                    }
                    self.lvt[i] = v;
                }
            }
        }
        self.publish(shared);
        fx
    }

    /// What other threads look at.
    fn publish(&self, shared: &Shared) {
        let ldr = if self.x2apic() { self.x2apic_ldr() } else { self.ldr >> 24 };
        shared.ldr.store(ldr, Ordering::Relaxed);
        shared.dfr_model.store((self.dfr >> 28) as u8, Ordering::Relaxed);
        shared.x2apic.store(self.x2apic(), Ordering::Relaxed);
        shared.enabled.store(self.enabled(), Ordering::Relaxed);
    }

    /// The message of an ICR write.
    fn ipi(&self, icr: u64) -> Option<Message> {
        let mode = ((icr >> 8) & 7) as u8;
        let level_assert = icr & (1 << 14) != 0;
        let level_trig = icr & (1 << 15) != 0;
        // INIT de-assert does nothing on a modern APIC.
        if mode == apic::DM_INIT && level_trig && !level_assert {
            return None;
        }
        let dest = if self.x2apic() { (icr >> 32) as u32 } else { ((icr >> 56) & 0xff) as u32 };
        let shorthand = match (icr >> 18) & 3 {
            1 => Shorthand::SelfOnly,
            2 => Shorthand::All,
            3 => Shorthand::AllButSelf,
            _ => Shorthand::None,
        };
        Some(Message { dest, logical: icr & (1 << 11) != 0, shorthand, mode, vector: icr as u8, level: false })
    }

    fn start_timer(&mut self, now: u64) {
        if self.timer_init == 0 {
            self.deadline = 0;
            return;
        }
        self.start = now;
        self.period = self.ticks(self.timer_init as u64);
        self.deadline = now.saturating_add(self.period);
    }

    /// When the timer next fires, by the TSC (0: it does not).
    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Fire the timer if its deadline has passed at `now`: whether it did
    /// (and the vCPU thread arms its next deadline).
    pub fn tick(&mut self, shared: &Shared, now: u64) -> bool {
        if self.deadline == 0 || now < self.deadline {
            return false;
        }
        let lvt = self.timer_lvt();
        if lvt & LVT_MASKED == 0 && self.enabled() {
            shared.request(lvt as u8, false);
        }
        match self.timer_mode() {
            TimerMode::Periodic if self.period != 0 => {
                // The next period after now: periods missed while the
                // vCPU did not run fire once.
                let behind = (now - self.deadline) / self.period + 1;
                self.deadline = self.deadline.saturating_add(behind.saturating_mul(self.period));
            }
            TimerMode::Deadline => {
                self.tsc_deadline = 0;
                self.deadline = 0;
            }
            _ => self.deadline = 0,
        }
        true
    }

    /// RDMSR of an APIC MSR: IA32_APIC_BASE, TSC_DEADLINE, or an x2APIC
    /// register (0x800-0x8ff, only in x2APIC mode).  None: #GP.
    pub fn rdmsr(&self, shared: &Shared, now: u64, msr: u32) -> Option<u64> {
        match msr {
            MSR_APIC_BASE => Some(self.base),
            MSR_TSC_DEADLINE => Some(if self.timer_mode() == TimerMode::Deadline { self.tsc_deadline } else { 0 }),
            0x800..=0x8ff if self.x2apic() => {
                let off = (msr - 0x800) << 4;
                match off {
                    // DFR does not exist in x2APIC mode, nor do EOI and
                    // SELF_IPI read; ICR is one 64-bit register.
                    DFR | EOI | SELF_IPI | ICR_HI => None,
                    ICR_LO => Some(self.icr),
                    _ if !Self::readable(off) => None,
                    _ => Some(self.read(shared, now, off) as u64),
                }
            }
            _ => None,
        }
    }

    fn readable(off: u32) -> bool {
        matches!(off, ID | VERSION | TPR | PPR | LDR | SVR | ESR | TIMER_INIT | TIMER_CUR | TIMER_DIV)
            || (ISR..=0x270).contains(&off)
            || Self::lvt_index(off).is_some()
    }

    /// WRMSR of an APIC MSR: None for #GP.
    pub fn wrmsr(&mut self, shared: &Shared, now: u64, msr: u32, val: u64) -> Option<Effects> {
        match msr {
            MSR_APIC_BASE => {
                // Only the mode bits; the base stays at 0xfee0_0000.  x2APIC
                // without global enable, and leaving x2APIC but for
                // disabling, are invalid transitions.
                let (enable, extd) = (val & BASE_ENABLE != 0, val & BASE_EXTD != 0);
                if (extd && !enable) || (self.x2apic() && !extd && enable) || val & !(BASE_BSP | BASE_EXTD | BASE_ENABLE | 0xffff_f000) != 0 {
                    return None;
                }
                self.base = BASE_ADDR | (self.base & BASE_BSP) | (val & (BASE_EXTD | BASE_ENABLE));
                self.publish(shared);
                Some(Effects::default())
            }
            MSR_TSC_DEADLINE => {
                if self.timer_mode() == TimerMode::Deadline {
                    self.tsc_deadline = val;
                    self.deadline = val;
                    return Some(Effects { timer: true, ..Default::default() });
                }
                Some(Effects::default())
            }
            0x800..=0x8ff if self.x2apic() => {
                let off = (msr - 0x800) << 4;
                match off {
                    ICR_LO => {
                        self.icr = val & !(1 << 12);
                        Some(Effects { send: self.ipi(self.icr), ..Default::default() })
                    }
                    // Reserved bits must be zero, as must EOI's value.
                    EOI if val != 0 => None,
                    TPR | EOI | SVR | ESR | TIMER_INIT | TIMER_DIV | SELF_IPI => Some(self.write(shared, now, off, val as u32)),
                    _ if Self::lvt_index(off).is_some() => Some(self.write(shared, now, off, val as u32)),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub fn tpr(&self) -> u32 {
        self.tpr
    }

    /// The guest wrote CR8 (TPR bits 7:4).
    pub fn set_cr8(&mut self, v: u64) {
        self.tpr = ((v & 0xf) << 4) as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HZ: u64 = 2_000_000_000;

    fn setup() -> (Lapic, Shared) {
        let s = Shared::new(1);
        let mut l = Lapic::new(1, false, HZ);
        l.write(&s, 0, SVR, 0x1ff);
        (l, s)
    }

    #[test]
    fn priorities_and_eoi() {
        let (mut l, s) = setup();
        assert_eq!(l.read(&s, 0, ID), 1 << 24);
        s.request(0x41, false);
        s.request(0x92, true);
        assert_eq!(l.pending(&s), Some(0x92));
        l.accept(&s, 0x92);
        // In service: 0x41 is of a lower class, so it waits.
        assert_eq!(l.pending(&s), None);
        assert_eq!(l.read(&s, 0, PPR), 0x90);
        assert_eq!(l.read(&s, 0, ISR + 0x40), 1 << (0x92 - 128 - 0));
        let fx = l.write(&s, 0, EOI, 0);
        assert_eq!(fx.eoi_level, Some(0x92), "level-triggered: the I/O APIC hears of it");
        assert_eq!(l.pending(&s), Some(0x41));
        // TPR masks a class and below.
        l.write(&s, 0, TPR, 0x40);
        assert_eq!(l.pending(&s), None);
        l.set_cr8(3);
        assert_eq!(l.pending(&s), Some(0x41));
        l.accept(&s, 0x41);
        assert_eq!(l.write(&s, 0, EOI, 0).eoi_level, None);
        // Disabled: nothing is delivered.
        s.request(0x50, false);
        l.write(&s, 0, SVR, 0xff);
        assert_eq!(l.pending(&s), None);
    }

    #[test]
    fn ipis() {
        let (mut l, s) = setup();
        l.write(&s, 0, ICR_HI, 3 << 24);
        let fx = l.write(&s, 0, ICR_LO, 0x0000_0850 | (1 << 14));
        let m = fx.send.unwrap();
        assert_eq!((m.dest, m.logical, m.mode, m.vector, m.shorthand), (3, true, apic::DM_FIXED, 0x50, Shorthand::None));
        // INIT assert, then de-assert (ignored), then SIPI to all but self.
        assert_eq!(l.write(&s, 0, ICR_LO, 0x0000_4500).send.unwrap().mode, apic::DM_INIT);
        assert_eq!(l.write(&s, 0, ICR_LO, 0x0000_8500).send, None);
        let m = l.write(&s, 0, ICR_LO, 0x000c_0698).send.unwrap();
        assert_eq!((m.mode, m.vector, m.shorthand), (apic::DM_SIPI, 0x98, Shorthand::AllButSelf));
        // The delivery status bit reads clear.
        assert_eq!(l.read(&s, 0, ICR_LO) & (1 << 12), 0);
    }

    #[test]
    fn x2apic_msrs() {
        let (mut l, s) = setup();
        assert!(l.wrmsr(&s, 0, MSR_APIC_BASE, BASE_ADDR | BASE_EXTD).is_none(), "EXTD needs EN");
        l.wrmsr(&s, 0, MSR_APIC_BASE, BASE_ADDR | BASE_ENABLE | BASE_EXTD).unwrap();
        assert!(s.x2apic.load(Ordering::Relaxed));
        assert_eq!(l.rdmsr(&s, 0, 0x802), Some(1), "x2APIC ID is the full ID");
        assert_eq!(l.rdmsr(&s, 0, 0x80d), Some((0 << 16) | (1 << 1)), "LDR");
        assert_eq!(l.rdmsr(&s, 0, 0x80e), None, "no DFR");
        assert!(l.wrmsr(&s, 0, MSR_APIC_BASE, BASE_ADDR | BASE_ENABLE).is_none(), "x2APIC to xAPIC directly");
        let fx = l.wrmsr(&s, 0, 0x830, (7u64 << 32) | 0x4031).unwrap();
        assert_eq!(fx.send.unwrap().dest, 7);
        assert!(l.wrmsr(&s, 0, 0x80b, 1).is_none(), "EOI takes 0");
        let fx = l.wrmsr(&s, 0, 0x83f, 0x33).unwrap();
        assert_eq!(fx.send.unwrap().shorthand, Shorthand::SelfOnly);
        // Not in x2APIC mode: #GP.
        let (l2, s2) = setup();
        assert_eq!(l2.rdmsr(&s2, 0, 0x802), None);
    }

    #[test]
    fn timer_modes() {
        let (mut l, s) = setup();
        // One-shot, divide by 1: 1000 counts of 1 ns are 2000 TSC ticks.
        l.write(&s, 0, TIMER_DIV, 0xb);
        l.write(&s, 0, LVT_TIMER, 0xec);
        assert!(l.write(&s, 100, TIMER_INIT, 1000).timer);
        assert_eq!(l.deadline(), 2100);
        assert_eq!(l.read(&s, 1100, TIMER_CUR), 500);
        assert!(!l.tick(&s, 2099));
        assert!(l.tick(&s, 2100));
        assert_eq!(l.pending(&s), Some(0xec));
        assert_eq!(l.deadline(), 0);
        // Periodic, divide by 2: catches up without firing for each missed period.
        l.write(&s, 0, TIMER_DIV, 0);
        l.write(&s, 0, LVT_TIMER, (1 << 17) | 0xed);
        l.write(&s, 0, TIMER_INIT, 500);
        assert_eq!(l.deadline(), 2000);
        assert!(l.tick(&s, 7500));
        assert_eq!(l.deadline(), 8000);
        // TSC-deadline: the MSR is the deadline; it reads 0 once fired.
        l.write(&s, 0, LVT_TIMER, (2 << 17) | 0xee);
        assert_eq!(l.deadline(), 0, "a mode change stops it");
        assert!(l.wrmsr(&s, 0, MSR_TSC_DEADLINE, 12345).unwrap().timer);
        assert_eq!(l.rdmsr(&s, 0, MSR_TSC_DEADLINE), Some(12345));
        assert!(l.tick(&s, 20000));
        assert_eq!(l.rdmsr(&s, 0, MSR_TSC_DEADLINE), Some(0));
        // Masked: it fires without an interrupt.
        l.write(&s, 0, LVT_TIMER, (2 << 17) | LVT_MASKED | 0x20);
        l.wrmsr(&s, 0, MSR_TSC_DEADLINE, 1).unwrap();
        s.irr.iter().for_each(|w| w.store(0, Ordering::Relaxed));
        assert!(l.tick(&s, 2));
        assert_eq!(l.pending(&s), None);
    }
}
