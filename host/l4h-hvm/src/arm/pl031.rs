//! A PL031 RTC (DESIGN.md §5.11): seconds since the epoch from the host's
//! clock, set by writing its load register, with its match interrupt.  Its
//! vCPU threads share it under a lock.  Free of seL4.

const DR: u64 = 0x00;
const MR: u64 = 0x04;
const LR: u64 = 0x08;
const CR: u64 = 0x0c;
const IMSC: u64 = 0x10;
const RIS: u64 = 0x14;
const MIS: u64 = 0x18;
const ICR: u64 = 0x1c;

/// The PrimeCell identification registers from 0xfe0.
const ID: [u8; 8] = [0x31, 0x10, 0x04, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

pub struct Pl031 {
    /// Wall clock (ns since the epoch) at tick count `epoch_ticks`.
    epoch_ns: u64,
    epoch_ticks: u64,
    hz: u64,
    /// What to add to the clock's seconds (LR).
    offset: u32,
    mr: u32,
    imsc: bool,
    ris: bool,
    /// The match is armed: it fires once, when the time reaches MR.
    armed: bool,
}

impl Pl031 {
    pub fn new(epoch_ns: u64, epoch_ticks: u64, hz: u64) -> Self {
        Pl031 { epoch_ns, epoch_ticks, hz: hz.max(1), offset: 0, mr: 0, imsc: false, ris: false, armed: false }
    }

    fn base_secs(&self, now: u64) -> u32 {
        let dt = now.saturating_sub(self.epoch_ticks) as u128;
        let ns = self.epoch_ns as u128 + dt * 1_000_000_000 / self.hz as u128;
        (ns / 1_000_000_000) as u32
    }

    fn secs(&self, now: u64) -> u32 {
        self.base_secs(now).wrapping_add(self.offset)
    }

    /// The match, if the time reached it.
    pub fn poll(&mut self, now: u64) {
        if self.armed && self.secs(now).wrapping_sub(self.mr) < 1 << 31 {
            self.armed = false;
            self.ris = true;
        }
    }

    /// The interrupt line's level.
    pub fn irq(&self) -> bool {
        self.ris && self.imsc
    }

    /// When the match is due (ticks; 0: none armed).
    pub fn deadline(&self, now: u64) -> u64 {
        if !self.armed {
            return 0;
        }
        let left = self.mr.wrapping_sub(self.secs(now));
        if left >= 1 << 31 {
            return now;
        }
        now.saturating_add((left as u64).saturating_mul(self.hz)).max(1)
    }

    pub fn read(&mut self, off: u64, now: u64) -> u32 {
        self.poll(now);
        match off {
            DR => self.secs(now),
            MR => self.mr,
            LR => self.secs(now),
            CR => 1,
            IMSC => self.imsc as u32,
            RIS => self.ris as u32,
            MIS => (self.ris && self.imsc) as u32,
            0xfe0..=0xffc => ID[((off - 0xfe0) / 4) as usize] as u32,
            _ => 0,
        }
    }

    pub fn write(&mut self, off: u64, v: u32, now: u64) {
        match off {
            MR => {
                self.mr = v;
                self.armed = true;
                self.poll(now);
            }
            LR => {
                self.offset = v.wrapping_sub(self.base_secs(now));
                self.poll(now);
            }
            IMSC => self.imsc = v & 1 != 0,
            ICR if v & 1 != 0 => self.ris = false,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HZ: u64 = 1000;
    const T0: u64 = 5000;

    fn rtc() -> Pl031 {
        Pl031::new(1_700_000_000_000_000_000, T0, HZ)
    }

    #[test]
    fn identifies_and_counts() {
        let mut r = rtc();
        let id: std::vec::Vec<u32> = (0..8).map(|i| r.read(0xfe0 + 4 * i, T0)).collect();
        assert_eq!(id, [0x31, 0x10, 0x04, 0x00, 0x0d, 0xf0, 0x05, 0xb1]);
        assert_eq!(r.read(DR, T0), 1_700_000_000);
        assert_eq!(r.read(DR, T0 + 2500), 1_700_000_002);
        assert_eq!(r.read(CR, T0), 1, "always running");
    }

    #[test]
    fn load_sets_the_time() {
        let mut r = rtc();
        r.write(LR, 100, T0);
        assert_eq!(r.read(DR, T0), 100);
        assert_eq!(r.read(DR, T0 + 3000), 103);
    }

    #[test]
    fn match_interrupt() {
        let mut r = rtc();
        r.write(IMSC, 1, T0);
        r.write(MR, 1_700_000_005, T0);
        assert!(!r.irq());
        assert_eq!(r.deadline(T0), T0 + 5 * HZ);
        r.poll(T0 + 4999);
        assert!(!r.irq());
        r.poll(T0 + 5000);
        assert!(r.irq());
        assert_eq!(r.read(MIS, T0 + 5000), 1);
        assert_eq!(r.deadline(T0 + 5000), 0, "fired");
        r.write(ICR, 1, T0 + 5000);
        assert!(!r.irq());
        r.poll(T0 + 9000);
        assert!(!r.irq(), "once");
        // A match already past fires at once; masked, the line stays low.
        r.write(IMSC, 0, T0 + 9000);
        r.write(MR, 1, T0 + 9000);
        assert_eq!(r.read(RIS, T0 + 9000), 1);
        assert!(!r.irq());
    }
}
