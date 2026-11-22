//! The MC146818 CMOS RTC (ports 0x70 and 0x71): the wall clock vmmgr knows
//! (HvmConfig::epoch_ns at tick epoch_ticks), BCD or binary, 12 or 24
//! hours as status register B says, the guest's writes kept as an offset,
//! and CMOS memory.  No update-ended or alarm interrupts (UIP always reads
//! clear).  Free of seL4.

const SECONDS: usize = 0x00;
const MINUTES: usize = 0x02;
const HOURS: usize = 0x04;
const WEEKDAY: usize = 0x06;
const DAY: usize = 0x07;
const MONTH: usize = 0x08;
const YEAR: usize = 0x09;
const REG_A: usize = 0x0a;
const REG_B: usize = 0x0b;
const REG_C: usize = 0x0c;
const REG_D: usize = 0x0d;
const CENTURY: usize = 0x32;

const B_SET: u8 = 1 << 7;
const B_BINARY: u8 = 1 << 2;
const B_24H: u8 = 1 << 1;

pub struct Rtc {
    index: u8,
    cmos: [u8; 128],
    /// Seconds since the epoch at TSC 0, as the guest last set it.
    offset: i64,
    tsc_hz: u64,
}

/// The civil date (year, month, day) of `days` since 1970-01-01.
pub fn civil(days: i64) -> (i64, u32, u32) {
    // Howard Hinnant's days_from_civil, inverted.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Days since 1970-01-01 of a civil date.
pub fn days(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

impl Rtc {
    /// `epoch_ns` (0 if unknown: 2000-01-01) at TSC `epoch_ticks`.
    pub fn new(epoch_ns: u64, epoch_ticks: u64, tsc_hz: u64) -> Self {
        let tsc_hz = tsc_hz.max(1);
        let base = if epoch_ns == 0 { 946_684_800 } else { (epoch_ns / 1_000_000_000) as i64 };
        let mut r = Rtc { index: 0, cmos: [0; 128], offset: base - (epoch_ticks / tsc_hz) as i64, tsc_hz };
        r.cmos[REG_A] = 0x26;
        r.cmos[REG_B] = B_24H;
        r.cmos[REG_D] = 0x80;
        r
    }

    fn now(&self, tsc: u64) -> i64 {
        self.offset + (tsc / self.tsc_hz) as i64
    }

    fn bcd(&self, v: u32) -> u8 {
        if self.cmos[REG_B] & B_BINARY != 0 { v as u8 } else { (((v / 10) << 4) | (v % 10)) as u8 }
    }

    fn of_bcd(&self, v: u8) -> u32 {
        if self.cmos[REG_B] & B_BINARY != 0 { v as u32 } else { (v >> 4) as u32 * 10 + (v & 0xf) as u32 }
    }

    /// The time registers at `tsc`.
    fn time(&self, tsc: u64) -> [u8; 10] {
        let t = self.now(tsc);
        let (day, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400) as u32);
        let (y, m, d) = civil(day);
        let (h, min, s) = (secs / 3600, secs / 60 % 60, secs % 60);
        let hour = if self.cmos[REG_B] & B_24H != 0 {
            self.bcd(h)
        } else {
            let h12 = if h % 12 == 0 { 12 } else { h % 12 };
            self.bcd(h12) | if h >= 12 { 0x80 } else { 0 }
        };
        let mut r = [0; 10];
        r[SECONDS] = self.bcd(s);
        r[MINUTES] = self.bcd(min);
        r[HOURS] = hour;
        r[WEEKDAY] = self.bcd(((day + 4).rem_euclid(7) + 1) as u32);
        r[DAY] = self.bcd(d);
        r[MONTH] = self.bcd(m);
        r[YEAR] = self.bcd(y.rem_euclid(100) as u32);
        r
    }

    pub fn read(&mut self, port: u16, tsc: u64) -> u8 {
        if port == 0x70 {
            return self.index;
        }
        let i = (self.index & 0x7f) as usize;
        match i {
            SECONDS..=YEAR if i.is_multiple_of(2) || i >= WEEKDAY => {
                if self.cmos[REG_B] & B_SET != 0 { self.cmos[i] } else { self.time(tsc)[i] }
            }
            CENTURY => {
                let y = civil(self.now(tsc).div_euclid(86_400)).0;
                self.bcd((y / 100) as u32)
            }
            // UIP never set: an update is always done.
            REG_A => self.cmos[REG_A] & 0x7f,
            REG_C => 0,
            _ => self.cmos[i],
        }
    }

    pub fn write(&mut self, port: u16, val: u8, tsc: u64) {
        if port == 0x70 {
            self.index = val;
            return;
        }
        let i = (self.index & 0x7f) as usize;
        match i {
            REG_B => {
                let was_set = self.cmos[REG_B] & B_SET != 0;
                if val & B_SET != 0 && !was_set {
                    // Freeze: the time registers keep what they read.
                    let t = self.time(tsc);
                    self.cmos[..10].copy_from_slice(&t);
                }
                self.cmos[REG_B] = val;
                if val & B_SET == 0 && was_set {
                    self.set_from_registers(tsc);
                }
            }
            REG_C | REG_D => {}
            SECONDS..=YEAR | CENTURY => {
                self.cmos[i] = val;
                if self.cmos[REG_B] & B_SET == 0 {
                    // A guest that writes without SET: take the time now.
                    let t = self.time(tsc);
                    for (j, &b) in t.iter().enumerate() {
                        if j != i {
                            self.cmos[j] = b;
                        }
                    }
                    self.set_from_registers(tsc);
                }
            }
            _ => self.cmos[i] = val,
        }
    }

    fn set_from_registers(&mut self, tsc: u64) {
        let c = &self.cmos;
        let hour = if c[REG_B] & B_24H != 0 {
            self.of_bcd(c[HOURS])
        } else {
            let h = self.of_bcd(c[HOURS] & 0x7f) % 12;
            h + if c[HOURS] & 0x80 != 0 { 12 } else { 0 }
        };
        let century = match self.of_bcd(c[CENTURY]) {
            0 => 20,
            n => n,
        } as i64;
        let year = century * 100 + self.of_bcd(c[YEAR]) as i64;
        let (month, day) = (self.of_bcd(c[MONTH]).clamp(1, 12), self.of_bcd(c[DAY]).clamp(1, 31));
        let t = days(year, month, day) * 86_400 + hour as i64 * 3600 + self.of_bcd(c[MINUTES]) as i64 * 60
            + self.of_bcd(c[SECONDS]) as i64;
        self.offset = t - (tsc / self.tsc_hz) as i64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(r: &mut Rtc, i: u8, tsc: u64) -> u8 {
        r.write(0x70, i, tsc);
        r.read(0x71, tsc)
    }

    #[test]
    fn calendar() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(days(2000, 2, 29)), (2000, 2, 29));
        assert_eq!(civil(days(2026, 11, 22)), (2026, 11, 22));
        assert_eq!(days(1969, 12, 31), -1);
    }

    #[test]
    fn reads_and_sets() {
        // 2026-11-22 20:24:37 UTC, at TSC 3e9 with a 1 GHz TSC.
        let t = (days(2026, 11, 22) * 86_400 + 20 * 3600 + 24 * 60 + 37) as u64;
        let mut r = Rtc::new(t * 1_000_000_000, 3_000_000_000, 1_000_000_000);
        let now = 3_000_000_000;
        assert_eq!(reg(&mut r, 0x00, now), 0x37);
        assert_eq!(reg(&mut r, 0x02, now), 0x24);
        assert_eq!(reg(&mut r, 0x04, now), 0x20);
        assert_eq!(reg(&mut r, 0x07, now), 0x22);
        assert_eq!(reg(&mut r, 0x08, now), 0x11);
        assert_eq!(reg(&mut r, 0x09, now), 0x26);
        assert_eq!(reg(&mut r, 0x32, now), 0x20);
        assert_eq!(reg(&mut r, 0x06, now), 0x01, "a Sunday");
        assert_eq!(reg(&mut r, 0x0d, now), 0x80);
        // Ten seconds later.
        assert_eq!(reg(&mut r, 0x00, now + 10_000_000_000), 0x47);
        // Binary, 12-hour mode.
        r.write(0x70, 0x0b, now);
        r.write(0x71, B_BINARY, now);
        assert_eq!(reg(&mut r, 0x04, now), 8 | 0x80);
        // Set 1999-12-31 23:59:50 with SET held.
        r.write(0x70, 0x0b, now);
        r.write(0x71, B_SET | B_24H, now);
        for (i, v) in [(0x00, 50u8), (0x02, 59), (0x04, 23), (0x07, 31), (0x08, 12), (0x09, 99), (0x32, 19)] {
            r.write(0x70, i, now);
            r.write(0x71, v, now);
        }
        r.write(0x70, 0x0b, now);
        r.write(0x71, B_24H | B_BINARY, now);
        assert_eq!(reg(&mut r, 0x09, now + 20_000_000_000), 0, "into 2000");
        assert_eq!(reg(&mut r, 0x32, now + 20_000_000_000), 20);
        // CMOS memory.
        r.write(0x70, 0x40, now);
        r.write(0x71, 0x5a, now);
        assert_eq!(reg(&mut r, 0x40, now), 0x5a);
    }
}
