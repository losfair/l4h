//! The 8254 PIT (ports 0x40-0x43) and port 0x61's speaker gate, counting at
//! 1.193182 MHz on the TSC: what Linux calibrates the TSC against where
//! CPUID leaf 0x15 says nothing (AMD).  No interrupts: a guest with the
//! TSC-deadline timer and ARAT, which CPUID offers, never needs the PIT's
//! (DESIGN.md §5.11).  Free of seL4.

pub const HZ: u64 = 1_193_182;

#[derive(Clone, Copy, Default)]
struct Channel {
    mode: u8,
    /// Access: 1 LSB, 2 MSB, 3 LSB then MSB.
    rw: u8,
    /// The count written (0 means 0x10000).
    count: u32,
    /// Bytes of a 16-bit count written and read so far.
    write_lsb: Option<u8>,
    read_msb_next: bool,
    latched: Option<u16>,
    /// When counting started (TSC), if it did.
    start: Option<u64>,
}

pub struct Pit {
    ch: [Channel; 3],
    gate2: bool,
    speaker: bool,
    refresh: bool,
    tsc_hz: u64,
}

impl Pit {
    pub const fn new(tsc_hz: u64) -> Self {
        let c = Channel { mode: 0, rw: 3, count: 0, write_lsb: None, read_msb_next: false, latched: None, start: None };
        Pit { ch: [c; 3], gate2: false, speaker: false, refresh: false, tsc_hz }
    }

    fn elapsed(&self, c: &Channel, now: u64) -> Option<u64> {
        let start = c.start?;
        Some((now.saturating_sub(start) as u128 * HZ as u128 / self.tsc_hz.max(1) as u128) as u64)
    }

    fn reload(c: &Channel) -> u64 {
        if c.count == 0 { 0x10000 } else { c.count as u64 }
    }

    /// The counter's value at `now`.
    fn value(&self, i: usize, now: u64) -> u16 {
        let c = &self.ch[i];
        let Some(e) = self.elapsed(c, now) else { return c.count as u16 };
        let n = Self::reload(c);
        match c.mode {
            // Rate generator and square wave reload at the terminal count.
            2 | 3 => (n - e % n) as u16,
            // Others count down through zero and wrap.
            _ => (n.wrapping_sub(e) & 0xffff) as u16,
        }
    }

    /// The counter's OUT at `now`.
    fn out(&self, i: usize, now: u64) -> bool {
        let c = &self.ch[i];
        let Some(e) = self.elapsed(c, now) else { return c.mode != 0 };
        let n = Self::reload(c);
        match c.mode {
            0 | 1 => e >= n,
            2 => e % n != n - 1,
            3 => e % n < n.div_ceil(2),
            _ => e != n,
        }
    }

    /// Counting runs while its gate is high: channel 2's is port 0x61 bit 0.
    fn gated(&self, i: usize) -> bool {
        i != 2 || self.gate2
    }

    pub fn read(&mut self, port: u16, now: u64) -> u8 {
        match port {
            0x40..=0x42 => {
                let i = (port - 0x40) as usize;
                let v = match self.ch[i].latched {
                    Some(v) => v,
                    None => self.value(i, now),
                };
                let c = &mut self.ch[i];
                match c.rw {
                    1 => {
                        c.latched = None;
                        v as u8
                    }
                    2 => {
                        c.latched = None;
                        (v >> 8) as u8
                    }
                    _ => {
                        let msb = c.read_msb_next;
                        c.read_msb_next = !msb;
                        if msb {
                            c.latched = None;
                            (v >> 8) as u8
                        } else {
                            // The MSB read next comes from the same value.
                            c.latched = Some(v);
                            v as u8
                        }
                    }
                }
            }
            0x43 => 0xff,
            0x61 => {
                // The refresh bit toggles: guests poll it to wait.
                self.refresh = !self.refresh;
                (self.gate2 as u8) | ((self.speaker as u8) << 1) | ((self.refresh as u8) << 4) | ((self.out(2, now) as u8) << 5)
            }
            _ => 0xff,
        }
    }

    pub fn write(&mut self, port: u16, val: u8, now: u64) {
        match port {
            0x40..=0x42 => {
                let i = (port - 0x40) as usize;
                let gated = self.gated(i);
                let c = &mut self.ch[i];
                let count = match c.rw {
                    1 => Some(val as u32),
                    2 => Some((val as u32) << 8),
                    _ => match c.write_lsb.take() {
                        Some(lsb) => Some(lsb as u32 | (val as u32) << 8),
                        None => {
                            c.write_lsb = Some(val);
                            None
                        }
                    },
                };
                if let Some(n) = count {
                    c.count = n;
                    c.start = gated.then_some(now);
                }
            }
            0x43 => {
                let i = (val >> 6) as usize;
                if i == 3 {
                    // Read-back: latch the counts of the channels selected
                    // (bit 5 clear means "latch count").
                    for j in 0..3 {
                        if val & (2 << j) != 0 && val & 0x20 == 0 {
                            let v = self.value(j, now);
                            self.ch[j].latched = Some(v);
                        }
                    }
                    return;
                }
                let rw = (val >> 4) & 3;
                if rw == 0 {
                    // Counter latch.
                    let v = self.value(i, now);
                    self.ch[i].latched = Some(v);
                    return;
                }
                let c = &mut self.ch[i];
                c.rw = rw;
                c.mode = match (val >> 1) & 7 {
                    6 => 2,
                    7 => 3,
                    m => m,
                };
                c.write_lsb = None;
                c.read_msb_next = false;
                c.latched = None;
                // A new mode stops the counter until its count is written.
                c.start = None;
            }
            0x61 => {
                let gate = val & 1 != 0;
                if gate && !self.gate2 {
                    // A rising gate (re)starts channel 2.
                    self.ch[2].start = Some(now);
                } else if !gate && self.ch[2].mode != 0 {
                    // Modes other than 0 stop with the gate low; mode 0's
                    // pause is not modelled (nothing calibrates so).
                    self.ch[2].start = None;
                }
                self.gate2 = gate;
                self.speaker = val & 2 != 0;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A TSC of HZ * 1000 ticks a second: 1000 TSC ticks per PIT tick.
    const TSC: u64 = HZ * 1000;

    #[test]
    fn calibration_sequence() {
        // As Linux's quick_pit_calibrate(): gate on, channel 2 mode 0,
        // LSB then MSB, count 0xffff, then read LSB and MSB.
        let mut p = Pit::new(TSC);
        p.write(0x61, 1, 0);
        p.write(0x43, 0xb0, 0);
        p.write(0x42, 0xff, 0);
        p.write(0x42, 0xff, 100);
        assert_eq!((p.read(0x42, 100), p.read(0x42, 100)), (0xff, 0xff));
        // 0x100 PIT ticks later the MSB has gone down by one.
        let t = 100 + 0x100 * 1000;
        let _ = p.read(0x42, t);
        assert_eq!(p.read(0x42, t + 999_000), 0xfe, "MSB from the value latched with the LSB");
        // OUT2 rises at the terminal count.
        assert_eq!(p.read(0x61, 100) & 0x20, 0);
        assert!(p.read(0x61, 100 + 0x10000 * 1000) & 0x20 != 0);
    }

    #[test]
    fn latch_modes_and_readback() {
        let mut p = Pit::new(TSC);
        // Channel 0, mode 2, count 1000.
        p.write(0x43, 0x34, 0);
        p.write(0x40, 0xe8, 0);
        p.write(0x40, 0x03, 0);
        p.write(0x43, 0x00, 250_000);
        let (lo, hi) = (p.read(0x40, 900_000), p.read(0x40, 900_000));
        assert_eq!(lo as u16 | (hi as u16) << 8, 750, "the latched count");
        // Mode 2 reloads.
        p.write(0x43, 0x00, 1_250_000);
        let v = p.read(0x40, 0) as u16 | (p.read(0x40, 0) as u16) << 8;
        assert_eq!(v, 750);
        // Read-back of channel 0's count.
        p.write(0x43, 0xd2, 500_000);
        let v = p.read(0x40, 0) as u16 | (p.read(0x40, 0) as u16) << 8;
        assert_eq!(v, 500);
        // Without a gate, channel 2 does not count.
        p.write(0x43, 0xb0, 0);
        p.write(0x42, 0x10, 0);
        p.write(0x42, 0x00, 0);
        assert_eq!(p.read(0x42, 5_000_000), 0x10);
        // The refresh bit toggles.
        assert_ne!(p.read(0x61, 0) & 0x10, p.read(0x61, 0) & 0x10);
    }
}
