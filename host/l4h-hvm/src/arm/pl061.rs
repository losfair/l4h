//! A PL061 GPIO controller (DESIGN.md §5.11): pin 3 is the power button,
//! which the guest's gpio-keys driver reads and takes interrupts from.  Its
//! vCPU threads share it under a lock.  Free of seL4.

const DATA_END: u64 = 0x400;
const DIR: u64 = 0x400;
const IS: u64 = 0x404;
const IBE: u64 = 0x408;
const IEV: u64 = 0x40c;
const IE: u64 = 0x410;
const RIS: u64 = 0x414;
const MIS: u64 = 0x418;
const IC: u64 = 0x41c;
const AFSEL: u64 = 0x420;

/// The pin of the power button (QEMU virt's).
pub const PIN_POWER: u32 = 3;

/// The PrimeCell identification registers from 0xfe0.
const ID: [u8; 8] = [0x61, 0x10, 0x04, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

#[derive(Default)]
pub struct Pl061 {
    /// What the pins are driven to from outside, and by the guest.
    input: u8,
    output: u8,
    dir: u8,
    is: u8,
    ibe: u8,
    iev: u8,
    ie: u8,
    /// Latched edges (level-sensitive pins are computed).
    edges: u8,
    afsel: u8,
}

impl Pl061 {
    pub const fn new() -> Self {
        Pl061 { input: 0, output: 0, dir: 0, is: 0, ibe: 0, iev: 0, ie: 0, edges: 0, afsel: 0 }
    }

    fn pins(&self) -> u8 {
        (self.input & !self.dir) | (self.output & self.dir)
    }

    fn ris(&self) -> u8 {
        let pins = self.pins();
        let level = self.is & !(pins ^ self.iev);
        (self.edges & !self.is) | level
    }

    /// The interrupt line's level.
    pub fn irq(&self) -> bool {
        self.ris() & self.ie != 0
    }

    /// Pins go from `old` to what they are now: edges latch.
    fn edges_from(&mut self, old: u8) {
        let new = self.pins();
        let changed = old ^ new;
        let both = changed & self.ibe;
        let one = changed & !self.ibe & !(new ^ self.iev);
        self.edges |= (both | one) & !self.is;
    }

    /// An outside pin goes to `level`.
    pub fn set_input(&mut self, pin: u32, level: bool) {
        let old = self.pins();
        let b = 1u8 << pin;
        self.input = if level { self.input | b } else { self.input & !b };
        self.edges_from(old);
    }

    pub fn read(&self, off: u64) -> u32 {
        (match off {
            // The address's bits [9:2] mask the pins read.
            o if o < DATA_END => self.pins() & (o >> 2) as u8,
            DIR => self.dir,
            IS => self.is,
            IBE => self.ibe,
            IEV => self.iev,
            IE => self.ie,
            RIS => self.ris(),
            MIS => self.ris() & self.ie,
            AFSEL => self.afsel,
            0xfe0..=0xffc => ID[((off - 0xfe0) / 4) as usize],
            _ => 0,
        }) as u32
    }

    pub fn write(&mut self, off: u64, v: u32) {
        let v8 = v as u8;
        let old = self.pins();
        match off {
            o if o < DATA_END => {
                let mask = (o >> 2) as u8;
                self.output = (self.output & !mask) | (v8 & mask);
            }
            DIR => self.dir = v8,
            IS => self.is = v8,
            IBE => self.ibe = v8,
            IEV => self.iev = v8,
            IE => self.ie = v8,
            IC => self.edges &= !v8,
            AFSEL => self.afsel = v8,
            _ => return,
        }
        self.edges_from(old);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: u8 = 1 << PIN_POWER;

    #[test]
    fn identifies_and_masks_data_by_address() {
        let mut g = Pl061::new();
        let id: std::vec::Vec<u32> = (0..8).map(|i| g.read(0xfe0 + 4 * i)).collect();
        assert_eq!(id, [0x61, 0x10, 0x04, 0x00, 0x0d, 0xf0, 0x05, 0xb1]);
        g.set_input(PIN_POWER, true);
        assert_eq!(g.read((B as u64) << 2), B as u32);
        assert_eq!(g.read(0x3fc), B as u32);
        assert_eq!(g.read(1 << 2), 0, "another pin's mask");
        // A write only reaches the pins its address names.
        g.write(DIR, 0x03);
        g.write(0x1 << 2, 0xff);
        assert_eq!(g.read(0x3fc), B as u32 | 1);
    }

    #[test]
    fn both_edges_as_gpio_keys_asks() {
        let mut g = Pl061::new();
        g.write(IBE, B as u32);
        g.write(IE, B as u32);
        assert!(!g.irq());
        g.set_input(PIN_POWER, true);
        assert!(g.irq(), "pressed");
        assert_eq!(g.read(MIS), B as u32);
        g.write(IC, B as u32);
        assert!(!g.irq());
        g.set_input(PIN_POWER, false);
        assert!(g.irq(), "released");
    }

    #[test]
    fn one_edge_and_masking() {
        let mut g = Pl061::new();
        g.write(IEV, B as u32);
        g.set_input(PIN_POWER, true);
        assert_eq!(g.read(RIS), B as u32, "rising");
        assert!(!g.irq(), "not enabled");
        g.write(IE, B as u32);
        assert!(g.irq());
        g.write(IC, B as u32);
        g.set_input(PIN_POWER, false);
        assert!(!g.irq(), "the falling edge is not asked for");
    }

    #[test]
    fn level_sensitive_follows_the_pin() {
        let mut g = Pl061::new();
        g.write(IS, B as u32);
        g.write(IEV, B as u32);
        g.write(IE, B as u32);
        assert!(!g.irq());
        g.set_input(PIN_POWER, true);
        assert!(g.irq());
        g.write(IC, B as u32);
        assert!(g.irq(), "a level is not cleared");
        g.set_input(PIN_POWER, false);
        assert!(!g.irq());
    }
}
