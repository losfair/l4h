//! The guest's flattened device tree (DESIGN.md §5.11), written with no heap
//! into a buffer l4h-hvm has for it: the machine as Linux finds it on QEMU's
//! `virt` board, with this monitor's layout (l4h_host::hvm::arm).  Free of
//! seL4.

use l4h_rt::host::hvm::arm::*;

const MAGIC: u32 = 0xd00d_feed;
const VERSION: u32 = 17;
const LAST_COMP: u32 = 16;
const HEADER: usize = 40;
/// An empty memory reservation block.
const RSVMAP: usize = 16;
const BEGIN_NODE: u32 = 1;
const END_NODE: u32 = 2;
const PROP: u32 = 3;
const END: u32 = 9;
/// Property names, dedicated.
const STRINGS: usize = 1024;

/// Too large for its buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLarge;

/// Writes a tree into `buf`: nodes and properties in order, then `finish`.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    at: usize,
    strings: [u8; STRINGS],
    nstr: usize,
    depth: usize,
    failed: bool,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        let failed = buf.len() < HEADER + RSVMAP;
        if !failed {
            buf[..HEADER + RSVMAP].fill(0);
        }
        Writer { buf, at: HEADER + RSVMAP, strings: [0; STRINGS], nstr: 0, depth: 0, failed }
    }

    fn put(&mut self, b: &[u8]) {
        match self.buf.get_mut(self.at..self.at + b.len()) {
            Some(d) if !self.failed => {
                d.copy_from_slice(b);
                self.at += b.len();
            }
            _ => self.failed = true,
        }
    }

    fn word(&mut self, v: u32) {
        self.put(&v.to_be_bytes());
    }

    fn pad(&mut self) {
        while !self.failed && !self.at.is_multiple_of(4) {
            self.put(&[0]);
        }
    }

    /// Where a property's name is in the strings block, added if it is new.
    fn name(&mut self, name: &str) -> u32 {
        let n = name.as_bytes();
        let mut i = 0;
        while i < self.nstr {
            let end = i + self.strings[i..self.nstr].iter().position(|&c| c == 0).unwrap_or(0);
            if &self.strings[i..end] == n {
                return i as u32;
            }
            i = end + 1;
        }
        let at = self.nstr;
        if at + n.len() + 1 > STRINGS {
            self.failed = true;
            return 0;
        }
        self.strings[at..at + n.len()].copy_from_slice(n);
        self.strings[at + n.len()] = 0;
        self.nstr = at + n.len() + 1;
        at as u32
    }

    pub fn begin(&mut self, name: &str) {
        self.word(BEGIN_NODE);
        self.put(name.as_bytes());
        self.put(&[0]);
        self.pad();
        self.depth += 1;
    }

    /// A node `name@<addr in hex>`.
    pub fn begin_at(&mut self, name: &str, addr: u64) {
        self.word(BEGIN_NODE);
        self.put(name.as_bytes());
        self.put(b"@");
        let digits = ((64 - (addr | 1).leading_zeros()).div_ceil(4)) as usize;
        for i in (0..digits).rev() {
            let d = ((addr >> (4 * i)) & 0xf) as u8;
            self.put(&[if d < 10 { b'0' + d } else { b'a' + d - 10 }]);
        }
        self.put(&[0]);
        self.pad();
        self.depth += 1;
    }

    pub fn end(&mut self) {
        self.word(END_NODE);
        self.depth = self.depth.saturating_sub(1);
    }

    pub fn prop(&mut self, name: &str, value: &[u8]) {
        let off = self.name(name);
        self.word(PROP);
        self.word(value.len() as u32);
        self.word(off);
        self.put(value);
        self.pad();
    }

    pub fn empty(&mut self, name: &str) {
        self.prop(name, &[]);
    }

    pub fn u32(&mut self, name: &str, v: u32) {
        self.prop(name, &v.to_be_bytes());
    }

    pub fn u64(&mut self, name: &str, v: u64) {
        self.prop(name, &v.to_be_bytes());
    }

    pub fn cells(&mut self, name: &str, v: &[u32]) {
        let off = self.name(name);
        self.word(PROP);
        self.word(v.len() as u32 * 4);
        self.word(off);
        for &c in v {
            self.word(c);
        }
    }

    /// `reg`-style pairs of 64-bit numbers.
    pub fn u64s(&mut self, name: &str, v: &[u64]) {
        let off = self.name(name);
        self.word(PROP);
        self.word(v.len() as u32 * 8);
        self.word(off);
        for &c in v {
            self.put(&c.to_be_bytes());
        }
    }

    pub fn string(&mut self, name: &str, s: &str) {
        self.strings_prop(name, &[s]);
    }

    /// A string property of raw bytes, NUL-terminated here.
    pub fn prop_nul(&mut self, name: &str, value: &[u8]) {
        let off = self.name(name);
        self.word(PROP);
        self.word(value.len() as u32 + 1);
        self.word(off);
        self.put(value);
        self.put(&[0]);
        self.pad();
    }

    /// A string list (`compatible`).
    pub fn strings_prop(&mut self, name: &str, list: &[&str]) {
        let off = self.name(name);
        let len: usize = list.iter().map(|s| s.len() + 1).sum();
        self.word(PROP);
        self.word(len as u32);
        self.word(off);
        for s in list {
            self.put(s.as_bytes());
            self.put(&[0]);
        }
        self.pad();
    }

    /// The tree's size in `buf`, complete with its header.
    pub fn finish(mut self) -> Result<usize, TooLarge> {
        if self.depth != 0 {
            return Err(TooLarge);
        }
        self.word(END);
        let off_strings = self.at;
        let size_struct = off_strings - (HEADER + RSVMAP);
        let (strings, n) = (self.strings, self.nstr);
        self.put(&strings[..n]);
        if self.failed {
            return Err(TooLarge);
        }
        let total = self.at;
        let header = [
            MAGIC, total as u32, (HEADER + RSVMAP) as u32, off_strings as u32, HEADER as u32, VERSION, LAST_COMP,
            0, n as u32, size_struct as u32,
        ];
        for (i, w) in header.iter().enumerate() {
            self.buf[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        Ok(total)
    }
}

const PH_GIC: u32 = 1;
const PH_V2M: u32 = 2;
const PH_CLK: u32 = 3;
const PH_GPIO: u32 = 4;

/// GIC interrupt specifiers.
const GIC_SPI: u32 = 0;
const GIC_PPI: u32 = 1;
const IRQ_LEVEL_HIGH: u32 = 4;
/// PPIs of the architected timer, as the binding orders them.
const TIMER_PPIS: [u32; 4] = [13, 14, 11, 10];
/// `linux,code` of KEY_POWER.
const KEY_POWER: u32 = 116;

/// The machine a tree describes.
pub struct Machine<'a> {
    pub vcpus: usize,
    pub gicv3: bool,
    pub ram_base: u64,
    pub ram: u64,
    pub cmdline: &'a [u8],
    /// (start, end) of the initrd, if there is one.
    pub initrd: Option<(u64, u64)>,
}

fn hi(v: u64) -> u32 {
    (v >> 32) as u32
}

fn lo(v: u64) -> u32 {
    v as u32
}

/// `reg` of one device: 2 address cells and 2 size cells.
fn reg1(w: &mut Writer, base: u64, size: u64) {
    w.u64s("reg", &[base, size]);
}

fn primecell(w: &mut Writer, compat: &str, base: u64, spi: u32) {
    w.strings_prop("compatible", &[compat, "arm,primecell"]);
    reg1(w, base, PRIMECELL_SIZE);
    w.cells("interrupts", &[GIC_SPI, spi, IRQ_LEVEL_HIGH]);
}

fn gic(w: &mut Writer, m: &Machine) {
    w.begin_at("intc", GICD_BASE);
    w.u32("phandle", PH_GIC);
    w.u32("#interrupt-cells", 3);
    w.empty("interrupt-controller");
    w.u32("#address-cells", 2);
    w.u32("#size-cells", 2);
    w.empty("ranges");
    if m.gicv3 {
        w.string("compatible", "arm,gic-v3");
        w.u64s("reg", &[GICD_BASE, GICD_SIZE, GICR_BASE, m.vcpus as u64 * GICR_STRIDE]);
        // Message-based SPIs: the doorbell is GICD_SETSPI_NSR.
        w.empty("msi-controller");
        w.cells("mbi-ranges", &[MSI_BASE, MSI_COUNT]);
    } else {
        w.string("compatible", "arm,cortex-a15-gic");
        w.u64s("reg", &[GICD_BASE, GICD_SIZE, GICC_BASE, GICC_SIZE]);
        w.begin_at("v2m", V2M_BASE);
        w.string("compatible", "arm,gic-v2m-frame");
        w.empty("msi-controller");
        w.u32("phandle", PH_V2M);
        reg1(w, V2M_BASE, V2M_SIZE);
        w.end();
    }
    w.end();
}

fn pci(w: &mut Writer, m: &Machine) {
    w.begin_at("pcie", ECAM_BASE);
    w.string("compatible", "pci-host-ecam-generic");
    w.string("device_type", "pci");
    w.u32("#address-cells", 3);
    w.u32("#size-cells", 2);
    w.u32("#interrupt-cells", 1);
    w.cells("bus-range", &[0, 0]);
    reg1(w, ECAM_BASE, ECAM_SIZE);
    w.empty("dma-coherent");
    // One 32-bit, non-prefetchable window.
    w.cells("ranges", &[0x0200_0000, hi(PCI_MMIO_BASE), lo(PCI_MMIO_BASE), hi(PCI_MMIO_BASE), lo(PCI_MMIO_BASE),
        hi(PCI_MMIO_SIZE), lo(PCI_MMIO_SIZE)]);
    w.u32("msi-parent", if m.gicv3 { PH_GIC } else { PH_V2M });
    // INTA#-INTD# of the first four slots, swizzled onto the four lines;
    // the mask repeats them for the others.
    w.cells("interrupt-map-mask", &[0x1800, 0, 0, 7]);
    let n = PCI_INTX_LINES as usize;
    let off = w.name("interrupt-map");
    w.word(PROP);
    w.word((n * n * 10 * 4) as u32);
    w.word(off);
    for dev in 0..n as u32 {
        for pin in 1..=n as u32 {
            let spi = PCI_INTX_SPI + (dev + pin - 1) % PCI_INTX_LINES;
            for c in [dev << 11, 0, 0, pin, PH_GIC, 0, 0, GIC_SPI, spi, IRQ_LEVEL_HIGH] {
                w.word(c);
            }
        }
    }
    w.end();
}

/// Write the tree of machine `m` into `buf`: its size.
pub fn build(buf: &mut [u8], m: &Machine) -> Result<usize, TooLarge> {
    let mut w = Writer::new(buf);
    w.begin("");
    w.strings_prop("compatible", &["linux,dummy-virt"]);
    w.string("model", "l4h-hvm");
    w.u32("#address-cells", 2);
    w.u32("#size-cells", 2);
    w.u32("interrupt-parent", PH_GIC);

    w.begin("chosen");
    // As given, whatever its encoding: up to its NUL, with one.
    let n = m.cmdline.iter().position(|&b| b == 0).unwrap_or(m.cmdline.len());
    w.prop_nul("bootargs", &m.cmdline[..n]);
    // QEMU's name for its UART's node.
    let mut path = [0u8; 32];
    let len = {
        let p = b"/pl011@9000000";
        path[..p.len()].copy_from_slice(p);
        p.len()
    };
    w.string("stdout-path", core::str::from_utf8(&path[..len]).unwrap_or(""));
    if let Some((start, end)) = m.initrd {
        w.u64("linux,initrd-start", start);
        w.u64("linux,initrd-end", end);
    }
    w.end();

    w.begin_at("memory", m.ram_base);
    w.string("device_type", "memory");
    reg1(&mut w, m.ram_base, m.ram);
    w.end();

    w.begin("cpus");
    w.u32("#address-cells", 1);
    w.u32("#size-cells", 0);
    for v in 0..m.vcpus {
        let aff = mpidr_aff(v);
        w.begin_at("cpu", aff);
        w.string("device_type", "cpu");
        w.string("compatible", "arm,armv8");
        w.u32("reg", aff as u32);
        w.string("enable-method", "psci");
        w.end();
    }
    w.end();

    w.begin("psci");
    w.strings_prop("compatible", &["arm,psci-1.0", "arm,psci-0.2"]);
    w.string("method", "hvc");
    w.end();

    w.begin("timer");
    w.string("compatible", "arm,armv8-timer");
    w.empty("always-on");
    // GICv2's PPI specifiers name the CPUs they reach.
    let flags = IRQ_LEVEL_HIGH | if m.gicv3 { 0 } else { (((1u32 << m.vcpus.min(8)) - 1) & 0xff) << 8 };
    let mut t = [0u32; 12];
    for (i, ppi) in TIMER_PPIS.iter().enumerate() {
        t[3 * i..3 * i + 3].copy_from_slice(&[GIC_PPI, *ppi, flags]);
    }
    w.cells("interrupts", &t);
    w.end();

    gic(&mut w, m);

    w.begin("apb-pclk");
    w.string("compatible", "fixed-clock");
    w.u32("#clock-cells", 0);
    w.u32("clock-frequency", 24_000_000);
    w.string("clock-output-names", "clk24mhz");
    w.u32("phandle", PH_CLK);
    w.end();

    w.begin_at("pl011", UART_BASE);
    primecell(&mut w, "arm,pl011", UART_BASE, UART_SPI);
    w.cells("clocks", &[PH_CLK, PH_CLK]);
    w.strings_prop("clock-names", &["uartclk", "apb_pclk"]);
    w.end();

    w.begin_at("pl031", RTC_BASE);
    primecell(&mut w, "arm,pl031", RTC_BASE, RTC_SPI);
    w.u32("clocks", PH_CLK);
    w.string("clock-names", "apb_pclk");
    w.end();

    w.begin_at("pl061", GPIO_BASE);
    primecell(&mut w, "arm,pl061", GPIO_BASE, GPIO_SPI);
    w.u32("clocks", PH_CLK);
    w.string("clock-names", "apb_pclk");
    w.empty("gpio-controller");
    w.u32("#gpio-cells", 2);
    w.empty("interrupt-controller");
    w.u32("#interrupt-cells", 2);
    w.u32("phandle", PH_GPIO);
    w.end();

    w.begin("gpio-keys");
    w.string("compatible", "gpio-keys");
    // The input device's name, which tests and logind go by.
    w.string("label", "Power Button");
    w.begin("poweroff");
    w.string("label", "Power Button");
    w.cells("gpios", &[PH_GPIO, super::pl061::PIN_POWER, 0]);
    w.u32("linux,code", KEY_POWER);
    w.end();
    w.end();

    pci(&mut w, m);

    w.end();
    w.finish()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::string::String;
    use std::vec::Vec;

    fn be(b: &[u8], at: usize) -> u32 {
        u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
    }

    /// A parsed tree: the nodes' paths, with their properties.
    pub fn parse(b: &[u8]) -> Vec<(String, Vec<(String, Vec<u8>)>)> {
        assert_eq!(be(b, 0), MAGIC);
        assert_eq!(be(b, 20), VERSION);
        let (off_struct, off_str, size) = (be(b, 8) as usize, be(b, 12) as usize, be(b, 4) as usize);
        assert!(off_str < size && size <= b.len());
        assert_eq!(&b[be(b, 16) as usize..be(b, 16) as usize + 16], &[0; 16], "an empty reservation map");
        let name_at = |o: usize| {
            let s = &b[off_str + o..];
            String::from_utf8(s[..s.iter().position(|&c| c == 0).unwrap()].to_vec()).unwrap()
        };
        let (mut at, mut path, mut out): (usize, Vec<String>, Vec<(String, Vec<(String, Vec<u8>)>)>) = (off_struct, Vec::new(), Vec::new());
        loop {
            let t = be(b, at);
            at += 4;
            match t {
                BEGIN_NODE => {
                    let s = &b[at..];
                    let n = s.iter().position(|&c| c == 0).unwrap();
                    path.push(String::from_utf8(s[..n].to_vec()).unwrap());
                    at = (at + n + 1).next_multiple_of(4);
                    out.push((path.join("/"), Vec::new()));
                }
                END_NODE => {
                    path.pop();
                }
                PROP => {
                    let (len, off) = (be(b, at) as usize, be(b, at + 4) as usize);
                    at += 8;
                    let at_node = path.join("/");
                    let node = out.iter_mut().rev().find(|(p, _)| *p == at_node).unwrap();
                    node.1.push((name_at(off), b[at..at + len].to_vec()));
                    at = (at + len).next_multiple_of(4);
                }
                END => break,
                x => panic!("token {x} at {at:#x}"),
            }
        }
        assert!(path.is_empty(), "unbalanced");
        out
    }

    pub fn prop<'t>(t: &'t [(String, Vec<(String, Vec<u8>)>)], node: &str, name: &str) -> Option<&'t [u8]> {
        let n = t.iter().find(|(p, _)| p == node || p.ends_with(&std::format!("/{node}")))?;
        n.1.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_slice())
    }

    fn machine(gicv3: bool, vcpus: usize) -> Vec<u8> {
        let mut b = std::vec![0u8; 1 << 16];
        let m = Machine { vcpus, gicv3, ram_base: RAM_BASE, ram: 256 << 20, cmdline: b"console=ttyAMA0 x=1\0junk", initrd: Some((0x4800_0000, 0x4810_0000)) };
        let n = build(&mut b, &m).unwrap();
        b.truncate(n);
        b
    }

    #[test]
    fn gicv3_machine() {
        let b = machine(true, 18);
        let t = parse(&b);
        assert_eq!(prop(&t, "chosen", "bootargs").unwrap(), b"console=ttyAMA0 x=1\0");
        assert_eq!(prop(&t, "chosen", "linux,initrd-start").unwrap(), 0x4800_0000u64.to_be_bytes());
        assert_eq!(prop(&t, "chosen", "linux,initrd-end").unwrap(), 0x4810_0000u64.to_be_bytes());
        assert_eq!(prop(&t, "chosen", "stdout-path").unwrap(), b"/pl011@9000000\0");
        let mem = prop(&t, "memory@40000000", "reg").unwrap();
        assert_eq!(&mem[..8], RAM_BASE.to_be_bytes());
        assert_eq!(&mem[8..16], (256u64 << 20).to_be_bytes());
        // CPU 17: Aff1 1, Aff0 1.
        assert_eq!(prop(&t, "cpus/cpu@101", "reg").unwrap(), 0x101u32.to_be_bytes());
        assert_eq!(prop(&t, "cpus/cpu@101", "enable-method").unwrap(), b"psci\0");
        assert_eq!(t.iter().filter(|(p, _)| p.contains("cpus/cpu@")).count(), 18);
        assert_eq!(prop(&t, "psci", "method").unwrap(), b"hvc\0");
        assert_eq!(prop(&t, "intc@8000000", "compatible").unwrap(), b"arm,gic-v3\0");
        let reg = prop(&t, "intc@8000000", "reg").unwrap();
        assert_eq!(&reg[16..24], GICR_BASE.to_be_bytes());
        assert_eq!(&reg[24..32], (18 * GICR_STRIDE).to_be_bytes());
        let mbi = prop(&t, "intc@8000000", "mbi-ranges").unwrap();
        assert_eq!(mbi, [MSI_BASE.to_be_bytes(), MSI_COUNT.to_be_bytes()].concat());
        assert!(prop(&t, "intc@8000000", "msi-controller").is_some());
        assert_eq!(prop(&t, "pcie@3f000000", "msi-parent").unwrap(), PH_GIC.to_be_bytes());
        // The timer's PPIs, with no CPU mask on GICv3.
        let timer = prop(&t, "timer", "interrupts").unwrap();
        assert_eq!(be(timer, 2 * 12 + 4), 11, "the virtual timer");
        assert_eq!(be(timer, 8), IRQ_LEVEL_HIGH);
    }

    #[test]
    fn gicv2_machine() {
        let b = machine(false, 2);
        let t = parse(&b);
        assert_eq!(prop(&t, "intc@8000000", "compatible").unwrap(), b"arm,cortex-a15-gic\0");
        let reg = prop(&t, "intc@8000000", "reg").unwrap();
        assert_eq!(&reg[16..24], GICC_BASE.to_be_bytes());
        assert_eq!(prop(&t, "intc@8000000/v2m@8020000", "compatible").unwrap(), b"arm,gic-v2m-frame\0");
        assert!(prop(&t, "intc@8000000/v2m@8020000", "msi-controller").is_some());
        assert_eq!(prop(&t, "pcie@3f000000", "msi-parent").unwrap(), PH_V2M.to_be_bytes());
        assert!(prop(&t, "intc@8000000", "mbi-ranges").is_none());
        // GICv2's PPI specifiers name the two CPUs.
        let timer = prop(&t, "timer", "interrupts").unwrap();
        assert_eq!(be(timer, 8), IRQ_LEVEL_HIGH | 3 << 8);
    }

    #[test]
    fn devices_and_power_button() {
        let b = machine(true, 1);
        let t = parse(&b);
        assert_eq!(prop(&t, "pl011@9000000", "compatible").unwrap(), b"arm,pl011\0arm,primecell\0");
        assert_eq!(&prop(&t, "pl011@9000000", "interrupts").unwrap()[4..8], UART_SPI.to_be_bytes());
        assert_eq!(&prop(&t, "pl031@9010000", "interrupts").unwrap()[4..8], RTC_SPI.to_be_bytes());
        assert_eq!(&prop(&t, "pl061@9030000", "interrupts").unwrap()[4..8], GPIO_SPI.to_be_bytes());
        assert_eq!(prop(&t, "gpio-keys", "label").unwrap(), b"Power Button\0");
        assert_eq!(prop(&t, "gpio-keys/poweroff", "linux,code").unwrap(), 116u32.to_be_bytes());
        let g = prop(&t, "gpio-keys/poweroff", "gpios").unwrap();
        assert_eq!((be(g, 0), be(g, 4)), (PH_GPIO, 3));
    }

    #[test]
    fn pci_host() {
        let b = machine(true, 1);
        let t = parse(&b);
        let ranges = prop(&t, "pcie@3f000000", "ranges").unwrap();
        assert_eq!(be(ranges, 0), 0x0200_0000);
        assert_eq!(be(ranges, 8), PCI_MMIO_BASE as u32);
        assert_eq!(be(ranges, 24), PCI_MMIO_SIZE as u32);
        assert_eq!(&prop(&t, "pcie@3f000000", "reg").unwrap()[..8], ECAM_BASE.to_be_bytes());
        let map = prop(&t, "pcie@3f000000", "interrupt-map").unwrap();
        assert_eq!(map.len(), 16 * 40);
        // Device 1's INTA# is the second line.
        let e = 4 * 40;
        assert_eq!((be(map, e), be(map, e + 12), be(map, e + 16)), (1 << 11, 1, PH_GIC));
        assert_eq!(be(map, e + 32), PCI_INTX_SPI + 1);
    }

    #[test]
    fn too_small_a_buffer_fails() {
        let mut b = [0u8; 256];
        let m = Machine { vcpus: 1, gicv3: true, ram_base: RAM_BASE, ram: 32 << 20, cmdline: b"", initrd: None };
        assert_eq!(build(&mut b, &m), Err(TooLarge));
        assert_eq!(build(&mut [0u8; 8], &m), Err(TooLarge));
    }

    #[test]
    fn a_command_line_is_kept_as_given() {
        let mut b = std::vec![0u8; 1 << 16];
        let m = Machine { vcpus: 1, gicv3: true, ram_base: RAM_BASE, ram: 32 << 20, cmdline: b"x=\xff y\0z", initrd: None };
        let n = build(&mut b, &m).unwrap();
        let t = parse(&b[..n]);
        assert_eq!(prop(&t, "chosen", "bootargs").unwrap(), b"x=\xff y\0");
    }

    #[test]
    fn names_are_shared() {
        let mut b = [0u8; 256];
        let mut w = Writer::new(&mut b);
        w.begin("");
        w.u32("a", 1);
        w.u32("bb", 2);
        w.u32("a", 3);
        w.end();
        let n = w.finish().unwrap();
        assert_eq!(be(&b, 32), 5, "\"a\" and \"bb\" once each");
        let t = parse(&b[..n]);
        assert_eq!(t[0].1.len(), 3);
    }
}
