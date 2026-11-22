//! A vCPU thread (DESIGN.md §5.11): it enters the guest, and handles what
//! makes it return.  Its local APIC is its own; what other threads ask of
//! it (interrupts, IPIs, NMI, INIT, SIPI) is in its apic::Shared, and its
//! notification ends VMEnter, or its wait in HLT, when they ask.  Port and
//! MMIO accesses go to the device models: the legacy devices and the
//! interrupt controllers here (vm.rs), PCI devices through the I/O thread
//! (io.rs), but for virtio's notifications, which only post a bit and
//! signal it.

use core::sync::atomic::Ordering;

use l4h_abi as abi;
use l4h_rt::host::{self, hvm as hv};

use crate::dev::apic::{PENDING_INIT, PENDING_NMI, PENDING_SIPI};
use crate::dev::lapic::{self, Lapic};
use crate::dev::virtio_pci::{self, NOTIFY_MULTIPLIER};
use crate::dev::{ioapic, pci, pm, uart};
use crate::hw::{Event, Exit, Hw};
use crate::vm::{self, vm};
use crate::x86::decode::{self, Kind, Mode, Seg};
use crate::x86::{cpuid, msr, walk};

const VEC_DB: u8 = 1;
const VEC_UD: u8 = 6;
const VEC_GP: u8 = 13;
const VEC_AC: u8 = 17;
const CR0_TS: u64 = 1 << 3;
const CR4_DE: u64 = 1 << 3;
const CR4_OSXSAVE: u64 = 1 << 18;
/// RFLAGS.DF.
const DF: u64 = 1 << 10;
/// Iterations of a REP string instruction one exit does.
const STRING_BATCH: u64 = 4096;

/// The CR4 bits a guest may set: seL4's allowlist (VCPU_GUEST_CR4_ALLOWED)
/// without LA57, which CPUID hides.
const CR4_ALLOWED: u64 = 0x1fff | (1 << 16) | (1 << 17) | (1 << 18) | (1 << 20) | (1 << 21);
const CR4_FLUSH: u64 = (1 << 4) | (1 << 5) | (1 << 7) | (1 << 17) | (1 << 20) | (1 << 21);

/// Guest RAM as the page walker reads it.
struct Ram;

impl walk::Tables for Ram {
    fn entry(&mut self, gpa: u64, bytes: u8) -> Option<u64> {
        let m = &vm().mem;
        if !m.valid(gpa, bytes as u64) {
            return None;
        }
        Some(if bytes == 4 { m.read::<u32>(gpa) as u64 } else { m.read::<u64>(gpa) })
    }

    fn set(&mut self, gpa: u64, bytes: u8, bits: u64) {
        let m = &vm().mem;
        if !m.valid(gpa, bytes as u64) {
            return;
        }
        // Atomically, as the CPU sets them: other vCPUs walk these too.
        let p = m.bytes(gpa, bytes as usize);
        unsafe {
            if bytes == 4 {
                (*(p as *const core::sync::atomic::AtomicU32)).fetch_or(bits as u32, Ordering::SeqCst);
            } else {
                (*(p as *const core::sync::atomic::AtomicU64)).fetch_or(bits, Ordering::SeqCst);
            }
        }
    }
}

pub struct Vcpu<H: Hw> {
    id: usize,
    hw: H,
    lapic: Lapic,
    msrs: msr::Msrs,
    tsc_offset: u64,
    halted: bool,
    wait_sipi: bool,
    nmis: u32,
    /// An event an exit's handling makes (an exception), for the next entry.
    inject: Option<Event>,
    dr: [u64; 4],
    dr6: u64,
    dr7: u64,
    xcr0: u64,
    armed: u64,
}

fn shared(v: usize) -> &'static crate::dev::apic::Shared {
    &vm().apics[v]
}

/// The thread of vCPU `v`.
pub fn run<H: Hw>(v: usize, hw: H) -> ! {
    let mut c = Vcpu::new(v, hw);
    loop {
        c.turn();
    }
}

impl<H: Hw> Vcpu<H> {
    /// vCPU `v` at reset: the boot vCPU at the kernel's entry, the others
    /// waiting for SIPI.
    pub fn new(v: usize, hw: H) -> Self {
        let vm = vm();
        let mut c = Vcpu {
            id: v, hw, lapic: Lapic::new(v as u32, v == 0, vm.tsc_hz), msrs: msr::Msrs::new(vm.amd), tsc_offset: 0,
            halted: false, wait_sipi: v != 0, nmis: 0, inject: None, dr: [0; 4], dr6: 0xffff_0ff0, dr7: 0x400, xcr0: 1, armed: 0,
        };
        c.lapic.init(shared(v));
        if v == 0 {
            c.hw.start_long_mode(&vm.entry);
        }
        c
    }

    #[cfg(test)]
    pub fn hw(&mut self) -> &mut H {
        &mut self.hw
    }

    /// Whether it waits for SIPI, and is halted.
    #[cfg(test)]
    pub fn state(&self) -> (bool, bool) {
        (self.wait_sipi, self.halted)
    }

    /// One entry of the guest and its exit's handling, or one wait.
    pub fn turn(&mut self) {
        let vm = vm();
        let sh = shared(self.id);
        // What other threads asked.
        let flags = sh.flags.swap(0, Ordering::SeqCst);
        if flags & PENDING_NMI != 0 {
            self.nmis = self.nmis.saturating_add(1);
        }
        if flags & PENDING_INIT != 0 {
            self.lapic.init(sh);
            self.wait_sipi = true;
            self.halted = false;
            self.nmis = 0;
            self.inject = None;
        }
        if flags & PENDING_SIPI != 0 && self.wait_sipi {
            self.wait_sipi = false;
            self.hw.start_real_mode(sh.sipi.load(Ordering::SeqCst));
        }
        if self.id == 0 {
            vm.pending_work();
        }
        if self.wait_sipi {
            return self.block();
        }
        let now = vm::now();
        if self.lapic.tick(sh, now) {
            self.arm_timer();
        }
        if self.halted {
            let wake = (self.lapic.pending(sh).is_some() && self.hw.rflags() & (1 << 9) != 0) || self.nmis != 0;
            if !wake {
                return self.block();
            }
            self.halted = false;
        }
        let mut ev = self.inject.take().or_else(|| self.hw.take_pending());
        if ev.is_none() && self.nmis != 0 && !self.hw.nmi_blocked() {
            self.nmis -= 1;
            ev = Some(Event::Nmi);
        }
        if ev.is_none()
            && self.hw.interruptible()
            && let Some(vector) = self.lapic.pending(sh)
        {
            self.lapic.accept(sh, vector);
            ev = Some(Event::Ext(vector));
        }
        let irq_window = self.lapic.pending(sh).is_some();
        let nmi_window = self.nmis != 0;
        let exit = self.hw.enter(ev, irq_window, nmi_window);
        self.exit(exit);
    }

    /// Wait for something to do: an interrupt, the timer, INIT or SIPI.
    fn block(&mut self) {
        self.arm_timer();
        let before = vm::now();
        crate::sys::wait(self.id);
        let page = host::vmm_event_page_va(self.id) as *mut abi::EventPage;
        unsafe {
            let p = core::ptr::addr_of_mut!((*page).idle_ticks);
            p.write_volatile(p.read_volatile().wrapping_add(vm::now() - before));
        }
    }

    fn arm_timer(&mut self) {
        let d = self.lapic.deadline();
        if d != self.armed {
            self.armed = d;
            crate::sys::vcpu_timer(self.id, d);
        }
    }

    fn fault(&mut self, vector: u8, error: Option<u32>) {
        self.inject = Some(Event::Exc(vector, error));
    }

    fn gp(&mut self) {
        self.fault(VEC_GP, Some(0));
    }

    fn ud(&mut self) {
        self.fault(VEC_UD, None);
    }

    fn skip(&mut self) {
        let len = self.hw.instr_len();
        self.hw.skip(len);
    }

    /// The guest stops: power off, reboot, crash (abi::POWER_*).
    fn power(&mut self, how: u64) -> ! {
        crate::sys::power(how)
    }

    fn fatal(&mut self, what: &str, why: u64) -> ! {
        l4h_rt::log!("l4h-hvm: guest {} vCPU {}: {} {:#x} at rip {:#x}", vm().cfg.guest_id, self.id, what, why, self.hw.rip());
        self.power(abi::POWER_CRASH)
    }

    fn exit(&mut self, exit: Exit) {
        match exit {
            Exit::Notified(_) | Exit::IrqWindow | Exit::NmiWindow | Exit::Iret => {}
            Exit::Io { port, size, input, string, rep, addr } => {
                if string {
                    self.string_io(port, size, input, rep, addr);
                } else {
                    let g = self.hw.gprs();
                    if input {
                        let v = self.pio_read(port, size) as u64;
                        let g = self.hw.gprs();
                        g[0] = match size {
                            1 => (g[0] & !0xff) | (v & 0xff),
                            2 => (g[0] & !0xffff) | (v & 0xffff),
                            _ => v & 0xffff_ffff,
                        };
                        self.hw.mark_gprs();
                    } else {
                        let v = decode::trunc(g[0], size) as u32;
                        self.pio_write(port, size, v);
                    }
                    self.skip();
                }
            }
            Exit::Mmio { gpa, .. } => {
                let mem = &vm().mem;
                if mem.is_ram(gpa, 1) {
                    if !crate::sys::map(mem.block_of(gpa)) {
                        self.fatal("cannot map RAM at", gpa);
                    }
                } else {
                    self.mmio(gpa);
                }
            }
            Exit::Rdmsr => {
                let m = self.hw.gprs()[1] as u32;
                match self.rdmsr(m) {
                    Some(v) => {
                        let g = self.hw.gprs();
                        g[0] = v & 0xffff_ffff;
                        g[2] = v >> 32;
                        self.hw.mark_gprs();
                        self.skip();
                    }
                    None => self.gp(),
                }
            }
            Exit::Wrmsr => {
                let g = self.hw.gprs();
                let (m, v) = (g[1] as u32, (g[2] << 32) | (g[0] & 0xffff_ffff));
                if self.wrmsr(m, v) { self.skip() } else { self.gp() }
            }
            Exit::Cpuid => {
                let (leaf, sub) = (self.hw.gprs()[0] as u32, self.hw.gprs()[1] as u32);
                let ctx = cpuid::Ctx {
                    vcpu: self.id as u32, vcpus: vm().vcpus as u32, tsc_hz: vm().tsc_hz,
                    osxsave: self.hw.cr4() & CR4_OSXSAVE != 0, xcr0: self.xcr0, invpcid: vm().invpcid.load(Ordering::Relaxed),
                };
                let [a, b, c, d] = cpuid::cpuid(leaf, sub, &ctx, &host_cpuid);
                let g = self.hw.gprs();
                (g[0], g[3], g[1], g[2]) = (a as u64, b as u64, c as u64, d as u64);
                self.hw.mark_gprs();
                self.skip();
            }
            Exit::Hlt => {
                self.skip();
                self.halted = true;
            }
            Exit::Xsetbv => {
                let g = self.hw.gprs();
                let (ecx, v) = (g[1] as u32, (g[2] << 32) | (g[0] & 0xffff_ffff));
                if self.hw.cr4() & CR4_OSXSAVE == 0 {
                    return self.ud();
                }
                if ecx != 0 || self.hw.cpl() != 0 || !cpuid::xcr0_valid(v, vm().xcr0) || !self.hw.set_xcr0(v) {
                    return self.gp();
                }
                self.xcr0 = v;
                self.skip();
            }
            Exit::Cr { cr, write, reg } => {
                let Some(reg) = reg.or_else(|| self.decoded_reg(true)) else { return self.ud() };
                self.cr(cr, write, reg);
            }
            Exit::Clts => {
                let cr0 = self.hw.cr0() & !CR0_TS;
                if self.hw.set_cr0(cr0) { self.skip() } else { self.gp() }
            }
            Exit::Lmsw(v) => {
                // PE can be set, not cleared.
                let cr0 = self.hw.cr0();
                let n = (cr0 & !0xe) | (v as u64 & 0xf) | (cr0 & 1);
                if self.hw.set_cr0(n) { self.skip() } else { self.gp() }
            }
            Exit::Dr { dr, write, reg } => {
                let Some(reg) = reg.or_else(|| self.decoded_reg(false)) else { return self.ud() };
                self.dr(dr, write, reg);
            }
            Exit::Exception { vector, error, dr6 } => match vector {
                VEC_DB => {
                    self.dr6 = (self.dr6 & !0xf) | (dr6 & 0x600f);
                    self.fault(VEC_DB, None);
                }
                VEC_AC => self.fault(VEC_AC, Some(error.unwrap_or(0))),
                18 => {}
                v => self.fault(v, error),
            },
            Exit::Shutdown => {
                l4h_rt::log!("l4h-hvm: guest {} vCPU {}: triple fault at rip {:#x}", vm().cfg.guest_id, self.id, self.hw.rip());
                self.power(abi::POWER_REBOOT)
            }
            Exit::Undefined => self.ud(),
            Exit::Nop => self.skip(),
            Exit::TaskSwitch => self.fatal("task switch", 0),
            Exit::Fatal(r) => self.fatal("VM exit", r),
        }
    }

    /// The register a MOV to or from CR (DR) names, decoding the
    /// instruction (AMD-V without decode assists).
    fn decoded_reg(&mut self, cr: bool) -> Option<u8> {
        let insn = self.fetch_decode()?;
        match insn.kind {
            Kind::MovCr { reg, .. } if cr => Some(reg),
            Kind::MovDr { reg, .. } if !cr => Some(reg),
            _ => None,
        }
    }

    fn reg(&mut self, r: u8) -> u64 {
        if r == 4 { self.hw.rsp() } else { self.hw.gprs()[r as usize] }
    }

    fn set_reg(&mut self, r: u8, v: u64) {
        if r == 4 {
            self.hw.set_rsp(v);
        } else {
            self.hw.gprs()[r as usize] = v;
            self.hw.mark_gprs();
        }
    }

    fn cr(&mut self, cr: u8, write: bool, reg: u8) {
        if self.hw.cpl() != 0 {
            return self.gp();
        }
        let long = self.hw.mode() == Mode::Bits64;
        let v = self.reg(reg);
        let v = if long { v } else { v & 0xffff_ffff };
        match (cr, write) {
            (0, true) => {
                // Reserved bits, PG without PE, NW without CD.
                let bad = (v >> 32 != 0) || (v & walk::CR0_PG != 0 && v & 1 == 0) || (v & (1 << 29) != 0 && v & (1 << 30) == 0);
                if bad || !self.hw.set_cr0(v) {
                    return self.gp();
                }
            }
            (4, true) => {
                let old = self.hw.cr4();
                if v & !CR4_ALLOWED != 0 || (long && v & walk::CR4_PAE == 0) || !self.hw.set_cr4(v) {
                    return self.gp();
                }
                if (old ^ v) & CR4_FLUSH != 0 {
                    self.hw.flush_tlb();
                }
            }
            (8, true) => {
                if v >> 4 != 0 {
                    return self.gp();
                }
                self.lapic.set_cr8(v);
                self.hw.set_tpr(self.lapic.tpr() as u8);
            }
            (8, false) => self.set_reg(reg, (self.lapic.tpr() >> 4) as u64),
            (0, false) => {
                let c = self.hw.cr0();
                self.set_reg(reg, c)
            }
            (4, false) => {
                let c = self.hw.cr4();
                self.set_reg(reg, c)
            }
            (3, false) => {
                let c = self.hw.paging().cr3;
                self.set_reg(reg, c)
            }
            _ => return self.ud(),
        }
        self.skip();
    }

    fn dr(&mut self, dr: u8, write: bool, reg: u8) {
        let de = self.hw.cr4() & CR4_DE != 0;
        let dr = match dr {
            4 | 5 if de => return self.ud(),
            4 | 5 => dr + 2,
            d => d,
        };
        if self.hw.cpl() != 0 {
            return self.gp();
        }
        if write {
            let v = self.reg(reg);
            match dr {
                0..=3 => self.dr[dr as usize] = v,
                6 => self.dr6 = (v & 0xe00f) | 0xffff_0ff0,
                7 => {
                    if v >> 32 != 0 {
                        return self.gp();
                    }
                    self.dr7 = (v & 0xffff_2bff) | 0x400;
                }
                _ => return self.ud(),
            }
        } else {
            let v = match dr {
                0..=3 => self.dr[dr as usize],
                6 => self.dr6,
                7 => self.dr7,
                _ => return self.ud(),
            };
            self.set_reg(reg, v);
        }
        self.skip();
    }

    fn rdmsr(&mut self, m: u32) -> Option<u64> {
        let sh = shared(self.id);
        match m {
            msr::TSC => return Some(vm::now().wrapping_add(self.tsc_offset)),
            lapic::MSR_TSC_DEADLINE => {
                let d = self.lapic.rdmsr(sh, vm::now(), m)?;
                return Some(if d == 0 { 0 } else { d.wrapping_add(self.tsc_offset) });
            }
            lapic::MSR_APIC_BASE | 0x800..=0x8ff => return self.lapic.rdmsr(sh, vm::now(), m),
            _ => {}
        }
        if let Some(r) = self.hw.rdmsr(m) {
            return r;
        }
        self.msrs.read(m)
    }

    fn wrmsr(&mut self, m: u32, v: u64) -> bool {
        let sh = shared(self.id);
        match m {
            msr::TSC => {
                self.tsc_offset = v.wrapping_sub(vm::now());
                self.hw.set_tsc_offset(self.tsc_offset);
                return true;
            }
            lapic::MSR_TSC_DEADLINE | lapic::MSR_APIC_BASE | 0x800..=0x8ff => {
                // The deadline in the host's TSC.
                let v = if m == lapic::MSR_TSC_DEADLINE && v != 0 { v.wrapping_sub(self.tsc_offset).max(1) } else { v };
                let Some(fx) = self.lapic.wrmsr(sh, vm::now(), m, v) else { return false };
                self.apic_effects(fx);
                return true;
            }
            _ => {}
        }
        if let Some(ok) = self.hw.wrmsr(m, v) {
            return ok;
        }
        self.msrs.write(m, v).is_some()
    }

    fn apic_effects(&mut self, fx: lapic::Effects) {
        if let Some(m) = fx.send {
            vm().deliver(&m);
        }
        if let Some(v) = fx.eoi_level {
            vm().eoi(v);
        }
        if fx.timer {
            self.arm_timer();
        }
        if fx.tpr {
            self.hw.set_tpr(self.lapic.tpr() as u8);
        }
    }

    // ---- Ports.

    fn pio_read(&mut self, port: u16, size: u8) -> u32 {
        let vm = vm();
        let now = vm::now();
        match port {
            0x40..=0x43 | 0x61 => vm.pit.lock().read(port, now) as u32,
            0x70 | 0x71 => vm.rtc.lock().read(port, now) as u32,
            uart::BASE..=0x3ff => {
                let v = vm.uart.lock().read(port - uart::BASE, &mut crate::console::Input) as u32;
                vm.sync_uart();
                v
            }
            pm::PM1_EVT..=0x60b => vm.pm.read(port, size, now, vm.tsc_hz),
            0xcf8 if size == 4 => vm.cf8.load(Ordering::SeqCst),
            0xcfc..=0xcff => match pci::cf8_offset(vm.cf8.load(Ordering::SeqCst), port) {
                Some(off) => crate::sys::call_access(hv::SPACE_CONFIG, off, size, false, 0) as u32,
                None => u32::MAX,
            },
            // No 8259s (their masks read back wrong, so Linux takes them for
            // absent), no 8042, no POST port: all ones.
            _ => u32::MAX >> (32 - 8 * size as u32),
        }
    }

    fn pio_write(&mut self, port: u16, size: u8, v: u32) {
        let vm = vm();
        let now = vm::now();
        match port {
            0x40..=0x43 | 0x61 => vm.pit.lock().write(port, v as u8, now),
            0x70 | 0x71 => vm.rtc.lock().write(port, v as u8, now),
            uart::BASE..=0x3ff => {
                vm.uart.lock().write(port - uart::BASE, v as u8, &mut crate::console::Input);
                vm.sync_uart();
            }
            pm::RESET if size == 1 => {
                if vm.pm.write(port, size, v) == pm::Action::Reset {
                    self.power(abi::POWER_REBOOT);
                }
            }
            pm::PM1_EVT..=0x60b => match vm.pm.write(port, size, v) {
                pm::Action::PowerOff => self.power(abi::POWER_OFF),
                pm::Action::Reset => self.power(abi::POWER_REBOOT),
                pm::Action::Sci => vm.sync_sci(),
                pm::Action::None => {}
            },
            0xcf8 if size == 4 => vm.cf8.store(v, Ordering::SeqCst),
            0xcfc..=0xcff => {
                if let Some(off) = pci::cf8_offset(vm.cf8.load(Ordering::SeqCst), port) {
                    crate::sys::call_access(hv::SPACE_CONFIG, off, size, true, v as u64);
                }
            }
            _ => {}
        }
    }

    /// INS and OUTS, REP or not: through the guest's page tables.
    fn string_io(&mut self, port: u16, size: u8, input: bool, rep: bool, addr: u8) {
        let mask = if addr >= 8 { u64::MAX } else { (1u64 << (8 * addr as u32)) - 1 };
        let mut count = if rep { self.hw.gprs()[1] & mask } else { 1 };
        let down = self.hw.rflags() & DF != 0;
        let (reg, seg) = if input { (7, Seg::Es) } else { (6, Seg::Ds) };
        let base = if self.hw.mode() == Mode::Bits64 && seg != Seg::Fs && seg != Seg::Gs { 0 } else { self.hw.seg_base(seg) };
        let mut done = 0;
        while count != 0 && done < STRING_BATCH {
            let off = self.hw.gprs()[reg] & mask;
            let Some(gpa) = self.translate(base.wrapping_add(off), input) else { return };
            let mut buf = [0u8; 4];
            if input {
                let v = self.pio_read(port, size);
                buf = v.to_le_bytes();
                if !self.write_phys(gpa, &buf[..size as usize]) {
                    return self.gp();
                }
            } else {
                if !self.read_phys(gpa, &mut buf[..size as usize]) {
                    return self.gp();
                }
                self.pio_write(port, size, u32::from_le_bytes(buf));
            }
            let g = self.hw.gprs();
            let step = if down { (size as u64).wrapping_neg() } else { size as u64 };
            g[reg] = (g[reg] & !mask) | (g[reg].wrapping_add(step) & mask);
            count -= 1;
            if rep {
                g[1] = (g[1] & !mask) | (count & mask);
            }
            self.hw.mark_gprs();
            done += 1;
        }
        // Done, or more to do from the same instruction.
        if count == 0 {
            self.skip();
        }
    }

    // ---- Memory-mapped devices.

    /// The linear address `la`'s GPA, injecting the page fault if it has
    /// none.
    fn translate(&mut self, la: u64, write: bool) -> Option<u64> {
        let p = self.hw.paging();
        let user = self.hw.cpl() == 3;
        match walk::translate(&p, la, walk::Access { write, user, fetch: false }, &mut Ram) {
            Ok(g) => Some(g),
            Err(_) => {
                // A page fault the guest would take: rare enough here (the
                // instruction itself just ran) to stop it than emulate.
                self.gp();
                None
            }
        }
    }

    /// The instruction at CS:RIP, decoded (#UD if we cannot).
    fn fetch_decode(&mut self) -> Option<decode::Insn> {
        let mode = self.hw.mode();
        let base = if mode == Mode::Bits64 { 0 } else { self.hw.seg_base(Seg::Cs) };
        let la = base.wrapping_add(self.hw.rip());
        let p = self.hw.paging();
        let user = self.hw.cpl() == 3;
        let mut bytes = [0u8; decode::MAX_LEN];
        let mut n = 0;
        while n < bytes.len() {
            let at = la.wrapping_add(n as u64);
            let Ok(gpa) = walk::translate(&p, at, walk::Access { write: false, user, fetch: true }, &mut Ram) else { break };
            let in_page = (4096 - (at & 0xfff)) as usize;
            let k = in_page.min(bytes.len() - n);
            if !vm().mem.read_bytes(gpa, &mut bytes[n..n + k]) {
                break;
            }
            n += k;
        }
        match decode::decode(&bytes[..n], mode) {
            Ok(i) => Some(i),
            Err(e) => {
                l4h_rt::log!("l4h-hvm: guest {} vCPU {}: cannot emulate {:x?} at {:#x}: {:?}", vm().cfg.guest_id, self.id, &bytes[..n.min(8)], la, e);
                None
            }
        }
    }

    fn mmio(&mut self, gpa: u64) {
        let Some(insn) = self.fetch_decode() else { return self.ud() };
        match insn.kind {
            Kind::Movs | Kind::Stos => return self.string_mmio(&insn),
            Kind::Load { .. } | Kind::Store { .. } | Kind::Alu { .. } | Kind::Xchg { .. } => {}
            _ => return self.ud(),
        }
        let size = insn.size;
        let mem = if decode::reads_mem(&insn.kind) { self.mmio_read(gpa, size) } else { 0 };
        let mut g = *self.hw.gprs();
        g[4] = self.hw.rsp();
        let mut fl = self.hw.rflags();
        let (g0, fl0) = (g, fl);
        let fx = decode::execute(&insn, &mut g, &mut fl, mem);
        if let Some(w) = fx.mem_write {
            self.mmio_write(gpa, size, w);
        }
        if g != g0 {
            if g[4] != g0[4] {
                self.hw.set_rsp(g[4]);
            }
            *self.hw.gprs() = g;
            self.hw.mark_gprs();
        }
        if fl != fl0 {
            self.hw.set_rflags(fl);
        }
        self.hw.skip(insn.len as u64);
    }

    /// MOVS and STOS, of which one side or both is MMIO.
    fn string_mmio(&mut self, insn: &decode::Insn) {
        let a = insn.addr;
        let mask = if a >= 8 { u64::MAX } else { (1u64 << (8 * a as u32)) - 1 };
        let rep = insn.rep != decode::Rep::None;
        let mut count = if rep { self.hw.gprs()[1] & mask } else { 1 };
        let size = insn.size as u64;
        let down = self.hw.rflags() & DF != 0;
        let long = self.hw.mode() == Mode::Bits64;
        let seg_base = |s: &mut Self, seg: Seg| if long && seg != Seg::Fs && seg != Seg::Gs { 0 } else { s.hw.seg_base(seg) };
        let es = seg_base(self, Seg::Es);
        let src_seg = seg_base(self, insn.seg.unwrap_or(Seg::Ds));
        let mut done = 0;
        while count != 0 && done < STRING_BATCH {
            let g = *self.hw.gprs();
            let v = if insn.kind == Kind::Movs {
                let Some(src) = self.translate(src_seg.wrapping_add(g[6] & mask), false) else { return };
                self.phys_read(src, insn.size)
            } else {
                decode::trunc(g[0], insn.size)
            };
            let Some(dst) = self.translate(es.wrapping_add(g[7] & mask), true) else { return };
            self.phys_write(dst, insn.size, v);
            let step = if down { size.wrapping_neg() } else { size };
            let g = self.hw.gprs();
            g[7] = (g[7] & !mask) | (g[7].wrapping_add(step) & mask);
            if insn.kind == Kind::Movs {
                g[6] = (g[6] & !mask) | (g[6].wrapping_add(step) & mask);
            }
            count -= 1;
            if rep {
                g[1] = (g[1] & !mask) | (count & mask);
            }
            self.hw.mark_gprs();
            done += 1;
        }
        if count == 0 {
            self.hw.skip(insn.len as u64);
        }
    }

    fn read_phys(&mut self, gpa: u64, buf: &mut [u8]) -> bool {
        vm().mem.read_bytes(gpa, buf)
    }

    fn write_phys(&mut self, gpa: u64, buf: &[u8]) -> bool {
        vm().mem.write_bytes(gpa, buf)
    }

    /// A read of `size` bytes at `gpa`, RAM or a device.
    fn phys_read(&mut self, gpa: u64, size: u8) -> u64 {
        let mut b = [0u8; 8];
        if self.read_phys(gpa, &mut b[..size as usize]) {
            return u64::from_le_bytes(b);
        }
        self.mmio_read(gpa, size)
    }

    fn phys_write(&mut self, gpa: u64, size: u8, v: u64) {
        if !self.write_phys(gpa, &v.to_le_bytes()[..size as usize]) {
            self.mmio_write(gpa, size, v);
        }
    }

    fn lapic_mmio(&self) -> bool {
        !self.lapic.x2apic()
    }

    fn mmio_read(&mut self, gpa: u64, size: u8) -> u64 {
        let vm = vm();
        let shift = 8 * (gpa & 3);
        let v = match gpa {
            lapic::BASE_ADDR..0xfee0_1000 if self.lapic_mmio() => {
                (self.lapic.read(shared(self.id), vm::now(), (gpa & 0xff0) as u32) as u64) >> shift
            }
            ioapic::BASE..ioapic::END => (vm.ioapic.lock().read(gpa & 0xff0) as u64) >> shift,
            pci::ECAM_BASE..0xe010_0000 => {
                return crate::sys::call_access(hv::SPACE_CONFIG, gpa - pci::ECAM_BASE, size, false, 0);
            }
            pci::MMIO_BASE..0xe000_0000 => return crate::sys::call_access(hv::SPACE_MMIO, gpa, size, false, 0),
            // Nothing there.
            _ => u64::MAX,
        };
        decode::trunc(v, size)
    }

    fn mmio_write(&mut self, gpa: u64, size: u8, v: u64) {
        let vm = vm();
        match gpa {
            lapic::BASE_ADDR..0xfee0_1000 if self.lapic_mmio() => {
                if gpa & 0xf == 0 {
                    let fx = self.lapic.write(shared(self.id), vm::now(), (gpa & 0xff0) as u32, v as u32);
                    self.apic_effects(fx);
                }
            }
            ioapic::BASE..ioapic::END => {
                if gpa & 0xf == 0 {
                    vm.ioapic.lock().write(gpa & 0xff0, v as u32, &mut |m| vm.deliver(&m));
                }
            }
            pci::ECAM_BASE..0xe010_0000 => {
                crate::sys::call_access(hv::SPACE_CONFIG, gpa - pci::ECAM_BASE, size, true, v);
            }
            pci::MMIO_BASE..0xe000_0000 => {
                // A queue notification: a bit for the I/O thread, no call.
                let slot = ((gpa - pci::MMIO_BASE) / pci::SLOT_MMIO) as usize;
                let base = vm.bar0.get(slot).map_or(0, |b| b.load(Ordering::Acquire));
                let off = gpa.wrapping_sub(base);
                if base != 0
                    && off < virtio_pci::BAR0_SIZE
                    && off.is_multiple_of(NOTIFY_MULTIPLIER)
                    && let Some(q) = virtio_pci::Transport::<crate::dev::blk::Blk>::notify_queue(off)
                {
                    if vm.kicks.post(slot, q) {
                        vm::signal_io(l4h_rt::host::badges::hvm::KICK);
                    }
                    return;
                }
                crate::sys::call_access(hv::SPACE_MMIO, gpa, size, true, v);
            }
            _ => {}
        }
    }
}

/// The host's CPUID.
pub fn host_cpuid(leaf: u32, sub: u32) -> [u32; 4] {
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    [r.eax, r.ebx, r.ecx, r.edx]
}

/// The entry of vCPU thread `v` (l4h_rt::start_thread).
#[cfg(not(test))]
pub extern "C" fn entry(v: usize) -> ! {
    unsafe { l4h_rt::thread_init(hv::SLOT_VCPU_TCB + v as u64, hv::vcpu_ipcbuf_va(v)) };
    vm::set_me(v);
    let obj = hv::SLOT_VCPU_OBJ + v as u64;
    if vm().amd {
        run(v, crate::hw::svm::Svm::new(obj))
    } else {
        let hw = crate::hw::vmx::Vmx::new(obj);
        vm().invpcid.store(hw.invpcid, Ordering::Relaxed);
        run(v, hw)
    }
}
