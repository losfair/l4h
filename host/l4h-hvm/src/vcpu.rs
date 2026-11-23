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
use crate::x86::{cpuid, msr, pvclock, walk};

const VEC_DB: u8 = 1;
const VEC_UD: u8 = 6;
const VEC_GP: u8 = 13;
const VEC_AC: u8 = 17;
const CR0_TS: u64 = 1 << 3;
const CR4_DE: u64 = 1 << 3;
const CR4_OSXSAVE: u64 = 1 << 18;
/// RFLAGS.DF and AC.
const DF: u64 = 1 << 10;
const AC: u64 = 1 << 18;
const VEC_PF: u8 = 14;

/// Register `old` with `v` written as an address of `addr` bytes: a
/// 16-bit one keeps the rest; a 32-bit one is zero-extended, as every
/// 32-bit register write; a 64-bit one is all of it.
pub fn with_addr(old: u64, v: u64, addr: u8) -> u64 {
    match addr {
        2 => (old & !0xffff) | (v & 0xffff),
        4 => v & 0xffff_ffff,
        _ => v,
    }
}

/// Up to two pieces (GPA, bytes) of an access at a linear address.
struct Span {
    parts: [(u64, u64); 2],
}
/// How long a halted vCPU polls before it blocks (Vcpu::halt_poll).
const HALT_POLL_US: u64 = 100;
/// Iterations of a REP string instruction one exit does.
const STRING_BATCH: u64 = 4096;

/// The CR4 bits a guest may set: seL4's allowlist (VCPU_GUEST_CR4_ALLOWED)
/// without LA57, which CPUID hides.
const CR4_ALLOWED: u64 = 0x0fff | (1 << 16) | (1 << 17) | (1 << 18) | (1 << 20) | (1 << 21);
const CR4_PCIDE: u64 = 1 << 17;
/// Protection keys: the guest's where its XSAVE state has PKRU
/// (cpuid.rs).  The page walker (walk.rs) does not check them.
const CR4_PKE: u64 = 1 << 22;
const CR0_NW: u64 = 1 << 29;
const CR0_CD: u64 = 1 << 30;
/// CR0 bits whose change flushes the guest's TLB: PG, WP, CD, NW.
const CR0_FLUSH: u64 = walk::CR0_PG | walk::CR0_WP | CR0_CD | CR0_NW;
const CR4_FLUSH: u64 = (1 << 4) | (1 << 5) | (1 << 7) | (1 << 17) | (1 << 20) | (1 << 21) | (1 << 22);

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
    /// MSR_KVM_SYSTEM_TIME_NEW and MSR_KVM_WALL_CLOCK_NEW as written
    /// (x86/pvclock.rs), and the version of this vCPU's time info.
    kvm_time: u64,
    kvm_wall: u64,
    kvm_version: u32,
    /// MSR_KVM_PV_EOI_EN as written, and whether this entry's PV EOI flag
    /// is set in the guest's word (pv_eoi_to_guest).
    pv_eoi: u64,
    pv_eoi_set: bool,
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
            kvm_time: 0, kvm_wall: 0, kvm_version: 0, pv_eoi: 0, pv_eoi_set: false,
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
            // A reset of its local APIC: what was requested before is
            // gone, and its timer stops.
            self.lapic.init(sh);
            sh.clear_requests();
            self.hw.set_tpr(0);
            self.arm_timer();
            self.wait_sipi = true;
            self.halted = false;
            self.nmis = 0;
            self.inject = None;
            // As KVM's reset: the guest names its PV EOI word again.
            self.pv_eoi = 0;
        }
        if flags & PENDING_SIPI != 0 && self.wait_sipi {
            sh.clear_requests();
            self.wait_sipi = false;
            self.hw.start_real_mode(sh.sipi.load(Ordering::SeqCst));
        }
        if self.id == 0 {
            vm.pending_work();
        }
        if self.wait_sipi {
            // Only INIT and SIPI reach a vCPU that waits for SIPI.
            sh.clear_requests();
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
        self.pv_eoi_to_guest(sh);
        let exit = self.hw.enter(ev, irq_window, nmi_window);
        self.pv_eoi_from_guest();
        self.exit(exit);
    }

    /// Wait for something to do: an interrupt, the timer, INIT or SIPI.
    fn block(&mut self) {
        self.arm_timer();
        if self.halted && self.halt_poll(vm::now()) {
            // What woke it may have signalled this thread too: taken now,
            // so the next VMEnter does not return at once to say so (turn
            // looks at the state itself).
            crate::sys::poll(self.id);
            return;
        }
        // Idle: the time blocked.  The poll ran on the vCPU's budget, as
        // its run time (vmmgr's steal is wall - run - idle).
        let before = vm::now();
        crate::sys::wait(self.id);
        let page = host::vmm_event_page_va(self.id) as *mut abi::EventPage;
        unsafe {
            let p = core::ptr::addr_of_mut!((*page).idle_ticks);
            p.write_volatile(p.read_volatile().wrapping_add(vm::now() - before));
        }
    }

    /// Halt polling, as KVM's halt_poll_ns: a halted vCPU watches, for a
    /// while, for what would wake it (`turn`) before it blocks: an
    /// interrupt it can take, an NMI, INIT or SIPI, its timer.  Each block
    /// and wakeup costs host scheduling and, under a hypervisor, IPIs and
    /// halts of its own; a guest waiting on I/O is often woken within tens
    /// of microseconds.  vCPU 0 also runs the VM's I/O APIC and UART work
    /// (Vm::pending_work).  Whether it was woken.
    fn halt_poll(&self, start: u64) -> bool {
        let vm = vm();
        let sh = shared(self.id);
        let ticks = vm.tsc_hz / 1_000_000 * HALT_POLL_US;
        loop {
            let now = vm::now();
            if sh.flags.load(Ordering::Relaxed) != 0
                || (self.lapic.pending(sh).is_some() && self.hw.rflags() & (1 << 9) != 0)
                || (self.armed != 0 && now >= self.armed)
                || (self.id == 0
                    && (vm.ioapic_stale.load(Ordering::Relaxed) || vm.uart_stale.load(Ordering::Relaxed)))
            {
                return true;
            }
            if now.wrapping_sub(start) >= ticks {
                return false;
            }
            core::hint::spin_loop();
        }
    }

    /// KVM's PV EOI (KVM_FEATURE_PV_EOI): when the guest's EOI could do
    /// nothing but end the one edge-triggered interrupt in service, the
    /// entry sets bit 0 of the guest's word, and the guest's EOI clears it
    /// instead of writing the APIC's EOI register (an exit per interrupt).
    /// Only this vCPU's guest writes the word while it runs, only this
    /// thread while it does not.
    fn pv_eoi_to_guest(&mut self, sh: &crate::dev::apic::Shared) {
        if self.pv_eoi & 1 != 0 && self.lapic.pv_eoi_ok(sh) {
            vm().mem.write::<u8>(self.pv_eoi & !1, 1);
            self.pv_eoi_set = true;
        }
    }

    /// After the exit: the flag still set, the guest made no EOI (and
    /// will write the register if it does, the flag now clear); clear,
    /// it did.
    fn pv_eoi_from_guest(&mut self) {
        if !self.pv_eoi_set {
            return;
        }
        self.pv_eoi_set = false;
        let mem = &vm().mem;
        let gpa = self.pv_eoi & !1;
        if mem.read::<u8>(gpa) & 1 != 0 {
            mem.write::<u8>(gpa, 0);
        } else {
            let fx = self.lapic.pv_eoi();
            self.apic_effects(fx);
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

    /// Step over the instruction that exited: by the length the CPU
    /// gave, or (AMD-V without next-RIP saving) its decoded length.
    fn skip(&mut self) {
        let mut len = self.hw.instr_len();
        if len == 0 {
            let (bytes, n) = self.fetch();
            len = decode::length(&bytes[..n], self.hw.mode()).unwrap_or(0) as u64;
            if len == 0 {
                self.fatal("no length for the instruction at", self.hw.rip());
            }
        }
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
            Exit::Io { port, size, input, string, rep, addr, seg } => {
                if string {
                    self.string_io(port, size, input, rep, addr, seg);
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
                    osxsave: self.hw.cr4() & CR4_OSXSAVE != 0, xcr0: self.xcr0, xcr0_max: vm().xcr0,
                    pke: self.hw.cr4() & CR4_PKE != 0, invpcid: vm().invpcid.load(Ordering::Relaxed),
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
                let decoded = if reg.is_none() { self.fetch_decode().map(|i| i.kind) } else { None };
                // AMD-V's selective CR0 write also stops an LMSW.
                if let (0, true, Some(Kind::Lmsw { src: Some(r) })) = (cr, write, decoded) {
                    let v = self.reg(r) as u16;
                    return self.lmsw(v);
                }
                // The instruction as fetched now: the one that exited, unless
                // the guest rewrote it meanwhile.
                let reg = reg.or(match decoded {
                    Some(Kind::MovCr { write: w, cr: c, reg }) if c == cr && w == write => Some(reg),
                    _ => None,
                });
                let Some(reg) = reg else { return self.ud() };
                self.cr(cr, write, reg);
            }
            Exit::Clts => {
                let cr0 = self.hw.cr0() & !CR0_TS;
                if self.hw.set_cr0(cr0) { self.skip() } else { self.gp() }
            }
            Exit::Lmsw(v) => self.lmsw(v),
            Exit::Dr { dr, write, reg } => {
                let Some(reg) = reg.or_else(|| self.decoded_dr_reg()) else { return self.ud() };
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
            // kvmclock's KVM signature (x86/pvclock.rs) makes Linux try
            // hypercalls whatever the feature bits say (ptp_kvm's
            // KVM_HC_CLOCK_PAIRING): none is there, as KVM answers one it
            // does not know (-KVM_ENOSYS; -KVM_EPERM outside ring 0).
            Exit::Hypercall => {
                let r: i64 = if self.hw.cpl() != 0 { -1 } else { -1000 };
                self.hw.gprs()[0] = r as u64;
                self.hw.mark_gprs();
                self.skip();
            }
            Exit::Undefined => self.ud(),
            Exit::Nop => self.skip(),
            Exit::Rdtsc => {
                let t = vm::now().wrapping_add(self.tsc_offset);
                let g = self.hw.gprs();
                (g[0], g[2]) = (t & 0xffff_ffff, t >> 32);
                self.hw.mark_gprs();
                self.skip();
            }
            Exit::Rdpmc => self.gp(),
            Exit::TaskSwitch => self.fatal("task switch", 0),
            Exit::Fatal(r) => self.fatal("VM exit", r),
        }
    }

    /// LMSW: PE can be set, not cleared.  Ring 0 only, as cr() checks
    /// (the CPU does so before the exit; this guards against a quirk).
    fn lmsw(&mut self, v: u16) {
        if self.hw.cpl() != 0 {
            return self.gp();
        }
        let cr0 = self.hw.cr0();
        let n = (cr0 & !0xe) | (v as u64 & 0xf) | (cr0 & 1);
        if self.hw.set_cr0(n) { self.skip() } else { self.gp() }
    }

    /// The register a MOV to or from a DR names, decoding the instruction
    /// (AMD-V without decode assists).  Exit::Cr decodes its own.
    fn decoded_dr_reg(&mut self) -> Option<u8> {
        match self.fetch_decode()?.kind {
            Kind::MovDr { reg, .. } => Some(reg),
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
                // #GP before anything changes: reserved bits, PG without
                // PE, NW without CD, long mode's paging without PAE, and
                // paging off from 64-bit code or with PCIDE.
                let p = self.hw.paging();
                let old = self.hw.cr0();
                let (pg, was_pg) = (v & walk::CR0_PG != 0, old & walk::CR0_PG != 0);
                let bad = (v >> 32 != 0)
                    || (pg && v & 1 == 0)
                    || (v & CR0_NW != 0 && v & CR0_CD == 0)
                    || (pg && !was_pg && p.efer & walk::EFER_LME != 0 && p.cr4 & walk::CR4_PAE == 0)
                    || (!pg && was_pg && (long || p.cr4 & CR4_PCIDE != 0));
                if bad || !self.hw.set_cr0(v) {
                    return self.gp();
                }
                // Translations the guest's TLB holds change meaning (VPID
                // keeps them across exits): flushed, as the guest saw CR0.
                if (old ^ v) & CR0_FLUSH != 0 {
                    self.hw.flush_tlb();
                }
            }
            (4, true) => {
                let old = self.hw.cr4();
                // Nothing outside the allowed (no LA57: 4-level paging, as
                // walk.rs has it); in IA-32e mode (EFER.LMA, compatibility
                // mode too) PAE kept, and PCIDE only there.
                // PCIDE needs PCIDs, and turning it on CR3[11:0] clear.
                let p = self.hw.paging();
                let lma = p.efer & walk::EFER_LMA != 0;
                let pcide_on = old & CR4_PCIDE == 0 && v & CR4_PCIDE != 0;
                let pke = if vm().xcr0 & cpuid::XCR0_PKRU != 0 { CR4_PKE } else { 0 };
                if v & !(CR4_ALLOWED | pke) != 0
                    || (lma && v & walk::CR4_PAE == 0)
                    || (v & CR4_PCIDE != 0 && (!lma || !vm().pcid.load(Ordering::Relaxed)))
                    || (pcide_on && p.cr3 & 0xfff != 0)
                    || !self.hw.set_cr4(v)
                {
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
            pvclock::MSR_SYSTEM_TIME => return Some(self.kvm_time),
            pvclock::MSR_WALL_CLOCK => return Some(self.kvm_wall),
            pvclock::MSR_PV_EOI => return Some(self.pv_eoi),
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
                // kvmclock's TSC at its time 0 moves with the TSC.  The
                // time info keeps PVCLOCK_TSC_STABLE_BIT: a guest that set
                // its vCPUs' TSCs apart would break Linux's vDSO, which
                // then reads vCPU 0's on every vCPU.  Linux does not, with
                // the rate known and TSC_ADJUST hidden.
                self.publish_clock();
                return true;
            }
            pvclock::MSR_SYSTEM_TIME => {
                self.kvm_time = v;
                self.publish_clock();
                return true;
            }
            pvclock::MSR_WALL_CLOCK => {
                self.kvm_wall = v;
                self.publish_wall_clock();
                return true;
            }
            pvclock::MSR_PV_EOI => {
                // As KVM: the word 4-byte aligned; on, it must be RAM.
                let gpa = v & !1;
                if gpa & 3 != 0 || (v & 1 != 0 && !vm().mem.valid(gpa, 4)) {
                    return false;
                }
                // As KVM: the word starts clear, so that nothing left in
                // it passes for an EOI the entry offered.
                if v & 1 != 0 {
                    vm().mem.write::<u32>(gpa, 0);
                }
                self.pv_eoi = v;
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

    /// kvmclock: this vCPU's time info where the guest asked for it (bit
    /// 0 of MSR_KVM_SYSTEM_TIME_NEW on), kvmclock time 0 at the VM's
    /// clock base in this vCPU's TSC.  Written once: the TSC is invariant
    /// and the same rate on every vCPU.  An address that is not RAM is
    /// left, as KVM leaves it.
    fn publish_clock(&mut self) {
        if self.kvm_time & 1 == 0 {
            return;
        }
        let vm = vm();
        let (mul, shift) = vm.clock_scale;
        self.kvm_version = self.kvm_version.wrapping_add(2) & !1;
        let info = pvclock::time_info(self.kvm_version, vm.clock_base.wrapping_add(self.tsc_offset), 0, mul, shift, pvclock::TSC_STABLE);
        publish_at(self.kvm_time & !1, &info);
    }

    /// kvmclock's wall clock: the wall time at kvmclock time 0, which the
    /// guest adds its kvmclock time to.  One structure in Linux for every
    /// vCPU, so one version for the VM, under a lock: two vCPUs naming the
    /// same address do not interleave.
    fn publish_wall_clock(&mut self) {
        let vm = vm();
        let ns = vm.wall_base_ns;
        let mut version = vm.wall_version.lock();
        *version = version.wrapping_add(2) & !1;
        let w = pvclock::wall_clock(*version, (ns / 1_000_000_000) as u32, (ns % 1_000_000_000) as u32);
        publish_at(self.kvm_wall, &w);
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
            uart::BASE..=0x3ff => vm.uart(|u, input| u.read(port - uart::BASE, input)) as u32,
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
            uart::BASE..=0x3ff => vm.uart(|u, input| u.write(port - uart::BASE, v as u8, input)),
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

    /// INS and OUTS, REP or not: through the guest's page tables, an
    /// element that spans two pages in two pieces.  INS reads the port
    /// only once its memory is known to be writable.
    fn string_io(&mut self, port: u16, size: u8, input: bool, rep: bool, addr: u8, seg: Option<Seg>) {
        let mask = if addr >= 8 { u64::MAX } else { (1u64 << (8 * addr as u32)) - 1 };
        let mut count = if rep { self.hw.gprs()[1] & mask } else { 1 };
        let down = self.hw.rflags() & DF != 0;
        // INS writes ES:rDI; OUTS reads rSI in DS or the segment its prefix
        // names (the CPU's word for it, or the instruction's).
        let (reg, seg) = if input { (7, Seg::Es) } else { (6, seg.or_else(|| self.prefix_seg()).unwrap_or(Seg::Ds)) };
        let base = if self.hw.mode() == Mode::Bits64 && seg != Seg::Fs && seg != Seg::Gs { 0 } else { self.hw.seg_base(seg) };
        let mut done = 0;
        while count != 0 && done < STRING_BATCH {
            let off = self.hw.gprs()[reg] & mask;
            let Some(span) = self.span(base.wrapping_add(off), size as u64, input) else { return };
            let mut buf = [0u8; 4];
            if input {
                let v = self.pio_read(port, size);
                buf = v.to_le_bytes();
                if !self.write_span(&span, &buf[..size as usize]) {
                    return self.gp();
                }
            } else {
                if !self.read_span(&span, &mut buf[..size as usize]) {
                    return self.gp();
                }
                self.pio_write(port, size, u32::from_le_bytes(buf));
            }
            let g = self.hw.gprs();
            let step = if down { (size as u64).wrapping_neg() } else { size as u64 };
            g[reg] = with_addr(g[reg], g[reg].wrapping_add(step), addr);
            count -= 1;
            if rep {
                g[1] = with_addr(g[1], count, addr);
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

    /// The linear address `la`'s GPA for a data access, injecting the
    /// page fault the guest takes if it has none (CR2 `la`), #GP if its
    /// tables are outside RAM.
    fn translate(&mut self, la: u64, write: bool) -> Option<u64> {
        let p = self.hw.paging();
        let user = self.hw.cpl() == 3;
        let ac = self.hw.rflags() & AC != 0;
        match walk::translate(&p, la, walk::Access { write, user, fetch: false, ac }, &mut Ram) {
            Ok(g) => Some(g),
            Err(walk::Error::Fault(f)) => {
                self.hw.set_cr2(la);
                self.fault(VEC_PF, Some(f.error));
                None
            }
            Err(walk::Error::BadTable | walk::Error::NonCanonical) => {
                self.gp();
                None
            }
        }
    }

    /// The GPAs of `len` bytes at linear `la`: one piece, or two where
    /// they cross into the next page, each translated (the page fault of
    /// either injected).
    fn span(&mut self, la: u64, len: u64, write: bool) -> Option<Span> {
        let first = (4096 - (la & 0xfff)).min(len);
        let a = self.translate(la, write)?;
        if first == len {
            return Some(Span { parts: [(a, len), (0, 0)] });
        }
        let b = self.translate(la.wrapping_add(first), write)?;
        Some(Span { parts: [(a, first), (b, len - first)] })
    }

    /// Bytes of a span: RAM, or a device for a whole piece.
    fn read_span(&mut self, span: &Span, buf: &mut [u8]) -> bool {
        let mut at = 0;
        for &(gpa, n) in span.parts.iter().filter(|p| p.1 != 0) {
            let piece = &mut buf[at..at + n as usize];
            if !self.read_phys(gpa, piece) {
                if !matches!(n, 1 | 2 | 4 | 8) {
                    return false;
                }
                let v = self.mmio_read(gpa, n as u8);
                piece.copy_from_slice(&v.to_le_bytes()[..n as usize]);
            }
            at += n as usize;
        }
        true
    }

    fn write_span(&mut self, span: &Span, buf: &[u8]) -> bool {
        let mut at = 0;
        for &(gpa, n) in span.parts.iter().filter(|p| p.1 != 0) {
            let piece = &buf[at..at + n as usize];
            if !self.write_phys(gpa, piece) {
                if !matches!(n, 1 | 2 | 4 | 8) {
                    return false;
                }
                let mut v = [0u8; 8];
                v[..n as usize].copy_from_slice(piece);
                self.mmio_write(gpa, n as u8, u64::from_le_bytes(v));
            }
            at += n as usize;
        }
        true
    }

    /// The bytes at CS:RIP that can be fetched (up to the longest
    /// instruction).
    fn fetch(&mut self) -> ([u8; decode::MAX_LEN], usize) {
        let mode = self.hw.mode();
        let base = if mode == Mode::Bits64 { 0 } else { self.hw.seg_base(Seg::Cs) };
        let la = base.wrapping_add(self.hw.rip());
        let p = self.hw.paging();
        let user = self.hw.cpl() == 3;
        let mut bytes = [0u8; decode::MAX_LEN];
        let mut n = 0;
        while n < bytes.len() {
            let at = la.wrapping_add(n as u64);
            let Ok(gpa) = walk::translate(&p, at, walk::Access { write: false, user, fetch: true, ac: false }, &mut Ram) else { break };
            let in_page = (4096 - (at & 0xfff)) as usize;
            let k = in_page.min(bytes.len() - n);
            if !vm().mem.read_bytes(gpa, &mut bytes[n..n + k]) {
                break;
            }
            n += k;
        }
        (bytes, n)
    }

    /// The segment an override prefix of the instruction at CS:RIP names
    /// (OUTS on AMD-V, which does not say).
    fn prefix_seg(&mut self) -> Option<Seg> {
        let (bytes, n) = self.fetch();
        decode::prefix_seg(&bytes[..n], self.hw.mode())
    }

    /// The instruction at CS:RIP, decoded (#UD if we cannot).
    fn fetch_decode(&mut self) -> Option<decode::Insn> {
        let mode = self.hw.mode();
        let base = if mode == Mode::Bits64 { 0 } else { self.hw.seg_base(Seg::Cs) };
        let la = base.wrapping_add(self.hw.rip());
        let (bytes, n) = self.fetch();
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
            // Both sides translated before either is touched (an element
            // that spans two pages in two pieces).
            let src = if insn.kind == Kind::Movs {
                let Some(s) = self.span(src_seg.wrapping_add(g[6] & mask), size, false) else { return };
                Some(s)
            } else {
                None
            };
            let Some(dst) = self.span(es.wrapping_add(g[7] & mask), size, true) else { return };
            let mut v = [0u8; 8];
            match src {
                Some(s) => {
                    if !self.read_span(&s, &mut v[..size as usize]) {
                        return self.gp();
                    }
                }
                None => v = g[0].to_le_bytes(),
            }
            if !self.write_span(&dst, &v[..size as usize]) {
                return self.gp();
            }
            let step = if down { size.wrapping_neg() } else { size };
            let g = self.hw.gprs();
            g[7] = with_addr(g[7], g[7].wrapping_add(step), a);
            if insn.kind == Kind::Movs {
                g[6] = with_addr(g[6], g[6].wrapping_add(step), a);
            }
            count -= 1;
            if rep {
                g[1] = with_addr(g[1], count, a);
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
                // The device whose BAR0 (where the guest put it) has it.
                let hit = (1..=vm.cfg.nr_devices as usize).find_map(|slot| {
                    let base = vm.bar0.get(slot)?.load(Ordering::Acquire);
                    let off = gpa.checked_sub(base)?;
                    (base != 0 && off < virtio_pci::BAR0_SIZE).then_some((slot, off))
                });
                if let Some((slot, off)) = hit
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
/// A pvclock structure `b` at `gpa` (pvclock::publish), only if all of it
/// is RAM: KVM leaves an address that is not, and a structure straddling
/// RAM's end would otherwise keep an odd version.  The version is one
/// 32-bit store when aligned (GuestMem::write).
fn publish_at(gpa: u64, b: &[u8]) {
    let mem = &vm().mem;
    if !mem.valid(gpa, b.len() as u64) {
        return;
    }
    pvclock::publish(b, |v| mem.write::<u32>(gpa, v), |body| {
        mem.write_bytes(gpa + 4, body);
    });
}

/// The host's CPUID, read once by `read_host_cpuid` before any vCPU runs:
/// under a hypervisor each CPUID is an exit, and emulating one guest
/// CPUID took four (leaf 0, 0x8000_0000, the leaf...).  What differs from
/// core to core (APIC IDs, OSXSAVE) the emulation makes itself.
struct HostCpuid {
    std: [[[u32; 4]; HOST_SUBS]; HOST_STD],
    ext: [[u32; 4]; HOST_EXT],
}
const HOST_STD: usize = 0x21;
const HOST_SUBS: usize = 16;
const HOST_EXT: usize = 0x29;
static HOST_CPUID: crate::sync::Global<HostCpuid> = crate::sync::Global::new();

fn cpuid_insn(leaf: u32, sub: u32) -> [u32; 4] {
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    [r.eax, r.ebx, r.ecx, r.edx]
}

/// Read the host's CPUID into the table (main.rs, once).
pub fn read_host_cpuid() {
    let mut t = HostCpuid { std: [[[0; 4]; HOST_SUBS]; HOST_STD], ext: [[0; 4]; HOST_EXT] };
    for (l, subs) in t.std.iter_mut().enumerate() {
        for (s, r) in subs.iter_mut().enumerate() {
            *r = cpuid_insn(l as u32, s as u32);
        }
    }
    for (l, r) in t.ext.iter_mut().enumerate() {
        *r = cpuid_insn(0x8000_0000 + l as u32, 0);
    }
    HOST_CPUID.set(t);
}

pub fn host_cpuid(leaf: u32, sub: u32) -> [u32; 4] {
    if HOST_CPUID.is_set() {
        let t = HOST_CPUID.get();
        if (leaf as usize) < HOST_STD && (sub as usize) < HOST_SUBS {
            return t.std[leaf as usize][sub as usize];
        }
        // Subleaf 0 only: no extended leaf it caches has others.
        if sub == 0 && (0x8000_0000..0x8000_0000 + HOST_EXT as u32).contains(&leaf) {
            return t.ext[(leaf - 0x8000_0000) as usize];
        }
    }
    cpuid_insn(leaf, sub)
}

/// The entry of vCPU thread `v` (l4h_rt::start_thread).
#[cfg(not(test))]
pub extern "C" fn entry(v: usize) -> ! {
    unsafe { l4h_rt::thread_init(hv::SLOT_VCPU_TCB + v as u64, hv::vcpu_ipcbuf_va(v)) };
    vm::set_me(v);
    let obj = hv::SLOT_VCPU_OBJ + v as u64;
    crate::hw::vcpu_write_msr(obj, crate::hw::FL4_MSR_VM_IBPB_DEFER, 1);
    if vm().amd {
        run(v, crate::hw::svm::Svm::new(obj))
    } else {
        let hw = crate::hw::vmx::Vmx::new(obj);
        vm().invpcid.store(hw.invpcid, Ordering::Relaxed);
        run(v, hw)
    }
}
