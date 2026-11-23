//! A vCPU thread on AArch64 (DESIGN.md §5.11): it enters the guest with
//! seL4_ARM_VCPU_Run, and handles what makes it return.  Its list registers
//! are its own (vgic::Cpu); what other threads raise is in the GIC's shared
//! state, and its notification ends the run, or its wait in WFI.  MMIO
//! accesses go to the device models: the GIC and the PrimeCells here, PCI
//! through the I/O thread (io.rs), but for virtio's notifications, which
//! only post a bit and signal it.

use core::sync::atomic::Ordering;

use l4h_abi as abi;
use l4h_rt::host::{self, hvm as hv};
use hv::arm;

use super::hw::{Exit, Hw};
use super::psci::{self, Outcome};
use super::regs::*;
use super::sysreg::{self, Access};
use super::vgic::{self, PPI_VTIMER};
use super::vm::{self, vm};
use crate::dev::virtio_pci::{self, NOTIFY_MULTIPLIER};

const EC_UNKNOWN: u64 = 0x00;
const EC_WFX: u64 = 0x01;
const EC_HVC64: u64 = 0x16;
const EC_SMC64: u64 = 0x17;
const EC_SYSREG: u64 = 0x18;
const EC_IABT_LOWER: u64 = 0x20;
const EC_IABT_CUR: u64 = 0x21;
const EC_DABT_LOWER: u64 = 0x24;
const EC_DABT_CUR: u64 = 0x25;

const ESR_IL: u64 = 1 << 25;
const ESR_ISV: u64 = 1 << 24;
const ESR_SSE: u64 = 1 << 21;
const ESR_SF: u64 = 1 << 15;
const ESR_CM: u64 = 1 << 8;
const ESR_S1PTW: u64 = 1 << 7;
const ESR_WNR: u64 = 1 << 6;
/// A synchronous external abort, as (D/I)FSC.
const FSC_EXTERNAL: u64 = 0x10;

pub struct Vcpu<H: Hw> {
    id: usize,
    hw: H,
    gic: vgic::Cpu,
    /// The state groups the next entry loads.
    load: u64,
    /// Powered on (PSCI), and waiting in WFI.
    on: bool,
    halted: bool,
    /// The deadline of its seL4 timer.
    armed: u64,
}

impl<H: Hw> Vcpu<H> {
    /// vCPU `v` at reset: the boot vCPU at the kernel's entry, the others
    /// off until CPU_ON.
    pub fn new(v: usize, mut hw: H) -> Self {
        let vm = vm();
        let gic = vgic::Cpu::new(v, vm.vgic.v3(), vm.cfg.arm_virt.vgic_vtr);
        let s = hw.state();
        *s = State::zeroed();
        s.regs[reg::VMPIDR] = 0x8000_0000 | arm::mpidr_aff(v);
        s.regs[reg::VPIDR] = vm.cfg.arm_virt.midr_el1;
        s.regs[reg::HCR] = HCR_GUEST;
        s.regs[reg::VGIC_HCR] = gic.hcr();
        let mut c = Vcpu { id: v, hw, gic, load: S_ALL, on: false, halted: false, armed: 0 };
        if v == 0 {
            let e = vm.entry;
            c.reset(e.pc, e.fdt);
            c.on = true;
        }
        c
    }

    #[cfg(test)]
    pub fn hw(&mut self) -> &mut H {
        &mut self.hw
    }

    /// Whether it is powered on, and in WFI.
    #[cfg(test)]
    pub fn power_state(&self) -> (bool, bool) {
        (self.on, self.halted)
    }

    /// Start at `pc` with x0 `x0`, as from reset: EL1h, DAIF masked, MMU
    /// and caches off.  It keeps nothing of EL1 from before.
    fn reset(&mut self, pc: u64, x0: u64) {
        let s = self.hw.state();
        s.gprs = [0; 37];
        s.gprs[0] = x0;
        s.gprs[GPR_PC] = pc;
        s.gprs[GPR_PSTATE] = PSTATE_EL1H_MASKED;
        for r in 0..reg::CNTV_CTL {
            if r != reg::VMPIDR {
                s.regs[r] = 0;
            }
        }
        s.regs[reg::SCTLR] = SCTLR_RESET;
        s.regs[reg::CNTV_CTL] = 0;
        s.regs[reg::CNTV_CVAL] = 0;
        s.regs[reg::CNTKCTL] = 0;
        s.vppi_masked = 0;
        let wake = self.gic.reset(&vm().vgic, &mut s.regs);
        wake_all(wake);
        // The whole VGIC group: VMCR and the active priorities too.
        self.load |= S_GPRS | S_EL1 | S_TIMER | S_VGIC;
        self.halted = false;
    }

    /// One entry of the guest and its exit's handling, or one wait.
    pub fn turn(&mut self) {
        let vm = vm();
        if self.id == 0 {
            vm.pending_work();
        }
        if !self.on {
            match vm.power[self.id].take_start() {
                Some((pc, ctx)) => {
                    self.reset(pc, ctx);
                    self.on = true;
                }
                None => return self.block(),
            }
        }
        self.sync_timer();
        // Its list registers filled and it marked in its guest in one step,
        // once no other vCPU is keeping it out.
        let (wake, go) = self.gic.enter(&vm.vgic, &mut self.hw.state().regs, self.halted);
        wake_all(wake);
        if !go {
            return self.block();
        }
        self.halted = false;
        let v3 = vm.vgic.v3();
        if self.gic.dirty {
            self.load |= if v3 { S_VGIC_LR } else { S_VGIC };
            self.gic.dirty = false;
        }
        // GICv2's mapped GICV page changes VMCR at any time; GICv3 changes
        // the list registers only while one is in use.
        let save = S_GPRS | S_TIMER | if !v3 { S_VGIC } else if self.gic.in_use() { S_VGIC_LR } else { 0 };
        let load = core::mem::take(&mut self.load);
        let exit = self.hw.run(load, save);
        let saved = save & (S_VGIC | S_VGIC_LR) != 0;
        wake_all(self.gic.left(&vm.vgic, &mut self.hw.state().regs, saved));
        self.exit(exit);
    }

    /// The virtual timer's line, from the state it last ran with.  FL4
    /// keeps its PPI masked once it fired: masked here too while the line
    /// is high, unmasked when it falls, so that it is one exit per tick.
    fn sync_timer(&mut self) {
        let now = vm::now();
        let (id, s) = (self.id, self.hw.state());
        let level = timer_level(s, now);
        vm().vgic.set_ppi_line(id, PPI_VTIMER, level);
        if (s.vppi_masked & 1 != 0) != level {
            s.vppi_masked = level as u64;
            self.load |= S_TIMER;
        }
    }

    /// Wait for something to do: an interrupt, the timer, CPU_ON.
    fn block(&mut self) {
        let mut d = if self.on { timer_deadline(self.hw.state()) } else { 0 };
        if self.id == 0 {
            let r = vm().rtc.lock().deadline(vm::now());
            if r != 0 && (d == 0 || r < d) {
                d = r;
            }
        }
        if d != self.armed {
            self.armed = d;
            crate::sys::vcpu_timer(self.id, d);
        }
        let before = vm::now();
        crate::sys::wait(self.id);
        let page = host::vmm_event_page_va(self.id) as *mut abi::EventPage;
        unsafe {
            let p = core::ptr::addr_of_mut!((*page).idle_ticks);
            p.write_volatile(p.read_volatile().wrapping_add(vm::now().saturating_sub(before)));
        }
    }

    fn fatal(&mut self, what: &str, why: u64) -> ! {
        let pc = self.hw.state().gprs[GPR_PC];
        l4h_rt::log!("l4h-hvm: guest {} vCPU {}: {} {:#x} at pc {:#x}", vm().cfg.guest_id, self.id, what, why, pc);
        crate::sys::power(abi::POWER_CRASH)
    }

    /// Past the instruction that trapped.
    fn skip(&mut self) {
        let s = self.hw.state();
        s.gprs[GPR_PC] = s.gprs[GPR_PC].wrapping_add(4);
        self.load |= S_GPRS;
    }

    fn set_x(&mut self, r: usize, v: u64) {
        self.hw.state().set_x(r, v);
        self.load |= S_GPRS;
    }

    /// Take a synchronous exception at EL1, as the CPU does.  What it
    /// changes of EL1 goes straight to the VCPU: the group is not loaded.
    fn inject(&mut self, esr: u64, far: Option<u64>) {
        let (pc, pstate) = {
            let s = self.hw.state();
            (s.gprs[GPR_PC], s.gprs[GPR_PSTATE])
        };
        let vbar = self.hw.read_reg(reg::VBAR);
        let sctlr = self.hw.read_reg(reg::SCTLR);
        let cfg = &vm().cfg;
        // What the guest's ID registers say it has (sysreg::id_reg).
        let has_pan = (cfg.arm_virt.id_aa64mmfr1 >> 20) & 0xf != 0;
        let has_ssbs = (cfg.cpu_id[4] >> 4) & 0xf != 0;
        // From EL1 with SP_EL1, EL1 with SP_EL0, or EL0.
        let off = match (pstate >> 2) & 3 {
            1 if pstate & 1 != 0 => 0x200,
            1 => 0,
            _ => 0x400,
        };
        self.hw.write_reg(reg::ELR_EL1, pc);
        self.hw.write_reg(reg::SPSR_EL1, pstate);
        self.hw.write_reg(reg::ESR, esr);
        if let Some(f) = far {
            self.hw.write_reg(reg::FAR, f);
        }
        let s = self.hw.state();
        s.gprs[GPR_PC] = vbar.wrapping_add(off);
        s.gprs[GPR_PSTATE] = exception_pstate(pstate, sctlr, has_pan, has_ssbs);
        self.load |= S_GPRS;
    }

    /// UNDEFINED, at the instruction that trapped.
    fn undef(&mut self) {
        self.inject(EC_UNKNOWN << 26 | ESR_IL, None);
    }

    /// An external abort for an access nothing can answer; `wnr` is the
    /// syndrome's WnR, of a data access.
    fn abort(&mut self, instruction: bool, far: u64, wnr: u64) {
        let from_el1 = (self.hw.state().gprs[GPR_PSTATE] >> 2) & 3 == 1;
        let ec = match (instruction, from_el1) {
            (true, true) => EC_IABT_CUR,
            (true, false) => EC_IABT_LOWER,
            (false, true) => EC_DABT_CUR,
            (false, false) => EC_DABT_LOWER,
        };
        self.inject(ec << 26 | ESR_IL | wnr | FSC_EXTERNAL, Some(far));
    }

    fn exit(&mut self, exit: Exit) {
        match exit {
            // What stopped it is in the shared state: the next turn looks.
            Exit::Interrupt(_) | Exit::VgicMaint | Exit::Vppi(_) => {}
            Exit::VmFault { esr, ipa, far } => self.vm_fault(esr, ipa, far),
            Exit::VcpuFault { esr } => match esr >> 26 {
                EC_WFX => {
                    self.skip();
                    self.halted = true;
                }
                // HVC's return address is past it already; SMC's is not.
                // Neither is EL0's to make (it does not trap here, but
                // this is what stands between it and PSCI if it did).
                EC_HVC64 if self.at_el0() => {
                    let s = self.hw.state();
                    s.gprs[GPR_PC] = s.gprs[GPR_PC].wrapping_sub(4);
                    self.undef();
                }
                EC_SMC64 if self.at_el0() => self.undef(),
                EC_HVC64 => self.firmware(),
                EC_SMC64 => {
                    self.skip();
                    self.firmware();
                }
                EC_SYSREG => self.sysreg(sysreg::decode(esr)),
                _ => self.undef(),
            },
            Exit::Refused(e) => self.fatal("VCPU run refused", e),
        }
    }

    /// PSCI and the SMCCC, as HVC or SMC ask.
    fn firmware(&mut self) {
        let vm = vm();
        let (fid, x) = {
            let s = self.hw.state();
            (s.gprs[0] as u32, [s.gprs[1], s.gprs[2], s.gprs[3]])
        };
        match psci::call(fid, x, &vm.power[..vm.vcpus]) {
            Outcome::Ret(v) => self.set_x(0, v as u64),
            Outcome::Started(t) => {
                self.set_x(0, psci::SUCCESS as u64);
                vm::wake(t);
            }
            Outcome::Standby => {
                self.set_x(0, psci::SUCCESS as u64);
                self.halted = true;
            }
            Outcome::Off => {
                // Its list registers go with it.
                self.set_x(0, psci::SUCCESS as u64);
                wake_all(self.gic.reset(&vm.vgic, &mut self.hw.state().regs));
                self.load |= S_VGIC;
                vm.power[self.id].set_off();
                self.on = false;
                self.halted = false;
            }
            Outcome::SystemOff => crate::sys::power(abi::POWER_OFF),
            Outcome::SystemReset => crate::sys::power(abi::POWER_REBOOT),
        }
    }

    /// Whether the instruction that trapped ran at EL0.
    fn at_el0(&mut self) -> bool {
        (self.hw.state().gprs[GPR_PSTATE] >> 2) & 3 == 0
    }

    fn sysreg(&mut self, a: Access) {
        // EL0 has only the registers of Op1 3 (the counters and timers).
        if self.at_el0() && (a.reg >> 12) & 7 != 3 {
            return self.undef();
        }
        let vm = vm();
        let value = if a.read { 0 } else { self.hw.state().x(a.rt) };
        let got: Option<u64> = match a.reg {
            sysreg::ICC_SGI1R | sysreg::ICC_ASGI1R if !a.read && vm.vgic.v3() => {
                vm.vgic.sgi1r(self.id, value, &mut vm::wake);
                Some(0)
            }
            // Group 0 is not the guest's.
            sysreg::ICC_SGI0R if !a.read && vm.vgic.v3() => Some(0),
            sysreg::ACTLR_EL1 => Some(0),
            sysreg::CNTPCT_EL0 if a.read => Some(vm::now()),
            // The physical timer is FL4's: it reads as off.
            sysreg::CNTP_CTL_EL0 | sysreg::CNTP_CVAL_EL0 | sysreg::CNTP_TVAL_EL0 => Some(0),
            r if r >> 16 == 2 => Some(0), // The debug registers: none.
            // The ID registers are read-only: a write is UNDEFINED.
            r if a.read => sysreg::id_reg(r, &vm.cfg.cpu_id, &vm.cfg.arm_virt, vm.vgic.v3()),
            _ => None,
        };
        let Some(v) = got else { return self.undef() };
        if a.read {
            self.set_x(a.rt, v);
        }
        self.skip();
    }

    fn vm_fault(&mut self, esr: u64, ipa: u64, far: u64) {
        let vm = vm();
        let mem = &vm.mem;
        if mem.is_ram(ipa, 1) {
            if !crate::sys::map(mem.block_of(ipa)) {
                self.fatal("cannot map RAM at", ipa);
            }
            return;
        }
        let ec = esr >> 26;
        // The guest's own page tables are not in RAM: whatever the access
        // was (a cache maintenance instruction too), its walk failed.
        if ec == EC_DABT_LOWER && esr & ESR_S1PTW != 0 {
            return self.abort(false, far, 0);
        }
        // A cache maintenance instruction on a device: nothing to maintain.
        if ec == EC_DABT_LOWER && esr & ESR_CM != 0 {
            return self.skip();
        }
        if ec != EC_DABT_LOWER || esr & ESR_ISV == 0 {
            // A fetch from no RAM, or an access the syndrome does not
            // describe (a pair, or with writeback): Linux makes none to
            // a device.
            let wnr = if ec == EC_DABT_LOWER { esr & ESR_WNR } else { 0 };
            return self.abort(ec == EC_IABT_LOWER, far, wnr);
        }
        let size = 1u8 << ((esr >> 22) & 3);
        let rt = ((esr >> 16) & 0x1f) as usize;
        if esr & ESR_WNR != 0 {
            let v = self.hw.state().x(rt);
            let v = if size == 8 { v } else { v & ((1u64 << (8 * size as u32)) - 1) };
            self.mmio_write(ipa, size, v);
        } else {
            let mut v = self.mmio_read(ipa, size);
            if size < 8 {
                v &= (1u64 << (8 * size as u32)) - 1;
                if esr & ESR_SSE != 0 {
                    let shift = 64 - 8 * size as u32;
                    v = (((v << shift) as i64) >> shift) as u64;
                }
            }
            if esr & ESR_SF == 0 {
                v &= 0xffff_ffff;
            }
            self.set_x(rt, v);
        }
        self.skip();
    }

    fn mmio_read(&mut self, gpa: u64, size: u8) -> u64 {
        let vm = vm();
        let g = &vm.vgic;
        let now = vm::now();
        match gpa {
            arm::GICD_BASE..0x0801_0000 => {
                g.dist_read_for(self.id, gpa - arm::GICD_BASE, size, &mut vm::wake)
            }
            arm::V2M_BASE..0x0802_1000 if !g.v3() => g.v2m_read(gpa - arm::V2M_BASE, size),
            arm::GICR_BASE..0x0900_0000 if g.v3() => match g.redist_at(gpa - arm::GICR_BASE) {
                Some((c, off)) => g.redist_read_for(self.id, c, off, size, &mut vm::wake),
                None => 0,
            },
            arm::UART_BASE..0x0900_1000 => vm.uart(|u, io| u.read(gpa - arm::UART_BASE, io)) as u64,
            arm::RTC_BASE..0x0901_1000 => vm.rtc(|r| r.read(gpa - arm::RTC_BASE, now)) as u64,
            arm::GPIO_BASE..0x0903_1000 => vm.gpio(|c| c.read(gpa - arm::GPIO_BASE)) as u64,
            arm::ECAM_BASE..0x3f10_0000 => crate::sys::call_access(hv::SPACE_CONFIG, gpa - arm::ECAM_BASE, size, false, 0),
            arm::PCI_MMIO_BASE..0x3000_0000 => crate::sys::call_access(hv::SPACE_MMIO, gpa, size, false, 0),
            // Nothing there.
            _ => u64::MAX,
        }
    }

    fn mmio_write(&mut self, gpa: u64, size: u8, v: u64) {
        let vm = vm();
        let g = &vm.vgic;
        let now = vm::now();
        match gpa {
            arm::GICD_BASE..0x0801_0000 => g.dist_write(self.id, gpa - arm::GICD_BASE, size, v, &mut vm::wake),
            arm::V2M_BASE..0x0802_1000 if !g.v3() => {
                if let Some(t) = g.v2m_write(gpa - arm::V2M_BASE, v) {
                    vm::wake(t);
                }
            }
            arm::GICR_BASE..0x0900_0000 if g.v3() => {
                if let Some((c, off)) = g.redist_at(gpa - arm::GICR_BASE) {
                    g.redist_write(self.id, c, off, size, v, &mut vm::wake);
                }
            }
            arm::UART_BASE..0x0900_1000 => vm.uart(|u, io| u.write(gpa - arm::UART_BASE, v as u32, io)),
            arm::RTC_BASE..0x0901_1000 => vm.rtc(|r| r.write(gpa - arm::RTC_BASE, v as u32, now)),
            arm::GPIO_BASE..0x0903_1000 => vm.gpio(|c| c.write(gpa - arm::GPIO_BASE, v as u32)),
            arm::ECAM_BASE..0x3f10_0000 => {
                crate::sys::call_access(hv::SPACE_CONFIG, gpa - arm::ECAM_BASE, size, true, v);
            }
            arm::PCI_MMIO_BASE..0x3000_0000 => {
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

/// Wake the vCPUs of the bits of `mask`.
fn wake_all(mut mask: u64) {
    while mask != 0 {
        vm::wake(mask.trailing_zeros() as usize);
        mask &= mask - 1;
    }
}

/// Whether the virtual timer's condition holds in state `s`.
pub fn timer_level(s: &State, now: u64) -> bool {
    let ctl = s.regs[reg::CNTV_CTL];
    ctl & CNTV_ENABLE != 0 && ctl & CNTV_IMASK == 0 && now.wrapping_sub(s.regs[reg::CNTVOFF]) >= s.regs[reg::CNTV_CVAL]
}

/// When it holds, on the host's counter (0: not armed).
fn timer_deadline(s: &State) -> u64 {
    let ctl = s.regs[reg::CNTV_CTL];
    if ctl & CNTV_ENABLE == 0 || ctl & CNTV_IMASK != 0 {
        return 0;
    }
    s.regs[reg::CNTV_CVAL].wrapping_add(s.regs[reg::CNTVOFF]).max(1)
}

/// The thread of vCPU `v`.
#[cfg(target_arch = "aarch64")]
pub fn run<H: Hw>(v: usize, hw: H) -> ! {
    let mut c = Vcpu::new(v, hw);
    loop {
        c.turn();
    }
}

/// The entry of vCPU thread `v` (l4h_rt::start_thread).
#[cfg(target_arch = "aarch64")]
pub extern "C" fn entry(v: usize) -> ! {
    unsafe { l4h_rt::thread_init(hv::SLOT_VCPU_TCB + v as u64, hv::vcpu_ipcbuf_va(v)) };
    vm::set_me(v);
    run(v, super::hw::Vcpu::new(v))
}
