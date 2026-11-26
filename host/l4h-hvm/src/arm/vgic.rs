//! The guest's interrupt controller (DESIGN.md §5.11): a GICv3 (distributor,
//! redistributors, MBI) or GICv2 (distributor with ITARGETSR and SGIR,
//! GICv2m) in software, over the hardware's virtual CPU interface: the
//! guest acknowledges and ends interrupts itself, through the list
//! registers each vCPU thread fills (`Cpu`).
//!
//! Two layers.  The I/O thread, which takes no lock (sync.rs), raises
//! interrupts through atomics alone (`io_edge`, `io_level`) and signals the
//! target.  The vCPU threads share the rest under one leaf lock (`state`),
//! held for a few instructions, and bring in what was raised (`drain_io`)
//! each time they take it.  An interrupt is pending while its latch is set
//! (an edge, or software), or if level-sensitive while its line is high.  A
//! list register holds it from the moment it is injected: a level-sensitive
//! one asks for a maintenance interrupt when the guest ends it, to look at
//! the line again; an edge that comes while it is in a list register sets
//! that register's pending state.  Only a vCPU's own thread touches its
//! list registers.  A vCPU that must see or change what another's guest
//! may be doing to them keeps that one out of its guest meanwhile
//! (`Vgic::with_paused`).  Free of seL4.

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering::SeqCst};

use l4h_rt::host::hvm::arm::{self, MSI_BASE, MSI_COUNT, NR_IRQS};
use l4h_rt::host::hvm::MAX_VCPUS;

use super::regs::reg;
use crate::sync::SpinLock;

const NR: usize = NR_IRQS as usize;
const WORDS: usize = NR / 32;
/// The virtual timer's PPI.
pub const PPI_VTIMER: u32 = 27;
const NO_IRQ: u16 = u16::MAX;
/// No vCPU: an SPI's target, or the holder of its list register.
const NO_OWNER: u8 = 0xff;
const _: () = assert!(MAX_VCPUS < NO_OWNER as usize);
/// GICD_IROUTER's Interrupt_Routing_Mode: any one CPU.
const ROUTE_ANY: u64 = 1 << 31;
/// The priority an interrupt has at reset.
const PRIO_RESET: u8 = 0xa0;

// The distributor's registers (both GIC versions unless noted).
const GICD_CTLR: u64 = 0x000;
const GICD_TYPER: u64 = 0x004;
const GICD_IIDR: u64 = 0x008;
const GICD_SETSPI_NSR: u64 = 0x040;
const GICD_CLRSPI_NSR: u64 = 0x048;
const GICD_IGROUPR: u64 = 0x080;
const GICD_ISENABLER: u64 = 0x100;
const GICD_ICENABLER: u64 = 0x180;
const GICD_ISPENDR: u64 = 0x200;
const GICD_ICPENDR: u64 = 0x280;
const GICD_ISACTIVER: u64 = 0x300;
const GICD_ICACTIVER: u64 = 0x380;
const GICD_IPRIORITYR: u64 = 0x400;
const GICD_ITARGETSR: u64 = 0x800;
const GICD_ICFGR: u64 = 0xc00;
const GICD_SGIR: u64 = 0xf00;
const GICD_CPENDSGIR: u64 = 0xf10;
const GICD_SPENDSGIR: u64 = 0xf20;
const GICD_IROUTER: u64 = 0x6000;

const CTLR_V3_G1A: u32 = 1 << 1;
const CTLR_V3_ARE: u32 = 1 << 4;
const CTLR_V3_DS: u32 = 1 << 6;
const TYPER_MBIS: u32 = 1 << 16;
/// ARM's JEP106 code, as a GIC-400 or GIC-500 has it in IIDR.
const IIDR: u32 = 0x0100_043b;

// A redistributor's registers: its RD frame, and its SGI frame after it.
const GICR_CTLR: u64 = 0x0000;
const GICR_IIDR: u64 = 0x0004;
const GICR_TYPER: u64 = 0x0008;
const GICR_WAKER: u64 = 0x0014;
const GICR_SGI: u64 = 0x1_0000;
const GICR_IGROUPR0: u64 = GICR_SGI + 0x080;
const GICR_IGRPMODR0: u64 = GICR_SGI + 0xd00;
const WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;
const TYPER_LAST: u64 = 1 << 4;

// GICv2m's MSI frame.
const V2M_TYPER: u64 = 0x008;
const V2M_SETSPI: u64 = 0x040;
const V2M_IIDR: u64 = 0xfcc;

// List registers.
const LR3_PENDING: u64 = 1 << 62;
const LR3_ACTIVE: u64 = 1 << 63;
const LR3_GROUP1: u64 = 1 << 60;
const LR3_EOI: u64 = 1 << 41;
const LR2_PENDING: u64 = 1 << 28;
const LR2_ACTIVE: u64 = 1 << 29;
const LR2_EOI: u64 = 1 << 19;
/// ICH_HCR_EL2 and GICH_HCR.
const HCR_EN: u64 = 1 << 0;
const HCR_UIE: u64 = 1 << 1;

fn bit(intid: u32) -> u32 {
    1 << (intid % 32)
}

/// A set of vCPUs, a bit each.
type Vcpus = u128;
const _: () = assert!(MAX_VCPUS <= Vcpus::BITS as usize);

/// The vCPUs of mask `m`, in turn.
fn each(mut m: Vcpus) -> impl Iterator<Item = usize> {
    core::iter::from_fn(move || {
        (m != 0).then(|| {
            let t = m.trailing_zeros() as usize;
            m &= m - 1;
            t
        })
    })
}

/// One word of INTIDs: what the distributor (or redistributor) has of them.
#[derive(Clone, Copy)]
struct Word {
    enable: u32,
    /// Pending by an edge or by software.
    latch: u32,
    /// Active by software (GICD_ISACTIVER); what the guest acknowledged is
    /// in a list register.
    active: u32,
    edge: u32,
    /// What the list registers of the vCPU that holds them say, as of its
    /// last exit, for the registers that read pending and active state.
    lr_pending: u32,
    lr_active: u32,
    /// In a list register, not yet acknowledged, and level-sensitive but
    /// pending by software: it stays pending when the line falls.
    lr_latched: u32,
    /// Cleared while a list register has them: its vCPU clears them there
    /// before it next runs.
    cancel_pend: u32,
    cancel_act: u32,
}

impl Word {
    const fn new(edge: u32) -> Self {
        Word { enable: 0, latch: 0, active: 0, edge, lr_pending: 0, lr_active: 0, lr_latched: 0, cancel_pend: 0, cancel_act: 0 }
    }
}

/// A vCPU's SGIs and PPIs (GICv3's redistributor; GICv2's banked registers).
struct Local {
    word: Word,
    prio: [u8; 32],
    /// GICv2: the CPUs each SGI is pending from, a bit each.  There, the
    /// only record of a pending SGI.
    sgi_from: [u8; 16],
    /// GICv2: the CPU (a bit) whose SGI a list register holds.
    held_src: [u8; 16],
    waker: u32,
    /// In its guest, which may be changing its list registers.
    in_guest: bool,
    /// How many vCPUs are keeping it out of its guest (`Vgic::with_paused`).
    pause: u32,
}

impl Local {
    const fn new() -> Self {
        Local {
            word: Word::new(0xffff),
            prio: [PRIO_RESET; 32],
            sgi_from: [0; 16],
            held_src: [0; 16],
            waker: WAKER_PROCESSOR_SLEEP | WAKER_CHILDREN_ASLEEP,
            in_guest: false,
            pause: 0,
        }
    }

    /// GICv2: the SGIs pending from any CPU, a bit each.
    fn sgi_bits(&self) -> u32 {
        (0..16).fold(0, |v, i| v | ((self.sgi_from[i] != 0) as u32) << i)
    }
}

/// What the vCPU threads share under `Vgic::state`.
struct State {
    enabled: bool,
    /// The SPIs' words (the first is each vCPU's, in `local`).
    spi: [Word; WORDS],
    prio: [u8; NR],
    local: [Local; MAX_VCPUS],
}

impl State {
    fn word(&self, cpu: usize, w: usize) -> &Word {
        if w == 0 { &self.local[cpu].word } else { &self.spi[w] }
    }

    fn word_mut(&mut self, cpu: usize, w: usize) -> &mut Word {
        if w == 0 { &mut self.local[cpu].word } else { &mut self.spi[w] }
    }

    fn prio_of(&self, cpu: usize, intid: u32) -> u8 {
        if intid < 32 { self.local[cpu].prio[intid as usize] } else { self.prio[intid as usize] }
    }

    fn prio_mut(&mut self, cpu: usize, intid: u32) -> &mut u8 {
        if intid < 32 { &mut self.local[cpu].prio[intid as usize] } else { &mut self.prio[intid as usize] }
    }

    fn is_edge(&self, cpu: usize, intid: u32) -> bool {
        self.word(cpu, (intid / 32) as usize).edge & bit(intid) != 0
    }

    /// Interrupt `b` of word `w` is not to be delivered now: the distributor
    /// or it is disabled, or software made it active.
    fn blocked(&self, cpu: usize, w: usize, b: u32) -> bool {
        let word = self.word(cpu, w);
        !self.enabled || word.enable & b == 0 || word.active & b != 0
    }
}

/// The interrupt controller every thread shares.
pub struct Vgic {
    v3: bool,
    vcpus: usize,
    /// The vCPU threads' state: held for a few instructions, across no
    /// entry, wait, yield, signal or other lock.  Never the I/O thread's.
    state: SpinLock<State>,
    /// Edges and messages from any thread, not yet in a latch (`drain_io`).
    io_edge: [AtomicU32; WORDS],
    /// The SPIs' lines.
    io_level: [AtomicU32; WORDS],
    /// Each vCPU's PPI lines.
    ppi_level: [AtomicU32; MAX_VCPUS],
    /// Which SPIs are edge-triggered, for the I/O thread (`Word::edge`).
    spi_edge: [AtomicU32; WORDS],
    /// Where each SPI goes, the one record of it (`spi_target`), written
    /// under the lock.  GICv3: GICD_IROUTER as written.  GICv2: ITARGETSR's
    /// byte.
    route: [AtomicU64; NR],
    /// The vCPU whose list register has each SPI (NO_OWNER: none), written
    /// under the lock: an SPI the guest moves meanwhile is not injected at
    /// its new vCPU as well, and a falling line finds who to tell.
    spi_owner: [AtomicU8; NR],
}

impl Vgic {
    pub fn new(v3: bool, vcpus: usize) -> Self {
        // GICv3's IROUTER resets to affinity 0; GICv2's ITARGETSR to no CPU.
        Vgic {
            v3,
            vcpus,
            state: SpinLock::new(State {
                enabled: false,
                spi: [Word::new(0); WORDS],
                prio: [PRIO_RESET; NR],
                local: [const { Local::new() }; MAX_VCPUS],
            }),
            io_edge: [const { AtomicU32::new(0) }; WORDS],
            io_level: [const { AtomicU32::new(0) }; WORDS],
            ppi_level: [const { AtomicU32::new(0) }; MAX_VCPUS],
            spi_edge: [const { AtomicU32::new(0) }; WORDS],
            route: [const { AtomicU64::new(0) }; NR],
            spi_owner: [const { AtomicU8::new(NO_OWNER) }; NR],
        }
    }

    pub fn v3(&self) -> bool {
        self.v3
    }

    /// The vCPU SPI `intid` goes to, if any.
    pub fn spi_target(&self, intid: u32) -> Option<usize> {
        let r = self.route[intid as usize].load(SeqCst);
        if !self.v3 {
            // The lowest of the CPUs named (no 1-of-N here).
            let mask = r as u8;
            return (mask != 0).then(|| mask.trailing_zeros() as usize);
        }
        if r & ROUTE_ANY != 0 {
            Some(0)
        } else if r & !(0xffff | ROUTE_ANY) != 0 {
            None
        } else {
            arm::vcpu_of_aff(r & 0xffff, self.vcpus)
        }
    }

    /// Every vCPU, a bit each.
    fn all(&self) -> Vcpus {
        if self.vcpus >= Vcpus::BITS as usize { Vcpus::MAX } else { (1 << self.vcpus) - 1 }
    }

    /// Bring what the I/O thread raised into the latches.
    fn drain_io(&self, st: &mut State) {
        for (w, e) in self.io_edge.iter().enumerate() {
            if e.load(SeqCst) != 0 {
                st.spi[w].latch |= e.swap(0, SeqCst);
            }
        }
    }

    /// The lines of word `w` of `cpu`'s view.
    fn level(&self, cpu: usize, w: usize) -> u32 {
        if w == 0 { self.ppi_level[cpu].load(SeqCst) } else { self.io_level[w].load(SeqCst) }
    }

    /// Pending in word `w` of `cpu`, outside the list registers.
    fn sw_pending(&self, st: &State, cpu: usize, w: usize) -> u32 {
        let word = st.word(cpu, w);
        let p = word.latch | (self.level(cpu, w) & !word.edge);
        if !self.v3 && w == 0 { p | st.local[cpu].sgi_bits() } else { p }
    }

    /// Pending in word `w` as the guest reads it (GICD_ISPENDR).
    fn visible_pending(&self, st: &State, cpu: usize, w: usize) -> u32 {
        self.sw_pending(st, cpu, w) | st.word(cpu, w).lr_pending
    }

    fn visible_active(st: &State, cpu: usize, w: usize) -> u32 {
        let word = st.word(cpu, w);
        word.active | word.lr_active
    }

    /// The vCPU whose list register has `id` of `cpu`'s view, if any does.
    fn holder(&self, cpu: usize, id: u32) -> Option<usize> {
        if id < 32 {
            return Some(cpu);
        }
        match self.spi_owner[id as usize].load(SeqCst) {
            NO_OWNER => None,
            o => Some(o as usize),
        }
    }

    // ---- With the others out of their guests.

    /// Run `f` under the lock with the vCPUs of `mask` (but `me`, which is
    /// outside its guest) out of their guests, their list registers as
    /// they left them, and kept out until `f` is done.  It adds to its
    /// `&mut Vcpus` the vCPUs that are then to look.  Those waiting here wait
    /// only for vCPUs in their guests, which leave when told to, never for
    /// each other: no cycle of waits can form.  Never the I/O thread's.
    fn with_paused<R>(&self, me: usize, mask: Vcpus, wake: &mut impl FnMut(usize), f: impl FnOnce(&mut State, &mut Vcpus) -> R) -> R {
        let mask = mask & !(1 << me);
        if mask != 0 {
            let mut running = 0;
            {
                let mut st = self.state.lock();
                for t in each(mask) {
                    st.local[t].pause += 1;
                    if st.local[t].in_guest {
                        running |= 1 << t;
                    }
                }
            }
            each(running).for_each(&mut *wake);
            while {
                let st = self.state.lock();
                each(mask).any(|t| st.local[t].in_guest)
            } {
                crate::yield_now();
            }
        }
        let mut then = 0;
        let r = {
            let mut st = self.state.lock();
            self.drain_io(&mut st);
            let r = f(&mut st, &mut then);
            for t in each(mask) {
                st.local[t].pause -= 1;
            }
            r
        };
        each(then).for_each(wake);
        r
    }

    /// Who to keep out of their guests for an access by `me` to the pending
    /// or active state of word `w` of `cpu`'s view.
    fn pause_for(&self, me: usize, cpu: usize, w: usize) -> Vcpus {
        if w == 0 {
            if cpu == me { 0 } else { 1 << cpu }
        } else {
            self.all() & !(1 << me)
        }
    }

    /// `pause_for` the distributor's register at `off`, if it is such a one.
    fn dist_pause(&self, me: usize, off: u64) -> Vcpus {
        let o = off & !3;
        let base = match o {
            _ if (GICD_ISPENDR..GICD_ICPENDR).contains(&o) => GICD_ISPENDR,
            _ if (GICD_ICPENDR..GICD_ISACTIVER).contains(&o) => GICD_ICPENDR,
            _ if (GICD_ISACTIVER..GICD_ICACTIVER).contains(&o) => GICD_ISACTIVER,
            _ if (GICD_ICACTIVER..GICD_IPRIORITYR).contains(&o) => GICD_ICACTIVER,
            _ => return 0,
        };
        let w = ((o - base) / 4) as usize;
        if self.dist_has(w) { self.pause_for(me, me, w) } else { 0 }
    }

    /// `pause_for` register `off` of `cpu`'s redistributor.
    fn redist_pause(&self, me: usize, cpu: usize, off: u64) -> Vcpus {
        let o = off & !3;
        if [GICD_ISPENDR, GICD_ICPENDR, GICD_ISACTIVER, GICD_ICACTIVER].iter().any(|&r| o == GICR_SGI + r) {
            self.pause_for(me, cpu, 0)
        } else {
            0
        }
    }

    // ---- Raising interrupts: any thread, the I/O thread too, with no
    // lock.  Each says which vCPU is to look (None: none need).

    /// SPI `intid`'s line goes to `level`.
    pub fn set_spi_line(&self, intid: u32, level: bool) -> Option<usize> {
        let (w, b) = ((intid / 32) as usize, bit(intid));
        if level {
            let old = self.io_level[w].fetch_or(b, SeqCst);
            if old & b != 0 {
                return None;
            }
            if self.spi_edge[w].load(SeqCst) & b != 0 {
                self.io_edge[w].fetch_or(b, SeqCst);
            }
            self.spi_target(intid)
        } else {
            let old = self.io_level[w].fetch_and(!b, SeqCst);
            // A list register may have it pending on the strength of the
            // line alone: the vCPU that holds it looks.
            if old & b == 0 || self.spi_edge[w].load(SeqCst) & b != 0 {
                return None;
            }
            match self.spi_owner[intid as usize].load(SeqCst) {
                NO_OWNER => None,
                o => Some(o as usize),
            }
        }
    }

    /// A message for SPI `intid` (MBI, GICv2m): it latches, as an edge.
    pub fn raise_spi(&self, intid: u32) -> Option<usize> {
        if !(32..NR_IRQS).contains(&intid) {
            return None;
        }
        self.io_edge[(intid / 32) as usize].fetch_or(bit(intid), SeqCst);
        self.spi_target(intid)
    }

    /// An MSI-X message as a device sent it: to the doorbell the guest was
    /// told of, with an SPI of the MSI range.
    pub fn msi(&self, addr: u64, data: u32) -> Option<usize> {
        let doorbell = if self.v3 { arm::GICD_BASE + GICD_SETSPI_NSR } else { arm::V2M_BASE + V2M_SETSPI };
        if addr != doorbell || !(MSI_BASE..MSI_BASE + MSI_COUNT).contains(&data) {
            return None;
        }
        self.raise_spi(data)
    }

    /// vCPU `cpu`'s PPI `intid` line.
    pub fn set_ppi_line(&self, cpu: usize, intid: u32, level: bool) {
        if level {
            self.ppi_level[cpu].fetch_or(bit(intid), SeqCst);
        } else {
            self.ppi_level[cpu].fetch_and(!bit(intid), SeqCst);
        }
    }

    // ---- SGIs.

    /// SGI `sgi` from vCPU `from` to vCPU `to`, which is told.
    #[cfg(test)]
    pub fn send_sgi(&self, from: usize, to: usize, sgi: u32, wake: &mut impl FnMut(usize)) {
        self.send_sgis(from, 1 << to, sgi as usize, wake);
    }

    /// SGI `sgi` from vCPU `me` to the vCPUs of `targets`, which are told.
    fn send_sgis(&self, me: usize, targets: Vcpus, sgi: usize, wake: &mut impl FnMut(usize)) {
        if self.v3 {
            return self.with_paused(me, 0, wake, |st, then| {
                for t in each(targets) {
                    st.local[t].word.latch |= 1 << sgi;
                    *then |= 1 << t;
                }
            });
        }
        let src = 1u8 << (me & 7);
        loop {
            // Only a target that may have this CPU's SGI in a list register
            // has to stop for it: whether that is still pending decides.
            let need = self.sgi_held(&self.state.lock(), me, targets, sgi, src);
            let done = self.with_paused(me, need, &mut *wake, |st, then| {
                if self.sgi_held(st, me, targets, sgi, src) & !need != 0 {
                    return false;
                }
                for t in each(targets) {
                    Self::pend_sgi(st, t, sgi, src);
                    *then |= 1 << t;
                }
                true
            });
            if done {
                return;
            }
        }
    }

    /// The other vCPUs of `targets` with an SGI from `src` in a list
    /// register that, as last known, the guest has not acknowledged.
    fn sgi_held(&self, st: &State, me: usize, targets: Vcpus, sgi: usize, src: u8) -> Vcpus {
        each(targets)
            .filter(|&t| t != me && st.local[t].held_src[sgi] & src != 0 && st.local[t].word.lr_pending & (1 << sgi) != 0)
            .fold(0, |m, t| m | 1 << t)
    }

    /// GICv2: SGI `sgi` of vCPU `to` becomes pending from the CPUs of
    /// `srcs`.  From a CPU whose SGI a list register has pending, it is
    /// already (IHI 0048B, table 4-24); once the guest has acknowledged
    /// that one, this is a new one.
    fn pend_sgi(st: &mut State, to: usize, sgi: usize, srcs: u8) {
        let l = &mut st.local[to];
        let add = if l.word.lr_pending & (1 << sgi) != 0 { srcs & !l.held_src[sgi] } else { srcs };
        l.sgi_from[sgi] |= add;
    }

    /// ICC_SGI1R_EL1 written by vCPU `me`: wakes each target.
    pub fn sgi1r(&self, me: usize, v: u64, wake: &mut impl FnMut(usize)) {
        let sgi = ((v >> 24) & 0xf) as usize;
        if v & (1 << 40) != 0 {
            // All but self.
            return self.send_sgis(me, self.all() & !(1 << me), sgi, wake);
        }
        let aff1 = (v >> 16) & 0xff;
        // We have no Aff2 or Aff3, nor range selectors (GICD_TYPER.RSS).
        if (v >> 32) & 0xff != 0 || (v >> 48) & 0xff != 0 || (v >> 44) & 0xf != 0 {
            return;
        }
        let targets = (0..16u64)
            .filter(|t| v & (1 << t) != 0)
            .filter_map(|t| arm::vcpu_of_aff((aff1 << 8) | t, self.vcpus))
            .fold(0 as Vcpus, |m, to| m | 1 << to);
        self.send_sgis(me, targets, sgi, wake);
    }

    /// GICD_SGIR (GICv2).
    fn sgir(&self, me: usize, v: u32, wake: &mut impl FnMut(usize)) {
        let list = match (v >> 24) & 3 {
            0 => (v >> 16) & 0xff,
            1 => 0xff & !(1 << me),
            2 => 1 << me,
            _ => 0,
        };
        let cpus: Vcpus = (1 << self.vcpus.min(8)) - 1;
        self.send_sgis(me, list as Vcpus & cpus, (v & 0xf) as usize, wake);
    }

    // ---- What the set and clear registers do, for a word of `cpu`'s view.
    // Under the lock; of pending and active state, with who holds them out
    // of their guests.  `then`: the vCPUs that are to look.

    /// The bits of word `w` that pending writes reach: GICv2's SGIs have
    /// GICD_SPENDSGIR and GICD_CPENDSGIR for that instead.
    fn pend_mask(&self, w: usize, bits: u32) -> u32 {
        if !self.v3 && w == 0 { bits & !0xffff } else { bits }
    }

    /// Whoever holds the interrupts of `bits` in word `w` is to look.
    fn tell_holders(&self, cpu: usize, w: usize, mut bits: u32, then: &mut Vcpus) {
        while bits != 0 {
            let i = bits.trailing_zeros();
            bits &= bits - 1;
            if let Some(h) = self.holder(cpu, w as u32 * 32 + i) {
                *then |= 1 << h;
            }
        }
    }

    /// Who is to look after `bits` of word `w` became deliverable.
    fn tell_targets(&self, me: usize, w: usize, bits: u32, then: &mut Vcpus) {
        if w == 0 {
            *then |= 1 << me;
            return;
        }
        for i in (0..32).filter(|i| bits & (1 << i) != 0) {
            if let Some(t) = self.spi_target(w as u32 * 32 + i) {
                *then |= 1 << t;
            }
        }
    }

    fn set_enable(&self, st: &mut State, cpu: usize, w: usize, bits: u32, then: &mut Vcpus) {
        st.word_mut(cpu, w).enable |= bits;
        self.tell_targets(cpu, w, bits, then);
    }

    /// A list register's pending interrupt that was disabled goes back.
    fn clear_enable(&self, st: &mut State, cpu: usize, w: usize, bits: u32, then: &mut Vcpus) {
        let word = st.word_mut(cpu, w);
        word.enable &= !bits;
        let held = word.lr_pending & bits;
        self.tell_holders(cpu, w, held, then);
    }

    /// GICD_ISPENDR.  A level-sensitive interrupt a list register has
    /// pending stays that one delivery, now pending by software too;
    /// otherwise, one more (after its EOI if the guest has it active).
    fn set_pending(&self, st: &mut State, cpu: usize, w: usize, bits: u32, then: &mut Vcpus) {
        let bits = self.pend_mask(w, bits);
        let word = st.word_mut(cpu, w);
        let in_lr = bits & !word.edge & word.lr_pending;
        word.lr_latched |= in_lr;
        word.latch |= bits & !in_lr;
        self.tell_targets(cpu, w, bits, then);
    }

    /// GICD_ICPENDR.  Only what has arrived so far (`with_paused` drained
    /// it): an edge after this is a new one.
    fn clear_pending(&self, st: &mut State, cpu: usize, w: usize, bits: u32, then: &mut Vcpus) {
        let bits = self.pend_mask(w, bits);
        let word = st.word_mut(cpu, w);
        word.latch &= !bits;
        let held = word.lr_pending & bits;
        word.lr_pending &= !held;
        word.lr_latched &= !held;
        word.cancel_pend |= held;
        self.tell_holders(cpu, w, held, then);
    }

    /// Software activation.  An interrupt the guest has active already
    /// stays as it is, to end with its EOI.  What a list register has not
    /// delivered yet comes back from it.
    fn set_active(&self, st: &mut State, cpu: usize, w: usize, bits: u32, then: &mut Vcpus) {
        let word = st.word_mut(cpu, w);
        let new = bits & !word.lr_active;
        word.active |= new;
        let held = word.lr_pending & new;
        self.tell_holders(cpu, w, held, then);
    }

    fn clear_active(&self, st: &mut State, cpu: usize, w: usize, bits: u32, then: &mut Vcpus) {
        let word = st.word_mut(cpu, w);
        word.active &= !bits;
        let held = word.lr_active & bits;
        word.lr_active &= !held;
        word.cancel_act |= held;
        self.tell_holders(cpu, w, held, then);
        // What software activation held back can be delivered.
        self.tell_targets(cpu, w, bits, then);
    }

    /// SPI `id`'s route changed: the vCPU that holds it gives it up.
    fn rerouted(&self, id: usize, then: &mut Vcpus) {
        let new = self.spi_target(id as u32);
        let owner = self.spi_owner[id].load(SeqCst);
        if owner != NO_OWNER && Some(owner as usize) != new {
            *then |= 1 << owner;
        }
        if let Some(t) = new {
            *then |= 1 << t;
        }
    }

    // ---- The distributor.

    fn group_word(&self) -> u32 {
        // GICv3 here has one security state and every interrupt in Group 1;
        // GICv2's guest takes its interrupts as Group 0.
        if self.v3 { u32::MAX } else { 0 }
    }

    /// Whether the distributor has word `word`: on GICv3 the first is the
    /// redistributor's.
    fn dist_has(&self, word: usize) -> bool {
        word < WORDS && !(self.v3 && word == 0)
    }

    /// vCPU `me` reads the distributor: the pending and active registers
    /// say what the guests have done.
    pub fn dist_read_for(&self, me: usize, off: u64, size: u8, wake: &mut impl FnMut(usize)) -> u64 {
        self.with_paused(me, self.dist_pause(me, off), wake, |st, _| self.dist_read_locked(st, me, off, size))
    }

    fn dist_read_locked(&self, st: &State, me: usize, off: u64, size: u8) -> u64 {
        let word = |base: u64| ((off - base) / 4) as usize;
        let v = match off & !3 {
            GICD_CTLR => {
                let on = st.enabled;
                if self.v3 { CTLR_V3_ARE | CTLR_V3_DS | if on { CTLR_V3_G1A } else { 0 } } else { on as u32 }
            }
            GICD_TYPER => {
                let lines = NR_IRQS / 32 - 1;
                if self.v3 { lines | (9 << 19) | TYPER_MBIS } else { lines | ((self.vcpus as u32 - 1) << 5) }
            }
            GICD_IIDR => IIDR,
            o if (GICD_IGROUPR..GICD_ISENABLER).contains(&o) => self.group_word(),
            o if (GICD_ISENABLER..GICD_ISPENDR).contains(&o) => {
                let w = word(if o < GICD_ICENABLER { GICD_ISENABLER } else { GICD_ICENABLER });
                if self.dist_has(w) { st.word(me, w).enable } else { 0 }
            }
            o if (GICD_ISPENDR..GICD_ISACTIVER).contains(&o) => {
                let w = word(if o < GICD_ICPENDR { GICD_ISPENDR } else { GICD_ICPENDR });
                if self.dist_has(w) { self.visible_pending(st, me, w) } else { 0 }
            }
            o if (GICD_ISACTIVER..GICD_IPRIORITYR).contains(&o) => {
                let w = word(if o < GICD_ICACTIVER { GICD_ISACTIVER } else { GICD_ICACTIVER });
                if self.dist_has(w) { Self::visible_active(st, me, w) } else { 0 }
            }
            o if (GICD_IPRIORITYR..GICD_ITARGETSR).contains(&o) => {
                let first = ((off & !3) - GICD_IPRIORITYR) as u32;
                if first + 3 >= NR_IRQS || (self.v3 && first < 32) {
                    0
                } else {
                    (0..4).fold(0, |v, i| v | (st.prio_of(me, first + i) as u32) << (8 * i))
                }
            }
            o if !self.v3 && (GICD_ITARGETSR..GICD_ICFGR).contains(&o) => {
                let first = ((off & !3) - GICD_ITARGETSR) as u32;
                if first + 3 >= NR_IRQS {
                    0
                } else {
                    (0..4).fold(0, |v, i| {
                        let t = first + i;
                        let b = if t < 32 { 1u8 << (me & 7) } else { self.route[t as usize].load(SeqCst) as u8 };
                        v | (b as u32) << (8 * i)
                    })
                }
            }
            o if (GICD_ICFGR..GICD_ICFGR + 0x100).contains(&o) => self.icfgr_read(st, me, word(GICD_ICFGR)),
            o if !self.v3 && (GICD_CPENDSGIR..GICD_SPENDSGIR + 16).contains(&o) => {
                let first = (o - if o < GICD_SPENDSGIR { GICD_CPENDSGIR } else { GICD_SPENDSGIR }) as usize;
                let l = &st.local[me];
                (0..4).fold(0, |v, i| {
                    let sgi = first + i;
                    let held = if l.word.lr_pending & (1 << sgi) != 0 { l.held_src[sgi] } else { 0 };
                    v | ((l.sgi_from[sgi] | held) as u32) << (8 * i)
                })
            }
            _ if self.v3 && (GICD_IROUTER + 32 * 8..GICD_IROUTER + NR as u64 * 8).contains(&(off & !7)) => {
                let v = self.route[((off & !7) - GICD_IROUTER) as usize / 8].load(SeqCst);
                return if size == 8 { v } else { (v >> (8 * (off & 4))) & 0xffff_ffff };
            }
            0xffe8 if self.v3 => 3 << 4,
            0xfe8 if !self.v3 => 2 << 4,
            _ => 0,
        };
        narrow(v as u64, off, size)
    }

    /// GICD_ICFGR word `w`: Int_config[1] of each INTID, in 2 bits.
    fn icfgr_read(&self, st: &State, me: usize, w: usize) -> u32 {
        let (word, shift) = (w / 2, 16 * (w % 2));
        if word >= WORDS || (self.v3 && word == 0) {
            return 0;
        }
        let edge = st.word(me, word).edge >> shift;
        (0..16).fold(0, |v, i| v | ((edge >> i) & 1) << (2 * i + 1))
    }

    fn icfgr_write(&self, st: &mut State, me: usize, w: usize, v: u32) {
        let (word, shift) = (w / 2, 16 * (w % 2));
        if word >= WORDS || (self.v3 && word == 0) || (word == 0 && w == 0) {
            // SGIs are always edge-triggered.
            return;
        }
        let edge = (0..16).fold(0u32, |e, i| e | ((v >> (2 * i + 1)) & 1) << i);
        let mask = 0xffffu32 << shift;
        let cfg = &mut st.word_mut(me, word).edge;
        *cfg = (*cfg & !mask) | (edge << shift);
        if word == 0 {
            // The timer's line is a level, whatever the guest writes.
            *cfg &= !bit(PPI_VTIMER);
        }
        if word != 0 {
            let cfg = *cfg;
            self.spi_edge[word].store(cfg, SeqCst);
        }
    }

    /// The guest writes the distributor.  `wake` says which vCPUs have
    /// something new to look at.
    pub fn dist_write(&self, me: usize, off: u64, size: u8, v: u64, wake: &mut impl FnMut(usize)) {
        let val = v as u32;
        let pause = match off & !3 {
            GICD_SETSPI_NSR if self.v3 => {
                if let Some(t) = self.raise_spi(val & 0x3ff) {
                    wake(t);
                }
                return;
            }
            GICD_SGIR if !self.v3 => return self.sgir(me, val, wake),
            GICD_CLRSPI_NSR if self.v3 => self.pause_for(me, me, ((val & 0x3ff) / 32) as usize),
            _ => self.dist_pause(me, off),
        };
        self.with_paused(me, pause, wake, |st, then| self.dist_write_locked(st, me, off, size, v, then));
    }

    fn dist_write_locked(&self, st: &mut State, me: usize, off: u64, size: u8, v: u64, then: &mut Vcpus) {
        let val = v as u32;
        let word = |base: u64| ((off - base) / 4) as usize;
        match off & !3 {
            GICD_CTLR => {
                st.enabled = if self.v3 { val & CTLR_V3_G1A != 0 } else { val & 1 != 0 };
                // On: what is pending can go.  Off: what the guests have not
                // acknowledged comes back from their list registers.
                *then |= self.all();
            }
            GICD_CLRSPI_NSR if self.v3 => {
                let id = val & 0x3ff;
                if (32..NR_IRQS).contains(&id) {
                    self.clear_pending(st, me, (id / 32) as usize, bit(id), then);
                }
            }
            o if (GICD_ISENABLER..GICD_ICENABLER).contains(&o) => {
                let w = word(GICD_ISENABLER);
                if self.dist_has(w) {
                    self.set_enable(st, me, w, val, then);
                }
            }
            o if (GICD_ICENABLER..GICD_ISPENDR).contains(&o) => {
                let w = word(GICD_ICENABLER);
                if self.dist_has(w) {
                    self.clear_enable(st, me, w, val, then);
                }
            }
            o if (GICD_ISPENDR..GICD_ICPENDR).contains(&o) => {
                let w = word(GICD_ISPENDR);
                if self.dist_has(w) {
                    self.set_pending(st, me, w, val, then);
                }
            }
            o if (GICD_ICPENDR..GICD_ISACTIVER).contains(&o) => {
                let w = word(GICD_ICPENDR);
                if self.dist_has(w) {
                    self.clear_pending(st, me, w, val, then);
                }
            }
            o if (GICD_ISACTIVER..GICD_ICACTIVER).contains(&o) => {
                let w = word(GICD_ISACTIVER);
                if self.dist_has(w) {
                    self.set_active(st, me, w, val, then);
                }
            }
            o if (GICD_ICACTIVER..GICD_IPRIORITYR).contains(&o) => {
                let w = word(GICD_ICACTIVER);
                if self.dist_has(w) {
                    self.clear_active(st, me, w, val, then);
                }
            }
            o if (GICD_IPRIORITYR..GICD_ITARGETSR).contains(&o) => {
                for i in 0..size.min(4) as u64 {
                    let id = (off - GICD_IPRIORITYR + i) as u32;
                    if id < NR_IRQS && !(self.v3 && id < 32) {
                        *st.prio_mut(me, id) = (v >> (8 * i)) as u8;
                    }
                }
            }
            o if !self.v3 && (GICD_ITARGETSR..GICD_ICFGR).contains(&o) => {
                for i in 0..size.min(4) as u64 {
                    let id = (off - GICD_ITARGETSR + i) as usize;
                    if (32..NR).contains(&id) {
                        // Of the CPUs there are.
                        let mask = (v >> (8 * i)) as u8 & ((1u16 << self.vcpus.min(8)) - 1) as u8;
                        self.route[id].store(mask as u64, SeqCst);
                        self.rerouted(id, then);
                    }
                }
            }
            o if (GICD_ICFGR..GICD_ICFGR + 0x100).contains(&o) => self.icfgr_write(st, me, word(GICD_ICFGR), val),
            o if !self.v3 && (GICD_CPENDSGIR..GICD_SPENDSGIR + 16).contains(&o) => {
                let set = o >= GICD_SPENDSGIR;
                let base = if set { GICD_SPENDSGIR } else { GICD_CPENDSGIR };
                for i in 0..size.min(4) as u64 {
                    let sgi = (off - base + i) as usize;
                    if sgi < 16 {
                        Self::sgi_sources(st, me, sgi, (v >> (8 * i)) as u8, set);
                    }
                }
                *then |= 1 << me;
            }
            _ if self.v3 && (GICD_IROUTER + 32 * 8..GICD_IROUTER + NR as u64 * 8).contains(&(off & !7)) => {
                let id = ((off & !7) - GICD_IROUTER) as usize / 8;
                let old = self.route[id].load(SeqCst);
                let new = match size {
                    8 => v,
                    _ if off & 4 != 0 => (old & 0xffff_ffff) | (v << 32),
                    _ => (old & !0xffff_ffff) | (v & 0xffff_ffff),
                };
                self.route[id].store(new, SeqCst);
                self.rerouted(id, then);
            }
            _ => {}
        }
    }

    /// GICD_SPENDSGIR or GICD_CPENDSGIR (GICv2): the sources of an SGI of
    /// the calling CPU, whose own list registers are as it left them.
    fn sgi_sources(st: &mut State, me: usize, sgi: usize, bits: u8, set: bool) {
        if set {
            return Self::pend_sgi(st, me, sgi, bits);
        }
        let l = &mut st.local[me];
        l.sgi_from[sgi] &= !bits;
        if l.word.lr_pending & (1 << sgi) != 0 && l.held_src[sgi] & bits != 0 {
            l.word.lr_pending &= !(1 << sgi);
            l.word.cancel_pend |= 1 << sgi;
        }
    }

    // ---- GICv3's redistributors.

    /// The vCPU whose frames offset `off` of the GICR region is in, and
    /// the offset in them.
    pub fn redist_at(&self, off: u64) -> Option<(usize, u64)> {
        let v = (off / arm::GICR_STRIDE) as usize;
        (v < self.vcpus).then_some((v, off % arm::GICR_STRIDE))
    }

    /// vCPU `me` reads vCPU `cpu`'s redistributor.
    pub fn redist_read_for(&self, me: usize, cpu: usize, off: u64, size: u8, wake: &mut impl FnMut(usize)) -> u64 {
        self.with_paused(me, self.redist_pause(me, cpu, off), wake, |st, _| self.redist_read_locked(st, cpu, off, size))
    }

    fn redist_read_locked(&self, st: &State, cpu: usize, off: u64, size: u8) -> u64 {
        let l = &st.local[cpu];
        let v: u64 = match off & !3 {
            GICR_CTLR => 0,
            GICR_IIDR => IIDR as u64,
            GICR_TYPER => {
                let aff = arm::mpidr_aff(cpu);
                let typer = ((cpu as u64) << 8) | if cpu + 1 == self.vcpus { TYPER_LAST } else { 0 } | (aff << 32);
                return if size == 8 { typer } else { typer & 0xffff_ffff };
            }
            0x000c => {
                let aff = arm::mpidr_aff(cpu);
                aff & 0xffff_ffff
            }
            GICR_WAKER => l.waker as u64,
            0xffe8 => 3 << 4,
            GICR_IGROUPR0 => u32::MAX as u64,
            GICR_IGRPMODR0 => 0,
            o if o == GICR_SGI + GICD_ISENABLER || o == GICR_SGI + GICD_ICENABLER => l.word.enable as u64,
            o if o == GICR_SGI + GICD_ISPENDR || o == GICR_SGI + GICD_ICPENDR => self.visible_pending(st, cpu, 0) as u64,
            o if o == GICR_SGI + GICD_ISACTIVER || o == GICR_SGI + GICD_ICACTIVER => Self::visible_active(st, cpu, 0) as u64,
            o if (GICR_SGI + GICD_IPRIORITYR..GICR_SGI + GICD_IPRIORITYR + 32).contains(&o) => {
                let first = (o - GICR_SGI - GICD_IPRIORITYR) as usize;
                (0..4).fold(0, |v, i| v | (l.prio[first + i] as u64) << (8 * i))
            }
            o if o == GICR_SGI + GICD_ICFGR => 0xaaaa_aaaa,
            o if o == GICR_SGI + GICD_ICFGR + 4 => {
                let edge = l.word.edge >> 16;
                (0..16).fold(0u64, |v, i| v | ((edge as u64 >> i) & 1) << (2 * i + 1))
            }
            _ => 0,
        };
        narrow(v, off, size)
    }

    pub fn redist_write(&self, me: usize, cpu: usize, off: u64, size: u8, v: u64, wake: &mut impl FnMut(usize)) {
        self.with_paused(me, self.redist_pause(me, cpu, off), wake, |st, then| self.redist_write_locked(st, cpu, off, size, v, then));
    }

    fn redist_write_locked(&self, st: &mut State, cpu: usize, off: u64, size: u8, v: u64, then: &mut Vcpus) {
        let val = v as u32;
        match off & !3 {
            GICR_WAKER => {
                // Awake as asked, at once.
                let w = val & WAKER_PROCESSOR_SLEEP;
                st.local[cpu].waker = w | if w != 0 { WAKER_CHILDREN_ASLEEP } else { 0 };
            }
            o if o == GICR_SGI + GICD_ISENABLER => self.set_enable(st, cpu, 0, val, then),
            o if o == GICR_SGI + GICD_ICENABLER => self.clear_enable(st, cpu, 0, val, then),
            o if o == GICR_SGI + GICD_ISPENDR => self.set_pending(st, cpu, 0, val, then),
            o if o == GICR_SGI + GICD_ICPENDR => self.clear_pending(st, cpu, 0, val, then),
            o if o == GICR_SGI + GICD_ISACTIVER => self.set_active(st, cpu, 0, val, then),
            o if o == GICR_SGI + GICD_ICACTIVER => self.clear_active(st, cpu, 0, val, then),
            o if (GICR_SGI + GICD_IPRIORITYR..GICR_SGI + GICD_IPRIORITYR + 32).contains(&o) => {
                for i in 0..size.min(4) as u64 {
                    let id = (off - GICR_SGI - GICD_IPRIORITYR + i) as usize;
                    if id < 32 {
                        st.local[cpu].prio[id] = (v >> (8 * i)) as u8;
                    }
                }
            }
            o if o == GICR_SGI + GICD_ICFGR + 4 => {
                let edge = (0..16).fold(0u32, |e, i| e | ((val >> (2 * i + 1)) & 1) << i);
                // The timer's line is a level, whatever the guest writes.
                st.local[cpu].word.edge = (0xffff | (edge << 16)) & !bit(PPI_VTIMER);
            }
            _ => {}
        }
    }

    // ---- GICv2m's frame.

    pub fn v2m_read(&self, off: u64, size: u8) -> u64 {
        let v: u64 = match off & !3 {
            V2M_TYPER => ((MSI_BASE as u64) << 16) | MSI_COUNT as u64,
            V2M_IIDR => 0x53 << 16 | 0x43b,
            _ => 0,
        };
        narrow(v, off, size)
    }

    pub fn v2m_write(&self, off: u64, v: u64) -> Option<usize> {
        if off & !3 == V2M_SETSPI && (MSI_BASE..MSI_BASE + MSI_COUNT).contains(&(v as u32)) {
            self.raise_spi(v as u32)
        } else {
            None
        }
    }

    /// What vCPU `cpu` could be given now, in word `w`, beyond `held`: not
    /// what software made active, nor an SPI some vCPU holds.
    fn deliverable(&self, st: &State, cpu: usize, w: usize, held: u32) -> u32 {
        if !st.enabled {
            return 0;
        }
        let word = st.word(cpu, w);
        let mut bits = word.enable & self.sw_pending(st, cpu, w) & !word.active & !held;
        if w != 0 {
            let mut keep = 0;
            while bits != 0 {
                let i = bits.trailing_zeros();
                bits &= bits - 1;
                let id = w as u32 * 32 + i;
                if self.spi_target(id) == Some(cpu) && self.spi_owner[id as usize].load(SeqCst) == NO_OWNER {
                    keep |= 1 << i;
                }
            }
            bits = keep;
        }
        bits
    }

    /// A list register of `cpu` gave up `id`: the vCPU that is to look, a
    /// bit, if the SPI has moved and waits there.
    fn release_spi(&self, st: &State, cpu: usize, id: u32) -> u64 {
        if id < 32 {
            return 0;
        }
        self.spi_owner[id as usize].store(NO_OWNER, SeqCst);
        let w = (id / 32) as usize;
        match self.spi_target(id) {
            Some(t) if t != cpu && self.deliverable(st, t, w, 0) & bit(id) != 0 => 1 << t,
            _ => 0,
        }
    }

    /// Take `intid`'s pending state for a list register, if it has any: the
    /// source of a GICv2 SGI, whether others are pending, and whether
    /// software made a level-sensitive one pending.
    fn take(&self, st: &mut State, cpu: usize, intid: u32) -> Option<(u8, bool, bool)> {
        if !self.v3 && intid < 16 {
            let from = &mut st.local[cpu].sgi_from[intid as usize];
            let old = *from;
            if old == 0 {
                return None;
            }
            *from = old & (old - 1);
            return Some((old.trailing_zeros() as u8, *from != 0, false));
        }
        let (w, b) = ((intid / 32) as usize, bit(intid));
        let line = self.level(cpu, w) & b != 0;
        let word = st.word_mut(cpu, w);
        let soft = word.latch & b != 0;
        word.latch &= !b;
        if word.edge & b != 0 {
            return soft.then_some((0, false, false));
        }
        (soft || line).then_some((0, false, soft))
    }
}

/// `size` bytes of the 32-bit register value `v` at byte `off` of it.
fn narrow(v: u64, off: u64, size: u8) -> u64 {
    let v = v >> (8 * (off & 3));
    if size >= 8 { v } else { v & ((1u64 << (8 * size as u32)) - 1) }
}

/// What a vCPU's thread alone keeps: which interrupts are in its list
/// registers.
pub struct Cpu {
    id: usize,
    v3: bool,
    nr_lrs: usize,
    lr: [u16; 16],
    /// GICv2: the source CPU of the SGI in each list register.
    lr_src: [u8; 16],
    /// `lr`'s INTIDs, a bit each.
    held: [u32; WORDS],
    /// The LRs or the control register changed since FL4 last had them.
    pub dirty: bool,
    hcr: u64,
}

impl Cpu {
    /// vCPU `id`, on a CPU interface with `vtr` (ICH_VTR_EL2 or GICH_VTR).
    pub fn new(id: usize, v3: bool, vtr: u64) -> Self {
        let nr_lrs = ((vtr & if v3 { 0x1f } else { 0x3f }) as usize + 1).min(16);
        // Not FL4's reset value, which traps Group 0's registers (TALL0):
        // Linux probes and clears them (ICC_AP0Rn_EL1), and FL4 switches them.
        Cpu { id, v3, nr_lrs, lr: [NO_IRQ; 16], lr_src: [0; 16], held: [0; WORDS], dirty: true, hcr: HCR_EN }
    }

    /// The value of VGIC_HCR for the next entry.
    pub fn hcr(&self) -> u64 {
        self.hcr
    }

    /// The CPU interface at reset (CPU_OFF, CPU_ON): its list registers,
    /// virtual control register and active priorities empty.  The vCPUs
    /// that are to look at an SPI it gave up, a bit each.
    pub fn reset(&mut self, vg: &Vgic, regs: &mut [u64; 64]) -> u64 {
        let mut st = vg.state.lock();
        vg.drain_io(&mut st);
        // What was cleared meanwhile is not to go back as pending below.
        let mut wake = self.reconcile(vg, &mut st, regs);
        for i in 0..self.nr_lrs {
            if self.lr[i] != NO_IRQ {
                // An SPI not yet taken is still pending, for whoever is next.
                if self.lr[i] >= 32 && regs[reg::VGIC_LR0 + i] & self.pend_bit() != 0 {
                    self.unpend(&mut st, i);
                }
                wake |= self.free(vg, &mut st, regs, i);
            }
        }
        self.hcr &= !HCR_UIE;
        regs[reg::VGIC_HCR] = self.hcr;
        regs[reg::VGIC_HCR + 1..].fill(0);
        self.dirty = true;
        wake
    }

    /// Whether any list register holds an interrupt, so that the entry
    /// must bring them back.
    pub fn in_use(&self) -> bool {
        self.lr.iter().any(|&i| i != NO_IRQ)
    }

    fn pend_bit(&self) -> u64 {
        if self.v3 { LR3_PENDING } else { LR2_PENDING }
    }

    fn act_bit(&self) -> u64 {
        if self.v3 { LR3_ACTIVE } else { LR2_ACTIVE }
    }

    fn eoi_bit(&self) -> u64 {
        if self.v3 { LR3_EOI } else { LR2_EOI }
    }

    /// A list register's priority, in the bits this GIC compares.
    fn lr_prio(&self, lr: u64) -> u8 {
        if self.v3 { (lr >> 48) as u8 } else { (((lr >> 23) & 0x1f) << 3) as u8 }
    }

    /// An interrupt's priority, in those bits.
    fn prio_bits(&self, prio: u8) -> u8 {
        if self.v3 { prio } else { prio & 0xf8 }
    }

    /// Empty list register `i`: the vCPU to look at an SPI it gave up.
    fn free(&mut self, vg: &Vgic, st: &mut State, regs: &mut [u64; 64], i: usize) -> u64 {
        let id = self.lr[i] as u32;
        let (w, b) = ((id / 32) as usize, bit(id));
        regs[reg::VGIC_LR0 + i] = 0;
        self.lr[i] = NO_IRQ;
        self.held[w] &= !b;
        self.dirty = true;
        let word = st.word_mut(self.id, w);
        word.lr_pending &= !b;
        word.lr_active &= !b;
        word.lr_latched &= !b;
        word.cancel_pend &= !b;
        word.cancel_act &= !b;
        if !self.v3 && id < 16 {
            st.local[self.id].held_src[id as usize] = 0;
        }
        vg.release_spi(st, self.id, id)
    }

    /// The pending state of list register `i` goes back where it came from
    /// (a level-sensitive interrupt's is its line).
    fn unpend(&mut self, st: &mut State, i: usize) {
        let id = self.lr[i] as u32;
        if !self.v3 && id < 16 {
            st.local[self.id].sgi_from[id as usize] |= 1 << self.lr_src[i];
            return;
        }
        let word = st.word_mut(self.id, (id / 32) as usize);
        if word.edge & bit(id) != 0 || word.lr_latched & bit(id) != 0 {
            word.latch |= bit(id);
        }
    }

    /// After an exit: the list registers as the guest left them.  Those it
    /// ended are free, and what the other threads asked of the rest is
    /// done.  The vCPUs that are to look at an SPI given up here, a bit
    /// each.
    #[cfg(test)]
    pub fn sync(&mut self, vg: &Vgic, regs: &mut [u64; 64]) -> u64 {
        let mut st = vg.state.lock();
        vg.drain_io(&mut st);
        self.sync_locked(vg, &mut st, regs)
    }

    fn sync_locked(&mut self, vg: &Vgic, st: &mut State, regs: &mut [u64; 64]) -> u64 {
        let mut wake = 0;
        let (pend, act) = (self.pend_bit(), self.act_bit());
        for i in 0..self.nr_lrs {
            if self.lr[i] == NO_IRQ {
                continue;
            }
            let id = self.lr[i] as u32;
            let r = regs[reg::VGIC_LR0 + i];
            if r & (pend | act) == 0 {
                wake |= self.free(vg, st, regs, i);
                continue;
            }
            let (word, b) = (st.word_mut(self.id, (id / 32) as usize), bit(id));
            if r & pend != 0 {
                word.lr_pending |= b;
            } else {
                // Acknowledged: software's pending state went with it.
                word.lr_pending &= !b;
                word.lr_latched &= !b;
            }
            if r & act != 0 {
                word.lr_active |= b;
            } else {
                word.lr_active &= !b;
            }
        }
        wake | self.reconcile(vg, st, regs)
    }

    /// Bring the list registers in line with the distributor: what the
    /// guest cleared, what is no longer pending, or enabled, or routed here.
    fn reconcile(&mut self, vg: &Vgic, st: &mut State, regs: &mut [u64; 64]) -> u64 {
        (0..self.nr_lrs).fold(0, |wake, i| wake | self.reconcile_one(vg, st, regs, i))
    }

    fn reconcile_one(&mut self, vg: &Vgic, st: &mut State, regs: &mut [u64; 64], i: usize) -> u64 {
        if self.lr[i] == NO_IRQ {
            return 0;
        }
        let (pend, act, eoi) = (self.pend_bit(), self.act_bit(), self.eoi_bit());
        let id = self.lr[i] as u32;
        let (w, b) = ((id / 32) as usize, bit(id));
        // What was cleared first: it is not to come back by `unpend`.
        let word = st.word_mut(self.id, w);
        if word.cancel_pend & b != 0 {
            word.cancel_pend &= !b;
            word.lr_pending &= !b;
            word.lr_latched &= !b;
            regs[reg::VGIC_LR0 + i] &= !pend;
            self.dirty = true;
        }
        if word.cancel_act & b != 0 {
            word.cancel_act &= !b;
            word.lr_active &= !b;
            regs[reg::VGIC_LR0 + i] &= !act;
            self.dirty = true;
        }
        let latched = word.lr_latched & b != 0;
        let r = regs[reg::VGIC_LR0 + i];
        let (p, a) = (r & pend != 0, r & act != 0);
        if !p && !a {
            return self.free(vg, st, regs, i);
        }
        // Not taken yet, and its line fell.
        if p && !a && !latched && !st.is_edge(self.id, id) && vg.sw_pending(st, self.id, w) & b == 0 {
            return self.free(vg, st, regs, i);
        }
        // Its pending state cannot stay here if the distributor or it is
        // disabled, if software made it active, or if it moved: it goes back
        // to the distributor.
        let moved = id >= 32 && vg.spi_target(id) != Some(self.id);
        if p && (moved || st.blocked(self.id, w, b)) {
            self.unpend(st, i);
            if !a {
                return self.free(vg, st, regs, i);
            }
            let word = st.word_mut(self.id, w);
            word.lr_pending &= !b;
            word.lr_latched &= !b;
            regs[reg::VGIC_LR0 + i] &= !pend;
            self.dirty = true;
        }
        // Active here: its EOI brings this thread back to free it.
        if moved && regs[reg::VGIC_LR0 + i] & eoi == 0 {
            regs[reg::VGIC_LR0 + i] |= eoi;
            self.dirty = true;
        }
        0
    }

    /// Before an entry, if no other vCPU is keeping this one out (None): in
    /// one critical section, fill the list registers and, if it is to run
    /// (not `halted`, or something ends the wait), mark it in its guest.
    /// The vCPUs that are to look at an SPI given up here, a bit each, and
    /// whether to enter.
    pub fn try_enter(&mut self, vg: &Vgic, regs: &mut [u64; 64], halted: bool) -> Option<(u64, bool)> {
        let mut st = vg.state.lock();
        if st.local[self.id].pause != 0 {
            return None;
        }
        vg.drain_io(&mut st);
        let wake = self.flush_locked(vg, &mut st, regs);
        let go = !halted || self.pending_locked(vg, &st, regs);
        st.local[self.id].in_guest = go;
        Some((wake, go))
    }

    /// `try_enter`, waiting for those who keep it out.
    pub fn enter(&mut self, vg: &Vgic, regs: &mut [u64; 64], halted: bool) -> (u64, bool) {
        loop {
            if let Some(r) = self.try_enter(vg, regs, halted) {
                return r;
            }
            crate::yield_now();
        }
    }

    /// After an entry: out of its guest, with the list registers as it left
    /// them if the exit `saved` them.  The vCPUs that are to look at an SPI
    /// given up here, a bit each.
    pub fn left(&mut self, vg: &Vgic, regs: &mut [u64; 64], saved: bool) -> u64 {
        let mut st = vg.state.lock();
        vg.drain_io(&mut st);
        let wake = if saved { self.sync_locked(vg, &mut st, regs) } else { 0 };
        st.local[self.id].in_guest = false;
        wake
    }

    /// What is deliverable goes into list registers (`flush_locked`).
    #[cfg(test)]
    pub fn flush(&mut self, vg: &Vgic, regs: &mut [u64; 64]) -> u64 {
        let mut st = vg.state.lock();
        vg.drain_io(&mut st);
        self.flush_locked(vg, &mut st, regs)
    }

    /// `flush`, with what another thread does inside `load`'s window.
    #[cfg(test)]
    fn flush_with(&mut self, vg: &Vgic, regs: &mut [u64; 64], mut before_take: impl FnMut(u32)) -> u64 {
        let mut st = vg.state.lock();
        vg.drain_io(&mut st);
        self.flush_inner(vg, &mut st, regs, &mut before_take)
    }

    /// What is deliverable into list registers, the most urgent first,
    /// taking one from a less urgent interrupt the guest has not
    /// acknowledged; and an underflow interrupt if some is left.  An edge
    /// that came for an interrupt the guest still holds pends again in its
    /// list register.  The vCPUs that are to look at an SPI given up here,
    /// a bit each.
    fn flush_locked(&mut self, vg: &Vgic, st: &mut State, regs: &mut [u64; 64]) -> u64 {
        self.flush_inner(vg, st, regs, &mut |_| {})
    }

    /// `flush_locked`; `before_take` runs where `load` has published an
    /// interrupt's owner and not yet sampled its line.
    fn flush_inner(&mut self, vg: &Vgic, st: &mut State, regs: &mut [u64; 64], before_take: &mut impl FnMut(u32)) -> u64 {
        let mut wake = self.reconcile(vg, st, regs);
        let (pend, act, eoi) = (self.pend_bit(), self.act_bit(), self.eoi_bit());
        for i in 0..self.nr_lrs {
            let intid = self.lr[i];
            if intid == NO_IRQ || !st.is_edge(self.id, intid as u32) {
                continue;
            }
            let id = intid as u32;
            // An SPI that moved takes its new edges with it.
            if id >= 32 && vg.spi_target(id) != Some(self.id) {
                continue;
            }
            let (w, b) = ((id / 32) as usize, bit(id));
            // Not while disabled, or active by software: the edge stays in
            // the distributor.
            let held_back = st.blocked(self.id, w, b);
            if !self.v3 && id < 16 {
                let same = 1u8 << self.lr_src[i];
                let r = regs[reg::VGIC_LR0 + i];
                let l = &mut st.local[self.id];
                if l.sgi_from[id as usize] & same != 0 {
                    if r & pend != 0 {
                        // Pending from that CPU already (table 4-24).
                        l.sgi_from[id as usize] &= !same;
                    } else if r & act != 0 && !held_back {
                        // A new one from it, while the last is active.
                        l.sgi_from[id as usize] &= !same;
                        regs[reg::VGIC_LR0 + i] |= pend;
                        l.word.lr_pending |= b;
                        self.dirty = true;
                    }
                }
                // Another CPU's has an LR of its own, once this one is
                // free: the guest's EOI is to bring us back.
                if l.sgi_from[id as usize] != 0 && regs[reg::VGIC_LR0 + i] & eoi == 0 {
                    regs[reg::VGIC_LR0 + i] |= eoi;
                    self.dirty = true;
                }
                continue;
            }
            let word = st.word_mut(self.id, w);
            if held_back || word.latch & b == 0 {
                continue;
            }
            word.latch &= !b;
            if regs[reg::VGIC_LR0 + i] & pend == 0 {
                regs[reg::VGIC_LR0 + i] |= pend;
                word.lr_pending |= b;
                self.dirty = true;
            }
        }
        let mut left = false;
        // What turned out to have nothing pending: the others still go in.
        let mut skip = [0u32; WORDS];
        while let Some((prio, id)) = self.best(vg, st, &skip) {
            let free = (0..self.nr_lrs).find(|&i| self.lr[i] == NO_IRQ);
            let slot = match free {
                Some(f) => f,
                None => match self.victim(regs) {
                    Some((v, p)) if p > self.prio_bits(prio) => {
                        self.unpend(st, v);
                        wake |= self.free(vg, st, regs, v);
                        v
                    }
                    _ => {
                        left = true;
                        break;
                    }
                },
            };
            if !self.load(vg, st, regs, slot, id, prio, before_take) {
                skip[(id / 32) as usize] |= bit(id);
            }
        }
        let hcr = (self.hcr & !HCR_UIE) | if left { HCR_UIE } else { 0 };
        if hcr != self.hcr {
            self.hcr = hcr;
            self.dirty = true;
        }
        regs[reg::VGIC_HCR] = self.hcr;
        wake
    }

    /// Put interrupt `id`, which `best` just chose under this same lock, in
    /// list register `slot`: its pending state moves there, and it is this
    /// vCPU's, in one step for anyone who looks.  False if it has none left.
    ///
    /// The I/O thread takes no lock: it lowers a line, then reads the owner.
    /// So the owner is published first, then the line sampled: either this
    /// sees the line low, or the I/O thread sees this vCPU and tells it.
    #[allow(clippy::too_many_arguments)]
    fn load(&mut self, vg: &Vgic, st: &mut State, regs: &mut [u64; 64], slot: usize, id: u32, prio: u8, before_take: &mut impl FnMut(u32)) -> bool {
        let (w, b) = ((id / 32) as usize, bit(id));
        if id >= 32 {
            vg.spi_owner[id as usize].store(self.id as u8, SeqCst);
        }
        before_take(id);
        let Some((src, more, soft)) = vg.take(st, self.id, id) else {
            if id >= 32 {
                vg.spi_owner[id as usize].store(NO_OWNER, SeqCst);
            }
            return false;
        };
        // A level is sampled again at EOI; so are GICv2's other sources.
        let ask_eoi = !st.is_edge(self.id, id) || more;
        regs[reg::VGIC_LR0 + slot] = if self.v3 {
            LR3_PENDING | LR3_GROUP1 | (prio as u64) << 48 | if ask_eoi { LR3_EOI } else { 0 } | id as u64
        } else {
            // Group 0, as the guest's GICv2 driver takes them.
            LR2_PENDING | ((prio >> 3) as u64) << 23 | if ask_eoi { LR2_EOI } else { 0 } | ((src as u64) << 10) | id as u64
        };
        self.lr[slot] = id as u16;
        self.lr_src[slot] = src;
        self.held[w] |= b;
        self.dirty = true;
        let word = st.word_mut(self.id, w);
        word.cancel_pend &= !b;
        word.cancel_act &= !b;
        word.lr_active &= !b;
        word.lr_pending |= b;
        word.lr_latched = (word.lr_latched & !b) | if soft { b } else { 0 };
        if !self.v3 && id < 16 {
            st.local[self.id].held_src[id as usize] = 1 << src;
        }
        true
    }

    /// The list register to give up for a more urgent interrupt: of those
    /// the guest has not acknowledged, the least urgent, with its priority.
    fn victim(&self, regs: &[u64; 64]) -> Option<(usize, u8)> {
        let (pend, act) = (self.pend_bit(), self.act_bit());
        (0..self.nr_lrs)
            .filter(|&i| self.lr[i] != NO_IRQ)
            .map(|i| (i, regs[reg::VGIC_LR0 + i]))
            .filter(|&(_, r)| r & pend != 0 && r & act == 0)
            .map(|(i, r)| (i, self.lr_prio(r)))
            .max_by_key(|&(_, p)| p)
    }

    /// The deliverable interrupt of the highest priority (lowest value),
    /// but for those of `skip`.
    fn best(&self, vg: &Vgic, st: &State, skip: &[u32; WORDS]) -> Option<(u8, u32)> {
        let mut best: Option<(u8, u32)> = None;
        for (w, &skipped) in skip.iter().enumerate() {
            let mut bits = vg.deliverable(st, self.id, w, self.held[w] | skipped);
            while bits != 0 {
                let i = bits.trailing_zeros();
                bits &= bits - 1;
                let id = w as u32 * 32 + i;
                let p = st.prio_of(self.id, id);
                if best.is_none_or(|(q, _)| p < q) {
                    best = Some((p, id));
                }
            }
        }
        best
    }

    /// Whether an interrupt waits for this vCPU, in a list register or
    /// to go in one: what ends WFI.
    #[cfg(test)]
    pub fn pending(&self, vg: &Vgic, regs: &[u64; 64]) -> bool {
        let mut st = vg.state.lock();
        vg.drain_io(&mut st);
        self.pending_locked(vg, &st, regs)
    }

    fn pending_locked(&self, vg: &Vgic, st: &State, regs: &[u64; 64]) -> bool {
        let pend = self.pend_bit();
        (0..self.nr_lrs).any(|i| self.lr[i] != NO_IRQ && regs[reg::VGIC_LR0 + i] & pend != 0)
            || (0..WORDS).any(|w| vg.deliverable(st, self.id, w, self.held[w]) != 0)
    }
}

#[cfg(test)]
impl Vgic {
    fn dist_read(&self, me: usize, off: u64, size: u8) -> u64 {
        self.dist_read_for(me, off, size, &mut |_| {})
    }

    fn redist_read(&self, cpu: usize, off: u64, size: u8) -> u64 {
        self.redist_read_for(cpu, cpu, off, size, &mut |_| {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LR: usize = reg::VGIC_LR0;
    const SPI: u32 = 40;

    /// SPI `id`'s latch: pending outside the list registers, by software or
    /// an edge.
    fn latched(v: &Vgic, id: u32) -> bool {
        let mut st = v.state.lock();
        v.drain_io(&mut st);
        st.spi[(id / 32) as usize].latch & bit(id) != 0
    }

    fn on(v: &Vgic) {
        v.dist_write(0, GICD_CTLR, 4, CTLR_V3_G1A as u64 | 1, &mut |_| {});
    }

    fn enable_spi(v: &Vgic, id: u32) {
        v.dist_write(0, GICD_ISENABLER + 4 * (id as u64 / 32), 4, bit(id) as u64, &mut |_| {});
    }

    fn edge_spi(v: &Vgic, id: u32) {
        let reg = GICD_ICFGR + 4 * (id as u64 / 16);
        let old = v.dist_read(0, reg, 4);
        v.dist_write(0, reg, 4, old | 2 << (2 * (id % 16)), &mut |_| {});
    }

    fn route3(v: &Vgic, id: u32, cpu: usize) {
        v.dist_write(0, GICD_IROUTER + 8 * id as u64, 8, arm::mpidr_aff(cpu) & 0xff | (arm::mpidr_aff(cpu) >> 8) << 8, &mut |_| {});
    }

    #[test]
    fn identity_and_typer() {
        let v = Vgic::new(true, 2);
        assert_eq!(v.dist_read(0, 0xffe8, 4) >> 4, 3);
        let t = v.dist_read(0, GICD_TYPER, 4) as u32;
        assert_eq!(t & 0x1f, NR_IRQS / 32 - 1);
        assert_ne!(t & TYPER_MBIS, 0, "MBI");
        assert_eq!(t & (1 << 17), 0, "no LPIs");
        let v2 = Vgic::new(false, 3);
        assert_eq!(v2.dist_read(0, 0xfe8, 4) >> 4, 2);
        assert_eq!((v2.dist_read(0, GICD_TYPER, 4) >> 5) & 7, 2, "CPUNumber");
    }

    #[test]
    fn redistributors() {
        let v = Vgic::new(true, 2);
        assert_eq!(v.redist_at(arm::GICR_STRIDE + 8), Some((1, 8)));
        assert_eq!(v.redist_at(2 * arm::GICR_STRIDE), None);
        assert_eq!(v.redist_read(0, GICR_TYPER, 8) & TYPER_LAST, 0);
        let t = v.redist_read(1, GICR_TYPER, 8);
        assert_ne!(t & TYPER_LAST, 0);
        assert_eq!(t >> 32, arm::mpidr_aff(1));
        assert_eq!((t >> 8) & 0xffff, 1, "processor number");
        // Waking it, as the driver does.
        assert_ne!(v.redist_read(0, GICR_WAKER, 4) & WAKER_CHILDREN_ASLEEP as u64, 0);
        v.redist_write(0, 0, GICR_WAKER, 4, 0, &mut |_| {});
        assert_eq!(v.redist_read(0, GICR_WAKER, 4), 0);
    }

    #[test]
    fn level_spi_through_a_list_register() {
        let v = Vgic::new(true, 2);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        enable_spi(&v, SPI);
        assert_eq!(v.set_spi_line(SPI, true), Some(0));
        assert_eq!(v.set_spi_line(SPI, true), None, "no new edge");
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0xffff_ffff, SPI as u64);
        assert_ne!(r[LR] & LR3_PENDING, 0);
        assert_ne!(r[LR] & LR3_EOI, 0, "level: a maintenance interrupt at EOI");
        assert_ne!(r[LR] & LR3_GROUP1, 0);
        assert!(c.in_use());
        // The guest took it, and ended it, with the line still high: again.
        r[LR] &= !(LR3_PENDING | LR3_ACTIVE);
        c.sync(&v, &mut r);
        assert!(!c.in_use());
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0xffff_ffff, SPI as u64, "the line is still high");
        // The line falls before the guest takes it: withdrawn.
        v.set_spi_line(SPI, false);
        c.sync(&v, &mut r);
        assert_eq!(r[LR], 0);
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0);
    }

    #[test]
    fn edge_while_active_pends_in_its_list_register() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & LR3_EOI, 0, "edge: no maintenance interrupt");
        // The guest acknowledged it, and another edge comes.
        r[LR] = (r[LR] & !LR3_PENDING) | LR3_ACTIVE;
        c.sync(&v, &mut r);
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & (LR3_PENDING | LR3_ACTIVE), LR3_PENDING | LR3_ACTIVE);
        assert_ne!(v.dist_read(0, GICD_ISPENDR + 4, 4) & bit(SPI) as u64, 0, "pending in its LR");
        assert!(!latched(&v, SPI), "moved there");
        assert_eq!(r[LR + 1], 0, "one list register");
    }

    #[test]
    fn priority_and_underflow() {
        let v = Vgic::new(true, 1);
        // Two list registers, three interrupts.
        let mut c = Cpu::new(0, true, 1);
        let mut r = [0u64; 64];
        on(&v);
        for (id, p) in [(40u32, 0x80u64), (41, 0x20), (42, 0x40)] {
            edge_spi(&v, id);
            enable_spi(&v, id);
            v.dist_write(0, GICD_IPRIORITYR + id as u64, 1, p, &mut |_| {});
            v.raise_spi(id);
        }
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, 41, "the most urgent first");
        assert_eq!(r[LR + 1] & 0x3ff, 42);
        assert_eq!((r[LR] >> 48) & 0xff, 0x20);
        assert_ne!(r[reg::VGIC_HCR] & HCR_UIE, 0, "one is left");
        // Both end: the third goes in, and no more underflow.
        r[LR] = 0;
        r[LR + 1] = 0;
        c.sync(&v, &mut r);
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, 40);
        assert_eq!(r[reg::VGIC_HCR] & HCR_UIE, 0);
    }

    #[test]
    fn disabled_or_elsewhere_is_not_delivered() {
        let v = Vgic::new(true, 2);
        let (mut c0, mut c1) = (Cpu::new(0, true, 3), Cpu::new(1, true, 3));
        let (mut r0, mut r1) = ([0u64; 64], [0u64; 64]);
        on(&v);
        edge_spi(&v, SPI);
        v.raise_spi(SPI);
        c0.flush(&v, &mut r0);
        assert_eq!(r0[LR], 0, "not enabled");
        enable_spi(&v, SPI);
        route3(&v, SPI, 1);
        assert_eq!(v.spi_target(SPI), Some(1));
        c0.flush(&v, &mut r0);
        assert_eq!(r0[LR], 0, "routed to vCPU 1");
        assert!(!c0.pending(&v, &r0));
        assert!(c1.pending(&v, &r1));
        c1.flush(&v, &mut r1);
        assert_eq!(r1[LR] & 0x3ff, SPI as u64);
        assert!(c1.pending(&v, &r1), "in its list register, not taken");
    }

    #[test]
    fn sgis_by_system_register() {
        let v = Vgic::new(true, 18);
        v.redist_write(17, 17, GICR_SGI + GICD_ISENABLER, 4, 0xffff, &mut |_| {});
        on(&v);
        let mut woken = Vec::new();
        // vCPU 17 is Aff1 1, Aff0 1.
        v.sgi1r(0, 3 << 24 | 1 << 16 | 1 << 1, &mut |c| woken.push(c));
        assert_eq!(woken, [17]);
        let mut c = Cpu::new(17, true, 3);
        let mut r = [0u64; 64];
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0xffff_ffff, 3);
        assert_eq!(r[LR] & LR3_EOI, 0, "an SGI is an edge");
        // IRM: all but the sender.
        let mut woken = Vec::new();
        v.sgi1r(2, 1 << 40 | 5 << 24, &mut |c| woken.push(c));
        assert_eq!(woken.len(), 17);
        assert!(!woken.contains(&2));
        // An affinity nobody has.
        let mut woken = Vec::new();
        v.sgi1r(0, 7 << 16 | 1, &mut |c| woken.push(c));
        v.sgi1r(0, 1 << 32 | 1, &mut |c| woken.push(c));
        assert!(woken.is_empty());
    }

    #[test]
    fn mbi() {
        let v = Vgic::new(true, 1);
        on(&v);
        let t = v.dist_read(0, GICD_TYPER, 4) as u32;
        assert_ne!(t & TYPER_MBIS, 0);
        edge_spi(&v, MSI_BASE);
        enable_spi(&v, MSI_BASE);
        let doorbell = arm::GICD_BASE + GICD_SETSPI_NSR;
        assert_eq!(v.msi(doorbell, MSI_BASE), Some(0));
        assert_eq!(v.msi(doorbell + 8, MSI_BASE), None, "not the doorbell");
        assert_eq!(v.msi(doorbell, 33), None, "not an MSI's SPI");
        assert_eq!(v.msi(doorbell, NR_IRQS), None);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0xffff_ffff, MSI_BASE as u64);
        // The register itself, as a guest could write it, and clearing.
        v.dist_write(0, GICD_SETSPI_NSR, 4, MSI_BASE as u64 + 1, &mut |_| {});
        assert_ne!(v.dist_read(0, GICD_ISPENDR + 4 * (MSI_BASE as u64 / 32), 4) & 2, 0);
        v.dist_write(0, GICD_CLRSPI_NSR, 4, MSI_BASE as u64 + 1, &mut |_| {});
        assert_eq!(v.dist_read(0, GICD_ISPENDR + 4 * (MSI_BASE as u64 / 32), 4) & 2, 0);
    }

    #[test]
    fn gicv2_targets_sgir_and_v2m() {
        let v = Vgic::new(false, 2);
        v.dist_write(0, GICD_CTLR, 4, 1, &mut |_| {});
        // A byte of ITARGETSR picks vCPU 1; its own banked bytes read back.
        v.dist_write(0, GICD_ITARGETSR + SPI as u64, 1, 2, &mut |_| {});
        assert_eq!(v.spi_target(SPI), Some(1));
        assert_eq!(v.dist_read(0, GICD_ITARGETSR + SPI as u64, 1), 2);
        assert_eq!(v.dist_read(1, GICD_ITARGETSR, 1), 2, "banked: its own CPU");
        // SGI 2 from vCPU 0 to vCPU 1.
        v.dist_write(1, GICD_ISENABLER, 4, 0xffff, &mut |_| {});
        let mut woken = Vec::new();
        v.dist_write(0, GICD_SGIR, 4, 2 << 16 | 2, &mut |c| woken.push(c));
        assert_eq!(woken, [1]);
        let mut c = Cpu::new(1, false, 3);
        let mut r = [0u64; 64];
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, 2);
        assert_eq!((r[LR] >> 10) & 7, 0, "from CPU 0");
        assert_ne!(r[LR] & LR2_PENDING, 0);
        assert_eq!(r[LR] & (1 << 30), 0, "Group 0");
        assert_eq!(r[LR] & LR2_EOI, 0);
        // GICv2m: the range, and a doorbell write.
        let t = v.v2m_read(V2M_TYPER, 4);
        assert_eq!((t >> 16) as u32, MSI_BASE);
        assert_eq!(t as u32 & 0x3ff, MSI_COUNT);
        edge_spi(&v, MSI_BASE);
        v.dist_write(0, GICD_ISENABLER + 4 * (MSI_BASE as u64 / 32), 4, bit(MSI_BASE) as u64, &mut |_| {});
        assert_eq!(v.msi(arm::V2M_BASE + V2M_SETSPI, MSI_BASE), None, "no CPU targeted yet");
        v.dist_write(0, GICD_ITARGETSR + MSI_BASE as u64, 1, 1, &mut |_| {});
        assert_eq!(v.msi(arm::V2M_BASE + V2M_SETSPI, MSI_BASE), Some(0));
        assert_eq!(v.msi(arm::GICD_BASE + GICD_SETSPI_NSR, MSI_BASE), None, "GICv3's doorbell");
        assert_eq!(v.v2m_write(V2M_SETSPI, 33), None);
        // A level LR, with GICv2's priority bits.
        let mut c0 = Cpu::new(0, false, 3);
        let mut r0 = [0u64; 64];
        v.dist_write(0, GICD_ITARGETSR + 50, 1, 1, &mut |_| {});
        v.dist_write(0, GICD_IPRIORITYR + 50, 1, 0x48, &mut |_| {});
        enable_spi(&v, 50);
        v.set_spi_line(50, true);
        c0.flush(&v, &mut r0);
        let lr = (0..4).map(|i| r0[LR + i]).find(|l| l & 0x3ff == 50).expect("in a list register");
        assert_ne!(lr & LR2_EOI, 0);
        assert_eq!((lr >> 23) & 0x1f, 0x48 >> 3);
    }

    #[test]
    fn gicv2_sgi_sources_are_kept_apart() {
        let v = Vgic::new(false, 3);
        v.dist_write(0, GICD_CTLR, 4, 1, &mut |_| {});
        v.dist_write(2, GICD_ISENABLER, 4, 0xffff, &mut |_| {});
        v.send_sgi(0, 2, 1, &mut |_| {});
        v.send_sgi(1, 2, 1, &mut |_| {});
        let mut c = Cpu::new(2, false, 3);
        let mut r = [0u64; 64];
        c.flush(&v, &mut r);
        assert_eq!((r[LR] >> 10) & 7, 0);
        assert_eq!(r[LR + 1], 0, "one at a time");
        r[LR] = 0;
        c.sync(&v, &mut r);
        c.flush(&v, &mut r);
        assert_eq!((r[LR] >> 10) & 7, 1, "the other source");
        r[LR] = 0;
        c.sync(&v, &mut r);
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0, "both done");
    }

    #[test]
    fn gicv2_second_source_comes_back_at_eoi() {
        let v = Vgic::new(false, 3);
        v.dist_write(0, GICD_CTLR, 4, 1, &mut |_| {});
        v.dist_write(2, GICD_ISENABLER, 4, 0xffff, &mut |_| {});
        v.send_sgi(0, 2, 1, &mut |_| {});
        let mut c = Cpu::new(2, false, 3);
        let mut r = [0u64; 64];
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & LR2_EOI, 0, "one source: an edge");
        // Another CPU sends it while the guest holds the first.
        v.send_sgi(1, 2, 1, &mut |_| {});
        c.flush(&v, &mut r);
        assert_ne!(r[LR] & LR2_EOI, 0, "its EOI brings the thread back");
        assert_eq!(r[LR + 1], 0);
    }

    #[test]
    fn a_software_pended_level_interrupt_stays() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        enable_spi(&v, SPI);
        v.dist_write(0, GICD_ISPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, SPI as u64);
        // Its line is low, and that does not take it back.
        c.sync(&v, &mut r);
        assert_ne!(r[LR] & LR3_PENDING, 0);
        r[LR] = 0;
        c.sync(&v, &mut r);
        assert!(!c.in_use());
        // The register is free for one that does follow its line.
        v.set_spi_line(SPI, true);
        c.flush(&v, &mut r);
        v.set_spi_line(SPI, false);
        c.sync(&v, &mut r);
        assert_eq!(r[LR], 0, "withdrawn");
    }

    #[test]
    fn an_spi_moved_while_held_is_not_injected_twice() {
        let v = Vgic::new(true, 2);
        let (mut c0, mut c1) = (Cpu::new(0, true, 3), Cpu::new(1, true, 3));
        let (mut r0, mut r1) = ([0u64; 64], [0u64; 64]);
        on(&v);
        enable_spi(&v, SPI);
        v.set_spi_line(SPI, true);
        c0.flush(&v, &mut r0);
        assert_eq!(r0[LR] & 0x3ff, SPI as u64);
        // The guest took it on vCPU 0, and moves it to vCPU 1.
        r0[LR] = (r0[LR] & !LR3_PENDING) | LR3_ACTIVE;
        assert_eq!(c0.sync(&v, &mut r0), 0);
        route3(&v, SPI, 1);
        c1.flush(&v, &mut r1);
        assert_eq!(r1[LR], 0, "still in vCPU 0's list register");
        assert!(!c1.pending(&v, &r1));
        // vCPU 0 ends it with the line still high: vCPU 1 takes over.
        r0[LR] = 0;
        assert_eq!(c0.sync(&v, &mut r0), 1 << 1, "vCPU 1 is told");
        c1.flush(&v, &mut r1);
        assert_eq!(r1[LR] & 0x3ff, SPI as u64);
        // Reset gives up what it held too.
        r1[LR] = (r1[LR] & !LR3_PENDING) | LR3_ACTIVE;
        c1.sync(&v, &mut r1);
        route3(&v, SPI, 0);
        c0.flush(&v, &mut r0);
        assert_eq!(r0[LR], 0);
        assert_eq!(c1.reset(&v, &mut r1), 1 << 0);
        assert!(!c1.in_use());
        c0.flush(&v, &mut r0);
        assert_eq!(r0[LR] & 0x3ff, SPI as u64);
    }

    fn pending_of(v: &Vgic, id: u32) -> bool {
        v.dist_read(0, GICD_ISPENDR + 4 * (id as u64 / 32), 4) & bit(id) as u64 != 0
    }

    fn active_of(v: &Vgic, id: u32) -> bool {
        v.dist_read(0, GICD_ISACTIVER + 4 * (id as u64 / 32), 4) & bit(id) as u64 != 0
    }

    #[test]
    fn icpendr_withdraws_what_the_guest_has_not_taken() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        assert_ne!(r[LR] & LR3_PENDING, 0);
        assert!(pending_of(&v, SPI), "in a list register, it reads pending");
        let mut woken = Vec::new();
        v.dist_write(0, GICD_ICPENDR + 4, 4, bit(SPI) as u64, &mut |c| woken.push(c));
        assert_eq!(woken, [0], "its holder is told");
        assert!(!pending_of(&v, SPI), "at once");
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0, "withdrawn");
        assert!(!c.in_use());
        assert!(!pending_of(&v, SPI));
        // CLRSPI does the same.
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        v.dist_write(0, GICD_CLRSPI_NSR, 4, SPI as u64, &mut |_| {});
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0);
    }

    #[test]
    fn isactiver_sees_what_the_guest_took() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        assert!(!active_of(&v, SPI));
        // Acknowledged, not ended.
        r[LR] = (r[LR] & !LR3_PENDING) | LR3_ACTIVE;
        c.sync(&v, &mut r);
        assert!(active_of(&v, SPI));
        assert!(!pending_of(&v, SPI));
        // ICACTIVER ends it there.
        v.dist_write(0, GICD_ICACTIVER + 4, 4, bit(SPI) as u64, &mut |_| {});
        assert!(!active_of(&v, SPI));
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0);
        assert!(!c.in_use());
    }

    #[test]
    fn software_active_holds_delivery_back() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.dist_write(0, GICD_ISACTIVER + 4, 4, bit(SPI) as u64, &mut |_| {});
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0, "active: not delivered");
        assert!(pending_of(&v, SPI) && active_of(&v, SPI));
        let mut woken = Vec::new();
        v.dist_write(0, GICD_ICACTIVER + 4, 4, bit(SPI) as u64, &mut |c| woken.push(c));
        assert!(woken.contains(&0));
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, SPI as u64);
    }

    #[test]
    fn an_edge_does_not_pend_a_disabled_list_register() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        r[LR] = (r[LR] & !LR3_PENDING) | LR3_ACTIVE;
        c.sync(&v, &mut r);
        v.dist_write(0, GICD_ICENABLER + 4, 4, bit(SPI) as u64, &mut |_| {});
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & LR3_PENDING, 0, "held in the distributor");
        assert!(pending_of(&v, SPI));
        r[LR] &= !LR3_ACTIVE;
        c.sync(&v, &mut r);
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0);
        enable_spi(&v, SPI);
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, SPI as u64);
    }

    #[test]
    fn software_active_takes_back_what_was_not_taken() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        let mut woken = Vec::new();
        v.dist_write(0, GICD_ISACTIVER + 4, 4, bit(SPI) as u64, &mut |c| woken.push(c));
        assert_eq!(woken, [0]);
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0);
        assert!(pending_of(&v, SPI) && active_of(&v, SPI));
        v.dist_write(0, GICD_ICACTIVER + 4, 4, bit(SPI) as u64, &mut |_| {});
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, SPI as u64);
    }

    #[test]
    fn disabling_takes_back_what_was_not_taken() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        let mut woken = Vec::new();
        v.dist_write(0, GICD_ICENABLER + 4, 4, bit(SPI) as u64, &mut |c| woken.push(c));
        assert_eq!(woken, [0]);
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0);
        assert!(pending_of(&v, SPI), "still pending");
        enable_spi(&v, SPI);
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, SPI as u64, "delivered once enabled");
    }

    #[test]
    fn gicv2_two_sources_at_once() {
        let v = Vgic::new(false, 3);
        v.dist_write(0, GICD_CTLR, 4, 1, &mut |_| {});
        v.dist_write(2, GICD_ISENABLER, 4, 0xffff, &mut |_| {});
        v.send_sgi(0, 2, 1, &mut |_| {});
        v.send_sgi(1, 2, 1, &mut |_| {});
        let mut c = Cpu::new(2, false, 3);
        let mut r = [0u64; 64];
        c.flush(&v, &mut r);
        assert_eq!((r[LR] >> 10) & 7, 0);
        assert_ne!(r[LR] & LR2_EOI, 0, "the second source: its EOI brings us back");
        // The guest ends it: state gone, EOI still set, as FL4 hands it back.
        r[LR] &= !(LR2_PENDING | LR2_ACTIVE);
        c.sync(&v, &mut r);
        c.flush(&v, &mut r);
        assert_eq!((r[LR] >> 10) & 7, 1, "the other source");
        assert_eq!(r[LR] & LR2_EOI, 0, "the last");
    }

    #[test]
    fn gicv2_sgi_pending_registers() {
        let v = Vgic::new(false, 3);
        v.dist_write(0, GICD_CTLR, 4, 1, &mut |_| {});
        v.dist_write(1, GICD_ISENABLER, 4, 0xffff, &mut |_| {});
        // GICD_ISPENDR0 and ICPENDR0 do not reach SGIs.
        v.dist_write(1, GICD_ISPENDR, 4, 1 << 3, &mut |_| {});
        assert_eq!(v.dist_read(1, GICD_ISPENDR, 4) & (1 << 3), 0);
        v.send_sgi(0, 1, 3, &mut |_| {});
        v.dist_write(1, GICD_ICPENDR, 4, 1 << 3, &mut |_| {});
        assert_ne!(v.dist_read(1, GICD_ISPENDR, 4) & (1 << 3), 0);
        // Their own registers do, by source.
        assert_eq!(v.dist_read(1, GICD_SPENDSGIR + 3, 1), 1);
        v.dist_write(1, GICD_SPENDSGIR + 3, 1, 4, &mut |_| {});
        assert_eq!(v.dist_read(1, GICD_CPENDSGIR + 3, 1), 5);
        v.dist_write(1, GICD_CPENDSGIR + 3, 1, 5, &mut |_| {});
        assert_eq!(v.dist_read(1, GICD_ISPENDR, 4) & (1 << 3), 0);
        // In a list register, its source can be withdrawn too.
        v.send_sgi(2, 1, 3, &mut |_| {});
        let mut c = Cpu::new(1, false, 3);
        let mut r = [0u64; 64];
        c.flush(&v, &mut r);
        assert_eq!((r[LR] >> 10) & 7, 2);
        assert_eq!(v.dist_read(1, GICD_SPENDSGIR + 3, 1), 4);
        v.dist_write(1, GICD_CPENDSGIR + 3, 1, 4, &mut |_| {});
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0);
    }

    #[test]
    fn a_pending_spi_moves_with_its_route() {
        let v = Vgic::new(true, 2);
        let (mut c0, mut c1) = (Cpu::new(0, true, 3), Cpu::new(1, true, 3));
        let (mut r0, mut r1) = ([0u64; 64], [0u64; 64]);
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        c0.flush(&v, &mut r0);
        assert_ne!(r0[LR] & LR3_PENDING, 0);
        // Moved before the guest took it: vCPU 0 is told, and gives it up.
        let mut woken = Vec::new();
        v.dist_write(0, GICD_IROUTER + 8 * SPI as u64, 8, 1, &mut |c| woken.push(c));
        assert!(woken.contains(&0) && woken.contains(&1));
        c1.flush(&v, &mut r1);
        assert_eq!(r1[LR], 0, "vCPU 0 still has it");
        assert_eq!(c0.flush(&v, &mut r0), 1 << 1, "vCPU 1 is told");
        assert_eq!(r0[LR], 0);
        c1.flush(&v, &mut r1);
        assert_eq!(r1[LR] & 0x3ff, SPI as u64, "not lost");
    }

    #[test]
    fn an_active_spi_finishes_where_it_is() {
        let v = Vgic::new(true, 2);
        let (mut c0, mut c1) = (Cpu::new(0, true, 3), Cpu::new(1, true, 3));
        let (mut r0, mut r1) = ([0u64; 64], [0u64; 64]);
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        c0.flush(&v, &mut r0);
        assert_eq!(r0[LR] & LR3_EOI, 0);
        r0[LR] = (r0[LR] & !LR3_PENDING) | LR3_ACTIVE;
        c0.sync(&v, &mut r0);
        route3(&v, SPI, 1);
        // A new edge belongs to the new vCPU, not this list register.
        v.raise_spi(SPI);
        c0.flush(&v, &mut r0);
        assert_eq!(r0[LR] & LR3_PENDING, 0);
        assert_ne!(r0[LR] & LR3_ACTIVE, 0);
        assert_ne!(r0[LR] & LR3_EOI, 0, "its EOI brings vCPU 0 back");
        c1.flush(&v, &mut r1);
        assert_eq!(r1[LR], 0, "not while vCPU 0 has it");
        r0[LR] &= !LR3_ACTIVE;
        assert_eq!(c0.sync(&v, &mut r0), 1 << 1);
        c1.flush(&v, &mut r1);
        assert_eq!(r1[LR] & 0x3ff, SPI as u64);
    }

    #[test]
    fn gicv2_no_target_is_no_delivery() {
        let v = Vgic::new(false, 2);
        let mut c = Cpu::new(0, false, 3);
        let mut c1 = Cpu::new(1, false, 3);
        let (mut r, mut r1) = ([0u64; 64], [0u64; 64]);
        v.dist_write(0, GICD_CTLR, 4, 1, &mut |_| {});
        enable_spi(&v, SPI);
        v.dist_write(0, GICD_ITARGETSR + SPI as u64, 1, 1, &mut |_| {});
        assert_eq!(v.spi_target(SPI), Some(0));
        v.dist_write(0, GICD_ITARGETSR + SPI as u64, 1, 0, &mut |_| {});
        assert_eq!(v.spi_target(SPI), None);
        assert_eq!(v.set_spi_line(SPI, true), None, "nobody to tell");
        c.flush(&v, &mut r);
        c1.flush(&v, &mut r1);
        assert_eq!((r[LR], r1[LR]), (0, 0));
        // A mask of CPUs that do not exist is none either.
        v.dist_write(0, GICD_ITARGETSR + SPI as u64, 1, 0xfc, &mut |_| {});
        assert_eq!(v.spi_target(SPI), None);
        assert_eq!(v.dist_read(0, GICD_ITARGETSR + SPI as u64, 1), 0);
    }

    #[test]
    fn a_more_urgent_interrupt_takes_a_list_register() {
        for v3 in [true, false] {
            let v = Vgic::new(v3, 1);
            let mut c = Cpu::new(0, v3, 1);
            let mut r = [0u64; 64];
            v.dist_write(0, GICD_CTLR, 4, CTLR_V3_G1A as u64 | 1, &mut |_| {});
            if !v3 {
                for id in [40, 41, 42] {
                    v.dist_write(0, GICD_ITARGETSR + id, 1, 1, &mut |_| {});
                }
            }
            for (id, p) in [(40u32, 0xc0u64), (41, 0xe0)] {
                edge_spi(&v, id);
                enable_spi(&v, id);
                v.dist_write(0, GICD_IPRIORITYR + id as u64, 1, p, &mut |_| {});
                v.raise_spi(id);
            }
            c.flush(&v, &mut r);
            assert_eq!((r[LR] & 0x3ff, r[LR + 1] & 0x3ff), (40, 41));
            // Both still pending (as if the guest's PMR masked them).
            edge_spi(&v, 42);
            enable_spi(&v, 42);
            v.dist_write(0, GICD_IPRIORITYR + 42, 1, 0x20, &mut |_| {});
            v.raise_spi(42);
            c.flush(&v, &mut r);
            let ids = [r[LR] & 0x3ff, r[LR + 1] & 0x3ff];
            assert!(ids.contains(&42), "the urgent one is in: {ids:?}");
            assert!(ids.contains(&40), "and the less urgent of the two stays");
            assert_ne!(r[reg::VGIC_HCR] & HCR_UIE, 0, "one waits");
            assert!(pending_of(&v, 41), "the one taken out is not lost");
            // It comes back when there is room.
            let slot = (0..2).find(|&i| r[LR + i] & 0x3ff == 42).unwrap();
            r[LR + slot] = 0;
            c.sync(&v, &mut r);
            c.flush(&v, &mut r);
            assert!((0..2).any(|i| r[LR + i] & 0x3ff == 41));
        }
    }

    #[test]
    fn taking_a_list_register_keeps_the_sgi_source() {
        let v = Vgic::new(false, 3);
        let mut c = Cpu::new(0, false, 0);
        let mut r = [0u64; 64];
        v.dist_write(0, GICD_CTLR, 4, 1, &mut |_| {});
        v.dist_write(0, GICD_ISENABLER, 4, 0xffff, &mut |_| {});
        v.dist_write(0, GICD_IPRIORITYR + 4, 1, 0xe0, &mut |_| {});
        v.dist_write(0, GICD_IPRIORITYR + 5, 1, 0x20, &mut |_| {});
        v.send_sgi(2, 0, 4, &mut |_| {});
        c.flush(&v, &mut r);
        assert_eq!((r[LR] & 0x3ff, (r[LR] >> 10) & 7), (4, 2));
        v.send_sgi(1, 0, 5, &mut |_| {});
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, 5, "the urgent SGI");
        assert_eq!(v.dist_read(0, GICD_SPENDSGIR + 4, 1), 1 << 2, "SGI 4 still from CPU 2");
        r[LR] = 0;
        c.sync(&v, &mut r);
        c.flush(&v, &mut r);
        assert_eq!((r[LR] & 0x3ff, (r[LR] >> 10) & 7), (4, 2));
    }

    #[test]
    fn a_remote_write_keeps_the_owner_out_of_its_guest() {
        let v = Vgic::new(true, 2);
        let mut c0 = Cpu::new(0, true, 3);
        let mut r0 = [0u64; 64];
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        assert!(c0.enter(&v, &mut r0, false).1);
        // Its guest acknowledges it; nothing has exited yet.
        r0[LR] = (r0[LR] & !LR3_PENDING) | LR3_ACTIVE;
        let mut exits = 0;
        v.dist_write(1, GICD_ISACTIVER + 4, 4, bit(SPI) as u64, &mut |t| {
            if t == 0 && exits == 0 {
                exits += 1;
                c0.left(&v, &mut r0, true);
                assert!(c0.try_enter(&v, &mut r0, false).is_none(), "kept out until the write is done");
            }
        });
        assert_eq!(exits, 1, "made to exit");
        assert_eq!(v.state.lock().spi[1].active & bit(SPI), 0, "the guest has it: no software state");
        assert!(active_of(&v, SPI));
        assert!(!pending_of(&v, SPI));
        // Free to go in again, and its EOI ends it for good.
        assert!(c0.enter(&v, &mut r0, false).1);
        r0[LR] = 0;
        c0.left(&v, &mut r0, true);
        assert!(!active_of(&v, SPI));
        v.raise_spi(SPI);
        c0.flush(&v, &mut r0);
        assert_eq!(r0[LR] & 0x3ff, SPI as u64, "the next one is delivered");
    }

    #[test]
    fn a_remote_read_sees_what_the_guest_took() {
        let v = Vgic::new(true, 2);
        let mut c0 = Cpu::new(0, true, 3);
        let mut r0 = [0u64; 64];
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        assert!(c0.enter(&v, &mut r0, false).1);
        r0[LR] = (r0[LR] & !LR3_PENDING) | LR3_ACTIVE;
        let mut woken = Vec::new();
        let got = v.dist_read_for(1, GICD_ISACTIVER + 4, 4, &mut |t| {
            woken.push(t);
            c0.left(&v, &mut r0, true);
        });
        assert_eq!(woken, [0]);
        assert_ne!(got & bit(SPI) as u64, 0, "vCPU 1 reads it active");
        // ICACTIVER, with it running again: the request is not lost.
        assert!(c0.enter(&v, &mut r0, false).1);
        let mut exits = 0;
        v.dist_write(1, GICD_ICACTIVER + 4, 4, bit(SPI) as u64, &mut |t| {
            if t == 0 && exits == 0 {
                exits += 1;
                c0.left(&v, &mut r0, true);
            }
        });
        assert!(!active_of(&v, SPI));
        c0.flush(&v, &mut r0);
        assert_eq!(r0[LR], 0, "ended");
        assert!(!c0.in_use());
    }

    #[test]
    fn vcpus_pausing_each_other_do_not_deadlock() {
        let v = Vgic::new(true, 4);
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        std::thread::scope(|s| {
            for me in 0..4 {
                let v = &v;
                s.spawn(move || {
                    let mut c = Cpu::new(me, true, 3);
                    let mut r = [0u64; 64];
                    for _ in 0..500 {
                        v.raise_spi(SPI);
                        assert!(c.enter(v, &mut r, false).1);
                        c.left(v, &mut r, true);
                        v.dist_read_for(me, GICD_ISACTIVER + 4, 4, &mut |_| {});
                        v.dist_write(me, GICD_ISPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
                        v.dist_write(me, GICD_ICPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
                    }
                });
            }
        });
        let st = v.state.lock();
        assert!(st.local[..4].iter().all(|l| l.pause == 0 && !l.in_guest));
    }

    #[test]
    fn isactiver_on_what_the_guest_has_active_is_idempotent() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        r[LR] = (r[LR] & !LR3_PENDING) | LR3_ACTIVE;
        c.sync(&v, &mut r);
        v.dist_write(0, GICD_ISACTIVER + 4, 4, bit(SPI) as u64, &mut |_| {});
        assert_eq!(v.state.lock().spi[1].active & bit(SPI), 0, "no software state to outlive the EOI");
        assert!(active_of(&v, SPI));
        r[LR] = 0;
        c.sync(&v, &mut r);
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, SPI as u64, "the next one is delivered");
    }

    #[test]
    fn an_edge_after_icpendr_is_a_new_one() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        // Raised and cleared, before any vCPU looked.
        v.raise_spi(SPI);
        v.dist_write(0, GICD_ICPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0, "the edge before the clear is gone");
        // From a list register, with a new edge before its vCPU looks.
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        v.dist_write(0, GICD_ICPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        v.raise_spi(SPI);
        assert!(pending_of(&v, SPI), "the new edge");
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, SPI as u64);
        assert_ne!(r[LR] & LR3_PENDING, 0, "delivered, not eaten by the clear");
    }

    #[test]
    fn a_cleared_edge_does_not_come_back_with_its_list_register() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        c.flush(&v, &mut r);
        // Cleared, then disabled: the list register would go back pending.
        v.dist_write(0, GICD_ICPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        v.dist_write(0, GICD_ICENABLER + 4, 4, bit(SPI) as u64, &mut |_| {});
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0);
        assert!(!latched(&v, SPI), "not revived");
        assert!(!pending_of(&v, SPI));
        enable_spi(&v, SPI);
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0, "nothing to deliver");
    }

    #[test]
    fn going_into_a_list_register_it_stays_pending() {
        let v = Vgic::new(true, 2);
        let (mut c0, mut c1) = (Cpu::new(0, true, 3), Cpu::new(1, true, 3));
        let (mut r0, mut r1) = ([0u64; 64], [0u64; 64]);
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        assert!(pending_of(&v, SPI), "raised");
        c0.flush(&v, &mut r0);
        assert!(!latched(&v, SPI));
        assert!(pending_of(&v, SPI), "in its list register, before any IAR");
        // Given up to another vCPU, it is pending all the way.
        route3(&v, SPI, 1);
        assert!(pending_of(&v, SPI));
        c0.flush(&v, &mut r0);
        assert!(pending_of(&v, SPI), "back in the distributor");
        c1.flush(&v, &mut r1);
        assert!(pending_of(&v, SPI), "in the other's");
        assert_eq!(r1[LR] & 0x3ff, SPI as u64);
    }

    #[test]
    fn a_level_spi_pended_twice_before_iar_is_delivered_once() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        enable_spi(&v, SPI);
        v.dist_write(0, GICD_ISPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        c.flush(&v, &mut r);
        assert_ne!(r[LR] & LR3_PENDING, 0);
        v.dist_write(0, GICD_ISPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        assert!(!latched(&v, SPI), "still that one delivery");
        c.flush(&v, &mut r);
        r[LR] = (r[LR] & !LR3_PENDING) | LR3_ACTIVE;
        c.sync(&v, &mut r);
        r[LR] = 0;
        c.sync(&v, &mut r);
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0, "once");
        assert!(!pending_of(&v, SPI));
    }

    #[test]
    fn a_level_spi_pended_again_after_iar_is_delivered_again() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        enable_spi(&v, SPI);
        v.dist_write(0, GICD_ISPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        c.flush(&v, &mut r);
        r[LR] = (r[LR] & !LR3_PENDING) | LR3_ACTIVE;
        c.sync(&v, &mut r);
        v.dist_write(0, GICD_ISPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        assert!(latched(&v, SPI));
        r[LR] = 0;
        c.sync(&v, &mut r);
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, SPI as u64, "the second delivery");
        assert_ne!(r[LR] & LR3_PENDING, 0);
    }

    #[test]
    fn software_pending_outlives_a_falling_line_in_a_list_register() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        enable_spi(&v, SPI);
        v.set_spi_line(SPI, true);
        c.flush(&v, &mut r);
        // Pending by its line, and now by software too: not withdrawn.
        v.dist_write(0, GICD_ISPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        v.set_spi_line(SPI, false);
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, SPI as u64);
        assert_ne!(r[LR] & LR3_PENDING, 0);
    }

    #[test]
    fn a_line_falling_as_it_is_loaded_tells_its_new_owner() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        enable_spi(&v, SPI);
        v.set_spi_line(SPI, true);
        let mut told = None;
        c.flush_with(&v, &mut r, |id| {
            if id == SPI && told.is_none() {
                told = Some(v.set_spi_line(SPI, false));
            }
        });
        assert_eq!(told, Some(Some(0)), "the I/O thread sees who to tell");
        assert_eq!(r[LR], 0, "and it is not injected");
        assert!(!c.in_use());
        assert_eq!(v.spi_owner[SPI as usize].load(SeqCst), NO_OWNER);
        assert_eq!(v.state.lock().spi[1].lr_pending & bit(SPI), 0);
    }

    #[test]
    fn software_pending_is_loaded_though_the_line_falls() {
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        enable_spi(&v, SPI);
        v.set_spi_line(SPI, true);
        v.dist_write(0, GICD_ISPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        c.flush_with(&v, &mut r, |id| {
            if id == SPI {
                v.set_spi_line(SPI, false);
            }
        });
        assert_eq!(r[LR] & 0x3ff, SPI as u64);
        assert_ne!(r[LR] & LR3_PENDING, 0);
        assert_eq!(v.spi_owner[SPI as usize].load(SeqCst), 0);
        assert_ne!(v.state.lock().spi[1].lr_latched & bit(SPI), 0);
    }

    /// A level SPI with its line up, at priority `prio`.
    fn level_up(v: &Vgic, id: u32, prio: u64) {
        enable_spi(v, id);
        v.dist_write(0, GICD_IPRIORITYR + id as u64, 1, prio, &mut |_| {});
        v.set_spi_line(id, true);
    }

    #[test]
    fn a_candidate_with_nothing_left_does_not_stop_the_next() {
        const A: u32 = 40;
        const B: u32 = 41;
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        level_up(&v, A, 0x20);
        level_up(&v, B, 0xa0);
        c.flush_with(&v, &mut r, |id| {
            if id == A {
                v.set_spi_line(A, false);
            }
        });
        assert_eq!(r[LR] & 0x3ff, B as u64, "in the same flush");
        assert_eq!(r[LR + 1], 0, "and A in none");
        assert_eq!(v.spi_owner[A as usize].load(SeqCst), NO_OWNER);
        assert_eq!(v.spi_owner[B as usize].load(SeqCst), 0);
    }

    #[test]
    fn a_candidate_that_evicted_and_fell_leaves_the_slot_to_the_next() {
        const A: u32 = 40;
        const B: u32 = 41;
        const C: u32 = 42;
        let v = Vgic::new(true, 1);
        let mut c = Cpu::new(0, true, 0);
        let mut r = [0u64; 64];
        on(&v);
        edge_spi(&v, C);
        enable_spi(&v, C);
        v.dist_write(0, GICD_IPRIORITYR + C as u64, 1, 0xe0, &mut |_| {});
        v.raise_spi(C);
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0x3ff, C as u64);
        level_up(&v, A, 0x20);
        level_up(&v, B, 0x80);
        c.flush_with(&v, &mut r, |id| {
            if id == A {
                v.set_spi_line(A, false);
            }
        });
        assert_eq!(r[LR] & 0x3ff, B as u64, "the next best has the slot");
        assert_eq!(v.spi_owner[A as usize].load(SeqCst), NO_OWNER);
        assert_ne!(r[reg::VGIC_HCR] & HCR_UIE, 0, "C still waits");
        assert!(pending_of(&v, C), "and is not lost");
    }

    #[test]
    fn cpu_off_does_not_revive_what_was_cleared() {
        let v = Vgic::new(true, 2);
        let (mut c0, mut c1) = (Cpu::new(0, true, 3), Cpu::new(1, true, 3));
        let (mut r0, mut r1) = ([0u64; 64], [0u64; 64]);
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        assert!(c0.enter(&v, &mut r0, false).1);
        c0.left(&v, &mut r0, true);
        v.dist_write(1, GICD_ICPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        c0.reset(&v, &mut r0);
        route3(&v, SPI, 1);
        c1.flush(&v, &mut r1);
        assert_eq!(r1[LR], 0, "nothing to deliver");
        assert!(!latched(&v, SPI));
        assert!(!pending_of(&v, SPI));
    }

    #[test]
    fn cpu_off_passes_on_an_edge_after_the_clear() {
        let v = Vgic::new(true, 2);
        let (mut c0, mut c1) = (Cpu::new(0, true, 3), Cpu::new(1, true, 3));
        let (mut r0, mut r1) = ([0u64; 64], [0u64; 64]);
        on(&v);
        edge_spi(&v, SPI);
        enable_spi(&v, SPI);
        v.raise_spi(SPI);
        assert!(c0.enter(&v, &mut r0, false).1);
        c0.left(&v, &mut r0, true);
        v.dist_write(1, GICD_ICPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        v.raise_spi(SPI);
        route3(&v, SPI, 1);
        assert_ne!(c0.reset(&v, &mut r0) & 1 << 1, 0, "vCPU 1 is told");
        c1.flush(&v, &mut r1);
        assert_eq!(r1[LR] & 0x3ff, SPI as u64);
        assert_ne!(r1[LR] & LR3_PENDING, 0);
    }

    #[test]
    fn the_timer_ppi_stays_level_triggered() {
        for gicv3 in [true, false] {
            let v = Vgic::new(gicv3, 1);
            let mut c = Cpu::new(0, gicv3, 3);
            let mut r = [0u64; 64];
            on(&v);
            let cfg = if gicv3 {
                v.redist_write(0, 0, GICR_SGI + GICD_ICFGR + 4, 4, 0xffff_ffff, &mut |_| {});
                v.redist_write(0, 0, GICR_SGI + GICD_ISENABLER, 4, bit(PPI_VTIMER) as u64, &mut |_| {});
                v.redist_read(0, GICR_SGI + GICD_ICFGR + 4, 4)
            } else {
                v.dist_write(0, GICD_ICFGR + 4, 4, 0xffff_ffff, &mut |_| {});
                v.dist_write(0, GICD_ISENABLER, 4, bit(PPI_VTIMER) as u64, &mut |_| {});
                v.dist_read(0, GICD_ICFGR + 4, 4)
            };
            assert_eq!(cfg & 1 << (2 * (PPI_VTIMER - 16) + 1), 0, "level, GICv3: {gicv3}");
            assert_ne!(cfg & 1 << (2 * (26 - 16) + 1), 0, "its neighbours as written");
            v.set_ppi_line(0, PPI_VTIMER, true);
            c.flush(&v, &mut r);
            assert_eq!(r[LR] & 0x3ff, PPI_VTIMER as u64);
        }
    }

    #[test]
    fn irouter_halves_written_at_once_both_land() {
        let v = Vgic::new(true, 2);
        let at = GICD_IROUTER + 8 * SPI as u64;
        const N: u64 = 20_000;
        std::thread::scope(|s| {
            s.spawn(|| (1..=N).for_each(|i| v.dist_write(0, at, 4, i, &mut |_| {})));
            s.spawn(|| (1..=N).for_each(|i| v.dist_write(1, at + 4, 4, i, &mut |_| {})));
        });
        assert_eq!(v.dist_read(0, at, 8), N << 32 | N);
    }

    #[test]
    fn gicv2_same_source_before_iar_is_one_sgi() {
        let v = Vgic::new(false, 3);
        let mut c = Cpu::new(0, false, 3);
        let mut r = [0u64; 64];
        v.dist_write(0, GICD_CTLR, 4, 1, &mut |_| {});
        v.dist_write(0, GICD_ISENABLER, 4, 0xffff, &mut |_| {});
        v.send_sgi(1, 0, 3, &mut |_| {});
        c.flush(&v, &mut r);
        assert_eq!((r[LR] & 0x3ff, (r[LR] >> 10) & 7), (3, 1));
        // Again from that CPU, and by GICD_SPENDSGIR: still pending, once.
        v.dist_write(1, GICD_SGIR, 4, 1 << 16 | 3, &mut |_| {});
        v.dist_write(0, GICD_SPENDSGIR + 3, 1, 1 << 1, &mut |_| {});
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & LR2_EOI, 0, "nothing more to come");
        r[LR] = 0;
        c.sync(&v, &mut r);
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0, "delivered once");
        assert_eq!(v.dist_read(0, GICD_SPENDSGIR + 3, 1), 0);
    }

    #[test]
    fn gicv2_same_source_after_iar_is_pending_and_active() {
        let v = Vgic::new(false, 3);
        let mut c = Cpu::new(0, false, 3);
        let mut r = [0u64; 64];
        v.dist_write(0, GICD_CTLR, 4, 1, &mut |_| {});
        v.dist_write(0, GICD_ISENABLER, 4, 0xffff, &mut |_| {});
        v.send_sgi(1, 0, 3, &mut |_| {});
        c.flush(&v, &mut r);
        r[LR] = (r[LR] & !LR2_PENDING) | LR2_ACTIVE;
        c.sync(&v, &mut r);
        v.send_sgi(1, 0, 3, &mut |_| {});
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & (LR2_PENDING | LR2_ACTIVE), LR2_PENDING | LR2_ACTIVE);
        assert_eq!(r[LR] & LR2_EOI, 0, "no other source");
        assert_eq!(v.state.lock().local[0].sgi_from[3], 0);
        // Its EOI leaves the second pending.
        r[LR] &= !LR2_ACTIVE;
        c.sync(&v, &mut r);
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & (LR2_PENDING | LR2_ACTIVE), LR2_PENDING);
        assert_eq!((r[LR] >> 10) & 7, 1);
    }

    #[test]
    fn gicv2_another_source_waits_for_the_eoi() {
        let v = Vgic::new(false, 3);
        let mut c = Cpu::new(0, false, 3);
        let mut r = [0u64; 64];
        v.dist_write(0, GICD_CTLR, 4, 1, &mut |_| {});
        v.dist_write(0, GICD_ISENABLER, 4, 0xffff, &mut |_| {});
        v.send_sgi(1, 0, 3, &mut |_| {});
        c.flush(&v, &mut r);
        v.send_sgi(2, 0, 3, &mut |_| {});
        c.flush(&v, &mut r);
        assert_ne!(r[LR] & LR2_EOI, 0);
        assert_eq!((r[LR] >> 10) & 7, 1);
        r[LR] = 0;
        c.sync(&v, &mut r);
        c.flush(&v, &mut r);
        assert_eq!((r[LR] >> 10) & 7, 2);
    }

    #[test]
    fn disabling_the_distributor_takes_back_what_was_not_taken() {
        for v3 in [true, false] {
            let v = Vgic::new(v3, 2);
            let mut c = Cpu::new(0, v3, 3);
            let mut r = [0u64; 64];
            let en = if v3 { CTLR_V3_G1A as u64 } else { 1 };
            v.dist_write(0, GICD_CTLR, 4, en, &mut |_| {});
            if !v3 {
                v.dist_write(0, GICD_ITARGETSR + SPI as u64, 1, 1, &mut |_| {});
            }
            edge_spi(&v, SPI);
            enable_spi(&v, SPI);
            v.raise_spi(SPI);
            c.flush(&v, &mut r);
            assert_eq!(r[LR] & 0x3ff, SPI as u64);
            let mut woken = Vec::new();
            v.dist_write(0, GICD_CTLR, 4, 0, &mut |t| woken.push(t));
            assert_eq!(woken, [0, 1], "every vCPU looks");
            c.flush(&v, &mut r);
            assert_eq!(r[LR], 0, "the guest's IAR would be spurious");
            assert!(pending_of(&v, SPI));
            let mut woken = Vec::new();
            v.dist_write(0, GICD_CTLR, 4, en, &mut |t| woken.push(t));
            assert_eq!(woken, [0, 1]);
            c.flush(&v, &mut r);
            assert_eq!(r[LR] & 0x3ff, SPI as u64, "delivered again");
            // What the guest has active stays, through a disable.
            let pend = if v3 { LR3_PENDING } else { LR2_PENDING };
            let act = if v3 { LR3_ACTIVE } else { LR2_ACTIVE };
            r[LR] = (r[LR] & !pend) | act;
            c.sync(&v, &mut r);
            v.dist_write(0, GICD_CTLR, 4, 0, &mut |_| {});
            c.flush(&v, &mut r);
            assert_ne!(r[LR] & act, 0);
        }
    }

    #[test]
    fn a_falling_line_tells_the_vcpu_that_holds_it() {
        let v = Vgic::new(true, 2);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        on(&v);
        enable_spi(&v, SPI);
        assert_eq!(v.set_spi_line(SPI, true), Some(0));
        assert_eq!(v.set_spi_line(SPI, false), None, "no one holds it");
        v.set_spi_line(SPI, true);
        c.flush(&v, &mut r);
        assert_ne!(r[LR], 0);
        assert_eq!(v.set_spi_line(SPI, false), Some(0), "1 -> 0, held");
        assert_eq!(v.set_spi_line(SPI, false), None, "0 -> 0");
        c.flush(&v, &mut r);
        assert_eq!(r[LR], 0, "withdrawn");
        // Software's pending state does not go with the line.
        v.set_spi_line(SPI, true);
        c.flush(&v, &mut r);
        v.dist_write(0, GICD_ISPENDR + 4, 4, bit(SPI) as u64, &mut |_| {});
        assert_eq!(v.set_spi_line(SPI, false), Some(0), "its holder looks");
        c.flush(&v, &mut r);
        assert_ne!(r[LR] & LR3_PENDING, 0, "still pending by software");
    }

    #[test]
    fn icfgr_halves_do_not_overwrite_each_other() {
        let v = Vgic::new(true, 1);
        v.dist_write(0, GICD_ICFGR + 8, 4, 0x8, &mut |_| {});
        v.dist_write(0, GICD_ICFGR + 12, 4, 0x2, &mut |_| {});
        assert_eq!(v.dist_read(0, GICD_ICFGR + 8, 4), 0x8, "the lower half stays");
        assert_eq!(v.dist_read(0, GICD_ICFGR + 12, 4), 0x2);
    }

    #[test]
    fn ppi_timer_is_level() {
        let v = Vgic::new(true, 1);
        on(&v);
        v.redist_write(0, 0, GICR_SGI + GICD_ISENABLER, 4, bit(PPI_VTIMER) as u64, &mut |_| {});
        v.set_ppi_line(0, PPI_VTIMER, true);
        let mut c = Cpu::new(0, true, 3);
        let mut r = [0u64; 64];
        c.flush(&v, &mut r);
        assert_eq!(r[LR] & 0xffff_ffff, PPI_VTIMER as u64);
        assert_ne!(r[LR] & LR3_EOI, 0);
        v.set_ppi_line(0, PPI_VTIMER, false);
        c.sync(&v, &mut r);
        assert_eq!(r[LR], 0, "withdrawn");
    }

    #[test]
    fn register_widths() {
        let v = Vgic::new(true, 2);
        // IROUTER in two halves.
        v.dist_write(0, GICD_IROUTER + 8 * 40, 4, 1, &mut |_| {});
        v.dist_write(0, GICD_IROUTER + 8 * 40 + 4, 4, 0, &mut |_| {});
        assert_eq!(v.dist_read(0, GICD_IROUTER + 8 * 40, 8), 1);
        assert_eq!(v.spi_target(40), Some(1));
        // IRM: vCPU 0.
        v.dist_write(0, GICD_IROUTER + 8 * 40, 8, 1 << 31, &mut |_| {});
        assert_eq!(v.spi_target(40), Some(0));
        // An affinity no vCPU has: none.
        v.dist_write(0, GICD_IROUTER + 8 * 40, 8, 1 << 16, &mut |_| {});
        assert_eq!(v.spi_target(40), None);
        v.dist_write(0, GICD_IROUTER + 8 * 40, 8, 5, &mut |_| {});
        assert_eq!(v.spi_target(40), None);
        // ICFGR: the edge bit of each.
        v.dist_write(0, GICD_ICFGR + 8, 4, 0x8, &mut |_| {});
        assert_eq!(v.dist_read(0, GICD_ICFGR + 8, 4), 0x8);
        assert!(v.state.lock().is_edge(0, 33));
        // A byte priority; word reads see it.
        v.dist_write(0, GICD_IPRIORITYR + 41, 1, 0x60, &mut |_| {});
        assert_eq!(v.dist_read(0, GICD_IPRIORITYR + 40, 4) >> 8 & 0xff, 0x60);
        assert_eq!(v.dist_read(0, GICD_IPRIORITYR + 41, 1), 0x60);
    }
}
