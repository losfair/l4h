//! A vCPU on AMD-V (hw.rs): the VMCB is seL4's (patch 0040), read 32 words
//! at a time into a copy that lives until the next entry and written a
//! word at a time; the misc1 intercepts and EVENTINJ go in with each
//! VMEnter.  The guest runs with nested paging; CR4 writes always exit (as
//! seL4 keeps them), and CR8 writes, so that our local APIC has the TPR;
//! CR0 and CR3 are the guest's own.  Without vNMI, NMI masking is ours,
//! until the guest's IRET.  Without decode assists (which nested
//! virtualization rarely has), CR and DR exits are decoded (vcpu.rs).

use l4h_rt::sel4;

use super::{Event, Exit, Gprs, Hw, SEL4_ORDER, exits, mr, vmenter, write_gprs};
use crate::x86::decode::{Mode, Seg};
use crate::x86::walk::{self, Paging};

const INTERCEPT_CR: u64 = 0x000;
const INTERCEPT_MISC2: u64 = 0x010;
const TSC_OFFSET: u64 = 0x050;
const INT_CTL: u64 = 0x060;
const INT_STATE: u64 = 0x068;
const EVENT_INJ: u64 = 0x0a8;
const SAVE: u64 = 0x400;
const ES: u64 = SAVE;
const GDTR: u64 = SAVE + 0x060;
const LDTR: u64 = SAVE + 0x070;
const IDTR: u64 = SAVE + 0x080;
const TR: u64 = SAVE + 0x090;
const CPL: u64 = SAVE + 0x0c8;
const EFER: u64 = SAVE + 0x0d0;
const CR4: u64 = SAVE + 0x148;
const CR3: u64 = SAVE + 0x150;
const CR0: u64 = SAVE + 0x158;
const DR7: u64 = SAVE + 0x160;
const DR6: u64 = SAVE + 0x168;
const RFLAGS: u64 = SAVE + 0x170;
const RSP: u64 = SAVE + 0x1d8;
const STAR: u64 = SAVE + 0x200;
const LSTAR: u64 = SAVE + 0x208;
const CSTAR: u64 = SAVE + 0x210;
const SFMASK: u64 = SAVE + 0x218;
const KERNEL_GS_BASE: u64 = SAVE + 0x220;
const SYSENTER_CS: u64 = SAVE + 0x228;
const SYSENTER_ESP: u64 = SAVE + 0x230;
const SYSENTER_EIP: u64 = SAVE + 0x238;
const G_PAT: u64 = SAVE + 0x268;
const END: u64 = SAVE + 0x2e8;
const CHUNK: usize = 32;
const WORDS: usize = (END / 8) as usize;
const CHUNKS: usize = WORDS.div_ceil(CHUNK);

const EFER_SVME: u64 = 1 << 12;
// misc1 intercepts.
const I1_VINTR: u64 = 1 << 4;
const I1_CPUID: u64 = 1 << 18;
const I1_IRET: u64 = 1 << 20;
const I1_HLT: u64 = 1 << 24;
// misc2.
const I2_VMMCALL: u64 = 1 << 1;
const I2_RDTSCP: u64 = 1 << 7;
const CR_WRITE_CR8: u64 = 1 << (16 + 8);
const V_IRQ: u64 = 1 << 8;
const V_INTR_PRIO: u64 = 0xf << 16;
const V_IGN_TPR: u64 = 1 << 20;

const EVT_VALID: u64 = 1 << 31;
const EVT_ERROR: u64 = 1 << 11;
const IF: u64 = 1 << 9;
const DR6_BS: u64 = 1 << 14;

const MSR_FS_BASE: u32 = crate::x86::msr::FS_BASE;
const MSR_GS_BASE: u32 = crate::x86::msr::GS_BASE;

pub struct Svm {
    vcpu: u64,
    gp: Gprs,
    gp_dirty: bool,
    rip: u64,
    rflags: u64,
    int_state: u64,
    len: u64,
    pending: Option<Event>,
    /// The VMCB as seL4 had it since the last entry, by chunks.
    vmcb: [u64; CHUNKS * CHUNK],
    valid: [bool; CHUNKS],
    /// NMIs are blocked from an NMI's delivery until its handler's IRET is
    /// done: after the exit for the IRET, at the next exit with RIP moved.
    nmi_masked: bool,
    iret_rip: Option<u64>,
    tpr: u8,
    /// The event this entry injected, as it was asked for (MR2 keeps only
    /// its low 32 bits: no error code).
    injected: Option<Event>,
    /// Single-stepping for an NMI window.
    step: exits::NmiStep,
    /// INT_CTL as we last wrote it (the CPU does not change it under us:
    /// a VINTR exit comes before the virtual interrupt is taken).
    int_ctl: u64,
}

fn read_chunk(vcpu: u64, first: usize, out: &mut [u64]) {
    let n = out.len();
    let e = sel4::with_ipc_buffer_mut(|b| {
        let r = b.inner_mut().seL4_X86_VCPU_ReadVMCB(vcpu, (first * 8) as u64, n as u64);
        out.copy_from_slice(&b.msg_regs()[..n]);
        r.error
    });
    assert_eq!(e, 0, "ReadVMCB {:#x}", first * 8);
}

fn write_word(vcpu: u64, off: u64, v: u64) -> Option<u64> {
    let r = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_X86_VCPU_WriteVMCB(vcpu, off, v));
    (r.error == 0).then_some(r.written)
}

impl Svm {
    pub fn new(vcpu: u64) -> Self {
        let mut s = Svm {
            vcpu, gp: [0; 16], gp_dirty: true, rip: 0, rflags: 2, int_state: 0, len: 0, pending: None,
            vmcb: [0; CHUNKS * CHUNK], valid: [false; CHUNKS], nmi_masked: false, iret_rip: None, tpr: 0, int_ctl: 0,
            injected: None, step: exits::NmiStep::default(),
        };
        s.int_ctl = s.rd(INT_CTL);
        s.wr(INTERCEPT_MISC2, I2_VMMCALL | I2_RDTSCP);
        s.wr(INTERCEPT_CR, CR_WRITE_CR8);
        s
    }

    fn rd(&mut self, off: u64) -> u64 {
        let w = (off / 8) as usize;
        let c = w / CHUNK;
        if !self.valid[c] {
            let first = c * CHUNK;
            let n = CHUNK.min(WORDS - first);
            read_chunk(self.vcpu, first, &mut self.vmcb[first..first + n]);
            self.valid[c] = true;
        }
        self.vmcb[w]
    }

    fn wr(&mut self, off: u64, v: u64) -> bool {
        match write_word(self.vcpu, off, v) {
            Some(w) => {
                self.vmcb[(off / 8) as usize] = w;
                true
            }
            None => false,
        }
    }

    /// A segment: selector, attributes (SVM's 12 bits), limit, base.
    fn seg(&mut self, at: u64, sel: u64, attrib: u64, limit: u64, base: u64) {
        self.wr(at, sel | (attrib << 16) | (limit << 32));
        self.wr(at + 8, base);
    }

    fn reset_common(&mut self) {
        self.wr(DR7, 0x400);
        self.wr(DR6, 0xffff_0ff0);
        self.wr(G_PAT, crate::x86::msr::PAT_DEFAULT);
        self.wr(SYSENTER_CS, 0);
        self.wr(SYSENTER_ESP, 0);
        self.wr(SYSENTER_EIP, 0);
        self.wr(CPL, 0);
        self.wr(INT_STATE, 0);
        self.int_state = 0;
        self.rflags = 2;
        self.wr(RFLAGS, 2);
        self.gp = [0; 16];
        self.gp_dirty = true;
        self.pending = None;
        self.nmi_masked = false;
        self.iret_rip = None;
    }
}

impl Hw for Svm {
    fn enter(&mut self, ev: Option<Event>, irq_window: bool, nmi_window: bool) -> Exit {
        if self.gp_dirty {
            write_gprs(self.vcpu, &self.gp);
            self.gp_dirty = false;
        }
        // The IRQ window: a virtual interrupt the guest takes, with an exit,
        // as soon as it can (svm_set_vintr()).
        let ctl = self.int_ctl;
        let want = (ctl & !(0xff_u64 << 32 | V_IRQ | V_INTR_PRIO | V_IGN_TPR | 0xf))
            | (self.tpr as u64 >> 4)
            | if irq_window { V_IRQ | V_INTR_PRIO | V_IGN_TPR } else { 0 };
        if want != ctl && self.wr(INT_CTL, want) {
            self.int_ctl = self.vmcb[(INT_CTL / 8) as usize];
        }
        let evt = match ev {
            None => 0,
            Some(Event::Ext(v)) => v as u64 | EVT_VALID,
            Some(Event::Nmi) => {
                self.nmi_masked = true;
                (2 << 8) | EVT_VALID
            }
            Some(Event::Exc(v, e)) => v as u64 | (3 << 8) | EVT_VALID | if e.is_some() { EVT_ERROR } else { 0 },
        };
        if let Some(Event::Exc(_, Some(e))) = ev {
            self.wr(EVENT_INJ, evt | (e as u64) << 32);
        }
        let mut misc1 = I1_CPUID | I1_HLT;
        if irq_window {
            misc1 |= I1_VINTR;
        }
        if self.nmi_masked && self.iret_rip.is_none() {
            misc1 |= I1_IRET;
        }
        // The NMI window (exits::NmiStep).
        if let Some(r) = self.step.arm(nmi_window, ev.is_some(), self.nmi_masked, self.iret_rip.is_some(), self.int_state & 1 != 0, self.rflags) {
            self.wr(RFLAGS, r);
        }
        self.injected = ev;
        let (fault, badge) = vmenter(self.rip, misc1, evt);
        self.valid = [false; CHUNKS];
        self.rip = mr(0);
        let left = mr(2);
        self.rflags = mr(7);
        self.int_state = mr(8);
        for (i, &x) in SEL4_ORDER.iter().enumerate() {
            self.gp[x] = mr(10 + i);
        }
        let (idt, idt_err) = (mr(27), mr(28));
        // Not delivered: again as it was asked for; being delivered: as
        // EXITINTINFO and its error code have it.
        self.pending = exits::svm_requeue(left, self.injected.take(), idt, idt_err);
        let (rflags, own_step) = self.step.done(self.rflags);
        if rflags != self.rflags {
            self.rflags = rflags;
            self.wr(RFLAGS, rflags);
        }
        if self.pending == Some(Event::Nmi) {
            self.nmi_masked = false;
        }
        // The IRET we waited for is done once RIP has moved.
        if let Some(r) = self.iret_rip
            && self.rip != r
        {
            self.iret_rip = None;
            self.nmi_masked = false;
        }
        if !fault {
            self.len = 0;
            return Exit::Notified(badge);
        }
        let (code, info1, info2) = (mr(3), mr(4), mr(6));
        // Without next-RIP saving the CPU gives no length: an I/O exit
        // has the next RIP in EXITINFO2; vcpu.rs decodes the others.
        self.len = exits::svm_len(code, mr(5), info2, self.rip);
        match exits::svm_exit(code, info1, info2, own_step) {
            Exit::NmiWindow => {
                // Our single step's #DB: DR6.BS taken back.
                let dr6 = self.rd(DR6);
                self.wr(DR6, dr6 & !DR6_BS);
                Exit::NmiWindow
            }
            Exit::Exception { vector: 1, error, .. } => Exit::Exception { vector: 1, error, dr6: self.rd(DR6) },
            Exit::Iret => {
                self.iret_rip = Some(self.rip);
                Exit::Iret
            }
            e => e,
        }
    }

    fn take_pending(&mut self) -> Option<Event> {
        self.pending.take()
    }

    fn gprs(&mut self) -> &mut Gprs {
        &mut self.gp
    }

    fn rsp(&mut self) -> u64 {
        self.rd(RSP)
    }

    fn set_rsp(&mut self, v: u64) {
        self.wr(RSP, v);
    }

    fn mark_gprs(&mut self) {
        self.gp_dirty = true;
    }

    fn rip(&self) -> u64 {
        self.rip
    }

    fn rflags(&self) -> u64 {
        self.rflags
    }

    fn set_rflags(&mut self, v: u64) {
        self.rflags = v | 2;
        self.wr(RFLAGS, self.rflags);
    }

    fn instr_len(&self) -> u64 {
        self.len
    }

    fn skip(&mut self, len: u64) {
        let rip = self.rip.wrapping_add(len);
        self.rip = if self.mode() == Mode::Bits64 { rip } else { rip & 0xffff_ffff };
        if self.int_state & 1 != 0 {
            self.int_state = 0;
            self.wr(INT_STATE, 0);
        }
    }

    fn interruptible(&self) -> bool {
        self.rflags & IF != 0 && self.int_state & 1 == 0
    }

    fn nmi_blocked(&self) -> bool {
        self.nmi_masked || self.int_state & 1 != 0
    }

    fn paging(&mut self) -> Paging {
        Paging { cr0: self.rd(CR0), cr3: self.rd(CR3), cr4: self.rd(CR4), efer: self.rd(EFER) }
    }

    fn mode(&mut self) -> Mode {
        let attrib = (self.rd(ES + 16) >> 16) & 0xfff;
        if self.rd(CR0) & walk::CR0_PE == 0 {
            Mode::Bits16
        } else if self.rd(EFER) & walk::EFER_LMA != 0 && attrib & (1 << 9) != 0 {
            Mode::Bits64
        } else if attrib & (1 << 10) != 0 {
            Mode::Bits32
        } else {
            Mode::Bits16
        }
    }

    fn cpl(&mut self) -> u8 {
        (self.rd(CPL) >> 24) as u8 & 3
    }

    fn seg_base(&mut self, s: Seg) -> u64 {
        self.rd(ES + 16 * s as u64 + 8)
    }

    fn cr0(&mut self) -> u64 {
        self.rd(CR0)
    }

    fn cr4(&mut self) -> u64 {
        self.rd(CR4)
    }

    fn set_cr0(&mut self, v: u64) -> bool {
        // Not intercepted: only our own emulation (LMSW, CLTS, a decoded
        // MOV) gets here.
        let old = self.rd(CR0);
        let mut efer = self.rd(EFER);
        if efer & walk::EFER_LME != 0 {
            if old & walk::CR0_PG == 0 && v & walk::CR0_PG != 0 {
                if self.rd(CR4) & walk::CR4_PAE == 0 {
                    return false;
                }
                efer |= walk::EFER_LMA;
            } else if old & walk::CR0_PG != 0 && v & walk::CR0_PG == 0 {
                efer &= !walk::EFER_LMA;
            }
            self.wr(EFER, efer | EFER_SVME);
        }
        self.wr(CR0, v)
    }

    fn set_cr4(&mut self, v: u64) -> bool {
        self.wr(CR4, v)
    }

    fn rdmsr(&mut self, msr: u32) -> Option<Option<u64>> {
        Some(Some(match msr {
            crate::x86::msr::EFER => self.rd(EFER) & !EFER_SVME,
            crate::x86::msr::PAT => self.rd(G_PAT),
            crate::x86::msr::STAR => self.rd(STAR),
            crate::x86::msr::LSTAR => self.rd(LSTAR),
            crate::x86::msr::CSTAR => self.rd(CSTAR),
            crate::x86::msr::FMASK => self.rd(SFMASK),
            crate::x86::msr::KERNEL_GS_BASE => self.rd(KERNEL_GS_BASE),
            crate::x86::msr::SYSENTER_CS => self.rd(SYSENTER_CS),
            crate::x86::msr::SYSENTER_ESP => self.rd(SYSENTER_ESP),
            crate::x86::msr::SYSENTER_EIP => self.rd(SYSENTER_EIP),
            MSR_FS_BASE => self.rd(ES + 16 * Seg::Fs as u64 + 8),
            MSR_GS_BASE => self.rd(ES + 16 * Seg::Gs as u64 + 8),
            _ => return None,
        }))
    }

    fn wrmsr(&mut self, msr: u32, v: u64) -> Option<bool> {
        Some(match msr {
            crate::x86::msr::EFER => {
                let cur = self.rd(EFER);
                if v & !(1 | walk::EFER_LME | walk::EFER_LMA | walk::EFER_NXE) != 0
                    || ((v ^ cur) & walk::EFER_LME != 0 && self.rd(CR0) & walk::CR0_PG != 0)
                {
                    return Some(false);
                }
                self.wr(EFER, (v & !walk::EFER_LMA) | (cur & walk::EFER_LMA) | EFER_SVME)
            }
            crate::x86::msr::PAT => crate::x86::msr::pat_valid(v) && self.wr(G_PAT, v),
            crate::x86::msr::STAR => self.wr(STAR, v),
            crate::x86::msr::LSTAR => self.wr(LSTAR, v),
            crate::x86::msr::CSTAR => self.wr(CSTAR, v),
            crate::x86::msr::FMASK => self.wr(SFMASK, v),
            crate::x86::msr::KERNEL_GS_BASE => self.wr(KERNEL_GS_BASE, v),
            crate::x86::msr::SYSENTER_CS => self.wr(SYSENTER_CS, v & 0xffff),
            crate::x86::msr::SYSENTER_ESP => self.wr(SYSENTER_ESP, v),
            crate::x86::msr::SYSENTER_EIP => self.wr(SYSENTER_EIP, v),
            MSR_FS_BASE => self.wr(ES + 16 * Seg::Fs as u64 + 8, v),
            MSR_GS_BASE => self.wr(ES + 16 * Seg::Gs as u64 + 8, v),
            _ => return None,
        })
    }

    fn set_xcr0(&mut self, v: u64) -> bool {
        super::vcpu_write_msr(self.vcpu, super::SEL4_MSR_XCR0, v)
    }

    fn set_tsc_offset(&mut self, off: u64) {
        self.wr(TSC_OFFSET, off);
    }

    fn set_cr2(&mut self, v: u64) {
        super::vcpu_write_msr(self.vcpu, super::SEL4_MSR_CR2, v);
    }

    fn set_tpr(&mut self, tpr: u8) {
        self.tpr = tpr;
    }

    fn flush_tlb(&mut self) {
        super::flush(self.vcpu);
    }

    fn start_real_mode(&mut self, vector: u8) {
        self.reset_common();
        let v = vector as u64;
        self.seg(ES + 16, v << 8, 0x9b, 0xffff, v << 12);
        for s in [Seg::Es, Seg::Ss, Seg::Ds, Seg::Fs, Seg::Gs] {
            self.seg(ES + 16 * s as u64, 0, 0x93, 0xffff, 0);
        }
        self.seg(LDTR, 0, 0x82, 0xffff, 0);
        self.seg(TR, 0, 0x8b, 0xffff, 0);
        self.seg(GDTR, 0, 0, 0xffff, 0);
        self.seg(IDTR, 0, 0, 0xffff, 0);
        self.wr(EFER, EFER_SVME);
        // CD and NW off (seL4 keeps the CPU's so): ET, as at reset.
        self.wr(CR0, 0x10);
        self.wr(CR4, 0);
        self.wr(CR3, 0);
        self.wr(RSP, 0);
        self.rip = 0;
        self.flush_tlb();
    }

    fn start_long_mode(&mut self, e: &crate::boot::Entry) {
        self.reset_common();
        self.seg(ES + 16, crate::boot::BOOT_CS as u64, 0xa9b, 0xffff_ffff, 0);
        for s in [Seg::Es, Seg::Ss, Seg::Ds, Seg::Fs, Seg::Gs] {
            self.seg(ES + 16 * s as u64, crate::boot::BOOT_DS as u64, 0xc93, 0xffff_ffff, 0);
        }
        self.seg(LDTR, 0, 0, 0, 0);
        self.seg(TR, 0, 0x8b, 0x67, 0);
        self.seg(GDTR, 0, 0, crate::boot::GDT_LIMIT as u64, e.gdt);
        self.seg(IDTR, 0, 0, 0, 0);
        self.wr(EFER, walk::EFER_LME | walk::EFER_LMA | EFER_SVME);
        self.wr(CR4, walk::CR4_PAE);
        self.wr(CR3, e.cr3);
        self.wr(CR0, walk::CR0_PG | walk::CR0_PE | 0x30);
        self.gp[6] = e.rsi;
        self.wr(RSP, e.rsi);
        self.rip = e.rip;
        self.flush_tlb();
    }
}
