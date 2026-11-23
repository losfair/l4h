//! A vCPU on VT-x (hw.rs): the VMCS is seL4's, read and written field by
//! field (seL4_X86_VCPU_ReadVMCS/WriteVMCS), with what an exit brings in
//! VMEnter's message registers (patch 0039).  The guest runs unrestricted
//! (real mode for APs starting), with EPT; CR0.NE and the CR0 and CR4 bits
//! seL4 keeps (CD, NW, and any CR4 bit off its allowlist) exit when the
//! guest changes them, and are kept as the guest sees them in the read
//! shadows; CR8 always exits (patch 0043); HLT exits.

use l4h_rt::sel4;

use super::{Event, Exit, Gprs, Hw, SEL4_ORDER, exits, vmenter, write_gprs};
use crate::x86::decode::{Mode, Seg};
use crate::x86::walk::{self, Paging};

// VMCS fields (Intel SDM, appendix B).
const ES_SELECTOR: u64 = 0x800;
const GUEST_PAT: u64 = 0x2804;
const GUEST_EFER: u64 = 0x2806;
const GUEST_PDPTE0: u64 = 0x280a;
const PRIMARY: u64 = 0x4002;
const EXCEPTION_BITMAP: u64 = 0x4004;
const ENTRY_CONTROLS: u64 = 0x4012;
const ENTRY_EXC_ERROR: u64 = 0x4018;
const SECONDARY: u64 = 0x401e;
const EXIT_INSTRUCTION_INFO: u64 = 0x440e;
const ES_LIMIT: u64 = 0x4800;
const GDTR_LIMIT: u64 = 0x4810;
const IDTR_LIMIT: u64 = 0x4812;
const ES_AR: u64 = 0x4814;
const CS_AR: u64 = 0x4816;
const SS_AR: u64 = 0x4818;
const INTERRUPTIBILITY: u64 = 0x4824;
const ACTIVITY: u64 = 0x4826;
const SYSENTER_CS: u64 = 0x482a;
const CR0_MASK: u64 = 0x6000;
const CR4_MASK: u64 = 0x6002;
const CR0_SHADOW: u64 = 0x6004;
const CR4_SHADOW: u64 = 0x6006;
const GUEST_CR0: u64 = 0x6800;
const GUEST_CR3: u64 = 0x6802;
const GUEST_CR4: u64 = 0x6804;
const ES_BASE: u64 = 0x6806;
const GDTR_BASE: u64 = 0x6816;
const IDTR_BASE: u64 = 0x6818;
const DR7: u64 = 0x681a;
const RSP: u64 = 0x681c;
const RFLAGS: u64 = 0x6820;
const PENDING_DBG: u64 = 0x6822;
const SYSENTER_ESP: u64 = 0x6824;
const SYSENTER_EIP: u64 = 0x6826;
const TSC_OFFSET: u64 = 0x2010;
const GUEST_DEBUGCTL: u64 = 0x2802;

const SEG_LDTR: u64 = 6;
const SEG_TR: u64 = 7;

// Controls.
const PRI_IRQ_WINDOW: u64 = 1 << 2;
const PRI_TSC_OFFSET: u64 = 1 << 3;
const PRI_HLT: u64 = 1 << 7;
const PRI_NMI_WINDOW: u64 = 1 << 22;
const PRI_SECONDARY: u64 = 1 << 31;
const SEC_EPT: u64 = 1 << 1;
const SEC_VPID: u64 = 1 << 5;
const SEC_WBINVD: u64 = 1 << 6;
const SEC_UNRESTRICTED: u64 = 1 << 7;
const SEC_INVPCID: u64 = 1 << 12;
const ENTRY_IA32E: u64 = 1 << 9;
const ENTRY_LOAD_PAT: u64 = 1 << 14;
const ENTRY_LOAD_EFER: u64 = 1 << 15;

const CR0_PE: u64 = 1 << 0;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_NW: u64 = 1 << 29;
const CR0_CD: u64 = 1 << 30;
const CR0_PG: u64 = 1 << 31;
const CR4_VMXE: u64 = 1 << 13;

const INTR_VALID: u64 = 1 << 31;
const INTR_ERROR: u64 = 1 << 11;
const IF: u64 = 1 << 9;

const MSR_STAR: u32 = 0xc000_0081;
const MSR_LSTAR: u32 = 0xc000_0082;
const MSR_CSTAR: u32 = 0xc000_0083;
const MSR_FMASK: u32 = 0xc000_0084;
const MSR_FS_BASE: u32 = crate::x86::msr::FS_BASE;
const MSR_GS_BASE: u32 = crate::x86::msr::GS_BASE;
const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// A cache of VMCS fields read since the last entry.
struct Cache {
    fields: [(u64, u64); 16],
    n: usize,
}

pub struct Vmx {
    vcpu: u64,
    gp: Gprs,
    gp_dirty: bool,
    rsp: Option<u64>,
    rip: u64,
    rflags: u64,
    rflags_dirty: bool,
    intr: u64,
    intr_dirty: bool,
    len: u64,
    pending: Option<Event>,
    cache: Cache,
    ppc: u64,
    /// INVPCID can be on (the CPU has it).
    pub invpcid: bool,
}

fn rd(vcpu: u64, field: u64) -> u64 {
    let r = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_X86_VCPU_ReadVMCS(vcpu, field));
    assert_eq!(r.error, 0, "ReadVMCS {:#x}", field);
    r.value
}

fn wr(vcpu: u64, field: u64, v: u64) -> u64 {
    let r = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_X86_VCPU_WriteVMCS(vcpu, field, v));
    assert_eq!(r.error, 0, "WriteVMCS {:#x}", field);
    r.written
}

impl Vmx {
    /// The VCPU in slot `vcpu`, with the controls l4h-hvm runs guests with.
    pub fn new(vcpu: u64) -> Self {
        let sec = wr(vcpu, SECONDARY, SEC_EPT | SEC_VPID | SEC_WBINVD | SEC_UNRESTRICTED | SEC_INVPCID);
        assert!(sec & SEC_UNRESTRICTED != 0, "l4h-hvm: the CPU has no VT-x unrestricted guest");
        wr(vcpu, CR0_MASK, exits::VMX_CR0_OWNED);
        // LA57 ours (on a CPU that has it): turning it on exits, and is
        // refused (vcpu.rs: 4-level paging only), as on AMD-V, where every
        // CR4 write exits.
        wr(vcpu, CR4_MASK, exits::CR4_LA57);
        wr(vcpu, EXCEPTION_BITMAP, 0);
        let ppc = wr(vcpu, PRIMARY, PRI_HLT | PRI_TSC_OFFSET | PRI_SECONDARY) & !(PRI_IRQ_WINDOW | PRI_NMI_WINDOW);
        Vmx {
            vcpu, gp: [0; 16], gp_dirty: true, rsp: None, rip: 0, rflags: 2, rflags_dirty: false, intr: 0, intr_dirty: false,
            len: 0, pending: None, cache: Cache { fields: [(0, 0); 16], n: 0 }, ppc, invpcid: sec & SEC_INVPCID != 0,
        }
    }

    fn rd(&mut self, field: u64) -> u64 {
        if let Some(&(_, v)) = self.cache.fields[..self.cache.n].iter().find(|(f, _)| *f == field) {
            return v;
        }
        let v = rd(self.vcpu, field);
        if self.cache.n < self.cache.fields.len() {
            self.cache.fields[self.cache.n] = (field, v);
            self.cache.n += 1;
        }
        v
    }

    fn wr(&mut self, field: u64, v: u64) {
        let w = wr(self.vcpu, field, v);
        if let Some(e) = self.cache.fields[..self.cache.n].iter_mut().find(|(f, _)| *f == field) {
            e.1 = w;
        }
    }

    /// Segment `s` (x86's numbers; LDTR 6, TR 7): selector, base, limit,
    /// access rights.
    fn seg(&mut self, s: u64, sel: u64, base: u64, limit: u64, ar: u64) {
        self.wr(ES_SELECTOR + 2 * s, sel);
        self.wr(ES_BASE + 2 * s, base);
        self.wr(ES_LIMIT + 2 * s, limit);
        self.wr(ES_AR + 2 * s, ar);
    }

    fn common_reset(&mut self) {
        self.wr(GDTR_LIMIT, 0xffff);
        self.wr(GDTR_BASE, 0);
        self.wr(IDTR_LIMIT, 0xffff);
        self.wr(IDTR_BASE, 0);
        self.wr(DR7, 0x400);
        self.wr(GUEST_PAT, crate::x86::msr::PAT_DEFAULT);
        self.wr(GUEST_DEBUGCTL, 0);
        self.wr(ACTIVITY, 0);
        self.wr(PENDING_DBG, 0);
        self.wr(SYSENTER_CS, 0);
        self.wr(SYSENTER_ESP, 0);
        self.wr(SYSENTER_EIP, 0);
        self.intr = 0;
        self.intr_dirty = true;
        self.rflags = 2;
        self.rflags_dirty = true;
        self.gp = [0; 16];
        self.gp_dirty = true;
        self.pending = None;
    }

    fn entry_controls(&mut self, set: u64, clear: u64) {
        let c = self.rd(ENTRY_CONTROLS);
        let n = (c & !clear) | set;
        if n != c {
            self.wr(ENTRY_CONTROLS, n);
        }
    }

    /// The PAE PDPTEs a MOV to CR0 or CR4 that ends in 32-bit PAE paging
    /// loads (exits::needs_pae_pdptes), read and checked first, as the CPU
    /// does: Some(None) if none are loaded, None for the MOV's #GP (not in
    /// RAM, or a reserved bit set), before anything changes.
    fn pdptes_for(&mut self, cr0: u64, cr4: u64) -> Option<Option<[u64; 4]>> {
        let (old_cr0, old_cr4, efer) = (self.cr0(), self.cr4(), self.rd(GUEST_EFER));
        if !exits::needs_pae_pdptes(old_cr0, cr0, old_cr4, cr4, efer) {
            return Some(None);
        }
        let vm = crate::vm::vm();
        let at = self.rd(GUEST_CR3) & 0xffff_ffe0;
        if !vm.mem.valid(at, 32) {
            return None;
        }
        let p: [u64; 4] = core::array::from_fn(|i| vm.mem.read::<u64>(at + 8 * i as u64));
        exits::pae_pdptes_valid(&p, vm.host.phys_bits).then_some(Some(p))
    }

    fn load_pdptes(&mut self, p: Option<[u64; 4]>) {
        for (i, &e) in p.iter().flatten().enumerate() {
            self.wr(GUEST_PDPTE0 + 2 * i as u64, e);
        }
    }
}

impl Hw for Vmx {
    fn enter(&mut self, ev: Option<Event>, irq_window: bool, nmi_window: bool) -> Exit {
        if self.gp_dirty {
            write_gprs(self.vcpu, &self.gp);
            self.gp_dirty = false;
        }
        if self.rflags_dirty {
            wr(self.vcpu, RFLAGS, self.rflags);
            self.rflags_dirty = false;
        }
        if self.intr_dirty {
            wr(self.vcpu, INTERRUPTIBILITY, self.intr);
            self.intr_dirty = false;
        }
        let (info, error) = match ev {
            None => (0, 0),
            Some(Event::Ext(v)) => (v as u64 | INTR_VALID, 0),
            Some(Event::Nmi) => (2 | (2 << 8) | INTR_VALID, 0),
            Some(Event::Exc(v, e)) => (v as u64 | (3 << 8) | INTR_VALID | if e.is_some() { INTR_ERROR } else { 0 }, e.unwrap_or(0)),
        };
        if info & INTR_ERROR != 0 {
            wr(self.vcpu, ENTRY_EXC_ERROR, error as u64);
        }
        let controls = self.ppc | if irq_window { PRI_IRQ_WINDOW } else { 0 } | if nmi_window { PRI_NMI_WINDOW } else { 0 };
        let (fault, badge) = vmenter(self.rip, controls, info);
        // Every word of the exit at once (a VCPU invocation overwrites them).
        let m = super::exit_mrs();
        self.cache.n = 0;
        self.rsp = None;
        self.rip = m[0];
        let left = m[2];
        self.rflags = m[7];
        self.intr = m[8];
        for (i, &x) in SEL4_ORDER.iter().enumerate() {
            self.gp[x] = m[10 + i];
        }
        let (idt, idt_err) = (m[27], m[28]);
        // What was not delivered, or was being delivered, goes in again.
        let vectoring = if left & INTR_VALID != 0 { left } else { idt };
        self.pending = if left & INTR_VALID != 0 { exits::vmx_event(left, error as u64) } else { exits::vmx_event(idt, idt_err) };
        let ei = m[25];
        if exits::vmx_nmi_reblock(ei, vectoring) {
            self.intr |= exits::VMX_BLOCK_NMI;
            self.intr_dirty = true;
        }
        if !fault {
            self.len = 0;
            return Exit::Notified(badge);
        }
        self.len = m[5];
        let vcpu = self.vcpu;
        exits::vmx_exit(m[3], m[4], ei, m[26], m[6], || rd(vcpu, EXIT_INSTRUCTION_INFO))
    }

    fn take_pending(&mut self) -> Option<Event> {
        self.pending.take()
    }

    fn gprs(&mut self) -> &mut Gprs {
        &mut self.gp
    }

    fn rsp(&mut self) -> u64 {
        if let Some(v) = self.rsp {
            return v;
        }
        let v = rd(self.vcpu, RSP);
        self.rsp = Some(v);
        v
    }

    fn set_rsp(&mut self, v: u64) {
        wr(self.vcpu, RSP, v);
        self.rsp = Some(v);
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
        self.rflags_dirty = true;
    }

    fn instr_len(&self) -> u64 {
        self.len
    }

    fn skip(&mut self, len: u64) {
        let rip = self.rip.wrapping_add(len);
        self.rip = if self.mode() == Mode::Bits64 { rip } else { rip & 0xffff_ffff };
        if self.intr & 3 != 0 {
            self.intr &= !3;
            self.intr_dirty = true;
        }
    }

    fn interruptible(&self) -> bool {
        self.rflags & IF != 0 && self.intr & 3 == 0
    }

    fn nmi_blocked(&self) -> bool {
        self.intr & (3 | 8) != 0
    }

    fn paging(&mut self) -> Paging {
        Paging { cr0: self.rd(GUEST_CR0), cr3: self.rd(GUEST_CR3), cr4: self.rd(GUEST_CR4), efer: self.rd(GUEST_EFER) }
    }

    fn mode(&mut self) -> Mode {
        let ar = self.rd(CS_AR);
        if self.rd(GUEST_CR0) & CR0_PE == 0 {
            Mode::Bits16
        } else if self.rd(GUEST_EFER) & walk::EFER_LMA != 0 && ar & (1 << 13) != 0 {
            Mode::Bits64
        } else if ar & (1 << 14) != 0 {
            Mode::Bits32
        } else {
            Mode::Bits16
        }
    }

    fn cpl(&mut self) -> u8 {
        ((self.rd(SS_AR) >> 5) & 3) as u8
    }

    fn seg_base(&mut self, s: Seg) -> u64 {
        self.rd(ES_BASE + 2 * s as u64)
    }

    fn cr0(&mut self) -> u64 {
        let mask = self.rd(CR0_MASK);
        (self.rd(GUEST_CR0) & !mask) | (self.rd(CR0_SHADOW) & mask)
    }

    fn cr4(&mut self) -> u64 {
        let mask = self.rd(CR4_MASK);
        (self.rd(GUEST_CR4) & !mask) | (self.rd(CR4_SHADOW) & mask)
    }

    fn set_cr0(&mut self, v: u64) -> bool {
        // Everything that can fail first, before any field changes: the
        // PDPTEs it loads, and IA-32e mode without PAE.
        let cr4 = self.cr4();
        let Some(pdptes) = self.pdptes_for(v, cr4) else { return false };
        let old = self.rd(GUEST_CR0);
        let mut efer = self.rd(GUEST_EFER);
        if efer & walk::EFER_LME != 0 && (old ^ v) & CR0_PG != 0 && v & CR0_PG != 0 && self.rd(GUEST_CR4) & walk::CR4_PAE == 0 {
            // Entering IA-32e mode needs PAE.
            return false;
        }
        if efer & walk::EFER_LME != 0 {
            if old & CR0_PG == 0 && v & CR0_PG != 0 {
                efer |= walk::EFER_LMA;
                self.entry_controls(ENTRY_IA32E, 0);
            } else if old & CR0_PG != 0 && v & CR0_PG == 0 {
                efer &= !walk::EFER_LMA;
                self.entry_controls(0, ENTRY_IA32E);
            }
            self.wr(GUEST_EFER, efer);
        }
        // The guest's CD and NW stay in the shadow: seL4 keeps them off.
        self.wr(CR0_SHADOW, v);
        self.wr(GUEST_CR0, (v | CR0_NE) & !(CR0_CD | CR0_NW));
        self.load_pdptes(pdptes);
        true
    }

    fn set_cr4(&mut self, v: u64) -> bool {
        let cr0 = self.cr0();
        let Some(pdptes) = self.pdptes_for(cr0, v) else { return false };
        self.wr(CR4_SHADOW, v);
        self.wr(GUEST_CR4, v | CR4_VMXE);
        self.load_pdptes(pdptes);
        true
    }

    fn rdmsr(&mut self, msr: u32) -> Option<Option<u64>> {
        Some(Some(match msr {
            crate::x86::msr::EFER => self.rd(GUEST_EFER),
            crate::x86::msr::PAT => self.rd(GUEST_PAT),
            crate::x86::msr::SYSENTER_CS => self.rd(SYSENTER_CS),
            crate::x86::msr::SYSENTER_ESP => self.rd(SYSENTER_ESP),
            crate::x86::msr::SYSENTER_EIP => self.rd(SYSENTER_EIP),
            MSR_FS_BASE => self.rd(ES_BASE + 2 * Seg::Fs as u64),
            MSR_GS_BASE => self.rd(ES_BASE + 2 * Seg::Gs as u64),
            MSR_STAR | MSR_LSTAR | MSR_CSTAR | MSR_FMASK | MSR_KERNEL_GS_BASE => return Some(super::vcpu_read_msr(self.vcpu, msr as u64)),
            _ => return None,
        }))
    }

    fn wrmsr(&mut self, msr: u32, v: u64) -> Option<bool> {
        let canonical = (((v << 16) as i64) >> 16) as u64 == v;
        Some(match msr {
            crate::x86::msr::EFER => {
                // SCE, LME, NXE; LMA is the CPU's.  LME cannot change with
                // paging on.
                let cur = self.rd(GUEST_EFER);
                if v & !(1 | walk::EFER_LME | walk::EFER_LMA | walk::EFER_NXE) != 0
                    || ((v ^ cur) & walk::EFER_LME != 0 && self.rd(GUEST_CR0) & CR0_PG != 0)
                {
                    return Some(false);
                }
                self.wr(GUEST_EFER, (v & !walk::EFER_LMA) | (cur & walk::EFER_LMA));
                true
            }
            crate::x86::msr::PAT => {
                if !crate::x86::msr::pat_valid(v) {
                    return Some(false);
                }
                self.wr(GUEST_PAT, v);
                true
            }
            crate::x86::msr::SYSENTER_CS => {
                self.wr(SYSENTER_CS, v & 0xffff);
                true
            }
            crate::x86::msr::SYSENTER_ESP | crate::x86::msr::SYSENTER_EIP | MSR_FS_BASE | MSR_GS_BASE if !canonical => false,
            crate::x86::msr::SYSENTER_ESP => {
                self.wr(SYSENTER_ESP, v);
                true
            }
            crate::x86::msr::SYSENTER_EIP => {
                self.wr(SYSENTER_EIP, v);
                true
            }
            MSR_FS_BASE => {
                self.wr(ES_BASE + 2 * Seg::Fs as u64, v);
                true
            }
            MSR_GS_BASE => {
                self.wr(ES_BASE + 2 * Seg::Gs as u64, v);
                true
            }
            MSR_STAR | MSR_LSTAR | MSR_CSTAR | MSR_FMASK | MSR_KERNEL_GS_BASE => super::vcpu_write_msr(self.vcpu, msr as u64, v),
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

    fn flush_tlb(&mut self) {
        super::flush(self.vcpu);
    }

    fn start_real_mode(&mut self, vector: u8) {
        self.common_reset();
        let v = vector as u64;
        self.seg(Seg::Cs as u64, v << 8, v << 12, 0xffff, 0x9b);
        for s in [Seg::Es, Seg::Ss, Seg::Ds, Seg::Fs, Seg::Gs] {
            self.seg(s as u64, 0, 0, 0xffff, 0x93);
        }
        self.seg(SEG_LDTR, 0, 0, 0xffff, 0x82);
        self.seg(SEG_TR, 0, 0, 0xffff, 0x8b);
        self.entry_controls(ENTRY_LOAD_PAT | ENTRY_LOAD_EFER, ENTRY_IA32E);
        self.wr(GUEST_EFER, 0);
        // CD and NW as at reset, which seL4 keeps off in the CPU.
        self.wr(CR0_SHADOW, CR0_CD | CR0_NW | CR0_ET);
        self.wr(GUEST_CR0, CR0_ET | CR0_NE);
        self.wr(CR4_SHADOW, 0);
        self.wr(GUEST_CR4, CR4_VMXE);
        self.wr(GUEST_CR3, 0);
        self.set_rsp(0);
        self.rip = 0;
        self.flush_tlb();
    }

    fn start_long_mode(&mut self, e: &crate::boot::Entry) {
        self.common_reset();
        self.seg(Seg::Cs as u64, crate::boot::BOOT_CS as u64, 0, 0xffff_ffff, 0xa09b);
        for s in [Seg::Es, Seg::Ss, Seg::Ds, Seg::Fs, Seg::Gs] {
            self.seg(s as u64, crate::boot::BOOT_DS as u64, 0, 0xffff_ffff, 0xc093);
        }
        // LDTR unusable; TR a busy 64-bit TSS.
        self.seg(SEG_LDTR, 0, 0, 0, 1 << 16);
        self.seg(SEG_TR, 0, 0, 0x67, 0x8b);
        self.wr(GDTR_BASE, e.gdt);
        self.wr(GDTR_LIMIT, crate::boot::GDT_LIMIT as u64);
        self.wr(IDTR_LIMIT, 0);
        self.entry_controls(ENTRY_IA32E | ENTRY_LOAD_PAT | ENTRY_LOAD_EFER, 0);
        self.wr(GUEST_EFER, walk::EFER_LME | walk::EFER_LMA);
        let cr0 = CR0_PE | CR0_ET | CR0_NE | CR0_PG;
        self.wr(CR0_SHADOW, cr0);
        self.wr(GUEST_CR0, cr0);
        self.wr(CR4_SHADOW, walk::CR4_PAE);
        self.wr(GUEST_CR4, walk::CR4_PAE | CR4_VMXE);
        self.wr(GUEST_CR3, e.cr3);
        self.gp[6] = e.rsi;
        self.set_rsp(e.rsi);
        self.rip = e.rip;
        self.flush_tlb();
    }
}
