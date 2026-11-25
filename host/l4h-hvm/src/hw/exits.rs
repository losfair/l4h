//! What a VM exit is, from the words seL4's VMEnter gives for it, on VT-x
//! and AMD-V: the part of vmx.rs and svm.rs that is arithmetic only, so
//! that it runs on the build host too (tests/hvm.rs).

use super::{Event, Exit};
use crate::x86::decode::Seg;

// ---- Both.

/// RIP after an exit's instruction of `len` bytes at `rip`: wrapped at
/// 4 GiB outside 64-bit mode.  `bits64` (the guest's mode, which costs
/// VMCS or VMCB reads, each a system call) is asked only when the step
/// crosses 4 GiB from below: a RIP above 4 GiB is 64-bit code (VM entry
/// requires bits 63:32 clear outside it), and below it nothing wraps.
pub fn skip_rip(rip: u64, len: u64, bits64: impl FnOnce() -> bool) -> u64 {
    let next = rip.wrapping_add(len);
    if rip <= 0xffff_ffff && next > 0xffff_ffff && !bits64() { next & 0xffff_ffff } else { next }
}

// ---- VT-x.

pub const VMX_INTR_VALID: u64 = 1 << 31;
pub const VMX_INTR_ERROR: u64 = 1 << 11;
/// Exit-interruption information: NMI unblocking due to IRET.
pub const VMX_INTR_NMI_UNBLOCKED: u64 = 1 << 12;
/// Guest interruptibility: blocking by NMI.
pub const VMX_BLOCK_NMI: u64 = 1 << 3;
pub const CR0_PE: u64 = 1 << 0;
pub const CR0_NE: u64 = 1 << 5;
pub const CR0_NW: u64 = 1 << 29;
pub const CR0_CD: u64 = 1 << 30;
pub const CR0_PG: u64 = 1 << 31;
pub const CR4_LA57: u64 = 1 << 12;
/// The CR0 bits l4h-hvm owns on VT-x (the guest/host mask): seL4's CD and
/// NW, NE, and PE and PG, so that every change of them exits and set_cr0
/// keeps the IA-32e entry control with EFER.LMA (an AP's trampoline turns
/// long mode on with a MOV to CR0).
pub const VMX_CR0_OWNED: u64 = CR0_NE | CR0_CD | CR0_NW | CR0_PE | CR0_PG;

/// An event in VT-x's interruption-information format, to go in again.
pub fn vmx_event(info: u64, error: u64) -> Option<Event> {
    if info & VMX_INTR_VALID == 0 {
        return None;
    }
    let v = info as u8;
    match (info >> 8) & 7 {
        0 => Some(Event::Ext(v)),
        2 => Some(Event::Nmi),
        3 => Some(Event::Exc(v, (info & VMX_INTR_ERROR != 0).then_some(error as u32))),
        // Software interrupts and exceptions run again from their
        // instruction.
        _ => None,
    }
}

/// Whether NMIs are to be blocked again after an exit: a fault of an NMI
/// handler's IRET unblocked them early (exit-interruption information
/// `exit_info`), unless a #DF, or an event was being delivered
/// (`vectoring`, the event that goes in again).
pub fn vmx_nmi_reblock(exit_info: u64, vectoring: u64) -> bool {
    exit_info & VMX_INTR_VALID != 0
        && exit_info & VMX_INTR_NMI_UNBLOCKED != 0
        && exit_info as u8 != 8
        && vectoring & VMX_INTR_VALID == 0
}

/// A VT-x exit: its basic reason, qualification, exit-interruption
/// information and error code, the GPA of an EPT violation, and the
/// VM-exit instruction information of a string I/O instruction
/// (`io_info`, asked only then: its address size and segment).
pub fn vmx_exit(reason: u64, q: u64, exit_info: u64, exit_error: u64, gpa: u64, io_info: impl FnOnce() -> u64) -> Exit {
    if reason & (1 << 31) != 0 {
        return Exit::Fatal(reason);
    }
    match reason & 0xffff {
        0 => {
            // The host's NMI: no instruction of the guest's.
            if (exit_info >> 8) & 7 == 2 {
                return Exit::Notified(0);
            }
            Exit::Exception { vector: exit_info as u8, error: (exit_info & VMX_INTR_ERROR != 0).then_some(exit_error as u32), dr6: q }
        }
        // An external interrupt, INIT or SIPI: no instruction either.
        1 | 3 | 4 => Exit::Notified(0),
        2 => Exit::Shutdown,
        7 => Exit::IrqWindow,
        8 => Exit::NmiWindow,
        9 => Exit::TaskSwitch,
        10 => Exit::Cpuid,
        12 => Exit::Hlt,
        // INVD, INVLPG, PAUSE, WBINVD.
        13 | 14 | 40 | 54 => Exit::Nop,
        15 => Exit::Rdpmc,
        16 => Exit::Rdtsc,
        18 => Exit::Hypercall,
        19..=27 | 36 | 39 | 50 | 51 | 53 | 58 => Exit::Undefined,
        28 => {
            let (cr, reg) = ((q & 15) as u8, Some(((q >> 8) & 15) as u8));
            match (q >> 4) & 3 {
                0 => Exit::Cr { cr, write: true, reg },
                1 => Exit::Cr { cr, write: false, reg },
                2 => Exit::Clts,
                _ => Exit::Lmsw((q >> 16) as u16),
            }
        }
        29 => Exit::Dr { dr: (q & 7) as u8, write: q & 16 == 0, reg: Some(((q >> 8) & 15) as u8) },
        30 => {
            let string = q & 16 != 0;
            let info = if string { io_info() } else { 0 };
            let addr = if string { 2 << ((info >> 7) & 3) } else { 0 };
            let seg = if string { seg_of((info >> 15) & 7) } else { None };
            Exit::Io { port: (q >> 16) as u16, size: ((q & 7) + 1) as u8, input: q & 8 != 0, string, rep: q & 32 != 0, addr, seg }
        }
        31 => Exit::Rdmsr,
        32 => Exit::Wrmsr,
        48 => Exit::Mmio { gpa, write: q & 2 != 0 },
        55 => Exit::Xsetbv,
        r => Exit::Fatal(r),
    }
}

/// A segment register by x86's number.
pub fn seg_of(n: u64) -> Option<Seg> {
    Some(match n {
        0 => Seg::Es,
        1 => Seg::Cs,
        2 => Seg::Ss,
        3 => Seg::Ds,
        4 => Seg::Fs,
        5 => Seg::Gs,
        _ => return None,
    })
}

/// CR4 bits whose change makes a CPU in PAE paging load the PDPTEs again,
/// and CR0's (SDM 4.4.1; KVM's kvm_set_cr0/cr4).
const PDPTE_CR4: u64 = (1 << 5) | (1 << 7) | (1 << 4) | (1 << 20);
const PDPTE_CR0: u64 = CR0_PG | CR0_CD | CR0_NW;

/// Whether a MOV to CR0 or CR4 from (`old_cr0`, `old_cr4`) to (`cr0`,
/// `cr4`), with `efer`, loads the PAE PDPTEs (32-bit PAE paging after it):
/// they are checked then, and a bad one is the MOV's #GP.
pub fn needs_pae_pdptes(old_cr0: u64, cr0: u64, old_cr4: u64, cr4: u64, efer: u64) -> bool {
    cr0 & CR0_PG != 0
        && cr4 & (1 << 5) != 0
        && efer & (1 << 8) == 0
        && ((old_cr0 ^ cr0) & PDPTE_CR0 != 0 || (old_cr4 ^ cr4) & PDPTE_CR4 != 0)
}

/// Whether PAE PDPTEs are valid (SDM table 4-8): a present one has none of
/// its reserved bits (2:1, 8:5, and from `phys_bits` up).
pub fn pae_pdptes_valid(pdptes: &[u64; 4], phys_bits: u32) -> bool {
    let rsvd = 0x1e6u64 | (!0u64).checked_shl(phys_bits.min(63)).unwrap_or(0);
    pdptes.iter().all(|&e| e & 1 == 0 || e & rsvd == 0)
}

// ---- AMD-V.

pub const SVM_EVT_VALID: u64 = 1 << 31;
pub const SVM_EVT_ERROR: u64 = 1 << 11;
pub const RFLAGS_TF: u64 = 1 << 8;
pub const RFLAGS_RF: u64 = 1 << 16;
/// DR6's causes the guest has: B0-B3 (its breakpoints) and BD.
pub const DR6_GUEST: u64 = 0x200f;

/// An event in AMD-V's EXITINTINFO format (the error code in the high
/// half), to go in again.
pub fn svm_event(info: u64) -> Option<Event> {
    if info & SVM_EVT_VALID == 0 {
        return None;
    }
    let v = info as u8;
    match (info >> 8) & 7 {
        0 => Some(Event::Ext(v)),
        2 => Some(Event::Nmi),
        // INT3 and INTO run again from their instruction, as INTn.
        3 if v != 3 && v != 4 => Some(Event::Exc(v, (info & SVM_EVT_ERROR != 0).then_some((info >> 32) as u32))),
        _ => None,
    }
}

/// What goes in again after an exit: the event injected, as it was asked
/// for, if it never went in (`left`, seL4's MR2, has its low half only);
/// what was being delivered (EXITINTINFO and its error code) otherwise.
pub fn svm_requeue(left: u64, injected: Option<Event>, exitintinfo: u64, error: u64) -> Option<Event> {
    if left & SVM_EVT_VALID != 0 { injected } else { svm_event(exitintinfo | error << 32) }
}

/// The length of an exit's instruction: seL4's (NEXT_RIP - RIP; 0 without
/// next-RIP saving), or an I/O exit's from its next RIP (EXITINFO2); 0
/// for the others, which vcpu.rs decodes.
pub fn svm_len(code: u64, len: u64, info2: u64, rip: u64) -> u64 {
    if len == 0 && code == 0x7b { info2.wrapping_sub(rip) & 0xf } else { len }
}

/// An AMD-V exit: its code, EXITINFO1 and 2, and whether a #DB is our
/// own single step (`own_step`).
pub fn svm_exit(code: u64, info1: u64, info2: u64, own_step: bool) -> Exit {
    let reg = |info1: u64| (info1 & (1 << 63) != 0).then_some((info1 & 15) as u8);
    match code {
        0x00..=0x0f => Exit::Cr { cr: code as u8, write: false, reg: reg(info1) },
        0x10..=0x1f => Exit::Cr { cr: (code - 0x10) as u8, write: true, reg: reg(info1) },
        0x20..=0x2f => Exit::Dr { dr: (code - 0x20) as u8, write: false, reg: reg(info1) },
        0x30..=0x3f => Exit::Dr { dr: (code - 0x30) as u8, write: true, reg: reg(info1) },
        // Our single step for an NMI window, which the guest did not ask
        // for: its #DB is ours.
        0x41 if own_step => Exit::NmiWindow,
        0x40..=0x5f => {
            let vector = (code - 0x40) as u8;
            let error = matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30).then_some(info1 as u32);
            Exit::Exception { vector, error, dr6: 0 }
        }
        // INTR, NMI, SMI, INIT: the host's, no instruction of the guest's.
        0x60..=0x63 => Exit::Notified(0),
        0x64 => Exit::IrqWindow,
        // A selective CR0 write (MOV to CR0 or LMSW changing more than TS
        // and MP): FL4 always intercepts it, so CD and NW never reach the
        // hardware CR0; seL4 leaves it off.  As a CR0 write (KVM's
        // cr_interception); without a register (LMSW), vcpu.rs decodes.
        0x65 => Exit::Cr { cr: 0, write: true, reg: reg(info1) },
        0x6e => Exit::Rdtsc,
        0x6f => Exit::Rdpmc,
        0x72 => Exit::Cpuid,
        0x74 => Exit::Iret,
        0x76 | 0x77 | 0x79 | 0x89 => Exit::Nop,
        0x78 => Exit::Hlt,
        0x7b => {
            let size = if info1 & 0x10 != 0 { 1 } else if info1 & 0x20 != 0 { 2 } else { 4 };
            let addr = match (info1 >> 7) & 7 {
                1 => 2,
                2 => 4,
                _ => 8,
            };
            Exit::Io { port: (info1 >> 16) as u16, size, input: info1 & 1 != 0, string: info1 & 4 != 0, rep: info1 & 8 != 0, addr, seg: None }
        }
        0x7c => if info1 & 1 != 0 { Exit::Wrmsr } else { Exit::Rdmsr },
        0x7d => Exit::TaskSwitch,
        0x7f => Exit::Shutdown,
        0x81 => Exit::Hypercall,
        0x73 | 0x7a | 0x80 | 0x82..=0x88 | 0x8a..=0x8c | 0x8e => Exit::Undefined,
        0x8d => Exit::Xsetbv,
        0x400 => Exit::Mmio { gpa: info2, write: info1 & 2 != 0 },
        c => Exit::Fatal(c),
    }
}

/// AMD-V's NMI window without vNMI (svm_enable_nmi_window()): an NMI that
/// waits for an IRET's completion or an interrupt shadow single-steps the
/// guest over its instruction, with RFLAGS.TF and RF set for that entry
/// (RF: no instruction breakpoint again at its RIP) and its own TF and RF
/// back after it.  An NMI masked until an IRET waits for the IRET
/// intercept instead; an entry that injects an event does not step, as its
/// frame would keep TF.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NmiStep {
    /// Stepping: the guest's own TF and RF.
    pub guest: Option<u64>,
}

impl NmiStep {
    /// Before an entry: the RFLAGS to enter with, if it steps.
    pub fn arm(&mut self, nmi_window: bool, injecting: bool, nmi_masked: bool, awaiting_iret: bool, shadow: bool, rflags: u64)
        -> Option<u64> {
        if !nmi_window || injecting || (nmi_masked && !awaiting_iret) || !(awaiting_iret || shadow) {
            return None;
        }
        self.guest = Some(rflags & (RFLAGS_TF | RFLAGS_RF));
        Some(rflags | RFLAGS_TF | RFLAGS_RF)
    }

    /// After the exit: the guest's RFLAGS, without the TF and RF we added
    /// (its own as the CPU left them: an instruction that ran cleared RF),
    /// and, if it stepped, whether the guest had TF of its own.
    pub fn done(&mut self, rflags: u64) -> (u64, Option<bool>) {
        match self.guest.take() {
            Some(g) => {
                let ours = (RFLAGS_TF | RFLAGS_RF) & !g;
                (rflags & !ours, Some(g & RFLAGS_TF != 0))
            }
            None => (rflags, None),
        }
    }
}

/// Whether a #DB during our single step is ours alone: the guest had no
/// TF of its own, and no breakpoint of its (DR6's B0-B3, BD) hit.
pub fn svm_db_is_ours(guest_tf: bool, dr6: u64) -> bool {
    !guest_tf && dr6 & DR6_GUEST == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_rip_asks_the_mode_only_across_4_gib() {
        let asked = core::cell::Cell::new(0);
        let mode = |bits64: bool| {
            let asked = &asked;
            move || {
                asked.set(asked.get() + 1);
                bits64
            }
        };
        // 64-bit code high in the address space: no question, no wrap.
        assert_eq!(skip_rip(0xffff_ffff_8100_0000, 2, mode(true)), 0xffff_ffff_8100_0002);
        // Low code (32-bit, or 64-bit below 4 GiB): no question either.
        assert_eq!(skip_rip(0x10_0000, 3, mode(false)), 0x10_0003);
        assert_eq!(skip_rip(0xffff_fff0, 0xf, mode(false)), 0xffff_ffff, "up to the last byte below 4 GiB");
        assert_eq!(asked.get(), 0, "no VMCS read for the common exits");
        // Across 4 GiB: 32-bit code wraps, 64-bit code goes on.
        assert_eq!(skip_rip(0xffff_fffe, 3, mode(false)), 1);
        assert_eq!(skip_rip(0xffff_fffe, 3, mode(true)), 0x1_0000_0001);
        assert_eq!(asked.get(), 2);
        // The top of the 64-bit space wraps as the CPU's RIP does.
        assert_eq!(skip_rip(u64::MAX, 2, mode(true)), 1);
        assert_eq!(asked.get(), 2);
    }

    #[test]
    fn vmx_owns_pe_and_pg_and_steps_over_instructions_only() {
        assert_eq!(VMX_CR0_OWNED & (CR0_PE | CR0_PG), CR0_PE | CR0_PG);
        assert_eq!(VMX_CR0_OWNED & (CR0_CD | CR0_NW), CR0_CD | CR0_NW);
        let never = || -> u64 { panic!("asked for a string's instruction information") };
        // External interrupt, INIT, SIPI, the host's NMI: no instruction.
        for r in [1, 3, 4] {
            assert_eq!(vmx_exit(r, 0, 0, 0, 0, never), Exit::Notified(0));
        }
        assert_eq!(vmx_exit(0, 0, VMX_INTR_VALID | 2 << 8 | 2, 0, 0, never), Exit::Notified(0));
        assert_eq!(vmx_exit(0, 0x4000, VMX_INTR_VALID | 3 << 8 | 1, 0, 0, never), Exit::Exception { vector: 1, error: None, dr6: 0x4000 });
        assert_eq!(vmx_exit(0, 0, VMX_INTR_VALID | VMX_INTR_ERROR | 3 << 8 | 17, 0, 0, never),
            Exit::Exception { vector: 17, error: Some(0), dr6: 0 });
        assert_eq!(vmx_exit(15, 0, 0, 0, 0, never), Exit::Rdpmc);
        assert_eq!(vmx_exit(16, 0, 0, 0, 0, never), Exit::Rdtsc);
        assert_eq!(vmx_exit(10, 0, 0, 0, 0, never), Exit::Cpuid);
        assert_eq!(vmx_exit(30, 0x3f8 << 16 | 8, 0, 0, 0, never),
            Exit::Io { port: 0x3f8, size: 1, input: true, string: false, rep: false, addr: 0, seg: None });
        // OUTSD with a 32-bit address and FS: (instruction information).
        assert_eq!(vmx_exit(30, 0x3f8 << 16 | 16 | 32 | 3, 0, 0, 0, || 1 << 7 | 4 << 15),
            Exit::Io { port: 0x3f8, size: 4, input: false, string: true, rep: true, addr: 4, seg: Some(Seg::Fs) });
        assert_eq!(vmx_exit(48, 2, 0, 0, 0xfee0_0300, never), Exit::Mmio { gpa: 0xfee0_0300, write: true });
        assert_eq!(vmx_exit(1 << 31 | 33, 0, 0, 0, 0, never), Exit::Fatal(1 << 31 | 33));
    }

    #[test]
    fn pae_pdptes_checked_when_loaded() {
        let good = [0x1001, 0x2001, 0, 0x3001 | 1 << 3 | 1 << 4 | 0xe00];
        assert!(pae_pdptes_valid(&good, 40));
        for bad in [1u64 << 1, 1 << 2, 1 << 5, 1 << 6, 1 << 7, 1 << 8, 1 << 40, 1 << 63] {
            let mut p = good;
            p[2] = 0x4001 | bad;
            assert!(!pae_pdptes_valid(&p, 40), "{bad:#x}");
        }
        // Not present: its other bits are not looked at.
        assert!(pae_pdptes_valid(&[0x1001, 0x1e6 | 1 << 50, 0, 0], 40));
        assert!(pae_pdptes_valid(&[0x1001 | 1 << 46, 0, 0, 0], 47));
        assert!(!pae_pdptes_valid(&[0x1001 | 1 << 47, 0, 0, 0], 47));
        // Loaded when paging ends up 32-bit PAE and PG, CD, NW or PAE, PGE,
        // PSE, SMEP change; never for long mode's.
        let (pg, pae) = (CR0_PG, 1u64 << 5);
        assert!(needs_pae_pdptes(CR0_PE, CR0_PE | pg, pae, pae, 0));
        assert!(needs_pae_pdptes(CR0_PE | pg, CR0_PE | pg | CR0_CD, pae, pae, 0));
        assert!(needs_pae_pdptes(CR0_PE | pg | CR0_CD | CR0_NW, CR0_PE | pg | CR0_CD, pae, pae, 0));
        for b in [1u64 << 7, 1 << 4, 1 << 20] {
            assert!(needs_pae_pdptes(CR0_PE | pg, CR0_PE | pg, pae, pae | b, 0), "CR4 bit {b:#x}");
        }
        assert!(needs_pae_pdptes(CR0_PE | pg, CR0_PE | pg, 0, pae, 0));
        assert!(!needs_pae_pdptes(CR0_PE | pg, CR0_PE | pg | (1 << 16), pae, pae, 0), "WP alone");
        assert!(!needs_pae_pdptes(CR0_PE | pg, CR0_PE | pg, pae, pae | 1 << 9, 0), "OSFXSR alone");
        assert!(!needs_pae_pdptes(CR0_PE, CR0_PE | pg, pae, pae, 1 << 8), "long mode");
        assert!(!needs_pae_pdptes(CR0_PE, CR0_PE | pg, 0, 0, 0), "32-bit paging");
        assert!(!needs_pae_pdptes(CR0_PE | pg, CR0_PE, pae, pae, 0), "paging off");
    }

    #[test]
    fn vmx_nmi_blocked_again_after_a_faulting_iret() {
        let gp = VMX_INTR_VALID | 3 << 8 | 13 | VMX_INTR_ERROR;
        assert!(vmx_nmi_reblock(gp | VMX_INTR_NMI_UNBLOCKED, 0));
        assert!(!vmx_nmi_reblock(gp, 0), "no IRET");
        assert!(!vmx_nmi_reblock((gp & !0xff) | 8 | VMX_INTR_NMI_UNBLOCKED, 0), "#DF");
        assert!(!vmx_nmi_reblock(gp | VMX_INTR_NMI_UNBLOCKED, VMX_INTR_VALID | 14), "while delivering");
        assert!(!vmx_nmi_reblock(VMX_INTR_NMI_UNBLOCKED, 0), "not valid");
        assert_eq!(vmx_event(VMX_INTR_VALID | VMX_INTR_ERROR | 3 << 8 | 14, 0x6), Some(Event::Exc(14, Some(6))));
        assert_eq!(vmx_event(VMX_INTR_VALID | 4 << 8 | 0x80, 0), None, "INTn runs again");
    }

    #[test]
    fn svm_requeues_with_the_error_code_and_finds_lengths() {
        let pf = Event::Exc(14, Some(0x1b));
        // Never went in: MR2 has the low half only, the event as asked.
        assert_eq!(svm_requeue(SVM_EVT_VALID | SVM_EVT_ERROR | 3 << 8 | 14, Some(pf), 0, 0), Some(pf));
        // Was being delivered: EXITINTINFO and EXITINTINFO's error.
        assert_eq!(svm_requeue(0, Some(Event::Ext(0x30)), SVM_EVT_VALID | SVM_EVT_ERROR | 3 << 8 | 13, 0x10), Some(Event::Exc(13, Some(0x10))));
        assert_eq!(svm_requeue(0, None, 0, 0), None);
        assert_eq!(svm_event(SVM_EVT_VALID | 3 << 8 | 3), None, "INT3 runs again");
        // Lengths: seL4's, an I/O exit's next RIP, or none (decoded).
        assert_eq!(svm_len(0x72, 2, 0, 0x1000), 2);
        assert_eq!(svm_len(0x7b, 0, 0x1001, 0x1000), 1);
        assert_eq!(svm_len(0x7b, 0, 0x1003, 0x1000), 3);
        assert_eq!(svm_len(0x72, 0, 0, 0x1000), 0);
        assert_eq!(svm_len(0x0, 0, 0, 0x1000), 0, "MOV from CR: decoded");
    }

    #[test]
    fn svm_exits() {
        for c in 0x60..=0x63 {
            assert_eq!(svm_exit(c, 0, 0, false), Exit::Notified(0), "{c:#x}");
        }
        assert_eq!(svm_exit(0x41, 0, 0, true), Exit::NmiWindow);
        assert_eq!(svm_exit(0x41, 0, 0, false), Exit::Exception { vector: 1, error: None, dr6: 0 });
        assert_eq!(svm_exit(0x4e, 0x2, 0, false), Exit::Exception { vector: 14, error: Some(2), dr6: 0 });
        assert_eq!(svm_exit(0x6e, 0, 0, false), Exit::Rdtsc);
        assert_eq!(svm_exit(0x6f, 0, 0, false), Exit::Rdpmc);
        assert_eq!(svm_exit(0x13, 1 << 63 | 3, 0, false), Exit::Cr { cr: 3, write: true, reg: Some(3) });
        assert_eq!(svm_exit(0x13, 0, 0, false), Exit::Cr { cr: 3, write: true, reg: None });
        assert_eq!(svm_exit(0x65, 1 << 63 | 7, 0, false), Exit::Cr { cr: 0, write: true, reg: Some(7) });
        assert_eq!(svm_exit(0x65, 0, 0, false), Exit::Cr { cr: 0, write: true, reg: None });
        assert_eq!(svm_exit(0x7c, 1, 0, false), Exit::Wrmsr);
        assert_eq!(svm_exit(0x81, 0, 0, false), Exit::Hypercall, "VMMCALL");
        assert_eq!(svm_exit(0x80, 0, 0, false), Exit::Undefined, "VMRUN");
        assert_eq!(svm_exit(0x400, 2, 0xfec0_0000, false), Exit::Mmio { gpa: 0xfec0_0000, write: true });
    }

    #[test]
    fn svm_nmi_window_single_steps_and_gives_tf_back() {
        let mut s = NmiStep::default();
        let (tf, rf) = (RFLAGS_TF, RFLAGS_RF);
        // Nothing to wait for, an event going in, or masked until an IRET.
        assert_eq!(s.arm(false, false, false, true, true, 2), None);
        assert_eq!(s.arm(true, true, false, true, true, 2), None);
        assert_eq!(s.arm(true, false, true, false, true, 2), None);
        assert_eq!(s.arm(true, false, false, false, false, 2), None);
        assert_eq!(s.done(0x102), (0x102, None), "not stepping");
        // An interrupt shadow: stepped with TF and RF, both taken back.
        assert_eq!(s.arm(true, false, false, false, true, 0x202), Some(0x202 | tf | rf));
        assert_eq!(s.done(0x202 | tf | rf), (0x202, Some(false)));
        // The guest's own TF (and RF) kept.
        assert_eq!(s.arm(true, false, true, true, false, 0x202 | tf), Some(0x202 | tf | rf));
        assert_eq!(s.done(0x202 | tf), (0x202 | tf, Some(true)));
        // The guest's own RF: as the CPU left it, cleared by an instruction
        // that ran, kept by an exit before it.
        assert_eq!(s.arm(true, false, false, false, true, 0x202 | rf), Some(0x202 | tf | rf));
        assert_eq!(s.done(0x202 | tf), (0x202, Some(false)), "ran: RF cleared stays cleared");
        assert_eq!(s.arm(true, false, false, false, true, 0x202 | rf), Some(0x202 | tf | rf));
        assert_eq!(s.done(0x202 | tf | rf), (0x202 | rf, Some(false)), "did not run: RF kept");
        assert_eq!(s.guest, None);
        // Whose #DB: ours only without the guest's TF or breakpoints.
        assert!(svm_db_is_ours(false, 1 << 14));
        assert!(!svm_db_is_ours(true, 1 << 14), "its own TF");
        assert!(!svm_db_is_ours(false, 1 << 14 | 1 << 2), "its breakpoint B2");
        assert!(!svm_db_is_ours(false, 1 << 13), "its BD");
    }
}
