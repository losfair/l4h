//! What a VM exit is, from the words seL4's VMEnter gives for it, on VT-x
//! and AMD-V: the part of vmx.rs and svm.rs that is arithmetic only, so
//! that it runs on the build host too (tests/hvm.rs).

use super::{Event, Exit};
use crate::x86::decode::Seg;

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
        18..=27 | 36 | 39 | 50 | 51 | 53 | 58 => Exit::Undefined,
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
        0x73 | 0x7a | 0x80..=0x88 | 0x8a..=0x8c | 0x8e => Exit::Undefined,
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
        assert_eq!(svm_exit(0x7c, 1, 0, false), Exit::Wrmsr);
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
