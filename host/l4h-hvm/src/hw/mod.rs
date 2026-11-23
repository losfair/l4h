//! A vCPU's hardware: seL4's VCPU object, on VT-x (vmx.rs) or AMD-V
//! (svm.rs), behind one interface (DESIGN.md §5.11).  seL4 chooses the
//! backend by the CPU's vendor, and so do we.  A thread enters its guest
//! with seL4_VMEnter on its own TCB, to which vmmgr bound the VCPU and the
//! guest's EPT; the call returns at an exit for us, or when a notification
//! (an interrupt for the guest, its timer) ends it.  The guest's registers
//! come with the exit; others are read and written by invocations of the
//! VCPU, each a system call, so what an exit's handling reads is cached
//! until the next entry.

#[cfg(not(test))]
use l4h_rt::sel4;

use crate::x86::decode::{Mode, Seg};
use crate::x86::walk::Paging;

pub mod exits;
#[cfg(not(test))]
pub mod svm;
#[cfg(not(test))]
pub mod vmx;

/// An event to inject at entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// An external interrupt (from the local APIC).
    Ext(u8),
    Nmi,
    /// A hardware exception, with its error code.
    Exc(u8, Option<u32>),
}

/// Why VMEnter returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// A notification, with its badge (badges::hvm_vcpu).
    Notified(u64),
    /// IN or OUT of `size` bytes at `port`; INS and OUTS (`string`, with
    /// REP), whose address size is `addr` bytes.
    /// OUTS's segment (`seg`), if the CPU said (else decode its prefixes).
    Io { port: u16, size: u8, input: bool, string: bool, rep: bool, addr: u8, seg: Option<Seg> },
    /// An access to guest-physical `gpa` the EPT does not map: RAM not yet
    /// mapped, or a device.
    Mmio { gpa: u64, write: bool },
    Rdmsr,
    Wrmsr,
    Cpuid,
    Hlt,
    Xsetbv,
    /// MOV to (`write`) or from CR `cr`, the register `reg` if the CPU
    /// said which (else decode the instruction); CLTS and LMSW.
    Cr { cr: u8, write: bool, reg: Option<u8> },
    Clts,
    Lmsw(u16),
    /// MOV to or from DR `dr`, as Cr.
    Dr { dr: u8, write: bool, reg: Option<u8> },
    /// The guest can take an interrupt (an NMI) now.
    IrqWindow,
    NmiWindow,
    /// IRET (AMD-V's NMI tracking).
    Iret,
    /// An exception seL4 always intercepts (#DB, #AC, #MC), with its error
    /// code and #DB's DR6 bits.
    Exception { vector: u8, error: Option<u32>, dr6: u64 },
    /// Triple fault (shutdown).
    Shutdown,
    /// VMCALL or VMMCALL: a KVM hypercall, none of which we have.
    Hypercall,
    /// MONITOR or MWAIT, RDTSCP, VMX or SVM instructions: #UD for the
    /// guest.
    Undefined,
    /// INVD, WBINVD, PAUSE, INVLPG: nothing to do but skip.
    Nop,
    /// RDTSC (if the CPU makes it exit).
    Rdtsc,
    /// RDPMC: #GP, as without performance counters.
    Rdpmc,
    /// A task switch (not emulated: the guest stops).
    TaskSwitch,
    /// VM entry failed, or an exit we do not know: the raw reason.
    Fatal(u64),
}

/// The guest's general-purpose registers, by x86's numbers (0 RAX ... 15
/// R15), and seL4's order of the 15 it keeps (not RSP).
pub type Gprs = [u64; 16];
pub const SEL4_ORDER: [usize; 15] = [0, 3, 1, 2, 6, 7, 5, 8, 9, 10, 11, 12, 13, 14, 15];

pub trait Hw {
    /// Run the guest until an exit, injecting `ev` first; exit as soon as it
    /// can take an interrupt (an NMI) if `irq_window` (`nmi_window`).
    fn enter(&mut self, ev: Option<Event>, irq_window: bool, nmi_window: bool) -> Exit;
    /// An event that was being delivered at the last exit, or was not
    /// delivered at the last entry: inject it again.
    fn take_pending(&mut self) -> Option<Event>;
    fn gprs(&mut self) -> &mut Gprs;
    /// RSP (not among the registers an exit brings).
    fn rsp(&mut self) -> u64;
    fn set_rsp(&mut self, v: u64);
    fn mark_gprs(&mut self);
    fn rip(&self) -> u64;
    fn rflags(&self) -> u64;
    fn set_rflags(&mut self, v: u64);
    /// The length of the instruction that exited, if the CPU said (0 if
    /// it did not: AMD-V without next-RIP saving).
    fn instr_len(&self) -> u64;
    /// Step over it: RIP past it, and no interrupt shadow.
    fn skip(&mut self, len: u64);
    /// Whether the guest can take an interrupt (IF, no STI or MOV SS
    /// shadow), and an NMI.
    fn interruptible(&self) -> bool;
    fn nmi_blocked(&self) -> bool;
    fn paging(&mut self) -> Paging;
    fn mode(&mut self) -> Mode;
    fn cpl(&mut self) -> u8;
    fn seg_base(&mut self, s: Seg) -> u64;
    /// CR0 and CR4 as the guest sees them.
    fn cr0(&mut self) -> u64;
    fn cr4(&mut self) -> u64;
    /// MOV to CR0 or CR4 of a value the caller checked: false for #GP.
    fn set_cr0(&mut self, v: u64) -> bool;
    fn set_cr4(&mut self, v: u64) -> bool;
    /// The MSRs the VCPU holds (EFER, PAT, the syscall MSRs, the segment
    /// bases, SYSENTER): Some(None) for #GP, None if it is not one.
    fn rdmsr(&mut self, msr: u32) -> Option<Option<u64>>;
    fn wrmsr(&mut self, msr: u32, v: u64) -> Option<bool>;
    fn set_xcr0(&mut self, v: u64) -> bool;
    fn set_tsc_offset(&mut self, off: u64);
    /// CR2, for a page fault about to be injected.
    fn set_cr2(&mut self, v: u64);
    /// The guest's TPR changed (AMD-V keeps it as V_TPR).
    fn set_tpr(&mut self, _tpr: u8) {}
    /// Flush the guest's own translations before it next runs.
    fn flush_tlb(&mut self);
    /// Start in real mode at `vector`:0 (a SIPI).
    fn start_real_mode(&mut self, vector: u8);
    /// Start in 64-bit mode (the boot protocol's state, boot.rs).
    fn start_long_mode(&mut self, entry: &crate::boot::Entry);
}

#[cfg(not(test))]
const VM_ENTER_WORDS: usize = 30;

/// Request the full VMEnter reply. The inputs are RIP, controls and event.
/// The first four reply words return in registers and the rest in the IPC
/// buffer. The syscall also returns the fault indicator and notification badge.
#[cfg(not(test))]
pub fn vmenter(rip: u64, controls: u64, event: u64) -> (bool, u64) {
    let (mut mr0, mut mr1, mut mr2, mut mr3) = (rip, controls, event, 0u64);
    let (info, badge): (u64, u64);
    let sys = sel4::sys::syscall_id::VMEnter as i64 as u64;
    unsafe {
        core::arch::asm!(
            "mov r14, rsp",
            "syscall",
            "mov rsp, r14",
            in("rdx") sys,
            inout("rdi") 0u64 => badge,
            inout("rsi") VM_ENTER_WORDS as u64 => info,
            inout("r10") mr0,
            inout("r8") mr1,
            inout("r9") mr2,
            inout("r15") mr3,
            in("r12") 0u64,
            lateout("rcx") _,
            lateout("r11") _,
            lateout("r14") _,
        );
    }
    sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[..4].copy_from_slice(&[mr0, mr1, mr2, mr3]));
    (info == 1, badge)
}

/// The message registers of an exit (MRs 0-29), read at once: any
/// invocation of the VCPU after VMEnter overwrites them.
#[cfg(not(test))]
pub fn exit_mrs() -> [u64; VM_ENTER_WORDS] {
    sel4::with_ipc_buffer(|b| {
        let mut m = [0; VM_ENTER_WORDS];
        m.copy_from_slice(&b.msg_regs()[..VM_ENTER_WORDS]);
        m
    })
}

/// Write the 15 registers seL4 keeps.
#[cfg(not(test))]
pub fn write_gprs(vcpu: u64, g: &Gprs) {
    let c = sel4::sys::seL4_VCPUContext {
        eax: g[0], ebx: g[3], ecx: g[1], edx: g[2], esi: g[6], edi: g[7], ebp: g[5],
        r8: g[8], r9: g[9], r10: g[10], r11: g[11], r12: g[12], r13: g[13], r14: g[14], r15: g[15],
    };
    let e = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_X86_VCPU_WriteRegisters(vcpu, &c));
    assert_eq!(e, 0, "VCPU WriteRegisters");
}

/// VCPU MSRs seL4 switches (Read/WriteMSR): its own numbers for CR2 and
/// XCR0.
#[cfg(not(test))]
pub const SEL4_MSR_XCR0: u64 = 0xffff_fffe;
#[cfg(not(test))]
pub const SEL4_MSR_CR2: u64 = 0xffff_ffff;

/// The XCR0 features the VCPUs take: `want` (the host's, cpuid.rs's
/// XCR0_ALLOWED) if VCPU `vcpu` takes it, else x87, SSE and AVX (seL4's
/// KernelXSaveFeatureSet 7).  Back to XCR0's reset value after.
#[cfg(not(test))]
pub fn probe_xcr0(vcpu: u64, want: u64) -> u64 {
    // The whole set, then without one group, then without both: a kernel
    // may allow AVX-512 without PKRU or the other way round.
    let tries = [want, want & !crate::x86::cpuid::XCR0_PKRU, want & !crate::x86::cpuid::XCR0_AVX512, want & 7];
    let got = tries.into_iter().find(|&x| vcpu_write_msr(vcpu, SEL4_MSR_XCR0, x)).unwrap_or(want & 7);
    vcpu_write_msr(vcpu, SEL4_MSR_XCR0, 1);
    got
}

/// FL4's VCPU MSR for leaving a VM exit's IBPB to the next switch to
/// another address space.  This monitor's address space is its guest's
/// alone (guest RAM, its I/O pool and rings, its own state), so guest
/// branch predictions reaching it expose nothing of another domain;
/// every other address space still gets the IBPB first.  An error (seL4,
/// an FL4 without it) leaves the IBPB at every exit.
#[cfg(not(test))]
pub const FL4_MSR_VM_IBPB_DEFER: u64 = 0xffff_fffd;

#[cfg(not(test))]
pub fn vcpu_write_msr(vcpu: u64, msr: u64, v: u64) -> bool {
    sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_X86_VCPU_WriteMSR(vcpu, msr, v)).error == 0
}

#[cfg(not(test))]
pub fn vcpu_read_msr(vcpu: u64, msr: u64) -> Option<u64> {
    let r = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_X86_VCPU_ReadMSR(vcpu, msr));
    (r.error == 0).then_some(r.value)
}

#[cfg(not(test))]
pub fn flush(vcpu: u64) {
    let e = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_X86_VCPU_FlushTLB(vcpu));
    assert_eq!(e, 0, "VCPU FlushTLB");
}
