//! A VCPU as a vCPU thread enters it: seL4_ARM_VCPU_Run, with the state
//! area of its IPC buffer (regs.rs).  A trait, so that tests/hvm-arm64.rs
//! can run vcpu.rs against a model of it.

use super::regs::State;

/// Why seL4_ARM_VCPU_Run returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// An event on the thread's notification (the badge).
    Interrupt(u64),
    /// A Stage-2 fault.
    VmFault { esr: u64, ipa: u64, far: u64 },
    /// Any other synchronous trap (WFI, HVC, SMC, MSR/MRS).
    VcpuFault { esr: u64 },
    VgicMaint,
    /// The virtual timer's PPI fired, and FL4 masked it.
    Vppi(u64),
    /// FL4 refused to enter it.
    Refused(u64),
}

pub trait Hw {
    /// The state area: what `run` loads and saves, by group.
    fn state(&mut self) -> &mut State;
    /// Enter the guest: load the groups `load`, save the groups `save`.
    fn run(&mut self, load: u64, save: u64) -> Exit;
    /// A register of FL4's VCPU that no group here carries.
    fn read_reg(&mut self, r: usize) -> u64;
    fn write_reg(&mut self, r: usize, v: u64);
}

#[cfg(target_arch = "aarch64")]
pub use imp::Vcpu;

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::*;
    use l4h_rt::host::hvm::{self as hv, arm::VCPU_STATE_OFFSET};
    use l4h_rt::sel4;

    /// FL4's stop reasons (seL4_ARM_VCPURunStop_*).
    const STOP_INTERRUPT: u64 = 0;
    const STOP_VMFAULT: u64 = 1;
    const STOP_VCPUFAULT: u64 = 2;
    const STOP_VGIC_MAINT: u64 = 3;
    const STOP_VPPI: u64 = 4;

    /// vCPU `v`'s VCPU, entered from its own thread.
    pub struct Vcpu {
        obj: u64,
        state: *mut State,
    }

    impl Vcpu {
        pub fn new(v: usize) -> Self {
            Vcpu { obj: hv::SLOT_VCPU_OBJ + v as u64, state: (hv::vcpu_ipcbuf_va(v) + VCPU_STATE_OFFSET) as *mut State }
        }
    }

    impl Hw for Vcpu {
        fn state(&mut self) -> &mut State {
            // In this thread's IPC buffer frame, past its message registers.
            unsafe { &mut *self.state }
        }

        fn run(&mut self, load: u64, save: u64) -> Exit {
            let obj = self.obj;
            let r = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_ARM_VCPU_Run(obj, VCPU_STATE_OFFSET as u64, load, save));
            if r.error != 0 {
                return Exit::Refused(r.error as u64);
            }
            match r.stop {
                STOP_INTERRUPT => Exit::Interrupt(r.w1),
                STOP_VMFAULT => Exit::VmFault { esr: r.w1, ipa: r.w2, far: r.w3 },
                STOP_VCPUFAULT => Exit::VcpuFault { esr: r.w1 },
                STOP_VGIC_MAINT => Exit::VgicMaint,
                STOP_VPPI => Exit::Vppi(r.w1),
                s => Exit::Refused(s),
            }
        }

        fn read_reg(&mut self, r: usize) -> u64 {
            let obj = self.obj;
            let ret = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_ARM_VCPU_ReadRegs(obj, r as u64));
            assert_eq!(ret.error, 0, "VCPU register {}", r);
            ret.value
        }

        fn write_reg(&mut self, r: usize, v: u64) {
            let obj = self.obj;
            let e = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_ARM_VCPU_WriteRegs(obj, r as u64, v));
            assert_eq!(e, 0, "VCPU register {}", r);
        }
    }
}
