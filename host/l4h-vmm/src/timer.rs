//! One TCB timer for console gaps/partial lines and memory-state retries.
//! The VMM arms their earliest deadline before receiving again. A timer
//! signal uses CONSOLE; received() also checks memory's retry deadline.

use l4h_rt::{cap, host, sel4};

pub struct Timer {
    armed: u64,
}

impl Timer {
    pub const fn new() -> Self {
        Self { armed: 0 }
    }

    pub fn update(&mut self, console: u64, memory: u64) {
        let deadline = match (console, memory) {
            (0, b) => b,
            (a, 0) => a,
            (a, b) => a.min(b),
        };
        if deadline != self.armed {
            self.armed = deadline;
            self.set();
        }
    }

    /// An expiry while the notification was unbound is consumed without
    /// a signal. Rearm the original deadline, including one now past.
    pub fn rearm(&self) {
        if self.armed != 0 {
            self.set();
        }
    }

    fn set(&self) {
        let tcb = cap::<sel4::cap_type::Tcb>(host::SLOT_TCB);
        let error = sel4::with_ipc_buffer_mut(|b| b.inner_mut().seL4_TCB_SetTimer(tcb.bits(), self.armed, host::badges::vmm::CONSOLE));
        assert_eq!(error, 0, "VMM timer");
    }
}
