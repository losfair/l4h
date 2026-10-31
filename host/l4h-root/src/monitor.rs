//! A minimal monitor on the serial console (COM1, the GCE serial port, or
//! the serial_port and serial_irq settings, e.g. COM2 for Supermicro
//! serial-over-LAN),
//! for when dom0 is not usable (DESIGN.md §10.1): list, destroy,
//! restart-dom0 (which vmmgr runs), and reboot.  The kernel keeps printing to the same port; we only take
//! its receive side.

use sel4::cap_type;

use crate::Host;
use crate::mem::Alloc;

/// Badge of the monitor's interrupt on the root task's bound notification.
pub const MONITOR_BADGE: u64 = 1 << 41;

/// seL4 user IRQ vector for the serial port.
#[cfg(target_arch = "x86_64")]
const VECTOR: u64 = crate::pci::VECTOR_MONITOR;

/// Longest input line; the rest of a longer one is dropped.
const LINE_MAX: usize = 80;

pub struct Monitor {
    port: u64,
    /// The UART's first I/O port (x86).
    #[cfg(target_arch = "x86_64")]
    base: u16,
    irq: Option<sel4::cap::IrqHandler>,
    /// The input line so far: printable ASCII.
    line: [u8; LINE_MAX],
    len: usize,
}

impl Monitor {
    #[cfg(target_arch = "x86_64")]
    pub fn new(alloc: &mut Alloc, _devmem: &mut crate::devmem::DevMem, ntfn: sel4::cap::Notification, base: u16, irq: u64, iommu: &mut crate::iommu::Iommu) -> Option<Self> {
        use sel4::init_thread::slot;
        let abs = |s: usize| slot::CNODE.cap().absolute_cptr(sel4::init_thread::Slot::<cap_type::Null>::from_index(s).cap());
        let port = alloc.slots.alloc();
        slot::IO_PORT_CONTROL.cap().ioport_control_issue(base as u64, base as u64 + 7, &abs(port)).ok()?;
        let mut m = Self { port: port as u64, base, irq: None, line: [0; LINE_MAX], len: 0 };
        // Unmapped I/O ports read as all ones. In particular, 0xff has
        // DR set, so never install a receive handler for an absent UART.
        if m.inb(5) == 0xff {
            info!("l4h-root: serial monitor unavailable on port {:#x} (no UART)", base);
            return None;
        }
        m.out(1, 0);
        let remap = match iommu.ioapic_irq(0, VECTOR) {
            Ok(remap) => remap,
            Err(reason) => {
                info!("l4h-root: serial monitor unavailable: {}", reason);
                return None;
            }
        };
        let irq_slot = alloc.slots.alloc();
        let dst = abs(irq_slot);
        if let Some(handle) = remap {
            let err = sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_IRQControl_GetIOAPICRemapped(
                slot::IRQ_CONTROL.cap().bits(), dst.root().bits(), dst.path().bits(), dst.path().depth().try_into().unwrap(),
                0, irq, 0, 0, VECTOR, handle as u64));
            if let Some(err) = sel4::Error::from_sys(err) {
                info!("l4h-root: serial monitor: remapped IRQ failed: {:?}", err);
                return None;
            }
        } else {
            slot::IRQ_CONTROL.cap().irq_control_get_ioapic(0, irq, 0, 0, VECTOR, &dst).ok()?;
        }
        let irq = sel4::init_thread::Slot::<cap_type::IrqHandler>::from_index(irq_slot).cap();
        let badged = alloc.slots.alloc();
        abs(badged)
            .mint(&slot::CNODE.cap().absolute_cptr(ntfn), sel4::CapRights::write_only(), MONITOR_BADGE)
            .ok()?;
        irq.irq_handler_set_notification(sel4::init_thread::Slot::<cap_type::Notification>::from_index(badged).cap()).ok()?;
        m.irq = Some(irq);
        // Receive-data interrupt; OUT2 routes UART interrupts to the PIC/IOAPIC.
        m.out(1, 0x01);
        m.out(4, m.inb(4) | 0x08);
        info!("l4h-root: serial monitor on port {:#x} ({}interrupts, type 'help')",
            base, if remap.is_some() { "remapped " } else { "" });
        Some(m)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn new(alloc: &mut Alloc, devmem: &mut crate::devmem::DevMem, ntfn: sel4::cap::Notification, _base: u16, _irq: u64, _iommu: &mut crate::iommu::Iommu) -> Option<Self> {
        use sel4::init_thread::slot;
        use sel4::{CapRights, VmAttributes};
        use crate::mem::ObjCtx;
        const UART_VA: usize = crate::layout::UART.base;
        let frames = devmem.frames(&mut alloc.slots, 0x0900_0000, 4096)?;
        crate::vspace::map_frame(&mut ObjCtx::global(alloc), slot::VSPACE.cap(), crate::devmem::granule(frames.start),
            UART_VA, CapRights::read_write(), VmAttributes::EXECUTE_NEVER);
        let irq_slot = alloc.slots.alloc();
        let dst = crate::component::abs_of(sel4::init_thread::Slot::<cap_type::Null>::from_index(irq_slot).cap());
        slot::IRQ_CONTROL.cap().irq_control_get_trigger_core(33, false, 0, &dst).ok()?;
        let irq = sel4::init_thread::Slot::<cap_type::IrqHandler>::from_index(irq_slot).cap();
        let badge_slot = alloc.slots.alloc();
        let badge = sel4::init_thread::Slot::<cap_type::Notification>::from_index(badge_slot).cap();
        crate::component::abs_of(badge).mint(&crate::component::abs_of(ntfn), CapRights::write_only(), MONITOR_BADGE).ok()?;
        irq.irq_handler_set_notification(badge).ok()?;
        unsafe {
            ((UART_VA + 0x44) as *mut u32).write_volatile(0x7ff); // clear pending IRQs
            ((UART_VA + 0x38) as *mut u32).write_volatile((1 << 4) | (1 << 6)); // RX, RX timeout
        }
        irq.irq_handler_ack().ok()?;
        info!("l4h-root: serial monitor on PL011 (type 'help')");
        Some(Self { port: UART_VA as u64, irq: Some(irq), line: [0; LINE_MAX], len: 0 })
    }

    #[cfg(target_arch = "x86_64")]
    fn inb(&self, off: u16) -> u8 {
        sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_X86_IOPort_In8(self.port, self.base + off).result as u8)
    }

    #[cfg(target_arch = "x86_64")]
    fn out(&self, off: u16, v: u8) {
        sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_X86_IOPort_Out8(self.port, (self.base + off) as u64, v as u64));
    }

    #[cfg(target_arch = "aarch64")]
    fn inb(&self, off: u16) -> u8 {
        unsafe {
            if off == 5 {
                (((self.port as usize + 0x18) as *const u32).read_volatile() & (1 << 4) == 0) as u8
            } else {
                (self.port as *const u32).read_volatile() as u8
            }
        }
    }

    /// The UART interrupted: collect input, run complete lines.
    pub fn interrupt(h: &mut Host) {
        let Some(mut m) = h.monitor.take() else { return };
        loop {
            let status = m.inb(5);
            // Keep the receive path safe if the UART becomes unavailable
            // after the startup probe, too. PL011 returns only 0 or 1 here.
            if status == 0xff || status & 1 == 0 { break; }
            let c = m.inb(0);
            match c {
                b'\r' | b'\n' => {
                    let (line, len) = (m.line, m.len);
                    m.len = 0;
                    let line = core::str::from_utf8(&line[..len]).unwrap_or("").trim();
                    if !line.is_empty() {
                        run(h, line);
                    }
                }
                0x08 | 0x7f => m.len = m.len.saturating_sub(1),
                c if (0x20..0x7f).contains(&c) && m.len < LINE_MAX => {
                    m.line[m.len] = c;
                    m.len += 1;
                }
                _ => {}
            }
        }
        #[cfg(target_arch = "aarch64")]
        unsafe { ((m.port + 0x44) as *mut u32).write_volatile(0x7ff); }
        if let Some(irq) = m.irq { let _ = irq.irq_handler_ack(); }
        h.monitor = Some(m);
    }
}

/// A guest's state as vmmgr reports it (GuestStatus::state).
pub fn state_name(state: u8) -> &'static str {
    match state.wrapping_sub(1) as u32 {
        l4h_abi::VM_CREATED => "Created",
        l4h_abi::VM_RUNNING => "Running",
        l4h_abi::VM_STOPPED => "Stopped",
        _ => "?",
    }
}

/// A guest's name as vmmgr reports it.
pub fn name(g: &l4h_host::vmmgr::GuestStatus) -> &str {
    let n = g.name.iter().position(|&c| c == 0).unwrap_or(g.name.len());
    core::str::from_utf8(&g.name[..n]).unwrap_or("?")
}

fn run(h: &mut Host, line: &str) {
    let mut words = line.split_whitespace();
    let cmd = words.next().unwrap_or("");
    // Root's own, which work whatever state vmmgr is in.
    match cmd {
        "help" => {
            log!("monitor: help | list | info | destroy <vm> | restart-dom0 | reboot");
            return;
        }
        "info" => {
            log!(
                "monitor: {} cores, {} MiB free of {} MiB ({} MiB reported to the hypervisor), {} disk(s), {} NIC(s)",
                h.info.cores, h.alloc.free_bytes() >> 20, h.total_bytes >> 20, h.alloc.reported_bytes() >> 20,
                h.disks.len(), h.netd.nics.len()
            );
            return;
        }
        // Every guest stops without notice: the way out when vmmgr, or
        // dom0, no longer answers.
        "reboot" => {
            let e = crate::reset::reboot(h, "monitor");
            log!("monitor: reboot failed: error {}", e);
            return;
        }
        _ => {}
    }
    let Some(v) = &h.vmmgr else {
        log!("monitor: vmmgr is not running");
        return;
    };
    // Guests are vmmgr's: it runs what changes them.
    let send = |cmd, arg| if !v.monitor(cmd, arg) { log!("monitor: vmmgr is busy, try again") };
    match cmd {
        "list" => {
            for id in 0..crate::MAX_GUESTS {
                let Some(g) = v.guest(id) else { continue };
                log!(
                    "monitor: vm {} '{}': {}, {} vCPU(s), {} MiB{}",
                    id, name(&g), state_name(g.state), g.vcpus, g.ram_mb,
                    if g.dom0 != 0 { ", dom0" } else { "" }
                );
            }
        }
        "destroy" => match words.next().and_then(|w| w.parse::<u32>().ok()) {
            Some(id) if v.guest(id as usize).is_some_and(|g| g.dom0 == 0) => send(l4h_host::vmmgr::MONITOR_DESTROY, id),
            _ => log!("monitor: destroy <vm> (not dom0; use restart-dom0)"),
        },
        "restart-dom0" => send(l4h_host::vmmgr::MONITOR_RESTART_DOM0, 0),
        _ => log!("monitor: unknown command '{}' (try 'help')", cmd),
    }
}
