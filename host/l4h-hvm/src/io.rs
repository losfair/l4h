//! The I/O thread (DESIGN.md §5.11): it owns the PCI devices (the host
//! bridge and the virtio devices with their backends), so that their
//! state, which their registers, the guest's queues and blkd's and netd's
//! completions all change, has one writer and no lock.  It serves the
//! vCPU threads' calls for the devices' registers and for RAM blocks to
//! map, and signals on the notification root made for the guest's VMM:
//! queue notifications (KICK), backend completions (DONE), vmmgr's console
//! input and power requests (CTL), console output and its timer (CONSOLE),
//! trustd's answers to the attestation port (ATTEST).

use core::sync::atomic::Ordering;

use l4h_abi as abi;
use l4h_rt::host::{self, hvm as hv};

use crate::console::{self, Serial};
use crate::dev::attest::Port;
use crate::dev::blk::Blk;
use crate::dev::net::Net;
use crate::dev::pci::{self, Config};
use crate::dev::virtio_pci::{Backend as _, Irq, Transport};
use crate::iopool::Pool;
use crate::sync::Owned;
use crate::sys;
use crate::vm::{self, vm};

// No heap to box the larger one in; the slots are static.
#[allow(clippy::large_enum_variant)]
pub enum Dev {
    Blk(Transport<Blk>),
    Net(Transport<Net>),
    /// The attestation port's console device (dev/attest.rs), in slot
    /// hv::ATTEST_SLOT.
    Attest(Transport<Port<TrustdKick>>),
}

macro_rules! each {
    ($d:expr, $t:ident => $e:expr) => {
        match $d {
            Dev::Blk($t) => $e,
            Dev::Net($t) => $e,
            Dev::Attest($t) => $e,
        }
    };
}

/// trustd's kick for the guest.
pub type TrustdKick = fn();

pub struct Io {
    host_bridge: Option<Config>,
    slots: [Option<Dev>; pci::SLOTS],
    serial: Serial,
    timer: u64,
}

static IO: Owned<Io> = Owned::new(Io { host_bridge: None, slots: [const { None }; pci::SLOTS], serial: Serial::new(0, 1, false), timer: 0 });
/// The I/O pool's bounce allocator, which the disks share.
static POOL: Owned<Pool> = Owned::new(Pool::new(0));

pub fn io() -> &'static mut Io {
    // Only the I/O thread calls this, and holds one reference at a time.
    unsafe { IO.get() }
}

/// The guest's PCI devices, from its configuration: device `i` in slot
/// `i + 1`.  The disks' channels must be ready.
pub fn init() {
    let vm = vm();
    let cfg = vm.cfg;
    let pool = unsafe { POOL.get() };
    *pool = Pool::new(cfg.io_pool_size);
    let io = io();
    io.host_bridge = Some(pci::host_bridge());
    io.serial = Serial::new(cfg.guest_id, vm.tsc_hz, cfg.serial != 0);
    for (i, d) in cfg.devices[..cfg.nr_devices as usize].iter().enumerate() {
        let slot = i + 1;
        let dev = match d.kind {
            host::VDEV_BLK | host::VDEV_BLK_UNAVAILABLE => {
                let (chan, kick) = if d.kind == host::VDEV_BLK {
                    (d.chan_va as usize, Some(sys::kick(d.chan_kick_slot)))
                } else {
                    (0, None)
                };
                Dev::Blk(Transport::new(slot, vm::PCI_MMIO_BASE, Blk::new(chan, kick, hv::IO_POOL_VA, cfg.io_pool_gpa, pool, cfg.guest_id, vm.tsc_hz, vm::now)))
            }
            host::VDEV_NET => {
                let kick = sys::kick(d.chan_kick_slot);
                Dev::Net(Transport::new(slot, vm::PCI_MMIO_BASE, Net::new(d.chan_va as usize, kick, d.mac[..6].try_into().unwrap(), vm.tsc_hz / 1_000_000 * NET_POLL_US)))
            }
            k => panic!("l4h-hvm: device kind {}", k),
        };
        io.slots[slot] = Some(dev);
    }
    if cfg.attest != 0 {
        let port = Port::new(hv::ATTEST_PAGE_VA as *mut abi::AttestPage, sys::kick_trustd as TrustdKick);
        io.slots[hv::ATTEST_SLOT] = Some(Dev::Attest(Transport::new(hv::ATTEST_SLOT, vm::PCI_MMIO_BASE, port)));
    }
}

/// How long a network queue that ran dry is polled (Net::keep_polling).
const NET_POLL_US: u64 = 50;

/// What a device's interrupt does: an MSI, or its INTA#, which shares a
/// line with others'.  The machine (vm.rs) routes both.
fn irq(slot: usize) -> impl FnMut(Irq) {
    move |i| match i {
        Irq::Msi { addr, data } => vm().msi(addr, data),
        Irq::Intx(level) => vm().set_intx(slot, level),
    }
}

/// A vCPU's access to a device's configuration space or BAR.
pub fn access(space: u32, addr: u64, size: u8, write: bool, value: u64) -> u64 {
    if !matches!(size, 1 | 2 | 4 | 8) {
        return u64::MAX;
    }
    let mem = &vm().mem;
    let io = io();
    match space {
        hv::SPACE_CONFIG => {
            let (slot, func, reg) = (((addr >> 15) & 31) as usize, (addr >> 12) & 7, addr & 0xfff);
            if func != 0 || addr >= pci::ECAM_SIZE {
                return if write { 0 } else { u64::MAX >> (64 - 8 * size as u32) };
            }
            let size = size.min(4);
            if slot == 0 {
                let hb = io.host_bridge.as_mut().unwrap();
                if write {
                    hb.write(reg, size, value as u32);
                    return 0;
                }
                return hb.read(reg, size) as u64;
            }
            let Some(d) = io.slots[slot].as_mut() else {
                return if write { 0 } else { u64::MAX >> (64 - 8 * size as u32) };
            };
            each!(d, t => {
                let mut out = irq(slot);
                let r = if write {
                    t.config_write(mem, reg, size, value as u32, &mut out);
                    0
                } else {
                    t.config_read(reg, size, &mut out) as u64
                };
                // Where vCPUs find its notifications.
                vm().bar0[slot].store(t.cfg.bar_addr(0).unwrap_or(0), Ordering::Release);
                r
            })
        }
        hv::SPACE_MMIO => {
            for (slot, d) in io.slots.iter_mut().enumerate() {
                let Some(d) = d.as_mut() else { continue };
                let hit = each!(d, t => {
                    match t.bar_of(addr) {
                        Some((bar, off)) => {
                            let mut out = irq(slot);
                            Some(if write {
                                t.write(mem, bar, off, size, value, &mut out);
                                0
                            } else {
                                t.read(bar, off, size, &mut out)
                            })
                        }
                        None => None,
                    }
                });
                if let Some(v) = hit {
                    return v;
                }
            }
            if write { 0 } else { u64::MAX }
        }
        _ => u64::MAX,
    }
}

/// Whether the network queues may be polled once they run dry, given
/// vmmgr's `io_flags`: not with abi::EVENT_IO_NO_POLL (the guest is
/// capped, this monitor's boost was withdrawn, or other guests' vCPUs
/// share its core, whose CPU the polling would take at PRIO_VMM).
pub fn poll_allowed(io_flags: u64) -> bool {
    io_flags & abi::EVENT_IO_NO_POLL == 0
}

/// poll_allowed, for every network device, before each turn of them.
fn refresh_polling() {
    let allowed = poll_allowed(sys::io_flags());
    for d in io().slots.iter_mut().flatten() {
        if let Dev::Net(t) = d {
            t.backend.set_poll_allowed(allowed);
        }
    }
}

/// Queue notifications, and work a device left for another turn.
pub fn kicked() {
    let vm = vm();
    refresh_polling();
    for (slot, d) in io().slots.iter_mut().enumerate() {
        let Some(d) = d.as_mut() else { continue };
        let bits = vm.kicks.take(slot);
        each!(d, t => {
            let bits = bits | t.backend.more() | t.backend.polling();
            if bits != 0 {
                t.poll(&vm.mem, bits, &mut irq(slot));
            }
        });
    }
}

/// Backends' completions, in two passes.  The disks share the I/O pool's
/// bounce pages: every device's completions first, then each device that
/// waits for room tries again, whichever slot freed it (a disk in an
/// earlier slot would otherwise wait for a completion of its own that may
/// never come).
pub fn completed() {
    let vm = vm();
    refresh_polling();
    for (slot, d) in io().slots.iter_mut().enumerate() {
        let Some(d) = d.as_mut() else { continue };
        each!(d, t => t.complete(&vm.mem, &mut irq(slot)));
    }
    for (slot, d) in io().slots.iter_mut().enumerate() {
        let Some(d) = d.as_mut() else { continue };
        each!(d, t => t.retry(&vm.mem, &mut irq(slot)));
    }
}

/// trustd answered the attestation port's request (vmmgr's signal).
pub fn attested() {
    if let Some(Dev::Attest(t)) = io().slots[hv::ATTEST_SLOT].as_mut() {
        t.complete(&vm().mem, &mut irq(hv::ATTEST_SLOT));
    }
}

/// vmmgr wrote the console page: input for the UART, a power request.
pub fn control() {
    let vm = vm();
    match console::power_request() {
        // The guest shuts down when it sees its power button.
        Some(abi::POWER_OFF) => vm.power_button(),
        Some(_) => sys::power(abi::POWER_REBOOT),
        None => {}
    }
    vm.console_input();
}

/// Console output to pass on, and the timer for a partial line.
pub fn console_turn() {
    let io = io();
    io.serial.drain(&vm().console, vm::now());
    let d = io.serial.deadline();
    if d != io.timer {
        io.timer = d;
        sys::io_timer(d);
    }
}

/// The I/O thread's timer as console_turn last set it.
pub fn timer() -> u64 {
    io().timer
}

/// While devices poll (more): spin, without the kernel, until one may
/// have work, a vCPU kicked, or `spin` ticks pass.
pub fn poll_spin(spin: u64) {
    let vm = vm();
    let start = vm::now();
    loop {
        for (slot, d) in io().slots.iter().enumerate() {
            let Some(d) = d.as_ref() else { continue };
            if vm.kicks.0[slot].load(Ordering::Relaxed) != 0 || each!(d, t => t.backend.ready(&vm.mem, &t.queues)) {
                return;
            }
        }
        if vm::now().wrapping_sub(start) >= spin {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Whether a device left work for another turn: there now, to take at
/// once.
pub fn more() -> bool {
    io().slots.iter().flatten().any(|d| each!(d, t => t.backend.more() != 0))
}

/// Whether a device polls queues that ran dry (only while allowed:
/// refresh_polling): work that may come, which the I/O thread spins for.
pub fn polling() -> bool {
    io().slots.iter().flatten().any(|d| each!(d, t => t.backend.polling() != 0))
}

