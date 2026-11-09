//! l4h-vmm: the per-guest virtual machine monitor.  Serves the guest's
//! hypercalls and implements its virtio-l4h devices on top of the host
//! drivers (blkd, netd).  See DESIGN.md §9.

#![no_std]
#![no_main]

mod blk;
mod console;
mod dev;
mod gpu;
mod guest;
mod mem;
mod memhp;
mod net;
mod virtq;

use l4h_rt::host::errno::Errno;
use l4h_abi as abi;
use l4h_rt::host::badges::vmm as recv;
use l4h_rt::host::hypercall::{Sender as Guest, call as hypercall};
use l4h_rt::ipc::Endpoint;
use l4h_rt::host::vmmgr::call::Client as _;
use l4h_rt::host::{self, VmmConfig};
use l4h_rt::sel4;
use l4h_rt::{Info, cap};
use sel4::cap_type;

use crate::console::Console;
use crate::dev::Device;
use crate::guest::{GuestMem, Vcpus};
use crate::memhp::MemDev;

enum Dev {
    Blk(Device<blk::Blk>),
    Net(Device<net::Net>),
    Gpu(Device<gpu::Gpu>),
    Usb(Usb),
}

/// A USB controller (DESIGN.md §9.7): usbd and the guest share its queue
/// area, which the VMM never maps.  It only relays usbd's signal to the
/// vCPU the guest routed the device's event to.
struct Usb {
    event: u32,
    vcpu: usize,
    badge: u64,
}
const _: () = assert!(core::mem::size_of::<[Option<Dev>; host::VMM_MAX_DEVICES]>() + (64 << 10) <= host::VMM_STACK_SIZE);

impl Dev {
    fn op(&mut self, mem: &GuestMem, vcpus: &Vcpus, op: u64, a: u64, b: u64) -> u64 {
        match self {
            Dev::Blk(d) => d.op(mem, vcpus, op, a, b),
            Dev::Net(d) => d.op(mem, vcpus, op, a, b),
            Dev::Gpu(d) => d.op(mem, vcpus, op, a, b),
            Dev::Usb(u) => match op {
                abi::usb::DEVOP_IRQ_VCPU if (a as usize) < vcpus.n => {
                    u.vcpu = a as usize;
                    0
                }
                _ => u64::MAX,
            },
        }
    }

    fn poll(&mut self, mem: &GuestMem, vcpus: &Vcpus) {
        match self {
            Dev::Blk(d) => d.poll(mem, vcpus, 0),
            Dev::Net(d) => d.poll(mem, vcpus, 0),
            Dev::Gpu(d) => d.poll(mem, vcpus, 0),
            Dev::Usb(_) => {}
        }
    }

    fn complete(&mut self, mem: &GuestMem, vcpus: &Vcpus) {
        match self {
            Dev::Blk(d) => d.complete(mem, vcpus),
            Dev::Net(d) => d.complete(mem, vcpus),
            Dev::Gpu(d) => d.complete(mem, vcpus),
            Dev::Usb(_) => {}
        }
    }
}

/// The guest's hypercalls, as l4h_host::hypercall::call declares them.
struct Hypercalls<'a> {
    cfg: &'a VmmConfig,
    tsc_hz: u64,
    mem: &'a GuestMem,
    vcpus: &'a Vcpus,
    devs: &'a mut [Option<Dev>; host::VMM_MAX_DEVICES],
    console: &'a mut Console,
    root_ep: Endpoint,
}

impl hypercall::Server for Hypercalls<'_> {
    fn power(&mut self, _: Guest, how: u64) -> Result<(), Errno> {
        // What the guest printed before (a crash report) goes out before
        // it stops.  vmmgr stops the vCPUs, which cancels this call: do not
        // reply.
        self.console.flush(self.vcpus);
        let _ = self.root_ep.guest_power(how);
        Err(host::wire::NO_REPLY)
    }

    fn dev_write(&mut self, _: Guest, device: usize, op: u64, a: u64, b: u64) -> Result<u64, Errno> {
        let d = self.devs.get_mut(device).and_then(|d| d.as_mut()).ok_or(host::wire::EINVAL)?;
        Ok(d.op(self.mem, self.vcpus, op, a, b))
    }

    fn get_time(&mut self, _: Guest) -> Result<u64, Errno> {
        Ok(wall_clock_ns(self.cfg, self.tsc_hz))
    }
}

/// Nanoseconds since the Unix epoch (0 if the host does not know).
fn wall_clock_ns(cfg: &VmmConfig, hz: u64) -> u64 {
    if cfg.epoch_ns == 0 || hz == 0 {
        return 0;
    }
    let ticks = host::ticks::now().wrapping_sub(cfg.epoch_ticks);
    cfg.epoch_ns + (ticks as u128 * 1_000_000_000 / hz as u128) as u64
}

fn main(info: &'static Info) -> ! {
    let cfg: &VmmConfig = unsafe { info.config() };
    let tsc_hz = info.header().tsc_hz;
    let mem = GuestMem { base: host::IO_POOL_VA, gpa: cfg.io_pool_gpa, size: cfg.io_pool_size };
    let vcpus = Vcpus { n: cfg.nr_vcpus as usize };

    // Block backends announce themselves ready (capacity known) on the
    // channel and signal our notification.
    let ntfn = cap::<cap_type::Notification>(host::SLOT_NTFN);
    let tcb = cap::<cap_type::Tcb>(host::SLOT_TCB);
    let devices = &cfg.devices[..cfg.nr_devices as usize];
    while !devices
        .iter()
        .filter(|d| d.kind == host::VDEV_BLK)
        .all(|d| unsafe { core::ptr::addr_of!((*(d.chan_va as *const host::blk::Channel)).ready).read_volatile() } != 0)
    {
        ntfn.wait();
    }

    // Devices by guest boot info index. All share kick/done badge bits;
    // each device checks its own kick word and backend ring for work.
    let mut devs: [Option<Dev>; host::VMM_MAX_DEVICES] = [const { None }; host::VMM_MAX_DEVICES];
    // Receive rings that leave room in the I/O pool for disk requests.
    let nics = devices.iter().filter(|d| d.kind == host::VDEV_NET).count();
    let rx_queue = host::iopool::rx_queue_size(cfg.io_pool_size as usize, nics);
    for d in devices.iter() {
        let idx = d.guest_index as usize;
        assert!(idx < host::VMM_MAX_DEVICES, "l4h-vmm: device index {} out of range", idx);
        let dev = match d.kind {
            host::VDEV_BLK_UNAVAILABLE => Dev::Blk(Device::new(
                d.page_va as usize, d.event, blk::Blk::unavailable(cfg.io_pool_size),
            )),
            host::VDEV_BLK => Dev::Blk(Device::new(
                d.page_va as usize,
                d.event,
                blk::Blk::new(
                    d.chan_va as usize,
                    cap::<cap_type::Notification>(d.chan_kick_slot),
                    cfg.io_pool_size,
                ),
            )),
            host::VDEV_NET => Dev::Net(Device::new(
                d.page_va as usize,
                d.event,
                net::Net::new(
                    d.chan_va as usize,
                    cap::<cap_type::Notification>(d.chan_kick_slot),
                    d.mac[..6].try_into().unwrap(),
                    rx_queue,
                ),
            )),
            host::VDEV_GPU => Dev::Gpu(Device::new(
                d.page_va as usize,
                d.event,
                gpu::Gpu::new(d.chan_va as usize, d.chan_size, d.width, d.height),
            )),
            host::VDEV_USB => Dev::Usb(Usb { event: d.event, vcpu: 0, badge: recv::USB.nth(d.chan_kick_slot as usize) }),
            k => panic!("l4h-vmm: unsupported device kind {}", k),
        };
        devs[idx] = Some(dev);
    }

    let mut memdev = (cfg.mem_dev != 0)
        .then(|| MemDev::new(host::vmm_device_page_va(cfg.mem_dev as usize - 1), cfg.mem_event, cfg.hp_count as usize));
    if let Some(m) = memdev.as_mut() {
        m.refresh();
    }

    let console = Console::new(cfg.serial != 0, if cfg.dom0 != 0 { None } else { Some(cfg.guest_id) }, cfg.console_event, tsc_hz);
    // vmmgr's endpoint (l4h_host::vmmgr::call).
    let root_ep = Endpoint(cap::<cap_type::Endpoint>(host::SLOT_ROOT_EP));
    let ep = cap::<cap_type::Endpoint>(host::SLOT_SERVICE_EP);
    let reply = cap::<cap_type::Reply>(host::SLOT_REPLY);

    let _ = root_ep.vmm_ready();

    let mut vmm = Vmm {
        cfg, tsc_hz, mem: &mem, vcpus: &vcpus, devices, devs, memdev, console, root_ep, tcb, ntfn,
        console_pending: false, unbound: false, after_unbound: false, answered: None,
    };
    l4h_rt::ipc::run(ep, reply, &mut vmm)
}

/// The VMM's thread: the guest's hypercalls, and its devices' kicks and
/// backends' completions.
struct Vmm<'a> {
    cfg: &'a VmmConfig,
    tsc_hz: u64,
    mem: &'a GuestMem,
    vcpus: &'a Vcpus,
    devices: &'a [host::VmmDevice],
    devs: [Option<Dev>; host::VMM_MAX_DEVICES],
    memdev: Option<MemDev>,
    console: Console,
    root_ep: Endpoint,
    tcb: sel4::cap::Tcb,
    ntfn: sel4::cap::Notification,
    /// The console ring has more than one batch.
    console_pending: bool,
    /// The notification is unbound, for a poll that gives a queued
    /// hypercall a turn.
    unbound: bool,
    /// That poll was the last receive.
    after_unbound: bool,
    /// The hypercall this turn served, and whether it was answered.
    answered: Option<bool>,
}

impl l4h_rt::ipc::Server for Vmm<'_> {
    const SIGNALS: u64 = recv::SIGNALS;
    // Only the guest holds a capability to the endpoint.
    type Sender = Guest;

    fn received(&mut self) {
        self.after_unbound = core::mem::take(&mut self.unbound);
        if self.after_unbound {
            // TCB invocations use the IPC buffer too (run keeps a hypercall
            // there).  A gap timer may have expired while unbound, losing
            // its notification: re-arm it before sleeping.
            self.tcb.tcb_bind_notification(self.ntfn).expect("bind VMM notification");
            self.console.rearm_timer();
        }
    }

    fn signal(&mut self, badge: u64) {
        // The unbound poll found no hypercall: receive again, bound.
        if core::mem::take(&mut self.after_unbound) {
            return;
        }
        let (vcpus, mem) = (self.vcpus, self.mem);
        self.console_pending |= badge & recv::CONSOLE != 0;
        if badge & recv::MEM != 0 {
            if let Some(m) = self.memdev.as_mut() {
                m.target_changed(vcpus);
            }
        }
        if badge & recv::MEM_REQ != 0 {
            if let Some(m) = self.memdev.as_mut() {
                m.request(vcpus);
            }
        }
        // Device kicks and backend completions, from any device.
        for idx in self.devices.iter().map(|d| d.guest_index as usize) {
            let Some(d) = self.devs[idx].as_mut() else { continue };
            if let Dev::Usb(u) = d {
                if badge & u.badge != 0 {
                    vcpus.raise(u.vcpu, u.event);
                }
                continue;
            }
            if badge & recv::DONE != 0 {
                d.complete(mem, vcpus);
            }
            if badge & recv::KICK != 0 {
                d.poll(mem, vcpus);
            }
        }
        if self.console_pending {
            self.console_pending = self.console.drain(vcpus);
            // Bound notifications take precedence over endpoint calls, even
            // in NBRecv. A guest retrying a full console ring can keep that
            // notification active: give a queued call a turn.  Signals
            // remain pending on ntfn while it is unbound.
            self.tcb.tcb_unbind_notification().expect("unbind VMM notification");
            self.unbound = true;
        }
    }

    fn call(&mut self, from: Guest, _: u64, info: &sel4::MessageInfo) -> Option<sel4::MessageInfo> {
        self.after_unbound = false;
        let mut hc = Hypercalls {
            cfg: self.cfg, tsc_hz: self.tsc_hz, mem: self.mem, vcpus: self.vcpus, devs: &mut self.devs,
            console: &mut self.console, root_ep: self.root_ep,
        };
        let answer = l4h_rt::ipc::serve(info, |label, args, out| hypercall::serve(&mut hc, label, args, from, out));
        self.answered = Some(answer.is_some());
        answer
    }

    fn next(&mut self) -> l4h_rt::ipc::Next {
        use l4h_rt::ipc::Next;
        if self.unbound {
            return Next::Poll;
        }
        match self.answered.take() {
            // The guest stays blocked.
            Some(false) => Next::Wait,
            // Draining can re-arm the console's timer, which overwrites
            // the reply (run keeps it).
            Some(true) if self.console_pending => {
                self.console_pending = self.console.drain(self.vcpus);
                if self.console_pending { Next::Poll } else { Next::Wait }
            }
            // A producer may have extended a nonempty ring without a kick.
            // Poll between bounded batches instead of waiting for a new kick.
            _ if self.console_pending => Next::Poll,
            _ => Next::Wait,
        }
    }
}

l4h_rt::component!(main, no_heap);
