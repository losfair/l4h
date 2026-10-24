//! l4h-vmm: the per-guest virtual machine monitor.  Serves the guest's
//! hypercalls and implements its virtio-l4h devices on top of the host
//! drivers (blkd, netd).  See DESIGN.md §8.

#![no_std]
#![no_main]

mod blk;
mod dev;
mod gpu;
mod guest;
mod mem;
mod net;
mod virtq;

use l4h_abi as abi;
use l4h_rt::host::{self, VmmConfig};
use l4h_rt::sel4;
use l4h_rt::{Info, cap};
use sel4::cap_type;

use crate::dev::Device;
use crate::guest::{GuestMem, Vcpus};

enum Dev {
    Blk(Device<blk::Blk>),
    Net(Device<net::Net>),
    Gpu(Device<gpu::Gpu>),
}

impl Dev {
    fn op(&mut self, mem: &GuestMem, vcpus: &Vcpus, op: u64, a: u64, b: u64) -> u64 {
        match self {
            Dev::Blk(d) => d.op(mem, vcpus, op, a, b),
            Dev::Net(d) => d.op(mem, vcpus, op, a, b),
            Dev::Gpu(d) => d.op(mem, vcpus, op, a, b),
        }
    }

    fn poll(&mut self, mem: &GuestMem, vcpus: &Vcpus) {
        match self {
            Dev::Blk(d) => d.poll(mem, vcpus, 0),
            Dev::Net(d) => d.poll(mem, vcpus, 0),
            Dev::Gpu(d) => d.poll(mem, vcpus, 0),
        }
    }

    fn complete(&mut self, mem: &GuestMem, vcpus: &Vcpus) {
        match self {
            Dev::Blk(d) => d.complete(mem, vcpus),
            Dev::Net(d) => d.complete(mem, vcpus),
            Dev::Gpu(d) => d.complete(mem, vcpus),
        }
    }
}

/// Guest console output: into the ring l4h-root reads, and optionally to
/// the serial port, each line prefixed with the guest id (except dom0).
struct Console {
    ring: *mut host::ConsoleRing,
    serial: bool,
    prefix: Option<u32>,
    line_start: bool,
}

impl Console {
    fn put(&mut self, c: u8) {
        unsafe {
            let head = core::ptr::addr_of!((*self.ring).head).read_volatile();
            core::ptr::addr_of_mut!((*self.ring).data[head as usize % host::CONSOLE_RING_DATA]).write_volatile(c);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::addr_of_mut!((*self.ring).head).write_volatile(head + 1);
        }
        if self.serial {
            if self.line_start {
                if let Some(id) = self.prefix {
                    sel4::debug_print!("[vm{}] ", id);
                }
            }
            sel4::debug_put_char(c);
            self.line_start = c == b'\n';
        }
    }
}

fn mr(i: usize) -> u64 {
    sel4::with_ipc_buffer(|b| b.msg_regs()[i])
}

fn set_mr(i: usize, v: u64) {
    sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[i] = v)
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
    let devices = &cfg.devices[..cfg.nr_devices as usize];
    while !devices
        .iter()
        .filter(|d| d.kind == host::VDEV_BLK)
        .all(|d| unsafe { core::ptr::addr_of!((*(d.chan_va as *const host::blk::Channel)).ready).read_volatile() } != 0)
    {
        ntfn.wait();
    }

    // Devices by guest boot info index, which is also the device's bit in
    // the notification badges.
    let mut devs: [Option<Dev>; host::VMM_MAX_DEVICES] = [const { None }; host::VMM_MAX_DEVICES];
    // Receive rings that leave room in the I/O pool for disk requests.
    let nics = devices.iter().filter(|d| d.kind == host::VDEV_NET).count();
    let rx_queue = host::iopool::rx_queue_size(cfg.io_pool_size as usize, nics);
    for d in devices.iter() {
        let idx = d.guest_index as usize;
        assert!(idx < host::VMM_MAX_DEVICES, "l4h-vmm: device index {} out of range", idx);
        let dev = match d.kind {
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
            k => panic!("l4h-vmm: unsupported device kind {}", k),
        };
        devs[idx] = Some(dev);
    }

    let mut console = Console {
        ring: host::VMM_CONSOLE_RING_VA as *mut host::ConsoleRing,
        serial: cfg.serial != 0,
        prefix: if cfg.dom0 != 0 { None } else { Some(cfg.guest_id) },
        line_start: true,
    };
    let root_ep = cap::<cap_type::Endpoint>(host::SLOT_ROOT_EP);
    let ep = cap::<cap_type::Endpoint>(host::SLOT_SERVICE_EP);
    let reply = cap::<cap_type::Reply>(host::SLOT_REPLY);

    set_mr(0, cfg.guest_id as u64);
    root_ep.call(sel4::MessageInfo::new(host::ROOT_CALL_VMM_READY, 0, 0, 1));

    let (mut info, mut badge) = ep.recv(reply);
    loop {
        if badge & host::VMM_BADGE_HYPERCALL == 0 {
            // Notification: device kicks and backend completions.
            for idx in devices.iter().map(|d| d.guest_index as usize) {
                let Some(d) = devs[idx].as_mut() else { continue };
                if badge & (1 << (host::VMM_BADGE_DONE_SHIFT as usize + idx)) != 0 {
                    d.complete(&mem, &vcpus);
                }
                if badge & (1 << (host::VMM_BADGE_KICK_SHIFT as usize + idx)) != 0 {
                    d.poll(&mem, &vcpus);
                }
            }
            (info, badge) = ep.recv(reply);
            continue;
        }
        let resp = match info.label() {
            abi::HC_CONSOLE_WRITE => {
                let len = (mr(0) as usize).min(abi::HC_CONSOLE_MAX_WORDS * 8);
                for i in 0..len {
                    let w = mr(1 + i / 8);
                    console.put((w >> ((i % 8) * 8)) as u8);
                }
                0
            }
            abi::HC_CTL if cfg.dom0 != 0 => {
                set_mr(0, cfg.guest_id as u64);
                root_ep.call(sel4::MessageInfo::new(host::ROOT_CALL_CTL, 0, 0, 1));
                0
            }
            abi::HC_POWER => {
                // l4h-root stops the vCPUs, which cancels this call: do not
                // reply.
                let how = mr(0);
                set_mr(0, cfg.guest_id as u64);
                set_mr(1, how);
                root_ep.call(sel4::MessageInfo::new(host::ROOT_CALL_GUEST_POWER, 0, 0, 2));
                (info, badge) = ep.recv(reply);
                continue;
            }
            abi::HC_DEV_WRITE => {
                let (idx, op, a, b) = (mr(0) as usize, mr(1), mr(2), mr(3));
                match devs.get_mut(idx).and_then(|d| d.as_mut()) {
                    Some(d) => d.op(&mem, &vcpus, op, a, b),
                    None => u64::MAX,
                }
            }
            abi::HC_GET_TIME => wall_clock_ns(cfg, tsc_hz),
            _ => u64::MAX,
        };
        set_mr(0, resp);
        (info, badge) = ep.reply_recv(sel4::MessageInfo::new(0, 0, 0, 1), reply);
    }
}

l4h_rt::component!(main, no_heap);
