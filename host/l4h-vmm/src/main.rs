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

use l4h_abi as abi;
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
}
const _: () = assert!(core::mem::size_of::<[Option<Dev>; host::VMM_MAX_DEVICES]>() + (64 << 10) <= host::VMM_STACK_SIZE);

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
            k => panic!("l4h-vmm: unsupported device kind {}", k),
        };
        devs[idx] = Some(dev);
    }

    let mut memdev = (cfg.mem_dev != 0)
        .then(|| MemDev::new(host::vmm_device_page_va(cfg.mem_dev as usize - 1), cfg.mem_event, cfg.hp_count as usize));
    if let Some(m) = memdev.as_mut() {
        m.refresh();
    }

    let mut console = Console::new(cfg.serial != 0, if cfg.dom0 != 0 { None } else { Some(cfg.guest_id) }, cfg.console_event, tsc_hz);
    let mut console_pending = false;
    let root_ep = cap::<cap_type::Endpoint>(host::SLOT_ROOT_EP);
    let ep = cap::<cap_type::Endpoint>(host::SLOT_SERVICE_EP);
    let reply = cap::<cap_type::Reply>(host::SLOT_REPLY);

    set_mr(0, cfg.guest_id as u64);
    root_ep.call(sel4::MessageInfo::new(host::ROOT_CALL_VMM_READY, 0, 0, 1));

    let (mut info, mut badge) = ep.recv(reply);
    loop {
        if badge & host::VMM_BADGE_HYPERCALL == 0 {
            console_pending |= badge & host::VMM_BADGE_CONSOLE != 0;
            if badge & host::VMM_BADGE_MEM != 0 {
                if let Some(m) = memdev.as_mut() {
                    m.target_changed(&vcpus);
                }
            }
            if badge & host::VMM_BADGE_MEM_REQ != 0 {
                if let Some(m) = memdev.as_mut() {
                    m.request(&vcpus);
                }
            }
            // Notification: device kicks and backend completions, from any
            // device.
            for idx in devices.iter().map(|d| d.guest_index as usize) {
                let Some(d) = devs[idx].as_mut() else { continue };
                if badge & host::VMM_BADGE_DONE != 0 {
                    d.complete(&mem, &vcpus);
                }
                if badge & host::VMM_BADGE_KICK != 0 {
                    d.poll(&mem, &vcpus);
                }
            }
            let served_console = console_pending;
            if served_console {
                console_pending = console.drain(&vcpus);
            }
            if served_console {
                // Bound notifications take precedence over endpoint calls,
                // even in NBRecv. A guest retrying a full console ring can
                // keep that notification active: give a queued call a turn.
                // Signals remain pending on ntfn while it is unbound.
                tcb.tcb_unbind_notification().expect("unbind VMM notification");
                let call = ep.nb_recv(reply);
                // TCB invocations use the IPC buffer too: preserve the
                // hypercall arguments across rebinding the notification.
                let args: [u64; 4] = core::array::from_fn(mr);
                tcb.tcb_bind_notification(ntfn).expect("bind VMM notification");
                // A gap timer may have expired while unbound, losing its
                // notification. Re-arm before sleeping; args are still saved.
                console.rearm_timer();
                if call.1 != 0 {
                    for (i, a) in args.into_iter().enumerate() {
                        set_mr(i, a);
                    }
                    (info, badge) = call;
                    continue;
                }
            }
            // A producer may have extended a nonempty ring without a kick.
            // Poll between bounded batches instead of waiting for a new kick.
            (info, badge) = if console_pending { ep.nb_recv(reply) } else { ep.recv(reply) };
            continue;
        }
        let resp = match info.label() {
            abi::HC_POWER => {
                // What the guest printed before (a crash report) goes out
                // before it stops.  l4h-root stops the vCPUs, which cancels
                // this call: do not reply.
                let how = mr(0);
                console.flush(&vcpus);
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
        if console_pending {
            console_pending = console.drain(&vcpus);
        }
        set_mr(0, resp);
        let response = sel4::MessageInfo::new(0, 0, 0, 1);
        (info, badge) = if console_pending {
            reply.send(response);
            ep.nb_recv(reply)
        } else {
            ep.reply_recv(response, reply)
        };
    }
}

l4h_rt::component!(main, no_heap);
