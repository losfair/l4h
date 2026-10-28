//! The control API for dom0 (DESIGN.md §9.1): requests arrive in dom0's
//! control page (struct l4h_ctl_req), the response is written next to it.
//! vmmgr serves the guests' ops; root those on the host's disks, switches
//! and NICs, which vmmgr passes on as integers (root.rs, VMMGR_HOST_OP).

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use l4h_abi as abi;
use l4h_host as host;

use crate::guest::{GuestConfig, State};
use crate::{MAX_GUESTS, Vmmgr, root};

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const EIO: i64 = 5;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EBUSY: i64 = 16;
pub const EINVAL: i64 = 22;
pub const ENOSPC: i64 = 28;
pub const ENOSYS: i64 = 38;

const HOST_VERSION: &str = match option_env!("L4H_VERSION") {
    Some(version) => version,
    None => "unknown",
};
const _: () = assert!(!HOST_VERSION.is_empty() && HOST_VERSION.len() <= abi::CTL_DATA_MAX);

/// Execute the request in the control page of guest `caller` (dom0).
pub fn handle(h: &mut Vmmgr, caller: usize) {
    let Some(page) = h.guest(caller).and_then(|g| g.ctl_page()) else { return };
    let req = unsafe { (page as *const abi::CtlReq).read_volatile() };
    let mut resp = abi::CtlResp { status: 0, vals: [0; 6], data: [0; abi::CTL_DATA_MAX] };
    resp.status = if req.version != abi::CTL_VERSION {
        -EINVAL
    } else {
        match execute(h, caller, &req, &mut resp) {
            Ok(()) => 0,
            Err(e) => -e,
        }
    };
    unsafe { (page.add(abi::CTL_RESP_OFF) as *mut abi::CtlResp).write_volatile(resp) };
}

/// dom0 kicked: execute the request of each dom0 whose control page has a
/// new seq (abi::CtlSync), then mark it done and raise the device's event.
pub fn kicked(h: &mut Vmmgr) {
    for id in 0..MAX_GUESTS {
        let Some((page, instance)) = h.guest(id).filter(|g| g.dom0).and_then(|g| Some((g.ctl_page()?, g.instance))) else { continue };
        let sync = unsafe { page.add(abi::CTL_SYNC_OFF) as *mut abi::CtlSync };
        let seq = unsafe { addr_of!((*sync).seq).read_volatile() };
        if seq == unsafe { addr_of!((*sync).done).read_volatile() } {
            continue;
        }
        fence(Ordering::Acquire);
        handle(h, id);
        // The request may have restarted dom0: the page is a new one then,
        // and no one waits.
        let Some(g) = h.guests[id].as_ref().filter(|g| g.instance == instance) else { continue };
        let Some(d) = g.devices.iter().position(|d| d.kind == crate::guest::DevKind::Ctl) else { continue };
        fence(Ordering::Release);
        unsafe { addr_of_mut!((*sync).done).write_volatile(seq) };
        g.raise_event(&mut h.alloc, crate::guest::dev_event(d));
    }
}

fn vm_arg(a: u64) -> Result<usize, i64> {
    let id = a as usize;
    if id >= MAX_GUESTS { Err(ENOENT) } else { Ok(id) }
}

fn cstr(data: &[u8]) -> &[u8] {
    let n = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    &data[..n]
}

fn execute(h: &mut Vmmgr, caller: usize, req: &abi::CtlReq, resp: &mut abi::CtlResp) -> Result<(), i64> {
    let a = &req.args;
    match req.op {
        abi::CTL_LOG_READ => {
            let ring = unsafe { &*(host::log::VA as *const host::log::Ring) };
            let r = ring.read(a[0], a[1], &mut resp.data).ok_or(EINVAL)?;
            resp.vals = [r.next, r.len as u64, r.lost, r.end, 0, 0];
            Ok(())
        }
        abi::CTL_HOST_VERSION => {
            let version = HOST_VERSION.as_bytes();
            resp.vals[0] = version.len() as u64;
            resp.data[..version.len()].copy_from_slice(version);
            Ok(())
        }
        abi::CTL_HOST_INFO => {
            resp.vals = root::host_op(req.op, a)?;
            // Root's free memory and memd's, and ours; the guests are ours.
            resp.vals[1] += h.alloc.local_free_bytes() as u64;
            resp.vals[4] = h.guests.iter().flatten().count() as u64;
            Ok(())
        }
        abi::CTL_IOMMU_INFO | abi::CTL_DISK_INFO | abi::CTL_BLK_INFO | abi::CTL_SWITCH_CREATE | abi::CTL_SWITCH_ATTACH_UPLINK
        | abi::CTL_NIC_INFO | abi::CTL_SWITCH_INFO | abi::CTL_HOST_REBOOT | abi::CTL_RTC_SET => {
            resp.vals = root::host_op(req.op, a)?;
            resp.data = *root::result_data();
            Ok(())
        }
        abi::CTL_BLK_WRITE => {
            // From dom0's control data area, which root maps too.
            if h.guest(caller).and_then(|g| g.ctl_data()).is_none() { return Err(EINVAL); }
            resp.vals = root::host_op(req.op, a)?;
            Ok(())
        }
        abi::CTL_VM_CREATE => {
            let name = core::str::from_utf8(cstr(&req.data[..abi::CTL_NAME_MAX])).map_err(|_| EINVAL)?;
            let (ram, vcpus) = (a[0] as usize, a[1] as usize);
            if vcpus == 0 || vcpus > h.info.cores * 4 {
                return Err(EINVAL);
            }
            let io_pool = if a[4] != 0 { a[4] as usize } else { crate::guest::IO_POOL_DEFAULT };
            if !io_pool.is_power_of_two() || !(crate::guest::IO_POOL_MIN..=crate::guest::IO_POOL_MAX).contains(&io_pool) {
                return Err(EINVAL);
            }
            // a[2] was the kernel's base VA, a[3] the seL4 object quota:
            // guests run the host's kernel, and their objects come from
            // their own RAM.
            let kernel = h.kernel.as_ref().ok_or(ENOSYS)?;
            let (ram_base, initrd_gpa) = (kernel.ram_base, kernel.initrd_gpa());
            let cfg = GuestConfig {
                name,
                ram,
                vcpus,
                io_pool,
                vspaces: 64,
                ram_base,
                dom0: false,
            };
            let id = h.create_guest(&cfg).ok_or(ENOMEM)?;
            resp.vals[0] = id as u64;
            resp.vals[1] = initrd_gpa as u64;
            Ok(())
        }
        abi::CTL_VM_LOAD => {
            let id = vm_arg(a[0])?;
            let (dst, src, len) = (a[1] as usize, a[2] as usize, a[3] as usize);
            if id == caller || len as u64 > abi::CTL_LOAD_MAX {
                return Err(EINVAL);
            }
            // The source is dom0's control data area, which belongs to
            // the host: vmmgr never reads a guest's RAM.
            let from = h.guest(caller).and_then(|d0| d0.ctl_data()).ok_or(EINVAL)?;
            if src.checked_add(len).is_none_or(|end| end > abi::CTL_LOAD_MAX as usize) {
                return Err(EINVAL);
            }
            h.with_guest(id, |h, g| {
                if g.state != State::Created || g.vmm.is_some() {
                    return Err(EBUSY);
                }
                // Check the arena's fixed tables as well as host memory
                // before block_frames makes any objects.
                let (bytes, slots) = g.load_cost(dst, len).ok_or(EINVAL)?;
                if !h.can_afford(bytes, 0, slots) || !g.reserve(&mut h.alloc, bytes) {
                    return Err(ENOMEM);
                }
                // dom0 may change the bytes meanwhile: it only corrupts the
                // image it loads.
                let from = unsafe { from.add(src) };
                if g.load_ram(&mut h.alloc, &mut h.wins.a, dst, from, len) { Ok(()) } else { Err(EINVAL) }
            })
            .ok_or(ENOENT)?
        }
        abi::CTL_VM_START => {
            let id = vm_arg(a[0])?;
            if id == caller {
                return Err(EINVAL);
            }
            let initrd = (a[1] as usize, a[2] as usize);
            let cmdline = cstr(&req.data);
            h.with_guest(id, |h, g| {
                let kernel = h.kernel.as_ref().expect("guests run the host's kernel");
                if g.state != State::Created || g.vmm.is_some() {
                    return Err(EINVAL);
                }
                // The boot blocks it fills with frames (as many as dom0
                // asks for) and its l4h-vmm.
                let (bytes, slots) = g.boot_cost(kernel.end, initrd).ok_or(EINVAL)?;
                let bytes = bytes + crate::vmm::start_bytes(g.pool.size, g.vcpus.len(), g.devices.len());
                if !h.can_afford(bytes, 1, slots) || !g.reserve(&mut h.alloc, bytes) {
                    return Err(ENOMEM);
                }
                if crate::guest::boot(g, &mut h.alloc, &mut h.wins.a, &h.info, kernel, initrd, cmdline) { Ok(()) } else { Err(EINVAL) }
            })
            .ok_or(ENOENT)??;
            h.start_guest(id)
        }
        abi::CTL_VM_DESTROY => {
            let id = vm_arg(a[0])?;
            if id == caller {
                return Err(EPERM);
            }
            h.destroy_guest(id)
        }
        abi::CTL_VM_LIST => {
            let first = a[0] as usize;
            let per = abi::CTL_DATA_MAX / core::mem::size_of::<abi::CtlVm>();
            let mut n = 0;
            for g in h.guests.iter().skip(first).flatten() {
                if n == per {
                    break;
                }
                let mut vm = abi::CtlVm {
                    id: g.id as u32,
                    state: match g.state {
                        State::Created => abi::VM_CREATED,
                        State::Running => abi::VM_RUNNING,
                        State::Stopped => abi::VM_STOPPED,
                    },
                    vcpus: g.vcpus.len() as u32,
                    reserved: 0,
                    ram: (g.owned_ram() + crate::memd::hotplug(g.id).plugged as usize * abi::HP_SIZE) as u64,
                    name: [0; abi::CTL_NAME_MAX],
                };
                let nb = g.name.as_bytes();
                let k = nb.len().min(abi::CTL_NAME_MAX - 1);
                vm.name[..k].copy_from_slice(&nb[..k]);
                let sz = core::mem::size_of::<abi::CtlVm>();
                unsafe {
                    core::ptr::copy_nonoverlapping(&vm as *const abi::CtlVm as *const u8, resp.data.as_mut_ptr().add(n * sz), sz);
                }
                n += 1;
            }
            resp.vals[0] = n as u64;
            Ok(())
        }
        abi::CTL_BLK_ATTACH => {
            let id = vm_arg(a[0])?;
            if id == caller {
                return Err(EINVAL);
            }
            h.attach_disk(id, a[1] as usize, a[2] != 0, a[3], a[4])
        }
        abi::CTL_CONSOLE_READ => {
            let g = h.guest(vm_arg(a[0])?).ok_or(ENOENT)?;
            let ring = g.console_ring();
            let head = unsafe { addr_of!((*ring).head).read_volatile() };
            fence(Ordering::Acquire);
            let off = a[1].min(head);
            let start = off.max(head.saturating_sub(host::CONSOLE_RING_DATA as u64));
            let n = (head - start).min(abi::CTL_DATA_MAX as u64) as usize;
            if let Some(t) = &h.flags { t.act(g, caller, abi::FLAG_CONSOLE_OUT, n != 0)?; }
            for i in 0..n {
                let idx = (start as usize + i) % host::CONSOLE_RING_DATA;
                resp.data[i] = unsafe { addr_of!((*ring).data[idx]).read_volatile() };
            }
            resp.vals = [start + n as u64, n as u64, start - off, 0, 0, 0];
            Ok(())
        }
        abi::CTL_GPU_ATTACH => {
            let id = vm_arg(a[0])?;
            if id == caller {
                return Err(EINVAL);
            }
            h.attach_gpu(id, a[1], a[2])
        }
        abi::CTL_GPU_READ => {
            // Into dom0's control data area, which belongs to the host.
            let to = h.guest(caller).and_then(|d0| d0.ctl_data()).ok_or(EINVAL)? as *mut u8;
            let g = h.guest(vm_arg(a[0])?).ok_or(ENOENT)?;
            if let Some(t) = &h.flags { t.act(g, caller, abi::FLAG_CONSOLE_OUT, false)?; }
            resp.vals = crate::gpu::read(g, a[1], to, |effect| {
                if let Some(t) = &h.flags { t.act(g, caller, abi::FLAG_CONSOLE_OUT, effect)?; }
                Ok(())
            })?;
            Ok(())
        }
        abi::CTL_CONSOLE_WRITE => {
            let g = h.guest(vm_arg(a[0])?).ok_or(ENOENT)?;
            let len = (a[1] as usize).min(abi::CTL_DATA_MAX);
            if let Some(t) = &h.flags { t.act(g, caller, abi::FLAG_CONSOLE_IN, len != 0)?; }
            let p = g.console_page();
            unsafe {
                let mut head = addr_of!((*p).in_head).read_volatile();
                let tail = addr_of!((*p).in_tail).read_volatile();
                // Both indices are in the guest's page: the guest may have
                // written anything there.
                let room = abi::CONSOLE_IN_SIZE.saturating_sub(head.wrapping_sub(tail) as usize);
                let n = len.min(room);
                for &c in &req.data[..n] {
                    addr_of_mut!((*p).input[head as usize % abi::CONSOLE_IN_SIZE]).write_volatile(c);
                    head = head.wrapping_add(1);
                }
                fence(Ordering::Release);
                addr_of_mut!((*p).in_head).write_volatile(head);
                resp.vals[0] = n as u64;
            }
            Ok(())
        }
        abi::CTL_VM_TRUST => {
            let g = h.guest(vm_arg(a[0])?).ok_or(ENOENT)?;
            let t = h.flags.as_ref().ok_or(ENOSYS)?;
            let flags = t.flags(g);
            resp.vals[0] = flags.taint[0];
            resp.vals[1] = flags.seal[0];
            Ok(())
        }
        abi::CTL_NIC_CREATE => {
            let id = vm_arg(a[0])?;
            if id == caller {
                return Err(EINVAL);
            }
            resp.vals[0] = h.create_nic(id, a[1] as u32, a[2], a[3] & abi::NIC_NO_MAC_LOCK == 0, a[3] & abi::NIC_ISOLATED != 0)?;
            Ok(())
        }
        abi::CTL_VM_SET_SCHED => {
            let id = vm_arg(a[0])?;
            if a[1] > 100 {
                return Err(EINVAL);
            }
            if crate::sched::set_cap(h, id, a[1] as u32) { Ok(()) } else { Err(ENOENT) }
        }
        abi::CTL_VM_SHUTDOWN => {
            let id = vm_arg(a[0])?;
            if a[1] != abi::POWER_OFF && a[1] != abi::POWER_REBOOT {
                return Err(EINVAL);
            }
            let g = h.guests.get(id).and_then(|g| g.as_ref()).ok_or(ENOENT)?;
            if g.state != State::Running {
                return Err(EBUSY);
            }
            unsafe { addr_of_mut!((*g.console_page()).power_request).write_volatile(a[1] as u32 + 1) };
            // The console is device 0.
            g.raise_event(&mut h.alloc, crate::guest::dev_event(0));
            Ok(())
        }
        abi::CTL_VM_STATS => {
            let g = h.guest(vm_arg(a[0])?).ok_or(ENOENT)?;
            resp.vals[0] = g.vcpus.iter().map(|v| v.usage as u64).sum();
            resp.vals[1] = g.cpu_cap_pct as u64;
            Ok(())
        }
        abi::CTL_VM_SET_MEM => {
            let id = vm_arg(a[0])?;
            h.with_guest(id, |h, g| {
                if g.mem_dev.is_none() {
                    return Err(EINVAL);
                }
                // In hotplug blocks above its boot RAM.
                let above = a[1].saturating_sub(g.owned_ram() as u64);
                let blocks = above.div_ceil(abi::HP_SIZE as u64).min(g.hp_count as u64) as usize;
                if !crate::memd::set_target(&h.alloc, id, blocks) {
                    return Err(EINVAL);
                }
                // Before it runs, its VMM reads the target when it starts.
                if g.vmm.is_some() {
                    g.signal_vmm(&mut h.alloc, host::VMM_BADGE_MEM);
                }
                Ok(())
            })
            .ok_or(ENOENT)?
        }
        abi::CTL_VM_MEM_INFO => {
            let g = h.guest(vm_arg(a[0])?).ok_or(ENOENT)?;
            let hp = crate::memd::hotplug(g.id);
            let hp_size = abi::HP_SIZE as u64;
            resp.vals[0] = g.owned_ram() as u64;
            resp.vals[1] = g.hp_count as u64 * hp_size;
            resp.vals[2] = hp.target as u64 * hp_size;
            resp.vals[3] = hp.plugged as u64 * hp_size;
            Ok(())
        }
        abi::CTL_VM_INFO => {
            let g = h.guest(vm_arg(a[0])?).ok_or(ENOENT)?;
            for (v, vcpu) in g.vcpus.iter().take(6).enumerate() {
                resp.vals[v] = vcpu.core as u64;
            }
            Ok(())
        }
        _ => Err(ENOSYS),
    }
}
