//! The part of the control API (DESIGN.md §9.1) that root serves: the
//! host's disks, switches and NICs, its IOMMU, clock and reset.  vmmgr
//! parses dom0's requests and passes these on as integers
//! (l4h_host::vmmgr::VMMGR_HOST_OP); root reads no request of dom0's.

use l4h_abi as abi;

use crate::Host;

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const EIO: i64 = 5;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EBUSY: i64 = 16;
pub const ENODEV: i64 = 19;
pub const EINVAL: i64 = 22;
pub const ENOSPC: i64 = 28;
pub const ENOSYS: i64 = 38;

/// Execute control op `op` with `a`: its vals, and its data into `data`.
pub fn host_op(h: &mut Host, op: u32, a: &[u64; 6], data: &mut [u8; abi::CTL_DATA_MAX]) -> Result<[u64; 6], i64> {
    let mut vals = [0; 6];
    match op {
        abi::CTL_HOST_INFO => {
            // The guests are vmmgr's to count.
            vals = [
                h.info.cores as u64,
                h.alloc.free_bytes() as u64,
                h.total_bytes as u64,
                h.disks.len() as u64,
                0,
                h.netd.nics.len() as u64,
            ];
        }
        abi::CTL_IOMMU_INFO => vals = h.iommu.info(),
        abi::CTL_DISK_INFO => {
            let i = a[0] as usize;
            if !h.ctrls[h.disks.get(i).ok_or(ENOENT)?.ctrl].failed { h.ensure_disk(i)?; }
            let d = &h.disks[i];
            let c = &h.ctrls[d.ctrl];
            let p = &c.pci;
            vals[0] = ((p.bus as u64) << 8) | ((p.dev as u64) << 3) | p.func as u64 | d.address << 16;
            vals[1] = c.owner(i).map_or(u64::MAX, |o| o as u64);
            vals[2] = c.failed as u64;
            vals[3] = c.kind as u64;
            vals[4] = d.capacity;
            vals[5] = c.attachments(i).count() as u64;
        }
        abi::CTL_BLK_WRITE => {
            let (disk, sector, len, zero) = (a[0] as usize, a[1], a[2] as usize, a[3]);
            if a[2] > abi::CTL_LOAD_MAX || zero > 1 { return Err(EINVAL); }
            h.ensure_disk(disk)?;
            // dom0's control data area, which root maps read-only.
            let from = (zero == 0).then_some(crate::vmmgr::CTL_DATA_VA as *const u8);
            if len == 0 {
                crate::blkd::flush(h, disk)?;
            } else {
                let dk = &h.disks[disk];
                crate::blkd::write(&mut h.ctrls[dk.ctrl], disk, dk, sector, len, from, &h.pci, &mut h.wins.a)?;
            }
        }
        abi::CTL_BLK_INFO => {
            let disk = h.disks.get(a[0] as usize).ok_or(ENOENT)?;
            let first = usize::try_from(a[1]).map_err(|_| EINVAL)?;
            if let Some((i, att)) = h.ctrls[disk.ctrl].attachments(a[0] as usize).find(|&(i, _)| i >= first) {
                vals = [i as u64 + 1, att.vm as u64, att.window.start, att.window.sectors, att.read_only as u64, 0];
            }
        }
        abi::CTL_SWITCH_CREATE => vals[0] = h.netd.try_create_switch()? as u64,
        abi::CTL_SWITCH_ATTACH_UPLINK => h.netd.attach_uplink(a[0] as u32, a[1] as usize)?,
        abi::CTL_NIC_INFO => {
            let n = h.netd.nics.get(a[0] as usize).ok_or(ENOENT)?;
            let p = &n.pci;
            vals[0] = ((p.bus as u64) << 8) | ((p.dev as u64) << 3) | p.func as u64;
            vals[1] = n.switch.map_or(u64::MAX, |s| s as u64);
            vals[2] = h.netd.nic_mac(a[0] as usize).unwrap_or(0);
        }
        abi::CTL_SWITCH_INFO => {
            let sw = a[0] as u32;
            if sw >= h.netd.switches {
                return Err(ENOENT);
            }
            let sz = core::mem::size_of::<abi::CtlPort>();
            let mut n = 0;
            for (p, info) in h.netd.ports.iter().enumerate() {
                let Some(info) = info else { continue };
                if info.switch != sw || (n + 1) * sz > abi::CTL_DATA_MAX {
                    continue;
                }
                let (rx_frames, tx_frames, drops) = h.netd.port_stats(p).ok_or(EIO)?;
                let e = abi::CtlPort { vm: info.vm as u32, port: p as u32, mac: info.mac, rx_frames, tx_frames, drops };
                unsafe {
                    core::ptr::copy_nonoverlapping(&e as *const abi::CtlPort as *const u8, data.as_mut_ptr().add(n * sz), sz);
                }
                n += 1;
            }
            vals[0] = n as u64;
            vals[1] = h.netd.nics.iter().position(|n| n.switch == Some(sw)).map_or(u64::MAX, |i| i as u64);
        }
        #[cfg(target_arch = "x86_64")]
        abi::CTL_HOST_KEXEC_LOAD => crate::kexec::load(h, a)?,
        #[cfg(target_arch = "x86_64")]
        abi::CTL_HOST_KEXEC_EXEC => {
            match a[0] {
                l4h_host::vmmgr::KEXEC_PREFLIGHT => crate::kexec::preflight(h)?,
                l4h_host::vmmgr::KEXEC_FAIL => crate::kexec::fail(h),
                _ => crate::kexec::exec(h)?,
            }
        }
        // Returns only on failure.
        abi::CTL_HOST_REBOOT => return Err(crate::reset::reboot(h, "dom0")),
        abi::CTL_RTC_SET => h.rtc.set_secs(&mut h.wins.a, a[0])?,
        _ => return Err(ENOSYS),
    }
    Ok(vals)
}
