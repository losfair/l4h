// SPDX-License-Identifier: BSD-2-Clause

//! l4hctl: dom0 client library of the l4h control API (DESIGN.md §9.1), on
//! /dev/l4hctl.  The request layouts mirror `include/l4h/abi.h`.  The
//! `l4hctl` binary is a command-line front end; other dom0 programs (such
//! as an orchestration agent) link this library.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

pub const CTL_VERSION: u32 = 3;
pub const CTL_DATA_MAX: usize = 1984;
pub const CTL_LOAD_MAX: usize = 1 << 20;
pub const CTL_NAME_MAX: usize = 32;

pub const CTL_HOST_INFO: u32 = 1;
pub const CTL_VM_CREATE: u32 = 2;
pub const CTL_VM_LOAD: u32 = 3;
pub const CTL_VM_START: u32 = 4;
pub const CTL_VM_DESTROY: u32 = 5;
pub const CTL_VM_LIST: u32 = 6;
pub const CTL_BLK_ATTACH: u32 = 7;
pub const CTL_CONSOLE_READ: u32 = 8;
pub const CTL_CONSOLE_WRITE: u32 = 9;
pub const CTL_DISK_INFO: u32 = 10;
pub const CTL_SWITCH_CREATE: u32 = 11;
pub const CTL_SWITCH_ATTACH_UPLINK: u32 = 12;
pub const CTL_NIC_CREATE: u32 = 13;
pub const CTL_SWITCH_INFO: u32 = 14;
pub const CTL_NIC_INFO: u32 = 15;
pub const NIC_NO_MAC_LOCK: u64 = 1;
pub const NIC_ISOLATED: u64 = 2;
pub const CTL_VM_SET_SCHED: u32 = 16;
pub const CTL_VM_INFO: u32 = 17;
pub const CTL_VM_STATS: u32 = 18;
pub const CTL_VM_SHUTDOWN: u32 = 19;
pub const CTL_BLK_WRITE: u32 = 20;
pub const CTL_BLK_INFO: u32 = 21;
pub const CTL_HOST_REBOOT: u32 = 22;
pub const CTL_RTC_SET: u32 = 23;
pub const CTL_IOMMU_INFO: u32 = 24;
pub const CTL_HOST_VERSION: u32 = 25;
pub const CTL_GPU_ATTACH: u32 = 26;
pub const CTL_GPU_READ: u32 = 27;
pub const CTL_VM_SET_MEM: u32 = 28;
pub const CTL_VM_MEM_INFO: u32 = 29;
pub const CTL_VM_TRUST: u32 = 30;
pub const CTL_LOG_READ: u32 = 31;
pub const CTL_BLK_ATTACH_EXTENTS: u32 = 32;
/// Extents of a disk made of them, and the least sectors of each when
/// there are several.
pub const BLK_MAX_EXTENTS: usize = 4096;
pub const BLK_MIN_EXTENT_SECTORS: u64 = 8192;
pub const GPU_POOL_IMAGES: u64 = 4;
pub const IOMMU_NONE: u64 = 0;
pub const IOMMU_OFF: u64 = 1;
pub const IOMMU_ON: u64 = 2;
pub const IOMMU_FAILED: u64 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CtlPort {
    pub vm: u32,
    pub port: u32,
    pub mac: u64,
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub drops: u64,
}

pub fn fmt_mac(m: u64) -> String {
    let b = m.to_be_bytes();
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[2], b[3], b[4], b[5], b[6], b[7])
}

pub fn parse_mac(s: &str) -> Result<u64> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return err(format!("bad MAC: {s}"));
    }
    let mut m = 0u64;
    for p in parts {
        m = (m << 8) | u8::from_str_radix(p, 16).map_err(|_| Error(format!("bad MAC: {s}")))? as u64;
    }
    Ok(m)
}

#[repr(C)]
pub struct Req {
    pub op: u32,
    pub version: u32,
    pub args: [u64; 6],
    pub data: [u8; CTL_DATA_MAX],
}

#[repr(C)]
pub struct Resp {
    pub status: i64,
    pub vals: [u64; 6],
    pub data: [u8; CTL_DATA_MAX],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CtlVm {
    pub id: u32,
    pub state: u32,
    pub vcpus: u32,
    pub reserved: u32,
    pub ram: u64,
    pub name: [u8; CTL_NAME_MAX],
}

#[repr(C)]
pub struct Call {
    req: u64,
    resp: u64,
    buf: u64,
    len: u64,
}

// _IOWR('L', 1, struct l4hctl_call)
pub const L4HCTL_IOC_CALL: u64 = (3 << 30) | ((std::mem::size_of::<Call>() as u64) << 16) | ((b'L' as u64) << 8) | 1;

unsafe extern "C" {
    fn ioctl(fd: i32, req: u64, ...) -> i32;
}

pub struct Ctl {
    dev: File,
}

#[derive(Debug)]
pub struct Error(pub String);

pub type Result<T> = std::result::Result<T, Error>;

pub fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error(msg.into()))
}

pub fn errno_name(e: i64) -> &'static str {
    match e {
        1 => "operation not permitted",
        2 => "no such VM or device",
        5 => "I/O error",
        11 => "try again",
        12 => "out of memory",
        16 => "busy",
        22 => "invalid argument",
        28 => "no space for devices",
        38 => "not supported",
        _ => "error",
    }
}

impl Ctl {
    pub fn open() -> Result<Self> {
        File::options()
            .read(true)
            .write(true)
            .open("/dev/l4hctl")
            .map(|dev| Ctl { dev })
            .map_err(|e| Error(format!("/dev/l4hctl: {e} (not dom0?)")))
    }

    pub fn call(&self, op: u32, args: &[u64], data: &[u8], buf: &[u8]) -> Result<Box<Resp>> {
        self.call_buf(op, args, data, buf.as_ptr() as u64, buf.len())
    }

    /// A call whose response bytes the driver copies into `out`
    /// (CTL_GPU_READ); the call's status, which may be an error.
    pub fn call_out(&self, op: u32, args: &[u64], out: &mut [u8]) -> Result<Box<Resp>> {
        let ptr = out.as_mut_ptr() as u64;
        self.raw_call(op, args, &[], ptr, out.len())
    }

    fn call_buf(&self, op: u32, args: &[u64], data: &[u8], buf: u64, len: usize) -> Result<Box<Resp>> {
        let resp = self.raw_call(op, args, data, buf, len)?;
        if resp.status < 0 {
            if resp.status == -1 && matches!(op, CTL_CONSOLE_READ | CTL_CONSOLE_WRITE | CTL_GPU_READ) {
                let kind = if op == CTL_CONSOLE_WRITE { "input" } else { "output" };
                return err(format!("{kind} sealed by the guest"));
            }
            return err(format!("request {op} failed: {}", errno_name(-resp.status)));
        }
        Ok(resp)
    }

    fn raw_call(&self, op: u32, args: &[u64], data: &[u8], buf: u64, len: usize) -> Result<Box<Resp>> {
        let mut req = Box::new(Req { op, version: CTL_VERSION, args: [0; 6], data: [0; CTL_DATA_MAX] });
        req.args[..args.len()].copy_from_slice(args);
        req.data[..data.len()].copy_from_slice(data);
        let mut resp = Box::new(Resp { status: 0, vals: [0; 6], data: [0; CTL_DATA_MAX] });
        let call = Call { req: &*req as *const Req as u64, resp: &mut *resp as *mut Resp as u64, buf, len: len as u64 };
        let r = unsafe { ioctl(self.dev.as_raw_fd(), L4HCTL_IOC_CALL, &call as *const Call) };
        if r < 0 {
            return err(format!("ioctl: {}", io::Error::last_os_error()));
        }
        Ok(resp)
    }
}

/// A VM's display, from [`Ctl::screenshot`]: `width` x `height` pixels,
/// each 4 bytes of `format` (a VIRTIO_GPU_FORMAT_*), rows `stride` apart.
pub struct Screen {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
    /// Changes with every update of the display.
    pub frame: u64,
    pub data: Vec<u8>,
}

impl Screen {
    /// Pixel (x, y) as (r, g, b).
    pub fn rgb(&self, x: u32, y: u32) -> Option<(u8, u8, u8)> {
        // Byte positions of red, green and blue in each format.
        let (r, g, b) = match self.format {
            1 | 2 => (2, 1, 0),     // B8G8R8A8, B8G8R8X8
            3 | 4 => (1, 2, 3),     // A8R8G8B8, X8R8G8B8
            67 | 134 => (0, 1, 2),  // R8G8B8A8, R8G8B8X8
            68 | 121 => (3, 2, 1),  // X8B8G8R8, A8B8G8R8
            _ => return None,
        };
        let p = &self.data[y as usize * self.stride as usize + x as usize * 4..][..4];
        Some((p[r], p[g], p[b]))
    }

    /// As a binary PPM (P6).
    pub fn ppm(&self) -> Result<Vec<u8>> {
        let mut out = format!("P6\n{} {}\n255\n", self.width, self.height).into_bytes();
        for y in 0..self.height {
            for x in 0..self.width {
                let (r, g, b) = self.rgb(x, y).ok_or(Error(format!("unknown pixel format {}", self.format)))?;
                out.extend_from_slice(&[r, g, b]);
            }
        }
        Ok(out)
    }
}

impl Ctl {
    /// The VM's display, read whole from one frame: a read that the VM
    /// updated meanwhile is read again (a few times; then the last read
    /// is returned, which may mix two frames).
    pub fn screenshot(&self, vm: u64) -> Result<Screen> {
        let mut chunk = vec![0u8; CTL_LOAD_MAX];
        read_screen(&mut chunk, |off, buf| {
            let r = self.call_out(CTL_GPU_READ, &[vm, off], buf)?;
            Ok((r.status, r.vals))
        })
    }
}

/// [`Ctl::screenshot`] on `read`, which makes CTL_GPU_READ from an offset
/// into `chunk` and returns its status and values.
fn read_screen(chunk: &mut [u8], mut read: impl FnMut(u64, &mut [u8]) -> Result<(i64, [u64; 6])>) -> Result<Screen> {
    const EAGAIN: i64 = 11;
    let mut last = None;
    for attempt in 0..20 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut s = Screen { width: 0, height: 0, stride: 0, format: 0, frame: 0, data: Vec::new() };
        let mut torn = false;
        loop {
            let off = s.data.len() as u64;
            let (status, v) = read(off, chunk)?;
            if status == -EAGAIN {
                torn = true;
                break;
            }
            if status < 0 {
                return err(format!("screenshot: {}", errno_name(-status)));
            }
            let n = v[0] as usize;
            if off == 0 {
                (s.width, s.height, s.stride, s.format, s.frame) = (v[1] as u32, v[2] as u32, v[3] as u32, v[4] as u32, v[5]);
            } else if v[5] != s.frame {
                torn = true;
                break;
            }
            if n > chunk.len() {
                return err("screenshot: bad length");
            }
            s.data.extend_from_slice(&chunk[..n]);
            if n == 0 || s.data.len() >= s.stride as usize * s.height as usize {
                break;
            }
        }
        // A torn read says nothing yet, not even whether anything is shown.
        if torn {
            if s.format != 0 && s.data.len() >= s.stride as usize * s.height as usize {
                last = Some(s);
            }
            continue;
        }
        if s.format == 0 {
            return err("screenshot: the VM shows nothing");
        }
        return Ok(s);
    }
    last.ok_or(Error("screenshot: the display keeps changing".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 2 x 2 display of format 2, frame 4, served 8 bytes at a time.
    fn display(off: u64, buf: &mut [u8], frame: u64) -> Result<(i64, [u64; 6])> {
        let img: Vec<u8> = (0..16).collect();
        let n = (16 - off as usize).min(8);
        buf[..n].copy_from_slice(&img[off as usize..off as usize + n]);
        Ok((0, [n as u64, 2, 2, 8, 2, frame]))
    }

    #[test]
    fn first_read_torn_is_read_again() {
        let mut chunk = [0u8; 8];
        let mut calls = 0;
        let s = read_screen(&mut chunk, |off, buf| {
            calls += 1;
            if calls == 1 { Ok((-11, [0; 6])) } else { display(off, buf, 4) }
        })
        .unwrap();
        assert_eq!((s.width, s.height, s.format, s.frame), (2, 2, 2, 4));
        assert_eq!(s.data, (0..16).collect::<Vec<u8>>());
    }

    #[test]
    fn frames_must_match_across_chunks() {
        let mut chunk = [0u8; 8];
        let mut calls = 0;
        let s = read_screen(&mut chunk, |off, buf| {
            calls += 1;
            // The second chunk of the first read is of a later frame.
            display(off, buf, if calls == 2 { 6 } else { 4 + 2 * (calls > 2) as u64 })
        })
        .unwrap();
        assert_eq!(s.frame, 6);
        assert_eq!(calls, 4);
    }

    #[test]
    fn nothing_shown_is_an_error() {
        let mut chunk = [0u8; 8];
        let e = read_screen(&mut chunk, |_, _| Ok((0, [0, 2, 2, 8, 0, 2]))).err().unwrap();
        assert!(e.0.contains("shows nothing"), "{}", e.0);
    }
}

pub fn load(ctl: &Ctl, vm: u64, gpa: u64, data: &[u8]) -> Result<()> {
    for (i, chunk) in data.chunks(CTL_LOAD_MAX).enumerate() {
        ctl.call(CTL_VM_LOAD, &[vm, gpa + (i * CTL_LOAD_MAX) as u64], &[], chunk)?;
    }
    Ok(())
}

/// The host's rules for a disk made of extents, with errors that name the
/// extent: 1 to BLK_MAX_EXTENTS, 4 KiB aligned, each at least
/// BLK_MIN_EXTENT_SECTORS if there are several.  The host also refuses
/// extents that overlap each other or another VM's disk.
pub fn check_extents(extents: &[(u64, u64)]) -> Result<()> {
    if extents.is_empty() || extents.len() > BLK_MAX_EXTENTS {
        return err(format!("{} extents: a disk has 1 to {BLK_MAX_EXTENTS}", extents.len()));
    }
    for (k, &(start, sectors)) in extents.iter().enumerate() {
        if start % 8 != 0 || sectors % 8 != 0 || sectors == 0 {
            return err(format!("extent {k} ({start}:{sectors}) is not 4 KiB aligned"));
        }
        if extents.len() > 1 && sectors < BLK_MIN_EXTENT_SECTORS {
            return err(format!("extent {k} ({start}:{sectors}) is shorter than {BLK_MIN_EXTENT_SECTORS} sectors (4 MiB)"));
        }
    }
    Ok(())
}

/// Extents as START:SECTORS+START:SECTORS..., in 512-byte sectors.
pub fn parse_extents(s: &str) -> Result<Vec<(u64, u64)>> {
    s.split('+').map(|e| {
        let (start, sectors) = e.split_once(':').ok_or(Error(format!("bad extent {e}: START:SECTORS")))?;
        Ok((parse_num(start)?, parse_num(sectors)?))
    }).collect()
}

pub fn fmt_extents(extents: &[(u64, u64)]) -> String {
    extents.iter().map(|(s, n)| format!("{s}:{n}")).collect::<Vec<_>>().join("+")
}

/// Rows of an `lvm` report, in 512-byte sectors.
fn lvm(args: &[&str]) -> Result<Vec<Vec<String>>> {
    let out = std::process::Command::new("lvm")
        .args(args)
        .args(["--noheadings", "--nosuffix", "--units", "s", "--separator", "|"])
        .output()
        .map_err(|e| Error(format!("lvm: {e}")))?;
    if !out.status.success() {
        return err(format!("lvm {}: {}", args[0], String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().filter(|l| !l.trim().is_empty())
        .map(|l| l.split('|').map(|f| f.trim().to_string()).collect()).collect())
}

/// The extents of LVM logical volume `lv` (VG/LV) on host disk sectors,
/// in guest order, whose single PV starts at sector `pv_start` of the host
/// disk.  Only linear LVs on one PV qualify: no thin, snapshot, origin,
/// mirror, RAID or cache volumes.  Physically adjacent runs are joined.
pub fn lv_extents(lv: &str, pv_start: u64) -> Result<Vec<(u64, u64)>> {
    let (vg, _) = lv.split_once('/').ok_or(Error(format!("{lv}: not VG/LV")))?;
    let field = |rows: &[Vec<String>], what: &str| -> Result<u64> {
        let v = rows.first().and_then(|r| r.first()).ok_or(Error(format!("{lv}: no {what}")))?;
        parse_num(v.split('.').next().unwrap())
    };
    let vgs = lvm(&["vgs", "-o", "pv_count", vg])?;
    if field(&vgs, "PV count")? != 1 {
        return err(format!("{vg}: only a volume group on one PV qualifies"));
    }
    let extent_size = field(&lvm(&["vgs", "-o", "vg_extent_size", vg])?, "extent size")?;
    let pe_start = field(&lvm(&["pvs", "-S", &format!("vg_name={vg}"), "-o", "pe_start"])?, "PV")?;
    let mut segs = Vec::new();
    for row in lvm(&["lvs", "--segments", "-o", "lv_attr,segtype,seg_start_pe,seg_pe_ranges", lv])? {
        let [attr, segtype, start_pe, ranges] = &row[..] else { return err(format!("{lv}: unexpected lvs output")) };
        if !attr.starts_with('-') || segtype != "linear" {
            return err(format!("{lv}: a {segtype} volume (attributes {attr}); only plain linear volumes qualify"));
        }
        let (_, range) = ranges.rsplit_once(':').ok_or(Error(format!("{lv}: bad PE range {ranges}")))?;
        let (a, b) = range.split_once('-').ok_or(Error(format!("{lv}: bad PE range {ranges}")))?;
        segs.push((parse_num(start_pe)?, parse_num(a)?, parse_num(b)?));
    }
    segs.sort();
    let mut extents: Vec<(u64, u64)> = Vec::new();
    for (_, a, b) in segs {
        let (start, sectors) = (pv_start + pe_start + a * extent_size, (b - a + 1) * extent_size);
        match extents.last_mut() {
            Some(last) if last.0 + last.1 == start => last.1 += sectors,
            _ => extents.push((start, sectors)),
        }
    }
    check_extents(&extents).map_err(|e| Error(format!("{lv}: {}", e.0)))?;
    Ok(extents)
}

pub fn read_file(path: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| Error(format!("{path}: {e}")))
}

pub fn parse_num(s: &str) -> Result<u64> {
    s.parse().map_err(|_| Error(format!("bad number: {s}")))
}

/// A size in MiB, as bytes.
pub fn parse_mib(s: &str) -> Result<u64> {
    parse_num(s)?.checked_mul(1 << 20).ok_or(Error(format!("too large: {s} MiB")))
}

/// A VM's memory (CTL_VM_MEM_INFO), in bytes of host memory: boot RAM,
/// its hotplug region, and the target and plugged part of the region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemInfo {
    pub boot: u64,
    pub region: u64,
    pub target: u64,
    pub plugged: u64,
}

impl Ctl {
    pub fn mem_info(&self, vm: u64) -> Result<MemInfo> {
        let r = self.call(CTL_VM_MEM_INFO, &[vm], &[], &[])?;
        Ok(MemInfo { boot: r.vals[0], region: r.vals[1], target: r.vals[2], plugged: r.vals[3] })
    }

    /// Plug or unplug memory until the VM has `bytes` (boot RAM included,
    /// the rest in whole hotplug blocks of 128 MiB).  Returns at once.
    pub fn set_mem(&self, vm: u64, bytes: u64) -> Result<()> {
        self.call(CTL_VM_SET_MEM, &[vm, bytes], &[], &[]).map(|_| ())
    }
}

/// A VM to create and start with [`Ctl::create_vm`].
pub struct VmSpec<'a> {
    pub name: &'a str,
    /// RAM in bytes.
    pub mem: u64,
    pub vcpus: u64,
    /// The initramfs (several concatenated archives are fine); may be empty.
    pub initrd: &'a [u8],
    pub cmdline: &'a str,
    /// (disk, read-only, first sector, sectors)
    pub disks: Vec<(u64, bool, u64, u64)>,
    /// (disk, read-only, extents): disks made of extents (start, sectors)
    /// of a host disk, in guest order, such as LVM logical volumes
    /// ([`lv_extents`]).  They come after `disks`.
    pub volumes: Vec<(u64, bool, Vec<(u64, u64)>)>,
    /// I/O pool in bytes (0: default, 4 MiB; a power of two, 1-256 MiB).
    pub io_pool: u64,
    /// (switch, MAC or 0, NIC_* flags)
    pub nics: Vec<(u64, u64, u64)>,
    /// A virtio-gpu with one scanout of (width, height).
    pub gpu: Option<(u64, u64)>,
}

/// The I/O pool a VM with a GPU of `width` x `height` gets by default: its
/// buffers, CTL_GPU_POOL_IMAGES images, and 4 MiB for its other devices.
pub fn gpu_io_pool(width: u64, height: u64) -> u64 {
    (GPU_POOL_IMAGES * width * height * 4 + (4 << 20)).next_power_of_two()
}

/// A VM as listed by [`Ctl::vm_list`].
#[derive(Clone, Debug)]
pub struct Vm {
    pub id: u64,
    /// VM_CREATED, VM_RUNNING or VM_STOPPED.
    pub state: u32,
    pub vcpus: u32,
    pub ram: u64,
    pub name: String,
}

pub const VM_CREATED: u32 = 1;
pub const VM_RUNNING: u32 = 2;
pub const VM_STOPPED: u32 = 3;
pub const POWER_OFF: u64 = 0;
pub const POWER_REBOOT: u64 = 1;

/// Host resources, from [`Ctl::host_info`].
#[derive(Clone, Copy, Debug)]
pub struct HostInfo {
    pub cores: u64,
    pub free: u64,
    pub total: u64,
    pub disks: u64,
    pub vms: u64,
    pub nics: u64,
}

/// The host's IOMMU, from [`Ctl::iommu_info`].
#[derive(Clone, Copy, Debug)]
pub struct IommuInfo {
    /// IOMMU_NONE, IOMMU_OFF, IOMMU_ON or IOMMU_FAILED.
    pub state: u64,
    /// Devices can raise only their own interrupts.
    pub intremap: bool,
    pub units: u64,
    /// Devices confined to the memory they were given.
    pub confined: u64,
    /// Devices l4h drives that no IOMMU covers.
    pub unconfined: u64,
    /// Faults and errors the IOMMUs logged since boot.
    pub events: u64,
}

impl IommuInfo {
    pub fn state_name(&self) -> &'static str {
        match self.state {
            IOMMU_NONE => "none",
            IOMMU_OFF => "off (iommu=0)",
            IOMMU_ON => "on",
            IOMMU_FAILED => "failed (see the serial log)",
            _ => "unknown",
        }
    }
}

impl Ctl {
    /// The running host's build version; an error from a host that predates the call.
    pub fn host_version(&self) -> Result<String> {
        let r = self.call(CTL_HOST_VERSION, &[], &[], &[])?;
        if r.vals[0] > CTL_DATA_MAX as u64 {
            return err("invalid host version length");
        }
        String::from_utf8(r.data[..r.vals[0] as usize].to_vec())
            .map_err(|_| Error("host version is not UTF-8".into()))
    }

    /// The IOMMU's state; an error from a host that predates the call.
    pub fn iommu_info(&self) -> Result<IommuInfo> {
        let v = self.call(CTL_IOMMU_INFO, &[], &[], &[])?.vals;
        Ok(IommuInfo { state: v[0], intremap: v[1] != 0, units: v[2], confined: v[3], unconfined: v[4], events: v[5] })
    }

    pub fn host_info(&self) -> Result<HostInfo> {
        let r = self.call(CTL_HOST_INFO, &[], &[], &[])?;
        let v = r.vals;
        Ok(HostInfo { cores: v[0], free: v[1], total: v[2], disks: v[3], vms: v[4], nics: v[5] })
    }

    /// Create a VM, attach its disks and NICs, load its initrd and start
    /// it with the host's kernel.
    /// Returns the VM id and the MAC of each NIC.  On failure the VM is
    /// destroyed again.
    pub fn create_vm(&self, o: &VmSpec) -> Result<(u64, Vec<u64>)> {
        let mut name = [0u8; CTL_NAME_MAX];
        let n = o.name.len().min(CTL_NAME_MAX - 1);
        name[..n].copy_from_slice(&o.name.as_bytes()[..n]);
        let io_pool = match (o.io_pool, o.gpu) {
            (0, Some((w, h))) => gpu_io_pool(w, h),
            (p, _) => p,
        };
        let resp = self.call(CTL_VM_CREATE, &[o.mem, o.vcpus, 0, 0, io_pool], &name, &[])?;
        let (vm, initrd_gpa) = (resp.vals[0], resp.vals[1]);
        let r = (|| {
            for &(disk, ro, start, sectors) in &o.disks {
                self.call(CTL_BLK_ATTACH, &[vm, disk, ro as u64, start, sectors], &[], &[])?;
            }
            for (disk, ro, extents) in &o.volumes {
                self.attach_extents(vm, *disk, *ro, extents)?;
            }
            let mut macs = Vec::new();
            for &(sw, mac, flags) in &o.nics {
                macs.push(self.call(CTL_NIC_CREATE, &[vm, sw, mac, flags], &[], &[])?.vals[0]);
            }
            if let Some((w, h)) = o.gpu {
                self.call(CTL_GPU_ATTACH, &[vm, w, h], &[], &[])?;
            }
            if !o.initrd.is_empty() {
                load(self, vm, initrd_gpa, o.initrd)?;
            }
            let mut cmdline = o.cmdline.as_bytes().to_vec();
            cmdline.truncate(CTL_DATA_MAX - 1);
            self.call(CTL_VM_START, &[vm, initrd_gpa, o.initrd.len() as u64], &cmdline, &[])?;
            Ok((vm, macs))
        })();
        if r.is_err() {
            let _ = self.call(CTL_VM_DESTROY, &[vm], &[], &[]);
        }
        r
    }

    pub fn vm_list(&self) -> Result<Vec<Vm>> {
        let mut out = Vec::new();
        let mut first = 0u64;
        loop {
            let r = self.call(CTL_VM_LIST, &[first], &[], &[])?;
            let n = r.vals[0] as usize;
            if n == 0 {
                return Ok(out);
            }
            for i in 0..n {
                let vm: CtlVm = unsafe {
                    std::ptr::read_unaligned(r.data.as_ptr().add(i * std::mem::size_of::<CtlVm>()) as *const CtlVm)
                };
                let name_len = vm.name.iter().position(|&c| c == 0).unwrap_or(CTL_NAME_MAX);
                out.push(Vm {
                    id: vm.id as u64,
                    state: vm.state,
                    vcpus: vm.vcpus,
                    ram: vm.ram,
                    name: String::from_utf8_lossy(&vm.name[..name_len]).into_owned(),
                });
                first = vm.id as u64 + 1;
            }
        }
    }

    pub fn vm_destroy(&self, vm: u64) -> Result<()> {
        self.call(CTL_VM_DESTROY, &[vm], &[], &[]).map(|_| ())
    }

    /// Reset the machine (dom0 only; sync first).  Returns only if it did
    /// not reset.
    pub fn host_reboot(&self) -> Result<()> {
        self.call(CTL_HOST_REBOOT, &[], &[], &[]).map(|_| ())
    }

    /// Set the machine RTC to UTC seconds since the Unix epoch (dom0
    /// only). The host's boot-time clock anchor and guest clocks stay as
    /// they were; the RTC supplies the time on the next host boot.
    pub fn rtc_set(&self, seconds: u64) -> Result<()> {
        self.call(CTL_RTC_SET, &[seconds], &[], &[]).map(|_| ())
    }

    /// Ask the guest to power off or reboot cleanly (POWER_OFF, POWER_REBOOT).
    pub fn vm_shutdown(&self, vm: u64, how: u64) -> Result<()> {
        self.call(CTL_VM_SHUTDOWN, &[vm, how], &[], &[]).map(|_| ())
    }

    /// Cap each vCPU at `cap` percent of a core (0: no cap).
    pub fn vm_set_sched(&self, vm: u64, cap: u64) -> Result<()> {
        self.call(CTL_VM_SET_SCHED, &[vm, cap], &[], &[]).map(|_| ())
    }

    /// (CPU used over the last 100 ms in permille of a core, cap in percent).
    pub fn vm_stats(&self, vm: u64) -> Result<(u64, u64)> {
        let r = self.call(CTL_VM_STATS, &[vm], &[], &[])?;
        Ok((r.vals[0], r.vals[1]))
    }

    /// Host taint and seal bits (0-63) of this VM instance.
    pub fn vm_trust(&self, vm: u64) -> Result<(u64, u64)> {
        let r = self.call(CTL_VM_TRUST, &[vm], &[], &[])?;
        Ok((r.vals[0], r.vals[1]))
    }

    /// Console output from offset `off`: (next offset, bytes, bytes lost).
    pub fn console_read(&self, vm: u64, off: u64) -> Result<(u64, Vec<u8>, u64)> {
        let r = self.call(CTL_CONSOLE_READ, &[vm, off], &[], &[])?;
        Ok((r.vals[0], r.data[..r.vals[1] as usize].to_vec(), r.vals[2]))
    }

    /// Host diagnostics from `cursor`; `end == 0` selects a new snapshot.
    /// Returns (next cursor, text, lost records, snapshot end).
    pub fn logs_read(&self, cursor: u64, end: u64) -> Result<(u64, Vec<u8>, u64, u64)> {
        let r = self.call(CTL_LOG_READ, &[cursor, end], &[], &[])?;
        if r.vals[1] > CTL_DATA_MAX as u64 || r.vals[0] < cursor || r.vals[0] > r.vals[3] {
            return err("invalid host log response");
        }
        Ok((r.vals[0], r.data[..r.vals[1] as usize].to_vec(), r.vals[2], r.vals[3]))
    }

    pub fn switch_create(&self) -> Result<u64> {
        Ok(self.call(CTL_SWITCH_CREATE, &[], &[], &[])?.vals[0])
    }

    /// The ports of a switch and its uplink NIC, if any.
    pub fn switch_info(&self, sw: u64) -> Result<(Vec<CtlPort>, Option<u64>)> {
        let r = self.call(CTL_SWITCH_INFO, &[sw], &[], &[])?;
        let ports = (0..r.vals[0] as usize)
            .map(|i| unsafe {
                std::ptr::read_unaligned(r.data.as_ptr().add(i * std::mem::size_of::<CtlPort>()) as *const CtlPort)
            })
            .collect();
        Ok((ports, (r.vals[1] != u64::MAX).then_some(r.vals[1])))
    }
}

/// A host disk (a unit of a physical controller) and its native capacity
/// (512-byte sectors).
#[derive(Clone, Copy, Debug)]
pub struct DiskInfo {
    pub index: u64,
    pub bdf: u64,
    /// virtio-scsi: target (bits 0-7) and LUN (from bit 8); else 0.
    pub address: u64,
    pub owner: Option<u64>,
    pub failed: bool,
    pub kind: u64,
    pub sectors: u64,
    pub attachments: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct DiskAttachment {
    pub vm: u64,
    pub start: u64,
    pub sectors: u64,
    pub read_only: bool,
}

impl Ctl {
    pub fn disk_info(&self, index: u64) -> Result<DiskInfo> {
        let r = self.call(CTL_DISK_INFO, &[index], &[], &[])?;
        Ok(DiskInfo { index, bdf: r.vals[0] & 0xffff, address: r.vals[0] >> 16, owner: (r.vals[1] != u64::MAX).then_some(r.vals[1]),
            failed: r.vals[2] != 0, kind: r.vals[3], sectors: r.vals[4], attachments: r.vals[5] })
    }

    /// Give `vm` a disk made of `extents` (start, sectors) of host disk
    /// `disk`, in guest order.
    pub fn attach_extents(&self, vm: u64, disk: u64, read_only: bool, extents: &[(u64, u64)]) -> Result<()> {
        check_extents(extents)?;
        let list: Vec<u8> = extents.iter().flat_map(|&(s, n)| [s.to_le_bytes(), n.to_le_bytes()]).flatten().collect();
        self.call(CTL_BLK_ATTACH_EXTENTS, &[vm, disk, read_only as u64, 0, extents.len() as u64], &[], &list)?;
        Ok(())
    }

    /// One entry per window, or per extent of a disk made of them.
    pub fn disk_attachments(&self, disk: u64) -> Result<Vec<DiskAttachment>> {
        let mut out = Vec::new();
        let mut first = 0;
        loop {
            let r = self.call(CTL_BLK_INFO, &[disk, first], &[], &[])?;
            if r.vals[0] == 0 { return Ok(out); }
            if r.vals[0] <= first { return err("invalid attachment cursor"); }
            first = r.vals[0];
            out.push(DiskAttachment { vm: r.vals[1], start: r.vals[2], sectors: r.vals[3], read_only: r.vals[4] != 0 });
        }
    }

    /// Seed an unattached, 4 KiB aligned region; at most CTL_LOAD_MAX bytes.
    pub fn disk_write(&self, disk: u64, sector: u64, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > CTL_LOAD_MAX || bytes.len() % 4096 != 0 || sector % 8 != 0 {
            return err("disk write must be 4 KiB aligned and 1..=CTL_LOAD_MAX bytes");
        }
        self.call(CTL_BLK_WRITE, &[disk, sector, bytes.len() as u64, 0], &[], bytes)?;
        Ok(())
    }

    /// Explicit zero writes, including sparse image holes and recycled space.
    pub fn disk_zero(&self, disk: u64, sector: u64, sectors: u64) -> Result<()> {
        if sector % 8 != 0 || sectors == 0 || sectors % 8 != 0 || sector.checked_add(sectors).is_none() {
            return err("disk zero must be a finite 4 KiB aligned range");
        }
        let mut offset = 0;
        while offset < sectors {
            let count = (sectors - offset).min((CTL_LOAD_MAX / 512) as u64);
            self.call(CTL_BLK_WRITE, &[disk, sector + offset, count * 512, 1], &[], &[])?;
            offset += count;
        }
        Ok(())
    }

    pub fn disk_flush(&self, disk: u64) -> Result<()> {
        self.call(CTL_BLK_WRITE, &[disk, 0, 0, 0], &[], &[])?;
        Ok(())
    }
}

/// Attestation by the host (DESIGN.md §9.2) on /dev/l4h-attest, in any
/// guest. ACT/SEAL work without a TPM.
pub mod attest {
    use super::*;

    const REPORT: u32 = 1;
    const EVIDENCE: u32 = 2;
    const ACTIVATE: u32 = 3;
    const ACT: u32 = 4;
    const SEAL: u32 = 5;
    pub const FLAG_BITS: usize = 256;
    pub const DATA_SIZE: usize = 64;

    #[repr(C)]
    struct Ioc {
        op: u32,
        blob_len: u32,
        secret_len: u32,
        out_len: u32,
        data: u64,
        out: u64,
    }

    // _IOWR('L', 2, struct l4h_attest_ioc)
    const IOC: u64 = (3 << 30) | ((std::mem::size_of::<Ioc>() as u64) << 16) | ((b'L' as u64) << 8) | 2;

    fn call(op: u32, data: &[u8], blob_len: usize) -> Result<Vec<u8>> {
        let dev = File::options()
            .read(true)
            .write(true)
            .open("/dev/l4h-attest")
            .map_err(|e| Error(format!("/dev/l4h-attest: {e} (does the host provide attestation/flags?)")))?;
        let mut out = vec![0u8; 64 << 10];
        let mut c = Ioc {
            op,
            blob_len: blob_len as u32,
            secret_len: (data.len() - blob_len) as u32,
            out_len: out.len() as u32,
            data: data.as_ptr() as u64,
            out: out.as_mut_ptr() as u64,
        };
        if unsafe { ioctl(dev.as_raw_fd(), IOC, &mut c as *mut Ioc) } < 0 {
            let e = io::Error::last_os_error();
            return err(match e.raw_os_error() {
                Some(19) => "no TPM: flags only".into(),
                Some(38) => "host has no taint/seal operations".into(),
                _ => format!("attestation request {op} failed: {e}"),
            });
        }
        out.truncate(c.out_len as usize);
        Ok(out)
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Flags {
        pub taint: [u8; 32],
        pub seal: [u8; 32],
    }

    fn flags_call(op: u32, data: &[u8]) -> Result<Flags> {
        let r = call(op, data, data.len())?;
        if r.len() != 64 { return err("bad flags response length"); }
        Ok(Flags { taint: r[..32].try_into().unwrap(), seal: r[32..].try_into().unwrap() })
    }

    pub fn flags() -> Result<Flags> { flags_call(ACT, &[0; 32]) }

    /// Record all actions, or fail without taking any. With `seal`, each
    /// action can be taken at most once. Do not act if this call fails.
    pub fn act(bits: &[u8; 32], seal: bool) -> Result<Flags> {
        let mut data = [0; 36];
        data[..32].copy_from_slice(bits);
        data[32..].copy_from_slice(&(seal as u32).to_le_bytes());
        flags_call(ACT, &data)
    }

    pub fn seal(bits: &[u8; 32]) -> Result<Flags> { flags_call(SEAL, bits) }

    /// Host names and numeric bit numbers. The driver enforces which
    /// ranges userspace may act on and seal.
    pub fn bitmap(spec: &[&str]) -> Result<[u8; 32]> {
        let mut bits = [0; 32];
        for s in spec {
            let bit = match *s {
                "console-in" => 0,
                "console-out" => 1,
                _ => s.parse::<usize>().map_err(|_| Error(format!("unknown flag: {s}")))?,
            };
            if bit >= FLAG_BITS { return err(format!("flag out of range: {s}")); }
            bits[bit / 8] |= 1 << (bit % 8);
        }
        Ok(bits)
    }

    pub fn format_bits(bits: &[u8]) -> String {
        const TAINT: &[u8] = b"PFSRMBUDAWCIOELKXTNJ";
        let mut out = Vec::new();
        for i in 0..bits.len() * 8 {
            if bits[i / 8] & (1 << (i % 8)) == 0 { continue; }
            out.push(match i {
                0 => "0(console-in)".into(),
                1 => "1(console-out)".into(),
                i if (64..64 + TAINT.len()).contains(&i) => format!("{i}({})", TAINT[i - 64] as char),
                _ => i.to_string(),
            });
        }
        out.join(",")
    }

    /// A report (COSE_Sign1) on this guest with `data` (a verifier's nonce,
    /// a hash of a key; at most DATA_SIZE bytes, zero padded).
    pub fn report(data: &[u8]) -> Result<Vec<u8>> {
        if data.len() > DATA_SIZE {
            return err(format!("report data is at most {DATA_SIZE} bytes"));
        }
        let mut d = [0u8; DATA_SIZE];
        d[..data.len()].copy_from_slice(data);
        call(REPORT, &d, 0)
    }

    /// The host evidence (CBOR): the TPM quote over the host's signing key.
    pub fn evidence() -> Result<Vec<u8>> {
        call(EVIDENCE, &[], 0)
    }

    /// TPM2_ActivateCredential of a credential made for the host's
    /// attestation key, in the format of tpm2_makecredential (and
    /// tools/l4h-attest.py make-credential): magic 0xbadcc0de, version 1,
    /// TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET.  Returns the secret.
    pub fn activate(file: &[u8]) -> Result<Vec<u8>> {
        let bad = || Error("not a credential file (tpm2_makecredential format)".into());
        if file.get(..8) != Some(&[0xba, 0xdc, 0xc0, 0xde, 0, 0, 0, 1]) {
            return Err(bad());
        }
        let tpm2b = |at: usize| -> Result<&[u8]> {
            let n = u16::from_be_bytes(file.get(at..at + 2).ok_or_else(bad)?.try_into().unwrap()) as usize;
            file.get(at + 2..at + 2 + n).ok_or_else(bad)
        };
        let blob = tpm2b(8)?;
        let secret = tpm2b(10 + blob.len())?;
        call(ACTIVATE, &[blob, secret].concat(), blob.len())
    }
}
