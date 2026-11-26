// SPDX-License-Identifier: BSD-2-Clause

//! l4hctl: dom0 client library of the l4h control API (DESIGN.md §10.1), on
//! /dev/l4hctl.  The request layouts mirror `include/l4h/abi.h`.  The
//! `l4hctl` binary is a command-line front end; other dom0 programs (such
//! as an orchestration agent) link this library.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

pub const CTL_VERSION: u32 = 3;
pub const CTL_DATA_MAX: usize = 1984;
pub const CTL_LOAD_MAX: usize = 1 << 20;
/// The most bytes one zeroing BLK_WRITE asks for (hosts before it: CTL_LOAD_MAX).
pub const CTL_ZERO_MAX: u64 = 1 << 30;
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
pub const NIC_IP_FILTER: u64 = 4;
/// CTL_BLK_ATTACH flags.
pub const BLK_RO: u64 = 1;
pub const BLK_VOLATILE: u64 = 2;
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
pub const CTL_EP_SET: u32 = 32;
pub const CTL_EP_DEL: u32 = 33;
pub const CTL_EP_LIST: u32 = 34;
pub const CTL_STEER_SET: u32 = 35;
pub const CTL_STEER_DEL: u32 = 36;
pub const CTL_STEER_LIST: u32 = 37;
pub const CTL_PARTITION_INFO: u32 = 38;
pub const CTL_BLK_ATTACH_EXTENTS: u32 = 39;
pub const CTL_USB_INFO: u32 = 40;
pub const CTL_USB_ATTACH: u32 = 41;
pub const CTL_PCI_LIST: u32 = 42;
pub const CTL_NIC_BIND: u32 = 43;
pub const CTL_NIC_UNBIND: u32 = 44;
pub const CTL_NIC_RESTART: u32 = 45;
pub const CTL_NIC_CTL: u32 = 46;
pub const CTL_NIC_CTL_READ: u32 = 47;
pub const CTL_DRIVER_INFO: u32 = 48;
pub const CTL_DRIVER_LOAD: u32 = 49;
pub const CTL_NIC_TEST: u32 = 50;
pub const CTL_FIRMWARE_INFO: u32 = 51;
pub const CTL_FIRMWARE_WANTED: u32 = 52;
pub const CTL_FIRMWARE_LOAD: u32 = 53;
pub const FIRMWARE_NAME: usize = 48;
pub const CTL_IP_ADD: u32 = 54;
pub const CTL_IP_DEL: u32 = 55;
pub const CTL_IP_LIST: u32 = 56;
pub const CTL_DASHBOARD_TITLE: u32 = 57;
pub const CTL_VM_VCPU_STATS: u32 = 58;
pub const CTL_BLK_DISCARD: u32 = 59;
pub const DASHBOARD_TITLE_MAX: usize = 32;
pub const PCI_OWNER_NONE: u16 = 0;
pub const PCI_OWNER_BLKD: u16 = 1;
pub const PCI_OWNER_NETD: u16 = 2;
pub const PCI_OWNER_MEMD: u16 = 3;
pub const PCI_OWNER_USBD: u16 = 4;
pub const PCI_OWNER_FIRMWARE: u16 = 5;
pub const PCI_OWNER_ROOT: u16 = 6;
pub const PCI_OWNER_NICD: u16 = 7;

/// A function from root's boot-time PCI inventory (CTL_PCI_LIST).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtlPci {
    pub bdf: u16,
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    /// PCI_OWNER_*: the host service, independently of guest assignment.
    pub owner: u16,
}

impl CtlPci {
    pub fn owner_name(&self) -> &'static str {
        match self.owner {
            PCI_OWNER_NONE => "none",
            PCI_OWNER_BLKD => "blkd",
            PCI_OWNER_NETD => "netd",
            PCI_OWNER_MEMD => "memd",
            PCI_OWNER_USBD => "usbd",
            PCI_OWNER_FIRMWARE => "firmware",
            PCI_OWNER_ROOT => "root",
            PCI_OWNER_NICD => "nicd",
            _ => "unknown",
        }
    }
}
const _: () = assert!(std::mem::size_of::<CtlPci>() == 16);
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

/// A steering endpoint (CTL_EP_LIST).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CtlEp {
    pub id: u32,
    pub sw: u32,
    pub mac: u64,
    pub peer: u64,
}

/// A steering rule (CTL_STEER_LIST).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CtlSteer {
    pub id: u32,
    pub ep: u32,
    /// family | proto << 8 | port << 16
    pub matches: u64,
    pub ip_hi: u64,
    pub ip_lo: u64,
    pub targets: u64,
    pub in_frames: u64,
    pub out_frames: u64,
}

/// What a steering rule matches: an address, and optionally a protocol
/// and (TCP and UDP only) a port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SteerMatch {
    pub ip: std::net::IpAddr,
    pub proto: u8,
    pub port: u16,
}

impl SteerMatch {
    /// `IP[/PROTO[:PORT]]`, PROTO being tcp, udp, icmp, icmpv6, esp or a
    /// number.
    pub fn parse(s: &str) -> Result<SteerMatch> {
        let bad = || Error(format!("bad match: {s} (IP[/PROTO[:PORT]])"));
        let (ip, rest) = s.split_once('/').map_or((s, None), |(a, b)| (a, Some(b)));
        let ip = ip.parse().map_err(|_| bad())?;
        let (mut proto, mut port) = (0, 0);
        if let Some(rest) = rest {
            let (p, n) = rest.split_once(':').map_or((rest, None), |(a, b)| (a, Some(b)));
            proto = match p {
                "tcp" => 6,
                "udp" => 17,
                "icmp" => 1,
                "icmpv6" => 58,
                "esp" => 50,
                _ => p.parse().map_err(|_| bad())?,
            };
            if proto == 0 {
                return Err(bad());
            }
            if let Some(n) = n {
                port = n.parse().map_err(|_| bad())?;
                if port == 0 || (proto != 6 && proto != 17) {
                    return Err(bad());
                }
            }
        }
        Ok(SteerMatch { ip, proto, port })
    }

    /// CTL_STEER_SET's args 1-3.
    pub fn words(&self) -> [u64; 3] {
        let (family, hi, lo) = match self.ip {
            std::net::IpAddr::V4(a) => (4, 0, u32::from(a) as u64),
            std::net::IpAddr::V6(a) => {
                let v = u128::from(a);
                (6, (v >> 64) as u64, v as u64)
            }
        };
        [family | (self.proto as u64) << 8 | (self.port as u64) << 16, hi, lo]
    }

    pub fn from_words(m: u64, hi: u64, lo: u64) -> SteerMatch {
        let ip = if m as u8 == 6 {
            std::net::IpAddr::V6((((hi as u128) << 64) | lo as u128).into())
        } else {
            std::net::IpAddr::V4((lo as u32).into())
        };
        SteerMatch { ip, proto: (m >> 8) as u8, port: (m >> 16) as u16 }
    }
}

impl std::fmt::Display for SteerMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ip)?;
        match self.proto {
            0 => return Ok(()),
            6 => write!(f, "/tcp")?,
            17 => write!(f, "/udp")?,
            1 => write!(f, "/icmp")?,
            58 => write!(f, "/icmpv6")?,
            50 => write!(f, "/esp")?,
            p => write!(f, "/{p}")?,
        }
        if self.port != 0 {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

/// An address prefix a filtered port may send from (CTL_IP_ADD).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpPrefix {
    pub ip: std::net::IpAddr,
    pub len: u8,
}

impl IpPrefix {
    /// `IP[/LEN]`; without a length, the one address.  Bits past the
    /// length must be clear.
    pub fn parse(s: &str) -> Result<IpPrefix> {
        let bad = || Error(format!("bad prefix: {s} (IP[/LEN])"));
        let (ip, len) = s.split_once('/').map_or((s, None), |(a, b)| (a, Some(b)));
        let ip: std::net::IpAddr = ip.parse().map_err(|_| bad())?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let len = match len {
            Some(l) => l.parse().ok().filter(|&l| l <= max).ok_or_else(bad)?,
            None => max,
        };
        let p = IpPrefix { ip, len };
        let [_, hi, lo] = p.words();
        let v = (hi as u128) << 64 | lo as u128;
        let host = (max - len) as u32;
        if host != 0 && v << (128 - host) != 0 {
            return err(format!("bad prefix: {s}: bits set past /{len}"));
        }
        Ok(p)
    }

    /// CTL_IP_ADD's args 1-3.
    pub fn words(&self) -> [u64; 3] {
        let (family, hi, lo) = match self.ip {
            std::net::IpAddr::V4(a) => (4, 0, u32::from(a) as u64),
            std::net::IpAddr::V6(a) => {
                let v = u128::from(a);
                (6, (v >> 64) as u64, v as u64)
            }
        };
        [family | (self.len as u64) << 8, hi, lo]
    }

    pub fn from_words(m: u64, hi: u64, lo: u64) -> IpPrefix {
        let ip = if m as u8 == 6 {
            std::net::IpAddr::V6((((hi as u128) << 64) | lo as u128).into())
        } else {
            std::net::IpAddr::V4((lo as u32).into())
        };
        IpPrefix { ip, len: (m >> 8) as u8 }
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.len)
    }
}

/// A vNIC of a VM being created: its switch, MAC (0: the host picks),
/// NIC_* flags and, with NIC_IP_FILTER, the prefixes it may send from,
/// set before the VM starts.
#[derive(Clone, Debug, Default)]
pub struct NicSpec {
    pub switch: u64,
    pub mac: u64,
    pub flags: u64,
    pub ips: Vec<IpPrefix>,
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
    /// VM_FLAG_*.
    pub flags: u32,
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
        19 => "unsupported device",
        17 => "already exists",
        22 => "invalid argument",
        28 => "no space for devices",
        38 => "not supported",
        95 => "not supported by this kind of VM",
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
    /// The bytes the display's rows take, if its geometry is sane: each
    /// row of `width` 4-byte pixels fits in `stride`.
    fn size(&self) -> Option<usize> {
        if (self.stride as u64) < self.width as u64 * 4 {
            return None;
        }
        (self.stride as usize).checked_mul(self.height as usize)
    }

    /// Pixel (x, y) as (r, g, b); None for a pixel outside the display or
    /// its data, or an unknown format.
    pub fn rgb(&self, x: u32, y: u32) -> Option<(u8, u8, u8)> {
        if x >= self.width || y >= self.height {
            return None;
        }
        // Byte positions of red, green and blue in each format.
        let (r, g, b) = match self.format {
            1 | 2 => (2, 1, 0),     // B8G8R8A8, B8G8R8X8
            3 | 4 => (1, 2, 3),     // A8R8G8B8, X8R8G8B8
            67 | 134 => (0, 1, 2),  // R8G8B8A8, R8G8B8X8
            68 | 121 => (3, 2, 1),  // X8B8G8R8, A8B8G8R8
            _ => return None,
        };
        let off = (y as usize).checked_mul(self.stride as usize)?.checked_add((x as usize).checked_mul(4)?)?;
        let p = self.data.get(off..off.checked_add(4)?)?;
        Some((p[r], p[g], p[b]))
    }

    /// As a binary PPM (P6).
    pub fn ppm(&self) -> Result<Vec<u8>> {
        if !matches!(self.format, 1..=4 | 67 | 134 | 68 | 121) {
            return err(format!("unknown pixel format {}", self.format));
        }
        if self.size().is_none_or(|n| self.data.len() < n) {
            return err(format!("screenshot: {}x{} with stride {} does not fit its {} bytes",
                self.width, self.height, self.stride, self.data.len()));
        }
        let mut out = format!("P6\n{} {}\n255\n", self.width, self.height).into_bytes();
        for y in 0..self.height {
            for x in 0..self.width {
                let (r, g, b) = self.rgb(x, y).ok_or(Error(format!("screenshot: no pixel {x},{y}")))?;
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
        // The display's bytes: 0 until known (nothing shown reads as 0).
        let mut need = 0;
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
                if s.format != 0 {
                    need = s.size().ok_or_else(|| Error(format!("screenshot: bad geometry {}x{} with stride {}",
                        s.width, s.height, s.stride)))?;
                }
            } else if v[5] != s.frame {
                torn = true;
                break;
            }
            if n > chunk.len() {
                return err("screenshot: bad length");
            }
            s.data.extend_from_slice(&chunk[..n]);
            if n == 0 || s.data.len() >= need {
                break;
            }
        }
        // A torn read says nothing yet, not even whether anything is shown.
        if torn {
            if s.format != 0 && s.data.len() >= need {
                last = Some(s);
            }
            continue;
        }
        if s.format == 0 {
            return err("screenshot: the VM shows nothing");
        }
        // The host stopped before the whole display: not a picture.
        if s.data.len() < need {
            return err(format!("screenshot: truncated, {} of {} bytes", s.data.len(), need));
        }
        return Ok(s);
    }
    last.ok_or(Error("screenshot: the display keeps changing".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_prefixes() {
        let p = IpPrefix::parse("10.0.0.5").unwrap();
        assert_eq!(p.words(), [4 | 32 << 8, 0, 0x0a00_0005]);
        assert_eq!(p.to_string(), "10.0.0.5/32");
        assert_eq!(IpPrefix::parse("10.1.0.0/16").unwrap().words(), [4 | 16 << 8, 0, 0x0a01_0000]);
        assert_eq!(IpPrefix::parse("0.0.0.0/0").unwrap().words(), [4, 0, 0]);
        let v6 = IpPrefix::parse("2001:db8::/32").unwrap();
        assert_eq!(v6.words(), [6 | 32 << 8, 0x2001_0db8_0000_0000, 0]);
        assert_eq!(IpPrefix::from_words(6 | 32 << 8, 0x2001_0db8_0000_0000, 0), v6);
        assert_eq!(IpPrefix::parse("fe80::1").unwrap().len, 128);
        for bad in ["10.0.0.5/24", "10.0.0.0/33", "2001:db8::1/64", "::/129", "x", "10.0.0.0/", "10.0.0.0/-1"] {
            assert!(IpPrefix::parse(bad).is_err(), "{bad}");
        }
    }

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
    fn a_short_display_is_an_error() {
        // The host stops after one chunk of two.
        let mut chunk = [0u8; 8];
        let e = read_screen(&mut chunk, |off, buf| {
            if off == 0 { display(off, buf, 4) } else { Ok((0, [0, 2, 2, 8, 2, 4])) }
        })
        .err()
        .unwrap();
        assert!(e.0.contains("truncated, 8 of 16"), "{}", e.0);
        // Rows narrower than their pixels, or too large to address.
        for (w, h, stride) in [(4, 2, 8), (u32::MAX as u64, 1, 4)] {
            let e = read_screen(&mut chunk, |_, buf| {
                buf[..8].fill(0);
                Ok((0, [8, w, h, stride, 2, 4]))
            })
            .err()
            .unwrap();
            assert!(e.0.contains("bad geometry"), "{}", e.0);
        }
    }

    #[test]
    fn pixels_outside_the_display_or_its_data() {
        let s = Screen { width: 2, height: 2, stride: 8, format: 2, frame: 0, data: (0..16).collect() };
        assert_eq!(s.rgb(1, 1), Some((14, 13, 12)));
        assert_eq!(s.rgb(2, 0), None);
        assert_eq!(s.rgb(0, 2), None);
        assert_eq!(s.rgb(u32::MAX, u32::MAX), None);
        assert_eq!(s.ppm().unwrap().len(), "P6\n2 2\n255\n".len() + 12);
        // Data shorter than the geometry says, a stride too short for a
        // row, an unknown format: errors, not panics.
        let short = Screen { data: (0..12).collect(), ..s };
        assert_eq!(short.rgb(1, 1), None);
        assert!(short.ppm().unwrap_err().0.contains("does not fit"));
        let narrow = Screen { width: 4, data: (0..16).collect(), ..short };
        assert!(narrow.ppm().is_err());
        let odd = Screen { width: 2, format: 99, data: (0..16).collect(), ..narrow };
        assert!(odd.ppm().unwrap_err().0.contains("unknown pixel format"));
        let huge = Screen { width: u32::MAX, height: u32::MAX, stride: u32::MAX, format: 2, frame: 0, data: vec![0; 16] };
        assert_eq!(huge.rgb(u32::MAX - 1, u32::MAX - 1), None);
        assert!(huge.ppm().is_err());
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
    linear_extents(pv_start, pe_start, extent_size, segs).map_err(|e| Error(format!("{lv}: {}", e.0)))
}

/// Map LVM's (logical start, first PE, last PE) segments to host sectors.
fn linear_extents(pv_start: u64, pe_start: u64, extent_size: u64, mut segs: Vec<(u64, u64, u64)>)
    -> Result<Vec<(u64, u64)>> {
    let invalid = || Error("invalid or overflowing physical extent range".into());
    let base = pv_start.checked_add(pe_start).ok_or_else(invalid)?;
    segs.sort();
    let mut extents: Vec<(u64, u64)> = Vec::new();
    for (_, a, b) in segs {
        let start = a.checked_mul(extent_size).and_then(|off| base.checked_add(off)).ok_or_else(invalid)?;
        let sectors = b.checked_sub(a).and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(extent_size)).ok_or_else(invalid)?;
        start.checked_add(sectors).ok_or_else(invalid)?;
        match extents.last_mut() {
            Some(last) if last.0.checked_add(last.1) == Some(start) => {
                last.1 = last.1.checked_add(sectors).ok_or_else(invalid)?;
            }
            _ => extents.push((start, sectors)),
        }
    }
    check_extents(&extents)?;
    Ok(extents)
}

#[cfg(test)]
mod extent_tests {
    use super::*;

    #[test]
    fn linear_segments_keep_guest_order_and_join_adjacent_runs() {
        let segs = vec![(5, 7, 7), (0, 10, 11), (4, 4, 4), (2, 2, 3)];
        assert_eq!(linear_extents(4096, 2048, 8192, segs).unwrap(),
            [(88064, 16384), (22528, 24576), (63488, 8192)]);
        // The last aligned end representable in u64 is still valid.
        assert_eq!(linear_extents(u64::MAX - 8199, 0, 8192, vec![(0, 0, 0)]).unwrap(),
            [(u64::MAX - 8199, 8192)]);
    }

    #[test]
    fn linear_segments_reject_overflow_and_reversed_ranges() {
        for (name, pv, head, size, segs) in [
            ("PV start plus metadata", u64::MAX - 2047, 2048, 8192, vec![(0, 0, 0)]),
            ("PE offset multiplication", 0, 0, 8, vec![(0, 1 << 61, 1 << 61)]),
            ("PV base plus PE offset", u64::MAX - 8191, 0, 8192, vec![(0, 1, 1)]),
            ("inclusive PE count", 0, 0, 8, vec![(0, 0, u64::MAX)]),
            ("sector count multiplication", 0, 0, 8192, vec![(0, 0, 1 << 51)]),
            ("reversed PE range", 0, 0, 8192, vec![(0, 2, 0)]),
            ("extent end", u64::MAX - 4095, 0, 8192, vec![(0, 0, 0)]),
            ("coalesced extent end", 0, 0, 8, vec![(0, 0, (1 << 61) - 2), (1, (1 << 61) - 1, (1 << 61) - 1)]),
        ] {
            let result = linear_extents(pv, head, size, segs);
            assert!(result.is_err(), "{name}: {result:?}");
        }
    }

    #[test]
    fn linear_segments_still_obey_volume_constraints() {
        for (pv, size, segs) in [
            (0, 8192, vec![]),
            (1, 8192, vec![(0, 0, 0)]),
            (0, 0, vec![(0, 0, 0)]),
            (0, 8, vec![(0, 0, 0), (1, 2, 2)]),
        ] {
            assert!(linear_extents(pv, 0, size, segs).is_err());
        }
    }
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
/// Then of the host's free memory, the same for every VM: what is reported
/// to the hypervisor, and what is untouched since boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemInfo {
    pub boot: u64,
    pub region: u64,
    pub target: u64,
    pub plugged: u64,
    pub reported: u64,
    pub clean: u64,
}

impl Ctl {
    pub fn mem_info(&self, vm: u64) -> Result<MemInfo> {
        let r = self.call(CTL_VM_MEM_INFO, &[vm], &[], &[])?;
        let v = r.vals;
        Ok(MemInfo { boot: v[0], region: v[1], target: v[2], plugged: v[3], reported: v[4], clean: v[5] })
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
    /// (disk, BLK_* flags, first sector, sectors)
    pub disks: Vec<(u64, u64, u64, u64)>,
    /// (disk, BLK_* flags, extents): disks made of extents (start, sectors)
    /// of a host disk, in guest order, such as LVM logical volumes
    /// ([`lv_extents`]).  They come after `disks`.
    pub volumes: Vec<(u64, u64, Vec<(u64, u64)>)>,
    /// I/O pool in bytes (0: default, 4 MiB; a power of two, 1-256 MiB).
    pub io_pool: u64,
    pub nics: Vec<NicSpec>,
    /// A virtio-gpu with one scanout of (width, height).
    pub gpu: Option<(u64, u64)>,
    /// Whole USB controllers ([`Ctl::usb_info`] indices).
    pub usbs: Vec<u64>,
    /// An HVM guest's kernel (a bzImage or an ELF vmlinux for x86-64, an
    /// `Image` or an ELF vmlinux for arm64),
    /// which it runs unmodified instead of the host's; None for an l4h
    /// guest.  HVM guests have no GPU or USB.
    pub kernel: Option<&'a [u8]>,
}

/// Where an HVM guest's kernel image and initrd go in its RAM (their
/// GPAs): above where the kernel runs (on x86-64 from 16 MiB, or its ELF
/// segments, all in the RAM below the 3 GiB hole; on arm64 from RAM_BASE +
/// 2 MiB), each 2 MiB aligned.
pub fn hvm_layout(kernel: &[u8], initrd_len: u64, ram: u64) -> Result<(u64, u64)> {
    const MIB2: u64 = 2 << 20;
    const LOW_RAM_MAX: u64 = 3 << 30;
    let le = |off: usize, n: usize| -> Result<u64> {
        let b = off.checked_add(n).and_then(|end| kernel.get(off..end)).ok_or(Error("kernel: truncated header".into()))?;
        Ok(b.iter().rev().fold(0, |v, &x| v << 8 | x as u64))
    };
    if let Some(run_end) = arm64_run_end(kernel, &le)? {
        return arm64_layout(kernel.len() as u64, initrd_len, ram, run_end);
    }
    let end = if kernel.starts_with(b"\x7fELF") {
        // ELF64 x86-64: its PT_LOAD segments' physical addresses.
        if le(4, 1)? != 2 || le(5, 1)? != 1 || le(18, 2)? != 62 {
            return err("kernel: not an x86-64 ELF64 image");
        }
        let (phoff, phentsize, phnum) = (le(32, 8)? as usize, le(54, 2)? as usize, le(56, 2)? as usize);
        let mut end = 0u64;
        for i in 0..phnum {
            let ph = i.checked_mul(phentsize).and_then(|o| phoff.checked_add(o)).ok_or(Error("kernel: bad program headers".into()))?;
            if le(ph, 4)? == 1 {
                let e = le(ph + 24, 8)?.checked_add(le(ph + 40, 8)?).ok_or(Error("kernel: segment past the address space".into()))?;
                end = end.max(e);
            }
        }
        if end == 0 {
            return err("kernel: ELF image without loadable segments");
        }
        end
    } else if le(0x202, 4)? == u32::from_le_bytes(*b"HdrS") as u64 && le(0x1fe, 2)? == 0xaa55 {
        // A bzImage: its payload runs from its preferred address (16 MiB
        // unless it says otherwise) and takes init_size there.
        if le(0x206, 2)? < 0x020c || le(0x236, 2)? & 1 == 0 {
            return err("kernel: not a 64-bit bzImage (boot protocol 2.12+, XLF_KERNEL_64)");
        }
        let setup = (match le(0x1f1, 1)? { 0 => 4, s => s } + 1) * 512;
        let payload = (kernel.len() as u64).checked_sub(setup).ok_or(Error("kernel: truncated bzImage".into()))?;
        // As l4h-hvm's boot::load_address: a kernel that cannot be
        // relocated runs at its preferred address, a relocatable one there
        // if it is aligned as asked, else at 16 MiB.
        let (pref, align) = (le(0x258, 8)?, le(0x230, 4)?.max(1));
        let load = match pref {
            0 => 16 << 20,
            p if le(0x234, 1)? == 0 || p % align == 0 => p,
            _ => 16 << 20,
        };
        load.checked_add(le(0x260, 4)?.max(payload)).ok_or(Error("kernel: placed past the address space".into()))?
    } else {
        return err("kernel: neither a bzImage nor an ELF vmlinux");
    };
    let past = || Error("kernel: placed past the address space".into());
    let image = end.checked_next_multiple_of(MIB2).ok_or_else(past)?;
    let initrd = image.checked_add(kernel.len() as u64).and_then(|e| e.checked_next_multiple_of(MIB2)).ok_or_else(past)?;
    let need = initrd.checked_add(initrd_len).ok_or_else(past)?;
    let top = ram.min(LOW_RAM_MAX);
    if need > top {
        return err(format!("kernel and initrd need {} MiB of RAM below 3 GiB; the VM has {} MiB there", need.div_ceil(1 << 20), top >> 20));
    }
    Ok((image, initrd))
}

/// An AArch64 HVM guest's RAM starts here (l4h_host::hvm::arm::RAM_BASE);
/// its first 2 MiB hold the device tree, and its kernel runs from the next.
const ARM64_RAM_BASE: u64 = 0x4000_0000;
const ARM64_KERNEL_BASE: u64 = ARM64_RAM_BASE + (2 << 20);

/// Where an arm64 `Image` or AArch64 ELF `vmlinux` ends as it runs, as
/// l4h-hvm's boot.rs lays it out; None for any other image.
fn arm64_run_end(kernel: &[u8], le: &impl Fn(usize, usize) -> Result<u64>) -> Result<Option<u64>> {
    const EM_AARCH64: u64 = 183;
    let past = || Error("kernel: placed past the address space".into());
    if kernel.starts_with(b"\x7fELF") {
        if le(18, 2)? != EM_AARCH64 {
            return Ok(None);
        }
        if le(4, 1)? != 2 || le(5, 1)? != 1 {
            return err("kernel: not a little-endian AArch64 ELF64 image");
        }
        let (phoff, phentsize, phnum) = (le(32, 8)? as usize, le(54, 2)? as usize, le(56, 2)? as usize);
        let (mut low, mut high) = (u64::MAX, 0u64);
        for i in 0..phnum {
            let ph = i.checked_mul(phentsize).and_then(|o| phoff.checked_add(o)).ok_or(Error("kernel: bad program headers".into()))?;
            if le(ph, 4)? == 1 && le(ph + 40, 8)? != 0 {
                let vaddr = le(ph + 16, 8)?;
                low = low.min(vaddr);
                high = high.max(vaddr.checked_add(le(ph + 40, 8)?).ok_or_else(past)?);
            }
        }
        if high == 0 {
            return err("kernel: ELF image without loadable segments");
        }
        return ARM64_KERNEL_BASE.checked_add(high - low).map(Some).ok_or_else(past);
    }
    if kernel.len() < 64 || le(56, 4)? != 0x644d_5241 {
        return Ok(None);
    }
    // Before Linux 3.17 image_size is 0: it runs at 512 KiB in 64 MiB or so.
    let (text, size) = match le(16, 8)? {
        0 => (0x8_0000, (64u64 << 20).max(kernel.len() as u64)),
        size => (le(8, 8)?, size),
    };
    if text >= 2 << 20 {
        return err("kernel: arm64 Image with a text offset past 2 MiB");
    }
    ARM64_KERNEL_BASE.checked_add(text).and_then(|a| a.checked_add(size)).map(Some).ok_or_else(past)
}

/// Stage an arm64 kernel and initrd above where it runs, each 2 MiB
/// aligned, in the guest's one range of RAM.
fn arm64_layout(kernel_len: u64, initrd_len: u64, ram: u64, run_end: u64) -> Result<(u64, u64)> {
    const MIB2: u64 = 2 << 20;
    let past = || Error("kernel: placed past the address space".into());
    let image = run_end.checked_next_multiple_of(MIB2).ok_or_else(past)?;
    let initrd = image.checked_add(kernel_len).and_then(|e| e.checked_next_multiple_of(MIB2)).ok_or_else(past)?;
    let need = initrd.checked_add(initrd_len).ok_or_else(past)?;
    let top = ARM64_RAM_BASE.checked_add(ram).ok_or_else(past)?;
    if need > top {
        return err(format!("kernel and initrd need {} MiB of RAM; the VM has {} MiB", (need - ARM64_RAM_BASE).div_ceil(1 << 20), ram >> 20));
    }
    // arm64/booting.rst: the initrd is in the 1 GiB-aligned 32 GiB window
    // that has the kernel's start.
    let window = ARM64_KERNEL_BASE & !((1u64 << 30) - 1);
    if initrd_len != 0 && (initrd < window || need > window + (32u64 << 30)) {
        return err("kernel: the initrd would end past the kernel's 32 GiB window");
    }
    Ok((image, initrd))
}

/// An xHCI controller of the host, as [`Ctl::usb_info`] reports it.
#[derive(Clone, Debug)]
pub struct UsbInfo {
    pub bdf: u16,
    pub vendor: u16,
    pub device: u16,
    pub usb2_ports: u16,
    pub usb3_ports: u16,
    /// "firmware", "idle", "vm", "failed" or "unsupported".
    pub state: &'static str,
    pub owner: Option<u64>,
    /// Requests usbd refused as malformed.
    pub refused: u64,
    /// Why it is unsupported.
    pub reason: String,
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
    /// An HVM guest.
    pub hvm: bool,
}

pub const VM_CREATED: u32 = 1;
pub const VM_RUNNING: u32 = 2;
pub const VM_STOPPED: u32 = 3;
/// CTL_VM_CREATE args[5]: an HVM guest, which runs an unmodified x86-64
/// kernel (`VmSpec::kernel`) with standard virtio-pci devices.
pub const VM_CREATE_HVM: u64 = 1 << 0;
/// CtlVm::flags: an HVM guest.
pub const VM_FLAG_HVM: u32 = 1 << 0;
pub const POWER_OFF: u64 = 0;
pub const POWER_REBOOT: u64 = 1;

/// Host resources, from [`Ctl::host_info`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostInfo {
    pub cores: u64,
    /// Distinct physical cores; `cores` on a host that predates it.
    pub physical_cores: u64,
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
    /// The running host's build version and kernel (seL4/FL4); an error from a host that predates the call.
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
        Ok(parse_host_info(r.vals, &r.data))
    }

    /// Every PCI function root enumerated, in BDF order. This is a
    /// read-only snapshot; queries never rescan or reconfigure hardware.
    pub fn pci_list(&self) -> Result<Vec<CtlPci>> {
        self.list(CTL_PCI_LIST, |p: &CtlPci| p.bdf as u32)
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
        // Each USB controller's transfers bounce through the pool: 4 MiB
        // more each by default.
        let io_pool = match (io_pool, o.usbs.len() as u64) {
            (0, 0) => 0,
            (0, n) => ((4 << 20) + (n << 22)).next_power_of_two(),
            (p, 0) => p,
            (p, n) => (p + (n << 22)).next_power_of_two(),
        };
        let io_pool = if o.io_pool != 0 { o.io_pool } else { io_pool };
        let hvm = match o.kernel {
            Some(k) => Some(hvm_layout(k, o.initrd.len() as u64, o.mem)?),
            None => None,
        };
        let flags = if hvm.is_some() { VM_CREATE_HVM } else { 0 };
        let resp = self.call(CTL_VM_CREATE, &[o.mem, o.vcpus, 0, 0, io_pool, flags], &name, &[])?;
        let (vm, initrd_gpa) = (resp.vals[0], resp.vals[1]);
        let (kernel_gpa, initrd_gpa) = hvm.unwrap_or((0, initrd_gpa));
        let r = (|| {
            for &(disk, flags, start, sectors) in &o.disks {
                self.call(CTL_BLK_ATTACH, &[vm, disk, flags, start, sectors], &[], &[])?;
            }
            for (disk, flags, extents) in &o.volumes {
                self.attach_extents(vm, *disk, *flags, extents)?;
            }
            let mut macs = Vec::new();
            for n in &o.nics {
                let mac = self.call(CTL_NIC_CREATE, &[vm, n.switch, n.mac, n.flags], &[], &[])?.vals[0];
                if !n.ips.is_empty() {
                    // The port is known by its MAC: two of this VM's on the
                    // switch with one MAC would be ambiguous.
                    let (ports, _) = self.switch_info(n.switch)?;
                    let port = match ports.iter().filter(|p| p.vm as u64 == vm && p.mac == mac).collect::<Vec<_>>()[..] {
                        [p] => p.port as u64,
                        _ => return err(format!("vm {vm}: no one port with mac {} on switch {} for ip=", fmt_mac(mac), n.switch)),
                    };
                    for p in &n.ips {
                        self.ip_add(port, p)?;
                    }
                }
                macs.push(mac);
            }
            if let Some((w, h)) = o.gpu {
                self.call(CTL_GPU_ATTACH, &[vm, w, h], &[], &[])?;
            }
            for &c in &o.usbs {
                self.call(CTL_USB_ATTACH, &[vm, c], &[], &[])?;
            }
            if let Some(k) = o.kernel {
                load(self, vm, kernel_gpa, k)?;
            }
            if !o.initrd.is_empty() {
                load(self, vm, initrd_gpa, o.initrd)?;
            }
            let mut cmdline = o.cmdline.as_bytes().to_vec();
            // An HVM guest's launch digest is over the command line as
            // given: one cut short here would be another guest's.
            if o.kernel.is_some() && cmdline.len() > CTL_DATA_MAX - 1 {
                return err(format!("--cmdline: {} bytes; at most {}", cmdline.len(), CTL_DATA_MAX - 1));
            }
            cmdline.truncate(CTL_DATA_MAX - 1);
            let kernel_len = o.kernel.map_or(0, |k| k.len() as u64);
            self.call(CTL_VM_START, &[vm, initrd_gpa, o.initrd.len() as u64, kernel_gpa, kernel_len, 0], &cmdline, &[])?;
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
                    hvm: vm.flags & VM_FLAG_HVM != 0,
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

    /// Show `title` in the title bar of the host's dashboard, in place of
    /// "l4h" (dom0 only); an empty one restores "l4h".  At most
    /// DASHBOARD_TITLE_MAX bytes of printable ASCII.  The host keeps it
    /// until it is set again or the host reboots.
    pub fn dashboard_title(&self, title: &str) -> Result<()> {
        if title.len() > DASHBOARD_TITLE_MAX {
            return err(format!("title longer than {DASHBOARD_TITLE_MAX} characters"));
        }
        if !title.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return err("title must be printable ASCII");
        }
        let mut bytes = [0u8; DASHBOARD_TITLE_MAX];
        bytes[..title.len()].copy_from_slice(title.as_bytes());
        let args: [u64; DASHBOARD_TITLE_MAX / 8] =
            std::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()));
        let resp = self.raw_call(CTL_DASHBOARD_TITLE, &args, &[], 0, 0)?;
        match resp.status {
            0.. => Ok(()),
            -19 => err("the host shows no dashboard (no boot framebuffer)"),
            e => err(format!("request {CTL_DASHBOARD_TITLE} failed: {}", errno_name(-e))),
        }
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

    /// Each vCPU's host core and CPU over the last 100 ms, and the VMM's
    /// (`CTL_VM_VCPU_STATS`): an error from a host that predates the call.
    pub fn vm_vcpu_stats(&self, vm: u64) -> Result<VcpuStats> {
        let mut out = VcpuStats::default();
        loop {
            let r = self.call(CTL_VM_VCPU_STATS, &[vm, out.vcpus.len() as u64], &[], &[])?;
            let page = parse_vcpu_stats(r.vals, &r.data);
            out.vmm = page.vmm;
            if page.vcpus.is_empty() {
                return Ok(out);
            }
            out.vcpus.extend(page.vcpus);
        }
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

    /// Set the steering endpoint (switch, mac) with gateway `peer`;
    /// returns its id.
    pub fn ep_set(&self, sw: u64, mac: u64, peer: u64) -> Result<u64> {
        Ok(self.call(CTL_EP_SET, &[sw, mac, peer], &[], &[])?.vals[0])
    }

    pub fn ep_del(&self, ep: u64) -> Result<()> {
        self.call(CTL_EP_DEL, &[ep], &[], &[]).map(|_| ())
    }

    pub fn ep_list(&self) -> Result<Vec<CtlEp>> {
        self.list(CTL_EP_LIST, |e: &CtlEp| e.id)
    }

    /// Steer endpoint `ep`'s traffic matching `m` to guest port `port`;
    /// returns the rule's id.
    pub fn steer_set(&self, ep: u64, m: &SteerMatch, port: u64) -> Result<u64> {
        if port >= 64 {
            return err(format!("bad port: {port}"));
        }
        let [w, hi, lo] = m.words();
        Ok(self.call(CTL_STEER_SET, &[ep, w, hi, lo, 1 << port], &[], &[])?.vals[0])
    }

    pub fn steer_del(&self, rule: u64) -> Result<()> {
        self.call(CTL_STEER_DEL, &[rule], &[], &[]).map(|_| ())
    }

    pub fn steer_list(&self) -> Result<Vec<CtlSteer>> {
        self.list(CTL_STEER_LIST, |r: &CtlSteer| r.id)
    }

    /// Let filtered guest port `port` send from `p`.
    pub fn ip_add(&self, port: u64, p: &IpPrefix) -> Result<()> {
        let [w, hi, lo] = p.words();
        self.call(CTL_IP_ADD, &[port, w, hi, lo], &[], &[]).map(|_| ())
    }

    pub fn ip_del(&self, port: u64, p: &IpPrefix) -> Result<()> {
        let [w, hi, lo] = p.words();
        self.call(CTL_IP_DEL, &[port, w, hi, lo], &[], &[]).map(|_| ())
    }

    /// Whether guest port `port` is filtered, and the prefixes it may
    /// send from.
    pub fn ip_list(&self, port: u64) -> Result<(bool, Vec<IpPrefix>)> {
        let r = self.call(CTL_IP_LIST, &[port], &[], &[])?;
        let n = (r.vals[0] as usize).min(CTL_DATA_MAX / 24);
        let ips = (0..n)
            .map(|i| {
                let w = |k: usize| u64::from_ne_bytes(r.data[i * 24 + k * 8..][..8].try_into().unwrap());
                IpPrefix::from_words(w(0), w(1), w(2))
            })
            .collect();
        Ok((r.vals[1] != 0, ips))
    }

    /// All entries of a list op that takes the first id and returns a
    /// count and an array.
    fn list<T: Copy>(&self, op: u32, id: impl Fn(&T) -> u32) -> Result<Vec<T>> {
        let mut out = Vec::new();
        let mut first = 0u64;
        loop {
            let r = self.call(op, &[first], &[], &[])?;
            let n = (r.vals[0] as usize).min(CTL_DATA_MAX / std::mem::size_of::<T>());
            if n == 0 {
                return Ok(out);
            }
            for i in 0..n {
                let e: T = unsafe { std::ptr::read_unaligned(r.data.as_ptr().add(i * std::mem::size_of::<T>()) as *const T) };
                first = id(&e) as u64 + 1;
                out.push(e);
            }
        }
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
    /// virtio-scsi: target (bits 0-7) and LUN (from bit 8); AHCI: SATA port; else 0.
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
    /// xHCI controller `index`, or None past the last.
    pub fn usb_info(&self, index: u64) -> Result<Option<UsbInfo>> {
        let r = self.raw_call(CTL_USB_INFO, &[index], &[], 0, 0)?;
        match r.status {
            0 => {}
            -2 => return Ok(None),
            s => return err(format!("request {CTL_USB_INFO} failed: {}", errno_name(-s))),
        }
        let v = r.vals;
        let state = match v[3] {
            0 => "firmware",
            1 => "idle",
            2 => "vm",
            3 => "failed",
            _ => "unsupported",
        };
        let n = r.data.iter().position(|&c| c == 0).unwrap_or(r.data.len());
        Ok(Some(UsbInfo {
            bdf: v[0] as u16,
            vendor: v[1] as u16,
            device: (v[1] >> 16) as u16,
            usb2_ports: v[2] as u16,
            usb3_ports: (v[2] >> 16) as u16,
            state,
            owner: (v[4] != u64::MAX).then_some(v[4]),
            refused: v[5],
            reason: String::from_utf8_lossy(&r.data[..n]).into_owned(),
        }))
    }

    /// Every xHCI controller of the host.
    pub fn usbs(&self) -> Result<Vec<UsbInfo>> {
        let mut v = Vec::new();
        while let Some(u) = self.usb_info(v.len() as u64)? {
            v.push(u);
        }
        Ok(v)
    }

    pub fn disk_info(&self, index: u64) -> Result<DiskInfo> {
        let r = self.call(CTL_DISK_INFO, &[index], &[], &[])?;
        Ok(DiskInfo { index, bdf: r.vals[0] & 0xffff, address: r.vals[0] >> 16, owner: (r.vals[1] != u64::MAX).then_some(r.vals[1]),
            failed: r.vals[2] != 0, kind: r.vals[3], sectors: r.vals[4], attachments: r.vals[5] })
    }

    /// Give `vm` a disk made of `extents` (start, sectors) of host disk
    /// `disk`, in guest order, with BLK_* `flags`.
    pub fn attach_extents(&self, vm: u64, disk: u64, flags: u64, extents: &[(u64, u64)]) -> Result<()> {
        check_extents(extents)?;
        let list: Vec<u8> = extents.iter().flat_map(|&(s, n)| [s.to_le_bytes(), n.to_le_bytes()]).flatten().collect();
        self.call(CTL_BLK_ATTACH_EXTENTS, &[vm, disk, flags, 0, extents.len() as u64], &[], &list)?;
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

    /// Discard an unattached 4 KiB aligned region, in 512-byte sectors.
    /// Reads after discard return unspecified data. Reclamation depends on the device.
    pub fn blk_discard(&self, disk: u64, sector: u64, sectors: u64) -> Result<()> {
        self.call(CTL_BLK_DISCARD, &discard_args(disk, sector, sectors)?, &[], &[])?;
        Ok(())
    }

    /// Discard each region in order. Earlier discards can succeed if a
    /// later request fails.
    pub fn blk_discard_extents(&self, disk: u64, extents: &[(u64, u64)]) -> Result<()> {
        for &(sector, sectors) in extents {
            discard_args(disk, sector, sectors)?;
        }
        for &(sector, sectors) in extents {
            self.blk_discard(disk, sector, sectors)?;
        }
        Ok(())
    }

    /// Explicit zeros, including sparse image holes and recycled space: the
    /// range reads zero after (the device's Write Zeroes where the host has
    /// it, written zeros otherwise; never a discard).
    pub fn disk_zero(&self, disk: u64, sector: u64, sectors: u64) -> Result<()> {
        if sector % 8 != 0 || sectors == 0 || sectors % 8 != 0 || sector.checked_add(sectors).is_none() {
            return err("disk zero must be a finite 4 KiB aligned range");
        }
        zero_in_steps(sector, sectors, |at, bytes| {
            let resp = self.raw_call(CTL_BLK_WRITE, &[disk, at, bytes, 1], &[], 0, 0)?;
            Ok((resp.status, resp.vals))
        })
    }

    pub fn disk_flush(&self, disk: u64) -> Result<()> {
        self.call(CTL_BLK_WRITE, &[disk, 0, 0, 0], &[], &[])?;
        Ok(())
    }
}

/// Zero `sector`, `sectors` by zeroing BLK_WRITEs, `call(at, bytes)` (its
/// status and vals): CTL_ZERO_MAX at most each, each answering what it
/// zeroed; CTL_LOAD_MAX at a time on a host that refuses more.
fn zero_in_steps(sector: u64, sectors: u64, mut call: impl FnMut(u64, u64) -> Result<(i64, [u64; 6])>) -> Result<()> {
    let mut max = CTL_ZERO_MAX;
    let mut offset = 0;
    while offset < sectors {
        let bytes = ((sectors - offset) * 512).min(max);
        let (status, vals) = call(sector + offset, bytes)?;
        // A host before CTL_ZERO_MAX: CTL_LOAD_MAX at a time.
        if status == -22 && bytes > CTL_LOAD_MAX as u64 && max != CTL_LOAD_MAX as u64 {
            max = CTL_LOAD_MAX as u64;
            continue;
        }
        if status < 0 {
            return err(format!("request {CTL_BLK_WRITE} failed: {}", errno_name(-status)));
        }
        offset += zeroed(vals, bytes)? / 512;
    }
    Ok(())
}

/// The bytes a zeroing BLK_WRITE of `asked` bytes zeroed: vals[0], a 4 KiB
/// multiple from its start (0 from a host before CTL_ZERO_MAX: all of it).
fn zeroed(vals: [u64; 6], asked: u64) -> Result<u64> {
    match vals[0] {
        0 => Ok(asked),
        n if n <= asked && n % 4096 == 0 => Ok(n),
        n => err(format!("the host zeroed {n} bytes of {asked}")),
    }
}

fn discard_args(disk: u64, sector: u64, sectors: u64) -> Result<[u64; 3]> {
    if sector % 8 != 0 || sectors == 0 || sectors % 8 != 0 || sector.checked_add(sectors).is_none() {
        return err("disk discard must be a finite 4 KiB aligned range");
    }
    Ok([disk, sector, sectors])
}

#[cfg(test)]
mod discard_tests {
    use super::*;

    #[test]
    fn discard_uses_sector_count_in_the_control_abi() {
        assert_eq!(CTL_BLK_DISCARD, 59);
        assert_eq!(discard_args(6, 16384, 8192).unwrap(), [6, 16384, 8192]);
        for (sector, sectors) in [(0, 0), (1, 8), (0, 7), (u64::MAX - 7, 8)] {
            assert!(discard_args(6, sector, sectors).is_err());
        }
    }

    /// Runs zero_in_steps against a host that zeroes at most `per_call`
    /// bytes a call (0: an old host, all of it, CTL_LOAD_MAX at most).
    fn zero_calls(sectors: u64, per_call: u64) -> (Result<()>, Vec<(u64, u64)>) {
        let mut calls = vec![];
        let r = zero_in_steps(8, sectors, |at, bytes| {
            calls.push((at, bytes));
            Ok(match per_call {
                0 if bytes > CTL_LOAD_MAX as u64 => (-22, [0; 6]),
                0 => (0, [0; 6]),
                n => (0, [n.min(bytes), 0, 0, 0, 0, 0]),
            })
        });
        (r, calls)
    }

    #[test]
    fn zeroing_goes_on_from_what_each_call_zeroed() {
        const G: u64 = 1 << 30;
        // A range larger than CTL_ZERO_MAX: one call per GiB, all done.
        let (r, calls) = zero_calls(3 * G / 512, u64::MAX);
        assert!(r.is_ok());
        assert_eq!(calls, [(8, G), (8 + G / 512, G), (8 + 2 * G / 512, G)]);
        // A host that stops short: asked again from where it stopped.
        let (r, calls) = zero_calls(16 << 11, 4 << 20);
        assert!(r.is_ok());
        assert_eq!(calls, [(8, 16 << 20), (8 + (4 << 11), 12 << 20), (8 + (8 << 11), 8 << 20), (8 + (12 << 11), 4 << 20)]);
        // A host before CTL_ZERO_MAX refuses more than CTL_LOAD_MAX once; then 1 MiB at a time.
        let (r, calls) = zero_calls(3 << 11, 0);
        assert!(r.is_ok());
        assert_eq!(calls, [(8, 3 << 20), (8, 1 << 20), (8 + (1 << 11), 1 << 20), (8 + (2 << 11), 1 << 20)]);
        // What a host claims beyond what was asked, or unaligned, is an error.
        for bad in [(4 << 20) + 4096, 512] {
            let r = zero_in_steps(8, 8192, |_, _| Ok((0, [bad, 0, 0, 0, 0, 0])));
            assert!(r.is_err(), "{bad}");
        }
        // Any other refusal is the caller's.
        assert!(zero_in_steps(8, 8192, |_, _| Ok((-16, [0; 6]))).is_err());
    }
}

/// Attestation by the host (DESIGN.md §10.2), in any guest: on
/// /dev/l4h-attest, an l4h guest's driver, or else on an HVM guest's
/// attestation port (§5.11: the virtio-console port named l4h.attest).
/// ACT/SEAL work without a TPM.
pub mod kernel;

pub mod attest {
    use super::*;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};

    const REPORT: u32 = 1;
    const EVIDENCE: u32 = 2;
    const ACTIVATE: u32 = 3;
    const ACT: u32 = 4;
    const SEAL: u32 = 5;
    const EVENT_LOG: u32 = 6;
    const TDX_EVIDENCE: u32 = 7;
    const TDX_EVENT_LOG: u32 = 8;
    const TDX_QUOTE: u32 = 9;
    /// What the guest's driver says reports are bound to.
    const PROVIDERS: &str = "/sys/kernel/l4h/attest/providers";
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

    /// The device of the virtio-console port named `name`, if the guest
    /// has one: the vport whose sysfs `name` is that (udev's
    /// /dev/virtio-ports link need not be there).
    pub(crate) fn find_port(class: &Path, dev: &Path, name: &str) -> Option<PathBuf> {
        let mut ports: Vec<_> = std::fs::read_dir(class).ok()?.flatten().map(|e| e.file_name()).collect();
        ports.sort();
        ports.into_iter().find(|p| std::fs::read_to_string(class.join(p).join("name")).is_ok_and(|n| n.trim_end() == name)).map(|p| dev.join(p))
    }

    const PORT_MAGIC: u32 = 0x4148_344c;
    /// A request's data on the port, and the largest piece of a result
    /// (abi.h, L4H_ATTEST_PAGE_DATA).
    const PORT_DATA: usize = 4096 - 64;

    /// One request on the port `f`: the answer's status (-errno), the
    /// whole result's length, the host's state and this piece's data.
    fn port_request(f: &mut (impl Read + Write), op: u32, offset: u32, data: &[u8], blob_len: usize) -> io::Result<(i32, u32, u32, Vec<u8>)> {
        let mut req = Vec::with_capacity(20 + data.len());
        for w in [PORT_MAGIC, op, offset, data.len() as u32, blob_len as u32] {
            req.extend_from_slice(&w.to_le_bytes());
        }
        req.extend_from_slice(data);
        // One write: a request is not interleaved with another's.
        f.write_all(&req)?;
        let mut head = [0u8; 20];
        f.read_exact(&mut head)?;
        let w = |i: usize| u32::from_le_bytes(head[4 * i..4 * i + 4].try_into().unwrap());
        let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("attestation port: {what}"));
        if w(0) != PORT_MAGIC {
            return Err(bad("not an answer"));
        }
        let n = w(3) as usize;
        if n > PORT_DATA {
            return Err(bad("an answer longer than any"));
        }
        let mut out = vec![0u8; n];
        f.read_exact(&mut out)?;
        Ok((w(1) as i32, w(2), w(4), out))
    }

    /// A request and its whole result on the port `f`, piece by piece,
    /// with the host's state at the last.
    fn port_call(f: &mut (impl Read + Write), op: u32, data: &[u8], blob_len: usize) -> io::Result<(Vec<u8>, u32)> {
        if data.len() > PORT_DATA {
            return Err(io::Error::from_raw_os_error(22));
        }
        let mut out = Vec::new();
        loop {
            let (status, total, state, piece) = port_request(f, op, out.len() as u32, data, blob_len)?;
            if status != 0 {
                // An errno, as the driver gives one; anything else is the host's failure.
                return Err(io::Error::from_raw_os_error(if (-4095..0).contains(&status) { -status } else { 5 }));
            }
            let total = total as usize;
            if total > OUT_MAX || out.len() + piece.len() > total || (piece.is_empty() && out.len() < total) {
                return Err(io::Error::from_raw_os_error(5));
            }
            out.extend_from_slice(&piece);
            if out.len() >= total {
                return Ok((out, state));
            }
        }
    }

    const PORT_NAME: &str = "l4h.attest";

    /// How the guest reaches the host: an l4h guest's driver, or an HVM
    /// guest's port.
    enum Dev {
        Driver(File),
        Port(File),
    }

    const DRIVER: &str = "/dev/l4h-attest";

    /// The guest's one way to the host, open: the driver where the guest
    /// has it (whatever opening it says: no other way is tried then),
    /// else its attestation port.  The kernel gives a port to one opener
    /// at a time: another l4hctl's turn is waited for.
    fn open_dev() -> Result<Dev> {
        let rw = |p: &Path| File::options().read(true).write(true).open(p);
        match rw(Path::new(DRIVER)) {
            Ok(f) => return Ok(Dev::Driver(f)),
            Err(e) if e.kind() != io::ErrorKind::NotFound => return err(format!("{DRIVER}: {e}")),
            Err(_) => {}
        }
        let Some(path) = find_port(Path::new("/sys/class/virtio-ports"), Path::new("/dev"), PORT_NAME) else {
            return err(format!("{DRIVER}: not found, and no attestation port (does the host provide attestation/flags?)"));
        };
        let start = std::time::Instant::now();
        loop {
            match rw(&path) {
                Ok(f) => return Ok(Dev::Port(f)),
                // EBUSY: open elsewhere.
                Err(e) if e.raw_os_error() == Some(16) && start.elapsed() < PORT_WAIT => std::thread::sleep(std::time::Duration::from_millis(20)),
                Err(e) => return err(format!("attestation port ({}): {e}", path.display())),
            }
        }
    }

    /// How long another's use of the port is waited for: a TPM's slowest
    /// request (ActivateCredential on first use) and some.
    const PORT_WAIT: std::time::Duration = std::time::Duration::from_secs(180);

    fn call(op: u32, data: &[u8], blob_len: usize) -> Result<Vec<u8>> {
        let dev = match open_dev()? {
            Dev::Driver(dev) => dev,
            Dev::Port(mut port) => return port_call(&mut port, op, data, blob_len).map(|(out, _)| out).map_err(|e| failed(op, e)),
        };
        let mut out = vec![0u8; 64 << 10];
        let mut c = Ioc {
            op,
            blob_len: blob_len as u32,
            secret_len: (data.len() - blob_len) as u32,
            out_len: out.len() as u32,
            data: data.as_ptr() as u64,
            out: out.as_mut_ptr() as u64,
        };
        let mut r = unsafe { ioctl(dev.as_raw_fd(), IOC, &mut c as *mut Ioc) };
        // A longer result (an event log can be): the driver said how long
        // (c.out_len); ask again with that much room, once.
        if r < 0 {
            let e = io::Error::last_os_error();
            if let Some(n) = grown(e.raw_os_error(), c.out_len, out.len()) {
                out.resize(n, 0);
                c.out_len = n as u32;
                c.out = out.as_mut_ptr() as u64;
                r = unsafe { ioctl(dev.as_raw_fd(), IOC, &mut c as *mut Ioc) };
            } else {
                return Err(failed(op, e));
            }
        }
        if r < 0 {
            return Err(failed(op, io::Error::last_os_error()));
        }
        out.truncate(c.out_len as usize);
        Ok(out)
    }

    /// The most a result may need (an event log is at most 1 MiB).
    const OUT_MAX: usize = 4 << 20;

    /// The room to retry with after an error `errno` that said the result
    /// is `need` bytes, with `have`: only for ENOSPC, and within OUT_MAX.
    fn grown(errno: Option<i32>, need: u32, have: usize) -> Option<usize> {
        let need = need as usize;
        (errno == Some(28) && need > have && need <= OUT_MAX).then_some(need)
    }

    fn failed(op: u32, e: io::Error) -> Error {
        let tdx = matches!(op, TDX_EVIDENCE | TDX_EVENT_LOG | TDX_QUOTE);
        Error(match e.raw_os_error() {
            Some(2) if op == TDX_EVENT_LOG => "no TDX (CC) event log available".into(),
            Some(19) if tdx => "no TDX attestation on this host".into(),
            Some(11) if op == TDX_QUOTE => "TDX quotes rate limited or busy: try again".into(),
            // -EINVAL from a guest kernel, -ENOSYS from a host, older than TDX.
            Some(22 | 38) if tdx => "the guest kernel or host does not know this TDX request".into(),
            Some(2) => "no TPM event log available".into(),
            Some(19) => "no TPM: flags only".into(),
            Some(38) => "host has no taint/seal operations".into(),
            Some(1) => "not permitted: a sealed flag, or one that is not userspace's to act on or seal".into(),
            _ => format!("attestation request {op} failed: {e}"),
        })
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

    /// The host's UEFI TPM 2.0 event log, raw (TCG2 crypto agile format):
    /// replayed, it gives the PCRs the evidence quotes.
    pub fn event_log() -> Result<Vec<u8>> {
        call(EVENT_LOG, &[], 0)
    }

    /// The host's Intel TDX evidence (CBOR): the DCAP quote over the
    /// host's signing key.
    pub fn tdx_evidence() -> Result<Vec<u8>> {
        call(TDX_EVIDENCE, &[], 0)
    }

    /// The host's CC event log (CCEL), raw (TCG2 format, SHA-384):
    /// replayed, it gives RTMR 0-2 of the TDX quotes.
    pub fn tdx_event_log() -> Result<Vec<u8>> {
        call(TDX_EVENT_LOG, &[], 0)
    }

    /// A fresh TDX quote over a report on this guest with `data` (at most
    /// DATA_SIZE bytes, zero padded): CBOR {"key", "quote", "report"}.
    pub fn tdx_quote(data: &[u8]) -> Result<Vec<u8>> {
        if data.len() > DATA_SIZE {
            return err(format!("report data is at most {DATA_SIZE} bytes"));
        }
        let mut d = [0u8; DATA_SIZE];
        d[..data.len()].copy_from_slice(data);
        call(TDX_QUOTE, &d, 0)
    }

    /// What reports are bound to: "tpm", "tdx", "tpm,tdx" or "none".
    pub fn providers() -> Result<String> {
        // An l4h guest's driver says, to anyone (the file is everyone's
        // to read; the device node is not opened for it).
        let sysfs = || {
            let s = std::fs::read_to_string(PROVIDERS).map_err(|e| Error(format!("{PROVIDERS}: {e} (does the guest kernel know TDX?)")))?;
            parse_providers(&s)
        };
        if says_driver(Path::new(DRIVER), Path::new("/sys/class/virtio-ports"), Path::new(PROVIDERS)) {
            return sysfs();
        }
        match open_dev()? {
            // A driver that came just now.
            Dev::Driver(_) => sysfs(),
            // An HVM guest has no driver to say: the host's state does,
            // as its port gives it with an answer (to an empty ACT).
            Dev::Port(mut port) => {
                let (_, state) = port_call(&mut port, ACT, &[0; 32], 0).map_err(|e| failed(ACT, e))?;
                Ok(state_providers(state).into())
            }
        }
    }

    /// Whether the driver is who says what reports are bound to: where
    /// a request would go to it (its device node is there, `open_dev`),
    /// or would go nowhere (no attestation port either) and it still
    /// says in sysfs.  Nothing is opened, so anyone can ask.  Never the
    /// driver for providers and the port for the report.
    fn says_driver(node: &Path, ports: &Path, sysfs: &Path) -> bool {
        node.metadata().is_ok() || (find_port(ports, Path::new("/dev"), PORT_NAME).is_none() && sysfs.symlink_metadata().is_ok())
    }

    /// What reports are bound to, by the host's state (abi.h,
    /// L4H_ATTEST_HAS_TPM and L4H_ATTEST_HAS_TDX).
    fn state_providers(state: u32) -> &'static str {
        match (state & 4 != 0, state & 8 != 0) {
            (true, true) => "tpm,tdx",
            (true, false) => "tpm",
            (false, true) => "tdx",
            (false, false) => "none",
        }
    }

    /// The driver's providers file, checked.
    pub fn parse_providers(s: &str) -> Result<String> {
        let s = s.trim();
        match s {
            "tpm" | "tdx" | "tpm,tdx" | "none" => Ok(s.to_string()),
            _ => err(format!("unexpected providers: {s:?}")),
        }
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

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The host's end of an attestation port: answers each request
        /// with the next piece of `result` (pieces of `piece` bytes), or
        /// with `status`.
        struct Host {
            result: Vec<u8>,
            piece: usize,
            status: i32,
            state: u32,
            asked: Vec<(u32, u32, Vec<u8>, u32)>,
            answer: Vec<u8>,
        }

        impl Write for Host {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                let w = |i: usize| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
                assert_eq!((w(0), w(3) as usize), (PORT_MAGIC, b.len() - 20), "one whole request a write");
                let at = w(2) as usize;
                self.asked.push((w(1), w(2), b[20..].to_vec(), w(4)));
                let data = if self.status != 0 { &[][..] } else { &self.result[at.min(self.result.len())..][..self.piece.min(self.result.len().saturating_sub(at))] };
                for v in [PORT_MAGIC, self.status as u32, self.result.len() as u32, data.len() as u32, self.state] {
                    self.answer.extend_from_slice(&v.to_le_bytes());
                }
                self.answer.extend_from_slice(data);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        impl Read for Host {
            // A byte or two at a time, as a port may give them.
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                let n = b.len().min(self.answer.len()).min(2);
                b[..n].copy_from_slice(&self.answer[..n]);
                self.answer.drain(..n);
                Ok(n)
            }
        }

        fn host(result: &[u8], piece: usize, status: i32) -> Host {
            Host { result: result.to_vec(), piece, status, state: 4, asked: Vec::new(), answer: Vec::new() }
        }

        #[test]
        fn port_requests_collect_a_result_in_pieces() {
            let result: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
            let mut h = host(&result, 4032, 0);
            let (out, state) = port_call(&mut h, EVENT_LOG, &[], 0).unwrap();
            assert_eq!((out, state), (result, 4));
            assert_eq!(h.asked.iter().map(|a| (a.0, a.1)).collect::<Vec<_>>(), [(EVENT_LOG, 0), (EVENT_LOG, 4032), (EVENT_LOG, 8064)]);
            // The request's data and blob length go with every piece.
            let mut h = host(b"secret", 4032, 0);
            assert_eq!(port_call(&mut h, ACTIVATE, b"blobsecret", 4).unwrap().0, b"secret");
            assert_eq!(h.asked, [(ACTIVATE, 0, b"blobsecret".to_vec(), 4)]);
            // An empty result is one answer.
            let mut h = host(b"", 4032, 0);
            assert_eq!(port_call(&mut h, EVIDENCE, &[], 0).unwrap().0, b"");
            assert_eq!(h.asked.len(), 1);
        }

        #[test]
        fn port_failures() {
            // The host's errno is the error, as the driver's ioctl gives it.
            let mut h = host(b"", 4032, -19);
            assert_eq!(port_call(&mut h, REPORT, &[0; 64], 0).unwrap_err().raw_os_error(), Some(19));
            assert_eq!(failed(REPORT, port_call(&mut host(b"", 1, -19), REPORT, &[0; 64], 0).unwrap_err()).0, "no TPM: flags only");
            // A status that is no errno, a host that gives no data of a
            // result it says is longer, or one too long to be any: EIO.
            for mut h in [host(b"", 1, 7), host(b"x", 0, 0), host(&vec![0; OUT_MAX + 1], 4032, 0)] {
                assert_eq!(port_call(&mut h, EVIDENCE, &[], 0).unwrap_err().raw_os_error(), Some(5));
            }
            // More data than a request holds is not sent.
            let mut h = host(b"", 1, 0);
            assert_eq!(port_call(&mut h, ACTIVATE, &vec![0; PORT_DATA + 1], 0).unwrap_err().raw_os_error(), Some(22));
            assert!(h.asked.is_empty());
            // What is not an answer.
            let mut h = host(b"", 1, 0);
            h.answer = vec![0; 20];
            assert!(port_request(&mut h, EVIDENCE, 0, &[], 0).is_err());
        }

        #[test]
        fn port_is_found_by_its_name() {
            let dir = std::env::temp_dir().join(format!("l4hctl-ports-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            for (port, name) in [("vport0p0", "org.qemu.guest_agent.0\n"), ("vport1p0", "l4h.attest\n"), ("vport2p0", "l4h.attest.other\n")] {
                std::fs::create_dir_all(dir.join(port)).unwrap();
                std::fs::write(dir.join(port).join("name"), name).unwrap();
            }
            std::fs::create_dir_all(dir.join("vport3p0")).unwrap();
            assert_eq!(find_port(&dir, Path::new("/dev"), PORT_NAME), Some(PathBuf::from("/dev/vport1p0")));
            assert_eq!(find_port(&dir, Path::new("/dev"), "none"), None);
            assert_eq!(find_port(&dir.join("absent"), Path::new("/dev"), PORT_NAME), None);
            // The driver is there by its node, which need not be ours to
            // open (root's alone), or by what it says in sysfs.
            use std::os::unix::fs::PermissionsExt;
            let node = dir.join("l4h-attest");
            let (sysfs, none) = (dir.join("vport0p0").join("name"), dir.join("absent"));
            // Its sysfs file without its node, beside a port: requests
            // go to the port, so the port says.  Without a port, sysfs.
            assert!(!says_driver(&node, &dir, &sysfs));
            assert!(says_driver(&node, &none, &sysfs));
            assert!(!says_driver(&node, &none, &none));
            std::fs::write(&node, "").unwrap();
            std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0)).unwrap();
            assert!(says_driver(&node, &dir, &sysfs));
            assert!(says_driver(&node, &none, &none));
            std::fs::remove_dir_all(&dir).unwrap();
            assert_eq!([0, 4, 8, 12].map(state_providers), ["none", "tpm", "tdx", "tpm,tdx"]);
        }

        #[test]
        fn retries_only_a_longer_result() {
            // ENOSPC with the result's length: room for it, up to OUT_MAX.
            assert_eq!(grown(Some(28), 200 << 10, 64 << 10), Some(200 << 10));
            assert_eq!(grown(Some(28), OUT_MAX as u32, 64 << 10), Some(OUT_MAX));
            assert_eq!(grown(Some(28), OUT_MAX as u32 + 1, 64 << 10), None);
            // Not shorter or equal (nothing to gain), nor other errors.
            assert_eq!(grown(Some(28), 64 << 10, 64 << 10), None);
            assert_eq!(grown(Some(2), 200 << 10, 64 << 10), None);
            assert_eq!(grown(None, 200 << 10, 64 << 10), None);
        }

        #[test]
        fn error_messages() {
            let msg = |n| failed(EVENT_LOG, io::Error::from_raw_os_error(n)).0;
            assert_eq!(msg(2), "no TPM event log available");
            assert_eq!(msg(19), "no TPM: flags only");
            assert!(msg(5).starts_with("attestation request 6 failed"));
            // The TPM's requests say what they always did.
            for op in [REPORT, EVIDENCE, ACTIVATE] {
                assert_eq!(failed(op, io::Error::from_raw_os_error(19)).0, "no TPM: flags only");
            }
        }

        #[test]
        fn tdx_error_messages() {
            let msg = |op, n| failed(op, io::Error::from_raw_os_error(n)).0;
            assert_eq!(msg(TDX_EVENT_LOG, 2), "no TDX (CC) event log available");
            assert_eq!(msg(TDX_EVIDENCE, 19), "no TDX attestation on this host");
            assert_eq!(msg(TDX_QUOTE, 19), "no TDX attestation on this host");
            assert_eq!(msg(TDX_QUOTE, 11), "TDX quotes rate limited or busy: try again");
            assert!(msg(TDX_EVIDENCE, 5).starts_with("attestation request 7 failed"));
            assert!(msg(TDX_QUOTE, 5).starts_with("attestation request 9 failed"));
            // An older host's -ENOSYS is about TDX, not taint/seal.
            for op in [TDX_EVIDENCE, TDX_EVENT_LOG, TDX_QUOTE] {
                assert_eq!(msg(op, 38), "the guest kernel or host does not know this TDX request");
                assert_eq!(msg(op, 22), "the guest kernel or host does not know this TDX request");
            }
            assert_eq!(msg(ACT, 38), "host has no taint/seal operations");
        }

        #[test]
        fn tdx_quote_data_is_at_most_64_bytes() {
            assert!(tdx_quote(&[0; DATA_SIZE + 1]).is_err_and(|e| e.0.contains("at most 64")));
        }

        #[test]
        fn providers_file() {
            for s in ["tpm\n", "tdx\n", "tpm,tdx\n", "none\n"] {
                assert_eq!(parse_providers(s).unwrap(), s.trim());
            }
            assert!(parse_providers("sgx\n").is_err());
            assert!(parse_providers("").is_err());
        }
    }
}

#[cfg(test)]
mod steer_tests {
    use super::*;

    #[test]
    fn matches_round_trip() {
        for s in ["203.0.113.5/tcp:443", "10.128.0.9", "2001:db8::1/udp:4500", "198.51.100.1/esp", "192.0.2.1/132"] {
            let m = SteerMatch::parse(s).unwrap();
            let [w, hi, lo] = m.words();
            assert_eq!(SteerMatch::from_words(w, hi, lo), m);
            assert_eq!(m.to_string(), s);
        }
        let [w, hi, lo] = SteerMatch::parse("203.0.113.5/tcp:443").unwrap().words();
        assert_eq!((w, hi, lo), (4 | 6 << 8 | 443 << 16, 0, 0xcb00_7105));
    }

    #[test]
    fn bad_matches() {
        for s in ["203.0.113.5/icmp:1", "203.0.113.5/tcp:0", "203.0.113.5/0", "nope", "1.2.3.4/tcp:70000"] {
            assert!(SteerMatch::parse(s).is_err(), "{s}");
        }
    }
}

/// One vCPU over the last balancer period: its host core (logical CPU),
/// the CPU it used there (permille of that core) and its steal time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VcpuStat {
    pub core: u64,
    pub usage: u64,
    pub steal_ns: u64,
}

/// A VM's vCPUs, and its VMM's (host core, permille) while it runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VcpuStats {
    pub vcpus: Vec<VcpuStat>,
    pub vmm: Option<(u64, u64)>,
}

impl VcpuStats {
    /// What the VM used of each of `cores` host cores, in permille of it:
    /// its vCPUs and its VMM where they are placed.
    pub fn per_core(&self, cores: usize) -> Vec<u64> {
        let mut out = vec![0; cores];
        let placed = self.vcpus.iter().map(|v| (v.core, v.usage)).chain(self.vmm);
        for (core, usage) in placed {
            if let Some(c) = out.get_mut(core as usize) {
                *c += usage;
            }
        }
        out
    }
}

/// One page of CTL_VM_VCPU_STATS: vals[0] records of 16 bytes (u32 core,
/// u32 usage, u64 steal_ns, little-endian); vals[1..3] the VMM's core and
/// use, u64::MAX without one.
fn parse_vcpu_stats(v: [u64; 6], data: &[u8]) -> VcpuStats {
    let n = (v[0] as usize).min(data.len() / 16);
    let vcpus = data[..n * 16]
        .chunks_exact(16)
        .map(|r| VcpuStat {
            core: u32::from_le_bytes(r[0..4].try_into().unwrap()) as u64,
            usage: u32::from_le_bytes(r[4..8].try_into().unwrap()) as u64,
            steal_ns: u64::from_le_bytes(r[8..16].try_into().unwrap()),
        })
        .collect();
    let vmm = (v[1] != u64::MAX).then_some((v[1], v[2]));
    VcpuStats { vcpus, vmm }
}

#[cfg(test)]
mod vcpu_stats_tests {
    use super::*;

    fn record(core: u32, usage: u32, steal: u64) -> Vec<u8> {
        [core.to_le_bytes().as_slice(), &usage.to_le_bytes(), &steal.to_le_bytes()].concat()
    }

    #[test]
    fn records_and_the_vmm() {
        let mut data = [0; CTL_DATA_MAX];
        let recs = [record(3, 950, 7), record(1, 20, 0)].concat();
        data[..recs.len()].copy_from_slice(&recs);
        let s = parse_vcpu_stats([2, 3, 40, 0, 0, 0], &data);
        assert_eq!(s.vcpus, vec![VcpuStat { core: 3, usage: 950, steal_ns: 7 }, VcpuStat { core: 1, usage: 20, steal_ns: 0 }]);
        assert_eq!(s.vmm, Some((3, 40)));
        // Core 3 has the vCPU and the VMM; a core past the host's is dropped.
        assert_eq!(s.per_core(4), vec![0, 20, 0, 990]);
        assert_eq!(s.per_core(2), vec![0, 20]);
    }

    #[test]
    fn no_vmm_and_a_count_past_the_data() {
        let s = parse_vcpu_stats([1000, u64::MAX, u64::MAX, 0, 0, 0], &[0; 32]);
        assert_eq!(s.vcpus.len(), 2);
        assert_eq!(s.vmm, None);
    }
}

/// CTL_HOST_INFO's answer. An older host leaves data[0..8] zero, and a
/// count above the logical cores is not believed: both give `cores`.
fn parse_host_info(v: [u64; 6], data: &[u8]) -> HostInfo {
    let physical = u64::from_le_bytes(data[..8].try_into().unwrap());
    let physical_cores = if physical == 0 || physical > v[0] { v[0] } else { physical };
    HostInfo { cores: v[0], physical_cores, free: v[1], total: v[2], disks: v[3], vms: v[4], nics: v[5] }
}

#[cfg(test)]
mod host_info_tests {
    use super::*;

    fn info(cores: u64, physical: u64) -> HostInfo {
        let mut data = [0; CTL_DATA_MAX];
        data[..8].copy_from_slice(&physical.to_le_bytes());
        parse_host_info([cores, 1 << 30, 2 << 30, 1, 2, 3], &data)
    }

    #[test]
    fn physical_cores_from_data() {
        let i = info(4, 2);
        assert_eq!(i, HostInfo { cores: 4, physical_cores: 2, free: 1 << 30, total: 2 << 30, disks: 1, vms: 2, nics: 3 });
        assert_eq!(info(8, 8).physical_cores, 8);
    }

    #[test]
    fn older_or_bad_hosts_fall_back_to_logical_cores() {
        assert_eq!(info(6, 0).physical_cores, 6);
        assert_eq!(info(4, 5).physical_cores, 4);
        assert_eq!(info(4, u64::MAX).physical_cores, 4);
    }
}

#[cfg(test)]
mod hvm_layout_tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    /// A bzImage header: `sects` setup sectors, `init` init_size.
    fn bzimage(len: usize, sects: u8, init: u32, xlf: u16) -> Vec<u8> {
        let mut k = vec![0u8; len];
        k[0x1f1] = sects;
        k[0x1fe..0x200].copy_from_slice(&0xaa55u16.to_le_bytes());
        k[0x202..0x206].copy_from_slice(b"HdrS");
        k[0x206..0x208].copy_from_slice(&0x020fu16.to_le_bytes());
        k[0x234] = 1;
        k[0x230..0x234].copy_from_slice(&(2 * MIB as u32).to_le_bytes());
        k[0x236..0x238].copy_from_slice(&xlf.to_le_bytes());
        k[0x258..0x260].copy_from_slice(&(16 * MIB).to_le_bytes());
        k[0x260..0x264].copy_from_slice(&init.to_le_bytes());
        k
    }

    #[test]
    fn bzimage_goes_above_its_init_size() {
        let k = bzimage(10 * MIB as usize, 30, 40 * MIB as u32, 1);
        // 16 MiB + 40 MiB, then the image (10 MiB), then the initrd.
        assert_eq!(hvm_layout(&k, 5 * MIB, 128 * MIB).unwrap(), (56 * MIB, 66 * MIB));
        // A payload larger than init_size counts as itself.
        let k = bzimage(50 * MIB as usize, 30, MIB as u32, 1);
        let (image, initrd) = hvm_layout(&k, 0, 256 * MIB).unwrap();
        assert!(image >= 16 * MIB + 50 * MIB - 31 * 512 && image % (2 * MIB) == 0);
        assert_eq!(initrd, (image + 50 * MIB).next_multiple_of(2 * MIB));
    }

    /// As l4h-hvm's boot::load_address: a kernel that cannot be relocated
    /// runs at its preferred address, aligned or not; the image and the
    /// initrd go above its window.
    #[test]
    fn non_relocatable_bzimage_at_its_preferred_address() {
        let mut k = bzimage(10 * MIB as usize, 30, 40 * MIB as u32, 1);
        k[0x234] = 0;
        k[0x258..0x260].copy_from_slice(&(3 * MIB).to_le_bytes());
        assert_eq!(hvm_layout(&k, 0, 256 * MIB).unwrap().0, (3 * MIB + 40 * MIB).next_multiple_of(2 * MIB));
        k[0x234] = 1;
        assert_eq!(hvm_layout(&k, 0, 256 * MIB).unwrap().0, 56 * MIB, "relocatable, misaligned: 16 MiB");
        k[0x258..0x260].copy_from_slice(&(64 * MIB).to_le_bytes());
        assert_eq!(hvm_layout(&k, 0, 256 * MIB).unwrap().0, 104 * MIB);
    }

    /// Program headers anywhere a hostile image puts them: errors.
    #[test]
    fn elf_program_headers_out_of_bounds() {
        let mut k = vec![0u8; 4096];
        k[..4].copy_from_slice(b"\x7fELF");
        k[4] = 2;
        k[5] = 1;
        k[18] = 62;
        k[56..58].copy_from_slice(&2u16.to_le_bytes());
        for (phoff, phentsize) in [(u64::MAX - 8, 56u16), (u64::MAX - 100, 0xffff), (4090, 56), (1 << 40, 56)] {
            k[32..40].copy_from_slice(&phoff.to_le_bytes());
            k[54..56].copy_from_slice(&phentsize.to_le_bytes());
            assert!(hvm_layout(&k, 0, 128 * MIB).is_err(), "{phoff:#x} {phentsize}");
        }
    }

    /// Places that do not fit in 64 bits are errors, not overflows.
    #[test]
    fn layouts_past_the_address_space() {
        let mut k = bzimage(10 * MIB as usize, 30, 40 * MIB as u32, 1);
        k[0x234] = 0;
        k[0x258..0x260].copy_from_slice(&(u64::MAX - MIB).to_le_bytes());
        assert!(hvm_layout(&k, 0, 256 * MIB).is_err());
        k[0x258..0x260].copy_from_slice(&(u64::MAX - 64 * MIB).to_le_bytes());
        assert!(hvm_layout(&k, 0, 256 * MIB).is_err(), "its 2 MiB-aligned staging");
        let k = bzimage(10 * MIB as usize, 30, 40 * MIB as u32, 1);
        assert!(hvm_layout(&k, u64::MAX - 8, u64::MAX).is_err(), "an initrd past the end");
    }

    #[test]
    fn refused_layouts() {
        // Not 64-bit, or too little RAM below the hole.
        assert!(hvm_layout(&bzimage(MIB as usize, 30, 8 << 20, 0), 0, 128 * MIB).is_err());
        let k = bzimage(10 * MIB as usize, 30, 40 * MIB as u32, 1);
        assert!(hvm_layout(&k, 64 * MIB, 128 * MIB).is_err());
        assert!(hvm_layout(&k, 64 * MIB, 4096 * MIB).is_ok());
        // Only RAM below 3 GiB counts.
        assert!(hvm_layout(&k, 3 * 1024 * MIB, 8192 * MIB).is_err());
        assert!(hvm_layout(b"not a kernel", 0, 128 * MIB).is_err());
        assert!(hvm_layout(&[0u8; 16], 0, 128 * MIB).is_err());
    }

    /// An arm64 Image header.
    fn image(len: usize, text: u64, size: u64) -> Vec<u8> {
        let mut k = vec![0u8; len];
        k[8..16].copy_from_slice(&text.to_le_bytes());
        k[16..24].copy_from_slice(&size.to_le_bytes());
        k[56..60].copy_from_slice(&0x644d_5241u32.to_le_bytes());
        k
    }

    const ARM_RAM: u64 = 0x4000_0000;

    #[test]
    fn arm64_image_goes_above_where_it_runs() {
        // It runs from RAM + 2 MiB + its text offset, for image_size.
        let k = image(10 * MIB as usize, 0, 30 * MIB);
        assert_eq!(hvm_layout(&k, 5 * MIB, 128 * MIB).unwrap(), (ARM_RAM + 32 * MIB, ARM_RAM + 42 * MIB));
        let k = image(10 * MIB as usize, 0x8_0000, 30 * MIB);
        assert_eq!(hvm_layout(&k, 0, 128 * MIB).unwrap().0, ARM_RAM + 34 * MIB, "rounded up to 2 MiB");
        // An old Image, with no size: at 512 KiB, in 64 MiB.
        let k = image(MIB as usize, 123, 0);
        assert_eq!(hvm_layout(&k, 0, 128 * MIB).unwrap().0, (ARM_RAM + 2 * MIB + 0x8_0000 + 64 * MIB).next_multiple_of(2 * MIB));
    }

    #[test]
    fn arm64_refused_layouts() {
        let k = image(10 * MIB as usize, 0, 30 * MIB);
        assert!(hvm_layout(&k, 100 * MIB, 128 * MIB).is_err(), "more than its RAM");
        assert!(hvm_layout(&k, u64::MAX - 8, u64::MAX).is_err());
        assert!(hvm_layout(&image(4096, 2 * MIB, MIB), 0, 128 * MIB).is_err(), "text offset past a block");
        assert!(hvm_layout(&image(4096, 0, u64::MAX), 0, 128 * MIB).is_err());
        // Anything else is still looked at as an x86-64 image.
        assert!(hvm_layout(&[0u8; 64], 0, 128 * MIB).is_err());
    }

    #[test]
    fn arm64_initrd_stays_in_the_kernels_window() {
        const GIB: u64 = 1 << 30;
        let run_end = ARM_RAM + 32 * MIB;
        let ram = 64 * GIB;
        // The kernel takes up to 2 MiB under the window's end.
        let fits = 32 * GIB - 34 * MIB;
        let (_, initrd) = arm64_layout(fits, MIB, ram, run_end).unwrap();
        assert_eq!(initrd + MIB, ARM_RAM + 32 * GIB - MIB, "inside it");
        assert!(arm64_layout(fits, 2 * MIB, ram, run_end).is_ok(), "up to its end");
        assert!(arm64_layout(fits, 2 * MIB + 1, ram, run_end).is_err(), "across it");
        assert!(arm64_layout(33 * GIB, 4096, ram, run_end).is_err(), "past it");
        assert!(arm64_layout(33 * GIB, 0, ram, run_end).is_ok(), "no initrd: nothing to place");
    }

    #[test]
    fn arm64_elf_goes_above_its_segments() {
        let mut k = vec![0u8; 4096];
        k[..4].copy_from_slice(b"\x7fELF");
        k[4] = 2;
        k[5] = 1;
        k[18] = 183;
        k[32..40].copy_from_slice(&64u64.to_le_bytes());
        k[54..56].copy_from_slice(&56u16.to_le_bytes());
        k[56..58].copy_from_slice(&2u16.to_le_bytes());
        let base = 0xffff_8000_8000_0000u64;
        for (i, (vaddr, memsz)) in [(base, 20 * MIB), (base + 24 * MIB, 3 * MIB)].into_iter().enumerate() {
            let ph = 64 + 56 * i;
            k[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
            k[ph + 16..ph + 24].copy_from_slice(&vaddr.to_le_bytes());
            k[ph + 40..ph + 48].copy_from_slice(&memsz.to_le_bytes());
        }
        // 27 MiB of it, from RAM + 2 MiB.
        assert_eq!(hvm_layout(&k, 0, 128 * MIB).unwrap().0, ARM_RAM + 30 * MIB);
        // A big-endian one is refused.
        k[5] = 2;
        assert!(hvm_layout(&k, 0, 128 * MIB).is_err());
    }

    #[test]
    fn elf_goes_above_its_segments() {
        let mut k = vec![0u8; 4096];
        k[..4].copy_from_slice(b"\x7fELF");
        k[4] = 2;
        k[5] = 1;
        k[18] = 62;
        k[32..40].copy_from_slice(&64u64.to_le_bytes());
        k[54..56].copy_from_slice(&56u16.to_le_bytes());
        k[56..58].copy_from_slice(&2u16.to_le_bytes());
        for (i, (paddr, memsz)) in [(16 * MIB, 20 * MIB), (40 * MIB, 3 * MIB)].into_iter().enumerate() {
            let ph = 64 + 56 * i;
            k[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
            k[ph + 24..ph + 32].copy_from_slice(&paddr.to_le_bytes());
            k[ph + 40..ph + 48].copy_from_slice(&memsz.to_le_bytes());
        }
        assert_eq!(hvm_layout(&k, MIB, 128 * MIB).unwrap(), (44 * MIB, 46 * MIB));
        k[18] = 3;
        assert!(hvm_layout(&k, MIB, 128 * MIB).is_err());
    }
}
