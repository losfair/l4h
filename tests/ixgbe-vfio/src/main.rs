//! Drive the Intel 82599/X550 driver (host/l4h-nicd-ixgbe/src/ixgbe.rs, compiled
//! here unchanged) from Linux userspace through VFIO, on the real NIC.
//! The port must be bound to vfio-pci and cabled to a network with an
//! IPv4 gateway that reaches the internet.  Checks, in order:
//!
//! 1. reset and link (the driver's own log line);
//! 2. ARP for the gateway, ICMP echo and a DNS query over UDP to 1.1.1.1,
//!    with checksums computed here, and that the device validated the
//!    checksum of the UDP reply (DATA_VALID);
//! 3. with --offload: the same DNS query with the UDP checksum left to the
//!    device, and a 4000-byte TCP send to 1.1.1.1:80 as one GSO frame that
//!    the device segments (TSO), acknowledged in full by the server;
//! 4. that RX and TX interrupts (MSI-X entries 0 and 1) arrived.
//!
//! Usage (root): ixgbe-vfio PCI-ADDRESS OUR-IP GATEWAY-IP [--offload]
//! e.g. ixgbe-vfio 0000:01:00.1 162.43.189.147 162.43.189.146 --offload

extern crate alloc;
extern crate self as l4h_rt;

pub use l4h_host as host;

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}

#[allow(dead_code)]
#[path = "../../../host/l4h-nicd-ixgbe/src/ixgbe.rs"]
mod ixgbe;
#[path = "../../nicdrv-vfio/sdk.rs"]
mod sdk;
use sdk::offload;

use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use l4h_host::blk::PciRegion;
use l4h_host::net;

const HDR: usize = net::HDR_SIZE;

// VFIO ioctls: _IO(';', 100 + n).
const fn vfio(n: u64) -> u64 {
    (b';' as u64) << 8 | (100 + n)
}
const VFIO_GET_API_VERSION: u64 = vfio(0);
const VFIO_SET_IOMMU: u64 = vfio(2);
const VFIO_GROUP_GET_STATUS: u64 = vfio(3);
const VFIO_GROUP_SET_CONTAINER: u64 = vfio(4);
const VFIO_GROUP_GET_DEVICE_FD: u64 = vfio(6);
const VFIO_DEVICE_GET_REGION_INFO: u64 = vfio(8);
const VFIO_DEVICE_SET_IRQS: u64 = vfio(10);
const VFIO_IOMMU_MAP_DMA: u64 = vfio(13);
const VFIO_TYPE1V2_IOMMU: u64 = 3;
const VFIO_PCI_CONFIG_REGION_INDEX: u32 = 7;
const VFIO_PCI_MSIX_IRQ_INDEX: u32 = 2;
const VFIO_IRQ_SET_DATA_EVENTFD: u32 = 1 << 2;
const VFIO_IRQ_SET_ACTION_TRIGGER: u32 = 1 << 5;
const DMA_IOVA: u64 = 0x4000_0000;
const DMA_SIZE: usize = 4 << 20;

#[repr(C)]
#[derive(Default)]
struct RegionInfo {
    argsz: u32,
    flags: u32,
    index: u32,
    cap_offset: u32,
    size: u64,
    offset: u64,
}

#[repr(C)]
struct DmaMap {
    argsz: u32,
    flags: u32,
    vaddr: u64,
    iova: u64,
    size: u64,
}

#[repr(C)]
struct IrqSet {
    argsz: u32,
    flags: u32,
    index: u32,
    start: u32,
    count: u32,
    fds: [i32; 2],
}

fn ioctl(fd: RawFd, req: u64, arg: u64) -> i64 {
    let r = unsafe { libc::ioctl(fd, req as _, arg) };
    if r < 0 {
        panic!("ioctl {:#x}: {}", req, std::io::Error::last_os_error());
    }
    r as i64
}

fn open(path: &str) -> RawFd {
    let c = CString::new(path).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR) };
    assert!(fd >= 0, "{path}: {}", std::io::Error::last_os_error());
    fd
}

struct Vfio {
    regs: usize,
    irq: [RawFd; 2],
}

/// Open the device, map BAR 0 and DMA memory at netd's address for NIC 0,
/// enable bus mastering and wire MSI-X entries 0 and 1 to eventfds.
fn vfio_open(bdf: &str) -> Vfio {
    let group = std::fs::read_link(format!("/sys/bus/pci/devices/{bdf}/iommu_group")).expect("iommu group");
    let group = group.file_name().unwrap().to_str().unwrap().to_string();
    let container = open("/dev/vfio/vfio");
    assert_eq!(ioctl(container, VFIO_GET_API_VERSION, 0), 0);
    let gfd = open(&format!("/dev/vfio/{group}"));
    let mut status = [8u32, 0];
    ioctl(gfd, VFIO_GROUP_GET_STATUS, status.as_mut_ptr() as u64);
    assert!(status[1] & 1 != 0, "group {group} is not viable: unbind its other devices");
    ioctl(gfd, VFIO_GROUP_SET_CONTAINER, &container as *const i32 as u64);
    ioctl(container, VFIO_SET_IOMMU, VFIO_TYPE1V2_IOMMU);
    let name = CString::new(bdf).unwrap();
    let dev = ioctl(gfd, VFIO_GROUP_GET_DEVICE_FD, name.as_ptr() as u64) as RawFd;

    let region = |index: u32| {
        let mut r = RegionInfo { argsz: size_of::<RegionInfo>() as u32, index, ..Default::default() };
        ioctl(dev, VFIO_DEVICE_GET_REGION_INFO, &mut r as *mut _ as u64);
        r
    };
    let bar0 = region(0);
    let regs = unsafe {
        libc::mmap(core::ptr::null_mut(), bar0.size as usize, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, dev, bar0.offset as i64)
    };
    assert!(regs != libc::MAP_FAILED, "mmap BAR 0");

    // DMA memory where netd has it, so that the driver's addresses work.
    let va = l4h_host::DMA_VA;
    let p = unsafe {
        libc::mmap(
            va as *mut _,
            DMA_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE | libc::MAP_LOCKED | libc::MAP_POPULATE,
            -1,
            0,
        )
    };
    assert_eq!(p as usize, va, "mmap DMA memory");
    let map = DmaMap { argsz: size_of::<DmaMap>() as u32, flags: 3, vaddr: va as u64, iova: DMA_IOVA, size: DMA_SIZE as u64 };
    ioctl(container, VFIO_IOMMU_MAP_DMA, &map as *const _ as u64);

    // Memory decoding and bus mastering (PCI command register).
    let cfg = region(VFIO_PCI_CONFIG_REGION_INDEX);
    // Root gives each nicd a read-only PCI snapshot. Use the real device's
    // snapshot here too, so the driver selects the same MAC variant.
    let snapshot = unsafe {
        libc::mmap(host::nicd::CFG_VA as *mut _, 4096, libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE, -1, 0)
    };
    assert_eq!(snapshot as usize, host::nicd::CFG_VA, "mmap PCI snapshot");
    let count = unsafe { libc::pread(dev, snapshot, 4096, cfg.offset as i64) };
    assert!(count >= 64, "read PCI snapshot");
    assert_eq!(unsafe { libc::mprotect(snapshot, 4096, libc::PROT_READ) }, 0);
    let mut cmd = [0u8; 2];
    unsafe { libc::pread(dev, cmd.as_mut_ptr() as *mut _, 2, cfg.offset as i64 + 4) };
    let v = u16::from_le_bytes(cmd) | 0x6;
    unsafe { libc::pwrite(dev, v.to_le_bytes().as_ptr() as *const _, 2, cfg.offset as i64 + 4) };

    let irq = [0, 1].map(|_| unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) });
    let set = IrqSet {
        argsz: size_of::<IrqSet>() as u32,
        flags: VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER,
        index: VFIO_PCI_MSIX_IRQ_INDEX,
        start: 0,
        count: 2,
        fds: irq,
    };
    ioctl(dev, VFIO_DEVICE_SET_IRQS, &set as *const _ as u64);
    Vfio { regs: regs as usize, irq }
}

fn tsc_hz() -> u64 {
    let (t, c) = (Instant::now(), l4h_host::ticks::now());
    std::thread::sleep(Duration::from_millis(200));
    ((l4h_host::ticks::now() - c) as f64 / t.elapsed().as_secs_f64()) as u64
}

/// Interrupts counted on an eventfd since the last call.
fn events(fd: RawFd) -> u64 {
    let mut v = 0u64;
    let r = unsafe { libc::read(fd, &mut v as *mut u64 as *mut _, 8) };
    if r == 8 { v } else { 0 }
}

// ---- packets

fn csum(mut sum: u32, data: &[u8]) -> u32 {
    for c in data.chunks(2) {
        sum += (c[0] as u32) << 8 | *c.get(1).unwrap_or(&0) as u32;
    }
    sum
}
fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f
}

/// An IPv4 packet in an Ethernet frame; returns the frame.
fn ipv4(dst_mac: [u8; 6], src_mac: [u8; 6], src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = eth(dst_mac, src_mac, 0x0800);
    let mut h = [0u8; 20];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    h[6] = 0x40;
    h[8] = 64;
    h[9] = proto;
    h[12..16].copy_from_slice(&src.octets());
    h[16..20].copy_from_slice(&dst.octets());
    let c = !fold(csum(0, &h));
    h[10..12].copy_from_slice(&c.to_be_bytes());
    f.extend_from_slice(&h);
    f.extend_from_slice(payload);
    f
}

/// Pseudo-header sum of an IPv4 TCP/UDP segment of `len` bytes.
fn pseudo(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> u32 {
    let mut s = csum(0, &src.octets());
    s = csum(s, &dst.octets());
    s + proto as u32 + len as u32
}

fn dns_query(id: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in ["example", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

struct Test {
    nic: ixgbe::Ixgbe,
    vfio: Vfio,
    mac: [u8; 6],
    ip: Ipv4Addr,
    gw: Ipv4Addr,
    gw_mac: [u8; 6],
    rx_irqs: u64,
    tx_irqs: u64,
    failures: u32,
}

impl Test {
    fn send(&mut self, frame: &[u8], hdr: &[u8; HDR]) {
        assert!(self.nic.transmit(frame, hdr), "no TX buffer");
        self.nic.kick_tx();
    }

    /// Receive until `f` accepts a frame or `secs` pass, as netd does:
    /// interrupts off while draining, then on with a final check.
    fn recv(&mut self, secs: u64, mut f: impl FnMut(&[u8], &[u8; HDR]) -> bool) -> bool {
        let end = Instant::now() + Duration::from_secs(secs);
        let mut buf = vec![0u8; net::MAX_FRAME];
        while Instant::now() < end {
            self.rx_irqs += events(self.vfio.irq[0]);
            self.tx_irqs += events(self.vfio.irq[1]);
            self.nic.rx_begin();
            loop {
                let mut hdr = [0u8; HDR];
                while let Some(n) = self.nic.receive(&mut buf, &mut hdr) {
                    if f(&buf[..n], &hdr) {
                        self.nic.rx_done();
                        return true;
                    }
                }
                if self.nic.rx_done() {
                    break;
                }
            }
            let mut p = libc::pollfd { fd: self.vfio.irq[0], events: libc::POLLIN, revents: 0 };
            unsafe { libc::poll(&mut p, 1, 50) };
        }
        false
    }

    fn check(&mut self, what: &str, ok: bool) {
        println!("{} {what}", if ok { "PASS" } else { "FAIL" });
        self.failures += !ok as u32;
    }

    fn arp(&mut self) -> bool {
        let mut a = eth([0xff; 6], self.mac, 0x0806);
        a.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        a.extend_from_slice(&self.mac);
        a.extend_from_slice(&self.ip.octets());
        a.extend_from_slice(&[0; 6]);
        a.extend_from_slice(&self.gw.octets());
        let gw = self.gw.octets();
        for _ in 0..3 {
            self.send(&a, &[0; HDR]);
            let mut mac = [0u8; 6];
            if self.recv(2, |f, _| {
                let ok = f.len() >= 42 && f[12..14] == [8, 6] && f[20..22] == [0, 2] && f[28..32] == gw;
                if ok {
                    mac.copy_from_slice(&f[22..28]);
                }
                ok
            }) {
                self.gw_mac = mac;
                return true;
            }
        }
        false
    }

    fn ping(&mut self, dst: Ipv4Addr) -> bool {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
        icmp.extend_from_slice(b"l4h ixgbe-vfio ping");
        let c = !fold(csum(0, &icmp));
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        let f = ipv4(self.gw_mac, self.mac, self.ip, dst, 1, &icmp);
        self.send(&f, &[0; HDR]);
        let src = dst.octets();
        self.recv(3, |f, _| f.len() >= 42 && f[12..14] == [8, 0] && f[23] == 1 && f[26..30] == src && f[34] == 0)
    }

    /// A DNS query to 1.1.1.1; with `offload` the device computes the UDP
    /// checksum.  Returns (reply received, device validated its checksum).
    fn dns(&mut self, id: u16, offload: bool) -> (bool, bool) {
        let dst = Ipv4Addr::new(1, 1, 1, 1);
        let q = dns_query(id);
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + q.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&q);
        let ph = pseudo(self.ip, dst, 17, udp.len());
        let mut hdr = [0u8; HDR];
        if offload {
            udp[6..8].copy_from_slice(&fold(ph).to_be_bytes());
            hdr[0] = offload::F_NEEDS_CSUM;
            hdr[6..8].copy_from_slice(&34u16.to_le_bytes());
            hdr[8..10].copy_from_slice(&6u16.to_le_bytes());
        } else {
            let c = !fold(csum(ph, &udp));
            udp[6..8].copy_from_slice(&c.to_be_bytes());
        }
        let f = ipv4(self.gw_mac, self.mac, self.ip, dst, 17, &udp);
        self.send(&f, &hdr);
        let mut valid = false;
        let got = self.recv(3, |f, h| {
            let ok = f.len() >= 44 && f[12..14] == [8, 0] && f[23] == 17 && f[34..36] == [0, 53] && f[42..44] == id.to_be_bytes();
            if ok {
                valid = h[0] & offload::F_DATA_VALID != 0;
            }
            ok
        });
        (got, valid)
    }

    fn tcp(&self, dst: Ipv4Addr, sport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8], gso_mss: u16) -> (Vec<u8>, [u8; HDR]) {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&sport.to_be_bytes());
        t[2..4].copy_from_slice(&80u16.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&ack.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&64240u16.to_be_bytes());
        t.extend_from_slice(payload);
        let ph = pseudo(self.ip, dst, 6, t.len());
        let mut hdr = [0u8; HDR];
        if gso_mss != 0 {
            // As a Linux guest sends it: pseudo-header sum with the full
            // length, checksum and segmentation left to the device.
            t[16..18].copy_from_slice(&fold(ph).to_be_bytes());
            hdr[0] = offload::F_NEEDS_CSUM;
            hdr[1] = offload::GSO_TCPV4;
            hdr[2..4].copy_from_slice(&54u16.to_le_bytes());
            hdr[4..6].copy_from_slice(&gso_mss.to_le_bytes());
            hdr[6..8].copy_from_slice(&34u16.to_le_bytes());
            hdr[8..10].copy_from_slice(&16u16.to_le_bytes());
        } else {
            let c = !fold(csum(ph, &t));
            t[16..18].copy_from_slice(&c.to_be_bytes());
        }
        (ipv4(self.gw_mac, self.mac, self.ip, dst, 6, &t), hdr)
    }

    /// Connect to 1.1.1.1:80 and send `len` bytes of HTTP request as one
    /// GSO frame; true if the server acknowledges all of them.
    fn tso(&mut self, sport: u16, len: usize) -> bool {
        let dst = Ipv4Addr::new(1, 1, 1, 1);
        let iss = 0x1000_0000u32;
        let (syn, h) = self.tcp(dst, sport, iss, 0, 0x02, &[], 0);
        self.send(&syn, &h);
        let mut srv = 0u32;
        let from = dst.octets();
        let is_ours = move |f: &[u8]| f.len() >= 54 && f[12..14] == [8, 0] && f[23] == 6 && f[26..30] == from && f[36..38] == sport.to_be_bytes();
        if !self.recv(3, |f, _| {
            let ok = is_ours(f) && f[47] & 0x12 == 0x12;
            if ok {
                srv = u32::from_be_bytes(f[38..42].try_into().unwrap());
            }
            ok
        }) {
            println!("     no SYN-ACK");
            return false;
        }
        let mut req = b"GET / HTTP/1.1\r\nHost: one.one.one.one\r\nX-Pad: ".to_vec();
        req.resize(len - 4, b'a');
        req.extend_from_slice(b"\r\n\r\n");
        let (data, h) = self.tcp(dst, sport, iss + 1, srv + 1, 0x18, &req, 1448);
        self.send(&data, &h);
        let want = iss + 1 + len as u32;
        let mut acked = 0;
        let ok = self.recv(5, |f, _| {
            if is_ours(f) && f[47] & 0x10 != 0 {
                acked = u32::from_be_bytes(f[42..46].try_into().unwrap());
            }
            acked == want
        });
        if !ok {
            println!("     server acknowledged {} of {} bytes", acked.wrapping_sub(iss + 1), len);
        }
        let (rst, h) = self.tcp(dst, sport, want, 0, 0x04, &[], 0);
        self.send(&rst, &h);
        ok
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: {} PCI-ADDRESS OUR-IP GATEWAY-IP [--offload]", args[0]);
        std::process::exit(2);
    }
    let offload = args.iter().any(|a| a == "--offload");
    let vfio = vfio_open(&args[1]);
    let hz = tsc_hz();
    let msix = vec![0u8; 64 * 16].leak();
    let bdf = u32::from_str_radix(&args[1][5..7], 16).unwrap() << 8
        | u32::from_str_radix(&args[1][8..10], 16).unwrap() << 3
        | u32::from_str_radix(&args[1][11..12], 16).unwrap();
    let none = PciRegion { va: 0, len: 0 };
    let regs = PciRegion { va: vfio.regs as u64, len: 4 << 20 };
    // VFIO owns the MSI-X table; the driver's writes go to a copy.
    let msix_table = PciRegion { va: msix.as_ptr() as u64, len: msix.len() as u64 };
    let hw = sdk::hw(sdk::config(bdf, 0, [regs, none, none, none, none, none], msix_table, DMA_IOVA, DMA_SIZE as u64), hz);
    let t0 = Instant::now();
    let mut nic = ixgbe::Ixgbe::new(&hw, Box::leak(Box::default()));
    println!("init took {:?}", t0.elapsed());
    if offload {
        nic.csum = true;
        nic.tso = true;
    }
    let mac = nic.mac;
    let mut t = Test {
        nic,
        vfio,
        mac,
        ip: args[2].parse().unwrap(),
        gw: args[3].parse().unwrap(),
        gw_mac: [0; 6],
        rx_irqs: 0,
        tx_irqs: 0,
        failures: 0,
    };
    let ok = t.arp();
    t.check(&format!("ARP for the gateway: {:02x?}", t.gw_mac), ok);
    if !ok {
        std::process::exit(1);
    }
    let ok = t.ping(Ipv4Addr::new(1, 1, 1, 1));
    t.check("ICMP echo to 1.1.1.1", ok);
    let (ok, valid) = t.dns(0x4c34, false);
    t.check("DNS over UDP to 1.1.1.1", ok);
    t.check("UDP reply checksum validated by the device", valid);
    if offload {
        let (ok, _) = t.dns(0x4c35, true);
        t.check("DNS with UDP checksum offload", ok);
        let ok = t.tso(40001, 4000);
        t.check("4000-byte TCP send as one TSO frame", ok);
        let ok = t.tso(40002, 60000);
        t.check("60000-byte TCP send as one TSO frame", ok);
    }
    // Interrupts: TX ones only arrive while enabled.
    t.nic.tx_interrupts(true);
    let (f, h) = t.tcp(Ipv4Addr::new(1, 1, 1, 1), 40003, 1, 0, 0x04, &[], 0);
    t.send(&f, &h);
    std::thread::sleep(Duration::from_millis(200));
    t.rx_irqs += events(t.vfio.irq[0]);
    t.tx_irqs += events(t.vfio.irq[1]);
    let (rx, tx) = (t.rx_irqs, t.tx_irqs);
    t.check(&format!("interrupts: {rx} RX, {tx} TX"), rx > 0 && tx > 0);
    println!("{} failure(s)", t.failures);
    std::process::exit((t.failures != 0) as i32);
}
