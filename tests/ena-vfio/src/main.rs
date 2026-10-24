//! Hardware integration test: production ENA and software GSO, with VFIO
//! standing in for seL4 mappings/interrupt delivery. Use a dedicated ENI.
//! Usage: ena-vfio PCI-ADDRESS OUR-IP PEER-IP [--host-queue] [--packets=N]

extern crate self as l4h_rt;
pub use l4h_host as host;
#[macro_export]
macro_rules! info { ($($arg:tt)*) => { eprintln!($($arg)*) }; }
pub mod sel4 {
    pub use crate::info as debug_println;
}
mod nic {
    pub type Partial = l4h_host::fixed::ArrayVec<u8, { l4h_host::net::MAX_FRAME }>;
}
#[allow(dead_code)]
#[path = "../../../host/l4h-netd/src/ena.rs"]
mod ena;
#[allow(dead_code)]
#[path = "../../../host/l4h-netd/src/offload.rs"]
mod offload;
#[allow(dead_code)]
#[path = "../../../host/l4h-netd/src/pool.rs"]
mod pool;
mod vfio;

use l4h_host::{
    blk::PciRegion,
    net::{self, NicConfig},
};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use vfio::Vfio;
const HDR: usize = net::HDR_SIZE;
const PORT: u16 = 9000;
const SPORT: u16 = 40000;

fn tsc_hz() -> u64 {
    let (t, c) = (Instant::now(), host::ticks::now());
    std::thread::sleep(Duration::from_millis(200));
    ((host::ticks::now() - c) as f64 / t.elapsed().as_secs_f64()) as u64
}

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
fn ipv4(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    payload: &[u8],
) -> Vec<u8> {
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

struct Test {
    nic: ena::Ena,
    vfio: Vfio,
    mac: [u8; 6],
    ip: Ipv4Addr,
    gw: Ipv4Addr,
    gw_mac: [u8; 6],
    failures: u32,
    management_irqs: u64,
    io_irqs: u64,
    rx: u64,
    tx: u64,
    rx_valid: u64,
}

impl Test {
    fn check(&mut self, what: &str, ok: bool) {
        println!("{} {what}", if ok { "PASS" } else { "FAIL" });
        self.failures += !ok as u32;
    }

    fn send_one(&mut self, frame: &[u8], hdr: &[u8; HDR]) {
        let end = Instant::now() + Duration::from_secs(3);
        while !self.nic.transmit(frame, hdr) {
            self.nic.kick_tx();
            self.nic.tx_interrupts(true);
            assert!(Instant::now() < end, "TX completion timed out");
            std::thread::yield_now();
        }
        self.tx += 1;
    }

    fn send(&mut self, frame: &[u8], hdr: &[u8; HDR]) {
        if offload::is_gso(hdr) {
            let mut buf = vec![0u8; net::MAX_FRAME];
            offload::segment(frame, hdr, &mut buf, |f, h| self.send_one(f, h));
        } else {
            self.send_one(frame, hdr);
        }
        self.nic.kick_tx();
    }

    fn count_irqs(&mut self) {
        self.management_irqs += self.vfio.events(0);
        self.io_irqs += self.vfio.events(1);
    }

    fn recv(&mut self, secs: u64, mut accept: impl FnMut(&[u8], &[u8; HDR]) -> bool) -> bool {
        let end = Instant::now() + Duration::from_secs(secs);
        let mut buf = vec![0u8; net::MAX_FRAME];
        while Instant::now() < end {
            self.count_irqs();
            self.nic.rx_begin();
            let mut hdr = [0u8; HDR];
            while let Some(n) = self.nic.receive(&mut buf, &mut hdr) {
                self.rx += 1;
                self.rx_valid += (hdr[0] & offload::F_DATA_VALID != 0) as u64;
                if accept(&buf[..n], &hdr) {
                    self.nic.rx_done();
                    return true;
                }
                if Instant::now() >= end {
                    break;
                }
            }
            if !self.nic.rx_done() {
                continue;
            }
            let mut poll = [0, 1].map(|i| libc::pollfd {
                fd: self.vfio.irq[i],
                events: libc::POLLIN,
                revents: 0,
            });
            unsafe {
                libc::poll(poll.as_mut_ptr(), 2, 20);
            }
        }
        false
    }

    fn udp(&self, payload: &[u8], partial: bool) -> (Vec<u8>, [u8; HDR]) {
        let mut udp = vec![0u8; 8];
        udp[..2].copy_from_slice(&SPORT.to_be_bytes());
        udp[2..4].copy_from_slice(&PORT.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(payload);
        let ph = pseudo(self.ip, self.gw, 17, udp.len());
        let mut hdr = [0u8; HDR];
        let checksum = if partial {
            hdr[0] = offload::F_NEEDS_CSUM;
            hdr[6..8].copy_from_slice(&34u16.to_le_bytes());
            hdr[8..10].copy_from_slice(&6u16.to_le_bytes());
            fold(ph)
        } else {
            let c = !fold(csum(ph, &udp));
            if c == 0 { 0xffff } else { c }
        };
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());
        (ipv4(self.gw_mac, self.mac, self.ip, self.gw, 17, &udp), hdr)
    }

    fn echo(&mut self, len: usize, partial: bool, seq: u32) -> (bool, bool) {
        let payload: Vec<u8> = (0..len)
            .map(|i| (i as u32 + seq).wrapping_mul(73) as u8)
            .collect();
        let (frame, hdr) = self.udp(&payload, partial);
        self.send(&frame, &hdr);
        let (ip, peer) = (self.ip, self.gw);
        let mut valid = false;
        let ok = self.recv(3, |f, h| {
            let Some(data) = udp_payload(f, peer, ip) else {
                return false;
            };
            if data != payload {
                return false;
            }
            valid = h[0] & offload::F_DATA_VALID != 0;
            true
        });
        (ok, valid)
    }

    fn burst(&mut self, first: u32, count: usize) -> bool {
        for seq in first..first + count as u32 {
            let mut payload = vec![0u8; 256];
            payload[..4].copy_from_slice(&seq.to_be_bytes());
            for (i, b) in payload[4..].iter_mut().enumerate() {
                *b = (seq as usize + i) as u8;
            }
            let (frame, hdr) = self.udp(&payload, true);
            self.send_one(&frame, &hdr);
        }
        self.nic.kick_tx();
        let (ip, peer) = (self.ip, self.gw);
        let mut seen = vec![false; count];
        let mut received = 0;
        self.recv(5, |f, h| {
            let Some(data) = udp_payload(f, peer, ip) else {
                return false;
            };
            if data.len() != 256 || h[0] & offload::F_DATA_VALID == 0 {
                return false;
            }
            let seq = u32::from_be_bytes(data[..4].try_into().unwrap());
            let index = seq.wrapping_sub(first) as usize;
            if index >= count || seen[index] {
                return false;
            }
            if !data[4..]
                .iter()
                .enumerate()
                .all(|(i, &b)| b == (seq as usize + i) as u8)
            {
                return false;
            }
            seen[index] = true;
            received += 1;
            received == count
        })
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
                let ok =
                    f.len() >= 42 && f[12..14] == [8, 6] && f[20..22] == [0, 2] && f[28..32] == gw;
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
        icmp.extend_from_slice(b"l4h ENA hardware test");
        let c = !fold(csum(0, &icmp));
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        let f = ipv4(self.gw_mac, self.mac, self.ip, dst, 1, &icmp);
        self.send(&f, &[0; HDR]);
        let src = dst.octets();
        self.recv(3, |f, _| {
            f.len() >= 42 && f[12..14] == [8, 0] && f[23] == 1 && f[26..30] == src && f[34] == 0
        })
    }

    fn tcp(
        &self,
        dst: Ipv4Addr,
        sport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
        gso_mss: u16,
    ) -> (Vec<u8>, [u8; HDR]) {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&sport.to_be_bytes());
        t[2..4].copy_from_slice(&9001u16.to_be_bytes());
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

    /// Send through the production software GSO path and check the peer ACK.
    fn tso(&mut self, sport: u16, len: usize) -> bool {
        let dst = self.gw;
        let iss = 0x1000_0000u32;
        let (syn, h) = self.tcp(dst, sport, iss, 0, 0x02, &[], 0);
        self.send(&syn, &h);
        let mut srv = 0u32;
        let from = dst.octets();
        let is_ours = move |f: &[u8]| {
            f.len() >= 54
                && f[12..14] == [8, 0]
                && f[23] == 6
                && f[26..30] == from
                && f[36..38] == sport.to_be_bytes()
        };
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
        let req: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
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
            println!(
                "     server acknowledged {} of {} bytes",
                acked.wrapping_sub(iss + 1),
                len
            );
        }
        let (rst, h) = self.tcp(dst, sport, want, 0, 0x04, &[], 0);
        self.send(&rst, &h);
        ok
    }
}

fn udp_payload(f: &[u8], peer: Ipv4Addr, ip: Ipv4Addr) -> Option<&[u8]> {
    if f.len() < 42
        || f[12..14] != [8, 0]
        || f[14] != 0x45
        || f[23] != 17
        || f[26..30] != peer.octets()
        || f[30..34] != ip.octets()
        || f[34..36] != PORT.to_be_bytes()
        || f[36..38] != SPORT.to_be_bytes()
    {
        return None;
    }
    let n = u16::from_be_bytes([f[38], f[39]]) as usize;
    if n < 8
        || 34 + n > f.len()
        || f[40..42] == [0, 0]
        || fold(csum(pseudo(peer, ip, 17, n), &f[34..34 + n])) != 0xffff
    {
        return None;
    }
    Some(&f[42..34 + n])
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: {} PCI-ADDRESS OUR-IP PEER-IP [--host-queue] [--packets=N]",
            args[0]
        );
        std::process::exit(2);
    }
    let ip: Ipv4Addr = args[2].parse().expect("OUR-IP");
    let peer: Ipv4Addr = args[3].parse().expect("PEER-IP");
    let mut packets = 4096usize;
    let mut host_queue = false;
    for arg in &args[4..] {
        if arg == "--host-queue" {
            host_queue = true;
        } else if let Some(n) = arg.strip_prefix("--packets=") {
            packets = n.parse().unwrap();
        } else {
            panic!("unknown option: {arg}");
        }
    }
    assert!(
        (1024..=1_000_000).contains(&packets),
        "packets must be 1024..1000000"
    );
    let vfio = Vfio::open(&args[1], host_queue);
    let msix = vec![0u8; 64 * 16].leak();
    let bdf = u32::from_str_radix(&args[1][5..7], 16).unwrap() << 8
        | u32::from_str_radix(&args[1][8..10], 16).unwrap() << 3
        | u32::from_str_radix(&args[1][11..12], 16).unwrap();
    let cfg = NicConfig {
        kind: net::NIC_ENA,
        revision: vfio.revision,
        pci_bdf: bdf,
        regs: vfio.regs,
        doorbells: vfio.llq,
        msix_table: PciRegion {
            va: msix.as_ptr() as u64,
            len: msix.len() as u64,
        },
        dma_paddr: vfio.dma_paddr,
        dma_size: vfio.dma_size(),
        ..Default::default()
    };
    let started = Instant::now();
    let nic = ena::Ena::new(0, &cfg, tsc_hz(), Box::leak(Box::default()));
    // The driver's device reset may clear MSI-X table entries.
    vfio.enable_irqs();
    println!("init completed in {:?}", started.elapsed());
    let mac = nic.mac;
    let mut t = Test {
        nic,
        vfio,
        mac,
        ip,
        gw: peer,
        gw_mac: [0; 6],
        failures: 0,
        management_irqs: 0,
        io_irqs: 0,
        rx: 0,
        tx: 0,
        rx_valid: 0,
    };
    t.check(
        "ENA initialization and hardware checksum capability",
        t.nic.csum && !t.nic.tso,
    );
    let ok = t.arp();
    t.check("ARP to the test peer", ok);
    if ok {
        let ok = t.ping(peer);
        t.check("ICMP echo", ok);
        for len in [1, 18, 53, 54, 55, 96, 128, 1400, 2000, 4000, 8973] {
            for partial in [false, true] {
                let (got, valid) = t.echo(len, partial, len as u32);
                t.check(
                    &format!(
                        "UDP echo: {len} payload bytes, TX {} checksum, RX DATA_VALID",
                        if partial { "hardware" } else { "software" }
                    ),
                    got && valid,
                );
            }
        }
        let mut done = 0;
        let start = Instant::now();
        while done < packets {
            let count = (packets - done).min(64);
            if !t.burst(0x1000_0000 + done as u32, count) {
                break;
            }
            done += count;
        }
        t.check(
            &format!(
                "queue wraparound: {done}/{packets} checked UDP echoes in {:?}",
                start.elapsed()
            ),
            done == packets,
        );
        for (port, len) in [(40001, 4000), (40002, 60000)] {
            let ok = t.tso(port, len);
            t.check(
                &format!("{len}-byte TCP GSO via netd software segmentation"),
                ok,
            );
        }
        // Drain stale events, then wait for a fresh I/O interrupt without
        // polling receive. Successful polling alone must not pass this test.
        t.recv(1, |_, _| false);
        t.count_irqs();
        let before = t.io_irqs;
        let (frame, hdr) = t.udp(b"interrupt delivery", true);
        t.send(&frame, &hdr);
        let mut poll = libc::pollfd {
            fd: t.vfio.irq[1],
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 2000) };
        t.count_irqs();
        t.check(
            "fresh MSI-X I/O event without RX polling",
            ready > 0 && t.io_irqs > before,
        );
        t.recv(1, |_, _| false);
    }
    t.count_irqs();
    t.check("management MSI-X events", t.management_irqs > 0);
    println!(
        "TX {} RX {} RX checksum-valid {}; MSI-X management {} I/O {}",
        t.tx, t.rx, t.rx_valid, t.management_irqs, t.io_irqs
    );
    println!(
        "ENATEST: {} ({} failures)",
        if t.failures == 0 { "PASS" } else { "FAIL" },
        t.failures
    );
    let failed = t.failures != 0;
    drop(t); // Disable DMA before releasing userspace memory.
    std::process::exit(failed as i32);
}
