//! The driver against a software model of the chip (`cargo test`), for
//! want of the hardware: registers in plain memory and a thread that plays
//! the chip's part.  It answers the PHY and EPHY windows (the PHY's
//! registers are a table the test reads back), clears the reset bit, and
//! moves both descriptor rings: frames the test queues go into RX buffers
//! the driver owns no more, and TX descriptors are taken while the
//! doorbell says so (or held, to fill the ring).  Interrupts are not
//! modelled.  What it checks: bring-up (MAC address, PHY parameters,
//! autonegotiation advertisement, a firmware program run through the
//! paged PHY view), RX across ring wraps with checksum verdicts and the
//! frames the driver drops, TX across ring and area wraps with Linux's
//! padding, checksums completed in the driver, TSO descriptors for IPv4
//! and IPv6, tagged and ECN GSO frames segmented in the driver, plain
//! frames past the MTU dropped, and the ring and area limits.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::ptr::{read_volatile, write_volatile};
use std::sync::atomic::{AtomicBool, Ordering, fence};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{DMA_IOVA, DMA_SIZE, HDR, PciRegion, csum, fold, ipv4, pseudo, r8125, sdk};
use crate::sdk::NicDriver;
use l4h_netcore::offload;

const BAR: usize = 64 << 10;
const OWN: u32 = 1 << 31;
const RING_END: u32 = 1 << 30;
const FS: u32 = 1 << 29;
const LS: u32 = 1 << 28;
const FLAG: u32 = 1 << 31;
const MAC: [u8; 6] = [0x00, 0xe0, 0x4c, 0x68, 0x12, 0x34];
const PEER: [u8; 6] = [0x02, 0, 0, 0, 0, 1];

fn r8(a: usize) -> u8 {
    unsafe { read_volatile(a as *const u8) }
}
fn w8(a: usize, v: u8) {
    unsafe { write_volatile(a as *mut u8, v) }
}
fn r16(a: usize) -> u16 {
    unsafe { read_volatile(a as *const u16) }
}
fn w16(a: usize, v: u16) {
    unsafe { write_volatile(a as *mut u16, v) }
}
fn r32(a: usize) -> u32 {
    unsafe { read_volatile(a as *const u32) }
}
fn w32(a: usize, v: u32) {
    unsafe { write_volatile(a as *mut u32, v) }
}
fn r64(a: usize) -> u64 {
    unsafe { read_volatile(a as *const u64) }
}

/// A DMA address as the test's virtual address.
fn va(pa: u64) -> usize {
    l4h_host::DMA_VA + (pa - DMA_IOVA) as usize
}

struct Tx {
    frame: Vec<u8>,
    opts1: u32,
    opts2: u32,
}

#[derive(Default)]
struct Shared {
    /// The PHY's registers by OCP address / 2.
    phy: Mutex<Vec<u16>>,
    /// Frames to receive, with the status bits their descriptor gets.
    rx: Mutex<VecDeque<(Vec<u8>, u32)>>,
    tx: Mutex<Vec<Tx>>,
    hold: AtomicBool,
    stop: AtomicBool,
}

/// The chip's side, until `stop`.
fn chip(bar: usize, s: Arc<Shared>) {
    // The values the chip itself last left in the two access windows: any
    // other is a request.
    let (mut gphy, mut ephy) = (0u32, 0u32);
    let mut ephy_regs = [0u16; 32];
    let (mut rx_cur, mut tx_cur, mut polling) = (0usize, 0usize, false);
    while !s.stop.load(Ordering::Relaxed) {
        let cmd = r8(bar + 0x37);
        if cmd & 0x10 != 0 {
            w8(bar + 0x37, cmd & !0x10);
            (rx_cur, tx_cur, polling) = (0, 0, false);
        }
        let v = r32(bar + 0xb8);
        if v != gphy {
            // The address's bit 0 (always clear) shares bit 15 with the data.
            let reg = ((v >> 15) & 0xfffe) as usize;
            let mut phy = s.phy.lock().unwrap();
            gphy = if v & FLAG != 0 {
                // BMCR's reset and restart bits clear themselves.
                phy[reg / 2] = if reg == 0xa400 { v as u16 & !0x8200 } else { v as u16 };
                v & !FLAG
            } else {
                FLAG | v | phy[reg / 2] as u32
            };
            w32(bar + 0xb8, gphy);
        }
        let v = r32(bar + 0x80);
        if v != ephy {
            let reg = ((v >> 16) & 0x1f) as usize;
            ephy = if v & FLAG != 0 {
                ephy_regs[reg] = v as u16;
                v & !FLAG
            } else {
                FLAG | v | ephy_regs[reg] as u32
            };
            w32(bar + 0x80, ephy);
        }
        let rx_pa = (r32(bar + 0xe8) as u64) << 32 | r32(bar + 0xe4) as u64;
        if rx_pa != 0 && cmd & 0x08 != 0 {
            let mut q = s.rx.lock().unwrap();
            while let Some((f, status)) = q.front() {
                let d = va(rx_pa) + rx_cur * 16;
                let o1 = r32(d);
                if o1 & OWN == 0 {
                    break;
                }
                fence(Ordering::Acquire);
                assert_eq!(o1 & RING_END != 0, rx_cur == 511, "RX ring end at {rx_cur}");
                let size = (o1 & 0x3fff) as usize;
                assert!(f.len() + 4 <= size, "a test frame larger than the buffer");
                let buf = va(r64(d + 8));
                unsafe { core::ptr::copy_nonoverlapping(f.as_ptr(), buf as *mut u8, f.len()) };
                fence(Ordering::Release);
                w32(d, status | (o1 & RING_END) | (f.len() + 4) as u32);
                rx_cur = if o1 & RING_END != 0 { 0 } else { rx_cur + 1 };
                q.pop_front();
            }
        }
        let tx_pa = (r32(bar + 0x24) as u64) << 32 | r32(bar + 0x20) as u64;
        if tx_pa != 0 && cmd & 0x04 != 0 && !s.hold.load(Ordering::Relaxed) {
            if r16(bar + 0x90) & 1 != 0 {
                w16(bar + 0x90, 0);
                polling = true;
            }
            while polling {
                let d = va(tx_pa) + tx_cur * 16;
                let o1 = r32(d);
                if o1 & OWN == 0 {
                    polling = false;
                    break;
                }
                fence(Ordering::Acquire);
                assert_eq!(o1 & RING_END != 0, tx_cur == 255, "TX ring end at {tx_cur}");
                assert_eq!(o1 & (FS | LS), FS | LS, "a frame in one descriptor");
                let len = (o1 & 0xffff) as usize;
                let frame = unsafe { core::slice::from_raw_parts(va(r64(d + 8)) as *const u8, len) }.to_vec();
                s.tx.lock().unwrap().push(Tx { frame, opts1: o1, opts2: r32(d + 4) });
                fence(Ordering::Release);
                w32(d, o1 & !OWN);
                tx_cur = if o1 & RING_END != 0 { 0 } else { tx_cur + 1 };
            }
        }
        std::hint::spin_loop();
    }
}

/// A deterministic byte stream.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// A TCP segment over IPv4 with `payload`; with `gso_mss` as a Linux
/// sender leaves a GSO frame (pseudo-header sum with the full length in
/// the checksum field), else with its checksum.
fn tcp4(payload: &[u8], gso_mss: u16) -> (Vec<u8>, [u8; HDR]) {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&40000u16.to_be_bytes());
    t[2..4].copy_from_slice(&80u16.to_be_bytes());
    t[4..8].copy_from_slice(&1000u32.to_be_bytes());
    t[12] = 5 << 4;
    t[13] = 0x18;
    t[14..16].copy_from_slice(&64240u16.to_be_bytes());
    t.extend_from_slice(payload);
    let ph = pseudo(SRC, DST, 6, t.len());
    let mut hdr = [0u8; HDR];
    if gso_mss != 0 {
        t[16..18].copy_from_slice(&fold(ph).to_be_bytes());
        hdr = gso_hdr(offload::GSO_TCPV4, 54, gso_mss, 34);
    } else {
        let c = !fold(csum(ph, &t));
        t[16..18].copy_from_slice(&c.to_be_bytes());
    }
    (ipv4(PEER, MAC, SRC, DST, 6, &t), hdr)
}

fn gso_hdr(ty: u8, hdr_len: u16, mss: u16, start: u16) -> [u8; HDR] {
    let mut h = [0u8; HDR];
    h[0] = offload::F_NEEDS_CSUM;
    h[1] = ty;
    h[2..4].copy_from_slice(&hdr_len.to_le_bytes());
    h[4..6].copy_from_slice(&mss.to_le_bytes());
    h[6..8].copy_from_slice(&start.to_le_bytes());
    h[8..10].copy_from_slice(&16u16.to_le_bytes());
    h
}

/// A TCP GSO frame over IPv6.
fn tcp6_gso(payload: &[u8], mss: u16) -> (Vec<u8>, [u8; HDR]) {
    let mut f = super::eth(PEER, MAC, 0x86dd);
    let mut ip = [0u8; 40];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    ip[6] = 6;
    ip[7] = 64;
    ip[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    ip[24..40].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&ip);
    let mut t = vec![0u8; 20];
    t[12] = 5 << 4;
    t[13] = 0x18;
    let ph = csum(0, &ip[8..40]) + 6 + (20 + payload.len()) as u32;
    t[16..18].copy_from_slice(&fold(ph).to_be_bytes());
    t.extend_from_slice(payload);
    f.extend_from_slice(&t);
    (f, gso_hdr(offload::GSO_TCPV6, 74, mss, 54))
}

/// Whether an IPv4 frame's TCP or UDP checksum is right, the IPv4 header
/// at `ip` (the frame may be padded past its total length).
fn l4_ok(f: &[u8], ip: usize) -> bool {
    let ihl = (f[ip] & 0xf) as usize * 4;
    let total = u16::from_be_bytes([f[ip + 2], f[ip + 3]]) as usize;
    let l4 = &f[ip + ihl..ip + total];
    let src = Ipv4Addr::new(f[ip + 12], f[ip + 13], f[ip + 14], f[ip + 15]);
    let dst = Ipv4Addr::new(f[ip + 16], f[ip + 17], f[ip + 18], f[ip + 19]);
    fold(csum(pseudo(src, dst, f[ip + 9], l4.len()), l4)) == 0xffff && fold(csum(0, &f[ip..ip + ihl])) == 0xffff
}

struct Rig {
    nic: r8125::R8125,
    s: Arc<Shared>,
}

impl Rig {
    /// Send, retrying while the driver has no room (the chip frees it).
    fn send(&mut self, f: &[u8], h: &[u8; HDR]) {
        let end = Instant::now() + Duration::from_secs(5);
        while !self.nic.transmit(f, h) {
            assert!(Instant::now() < end, "the driver keeps refusing a frame");
            std::thread::sleep(Duration::from_micros(50));
        }
        self.nic.kick_tx();
    }

    /// Wait for `n` frames on the wire and take them.
    fn sent(&mut self, n: usize) -> Vec<Tx> {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            {
                let mut tx = self.s.tx.lock().unwrap();
                if tx.len() >= n {
                    assert_eq!(tx.len(), n, "more frames on the wire than sent");
                    return std::mem::take(&mut *tx);
                }
            }
            assert!(Instant::now() < end, "frames do not reach the wire");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// The frames that leave for (frame, hdr): what transmit pads and checks.
fn padded(f: &[u8], len: usize) -> Vec<u8> {
    let mut v = f.to_vec();
    v.resize(len.max(f.len()), 0);
    v
}

#[test]
fn manifest() {
    let m = r8125::MANIFEST;
    assert!(m.valid(), "root takes the manifest");
    let ids = |device| l4h_host::nicd::Ids { vendor: 0x10ec, device, subvendor: 0x1849, subdevice: 0x8125, class: 0x020000, revision: 5 };
    assert!(m.matching(&ids(0x8125)).is_some() && m.matching(&ids(0x3000)).is_some() && m.matching(&ids(0x8168)).is_none());
    assert_eq!(&m.firmware[0][..22], b"rtl_nic/rtl8125b-2.fw\0");
}

#[test]
fn model() {
    // DMA memory and the configuration snapshot where root maps them.
    let map = |at: usize, len: usize| {
        let p = unsafe {
            libc::mmap(at as *mut _, len, libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE, -1, 0)
        };
        assert_eq!(p as usize, at, "mmap {at:#x}");
    };
    map(l4h_host::DMA_VA, DMA_SIZE);
    map(l4h_host::nicd::CFG_VA, 4096);
    let bar = vec![0u32; BAR / 4].leak().as_mut_ptr() as usize;
    w32(bar + 0x40, 0x641 << 20);
    w8(bar + 0xd3, 0x32);
    w16(bar + 0xe2, 0x0103);
    for (i, b) in MAC.iter().enumerate() {
        w8(bar + 0x19e0 + i, *b);
    }
    let s = Arc::new(Shared::default());
    {
        let mut phy = s.phy.lock().unwrap();
        phy.resize(0x8000, 0);
        phy[0xa402 / 2] = 0x0004;
        phy[0xa434 / 2] = 0x0210;
    }
    let chip_thread = {
        let s = s.clone();
        std::thread::spawn(move || chip(bar, s))
    };

    // A firmware program: a page, a write, a read back, OR, write of the
    // read value, page 0, a skip that skips one write, one it does not.
    let fw: Vec<u8> = [
        0x8 << 28 | 0x1f << 16 | 0x0bc3,
        0x8 << 28 | 0x12 << 16 | 0x1234,
        0x12 << 16,
        0x1 << 28 | 0x0001,
        0xc << 28 | 0x13 << 16,
        0x8 << 28 | 0x1f << 16,
        0xa << 28 | 1 << 16 | 0x1235,
        0x8 << 28 | 0x10 << 16 | 0xdead,
        0x8 << 28 | 0x11 << 16 | 0xbeef,
    ]
    .iter()
    .flat_map(|w: &u32| w.to_le_bytes())
    .collect();
    let fw = fw.leak();
    let none = PciRegion { va: 0, len: 0 };
    let msix = vec![0u8; 32 * 16].leak();
    let mut config = sdk::config(0x500, 0, [none, none, PciRegion { va: bar as u64, len: BAR as u64 }, none, none, none],
        PciRegion { va: msix.as_ptr() as u64, len: msix.len() as u64 }, DMA_IOVA, DMA_SIZE as u64);
    config.firmware[0] = PciRegion { va: fw.as_ptr() as u64, len: fw.len() as u64 };
    let hw = sdk::hw(config, super::tsc_hz());
    let nic = r8125::R8125::new(&hw).expect("bring-up");

    // ---- bring-up
    assert_eq!(nic.mac, MAC);
    assert_eq!((r32(bar), r16(bar + 4)), (u32::from_le_bytes([MAC[0], MAC[1], MAC[2], MAC[3]]), u16::from_le_bytes([MAC[4], MAC[5]])));
    let link = NicDriver::link(&nic);
    assert!(link.up() && link.speed() == 2500, "link {:#x}", link.0);
    {
        let phy = s.phy.lock().unwrap();
        let p = |a: usize| phy[a / 2];
        assert_eq!((p(0xbc34), p(0xbc36), p(0xa420), p(0xa422)), (0x1234, 0x1235, 0, 0xbeef), "firmware program");
        assert_eq!(p(0xa5d4) & 0x1180, 0x0080, "2.5G advertised, 5G and 10G not");
        assert_eq!(p(0xa408), 0x0de1, "10/100 and pause advertised");
        assert_eq!(p(0xa412) & 0x0300, 0x0200, "1000 full advertised");
        assert_ne!(p(0xa400) & 0x1000, 0, "autonegotiation on");
        assert_eq!(p(0xa430) & 1 << 2, 0, "ALDPS off");
        assert_ne!(p(0xa442) & 1 << 11, 0, "10M on");
        assert_eq!((p(0xb87c), p(0xb87e)), (0x8551, 0x080e), "rtl8125_phy_param, a masked one last");
    }
    let rx_config = r32(bar + 0x44);
    assert_eq!(rx_config & 0x3f, 0x0f, "every frame, no error frames");
    assert_eq!(rx_config & 3 << 22, 0, "VLAN tags kept");
    assert_ne!(r16(bar + 0xe0) & 1 << 5, 0, "RX checksums");
    assert_eq!(r32(bar + 0x38), 3, "RX causes on, TX ones off");
    assert_eq!(r8(bar + 0x37) & 0x0c, 0x0c, "RX and TX on");
    let o = nic.offer();
    assert_eq!((o.tx_gso_mask, o.tx_gso_max, o.tx_mss_min, o.tx_mss_max), (1 << 1 | 1 << 4, 64000, 1000, 2047));
    let mut rig = Rig { nic, s: s.clone() };

    // ---- receive: 1200 frames, twice round the ring and more.
    let mut lcg = Lcg(1);
    let mut want = Vec::new();
    {
        let mut q = s.rx.lock().unwrap();
        for i in 0..1200usize {
            let len = 14 + lcg.next() as usize % 1501;
            let f = lcg.bytes(len);
            let (status, keep, valid) = match i {
                _ if i % 97 == 5 => (FS | LS | 1 << 21, false, false),
                _ if i % 50 == 3 => (FS, false, false),
                _ if i % 50 == 4 => (LS, false, false),
                _ if i % 11 == 0 => (FS | LS | 1 << 17 | 1 << 14, true, false),
                _ if i % 7 == 0 => (FS | LS | 1 << 17, true, true),
                _ if i % 13 == 0 => (FS | LS | 1 << 18, true, true),
                _ => (FS | LS, true, false),
            };
            if keep {
                want.push((f.clone(), valid));
            }
            q.push_back((f, status));
        }
    }
    let mut got = Vec::new();
    let mut buf = vec![0u8; l4h_host::net::MAX_FRAME];
    let end = Instant::now() + Duration::from_secs(10);
    while got.len() < want.len() && Instant::now() < end {
        rig.nic.rx_begin();
        loop {
            let mut h = [0u8; HDR];
            while let Some(n) = rig.nic.receive(&mut buf, &mut h) {
                got.push((buf[..n].to_vec(), h[0] & offload::F_DATA_VALID != 0));
            }
            if rig.nic.rx_done() {
                break;
            }
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    assert_eq!(got.len(), want.len(), "frames received");
    for (i, (g, w)) in got.iter().zip(&want).enumerate() {
        assert!(g == w, "received frame {i}: {} bytes valid {}, want {} bytes valid {}", g.0.len(), g.1, w.0.len(), w.1);
    }

    // ---- transmit: 3000 frames of every length, round the ring and the
    // area many times.  Frames shorter than ETH_ZLEN are padded.
    let mut frames = Vec::new();
    for _ in 0..3000 {
        let len = 14 + lcg.next() as usize % 1501;
        let mut f = lcg.bytes(len);
        // Not IP (no UDP padding quirk).
        f[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        rig.send(&f, &[0; HDR]);
        frames.push(f);
    }
    let tx = rig.sent(frames.len());
    for (i, (t, f)) in tx.iter().zip(&frames).enumerate() {
        assert!(t.frame == padded(f, 60), "frame {i} of {} bytes", f.len());
        assert_eq!((t.opts1 & 0x0ffe_0000, t.opts2), (0, 0), "frame {i}: no offload bits");
    }

    // A short UDP packet to the PTP event port: padded by
    // rtl8125_quirk_udp_padto, to 47 bytes after the UDP header's start.
    let mut udp = vec![0u8; 8 + 10];
    udp[0..2].copy_from_slice(&319u16.to_be_bytes());
    udp[2..4].copy_from_slice(&319u16.to_be_bytes());
    udp[4..6].copy_from_slice(&18u16.to_be_bytes());
    let c = !fold(csum(pseudo(SRC, DST, 17, 18), &udp));
    udp[6..8].copy_from_slice(&c.to_be_bytes());
    let f = ipv4(PEER, MAC, SRC, DST, 17, &udp);
    rig.send(&f, &[0; HDR]);
    let t = rig.sent(1);
    assert!(t[0].frame == padded(&f, f.len() + 47 - 18), "PTP padding: {} bytes", t[0].frame.len());

    // Checksums left to the driver (NEEDS_CSUM), TCP and UDP.
    let (mut f, _) = tcp4(&lcg.bytes(1000), 0);
    f[50..52].copy_from_slice(&fold(pseudo(SRC, DST, 6, 1020)).to_be_bytes());
    let mut h = [0u8; HDR];
    h[0] = offload::F_NEEDS_CSUM;
    h[6..8].copy_from_slice(&34u16.to_le_bytes());
    h[8..10].copy_from_slice(&16u16.to_le_bytes());
    rig.send(&f, &h);
    let mut udp = vec![0u8; 8 + 200];
    udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
    udp[2..4].copy_from_slice(&53u16.to_be_bytes());
    udp[4..6].copy_from_slice(&208u16.to_be_bytes());
    udp[6..8].copy_from_slice(&fold(pseudo(SRC, DST, 17, 208)).to_be_bytes());
    let fu = ipv4(PEER, MAC, SRC, DST, 17, &udp);
    h[8..10].copy_from_slice(&6u16.to_le_bytes());
    rig.send(&fu, &h);
    let t = rig.sent(2);
    assert!(l4_ok(&t[0].frame, 14) && l4_ok(&t[1].frame, 14), "checksums completed");
    assert_eq!((t[0].opts2, t[1].opts2), (0, 0));

    // TSO, IPv4: the frame as it came, GTSENV4 and the TCP offset, the MSS.
    let (f4, h4) = tcp4(&lcg.bytes(59000), 1448);
    rig.send(&f4, &h4);
    // IPv6: no payload length, and the pseudo-header sum without it.
    let (f6, h6) = tcp6_gso(&lcg.bytes(30000), 1428);
    rig.send(&f6, &h6);
    let t = rig.sent(2);
    assert!(t[0].frame == f4, "TSO IPv4 frame unchanged");
    assert_eq!(t[0].opts1 & 0x0ffe_0000, 1 << 26 | 34 << 18);
    assert_eq!(t[0].opts2, 1448 << 18);
    let mut want6 = f6.clone();
    want6[18..20].fill(0);
    let s6 = fold(csum(6, &f6[22..54]));
    want6[70..72].copy_from_slice(&s6.to_be_bytes());
    assert!(t[1].frame == want6, "TSO IPv6 prepared as tcp_v6_gso_csum_prep");
    assert_eq!(t[1].opts1 & 0x0ffe_0000, 1 << 25 | 54 << 18);
    assert_eq!(t[1].opts2, 1428 << 18);

    // A tagged GSO frame: segmented in the driver, every segment whole.
    let payload = lcg.bytes(20000);
    let (f, _) = tcp4(&payload, 1448);
    let mut tagged = f[..12].to_vec();
    tagged.extend_from_slice(&[0x81, 0x00, 0x00, 0x05]);
    tagged.extend_from_slice(&f[12..]);
    rig.send(&tagged, &gso_hdr(offload::GSO_TCPV4, 58, 1448, 38));
    let segs = 20000usize.div_ceil(1448);
    let t = rig.sent(segs);
    let mut data = Vec::new();
    for (i, seg) in t.iter().enumerate() {
        let g = &seg.frame;
        assert_eq!(&g[12..16], &[0x81, 0, 0, 5], "segment {i} keeps its tag");
        assert!(l4_ok(g, 18), "segment {i} checksums");
        let seq = u32::from_be_bytes(g[42..46].try_into().unwrap());
        assert_eq!(seq, 1000 + (i * 1448) as u32, "segment {i} sequence");
        data.extend_from_slice(&g[58..]);
    }
    assert!(data == payload, "segments carry the payload");

    // An ECN GSO frame is segmented here too; a plain frame past the MTU
    // is dropped (the next frame is the first on the wire).
    let payload = lcg.bytes(5000);
    let (mut f, mut h) = tcp4(&payload, 1448);
    f[47] |= 0x80;
    h[1] |= offload::GSO_ECN;
    rig.send(&f, &h);
    rig.send(&padded(&[0x55; 14], 1519), &[0; HDR]);
    rig.send(&padded(&[0x55; 14], 1518), &[0; HDR]);
    let t = rig.sent(5000usize.div_ceil(1448) + 1);
    for (i, seg) in t[..t.len() - 1].iter().enumerate() {
        assert_eq!((seg.opts1 & 0x0ffe_0000, seg.frame[47] & 0x80 != 0), (0, i == 0), "ECN segment {i}: CWR on the first only");
        assert!(l4_ok(&seg.frame, 14), "ECN segment {i} checksums");
    }
    assert_eq!(t.last().unwrap().frame.len(), 1518);

    // ---- limits: a held chip fills the ring (256 frames), then the area
    // (1 MiB: 15 or 16 frames of 60000 bytes, as the wrap falls).
    for (len, gso, lo, hi) in [(1500usize, false, 256usize, 256usize), (59000, true, 15, 16)] {
        s.hold.store(true, Ordering::Relaxed);
        let (f, h) = if gso { tcp4(&lcg.bytes(len), 1448) } else { (padded(&[0x55; 14], len), [0; HDR]) };
        let mut n = 0;
        while rig.nic.transmit(&f, &h) {
            n += 1;
            assert!(n <= hi, "more queued than fits");
        }
        rig.nic.kick_tx();
        assert!((lo..=hi).contains(&n), "{n} frames of {len} bytes queued");
        assert!(!rig.nic.tx_interrupts(true), "nothing completed yet");
        s.hold.store(false, Ordering::Relaxed);
        rig.sent(n);
        assert!(rig.nic.tx_interrupts(true), "completions seen");
        rig.nic.tx_interrupts(false);
        rig.send(&f, &h);
        rig.sent(1);
    }

    rig.nic.stop();
    s.stop.store(true, Ordering::Relaxed);
    chip_thread.join().unwrap();
}
