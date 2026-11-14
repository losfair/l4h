//! Tests of netd's L3 source filter (host/l4h-netd/src/ipfilter.rs,
//! compiled here unchanged).
//!
//! - Unit tests: each rule of the filter, its exceptions and its guards.
//! - Prefixes from the control ABI's words are accepted exactly when a
//!   plain model says they are canonical.
//! - Generated frames, mutated and truncated, never panic (no read past
//!   the frame), and the filter never passes a frame that is not IPv4,
//!   IPv6 or ARP, whose source is neither allowed nor unspecified, or
//!   that a router or DHCP server sends; a frame it calls spoofed has a
//!   source it does not allow.
//! - Frames go the way netd takes them, with random offload metadata
//!   (l4h-netcore's sanitize, then the checksum completed for a filtered
//!   port): whatever later ports and devices do with the metadata
//!   (complete the checksum, segment) leaves the verdict as it was.

#![allow(dead_code)]

#[path = "../../../host/l4h-netd/src/ipfilter.rs"]
mod ipfilter;

use ipfilter::{Filter, MAX_PREFIXES, Prefix, Verdict, check};
use l4h_netcore::offload::{self, F_NEEDS_CSUM, GSO_TCPV4, GSO_TCPV6, HDR_SIZE};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
    fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(v.len() as u64) as usize]
    }
}

const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const OTHER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];

fn v4(a: [u8; 4]) -> [u8; 16] {
    let mut ip = [0; 16];
    ip[12..].copy_from_slice(&a);
    ip
}

fn v6(last: u8) -> [u8; 16] {
    let mut ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    ip[15] = last;
    ip
}

fn prefix4(a: [u8; 4], len: u8) -> Prefix {
    let w = u32::from_be_bytes(a) as u64;
    Prefix::from_words(4 | (len as u64) << 8, 0, w).expect("canonical")
}

fn prefix6(ip: [u8; 16], len: u8) -> Prefix {
    let hi = u64::from_be_bytes(ip[..8].try_into().unwrap());
    let lo = u64::from_be_bytes(ip[8..].try_into().unwrap());
    Prefix::from_words(6 | (len as u64) << 8, hi, lo).expect("canonical")
}

/// The test port's filter: 10.0.0.5, 10.1.0.0/16, 2001:db8::5 and
/// 2001:db8:1::/48.
fn filter() -> Filter {
    let mut f = Filter { on: true, ..Filter::OFF };
    f.set(0, prefix4([10, 0, 0, 5], 32));
    f.set(1, prefix4([10, 1, 0, 0], 16));
    f.set(2, prefix6(v6(5), 128));
    let mut net = v6(0);
    net[5] = 1;
    f.set(5, prefix6(net, 48));
    f
}

fn eth(src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0xff; 6];
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// An IPv4 packet from `src`: protocol `proto`, fragment offset `frag`
/// (in 8 bytes), `l4` after `opts` bytes of options.
fn ip4(src: [u8; 4], proto: u8, frag: u16, opts: usize, l4: &[u8]) -> Vec<u8> {
    let ihl = 20 + opts;
    let mut p = vec![0u8; ihl];
    p[0] = 0x40 | (ihl / 4) as u8;
    p[2..4].copy_from_slice(&((ihl + l4.len()) as u16).to_be_bytes());
    p[6..8].copy_from_slice(&frag.to_be_bytes());
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&[10, 0, 0, 1]);
    p.extend_from_slice(l4);
    p
}

fn udp(sport: u16, dport: u16) -> Vec<u8> {
    let mut u = vec![0u8; 8];
    u[..2].copy_from_slice(&sport.to_be_bytes());
    u[2..4].copy_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(b"payload");
    u
}

/// A DHCP client's message from UDP port `sport` to a server, for `mac`.
fn dhcp(sport: u16, mac: [u8; 6]) -> Vec<u8> {
    let mut u = udp(sport, 67);
    u.truncate(8);
    let mut m = vec![0u8; 240];
    m[..3].copy_from_slice(&[1, 1, 6]);
    m[28..34].copy_from_slice(&mac);
    m[236..240].copy_from_slice(&[99, 130, 83, 99]);
    u.extend(m);
    u
}

/// A TCP header and `n` bytes of payload.
fn tcp(n: usize) -> Vec<u8> {
    let mut t = vec![0u8; 20 + n];
    t[..4].copy_from_slice(&[0x1f, 0x90, 0xc0, 0x00]);
    t[12] = 0x50;
    t
}

fn icmp(kind: u8) -> Vec<u8> {
    vec![kind, 0, 0, 0, 0, 0, 0, 0]
}

/// An IPv6 extension header: `nh` next, `len` bytes in all.
fn ext(nh: u8, len: usize) -> Vec<u8> {
    let mut h = vec![0u8; len];
    h[0] = nh;
    h[1] = (len / 8 - 1) as u8;
    h
}

/// An IPv6 packet from `src`, its first header `nh`, then `rest` (its
/// extension headers and payload).
fn ip6(src: [u8; 16], nh: u8, rest: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(rest.len() as u16).to_be_bytes());
    p[6] = nh;
    p[7] = 255;
    p[8..24].copy_from_slice(&src);
    p[24] = 0xff;
    p[25] = 0x02;
    p[39] = 1;
    p.extend_from_slice(rest);
    p
}

fn frag6(nh: u8, offset: u16) -> Vec<u8> {
    let mut h = vec![nh, 0, 0, 0, 0, 0, 0, 1];
    h[2..4].copy_from_slice(&(offset << 3).to_be_bytes());
    h
}

/// A Neighbor Discovery message of `kind` about `target`, with a
/// link-layer address option of type `opt` for `mac` (none if `opt` 0).
fn nd(kind: u8, target: [u8; 16], opt: u8, mac: [u8; 6]) -> Vec<u8> {
    let mut m = vec![kind, 0, 0, 0, 0, 0, 0, 0];
    if kind != 133 {
        m.extend_from_slice(&target);
    }
    if opt != 0 {
        m.extend_from_slice(&[opt, 1]);
        m.extend_from_slice(&mac);
    }
    m
}

fn arp(sha: [u8; 6], spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0, 1, 8, 0, 6, 4, 0, 1];
    p.extend_from_slice(&sha);
    p.extend_from_slice(&spa);
    p.extend_from_slice(&[0; 6]);
    p.extend_from_slice(&tpa);
    p
}

fn v4_frame(src: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    eth(MAC, 0x0800, &ip4(src, proto, 0, 0, l4))
}

fn v6_frame(src: [u8; 16], nh: u8, rest: &[u8]) -> Vec<u8> {
    eth(MAC, 0x86dd, &ip6(src, nh, rest))
}

// --- The randomised part.

/// Whether the 16 bytes of the frame's IP source (or ARP sender) are
/// allowed by `f` or unspecified.
fn source_ok(f: &Filter, v6: bool, ip: &[u8; 16]) -> bool {
    *ip == [0; 16] || f.prefixes.iter().flatten().any(|p| p.v6 == v6 && covers(p, ip))
}

/// A plain model of prefix containment.
fn covers(p: &Prefix, ip: &[u8; 16]) -> bool {
    let (a, b) = (u128::from_be_bytes(p.ip), u128::from_be_bytes(*ip));
    let bits = if p.v6 { p.len as u32 } else { 96 + p.len as u32 };
    let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
    a & mask == b & mask
}

/// The model of a canonical prefix in the ABI's words.
fn canonical(m: u64, hi: u64, lo: u64) -> bool {
    let (family, len) = (m as u8, (m >> 8) as u8 as u32);
    let ip = (hi as u128) << 64 | lo as u128;
    let bits = match family {
        4 if ip >> 32 == 0 => 32,
        6 => 128,
        _ => return false,
    };
    m >> 16 == 0 && len <= bits && (0..bits - len).all(|i| ip >> i & 1 == 0)
}

fn random_prefix(rng: &mut Rng) -> Prefix {
    if rng.chance(50) {
        let a = [10, rng.below(3) as u8, rng.below(3) as u8, rng.below(8) as u8];
        let len = rng.pick(&[8, 16, 24, 30, 32]);
        let w = u32::from_be_bytes(a) as u64;
        let w = if len == 32 { w } else { w & !((1u64 << (32 - len)) - 1) };
        Prefix::from_words(4 | (len as u64) << 8, 0, w).unwrap()
    } else {
        let mut ip = v6(rng.below(8) as u8);
        ip[5] = rng.below(3) as u8;
        let len = rng.pick(&[32, 48, 64, 128]);
        let v = u128::from_be_bytes(ip);
        let v = if len == 128 { v } else { v & !((1u128 << (128 - len)) - 1) };
        prefix6(v.to_be_bytes(), len)
    }
}

fn random_filter(rng: &mut Rng) -> Filter {
    let mut f = Filter { on: rng.chance(90), ..Filter::OFF };
    for slot in 0..MAX_PREFIXES {
        if rng.chance(20) {
            f.set(slot, random_prefix(rng));
        }
    }
    f
}

fn random_src4(rng: &mut Rng) -> [u8; 4] {
    match rng.below(4) {
        0 => [0, 0, 0, 0],
        _ => [10, rng.below(3) as u8, rng.below(3) as u8, rng.below(8) as u8],
    }
}

fn random_src6(rng: &mut Rng) -> [u8; 16] {
    if rng.chance(20) {
        return [0; 16];
    }
    let mut ip = v6(rng.below(8) as u8);
    ip[5] = rng.below(3) as u8;
    ip
}

/// A frame of one of the kinds the filter tells apart.
fn random_frame(rng: &mut Rng) -> Vec<u8> {
    let src = if rng.chance(90) { MAC } else { OTHER_MAC };
    match rng.below(8) {
        0 | 1 => {
            let proto = rng.pick(&[1, 6, 17, 47]);
            let l4 = match proto {
                17 if rng.chance(30) => dhcp(rng.pick(&[68, 4000]), if rng.chance(80) { src } else { OTHER_MAC }),
                17 => udp(rng.pick(&[53, 67, 68, 547, 4000]), rng.pick(&[53, 67, 68, 546])),
                1 => icmp(rng.pick(&[0, 3, 5, 8, 9])),
                6 => tcp(rng.pick(&[0, 100, 3000])),
                _ => vec![0; 20],
            };
            // Offset, and sometimes more fragments.
            let off = if rng.chance(20) { rng.below(100) as u16 } else { 0 };
            let frag = off | if rng.chance(10) { 0x2000 } else { 0 };
            eth(src, 0x0800, &ip4(random_src4(rng), proto, frag, 4 * rng.below(3) as usize, &l4))
        }
        2 => {
            let spa = random_src4(rng);
            let sha = if rng.chance(90) { src } else { OTHER_MAC };
            eth(src, 0x0806, &arp(sha, spa, [10, 0, 0, 1]))
        }
        3..=6 => {
            let mut rest = Vec::new();
            let mut nhs = Vec::new();
            for _ in 0..rng.below(4) {
                nhs.push(rng.pick(&[0, 43, 44, 51, 60]));
            }
            let upper = rng.pick(&[6, 17, 58, 58, 58]);
            let payload = match upper {
                6 => tcp(rng.pick(&[0, 100, 3000])),
                17 => udp(rng.pick(&[546, 547, 4000]), rng.pick(&[546, 547])),
                58 => {
                    let kind = rng.pick(&[128, 131, 133, 134, 135, 136, 137, 138, 143]);
                    let target = random_src6(rng);
                    let opt = rng.pick(&[0, 1, 2]);
                    nd(kind, target, opt, if rng.chance(90) { src } else { OTHER_MAC })
                }
                _ => vec![0; 20],
            };
            let first = nhs.first().copied().unwrap_or(upper);
            for (i, &h) in nhs.iter().enumerate() {
                let next = nhs.get(i + 1).copied().unwrap_or(upper);
                match h {
                    44 => rest.extend(frag6(next, if rng.chance(30) { rng.below(50) as u16 } else { 0 })),
                    51 => {
                        let mut a = vec![0u8; 16];
                        a[0] = next;
                        a[1] = 2;
                        rest.extend(a);
                    }
                    _ => rest.extend(ext(next, 8 * (1 + rng.below(2) as usize))),
                }
            }
            rest.extend(payload);
            eth(src, 0x86dd, &ip6(random_src6(rng), first, &rest))
        }
        _ => {
            let t = rng.pick(&[0x8100, 0x88a8, 0x88cc, 0x8863, 0x1234]);
            eth(src, t, &ip4(random_src4(rng), 17, 0, 0, &dhcp(68, src)))
        }
    }
}

/// Damage a frame: flip bytes, cut it short, or grow it.
fn mutate(rng: &mut Rng, f: &mut Vec<u8>) {
    for _ in 0..rng.below(4) {
        match rng.below(3) {
            0 if !f.is_empty() => {
                let i = rng.below(f.len() as u64) as usize;
                f[i] = rng.next() as u8;
            }
            1 => f.truncate(rng.below(f.len() as u64 + 1) as usize),
            _ => f.push(rng.next() as u8),
        }
    }
}

/// What the filter may say of `frame`, by the properties it guarantees.
fn check_properties(f: &Filter, frame: &[u8]) -> Verdict {
    let v = check(f, frame);
    if !f.on {
        assert_eq!(v, Verdict::Pass);
        return v;
    }
    if v == Verdict::Denied {
        return v;
    }
    assert!(frame.len() >= 14);
    let (is_v6, ip): (bool, [u8; 16]) = match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0800 => (false, v4(frame[26..30].try_into().unwrap())),
        0x86dd => (true, frame[22..38].try_into().unwrap()),
        0x0806 => {
            assert_eq!(v, Verdict::Pass, "ARP is never spoofed: passed or denied");
            assert_eq!(frame[22..28], frame[6..12], "ARP sender MAC");
            if frame[28..32] == [0; 4] {
                assert!(source_ok(f, false, &v4(frame[38..42].try_into().unwrap())), "probe of another's address");
            }
            (false, v4(frame[28..32].try_into().unwrap()))
        }
        t => panic!("ethertype {t:#x} passed"),
    };
    assert!(!server_or_router(frame), "a router's or DHCP server's frame passed");
    match v {
        Verdict::Pass => assert!(source_ok(f, is_v6, &ip), "passed from {ip:?}"),
        Verdict::Spoofed => assert!(ip != [0; 16] && !source_ok(f, is_v6, &ip), "spoofed from {ip:?}"),
        Verdict::Denied => unreachable!(),
    }
    v
}

/// A plain model of the guards, for headers right after the IP header:
/// a router's message (advertisement, redirect, renumbering), a DHCP or
/// DHCPv6 server's, or a DHCP client's for another MAC or fragmented.
fn server_or_router(frame: &[u8]) -> bool {
    let at = |i: usize| frame.get(i).copied();
    let port = |i: usize| Some(u16::from_be_bytes([at(i)?, at(i + 1)?]));
    match port(12) {
        Some(0x0800) if at(20).map(|b| b & 0x1f) == Some(0) && at(21) == Some(0) => {
            let l4 = 14 + (at(14).unwrap_or(0) & 15) as usize * 4;
            let more = at(20).unwrap_or(0) & 0x20 != 0;
            let chaddr = (l4 + 8 + 28..l4 + 8 + 34).map(at).collect::<Option<Vec<u8>>>();
            match at(23) {
                Some(17) if port(l4 + 2) == Some(67) => more || chaddr.as_deref() != Some(&frame[6..12]),
                Some(17) => port(l4) == Some(67) || port(l4 + 2) == Some(68),
                Some(1) => matches!(at(l4), Some(5 | 9)),
                _ => false,
            }
        }
        Some(0x86dd) => match at(20) {
            Some(17) => port(54) == Some(547) || port(56) == Some(546),
            Some(58) => matches!(at(54), Some(134 | 137 | 138)),
            _ => false,
        },
        _ => false,
    }
}

/// Offload metadata a guest might send with `frame`: none, a partial
/// checksum at its L4 header or anywhere, or GSO.
fn random_hdr(rng: &mut Rng, frame: &[u8]) -> [u8; HDR_SIZE] {
    let mut h = [0u8; HDR_SIZE];
    let put = |h: &mut [u8; HDR_SIZE], i: usize, v: usize| h[i..i + 2].copy_from_slice(&(v as u16).to_le_bytes());
    match rng.below(4) {
        0 => {}
        1 => {
            h[0] = F_NEEDS_CSUM;
            put(&mut h, 6, rng.below(frame.len() as u64 + 2) as usize);
            put(&mut h, 8, rng.below(64) as usize);
        }
        _ => {
            h[0] = F_NEEDS_CSUM;
            let l4 = match frame.get(12..14) {
                Some([0x86, 0xdd]) => 54,
                _ => 14 + (frame.get(14).copied().unwrap_or(0x45) & 15) as usize * 4,
            };
            put(&mut h, 6, l4);
            put(&mut h, 8, rng.pick(&[6, 16]));
            if rng.chance(50) {
                h[1] = if frame.get(12..14) == Some(&[0x86, 0xdd]) { GSO_TCPV6 } else { GSO_TCPV4 };
                put(&mut h, 4, rng.pick(&[48, 536, 1448]));
            }
        }
    }
    h
}

/// A frame and its metadata as netd takes them from a guest port with
/// filter `f` (Netd::forward): the verdict, or None if `sanitize` drops
/// it.  The ports and devices it goes on to must see what was checked.
fn forward(f: &Filter, frame: &mut [u8], hdr: &mut [u8; HDR_SIZE]) -> Option<Verdict> {
    if frame.len() < 14 || !offload::sanitize(hdr, frame) {
        return None;
    }
    if f.on && !offload::is_gso(hdr) {
        offload::complete_csum(frame, hdr);
    }
    let v = check_properties(f, frame);
    if v == Verdict::Denied {
        return Some(v);
    }
    if offload::is_gso(hdr) {
        let mut buf = vec![0u8; 2048];
        offload::segment(frame, hdr, &mut buf, |seg, _| assert_eq!(check(f, seg), v, "a segment"));
    } else {
        let (mut g, mut gh) = (frame.to_vec(), *hdr);
        offload::complete_csum(&mut g, &mut gh);
        assert_eq!(check(f, &g), v, "after the checksum");
    }
    Some(v)
}

fn run(rng: &mut Rng, iters: u64) -> [u64; 4] {
    let mut counts = [0; 4];
    let mut filt = random_filter(rng);
    for i in 0..iters {
        if i % 64 == 0 {
            filt = random_filter(rng);
        }
        let mut frame = random_frame(rng);
        if rng.chance(50) {
            mutate(rng, &mut frame);
        }
        let v = check_properties(&filt, &frame);
        counts[v as usize] += 1;
        let mut hdr = random_hdr(rng, &frame);
        // The last count: GSO frames sanitize took.
        if forward(&filt, &mut frame, &mut hdr).is_some() && offload::is_gso(&hdr) {
            counts[3] += 1;
        }
        // Prefixes from words: canonical ones only.
        let any = rng.next();
        let w = rng.pick(&[4, 6, 4 | 32 << 8, 4 | 24 << 8, 6 | 64 << 8, 6 | 128 << 8, 4 | 33 << 8, 6 | 129 << 8, any]);
        let (hi, lo) = match rng.below(3) {
            0 => (0, rng.next() >> 32),
            1 => (rng.next(), 0),
            _ => (rng.next() & 0xffff_ffff_0000_0000, rng.next() & !0xff),
        };
        let lo = if rng.chance(30) { lo & !0xffff_ffff } else { lo };
        let p = Prefix::from_words(w, hi, lo);
        assert_eq!(p.is_some(), canonical(w, hi, lo), "{w:#x} {hi:#x} {lo:#x}");
    }
    counts
}

fn main() {
    let iters = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(200_000);
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64 | 1;
    let mut rng = Rng(seed);
    let [pass, spoofed, denied, gso] = run(&mut rng, iters);
    println!("fuzz-ipfilter: {iters} frames (seed {seed:#x}): {pass} passed, {spoofed} spoofed, {denied} denied, {gso} GSO");
}

#[cfg(test)]
mod tests {
    use super::*;
    use Verdict::*;

    #[test]
    fn off_passes_everything() {
        let f = Filter::OFF;
        assert_eq!(check(&f, &eth(MAC, 0x88cc, &[0; 40])), Pass);
        assert_eq!(check(&f, &v4_frame([192, 168, 9, 9], 17, &udp(67, 68))), Pass);
    }

    #[test]
    fn ipv4_sources() {
        let f = filter();
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 6, &[0; 20])), Pass);
        assert_eq!(check(&f, &v4_frame([10, 1, 200, 7], 6, &[0; 20])), Pass);
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 6], 6, &[0; 20])), Spoofed);
        assert_eq!(check(&f, &v4_frame([10, 2, 0, 1], 1, &icmp(8))), Spoofed);
        // A filter with no prefixes allows nothing but the exceptions.
        let none = Filter { on: true, ..Filter::OFF };
        assert_eq!(check(&none, &v4_frame([10, 0, 0, 5], 6, &[0; 20])), Spoofed);
        assert_eq!(check(&none, &v4_frame([0, 0, 0, 0], 17, &dhcp(68, MAC))), Pass);
    }

    #[test]
    fn ipv4_unspecified_is_dhcp_only() {
        let f = filter();
        assert_eq!(check(&f, &v4_frame([0, 0, 0, 0], 17, &dhcp(68, MAC))), Pass);
        assert_eq!(check(&f, &v4_frame([0, 0, 0, 0], 17, &udp(68, 53))), Denied);
        assert_eq!(check(&f, &v4_frame([0, 0, 0, 0], 1, &icmp(8))), Denied);
        // Not a first fragment: no ports to show it is DHCP.
        assert_eq!(check(&f, &eth(MAC, 0x0800, &ip4([0, 0, 0, 0], 17, 4, 0, &dhcp(68, MAC)))), Denied);
    }

    #[test]
    fn ipv4_guards() {
        let f = filter();
        // A DHCP server's reply and a redirect, from an allowed address.
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 17, &udp(67, 68))), Denied);
        // Clients take a reply to their port from any port.
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 17, &udp(1234, 68))), Denied);
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 17, &udp(1234, 53))), Pass);
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 1, &icmp(5))), Denied);
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 1, &icmp(9))), Denied);
        // A client's message for its own MAC, from any port; not for
        // another's (a release or decline of its lease), not fragmented,
        // not a bare UDP datagram.
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 17, &dhcp(68, MAC))), Pass);
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 17, &dhcp(4000, MAC))), Pass);
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 17, &dhcp(68, OTHER_MAC))), Denied);
        assert_eq!(check(&f, &v4_frame([0, 0, 0, 0], 17, &dhcp(68, OTHER_MAC))), Denied);
        assert_eq!(check(&f, &eth(MAC, 0x0800, &ip4([10, 0, 0, 5], 17, 0x2000, 0, &dhcp(68, MAC)))), Denied);
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 17, &udp(68, 67))), Denied);
        let mut reply = dhcp(68, MAC);
        reply[8] = 2;
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 17, &reply)), Denied);
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 1, &icmp(0))), Pass);
        // A later fragment's bytes are payload, not a header.
        assert_eq!(check(&f, &eth(MAC, 0x0800, &ip4([10, 0, 0, 5], 17, 9, 0, &udp(67, 68)))), Pass);
        // With options, the header is found past them.
        assert_eq!(check(&f, &eth(MAC, 0x0800, &ip4([10, 0, 0, 5], 17, 0, 8, &udp(67, 68)))), Denied);
        // A first fragment too short for the UDP ports.
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 17, &[0, 67])), Denied);
    }

    #[test]
    fn ipv4_malformed() {
        let f = filter();
        let good = v4_frame([10, 0, 0, 5], 6, &[0; 20]);
        assert_eq!(check(&f, &good[..14 + 19]), Denied);
        let mut bad_ihl = good.clone();
        bad_ihl[14] = 0x44;
        assert_eq!(check(&f, &bad_ihl), Denied);
        let mut long_ihl = good.clone();
        long_ihl[14] = 0x4f;
        assert_eq!(check(&f, &long_ihl[..14 + 40]), Denied);
        let mut v6_in_v4 = good;
        v6_in_v4[14] = 0x65;
        assert_eq!(check(&f, &v6_in_v4), Denied);
    }

    #[test]
    fn arp() {
        let f = filter();
        assert_eq!(check(&f, &eth(MAC, 0x0806, &super::arp(MAC, [10, 0, 0, 5], [10, 0, 0, 1]))), Pass);
        // An RFC 5227 probe, of its own address only: the owner of another
        // would give it up.
        assert_eq!(check(&f, &eth(MAC, 0x0806, &super::arp(MAC, [0, 0, 0, 0], [10, 0, 0, 5]))), Pass);
        assert_eq!(check(&f, &eth(MAC, 0x0806, &super::arp(MAC, [0, 0, 0, 0], [10, 0, 0, 1]))), Denied);
        // Another's address, or another's MAC.
        assert_eq!(check(&f, &eth(MAC, 0x0806, &super::arp(MAC, [10, 0, 0, 1], [10, 0, 0, 2]))), Denied);
        assert_eq!(check(&f, &eth(MAC, 0x0806, &super::arp(OTHER_MAC, [10, 0, 0, 5], [10, 0, 0, 1]))), Denied);
        // Not Ethernet over IPv4, or cut short.
        let mut p = super::arp(MAC, [10, 0, 0, 5], [10, 0, 0, 1]);
        p[1] = 6;
        assert_eq!(check(&f, &eth(MAC, 0x0806, &p)), Denied);
        let p = super::arp(MAC, [10, 0, 0, 5], [10, 0, 0, 1]);
        assert_eq!(check(&f, &eth(MAC, 0x0806, &p[..27])), Denied);
    }

    #[test]
    fn other_ethertypes() {
        let f = filter();
        let ip = ip4([10, 0, 0, 5], 6, 0, 0, &[0; 20]);
        for t in [0x8100, 0x88a8, 0x88cc, 0x8863, 0x8847, 0x0842] {
            // A VLAN tag would carry IP past the checks.
            let mut tagged = vec![0, 5, 0x08, 0x00];
            tagged.extend_from_slice(&ip);
            assert_eq!(check(&f, &eth(MAC, t, &tagged)), Denied, "{t:#x}");
        }
        assert_eq!(check(&f, &eth(MAC, 0x0800, &[])), Denied);
        assert_eq!(check(&f, &[0; 13]), Denied);
    }

    #[test]
    fn ipv6_sources() {
        let f = filter();
        assert_eq!(check(&f, &v6_frame(v6(5), 6, &[0; 20])), Pass);
        let mut in_net = v6(9);
        in_net[5] = 1;
        assert_eq!(check(&f, &v6_frame(in_net, 6, &[0; 20])), Pass);
        assert_eq!(check(&f, &v6_frame(v6(6), 6, &[0; 20])), Spoofed);
        assert_eq!(check(&f, &v6_frame(v6(6), 58, &icmp(128))), Spoofed);
        // An IPv4-mapped address is IPv6, not 10.0.0.5.
        let mut mapped = [0u8; 16];
        mapped[10..12].copy_from_slice(&[0xff, 0xff]);
        mapped[12..].copy_from_slice(&[10, 0, 0, 5]);
        assert_eq!(check(&f, &v6_frame(mapped, 6, &[0; 20])), Spoofed);
    }

    #[test]
    fn ipv6_unspecified() {
        let f = filter();
        // Duplicate address detection, router solicitation, MLD reports
        // (behind a hop-by-hop header).
        assert_eq!(check(&f, &v6_frame([0; 16], 58, &nd(135, v6(5), 0, MAC))), Pass);
        // Duplicate address detection of another's address fails its DAD.
        assert_eq!(check(&f, &v6_frame([0; 16], 58, &nd(135, v6(1), 0, MAC))), Denied);
        assert_eq!(check(&f, &v6_frame([0; 16], 58, &nd(133, [0; 16], 0, MAC))), Pass);
        let mut mld = ext(58, 8);
        mld.extend_from_slice(&icmp(143));
        assert_eq!(check(&f, &v6_frame([0; 16], 0, &mld)), Pass);
        // Nothing else.
        assert_eq!(check(&f, &v6_frame([0; 16], 58, &icmp(128))), Denied);
        assert_eq!(check(&f, &v6_frame([0; 16], 17, &udp(546, 547))), Denied);
        assert_eq!(check(&f, &v6_frame([0; 16], 58, &nd(136, v6(5), 0, MAC))), Denied);
        // Nor fragmented.
        let mut fr = frag6(58, 0);
        fr.extend_from_slice(&nd(135, v6(5), 0, MAC));
        assert_eq!(check(&f, &v6_frame([0; 16], 44, &fr)), Denied);
    }

    #[test]
    fn ipv6_router_and_dhcp_guards() {
        let f = filter();
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &icmp(134))), Denied);
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &nd(137, v6(1), 0, MAC))), Denied);
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &icmp(138))), Denied);
        assert_eq!(check(&f, &v6_frame(v6(5), 17, &udp(547, 546))), Denied);
        assert_eq!(check(&f, &v6_frame(v6(5), 17, &udp(1234, 546))), Denied);
        assert_eq!(check(&f, &v6_frame(v6(5), 17, &udp(546, 547))), Pass);
        // Behind extension headers, and in a first fragment.
        let mut hidden = ext(60, 16);
        hidden.extend(ext(43, 8));
        hidden[16] = 44;
        hidden.extend(frag6(58, 0));
        hidden.extend(icmp(134));
        assert_eq!(check(&f, &v6_frame(v6(5), 0, &hidden)), Denied);
        // A later fragment is payload, its source still checked.
        let mut later = frag6(58, 3);
        later.extend(icmp(134));
        assert_eq!(check(&f, &v6_frame(v6(5), 44, &later)), Pass);
        assert_eq!(check(&f, &v6_frame(v6(6), 44, &later)), Spoofed);
    }

    #[test]
    fn ipv6_header_chains() {
        let f = filter();
        // A chain cut short of the upper-layer header, an AH, too many
        // headers, two fragment headers.
        let mut cut = ext(58, 16);
        cut.truncate(12);
        assert_eq!(check(&f, &v6_frame(v6(5), 60, &cut)), Denied);
        let mut ah = vec![58, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        ah.extend(icmp(134));
        assert_eq!(check(&f, &v6_frame(v6(5), 51, &ah)), Denied);
        let mut long = Vec::new();
        for i in 0..8 {
            long.extend(ext(if i == 7 { 58 } else { 60 }, 8));
        }
        long.extend(icmp(128));
        assert_eq!(check(&f, &v6_frame(v6(5), 60, &long)), Pass);
        let mut longer = ext(60, 8);
        longer.extend(&long);
        assert_eq!(check(&f, &v6_frame(v6(5), 60, &longer)), Denied);
        let mut two = frag6(44, 0);
        two.extend(frag6(6, 0));
        assert_eq!(check(&f, &v6_frame(v6(5), 44, &two)), Denied);
        // The upper-layer header itself missing.
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &[])), Denied);
        assert_eq!(check(&f, &v6_frame(v6(5), 17, &[0, 0])), Denied);
    }

    #[test]
    fn neighbor_discovery() {
        let f = filter();
        // Advertising its own address, with its own MAC.
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &nd(136, v6(5), 2, MAC))), Pass);
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &nd(136, v6(5), 0, MAC))), Pass);
        // Another's address, or another MAC in an option.
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &nd(136, v6(1), 2, MAC))), Denied);
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &nd(136, v6(5), 2, OTHER_MAC))), Denied);
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &nd(135, v6(1), 1, OTHER_MAC))), Denied);
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &nd(135, v6(1), 1, MAC))), Pass);
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &nd(133, [0; 16], 1, OTHER_MAC))), Denied);
        // Malformed options: zero length, past the end, a long address.
        let mut zero = nd(135, v6(1), 1, MAC);
        zero[25] = 0;
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &zero)), Denied);
        let mut past = nd(135, v6(1), 1, MAC);
        past[25] = 2;
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &past)), Denied);
        let mut long = nd(135, v6(1), 1, MAC);
        long[25] = 2;
        long.extend_from_slice(&[0; 8]);
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &long)), Denied);
        // Other options are skipped.
        let mut nonce = nd(135, v6(1), 1, MAC);
        nonce.extend_from_slice(&[14, 1, 1, 2, 3, 4, 5, 6]);
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &nonce)), Pass);
        // Fragmented (RFC 6980): a later fragment's options go unchecked.
        for kind in [133, 135, 136] {
            let mut fr = frag6(58, 0);
            fr[3] |= 1;
            fr.extend(nd(kind, v6(5), 0, MAC));
            assert_eq!(check(&f, &v6_frame(v6(5), 44, &fr)), Denied, "{kind}");
        }
        // Cut short of the target.
        assert_eq!(check(&f, &v6_frame(v6(5), 58, &nd(136, v6(5), 0, MAC)[..20])), Denied);
    }

    #[test]
    fn prefixes() {
        assert!(Prefix::from_words(4 | 24 << 8, 0, 0x0a00_0000).is_some());
        assert!(Prefix::from_words(4 | 24 << 8, 0, 0x0a00_0001).is_none());
        assert!(Prefix::from_words(4 | 33 << 8, 0, 0x0a00_0001).is_none());
        assert!(Prefix::from_words(4 | 32 << 8, 1, 0x0a00_0001).is_none());
        assert!(Prefix::from_words(4 | 32 << 8, 0, 1 << 32).is_none());
        assert!(Prefix::from_words(4, 0, 0).is_some());
        assert!(Prefix::from_words(6, 0, 0).is_some());
        assert!(Prefix::from_words(6, 0, 1).is_none());
        assert!(Prefix::from_words(6 | 128 << 8, u64::MAX, u64::MAX).is_some());
        assert!(Prefix::from_words(6 | 129 << 8, 0, 0).is_none());
        assert!(Prefix::from_words(5 | 8 << 8, 0, 0).is_none());
        assert!(Prefix::from_words(4 | 1 << 16, 0, 0).is_none());
        // /0 allows every address of its family.
        let mut any = Filter { on: true, ..Filter::OFF };
        any.set(0, Prefix::from_words(4, 0, 0).unwrap());
        assert_eq!(check(&any, &v4_frame([192, 168, 1, 1], 6, &[0; 20])), Pass);
        assert_eq!(check(&any, &v6_frame(v6(1), 6, &[0; 20])), Spoofed);
        // Slots past the table are refused; deleting one forgets it.
        let mut f = filter();
        assert!(!f.set(MAX_PREFIXES, prefix4([10, 0, 0, 9], 32)));
        f.del(0);
        assert_eq!(check(&f, &v4_frame([10, 0, 0, 5], 6, &[0; 20])), Spoofed);
    }

    /// A partial checksum aimed at the IPv4 source would rewrite it after
    /// the check (to 10.0.0.9, with the padding chosen): netd completes it
    /// first, so the filter sees what leaves, and sanitize keeps it out of
    /// the Ethernet header.
    #[test]
    fn checksum_offsets_cannot_rewrite_what_was_checked() {
        let f = filter();
        let mut frame = v4_frame([10, 0, 0, 5], 6, &tcp(0));
        frame.extend_from_slice(&[0; 2]);
        let mut hdr = [0u8; HDR_SIZE];
        hdr[0] = F_NEEDS_CSUM;
        hdr[6..8].copy_from_slice(&28u16.to_le_bytes());
        // Pick the padding so that the checksum written at 28 says 00 09.
        let at = frame.len() - 2;
        for pad in 0..=u16::MAX {
            frame[at..].copy_from_slice(&pad.to_be_bytes());
            let (mut g, mut gh) = (frame.clone(), hdr);
            offload::complete_csum(&mut g, &mut gh);
            if g[28..30] == [0, 9] {
                break;
            }
        }
        // Completed in a later place, the frame would leave as 10.0.0.9.
        let (mut late, mut lh) = (frame.clone(), hdr);
        assert!(offload::sanitize(&mut lh, &late));
        assert_eq!(check(&f, &late), Pass);
        offload::complete_csum(&mut late, &mut lh);
        assert_eq!(late[26..30], [10, 0, 0, 9]);
        assert_eq!(check(&f, &late), Spoofed);
        // As netd takes it, the rewrite comes before the check, and
        // nothing is left to write after it.
        let (mut first, mut h) = (frame.clone(), hdr);
        assert_eq!(forward(&f, &mut first, &mut h), Some(Spoofed));
        assert_eq!((first[26..30].to_vec(), h[0] & F_NEEDS_CSUM), (vec![10, 0, 0, 9], 0));
        // Into the source MAC: refused.
        let mut mac = hdr;
        mac[6..8].copy_from_slice(&6u16.to_le_bytes());
        assert_eq!(forward(&f, &mut frame.clone(), &mut mac), None);
    }

    #[test]
    fn random_frames() {
        let mut rng = Rng(0x1234_5678_9abc_def1);
        let [pass, spoofed, denied, gso] = run(&mut rng, 100_000);
        // Every verdict comes up, and GSO frames that are segmented.
        assert!(pass > 1000 && spoofed > 1000 && denied > 1000 && gso > 100, "{pass} {spoofed} {denied} {gso}");
    }
}
