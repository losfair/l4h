//! Randomised test of netd's steering (host/l4h-netd/src/steer.rs,
//! compiled here unchanged).
//!
//! - Random rule sets, changed by sets, deletions and port removals, are
//!   checked against a plain model of most-specific lookup, which also
//!   exercises the tables' back-shift on removal.
//! - Generated packets (IPv4 options and fragments, IPv6 extension
//!   headers, ICMP errors quoting whole or cut packets) are classified as
//!   the generator says they should be.
//! - Whatever rule steers a request inbound also takes the target's reply
//!   and its ICMP errors out, and an inbound ICMP error about the reply
//!   reaches the same target.
//! - Mutated and truncated frames never panic (no read past the frame),
//!   and steering changes only bytes 0..12.

#![allow(dead_code)]

#[path = "../../../host/l4h-netd/src/steer.rs"]
mod steer;

use steer::{Endpoint, Flow, Match, Side, Steer, classify};

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

const PEER: [u8; 6] = [0x02, 0, 0, 0, 0, 0xfe];
const OTHER: [u8; 6] = [0x02, 0, 0, 0, 0, 0xfd];
const ENDPOINTS: [Endpoint; 3] = [
    Endpoint { switch: 0, mac: [0x42, 1, 1, 1, 1, 0], peer: PEER },
    Endpoint { switch: 0, mac: [0x42, 1, 1, 1, 1, 1], peer: PEER },
    Endpoint { switch: 5, mac: [0x42, 1, 1, 1, 1, 2], peer: [0x02, 0, 0, 0, 0, 0xfc] },
];
const PORTS: usize = 6;

fn port_mac(p: usize) -> [u8; 6] {
    [0x52, 0x54, 0, 0, 0, p as u8]
}

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

/// Addresses rules are made of, and clients.
fn servers(is_v6: bool) -> [[u8; 16]; 3] {
    if is_v6 { [v6(1), v6(2), v6(3)] } else { [v4([203, 0, 113, 5]), v4([203, 0, 113, 6]), v4([10, 128, 0, 9])] }
}

fn client(rng: &mut Rng, is_v6: bool) -> [u8; 16] {
    if is_v6 { v6(0x80 | rng.below(64) as u8) } else { v4([198, 51, 100, rng.below(250) as u8 + 1]) }
}

fn icmp_proto(is_v6: bool) -> u8 {
    if is_v6 { 58 } else { 1 }
}

// ---------------------------------------------------------------------
// The model: rules as dom0 (via root) sets them, and lookup by scanning.

#[derive(Clone, Copy, Debug)]
struct MRule {
    ep: usize,
    m: Match,
    target: usize,
}

struct Model {
    rules: [Option<MRule>; steer::MAX_RULES],
}

impl Model {
    /// The rule for `f` among those `pick` admits, most specific first.
    fn lookup(&self, f: &Flow, pick: impl Fn(&MRule) -> bool) -> Option<usize> {
        let level = |proto: u8, port: u16| {
            self.rules.iter().position(|r| {
                r.is_some_and(|r| {
                    pick(&r) && r.m.v6 == f.v6 && r.m.ip == f.ip && r.m.proto == proto && r.m.port == port
                })
            })
        };
        if let Some(p) = f.proto {
            if let Some(port) = f.port.filter(|&x| x != 0)
                && let Some(r) = level(p, port)
            {
                return Some(r);
            }
            if let Some(r) = level(p, 0) {
                return Some(r);
            }
        }
        level(0, 0)
    }

    /// Root's checks: a target port takes an address from one endpoint
    /// only, and (endpoint, match) names one rule.  Returns the id.
    fn set(&mut self, s: &mut Steer, r: MRule) -> Option<usize> {
        let same_ip = |o: &MRule| o.m.v6 == r.m.v6 && o.m.ip == r.m.ip;
        if self.rules.iter().flatten().any(|o| same_ip(o) && o.ep != r.ep && o.target == r.target) {
            return None;
        }
        let id = match self.rules.iter().position(|o| o.is_some_and(|o| o.ep == r.ep && o.m == r.m)) {
            Some(id) => id,
            None => self.rules.iter().position(|o| o.is_none())?,
        };
        assert!(s.rule_set(id, r.ep, r.m, 1 << r.target, port_mac(r.target)));
        self.rules[id] = Some(r);
        Some(id)
    }
}

fn random_rule(rng: &mut Rng) -> MRule {
    let is_v6 = rng.chance(40);
    let ip = rng.pick(&servers(is_v6));
    let proto = rng.pick(&[0, 6, 17, icmp_proto(is_v6), 50]);
    let port = if proto == 6 || proto == 17 { rng.pick(&[0, 80, 443, 4500]) } else { 0 };
    MRule { ep: rng.below(ENDPOINTS.len() as u64) as usize, m: Match { v6: is_v6, proto, port, ip }, target: rng.below(PORTS as u64) as usize }
}

/// Change the rule set at random, in netd's table and the model alike.
fn churn(rng: &mut Rng, s: &mut Steer, model: &mut Model) {
    for _ in 0..rng.below(40) {
        match rng.below(10) {
            0..=5 => {
                let r = random_rule(rng);
                model.set(s, r);
            }
            6 | 7 => {
                let id = rng.below(steer::MAX_RULES as u64) as usize;
                s.rule_del(id);
                model.rules[id] = None;
            }
            8 => {
                let p = rng.below(PORTS as u64) as usize;
                s.port_removed(p);
                for r in model.rules.iter_mut() {
                    if r.is_some_and(|r| r.target == p) {
                        *r = None;
                    }
                }
            }
            _ => {
                // A new peer keeps the rules.
                let e = rng.below(ENDPOINTS.len() as u64) as usize;
                assert!(s.ep_set(e, ENDPOINTS[e]));
            }
        }
    }
}

// ---------------------------------------------------------------------
// Packets.

#[derive(Clone, Copy, Debug)]
struct Pkt {
    v6: bool,
    src: [u8; 16],
    dst: [u8; 16],
    proto: u8,
    sport: u16,
    dport: u16,
    /// A fragment after the first.
    later_frag: bool,
}

impl Pkt {
    fn reply(&self) -> Pkt {
        Pkt { src: self.dst, dst: self.src, sport: self.dport, dport: self.sport, ..*self }
    }

    /// What classifying it by `side` must give.
    fn flow(&self, side: Side) -> Flow {
        let (ip, port) = match side {
            Side::Dst => (self.dst, self.dport),
            Side::Src => (self.src, self.sport),
        };
        let ports = (self.proto == 6 || self.proto == 17) && !self.later_frag;
        Flow { v6: self.v6, ip, proto: Some(self.proto), port: ports.then_some(port) }
    }
}

fn random_pkt(rng: &mut Rng, is_v6: bool, src: [u8; 16], dst: [u8; 16]) -> Pkt {
    let proto = rng.pick(&[6, 6, 17, 17, icmp_proto(is_v6), 50, 132]);
    let port = |rng: &mut Rng| if rng.chance(50) { rng.pick(&[80, 443, 4500]) } else { rng.below(65536) as u16 };
    Pkt { v6: is_v6, src, dst, proto, sport: port(rng), dport: port(rng), later_frag: rng.chance(10) }
}

/// The L4 header (and a little payload) of `p`.
fn l4(rng: &mut Rng, p: &Pkt) -> Vec<u8> {
    let mut b = Vec::new();
    match p.proto {
        6 | 17 => {
            b.extend_from_slice(&p.sport.to_be_bytes());
            b.extend_from_slice(&p.dport.to_be_bytes());
            b.resize(if p.proto == 6 { 20 } else { 8 }, 0);
        }
        // An echo request, never an error.
        1 => b.extend_from_slice(&[8, 0, 0, 0, 0, 0, 0, 0]),
        58 => b.extend_from_slice(&[128, 0, 0, 0, 0, 0, 0, 0]),
        _ => b.extend((0..8).map(|_| rng.next() as u8)),
    }
    b.extend((0..rng.below(32)).map(|_| rng.next() as u8));
    b
}

/// The IP packet `p` with `payload`, with random options or extension
/// headers that the classifier must skip.
fn ip(rng: &mut Rng, p: &Pkt, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    if !p.v6 {
        let opts = rng.below(11) as usize;
        let ihl = 5 + opts;
        b.push(0x40 | ihl as u8);
        b.push(0);
        b.extend_from_slice(&((ihl * 4 + payload.len()) as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        let frag: u16 = if p.later_frag { 1 + rng.below(0x1fff) as u16 } else { 0 } | if rng.chance(30) { 0x2000 } else { 0 };
        b.extend_from_slice(&frag.to_be_bytes());
        b.extend_from_slice(&[64, p.proto, 0, 0]);
        b.extend_from_slice(&p.src[12..]);
        b.extend_from_slice(&p.dst[12..]);
        b.extend((0..opts * 4).map(|_| 1u8));
    } else {
        // Up to two option headers, and a fragment header if fragmented.
        let mut chain: Vec<u8> = (0..rng.below(3)).map(|_| rng.pick(&[0, 43, 60])).collect();
        if p.later_frag || rng.chance(10) {
            chain.push(44);
        }
        chain.push(p.proto);
        let mut ext = Vec::new();
        for w in chain.windows(2) {
            if w[0] == 44 {
                let off: u16 = if p.later_frag { (1 + rng.below(0x1fff) as u16) << 3 } else { 0 };
                ext.extend_from_slice(&[w[1], 0]);
                ext.extend_from_slice(&off.to_be_bytes());
                ext.extend_from_slice(&[0, 0, 0, 1]);
            } else {
                let units = rng.below(3) as usize;
                ext.extend_from_slice(&[w[1], units as u8]);
                ext.extend((0..6 + units * 8).map(|_| 1u8));
            }
        }
        b.extend_from_slice(&[0x60, 0, 0, 0]);
        b.extend_from_slice(&((ext.len() + payload.len()) as u16).to_be_bytes());
        b.extend_from_slice(&[chain[0], 64]);
        b.extend_from_slice(&p.src);
        b.extend_from_slice(&p.dst);
        b.extend_from_slice(&ext);
    }
    b.extend_from_slice(payload);
    b
}

fn frame(dst: [u8; 6], src: [u8; 6], v6: bool, ip: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + ip.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(if v6 { &[0x86, 0xdd] } else { &[0x08, 0x00] });
    f.extend_from_slice(ip);
    f
}

/// An ICMP error from `from` to `to` quoting `q`, cut at random; and the
/// classification it must get by `side` (the quoted packet's other side).
fn icmp_error(rng: &mut Rng, from: [u8; 16], to: [u8; 16], q: &Pkt, side: Side) -> (Vec<u8>, Flow) {
    let full = {
        let l = l4(rng, q);
        ip(rng, q, &l)
    };
    // The quoted packet's IP header, with all of it, 8 bytes of it, or less.
    let hdr = full.len() - l4_len(&full, q);
    let cut = match rng.below(4) {
        0 => full.len(),
        1 => hdr + 8,
        2 => hdr + rng.below(8) as usize,
        _ => rng.below(hdr as u64) as usize,
    }
    .min(full.len());
    let mut payload = vec![if q.v6 { rng.pick(&[1, 2, 3, 4]) } else { rng.pick(&[3, 11, 12]) }, 0, 0, 0, 0, 0, 0, 0];
    payload.extend_from_slice(&full[..cut]);
    let outer = Pkt { v6: q.v6, src: from, dst: to, proto: icmp_proto(q.v6), sport: 0, dport: 0, later_frag: false };
    let ipb = ip(rng, &outer, &payload);
    let expect = if cut < hdr {
        outer.flow(side)
    } else {
        let mut f = q.flow(match side {
            Side::Dst => Side::Src,
            Side::Src => Side::Dst,
        });
        if cut - hdr < 4 {
            f.port = None;
        }
        f
    };
    (ipb, expect)
}

/// The length of the L4 part of the IP packet `b` built from `p`.
fn l4_len(b: &[u8], p: &Pkt) -> usize {
    if !p.v6 {
        return b.len() - (b[0] & 15) as usize * 4;
    }
    let (mut nh, mut off) = (b[6], 40);
    while matches!(nh, 0 | 43 | 60 | 44) {
        let len = if nh == 44 { 8 } else { (b[off + 1] as usize + 1) * 8 };
        (nh, off) = (b[off], off + len);
    }
    b.len() - off
}

// ---------------------------------------------------------------------
// The checks.

/// Steer `f` inbound on switch `sw`; assert that only bytes 0..12 change
/// and return the target and the rule that took it.
fn inbound(s: &mut Steer, sw: u8, from: Option<usize>, f: &mut [u8]) -> Option<(usize, usize)> {
    let before = f.to_vec();
    let counts: Vec<u64> = s.rules.iter().map(|r| r.map_or(0, |r| r.in_frames)).collect();
    let t = s.inbound(sw, from, f);
    assert_eq!(f.get(12..), before.get(12..));
    let rule = s.rules.iter().zip(&counts).position(|(r, &c)| r.is_some_and(|r| r.in_frames != c));
    match t {
        Some(t) => {
            assert_eq!(f[..6], port_mac(t));
            assert_eq!(f[6..12], before[6..12]);
            Some((t, rule.expect("a counted rule")))
        }
        None => {
            assert_eq!(f, &before[..]);
            assert!(rule.is_none());
            None
        }
    }
}

/// Steer `f` out from port `port`: the endpoint and the rule.
fn outbound(s: &mut Steer, port: usize, f: &mut [u8]) -> Option<(Endpoint, usize)> {
    let before = f.to_vec();
    let counts: Vec<u64> = s.rules.iter().map(|r| r.map_or(0, |r| r.out_frames)).collect();
    let e = s.outbound(port, f);
    assert_eq!(f.get(12..), before.get(12..));
    let rule = s.rules.iter().zip(&counts).position(|(r, &c)| r.is_some_and(|r| r.out_frames != c));
    match e {
        Some(e) => {
            assert_eq!((&f[..6], &f[6..12]), (&e.peer[..], &e.mac[..]));
            Some((e, rule.expect("a counted rule")))
        }
        None => {
            assert_eq!(f, &before[..]);
            assert!(rule.is_none());
            None
        }
    }
}

fn ep_of(e: &Endpoint) -> usize {
    ENDPOINTS.iter().position(|x| x.mac == e.mac).unwrap()
}

fn round(rng: &mut Rng, s: &mut Steer, model: &Model, mutated: &mut u64, steered: &mut u64) {
    let is_v6 = rng.chance(40);
    let e = rng.below(ENDPOINTS.len() as u64) as usize;
    let ep = ENDPOINTS[e];
    let dst = if rng.chance(85) { rng.pick(&servers(is_v6)) } else { client(rng, is_v6) };
    let c = client(rng, is_v6);
    let req = random_pkt(rng, is_v6, c, dst);
    let payload = l4(rng, &req);
    let req_ip = ip(rng, &req, &payload);
    let f = frame(ep.mac, ep.peer, is_v6, &req_ip);
    assert_eq!(classify(&f, Side::Dst), Some(req.flow(Side::Dst)), "{req:?}");

    let want = model.lookup(&req.flow(Side::Dst), |r| r.ep == e);
    let got = inbound(s, ep.switch, None, &mut f.clone());
    assert_eq!(got.map(|g| g.1), want, "{req:?}");
    // Not from the peer, or on another switch: not steered.
    let mut g = frame(ep.mac, OTHER, is_v6, &req_ip);
    assert!(inbound(s, ep.switch, None, &mut g).is_none());
    assert!(inbound(s, ep.switch ^ 1, None, &mut f.clone()).is_none());

    if let Some((t, rule)) = got {
        *steered += 1;
        // Not from the target itself.
        assert!(inbound(s, ep.switch, Some(t), &mut f.clone()).is_none());
        // The reply leaves through the same endpoint and rule.
        let rep = req.reply();
        let l = l4(rng, &rep);
        let mut r = frame(rng.pick(&[PEER, OTHER]), port_mac(t), is_v6, &ip(rng, &rep, &l));
        let (oe, orule) = outbound(s, t, &mut r).expect("the reply is steered");
        assert_eq!((ep_of(&oe), orule), (e, rule));
        // So does an error the target sends about the request, at the
        // same level of match or a less specific one.
        let (eb, flow) = icmp_error(rng, req.dst, req.src, &req, Side::Src);
        let mut ef = frame(PEER, port_mac(t), is_v6, &eb);
        assert_eq!(classify(&ef, Side::Src), Some(flow));
        let want = model.lookup(&flow, |r| r.target == t);
        assert_eq!(outbound(s, t, &mut ef).map(|o| o.1), want);
        if flow == req.flow(Side::Dst) {
            assert_eq!(want, Some(rule));
        }
        // And an error from the network about the reply reaches the
        // target.
        let router = client(rng, is_v6);
        let (eb, flow) = icmp_error(rng, router, req.dst, &rep, Side::Dst);
        let mut ef = frame(ep.mac, ep.peer, is_v6, &eb);
        assert_eq!(classify(&ef, Side::Dst), Some(flow));
        let want = model.lookup(&flow, |r| r.ep == e);
        assert_eq!(inbound(s, ep.switch, None, &mut ef).map(|o| o.1), want);
        if flow == req.flow(Side::Dst) {
            assert_eq!(want, Some(rule));
        }
    }

    // Any frame a target sends from a steered address: as the model says.
    let t = rng.below(PORTS as u64) as usize;
    let (a, c) = (rng.pick(&servers(is_v6)), client(rng, is_v6));
    let out = random_pkt(rng, is_v6, a, c);
    let l = l4(rng, &out);
    let mut o = frame(PEER, port_mac(t), is_v6, &ip(rng, &out, &l));
    let want = model.lookup(&out.flow(Side::Src), |r| r.target == t);
    let got = outbound(s, t, &mut o);
    assert_eq!(got.map(|g| g.1), want);
    if let Some((oe, r)) = got {
        assert_eq!(ep_of(&oe), model.rules[r].unwrap().ep);
    }

    // Mutated and cut frames: no panic, only MACs change.
    for _ in 0..4 {
        let mut m = f.clone();
        for _ in 0..rng.below(4) {
            let i = rng.below(m.len() as u64) as usize;
            m[i] = rng.next() as u8;
        }
        if rng.chance(30) {
            // VLAN-tagged: never steered.
            m[12..14].copy_from_slice(&[0x81, 0x00]);
        }
        let cut = if rng.chance(50) { rng.below(m.len() as u64 + 1) as usize } else { m.len() };
        let m = &mut m[..cut];
        let _ = classify(m, Side::Dst);
        let _ = classify(m, Side::Src);
        let vlan = m.len() >= 14 && m[12..14] == [0x81, 0x00];
        let i = inbound(s, ep.switch, None, m);
        let o = outbound(s, t, m);
        if vlan || m.len() < 34 {
            assert!(i.is_none() && o.is_none());
        }
        *mutated += 1;
    }
}

fn check(rng: &mut Rng, iters: u64) {
    let mut s = Box::new(Steer::new());
    for (i, e) in ENDPOINTS.iter().enumerate() {
        assert!(s.ep_set(i, *e));
    }
    let mut model = Model { rules: [None; steer::MAX_RULES] };
    let (mut mutated, mut steered) = (0, 0);
    for i in 0..iters {
        if i % 200 == 0 {
            churn(rng, &mut s, &mut model);
        }
        round(rng, &mut s, &model, &mut mutated, &mut steered);
    }
    let rules = model.rules.iter().flatten().count();
    println!("fuzz-steer: {iters} rounds, {steered} requests steered, {mutated} mutated frames, {rules} rules at the end");
    assert!(steered > iters / 10, "too few requests steered to check anything");
}

fn main() {
    let iters = std::env::args().nth(1).map_or(100_000, |s| s.parse().expect("iterations"));
    let seed = std::env::var("SEED").ok().map_or(0x5eed_1234_abcd, |s| s.parse().expect("SEED"));
    check(&mut Rng(seed), iters);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp4(dst: [u8; 4], dport: u16) -> Vec<u8> {
        let p = Pkt {
            v6: false,
            src: v4([198, 51, 100, 7]),
            dst: v4(dst),
            proto: 6,
            sport: 40000,
            dport,
            later_frag: false,
        };
        let b = ip(&mut Rng(1), &p, &[0x9c, 0x40, (dport >> 8) as u8, dport as u8, 0, 0, 0, 0]);
        frame(ENDPOINTS[0].mac, PEER, false, &b)
    }

    fn setup() -> Steer {
        let mut s = Steer::new();
        assert!(s.ep_set(0, ENDPOINTS[0]));
        s
    }

    fn m(proto: u8, port: u16) -> Match {
        Match { v6: false, proto, port, ip: v4([203, 0, 113, 5]) }
    }

    #[test]
    fn match_words() {
        let ok = Match::from_words(4 | 6 << 8 | 443 << 16, 0, 0xcb00_7105).unwrap();
        assert_eq!(ok, m(6, 443));
        assert!(Match::from_words(6 | 1 << 8, 0x2001_0db8 << 32, 1).is_some_and(|m| m.v6));
        for (w, hi, lo) in [
            (5, 0, 1),                 // family
            (4, 1, 1),                 // IPv4 with high bits
            (4, 0, 1 << 32),
            (4 | 1 << 8 | 80 << 16, 0, 1), // port without TCP or UDP
            (4 | 80 << 16, 0, 1),      // port without proto
            (4 | 1 << 32, 0, 1),       // reserved bits
        ] {
            assert!(Match::from_words(w, hi, lo).is_none(), "{w:#x}");
        }
    }

    #[test]
    fn most_specific_wins() {
        let mut s = setup();
        assert!(s.rule_set(0, 0, m(0, 0), 1 << 1, port_mac(1)));
        assert!(s.rule_set(1, 0, m(6, 0), 1 << 2, port_mac(2)));
        assert!(s.rule_set(2, 0, m(6, 443), 1 << 3, port_mac(3)));
        assert_eq!(s.inbound(0, None, &mut tcp4([203, 0, 113, 5], 443)), Some(3));
        assert_eq!(s.inbound(0, None, &mut tcp4([203, 0, 113, 5], 80)), Some(2));
        s.rule_del(1);
        assert_eq!(s.inbound(0, None, &mut tcp4([203, 0, 113, 5], 80)), Some(1));
        assert_eq!(s.inbound(0, None, &mut tcp4([203, 0, 113, 6], 80)), None);
    }

    #[test]
    fn replacing_targets_keeps_counters() {
        let mut s = setup();
        assert!(s.rule_set(4, 0, m(6, 443), 1 << 3, port_mac(3)));
        assert_eq!(s.inbound(0, None, &mut tcp4([203, 0, 113, 5], 443)), Some(3));
        assert!(s.rule_set(4, 0, m(6, 443), 1 << 5, port_mac(5)));
        assert_eq!(s.inbound(0, None, &mut tcp4([203, 0, 113, 5], 443)), Some(5));
        assert_eq!(s.rules[4].unwrap().in_frames, 2);
        assert_eq!(s.table_lens(), (1, 1));
        assert_eq!(s.targets, 1 << 5);
    }

    #[test]
    fn removing_a_port_deletes_its_rules() {
        let mut s = setup();
        assert!(s.rule_set(0, 0, m(6, 80), 1 << 3, port_mac(3)));
        assert!(s.rule_set(1, 0, m(6, 443), 1 << 4, port_mac(4)));
        s.port_removed(3);
        assert!(s.rules[0].is_none() && s.rules[1].is_some());
        assert_eq!(s.table_lens(), (1, 1));
        assert_eq!(s.inbound(0, None, &mut tcp4([203, 0, 113, 5], 80)), None);
        s.ep_del(0);
        assert_eq!(s.table_lens(), (0, 0));
        assert_eq!((s.switches, s.targets), (0, 0));
    }

    #[test]
    fn full_tables_back_shift() {
        // Every rule, then half of them removed: the rest are all found.
        let mut s = setup();
        let mut rng = Rng(7);
        let ip = |i: usize| [10, 0, (i >> 8) as u8, i as u8];
        let rule = |i: usize| Match { v6: false, proto: 6, port: 443, ip: v4(ip(i)) };
        for i in 0..steer::MAX_RULES {
            assert!(s.rule_set(i, 0, rule(i), 1 << (i % 40), port_mac(i % 40)));
        }
        let mut live = vec![true; steer::MAX_RULES];
        for _ in 0..steer::MAX_RULES / 2 {
            let i = rng.below(steer::MAX_RULES as u64) as usize;
            s.rule_del(i);
            live[i] = false;
        }
        for i in 0..steer::MAX_RULES {
            assert_eq!(s.inbound(0, None, &mut tcp4(ip(i), 443)).is_some(), live[i], "rule {i}");
        }
    }

    #[test]
    fn short_run() {
        check(&mut Rng(42), 20_000);
    }
}
