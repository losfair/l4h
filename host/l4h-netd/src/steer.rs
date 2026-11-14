//! Stateless L3/L4 steering (DESIGN.md §9.3): dom0 hands part of an
//! address's traffic to another port.
//!
//! An endpoint is (switch, MAC, peer MAC): an address on a switch and the
//! gateway it talks to.  A rule hands the endpoint's frames that match
//! (IP, proto, port) to a target port, where proto and port may be
//! wildcards.  Frames from the peer to the endpoint MAC that match go to
//! the target with its MAC as destination; the target's frames matching
//! the mirrored tuple leave on the endpoint's switch as endpoint MAC ->
//! peer.  Only the two MAC fields change and nothing is remembered.
//!
//! This file is pure (no netd state, no I/O), so that tests/fuzz-steer
//! compiles it unchanged.

pub const MAX_ENDPOINTS: usize = 16;
pub const MAX_RULES: usize = 128;
/// Ports a target mask can name.
pub const MAX_TARGETS: usize = 64;
/// Slots of each table: linear probing at no more than half full.
const SLOTS: usize = 2 * MAX_RULES;
const _: () = assert!(SLOTS.is_power_of_two() && MAX_RULES <= u8::MAX as usize && MAX_ENDPOINTS <= u8::MAX as usize);

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

/// What a rule matches: an address and optionally a protocol (0: any)
/// and a port (0: any; TCP and UDP only).  IPv4 is in ip[12..].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Match {
    pub v6: bool,
    pub proto: u8,
    pub port: u16,
    pub ip: [u8; 16],
}

impl Match {
    /// From the control ABI's words: family | proto << 8 | port << 16, and
    /// the IP's bits 127-64 and 63-0.  None if malformed.
    pub fn from_words(m: u64, hi: u64, lo: u64) -> Option<Match> {
        let (family, proto, port) = (m as u8, (m >> 8) as u8, (m >> 16) as u16);
        let v6 = match family {
            4 if hi == 0 && lo >> 32 == 0 => false,
            6 => true,
            _ => return None,
        };
        if m >> 32 != 0 || (proto == 0 && port != 0) || (port != 0 && proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
            return None;
        }
        let mut ip = [0; 16];
        ip[..8].copy_from_slice(&hi.to_be_bytes());
        ip[8..].copy_from_slice(&lo.to_be_bytes());
        Some(Match { v6, proto, port, ip })
    }

    fn key(&self, ctx: u8) -> Key {
        Key { ctx, v6: self.v6, proto: self.proto, port: self.port, ip: self.ip }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Key {
    /// Inbound: the endpoint; return: the target port.
    ctx: u8,
    v6: bool,
    proto: u8,
    port: u16,
    ip: [u8; 16],
}

impl Key {
    const NONE: Key = Key { ctx: 0, v6: false, proto: 0, port: 0, ip: [0; 16] };
}

#[derive(Clone, Copy)]
struct Slot {
    used: bool,
    key: Key,
    rule: u8,
}

/// Rules by (context, match): open addressing with linear probing.  The
/// keys are dom0's, so the hash needs no seed.
pub struct Table {
    slots: [Slot; SLOTS],
}

impl Table {
    pub const fn new() -> Table {
        Table { slots: [Slot { used: false, key: Key::NONE, rule: 0 }; SLOTS] }
    }

    fn home(k: &Key) -> usize {
        let a = u64::from_le_bytes(k.ip[..8].try_into().unwrap());
        let b = u64::from_le_bytes(k.ip[8..].try_into().unwrap());
        let c = k.ctx as u64 | (k.v6 as u64) << 8 | (k.proto as u64) << 16 | (k.port as u64) << 24;
        let mut x = a ^ b.rotate_left(17) ^ c.rotate_left(41);
        x ^= x >> 32;
        (x.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - SLOTS.trailing_zeros())) as usize
    }

    fn find(&self, k: &Key) -> Option<usize> {
        let mut i = Self::home(k);
        while self.slots[i].used {
            if self.slots[i].key == *k {
                return Some(i);
            }
            i = (i + 1) % SLOTS;
        }
        None
    }

    fn get(&self, k: &Key) -> Option<u8> {
        self.find(k).map(|i| self.slots[i].rule)
    }

    /// Map `k` to `rule`, replacing what it mapped to.  False if full.
    fn insert(&mut self, k: Key, rule: u8) -> bool {
        let mut i = Self::home(&k);
        for _ in 0..SLOTS {
            let s = &mut self.slots[i];
            if !s.used || s.key == k {
                *s = Slot { used: true, key: k, rule };
                return true;
            }
            i = (i + 1) % SLOTS;
        }
        false
    }

    /// Forget `k`.  Later entries of its probe run move back into the
    /// hole, so that no lookup stops short of them (as Fdb::remove).
    fn remove(&mut self, k: &Key) {
        let Some(mut i) = self.find(k) else { return };
        loop {
            self.slots[i].used = false;
            let mut j = i;
            loop {
                j = (j + 1) % SLOTS;
                let e = self.slots[j];
                if !e.used {
                    return;
                }
                let home = Self::home(&e.key);
                if j.wrapping_sub(home) % SLOTS >= j.wrapping_sub(i) % SLOTS {
                    break;
                }
            }
            self.slots[i] = self.slots[j];
            i = j;
        }
    }

    /// The most specific rule for `f` under context `ctx`: (IP, proto,
    /// port), then (IP, proto, *), then (IP, *, *).
    fn lookup(&self, ctx: u8, f: &Flow) -> Option<u8> {
        let mut k = Key { ctx, v6: f.v6, proto: 0, port: 0, ip: f.ip };
        if let Some(proto) = f.proto {
            k.proto = proto;
            if let Some(port) = f.port.filter(|&p| p != 0) {
                k.port = port;
                if let Some(r) = self.get(&k) {
                    return Some(r);
                }
                k.port = 0;
            }
            if let Some(r) = self.get(&k) {
                return Some(r);
            }
            k.proto = 0;
        }
        self.get(&k)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.used).count()
    }
}

/// Which side of a packet is classified: inbound frames by their
/// destination, the target's frames by their source.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Dst,
    Src,
}

impl Side {
    fn mirror(self) -> Side {
        match self {
            Side::Dst => Side::Src,
            Side::Src => Side::Dst,
        }
    }
}

/// A frame's classification: the address on one side, and the protocol
/// and that side's port where they are known.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Flow {
    pub v6: bool,
    pub ip: [u8; 16],
    pub proto: Option<u8>,
    pub port: Option<u16>,
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

/// Classify the Ethernet frame `frame` by `side`.  None unless it is an
/// untagged IPv4 or IPv6 frame with a valid IP header.  IPv6 Neighbor
/// Discovery stays on its link, including unicast reachability probes.
pub fn classify(frame: &[u8], side: Side) -> Option<Flow> {
    if frame.len() < 14 {
        return None;
    }
    match be16(frame, 12) {
        0x0800 => ip4(&frame[14..], side, true),
        0x86dd => ip6(&frame[14..], side, true),
        _ => None,
    }
}

/// The ports of the TCP or UDP header at the start of `l4`, if present.
fn port_of(proto: u8, l4: &[u8], side: Side) -> Option<u16> {
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) || l4.len() < 4 {
        return None;
    }
    Some(match side {
        Side::Src => be16(l4, 0),
        Side::Dst => be16(l4, 2),
    })
}

/// An ICMP error quoting a packet: classify as that packet, mirrored.
/// It is the classified side's own packet only if the quoted address on
/// the mirrored side is the outer one.  If not, or if the quoted headers
/// are cut short of its protocol, the outer flow stands.
fn quoted(outer: Flow, inner: Option<Flow>) -> Flow {
    match inner {
        Some(f) if f.v6 == outer.v6 && f.ip == outer.ip && f.proto.is_some() => f,
        _ => outer,
    }
}

fn ip4(p: &[u8], side: Side, icmp: bool) -> Option<Flow> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = (p[0] & 15) as usize * 4;
    if ihl < 20 || ihl > p.len() {
        return None;
    }
    let mut ip = [0; 16];
    ip[12..].copy_from_slice(match side {
        Side::Src => &p[12..16],
        Side::Dst => &p[16..20],
    });
    let proto = p[9];
    let mut f = Flow { v6: false, ip, proto: Some(proto), port: None };
    // Only the first fragment has the L4 header.
    if be16(p, 6) & 0x1fff != 0 {
        return Some(f);
    }
    let l4 = &p[ihl..];
    f.port = port_of(proto, l4, side);
    // Destination unreachable, time exceeded, parameter problem.
    if icmp && proto == IPPROTO_ICMP && l4.len() >= 8 && matches!(l4[0], 3 | 11 | 12) {
        return Some(quoted(f, ip4(&l4[8..], side.mirror(), false)));
    }
    Some(f)
}

fn ip6(p: &[u8], side: Side, icmp: bool) -> Option<Flow> {
    if p.len() < 40 || p[0] >> 4 != 6 {
        return None;
    }
    let mut ip = [0; 16];
    ip.copy_from_slice(match side {
        Side::Src => &p[8..24],
        Side::Dst => &p[24..40],
    });
    let mut f = Flow { v6: true, ip, proto: None, port: None };
    let (mut nh, mut off) = (p[6], 40);
    let mut opts = 0;
    let mut frag = false;
    loop {
        match nh {
            // Hop-by-hop, routing, destination options: at most two.
            0 | 43 | 60 => {
                if opts == 2 || off + 8 > p.len() {
                    return Some(f);
                }
                let len = (p[off + 1] as usize + 1) * 8;
                if off + len > p.len() {
                    return Some(f);
                }
                opts += 1;
                (nh, off) = (p[off], off + len);
            }
            // Fragment: once.
            44 => {
                if frag || off + 8 > p.len() {
                    return Some(f);
                }
                frag = true;
                let first = be16(p, off + 2) >> 3 == 0;
                (nh, off) = (p[off], off + 8);
                if !first {
                    // Headers after Fragment occur only in the first
                    // fragment.  Here the bytes are payload, even if Next
                    // Header names an extension we normally skip.
                    f.proto = (!matches!(nh, 0 | 43 | 44 | 60)).then_some(nh);
                    return Some(f);
                }
            }
            _ => break,
        }
    }
    f.proto = Some(nh);
    let l4 = &p[off..];
    // The endpoint owner answers ND for the steered address.  Sending its
    // unicast probes to a target with the address on lo breaks NUD; ND
    // from a target must also retain its own link and MAC addresses.
    if nh == IPPROTO_ICMPV6 && l4.first().is_some_and(|&kind| matches!(kind, 133..=137)) {
        return None;
    }
    f.port = port_of(nh, l4, side);
    // Destination unreachable, packet too big, time exceeded, parameter
    // problem.
    if icmp && nh == IPPROTO_ICMPV6 && l4.len() >= 8 && matches!(l4[0], 1..=4) {
        return Some(quoted(f, ip6(&l4[8..], side.mirror(), false)));
    }
    Some(f)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Endpoint {
    pub switch: u8,
    pub mac: [u8; 6],
    pub peer: [u8; 6],
}

#[derive(Clone, Copy, Debug)]
pub struct Rule {
    pub ep: u8,
    pub m: Match,
    /// Target ports, a bit each; one bit for now.
    pub targets: u64,
    /// The target's MAC, copied when the rule is set.
    pub target_mac: [u8; 6],
    pub in_frames: u64,
    pub out_frames: u64,
}

impl Rule {
    fn target(&self) -> usize {
        self.targets.trailing_zeros() as usize
    }
}

/// netd's endpoints and rules, and the tables of both directions.
pub struct Steer {
    pub eps: [Option<Endpoint>; MAX_ENDPOINTS],
    pub rules: [Option<Rule>; MAX_RULES],
    /// (endpoint, match) -> rule.
    inbound: Table,
    /// (target port, match) -> rule.
    ret: Table,
    /// Switches that have endpoints, and ports that are targets: a frame
    /// elsewhere costs a bit test.
    pub switches: u64,
    pub targets: u64,
}

impl Steer {
    pub const fn new() -> Steer {
        Steer {
            eps: [None; MAX_ENDPOINTS],
            rules: [None; MAX_RULES],
            inbound: Table::new(),
            ret: Table::new(),
            switches: 0,
            targets: 0,
        }
    }

    fn update_masks(&mut self) {
        self.switches = self.eps.iter().flatten().fold(0, |m, e| m | 1u64.checked_shl(e.switch as u32).unwrap_or(0));
        self.targets = self.rules.iter().flatten().fold(0, |m, r| m | r.targets);
    }

    /// Set endpoint `id`.  Its rules stay if its (switch, MAC) does: only
    /// the peer changes.
    pub fn ep_set(&mut self, id: usize, ep: Endpoint) -> bool {
        if id >= MAX_ENDPOINTS || ep.switch >= 64 {
            return false;
        }
        if self.eps[id].is_some_and(|e| (e.switch, e.mac) != (ep.switch, ep.mac)) {
            self.ep_del(id);
        }
        self.eps[id] = Some(ep);
        self.update_masks();
        true
    }

    /// Delete endpoint `id` and its rules.
    pub fn ep_del(&mut self, id: usize) {
        if id >= MAX_ENDPOINTS {
            return;
        }
        for r in 0..MAX_RULES {
            if self.rules[r].is_some_and(|r| r.ep as usize == id) {
                self.unlink(r);
                self.rules[r] = None;
            }
        }
        self.eps[id] = None;
        self.update_masks();
    }

    /// Take rule `r`'s keys out of both tables.
    fn unlink(&mut self, r: usize) {
        let Some(rule) = self.rules[r] else { return };
        self.inbound.remove(&rule.m.key(rule.ep));
        for t in 0..MAX_TARGETS {
            if rule.targets & (1 << t) != 0 {
                self.ret.remove(&rule.m.key(t as u8));
            }
        }
    }

    /// Set rule `id`: frames of endpoint `ep` matching `m` go to the
    /// ports in `targets` (one, for now), whose MAC is `target_mac`.  A
    /// rule set again with the same endpoint and match keeps its counters.
    pub fn rule_set(&mut self, id: usize, ep: usize, m: Match, targets: u64, target_mac: [u8; 6]) -> bool {
        if id >= MAX_RULES || ep >= MAX_ENDPOINTS || self.eps[ep].is_none() || targets.count_ones() != 1 {
            return false;
        }
        let (mut in_frames, mut out_frames) = (0, 0);
        if let Some(old) = self.rules[id] {
            if old.ep as usize == ep && old.m == m {
                (in_frames, out_frames) = (old.in_frames, old.out_frames);
            }
            self.unlink(id);
        }
        let rule = Rule { ep: ep as u8, m, targets, target_mac, in_frames, out_frames };
        self.rules[id] = Some(rule);
        // Each table holds at most a key per rule (one target each), in
        // twice as many slots: never full.
        self.inbound.insert(m.key(ep as u8), id as u8);
        self.ret.insert(m.key(rule.target() as u8), id as u8);
        self.update_masks();
        true
    }

    pub fn rule_del(&mut self, id: usize) {
        if id < MAX_RULES {
            self.unlink(id);
            self.rules[id] = None;
            self.update_masks();
        }
    }

    /// Port `port` is gone: it leaves every rule, and rules left without
    /// a target are deleted.
    pub fn port_removed(&mut self, port: usize) {
        if port >= MAX_TARGETS || self.targets & (1 << port) == 0 {
            return;
        }
        for r in 0..MAX_RULES {
            if self.rules[r].is_some_and(|r| r.targets & (1 << port) != 0) {
                self.unlink(r);
                self.rules[r] = None;
            }
        }
        self.update_masks();
    }

    /// A frame on switch `sw` (from guest port `from`, if from a guest):
    /// if it is an endpoint's steered traffic, rewrite its destination MAC
    /// to the target's and return the target port.
    pub fn inbound(&mut self, sw: u8, from: Option<usize>, frame: &mut [u8]) -> Option<usize> {
        if sw >= 64 || self.switches & (1 << sw) == 0 || frame.len() < 14 {
            return None;
        }
        let ep = self.eps.iter().position(|e| {
            e.is_some_and(|e| e.switch == sw && frame[0..6] == e.mac && frame[6..12] == e.peer)
        })?;
        let flow = classify(frame, Side::Dst)?;
        let r = self.inbound.lookup(ep as u8, &flow)? as usize;
        let rule = self.rules[r].as_mut()?;
        if from.is_some_and(|p| p < MAX_TARGETS && rule.targets & (1 << p) != 0) {
            return None;
        }
        frame[0..6].copy_from_slice(&rule.target_mac);
        rule.in_frames += 1;
        Some(rule.target())
    }

    /// A frame from guest port `port`: if it is the return path of a rule
    /// that targets the port, rewrite its MACs to endpoint -> peer and
    /// return the endpoint.
    pub fn outbound(&mut self, port: usize, frame: &mut [u8]) -> Option<Endpoint> {
        if port >= MAX_TARGETS || self.targets & (1 << port) == 0 || frame.len() < 14 {
            return None;
        }
        let flow = classify(frame, Side::Src)?;
        let r = self.ret.lookup(port as u8, &flow)? as usize;
        let rule = self.rules[r].as_mut()?;
        let ep = self.eps[rule.ep as usize]?;
        frame[0..6].copy_from_slice(&ep.peer);
        frame[6..12].copy_from_slice(&ep.mac);
        rule.out_frames += 1;
        Some(ep)
    }

    /// Whether `outbound` would take this frame from guest port `port`:
    /// the port may send it as the rule's address.
    pub fn is_return(&self, port: usize, frame: &[u8]) -> bool {
        if port >= MAX_TARGETS || self.targets & (1 << port) == 0 || frame.len() < 14 {
            return false;
        }
        classify(frame, Side::Src)
            .and_then(|flow| self.ret.lookup(port as u8, &flow))
            .is_some_and(|r| self.rules[r as usize].is_some_and(|rule| self.eps[rule.ep as usize].is_some()))
    }

    #[cfg(test)]
    pub fn table_lens(&self) -> (usize, usize) {
        (self.inbound.len(), self.ret.len())
    }
}
