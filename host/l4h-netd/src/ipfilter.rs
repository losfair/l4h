//! L3 source filtering of a guest port's frames (DESIGN.md §9.3): with
//! the filter on, a port sends only IPv4, IPv6 and ARP from the addresses
//! dom0 gave it, and acts as no router or DHCP server.
//!
//! - IPv4: the source is an allowed address, or 0.0.0.0 for a DHCP client
//!   (UDP 68 -> 67).  A message to a DHCP server (UDP port 67) is a
//!   client's, unfragmented, for the frame's source MAC (chaddr) and not
//!   relayed (hops and giaddr 0): one for another's MAC could release or
//!   decline its lease (a client identifier still can: DESIGN.md), and a
//!   relay names the subnet to lease from.
//! - ARP: Ethernet over IPv4; the sender is an allowed address, or 0.0.0.0
//!   for an RFC 5227 probe of an allowed address, and its MAC the frame's
//!   source.
//! - IPv6: the source is an allowed address, or :: for duplicate address
//!   detection of an allowed address, router solicitations and MLD
//!   reports.  A Neighbor Advertisement's target is an allowed address;
//!   link-layer address options of Neighbor Discovery are the frame's
//!   source MAC, and its messages are unfragmented (RFC 6980), so that no
//!   option is past what is checked.  (A probe of another's address would
//!   make its owner give it up.)
//! - Guards: Router Advertisements, Redirects and Router Renumbering
//!   (ICMPv6 134, 137, 138), ICMPv4 Redirects and Router Advertisements
//!   (5, 9), and DHCP or DHCPv6 server and relay messages (UDP source port
//!   67 or 547, to a client's port, 68 or 546, or a DHCPv6 server's or
//!   relay's message type to 547) are dropped, whatever their source.
//! - Everything else is dropped: other EtherTypes, VLAN tags (whose frames
//!   would carry IP past these checks), malformed headers, and an IPv6
//!   first fragment whose headers do not reach the upper-layer header.
//!
//! This file is pure (no netd state, no I/O), so that tests/fuzz-ipfilter
//! compiles it unchanged.

/// Allowed prefixes per port.
pub const MAX_PREFIXES: usize = 16;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;
/// IPv6 extension headers that may come before the upper-layer header.
const MAX_EXT_HEADERS: usize = 8;

/// An allowed prefix: `len` leading bits of `ip`, the rest zero.  IPv4 is
/// in ip[12..].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Prefix {
    pub v6: bool,
    pub len: u8,
    pub ip: [u8; 16],
}

impl Prefix {
    /// From the control ABI's words: family | length << 8, and the IP's
    /// bits 127-64 and 63-0.  None if malformed, or if bits past the
    /// length are set.
    pub fn from_words(m: u64, hi: u64, lo: u64) -> Option<Prefix> {
        let (family, len) = (m as u8, (m >> 8) as u8);
        let v6 = match family {
            4 if hi == 0 && lo >> 32 == 0 && len <= 32 => false,
            6 if len <= 128 => true,
            _ => return None,
        };
        if m >> 16 != 0 {
            return None;
        }
        let mut ip = [0; 16];
        ip[..8].copy_from_slice(&hi.to_be_bytes());
        ip[8..].copy_from_slice(&lo.to_be_bytes());
        let p = Prefix { v6, len, ip };
        (p.mask(&ip) == ip).then_some(p)
    }

    /// `ip` with the bits past the prefix cleared.
    fn mask(&self, ip: &[u8; 16]) -> [u8; 16] {
        // IPv4's bits start at ip[12].
        let bits = self.len as usize + if self.v6 { 0 } else { 96 };
        let mut m = *ip;
        for (i, b) in m.iter_mut().enumerate() {
            let keep = bits.saturating_sub(i * 8).min(8);
            *b &= !(0xffu16 >> keep) as u8;
        }
        if !self.v6 {
            m[..12].fill(0);
        }
        m
    }

    fn contains(&self, v6: bool, ip: &[u8; 16]) -> bool {
        self.v6 == v6 && self.mask(ip) == self.ip
    }
}

/// A port's filter: off, or on with the prefixes it may send from.
#[derive(Clone, Copy)]
pub struct Filter {
    pub on: bool,
    pub prefixes: [Option<Prefix>; MAX_PREFIXES],
}

impl Filter {
    pub const OFF: Filter = Filter { on: false, prefixes: [None; MAX_PREFIXES] };

    /// Put `p` in slot `slot`, replacing what was there.
    pub fn set(&mut self, slot: usize, p: Prefix) -> bool {
        match self.prefixes.get_mut(slot) {
            Some(s) => {
                *s = Some(p);
                true
            }
            None => false,
        }
    }

    pub fn del(&mut self, slot: usize) {
        if let Some(s) = self.prefixes.get_mut(slot) {
            *s = None;
        }
    }

    fn allows(&self, v6: bool, ip: &[u8; 16]) -> bool {
        self.prefixes.iter().flatten().any(|p| p.contains(v6, ip))
    }
}

/// What the filter makes of a frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Pass,
    /// IP from a source the port was not given: a steering rule's return
    /// traffic may still pass (dom0 lets the target send as the address).
    Spoofed,
    /// Never sent: not IP or ARP, malformed, a spoofed ARP or Neighbor
    /// Discovery message, or a router's or DHCP server's.
    Denied,
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

/// Check the Ethernet frame `frame` a port with filter `f` sent.  The
/// caller drops frames shorter than an Ethernet header.
pub fn check(f: &Filter, frame: &[u8]) -> Verdict {
    if !f.on {
        return Verdict::Pass;
    }
    if frame.len() < 14 {
        return Verdict::Denied;
    }
    let src: &[u8; 6] = frame[6..12].try_into().unwrap();
    let p = &frame[14..];
    match be16(frame, 12) {
        0x0800 => ip4(f, src, p),
        0x86dd => ip6(f, src, p),
        0x0806 => arp(f, src, p),
        _ => Verdict::Denied,
    }
}

fn v4(b: &[u8]) -> [u8; 16] {
    let mut ip = [0; 16];
    ip[12..].copy_from_slice(&b[..4]);
    ip
}

fn arp(f: &Filter, src: &[u8; 6], p: &[u8]) -> Verdict {
    // Ethernet, IPv4, 6-byte and 4-byte addresses.
    if p.len() < 28 || p[..6] != [0, 1, 8, 0, 6, 4] || p[8..14] != *src {
        return Verdict::Denied;
    }
    let (spa, tpa) = (v4(&p[14..18]), v4(&p[24..28]));
    let ok = if spa == [0; 16] { f.allows(false, &tpa) } else { f.allows(false, &spa) };
    if ok { Verdict::Pass } else { Verdict::Denied }
}

fn ip4(f: &Filter, mac: &[u8; 6], p: &[u8]) -> Verdict {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return Verdict::Denied;
    }
    let ihl = (p[0] & 15) as usize * 4;
    if ihl < 20 || ihl > p.len() {
        return Verdict::Denied;
    }
    let proto = p[9];
    // Only the first fragment has the upper-layer header, whole.
    let first = be16(p, 6) & 0x1fff == 0;
    let more = be16(p, 6) & 0x2000 != 0;
    let l4 = &p[ihl..];
    if first {
        let need = match proto {
            IPPROTO_UDP => 4,
            IPPROTO_ICMP => 1,
            _ => 0,
        };
        if l4.len() < need {
            return Verdict::Denied;
        }
        let dhcp_server = proto == IPPROTO_UDP && (be16(l4, 0) == 67 || be16(l4, 2) == 68);
        // ICMP Redirect, Router Advertisement.
        if dhcp_server || (proto == IPPROTO_ICMP && matches!(l4[0], 5 | 9)) {
            return Verdict::Denied;
        }
        if proto == IPPROTO_UDP && be16(l4, 2) == 67 && (more || !dhcp_client(mac, &l4[8.min(l4.len())..])) {
            return Verdict::Denied;
        }
    }
    let src = v4(&p[12..16]);
    if src == [0; 16] {
        let dhcp = first && proto == IPPROTO_UDP && be16(l4, 0) == 68 && be16(l4, 2) == 67;
        return if dhcp { Verdict::Pass } else { Verdict::Denied };
    }
    if f.allows(false, &src) { Verdict::Pass } else { Verdict::Spoofed }
}

/// A BOOTP request (op 1, Ethernet) from the client itself (no relay
/// hops, no giaddr) whose client hardware address is `mac`.  `m` is the
/// UDP payload, with whatever padding the frame has: at worst a server
/// sees a short message it drops.
fn dhcp_client(mac: &[u8; 6], m: &[u8]) -> bool {
    m.len() >= 34 && m[..4] == [1, 1, 6, 0] && m[24..28] == [0; 4] && m[28..34] == *mac
}

/// DHCPv6 message types only servers and relays send: Advertise, Reply,
/// Reconfigure, Relay-forward, Relay-reply.
fn dhcp6_server_type(t: u8) -> bool {
    matches!(t, 2 | 7 | 10 | 12 | 13)
}

fn ip6(f: &Filter, mac: &[u8; 6], p: &[u8]) -> Verdict {
    if p.len() < 40 || p[0] >> 4 != 6 {
        return Verdict::Denied;
    }
    let src: [u8; 16] = p[8..24].try_into().unwrap();
    let (mut nh, mut off) = (p[6], 40);
    // The upper-layer header, unless this is a later fragment.
    let mut first = true;
    let mut frag = false;
    let mut n = 0;
    // Hop-by-hop, routing, fragment, destination options, AH, mobility,
    // HIP, shim6.
    while matches!(nh, 0 | 43 | 44 | 51 | 60 | 135 | 139 | 140) {
        // The headers before the upper-layer one are all in the first
        // fragment (RFC 7112): one that is cut short, or too many, hides
        // what follows.
        if off + 8 > p.len() || n == MAX_EXT_HEADERS || (nh == 44 && frag) {
            return Verdict::Denied;
        }
        let len = match nh {
            44 => {
                frag = true;
                first = be16(p, off + 2) >> 3 == 0;
                8
            }
            51 => (p[off + 1] as usize + 2) * 4,
            _ => (p[off + 1] as usize + 1) * 8,
        };
        if off + len > p.len() {
            return Verdict::Denied;
        }
        n += 1;
        (nh, off) = (p[off], off + len);
        if !first {
            break;
        }
    }
    let l4 = &p[off..];
    let mut icmp = None;
    if first {
        match nh {
            IPPROTO_UDP if l4.len() < 4 || be16(l4, 0) == 547 || be16(l4, 2) == 546 => return Verdict::Denied,
            IPPROTO_UDP if be16(l4, 2) == 547 && l4.get(8).is_none_or(|&t| dhcp6_server_type(t)) => {
                return Verdict::Denied;
            }
            IPPROTO_ICMPV6 => {
                let Some(&kind) = l4.first() else { return Verdict::Denied };
                // Router Advertisement, Redirect, Router Renumbering.
                if matches!(kind, 134 | 137 | 138) {
                    return Verdict::Denied;
                }
                if matches!(kind, 133 | 135 | 136) && (frag || !nd_ok(f, mac, kind, src == [0; 16], l4)) {
                    return Verdict::Denied;
                }
                icmp = Some(kind);
            }
            _ => {}
        }
    }
    if src == [0; 16] {
        // Router Solicitation, Neighbor Solicitation (DAD), MLD reports.
        let ok = !frag && icmp.is_some_and(|k| matches!(k, 131 | 133 | 135 | 143));
        return if ok { Verdict::Pass } else { Verdict::Denied };
    }
    if f.allows(true, &src) { Verdict::Pass } else { Verdict::Spoofed }
}

/// A Router Solicitation, Neighbor Solicitation or Advertisement (`kind`)
/// whose link-layer address options name `mac`, and an Advertisement's
/// target, or a duplicate address detection's (from `dad`, the
/// unspecified address), one of the port's addresses.
fn nd_ok(f: &Filter, mac: &[u8; 6], kind: u8, dad: bool, l4: &[u8]) -> bool {
    let opts = match kind {
        133 => 8,
        _ => 24,
    };
    if l4.len() < opts {
        return false;
    }
    if (kind == 136 || (kind == 135 && dad)) && !f.allows(true, l4[8..24].try_into().unwrap()) {
        return false;
    }
    let mut o = &l4[opts..];
    while o.len() >= 2 {
        let len = o[1] as usize * 8;
        if len == 0 || len > o.len() {
            return false;
        }
        // Source and target link-layer addresses.
        if matches!(o[0], 1 | 2) && (len != 8 || o[2..8] != *mac) {
            return false;
        }
        o = &o[len..];
    }
    o.is_empty()
}
