//! virtio-net offload metadata (struct virtio_net_hdr_v1) on frames that
//! cross the switch: validation of what a guest sent, and TCP segmentation
//! for receivers that cannot take large (GSO) frames.  Free of seL4
//! dependencies so that it can be tested on the build machine.

pub const HDR_SIZE: usize = 12;
pub const F_NEEDS_CSUM: u8 = 1;
pub const GSO_NONE: u8 = 0;
pub const GSO_TCPV4: u8 = 1;
pub const GSO_TCPV6: u8 = 4;
pub const GSO_ECN: u8 = 0x80;
/// The smallest `gso_size` netd takes from a sender it does not trust, a
/// guest or a peer partition (Linux's sender floor, `TCP_MIN_SND_MSS`, the
/// default of net.ipv4.tcp_min_snd_mss): a tiny one would make `segment`
/// cut one frame into tens of thousands of packets and keep netd's single
/// thread busy for every other port (DESIGN.md §9.3).  An uplink's frames
/// (`UPLINK_MIN_MSS`) keep the size the device merged them with: they
/// segment into no more packets than it received.
pub const MIN_MSS: usize = 48;
/// The smallest `gso_size` taken from an uplink device: any.
pub const UPLINK_MIN_MSS: usize = 1;

fn get16(h: &[u8; HDR_SIZE], off: usize) -> usize {
    u16::from_le_bytes([h[off], h[off + 1]]) as usize
}

fn put16(h: &mut [u8; HDR_SIZE], off: usize, v: usize) {
    h[off..off + 2].copy_from_slice(&(v as u16).to_le_bytes());
}

/// Headers of a TCP segment: offsets of the IP and TCP headers and the
/// length of all headers.
#[derive(Clone, Copy, Debug)]
pub struct TcpFrame {
    pub ip: usize,
    pub v6: bool,
    pub tcp: usize,
    pub hdrs: usize,
}

/// A frame's EtherType after at most one 802.1Q tag, and where its
/// network header starts; None if the frame is too short for either.
pub fn ethertype(frame: &[u8]) -> Option<(u16, usize)> {
    let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if ethertype != 0x8100 {
        return Some((ethertype, 14));
    }
    Some((u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]), 18))
}

/// Parse Ethernet (optionally one 802.1Q tag) + IPv4/IPv6 + TCP, without
/// IP options beyond the header length or IPv6 extension headers.
pub fn parse_tcp(frame: &[u8]) -> Option<TcpFrame> {
    let (ethertype, ip) = ethertype(frame)?;
    let (v6, tcp) = match ethertype {
        0x0800 => {
            let ihl = (*frame.get(ip)? & 0x0f) as usize * 4;
            if *frame.get(ip)? >> 4 != 4 || ihl < 20 || *frame.get(ip + 9)? != 6 {
                return None;
            }
            (false, ip + ihl)
        }
        0x86dd => {
            if *frame.get(ip)? >> 4 != 6 || *frame.get(ip + 6)? != 6 {
                return None;
            }
            (true, ip + 40)
        }
        _ => return None,
    };
    let thl = (*frame.get(tcp + 12)? >> 4) as usize * 4;
    if thl < 20 || tcp + thl > frame.len() {
        return None;
    }
    Some(TcpFrame { ip, v6, tcp, hdrs: tcp + thl })
}

/// Check and normalise the header a guest sent with `frame`.  Returns
/// false if the frame must be dropped.
pub fn sanitize(hdr: &mut [u8; HDR_SIZE], frame: &[u8]) -> bool {
    check(hdr, frame, MIN_MSS)
}

/// `sanitize`, taking GSO frames of `min_mss` bytes a segment or more.
fn check(hdr: &mut [u8; HDR_SIZE], frame: &[u8], min_mss: usize) -> bool {
    // Only NEEDS_CSUM has a meaning from driver to device.
    hdr[0] &= F_NEEDS_CSUM;
    hdr[10] = 0;
    hdr[11] = 0;
    if hdr[0] & F_NEEDS_CSUM != 0 && get16(hdr, 6) + get16(hdr, 8) + 2 > frame.len() {
        return false;
    }
    match hdr[1] & !GSO_ECN {
        GSO_NONE => {
            hdr[1] = GSO_NONE;
            put16(hdr, 2, 0);
            put16(hdr, 4, 0);
            true
        }
        t @ (GSO_TCPV4 | GSO_TCPV6) => {
            // The receiver trusts these: they must describe the frame.
            let Some(f) = parse_tcp(frame) else { return false };
            if f.v6 != (t == GSO_TCPV6) || hdr[0] & F_NEEDS_CSUM == 0 || get16(hdr, 4) < min_mss {
                return false;
            }
            if get16(hdr, 6) != f.tcp || get16(hdr, 8) != 16 {
                return false;
            }
            put16(hdr, 2, f.hdrs);
            true
        }
        _ => false,
    }
}

pub const F_DATA_VALID: u8 = 2;

/// Check and normalise the header that came with a received `frame`: as
/// `sanitize`, but DATA_VALID (the device checked the checksum) is kept.
/// `min_mss` is the smallest gso_size taken, the bound on how many
/// packets `segment` can cut the frame into: MIN_MSS from a peer
/// partition's link, which netd does not trust; UPLINK_MIN_MSS from an
/// uplink device, whose frames hold the packets it received.  A GSO frame
/// without NEEDS_CSUM fails here (guests refuse it); the uplink's caller
/// segments it instead.
pub fn sanitize_rx(hdr: &mut [u8; HDR_SIZE], frame: &[u8], min_mss: usize) -> bool {
    let valid = hdr[0] & F_DATA_VALID;
    if !check(hdr, frame, min_mss) {
        return false;
    }
    if hdr[0] & F_NEEDS_CSUM == 0 {
        hdr[0] |= valid;
    }
    true
}

pub fn is_gso(hdr: &[u8; HDR_SIZE]) -> bool {
    hdr[1] != GSO_NONE
}

/// Whether a peer partition's link takes this GSO frame whole: it
/// refuses one with segments under MIN_MSS (`sanitize_rx` in link.rs),
/// which an uplink's frames and GRO runs can have.  Those go segmented.
pub fn link_takes_gso(hdr: &[u8; HDR_SIZE]) -> bool {
    get16(hdr, 4) >= MIN_MSS
}

/// Ones' complement sum of `data` (big-endian words) added to `sum`.
fn sum(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        if sum > 0xffff_0000 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    if let [b] = chunks.remainder() {
        sum += (*b as u32) << 8;
    }
    sum
}

fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

/// Complete a checksum the sender left to the device (NEEDS_CSUM): the
/// ones' complement sum from csum_start, stored at csum_start +
/// csum_offset (which holds the pseudo-header sum already).
pub fn complete_csum(frame: &mut [u8], hdr: &mut [u8; HDR_SIZE]) {
    if hdr[0] & F_NEEDS_CSUM == 0 {
        return;
    }
    let start = get16(hdr, 6);
    let at = start + get16(hdr, 8);
    if at + 2 <= frame.len() && start < frame.len() {
        let c = !fold(sum(0, &frame[start..]));
        frame[at..at + 2].copy_from_slice(&c.to_be_bytes());
    }
    hdr[0] &= !F_NEEDS_CSUM;
}

/// Split a GSO TCP frame (validated by `sanitize`) into MSS-sized frames
/// with complete checksums, built in `buf`, and pass each to `emit`.  It
/// takes any nonzero gso_size: the bound on segments is where a frame
/// comes in, MIN_MSS from senders netd does not trust (`sanitize`,
/// `sanitize_rx`); an uplink's frames and GRO runs segment back into the
/// packets that were received.
pub fn segment(frame: &[u8], hdr: &[u8; HDR_SIZE], buf: &mut [u8], mut emit: impl FnMut(&mut [u8], &mut [u8; HDR_SIZE])) {
    let Some(f) = parse_tcp(frame) else { return };
    let mss = get16(hdr, 4);
    let payload = &frame[f.hdrs..];
    // A segment's IP length must fit its 16 bits (a slot holds more).
    if mss == 0 || f.hdrs + mss > buf.len() || f.hdrs - f.ip + mss.min(payload.len()) > 0xffff {
        return;
    }
    let seq0 = u32::from_be_bytes(frame[f.tcp + 4..f.tcp + 8].try_into().unwrap());
    let flags0 = frame[f.tcp + 13];
    let id0 = u16::from_be_bytes([frame[f.ip + 4], frame[f.ip + 5]]);
    let n = payload.len().div_ceil(mss).max(1);
    for i in 0..n {
        let chunk = &payload[(i * mss).min(payload.len())..((i + 1) * mss).min(payload.len())];
        let len = f.hdrs + chunk.len();
        let out = &mut buf[..len];
        out[..f.hdrs].copy_from_slice(&frame[..f.hdrs]);
        out[f.hdrs..].copy_from_slice(chunk);
        let tcp_len = len - f.tcp;
        // IP header: lengths, IPv4 id and header checksum.
        if f.v6 {
            out[f.ip + 4..f.ip + 6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        } else {
            out[f.ip + 2..f.ip + 4].copy_from_slice(&((len - f.ip) as u16).to_be_bytes());
            out[f.ip + 4..f.ip + 6].copy_from_slice(&id0.wrapping_add(i as u16).to_be_bytes());
            out[f.ip + 10..f.ip + 12].copy_from_slice(&[0, 0]);
            let c = !fold(sum(0, &out[f.ip..f.tcp]));
            out[f.ip + 10..f.ip + 12].copy_from_slice(&c.to_be_bytes());
        }
        // TCP: sequence number; FIN and PSH only on the last segment, CWR
        // only on the first.
        let seq = seq0.wrapping_add((i * mss) as u32);
        out[f.tcp + 4..f.tcp + 8].copy_from_slice(&seq.to_be_bytes());
        let mut flags = flags0;
        if i + 1 < n {
            flags &= !0x09;
        }
        if i > 0 {
            flags &= !0x80;
        }
        out[f.tcp + 13] = flags;
        // TCP checksum over the pseudo header and the segment.
        out[f.tcp + 16..f.tcp + 18].copy_from_slice(&[0, 0]);
        let mut s = if f.v6 {
            sum(0, &out[f.ip + 8..f.ip + 40])
        } else {
            sum(0, &out[f.ip + 12..f.ip + 20])
        };
        s = sum(s, &[0, 6]);
        s += tcp_len as u32;
        let c = !fold(sum(s, &out[f.tcp..]));
        out[f.tcp + 16..f.tcp + 18].copy_from_slice(&c.to_be_bytes());
        let mut h = [0u8; HDR_SIZE];
        emit(out, &mut h);
    }
}

/// Whether a received TCP segment's checksum is known good: the device
/// says so (DATA_VALID), will not need it (NEEDS_CSUM: a partial checksum
/// from a local sender), or it checks out here.
fn csum_ok(frame: &[u8], hdr: &[u8; HDR_SIZE], f: &TcpFrame) -> bool {
    if hdr[0] & (F_NEEDS_CSUM | F_DATA_VALID) != 0 {
        return true;
    }
    if !f.v6 && fold(sum(0, &frame[f.ip..f.tcp])) != 0xffff {
        return false;
    }
    fold(sum(pseudo(frame, f, frame.len() - f.tcp), &frame[f.tcp..])) == 0xffff
}

/// Ones' complement sum of the TCP pseudo header for `tcp_len` bytes.
fn pseudo(frame: &[u8], f: &TcpFrame, tcp_len: usize) -> u32 {
    let s = if f.v6 { sum(0, &frame[f.ip + 8..f.ip + 40]) } else { sum(0, &frame[f.ip + 12..f.ip + 20]) };
    sum(s, &[0, 6]) + tcp_len as u32
}

/// Receive offload (GRO) for frames from an uplink: consecutive full-size
/// TCP segments of one flow become one GSO frame (NEEDS_CSUM, gso_size =
/// the segment size), so a guest takes one frame instead of up to 44.
/// Segments merge only where Linux's GRO would merge them, and a frame
/// on its own passes unchanged.
pub struct Gro {
    buf: [u8; 14 + 4 + GRO_MAX],
    len: usize,
    hdr: [u8; HDR_SIZE],
    f: Option<TcpFrame>,
    segs: usize,
    mss: usize,
    next_seq: u32,
    /// A short segment or PSH ended the run.
    closed: bool,
}

/// Largest merged frame: IPv4's 64 KiB total length.
const GRO_MAX: usize = 65535;

impl Gro {
    /// For the host tests; netd makes its own with init().
    #[allow(dead_code)]
    pub const fn new() -> Self {
        Gro { buf: [0; 14 + 4 + GRO_MAX], len: 0, hdr: [0; HDR_SIZE], f: None, segs: 0, mss: 0, next_seq: 0, closed: false }
    }

    /// new(), in place at `g`: a Gro is too large to build on the stack.
    pub fn init(g: &mut core::mem::MaybeUninit<Gro>) -> &mut Gro {
        let p = g.as_mut_ptr();
        unsafe {
            core::ptr::addr_of_mut!((*p).buf).write_bytes(0, 1);
            core::ptr::addr_of_mut!((*p).len).write(0);
            core::ptr::addr_of_mut!((*p).hdr).write([0; HDR_SIZE]);
            core::ptr::addr_of_mut!((*p).f).write(None);
            core::ptr::addr_of_mut!((*p).segs).write(0);
            core::ptr::addr_of_mut!((*p).mss).write(0);
            core::ptr::addr_of_mut!((*p).next_seq).write(0);
            core::ptr::addr_of_mut!((*p).closed).write(false);
            g.assume_init_mut()
        }
    }

    /// A segment that may merge: TCP with payload, only ACK/PSH set, no IP
    /// options or fragments, lengths that match the frame, a good checksum.
    fn candidate(frame: &[u8], hdr: &[u8; HDR_SIZE]) -> Option<(TcpFrame, usize)> {
        if is_gso(hdr) {
            return None;
        }
        let f = parse_tcp(frame)?;
        if f.v6 {
            if f.ip + 40 + u16::from_be_bytes([frame[f.ip + 4], frame[f.ip + 5]]) as usize != frame.len() {
                return None;
            }
        } else {
            let total = u16::from_be_bytes([frame[f.ip + 2], frame[f.ip + 3]]) as usize;
            let frag = u16::from_be_bytes([frame[f.ip + 6], frame[f.ip + 7]]);
            // Ethernet pads short frames: the IP length is the truth.
            if f.tcp != f.ip + 20 || frag & 0x3fff != 0 || f.ip + total > frame.len() || f.ip + total <= f.hdrs {
                return None;
            }
        }
        let flags = frame[f.tcp + 13];
        if flags & !0x08 != 0x10 {
            return None;
        }
        let end = if f.v6 { frame.len() } else { f.ip + u16::from_be_bytes([frame[f.ip + 2], frame[f.ip + 3]]) as usize };
        // An IPv6 datagram can be 40 bytes longer than a run may grow
        // (its payload length leaves out the header): it passes alone.
        if end <= f.hdrs || end > f.ip + GRO_MAX || !csum_ok(&frame[..end], hdr, &f) {
            return None;
        }
        Some((f, end))
    }

    /// Whether `frame` continues the run being built.
    fn continues(&self, frame: &[u8], f: &TcpFrame, payload: usize) -> bool {
        let Some(p) = self.f else { return false };
        let b = &self.buf;
        let seq = u32::from_be_bytes(frame[f.tcp + 4..f.tcp + 8].try_into().unwrap());
        !self.closed
            && p.hdrs == f.hdrs && p.tcp == f.tcp && p.ip == f.ip && p.v6 == f.v6
            && payload <= self.mss
            && self.len + payload <= p.ip + GRO_MAX
            && seq == self.next_seq
            // Ethernet header; IP header but lengths, IPv4 id and checksum.
            && b[..p.ip] == frame[..f.ip]
            && if f.v6 {
                b[p.ip..p.ip + 4] == frame[f.ip..f.ip + 4] && b[p.ip + 6..p.tcp] == frame[f.ip + 6..f.tcp]
            } else {
                b[p.ip..p.ip + 2] == frame[f.ip..f.ip + 2] && b[p.ip + 6..p.ip + 10] == frame[f.ip + 6..f.ip + 10]
                    && b[p.ip + 12..p.tcp] == frame[f.ip + 12..f.tcp]
            }
            // Ports; ACK number; window; options.
            && b[p.tcp..p.tcp + 4] == frame[f.tcp..f.tcp + 4]
            && b[p.tcp + 8..p.tcp + 12] == frame[f.tcp + 8..f.tcp + 12]
            && b[p.tcp + 14..p.tcp + 16] == frame[f.tcp + 14..f.tcp + 16]
            && b[p.tcp + 20..p.hdrs] == frame[f.tcp + 20..f.hdrs]
    }

    /// Take `frame` into the run (merging or starting one): true.  False
    /// if it cannot merge; the caller then flushes and forwards it as is.
    pub fn add(&mut self, frame: &[u8], hdr: &[u8; HDR_SIZE]) -> bool {
        let Some((f, end)) = Self::candidate(frame, hdr) else { return false };
        let payload = end - f.hdrs;
        let seq = u32::from_be_bytes(frame[f.tcp + 4..f.tcp + 8].try_into().unwrap());
        let push = frame[f.tcp + 13] & 0x08 != 0;
        if self.f.is_none() {
            self.buf[..end].copy_from_slice(&frame[..end]);
            self.len = end;
            self.hdr = *hdr;
            self.f = Some(f);
            self.segs = 1;
            self.mss = payload;
            self.next_seq = seq.wrapping_add(payload as u32);
            self.closed = push;
            return true;
        }
        if !self.continues(frame, &f, payload) {
            return false;
        }
        self.buf[self.len..self.len + payload].copy_from_slice(&frame[f.hdrs..end]);
        self.len += payload;
        self.segs += 1;
        self.next_seq = seq.wrapping_add(payload as u32);
        if push {
            self.buf[f.tcp + 13] |= 0x08;
        }
        self.closed = push || payload < self.mss;
        true
    }

    /// Pass the run built so far to `emit` (as received if it is one
    /// segment), and start afresh.
    pub fn flush(&mut self, mut emit: impl FnMut(&mut [u8], &mut [u8; HDR_SIZE])) {
        let Some(f) = self.f.take() else { return };
        let len = self.len;
        if self.segs > 1 {
            let b = &mut self.buf[..len];
            let tcp_len = len - f.tcp;
            if f.v6 {
                b[f.ip + 4..f.ip + 6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
            } else {
                b[f.ip + 2..f.ip + 4].copy_from_slice(&((len - f.ip) as u16).to_be_bytes());
                b[f.ip + 10..f.ip + 12].copy_from_slice(&[0, 0]);
                let c = !fold(sum(0, &b[f.ip..f.tcp]));
                b[f.ip + 10..f.ip + 12].copy_from_slice(&c.to_be_bytes());
            }
            // A partial checksum: the pseudo header's sum, as a TSO sender
            // leaves it.
            let p = fold(pseudo(b, &f, tcp_len));
            b[f.tcp + 16..f.tcp + 18].copy_from_slice(&p.to_be_bytes());
            let mut h = [0u8; HDR_SIZE];
            h[0] = F_NEEDS_CSUM;
            h[1] = if f.v6 { GSO_TCPV6 } else { GSO_TCPV4 };
            put16(&mut h, 2, f.hdrs);
            put16(&mut h, 4, self.mss);
            put16(&mut h, 6, f.tcp);
            put16(&mut h, 8, 16);
            self.hdr = h;
        }
        emit(&mut self.buf[..len], &mut self.hdr);
    }
}
