//! Unit tests of usbd's guest-facing checks and TRB layout
//! (host/l4h-host/src/usb.rs, through the l4h-host crate): the capability
//! walk on malformed lists, endpoint range checks, the context dwords made
//! of a guest's values, 64 KiB TRB splits and index arithmetic on wrap.
//! Run by tests/run-fuzz.sh.

#![allow(dead_code)]

use l4h_host::usb;

use l4h_abi::usb as abi;
use usb::*;

fn pool() -> Pool {
    Pool { gpa: 0x1000_0000, paddr: 0x8000_0000, size: 4 << 20 }
}

fn xfer(ty: u8, dci: u8, segs: &[(u64, u32)]) -> abi::XferReq {
    let mut r: abi::XferReq = unsafe { std::mem::zeroed() };
    r.tag = 7;
    r.slot = 1;
    r.dci = dci;
    r.ty = ty;
    r.n_segs = segs.len() as u16;
    for (i, &(gpa, len)) in segs.iter().enumerate() {
        r.segs[i] = abi::Seg { gpa, len, reserved: 0 };
        r.length = r.length.wrapping_add(len);
    }
    r
}

const EP: EpShape = EpShape { max_packet: 512, burst: 1, mult: 1, hci_1_0: true, full_speed: false, period: 1, mfindex: 0, ist: 0, cfc: true };

#[test]
fn walk_ends_on_loops_and_out_of_bounds() {
    // A list that points at itself is walked MAX_XCAPS times, no more.
    let reads = std::cell::Cell::new(0);
    let x = xcaps(|_| { reads.set(reads.get() + 1); 0x0000_0002 | 0 << 8 }, 0x40, 0x1000, 4);
    assert!(x.legacy.is_none());
    assert!(reads.get() <= 2 * MAX_XCAPS);
    // Next pointer 0xff dwords: past the BAR (0x43c), stops.
    let x = xcaps(|o| if o == 0x40 { 0xff01 } else { panic!("read {o:#x} outside the list") }, 0x40, 0x440, 4);
    assert_eq!(x.legacy, Some(0x40));
    // An offset at the very end of the BAR is not read.
    let x = xcaps(|o| panic!("read {o:#x}"), 0xff8, 0x1000, 4);
    assert!(x.legacy.is_none());
    // A misaligned first offset is not followed.
    let x = xcaps(|o| panic!("read {o:#x}"), 0x41, 0x1000, 4);
    assert!(x.legacy.is_none());
    // A self loop with a next of 0 ends.
    let x = xcaps(|o| match o { 0x40 => 0x0302_0002, 0x48 => 0x0000_0201, _ => 0 }, 0x40, 0x1000, 4);
    assert_eq!(x.port_proto[1..=4], [3, 3, 0, 0]);
}

#[test]
fn protocol_ports_bounded() {
    // USB 2 on 1-2, USB 3 claims 2-300: port 2 stays USB 2, ports beyond
    // MaxPorts are ignored, and the walk does not panic on huge counts.
    let x = xcaps(|o| match o {
        0x40 => 0x0200_0402,
        0x48 => 0x0000_0201,
        0x50 => 0x0300_0002,
        0x58 => 0x0000_ff02,
        _ => 0,
    }, 0x40, 0x1000, 8);
    assert_eq!(&x.port_proto[..10], &[0, 2, 2, 3, 3, 3, 3, 3, 3, 0]);
    // A revision other than 2 or 3 is ignored.
    let x = xcaps(|o| match o { 0x40 => 0x0100_0002, 0x48 => 0x0000_0101, _ => 0 }, 0x40, 0x1000, 8);
    assert_eq!(x.port_proto[1], 0);
}

#[test]
fn endpoint_ranges() {
    let ep = |dci, ty, mps, burst_mult, interval, esit| abi::Ep { dci, ty, interval, burst_mult, max_packet: mps, max_esit: esit };
    assert!(ep_ok(&ep(2, abi::EP_BULK_OUT, 512, 0, 0, 0), abi::SPEED_HIGH));
    assert!(!ep_ok(&ep(2, abi::EP_BULK_OUT, 1024, 0, 0, 0), abi::SPEED_HIGH));
    assert!(ep_ok(&ep(3, abi::EP_BULK_IN, 1024, 15, 0, 0), abi::SPEED_SUPER));
    assert!(!ep_ok(&ep(3, abi::EP_BULK_IN, 1024, 16, 0, 0), abi::SPEED_SUPER), "burst > 15");
    assert!(!ep_ok(&ep(2, abi::EP_BULK_IN, 1024, 0, 0, 0), abi::SPEED_SUPER), "IN on an OUT DCI");
    assert!(!ep_ok(&ep(32, abi::EP_BULK_IN, 1024, 0, 0, 0), abi::SPEED_SUPER));
    assert!(!ep_ok(&ep(1, abi::EP_CONTROL, 64, 0, 0, 0), abi::SPEED_FULL), "ep0 is not configured");
    assert!(ep_ok(&ep(3, abi::EP_INT_IN, 8, 0, 3, 8), abi::SPEED_LOW));
    assert!(!ep_ok(&ep(3, abi::EP_INT_IN, 9, 0, 3, 8), abi::SPEED_LOW));
    assert!(!ep_ok(&ep(3, abi::EP_INT_IN, 8, 0, 16, 8), abi::SPEED_LOW), "interval > 15");
    assert!(!ep_ok(&ep(3, abi::EP_INT_IN, 8, 0, 3, 9), abi::SPEED_LOW), "ESIT beyond a packet");
    // SuperSpeed interrupt bursts up to 16 packets of 1024; high speed
    // has at most 2 more transactions.
    assert!(ep_ok(&ep(3, abi::EP_INT_IN, 1024, 3, 0, 4096), abi::SPEED_SUPER));
    assert!(ep_ok(&ep(3, abi::EP_INT_IN, 1024, 15, 0, 16384), abi::SPEED_SUPER));
    assert!(!ep_ok(&ep(3, abi::EP_INT_IN, 512, 3, 0, 2048), abi::SPEED_SUPER), "burst needs 1024");
    assert!(!ep_ok(&ep(3, abi::EP_INT_IN, 1024, 0x13, 0, 4096), abi::SPEED_SUPER), "mult on interrupt");
    assert!(!ep_ok(&ep(3, abi::EP_INT_IN, 1024, 3, 0, 4096), abi::SPEED_HIGH));
    // SuperSpeed isoch: 3 x 16 x 1024.
    assert!(ep_ok(&ep(5, abi::EP_ISOC_IN, 1024, 0x2f, 0, 49152), abi::SPEED_SUPER));
    assert!(!ep_ok(&ep(5, abi::EP_ISOC_IN, 1024, 0x3f, 0, 0), abi::SPEED_SUPER), "mult 3");
    assert!(!ep_ok(&ep(5, abi::EP_ISOC_IN, 1023, 0x2f, 0, 0), abi::SPEED_SUPER), "burst needs 1024");
    // High bandwidth high speed isoch: 3 x 1024.
    assert!(ep_ok(&ep(4, abi::EP_ISOC_OUT, 1024, 2, 0, 3072), abi::SPEED_HIGH));
    assert!(!ep_ok(&ep(4, abi::EP_ISOC_OUT, 1024, 3, 0, 0), abi::SPEED_HIGH));
    // Zero-bandwidth alternate setting.
    assert!(ep_ok(&ep(4, abi::EP_ISOC_OUT, 0, 0, 3, 0), abi::SPEED_FULL));
    assert!(!ep_ok(&ep(4, abi::EP_ISOC_OUT, 1023, 0, 0, 0), abi::SPEED_LOW));
    assert!(!ep_ok(&ep(4, 0, 64, 0, 0, 0), abi::SPEED_FULL), "no type");
    assert!(!ep_ok(&ep(4, abi::EP_BULK_OUT, 64, 0, 0, 0), 9), "no speed");
}

#[test]
fn endpoint_intervals() {
    let ep = |dci, ty, mps, interval, esit| abi::Ep { dci, ty, interval, burst_mult: 0, max_packet: mps, max_esit: esit };
    // Low and full speed interrupt: 1 to 128 frames (2^3..2^10 microframes).
    for (interval, ok) in [(0, false), (2, false), (3, true), (10, true), (11, false), (15, false)] {
        assert_eq!(ep_ok(&ep(3, abi::EP_INT_IN, 8, interval, 8), abi::SPEED_LOW), ok, "LS interrupt {interval}");
        assert_eq!(ep_ok(&ep(3, abi::EP_INT_IN, 64, interval, 64), abi::SPEED_FULL), ok, "FS interrupt {interval}");
    }
    // Full speed isoch: from a frame.
    for (interval, ok) in [(0, false), (2, false), (3, true), (15, true), (16, false)] {
        assert_eq!(ep_ok(&ep(5, abi::EP_ISOC_IN, 1023, interval, 1023), abi::SPEED_FULL), ok, "FS isoch {interval}");
    }
    // High speed and SuperSpeed periodic: any 2^0..2^15 microframes.
    for speed in [abi::SPEED_HIGH, abi::SPEED_SUPER, abi::SPEED_SUPER_PLUS] {
        for (interval, ok) in [(0, true), (15, true), (16, false), (255, false)] {
            assert_eq!(ep_ok(&ep(3, abi::EP_INT_IN, 1024, interval, 1024), speed), ok, "interrupt {interval} at {speed}");
            assert_eq!(ep_ok(&ep(5, abi::EP_ISOC_IN, 1024, interval, 1024), speed), ok, "isoch {interval} at {speed}");
        }
    }
    // Bulk: a NAK rate at high speed, nothing elsewhere.
    assert!(ep_ok(&ep(2, abi::EP_BULK_OUT, 512, 7, 0), abi::SPEED_HIGH));
    assert!(!ep_ok(&ep(2, abi::EP_BULK_OUT, 512, 16, 0), abi::SPEED_HIGH));
    assert!(!ep_ok(&ep(2, abi::EP_BULK_OUT, 64, 1, 0), abi::SPEED_FULL));
    assert!(!ep_ok(&ep(2, abi::EP_BULK_OUT, 1024, 1, 0), abi::SPEED_SUPER));
    assert!(interval_ok(abi::EP_CONTROL, 0, abi::SPEED_FULL) && !interval_ok(abi::EP_CONTROL, 3, abi::SPEED_FULL));
}

fn address(route: u32, speed: u32, tt_slot: u32, tt_port: u32, mtt: u32, mps: u32, bsr: u32) -> Address {
    Address { route, speed, tt_slot, tt_port, mtt, mps, bsr }
}

#[test]
fn address_names_no_interrupter() {
    // A device on a root port, and a full speed one behind a TT.
    let a = address(0, abi::SPEED_HIGH, 0, 0, 0, 64, 0);
    assert!(a.ok());
    assert_eq!(a.slot_ctx(5), [abi::SPEED_HIGH << 20 | 1 << 27, 5 << 16, 0]);
    let a = address(0x21, abi::SPEED_FULL, 3, 4, 1, 8, 1);
    assert!(a.ok());
    assert_eq!(a.slot_ctx(2), [0x21 | abi::SPEED_FULL << 20 | 1 << 25 | 1 << 27, 2 << 16, 3 | 4 << 8]);
    // Without a TT hub the TT port is not the guest's to set: it would
    // reach the TT think time and the Interrupter Target (bits 16..31).
    for tt_port in [1, 0x100, 1 << 14, 0x3f_c000, u32::MAX] {
        assert!(!address(0, abi::SPEED_HIGH, 0, tt_port, 0, 64, 0).ok(), "TT port {tt_port:#x} without a TT");
    }
    assert!(!address(0, abi::SPEED_HIGH, 0, 0, 1, 64, 0).ok(), "multi-TT without a TT");
    // With one: a slot and a port of eight bits each.
    assert!(!address(0, abi::SPEED_FULL, 3, 0, 0, 8, 0).ok());
    assert!(!address(0, abi::SPEED_FULL, 3, 256, 0, 8, 0).ok());
    assert!(!address(0, abi::SPEED_FULL, 256, 1, 0, 8, 0).ok());
    assert!(!address(0, abi::SPEED_FULL, 3, 1, 2, 8, 0).ok());
    // The other fields.
    assert!(!address(0x100000, abi::SPEED_HIGH, 0, 0, 0, 64, 0).ok());
    assert!(!address(0, 0, 0, 0, 0, 64, 0).ok());
    assert!(!address(0, 6, 0, 0, 0, 512, 0).ok());
    assert!(!address(0, abi::SPEED_HIGH, 0, 0, 0, 8, 0).ok());
    assert!(!address(0, abi::SPEED_HIGH, 0, 0, 0, 64, 2).ok());
    // Whatever the fields, the dwords carry nothing but the bits usbd
    // gives a controller.
    let a = address(u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX);
    let dw = a.slot_ctx(255);
    assert_eq!(dw[2] >> 16, 0, "TT think time or Interrupter Target");
    assert_eq!((dw[0] & !SLOT_CTX_BITS[0], dw[1] & !SLOT_CTX_BITS[1], dw[2] & !SLOT_CTX_BITS[2]), (0, 0, 0));
    assert_eq!(dw[0] >> 27, 1, "context entries");
}

#[test]
fn slot_context_copies_are_masked() {
    // What the controller wrote in an output context goes back without
    // the reserved bits, a Max Exit Latency or an Interrupter Target.
    assert_eq!(slot_ctx([u32::MAX; 3]), [!(1 << 24), 0xffff_0000, 0x3_ffff]);
    let out = [0x0830_0021, 0x0402_0000, 0x0002_0403];
    assert_eq!(slot_ctx(out), out);
}

#[test]
fn hub_contexts() {
    let sc = [abi::SPEED_HIGH << 20 | 1 << 27, 3 << 16, 0];
    // A high speed hub with seven ports and a think time, on xHCI 1.0.
    assert_eq!(hub_slot_ctx(sc, abi::SPEED_HIGH, 0x100, 7, 2, 0), Some([sc[0] | 1 << 26, 3 << 16 | 7 << 24, 2 << 16]));
    // Multi-TT; a SuperSpeed hub has no think time from 1.0; 0.95 takes neither.
    assert_eq!(hub_slot_ctx(sc, abi::SPEED_HIGH, 0x100, 4, 0, 1).unwrap()[0], sc[0] | 1 << 26 | 1 << 25);
    assert_eq!(hub_slot_ctx(sc, abi::SPEED_SUPER, 0x100, 4, 3, 0).unwrap()[2], 0);
    assert_eq!(hub_slot_ctx(sc, abi::SPEED_HIGH, 0x95, 4, 3, 0), Some([sc[0] | 1 << 26, sc[1], 0]));
    // A full speed hub loses a stale multi-TT bit.
    assert_eq!(hub_slot_ctx([sc[0] | 1 << 25, sc[1], 0], abi::SPEED_FULL, 0x100, 4, 0, 0).unwrap()[0] & (1 << 25), 0);
    // Out of range.
    assert_eq!(hub_slot_ctx(sc, abi::SPEED_HIGH, 0x100, 256, 0, 0), None);
    assert_eq!(hub_slot_ctx(sc, abi::SPEED_HIGH, 0x100, 4, 4, 0), None);
    assert_eq!(hub_slot_ctx(sc, abi::SPEED_HIGH, 0x100, 4, 0, 2), None);
    assert_eq!(hub_slot_ctx(sc, 0, 0x100, 4, 0, 0), None, "not addressed");
    // Nothing the context held beyond usbd's bits survives.
    let dw = hub_slot_ctx([u32::MAX; 3], abi::SPEED_HIGH, 0x100, 255, 3, 1).unwrap();
    assert_eq!(dw, slot_ctx(dw));
    assert_eq!(dw[2] >> 18, 0);
}

#[test]
fn stream_counts() {
    // A primary stream array has 2^(MaxPStreams+1) entries, MaxPStreams 0
    // is no streams: 2 cannot be asked for.
    for (count, max, ok) in [(0, 16, false), (1, 16, false), (2, 16, false), (3, 16, false), (4, 16, true), (8, 16, true),
        (16, 16, true), (32, 16, false), (12, 16, false), (4, 0, false), (8, 4, false), (u32::MAX, 16, false), (1 << 31, u32::MAX, true)] {
        assert_eq!(streams_ok(count, max), ok, "{count} of {max}");
    }
    let bulk = abi::Ep { dci: 3, ty: abi::EP_BULK_IN, interval: 0, burst_mult: 15, max_packet: 1024, max_esit: 0 };
    // No streams: a transfer ring, MaxPStreams 0, no linear array.
    assert_eq!(ep_ctx(&bulk, 0)[0], 0);
    for (count, pstreams) in [(4, 1), (8, 2), (16, 3)] {
        assert!(streams_ok(count, 16));
        let dw0 = ep_ctx(&bulk, count)[0];
        assert_eq!(((dw0 >> 10) & 0x1f, dw0 & (1 << 15)), (pstreams, 1 << 15), "{count} streams");
        assert_eq!(2 << ((dw0 >> 10) & 0x1f), count, "array entries");
    }
}

#[test]
fn endpoint_contexts() {
    // SuperSpeed isoch IN, 3 x 16 x 1024 every 2^4 microframes.
    let e = abi::Ep { dci: 5, ty: abi::EP_ISOC_IN, interval: 4, burst_mult: 0x2f, max_packet: 1024, max_esit: 49152 };
    assert!(ep_ok(&e, abi::SPEED_SUPER));
    assert_eq!(ep_ctx(&e, 0), [2 << 8 | 4 << 16, (abi::EP_ISOC_IN as u32) << 3 | 15 << 8 | 1024 << 16, 49152 | 49152 << 16]);
    // High speed bulk OUT: three retries, Linux's average TRB length.
    let e = abi::Ep { dci: 2, ty: abi::EP_BULK_OUT, interval: 0, burst_mult: 0, max_packet: 512, max_esit: 0 };
    assert_eq!(ep_ctx(&e, 0), [0, 3 << 1 | (abi::EP_BULK_OUT as u32) << 3 | 512 << 16, 3072]);
    assert_eq!(ep0_ctx_dw1(64), 3 << 1 | (abi::EP_CONTROL as u32) << 3 | 64 << 16);
    // Whatever the record, no reserved bit and no Host Initiate Disable:
    // dword 0 bits 0..7 (the state is the controller's) and 24..31 (usbd
    // has no ESIT payload beyond 16 bits), dword 1 bits 0, 6 and 7.
    let e = abi::Ep { dci: 31, ty: 0xff, interval: 0xff, burst_mult: 0xff, max_packet: 0xffff, max_esit: 0xffff };
    let dw = ep_ctx(&e, u32::MAX);
    assert_eq!(dw[0] & 0x0000_00ff, 0);
    assert_eq!(dw[1] & 0xc1, 0);
    // ep0's packet sizes.
    for (speed, mps, ok) in [(abi::SPEED_LOW, 8, true), (abi::SPEED_LOW, 64, false), (abi::SPEED_FULL, 16, true), (abi::SPEED_FULL, 24, false),
        (abi::SPEED_HIGH, 64, true), (abi::SPEED_HIGH, 512, false), (abi::SPEED_SUPER, 512, true), (abi::SPEED_SUPER_PLUS, 512, true),
        (abi::SPEED_SUPER, 64, false), (0, 8, false), (0, 512, false), (6, 512, false)] {
        assert_eq!(ep0_mps_ok(speed, mps), ok, "speed {speed} mps {mps}");
    }
}

#[test]
fn endpoint_set_never_fills() {
    let mut set = EpSet::new();
    assert_eq!(set.pop(), None);
    // One entry an endpoint, however often it is added.
    for _ in 0..1000 {
        set.insert(3, 4);
        set.insert(1, 31);
    }
    assert_eq!((set.pop(), set.pop(), set.pop()), (Some((1, 31)), Some((3, 4)), None));
    // Every endpoint there is, at once.
    for slot in 1..=MAX_SLOTS as usize {
        for dci in 1..32 {
            set.insert(slot, dci);
        }
    }
    let mut n = 0;
    let mut last = (0, 0);
    while let Some(e) = set.pop() {
        assert!(e > last && (1..=MAX_SLOTS as usize).contains(&e.0) && (1..32).contains(&e.1));
        last = e;
        n += 1;
    }
    assert_eq!(n, MAX_SLOTS as usize * 31);
    // Nothing outside the table, and clear empties it.
    for (slot, dci) in [(0, 1), (MAX_SLOTS as usize + 1, 1), (1, 0), (1, 32), (usize::MAX, usize::MAX)] {
        set.insert(slot, dci);
    }
    assert_eq!(set.pop(), None);
    set.insert(2, 2);
    set.clear();
    assert_eq!(set.pop(), None);
}

#[test]
fn routes() {
    assert!(route_ok(0));
    assert!(route_ok(0x54321));
    assert!(route_ok(0xfffff));
    assert!(!route_ok(0x100000), "6 tiers");
    assert!(!route_ok(0x10), "port after an end");
    assert!(!route_ok(0x01020), "port after an end");
}

#[test]
fn segments_must_lie_in_the_pool() {
    let p = pool();
    let ok = xfer(abi::XFER_BULK, 2, &[(p.gpa, 4096), (p.gpa + p.size - 512, 512)]);
    let x = check_xfer(&ok, &p, MAX_TRANSFER).unwrap();
    assert_eq!(x.segs[0], (p.paddr, 4096));
    assert_eq!(x.segs[1], (p.paddr + p.size - 512, 512));
    for bad in [
        vec![(p.gpa - 1, 2)],
        vec![(p.gpa + p.size - 511, 512)],
        vec![(p.gpa + p.size, 1)],
        vec![(u64::MAX - 10, 100)],
        vec![(0, 4096)],
        vec![(p.gpa, 0)],
    ] {
        assert_eq!(check_xfer(&xfer(abi::XFER_BULK, 2, &bad), &p, MAX_TRANSFER).err(), Some(abi::ST_INVALID), "{bad:x?}");
    }
    // Lengths that overflow, lengths beyond the maximum, a length that
    // disagrees with the segments.
    let mut r = xfer(abi::XFER_BULK, 2, &[(p.gpa, 0x8000_0000), (p.gpa, 0x8000_0000)]);
    r.length = 0;
    assert!(check_xfer(&r, &p, MAX_TRANSFER).is_err());
    let r = xfer(abi::XFER_BULK, 2, &[(p.gpa, MAX_TRANSFER + 1)]);
    assert!(check_xfer(&r, &Pool { size: 1 << 30, ..p }, MAX_TRANSFER).is_err());
    let mut r = xfer(abi::XFER_BULK, 2, &[(p.gpa, 512)]);
    r.length = 1024;
    assert!(check_xfer(&r, &p, MAX_TRANSFER).is_err());
    let mut r = xfer(abi::XFER_BULK, 2, &[(p.gpa, 512)]);
    r.n_segs = abi::MAX_SEGS as u16 + 1;
    assert!(check_xfer(&r, &p, MAX_TRANSFER).is_err());
}

#[test]
fn types_directions_and_isoch_packets() {
    let p = pool();
    // ep0 carries control transfers only.
    assert!(check_xfer(&xfer(abi::XFER_BULK, 1, &[]), &p, MAX_TRANSFER).is_err());
    assert!(check_xfer(&xfer(abi::XFER_CONTROL, 2, &[]), &p, MAX_TRANSFER).is_err());
    let mut c = xfer(abi::XFER_CONTROL, 1, &[(p.gpa, 18)]);
    c.setup = [0x80, 6, 0, 1, 0, 0, 18, 0];
    c.flags = abi::XF_IN;
    assert!(check_xfer(&c, &p, MAX_TRANSFER).is_ok());
    c.flags = 0;
    assert!(check_xfer(&c, &p, MAX_TRANSFER).is_err(), "data direction against the setup packet");
    c.flags = abi::XF_IN;
    c.setup[6] = 17;
    assert!(check_xfer(&c, &p, MAX_TRANSFER).is_err(), "more data than wLength");
    let mut i = xfer(abi::XFER_ISOC, 3, &[(p.gpa, 3000)]);
    i.n_iso = 3;
    i.iso[0] = abi::Iso { offset: 0, len: 1000 };
    i.iso[1] = abi::Iso { offset: 1000, len: 1000 };
    i.iso[2] = abi::Iso { offset: 2000, len: 1000 };
    assert!(check_xfer(&i, &p, MAX_TRANSFER).is_ok());
    i.iso[2] = abi::Iso { offset: 2001, len: 1000 };
    assert!(check_xfer(&i, &p, MAX_TRANSFER).is_err());
    i.iso[2] = abi::Iso { offset: u32::MAX, len: 2 };
    assert!(check_xfer(&i, &p, MAX_TRANSFER).is_err());
    i.n_iso = 49;
    assert!(check_xfer(&i, &p, MAX_TRANSFER).is_err());
    i.n_iso = 0;
    assert!(check_xfer(&i, &p, MAX_TRANSFER).is_err(), "isoch without packets");
    let mut b = xfer(abi::XFER_BULK, 2, &[(p.gpa, 1)]);
    b.n_iso = 1;
    assert!(check_xfer(&b, &p, MAX_TRANSFER).is_err(), "packets on bulk");
    b.n_iso = 0;
    b.flags = 1 << 7;
    assert!(check_xfer(&b, &p, MAX_TRANSFER).is_err(), "unknown flags");
}

fn trbs(x: &Xfer, ep: &EpShape) -> (Trbs, TdEnds) {
    let (mut t, mut e) = (Trbs::new(), TdEnds::new());
    build_trbs(x, ep, &mut t, &mut e).unwrap();
    (t, e)
}

#[test]
fn trbs_split_at_64k_and_segments() {
    let p = Pool { gpa: 0x1000_0000, paddr: 0x8000_f000, size: 4 << 20 };
    // 0x8000_f000 + 0x30000: crosses 64 KiB boundaries at 0x8001_0000,
    // 0x8002_0000, 0x8003_0000.
    let x = check_xfer(&xfer(abi::XFER_BULK, 2, &[(p.gpa, 0x30000), (p.gpa + 0x100000, 100)]), &p, MAX_TRANSFER).unwrap();
    let (t, ends) = trbs(&x, &EP);
    let lens: Vec<u32> = t.iter().map(|t| t.len()).collect();
    assert_eq!(lens, [0x1000, 0x10000, 0x10000, 0xf000, 100]);
    for t in t.iter() {
        assert_eq!(t.param >> 16, (t.param + t.len() as u64 - 1) >> 16, "TRB crosses 64 KiB");
    }
    assert_eq!(&ends[..], &[4]);
    assert!(t[..4].iter().all(|t| t.control & TRB_CH != 0));
    assert_eq!(t[4].control & (TRB_CH | TRB_IOC), TRB_IOC);
    // TD Size: packets left after each TRB, 0 on the last.
    assert_eq!(t[4].status >> 17, 0);
    assert_eq!(t[0].status >> 17, ((0x30000 + 100u32).div_ceil(512) - 0x1000 / 512).min(31));
}

#[test]
fn control_and_zero_length_trbs() {
    let p = pool();
    let mut c = xfer(abi::XFER_CONTROL, 1, &[(p.gpa, 18)]);
    c.setup = [0x80, 6, 0, 1, 0, 0, 18, 0];
    c.flags = abi::XF_IN;
    let (t, ends) = trbs(&check_xfer(&c, &p, MAX_TRANSFER).unwrap(), &EpShape { max_packet: 64, ..EP });
    assert_eq!(t.iter().map(|t| t.ty()).collect::<Vec<_>>(), [TRB_SETUP, TRB_DATA, TRB_STATUS]);
    assert_eq!(t[0].control & TRB_IDT, TRB_IDT);
    assert_eq!(t[0].control >> 16 & 3, 3, "IN data stage");
    assert_eq!(t[1].control & TRB_DIR_IN, TRB_DIR_IN);
    assert_eq!(t[2].control & TRB_DIR_IN, 0, "status stage OUT after IN data");
    assert_eq!(&ends[..], &[2]);
    // No data: the status stage is IN.
    let mut c = xfer(abi::XFER_CONTROL, 1, &[]);
    c.setup = [0, 5, 3, 0, 0, 0, 0, 0];
    let (t, _) = trbs(&check_xfer(&c, &p, MAX_TRANSFER).unwrap(), &EP);
    assert_eq!(t.len(), 2);
    assert_eq!(t[1].control & TRB_DIR_IN, TRB_DIR_IN);
    // A zero-length bulk transfer, and a zero-length packet after a
    // whole number of packets.
    let (t, _) = trbs(&check_xfer(&xfer(abi::XFER_BULK, 2, &[]), &p, MAX_TRANSFER).unwrap(), &EP);
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].len(), 0);
    let mut z = xfer(abi::XFER_BULK, 2, &[(p.gpa, 1024)]);
    z.flags = abi::XF_ZERO_PACKET;
    let (t, ends) = trbs(&check_xfer(&z, &p, MAX_TRANSFER).unwrap(), &EP);
    assert_eq!(t.iter().map(|t| t.len()).collect::<Vec<_>>(), [1024, 0]);
    // A TD of its own: the data TD ends before it, the URB with it.
    assert_eq!(&ends[..], &[0, 1]);
    assert_eq!(t[0].control & (TRB_CH | TRB_IOC), 0);
    assert_eq!(t[1].control & (TRB_CH | TRB_IOC), TRB_IOC);
}

#[test]
fn isoch_tds() {
    let p = pool();
    let mut i = xfer(abi::XFER_ISOC, 3, &[(p.gpa, 3 * 192)]);
    i.flags = abi::XF_IN | abi::XF_ISO_ASAP;
    i.n_iso = 3;
    for k in 0..3 {
        i.iso[k] = abi::Iso { offset: 192 * k as u32, len: 192 };
    }
    let (t, ends) = trbs(&check_xfer(&i, &p, MAX_TRANSFER).unwrap(), &EpShape { max_packet: 192, ..EP });
    assert_eq!(&ends[..], &[0, 1, 2]);
    assert!(t.iter().all(|t| t.ty() == TRB_ISOCH && t.control & TRB_SIA != 0 && t.control & TRB_IOC != 0));
    assert_eq!(t[0].control & TRB_BEI, TRB_BEI);
    assert_eq!(t[2].control & TRB_BEI, 0);
}

#[test]
fn isoch_frame_ids() {
    // High speed, interval 1 microframe, from microframe 80: frames 10, 10.
    let hs = EpShape { max_packet: 192, period: 1, ..EP };
    assert_eq!((0..9).map(|k| iso_frame(&hs, 80, k)).collect::<Vec<_>>(), [10, 10, 10, 10, 10, 10, 10, 10, 11]);
    // High speed, every 4 microframes: two packets a frame.
    let hs4 = EpShape { period: 4, ..hs };
    assert_eq!((0..4).map(|k| iso_frame(&hs4, 80, k)).collect::<Vec<_>>(), [10, 10, 11, 11]);
    // Full speed, every frame (8 microframes), start in frames; wraps at 2048.
    let fs = EpShape { full_speed: true, period: 8, ..hs };
    assert_eq!((0..3).map(|k| iso_frame(&fs, 2047, k)).collect::<Vec<_>>(), [2047, 0, 1]);
    // In the TRBs: a non-ASAP high-speed URB from microframe 80.
    let p = pool();
    let mut i = xfer(abi::XFER_ISOC, 3, &[(p.gpa, 2 * 192)]);
    i.flags = abi::XF_IN;
    i.start_frame = 80;
    i.n_iso = 2;
    for k in 0..2 {
        i.iso[k] = abi::Iso { offset: 192 * k as u32, len: 192 };
    }
    let x = check_xfer(&i, &p, MAX_TRANSFER).unwrap();
    let (t, _) = trbs(&x, &hs);
    assert_eq!(t.iter().map(|t| (t.control >> 20) & 0x7ff).collect::<Vec<_>>(), [10, 10]);
    assert!(t.iter().all(|t| t.control & TRB_SIA == 0));
    // Without CFC, or outside the valid window (MFINDEX 800: frames 101
    // on), as soon as possible.
    let (t, _) = trbs(&x, &EpShape { cfc: false, ..hs });
    assert!(t.iter().all(|t| t.control & TRB_SIA != 0));
    let (t, _) = trbs(&x, &EpShape { mfindex: 800, ..hs });
    assert!(t.iter().all(|t| t.control & TRB_SIA != 0));
}

#[test]
fn isoch_schedule() {
    // High speed, IST 2 microframes, MFINDEX 100: 100 + 2 + 10 rounded up
    // to a frame, then to the 32-microframe interval.
    let hs = EpShape { max_packet: 192, period: 32, ist: 2, mfindex: 100, ..EP };
    assert_eq!(iso_start(&hs), 128);
    assert!(iso_frame_ok(&hs, iso_frame(&hs, iso_start(&hs), 0)));
    // The next URB of 3 packets follows, wrapping at 2048 frames.
    assert_eq!(iso_next(&hs, 128, 3), 224);
    assert_eq!(iso_next(&hs, 0x3fe0, 1), 0);
    // Full speed, every 4 frames, in frames.
    let fs = EpShape { full_speed: true, period: 32, ..hs };
    assert_eq!(iso_start(&fs), 16);
    assert_eq!(iso_next(&fs, 2046, 1), 2);
    // The window, across the wrap: MFINDEX in frame 2000 reaches 847.
    let w = EpShape { mfindex: 2000 << 3, ist: 0, ..hs };
    assert!(iso_frame_ok(&w, 2001) && iso_frame_ok(&w, 0) && iso_frame_ok(&w, 847));
    assert!(!iso_frame_ok(&w, 2000) && !iso_frame_ok(&w, 848));
}

#[test]
fn link_alignment() {
    // The reviewer's case: 64 + 448 bytes of one 512-byte packet.
    let p = pool();
    let x = check_xfer(&xfer(abi::XFER_BULK, 2, &[(p.gpa, 64), (p.gpa + 0x1000, 448)]), &p, MAX_TRANSFER).unwrap();
    let (t, ends) = trbs(&x, &EP);
    assert_eq!(t.len(), 2);
    assert!(!link_ok(&t, &ends, 1, 512));
    // Nothing, or all of it, before the link.
    assert!(link_ok(&t, &ends, 0, 512) && link_ok(&t, &ends, 2, 512));
    // Whole packets before the link.
    let x = check_xfer(&xfer(abi::XFER_BULK, 2, &[(p.gpa, 1024), (p.gpa + 0x1000, 448)]), &p, MAX_TRANSFER).unwrap();
    let (t, ends) = trbs(&x, &EP);
    assert!(link_ok(&t, &ends, 1, 512));
    // At a TD boundary of an isoch URB, whatever the bytes.
    let mut i = xfer(abi::XFER_ISOC, 3, &[(p.gpa, 2 * 100)]);
    i.flags = abi::XF_IN | abi::XF_ISO_ASAP;
    i.n_iso = 2;
    for k in 0..2 {
        i.iso[k] = abi::Iso { offset: 100 * k as u32, len: 100 };
    }
    let (t, ends) = trbs(&check_xfer(&i, &p, MAX_TRANSFER).unwrap(), &EpShape { max_packet: 192, ..EP });
    assert!(link_ok(&t, &ends, 1, 192));
}

#[test]
fn too_many_trbs_refused() {
    // 64 segments, each crossing several 64 KiB boundaries, beyond
    // MAX_URB_TRBS.
    let p = Pool { gpa: 0, paddr: 0x10_0800, size: 64 << 20 };
    let segs: Vec<(u64, u32)> = (0..64).map(|i| (i * 0x10_0000, 0x3_0000)).collect();
    let x = check_xfer(&xfer(abi::XFER_BULK, 2, &segs), &p, 32 << 20).unwrap();
    let (mut t, mut e) = (Trbs::new(), TdEnds::new());
    assert_eq!(build_trbs(&x, &EP, &mut t, &mut e), Err(abi::ST_INVALID));
}

#[test]
fn indices_wrap() {
    let sq = Sq { tail: u32::MAX - 1, size: 32 };
    assert_eq!(sq.avail(u32::MAX - 1), Some(0));
    assert_eq!(sq.avail(3), Some(5));
    assert_eq!(sq.avail(30), Some(32));
    assert_eq!(sq.avail(31), None, "beyond the queue");
    assert_eq!(sq.avail(u32::MAX - 2), None, "behind our tail");
    let cq = Cq { head: 2, size: 256 };
    assert_eq!(cq.room(2), Some(256));
    assert_eq!(cq.room(u32::MAX - 253), Some(0));
    assert_eq!(cq.room(u32::MAX - 254), None, "more than the queue holds");
    assert_eq!(cq.room(3), None, "tail ahead of our head");
}

#[test]
fn port_writes_only_allowed_bits() {
    let allowed = (1 << 1) | (1 << 4) | (1 << 5 | 0xf << 5) | (1 << 9) | (1 << 16) | (0x7f << 17) | (7 << 25) | (1 << 31);
    for set in [false, true] {
        for f in 0..16 {
            for v in [0, 1, 3, 4, 5, 15, 0x7f << 17, 0xffff_ffff] {
                for usb3 in [false, true] {
                    if let Some(b) = portsc_write(set, f, v, usb3) {
                        assert_eq!(b & !allowed, 0, "set {set} feature {f} value {v:#x}");
                        let w = portsc_value(0xffff_ffff, set, f, b);
                        assert_eq!(w & !(allowed | PORTSC_PRESERVE), 0);
                    }
                }
            }
        }
    }
    assert!(portsc_write(true, abi::PF_WARM_RESET, 0, false).is_none(), "warm reset of a USB 2 port");
    assert!(portsc_write(true, abi::PF_LINK_STATE, 15, true).is_none());
    assert!(portsc_write(false, abi::PF_CHANGE, 1 << 16, true).is_none());
    // Clearing a change bit writes it, and no other change bit.
    let csc = 1 << 17;
    let w = portsc_value(0x7f << 17 | 1 << 9, false, abi::PF_CHANGE, portsc_write(false, abi::PF_CHANGE, csc, true).unwrap());
    assert_eq!(w & (0x7f << 17), csc);
    assert_eq!(w & (1 << 9), 1 << 9, "power kept");
}

#[test]
fn dma_region_sizes() {
    assert_eq!(dma_bytes(32, 0, 4096), 4 << 20);
    assert_eq!(dma_bytes(255, 1023, 4096).count_ones(), 1);
    assert!(dma_bytes(64, 256, 4096) >= FIXED_BYTES + 64 * 4096 + USB_RINGS * RING_BYTES + 257 * 4096);
}
