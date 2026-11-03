#[allow(dead_code)]
#[path = "../host/l4h-host/src/blk.rs"]
mod blk;
use blk::*;

fn pool() -> Pool { Pool { gpa: 0x8000000, paddr: 0x10000000, size: 4 << 20 } }
fn window() -> DiskWindow { DiskWindow::new(2048, 16384, 131072).unwrap() }
fn request() -> Req {
    let mut req = Req { op: OP_READ, nr_segs: 1, ..Default::default() };
    req.segs[0] = Seg { gpa: pool().gpa, len: 4096, flags: SEG_WRITE };
    req
}

#[test]
fn finite_aligned_nonoverlapping_windows() {
    assert!(DiskWindow::new(1, 8, 1024).is_none());
    assert!(DiskWindow::new(8, 7, 1024).is_none());
    assert!(DiskWindow::new(1024, 0, 1024).is_none());
    assert!(DiskWindow::new(u64::MAX - 7, 16, u64::MAX).is_none());
    assert_eq!(DiskWindow::new(8, 0, 1024).unwrap().sectors, 1016);
    let a = window();
    let b = DiskWindow::new(a.start + a.sectors, 8, 131072).unwrap();
    assert!(!a.overlaps(b));
    assert!(a.overlaps(DiskWindow::new(a.start + a.sectors - 8, 8, 131072).unwrap()));
}

#[test]
fn only_read_only_windows_share_sectors() {
    let a = window();
    let inside = DiskWindow::new(a.start + 8, 8, 131072).unwrap();
    let after = DiskWindow::new(a.start + a.sectors, 8, 131072).unwrap();
    assert!(!a.conflicts(true, a, true));
    assert!(!a.conflicts(true, inside, true));
    assert!(a.conflicts(false, a, true));
    assert!(a.conflicts(true, inside, false));
    assert!(a.conflicts(false, inside, false));
    assert!(!a.conflicts(false, after, false));
}

#[test]
fn channels_fit_their_stride() {
    assert!(MAX_CLIENTS >= 512);
    assert!(CHANNEL_PAGES * 4096 <= CHANNEL_STRIDE);
    assert!(channel_va(MAX_CLIENTS - 1) + CHANNEL_STRIDE > channel_va(MAX_CLIENTS - 1));
}

#[test]
fn request_bounds_include_last_block_and_reject_wraparound() {
    let mut r = request();
    assert_eq!(window().check_request(&r, pool(), 4096, false), Ok(2048));
    r.sector = window().sectors - 8;
    assert!(window().check_request(&r, pool(), 4096, false).is_ok());
    for sector in [window().sectors, window().sectors - 1, u64::MAX, u64::MAX - 7] {
        r.sector = sector;
        assert!(window().check_request(&r, pool(), 4096, false).is_err());
    }
}

#[test]
fn only_this_clients_dma_pool_is_valid() {
    let mut r = request();
    for gpa in [0, pool().gpa - 1, pool().gpa + pool().size, u64::MAX - 7] {
        r.segs[0].gpa = gpa;
        assert!(window().check_request(&r, pool(), 512, false).is_err());
    }
    r.segs[0].gpa = pool().gpa + pool().size - 4096;
    assert!(window().check_request(&r, pool(), 4096, false).is_ok());
    let other = Pool { gpa: pool().gpa + pool().size, ..pool() };
    assert!(window().check_request(&r, other, 4096, false).is_err());
}

#[test]
fn permissions_operations_direction_and_segment_count() {
    let mut r = request();
    r.op = OP_WRITE;
    r.segs[0].flags = 0;
    assert!(window().check_request(&r, pool(), 4096, false).is_ok());
    assert!(window().check_request(&r, pool(), 4096, true).is_err());
    r.segs[0].flags = SEG_WRITE;
    assert!(window().check_request(&r, pool(), 4096, false).is_err());
    r.op = OP_READ;
    r.segs[0].flags = 2 | SEG_WRITE;
    assert!(window().check_request(&r, pool(), 4096, false).is_err());
    r = request();
    r.nr_segs = MAX_SEGS as u32 + 1;
    assert!(window().check_request(&r, pool(), 4096, false).is_err());
    r = request();
    r.op = OP_DISCARD;
    assert!(window().check_request(&r, pool(), 4096, false).is_err());
    r.op = OP_FLUSH;
    assert!(window().check_request(&r, pool(), 4096, false).is_err());
    r.nr_segs = 0;
    assert_eq!(window().check_request(&r, pool(), 4096, true), Ok(0));
}

#[test]
fn randomized_accepted_requests_stay_in_the_assigned_window_and_pool() {
    let mut state = 0x7123456789abcdefu64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut accepted = 0;
    for _ in 0..100_000 {
        let mut r = request();
        r.op = [OP_READ, OP_WRITE, OP_FLUSH, OP_DISCARD][next() as usize % 4];
        let ro = next() & 1 != 0;
        let bs = if next() & 1 != 0 { 512 } else { 4096 };
        r.nr_segs = (next() % (MAX_SEGS as u64 + 2)) as u32;
        r.sector = match next() % 4 {
            0 => u64::MAX - next() % 16,
            1 => window().sectors - next() % 16,
            _ => (next() % 2048) * 8,
        };
        for seg in &mut r.segs {
            seg.gpa = match next() % 4 {
                0 => u64::MAX - next() % 4096,
                1 => pool().gpa + pool().size - next() % 4096,
                _ => pool().gpa + (next() % 256) * 4096,
            };
            seg.len = [0, 512, 4096, 8192][next() as usize % 4];
            seg.flags = (next() % 3) as u32;
        }
        if let Ok(sector) = window().check_request(&r, pool(), bs, ro) {
            accepted += 1;
            if r.op == OP_FLUSH {
                assert_eq!(r.nr_segs, 0);
                continue;
            }
            let segs = &r.segs[..r.nr_segs as usize];
            let bytes: u128 = segs.iter().map(|s| s.len as u128).sum();
            assert!(bytes > 0);
            assert!(sector as u128 * 512 >= window().start as u128 * 512);
            assert!(sector as u128 * 512 + bytes <= (window().start + window().sectors) as u128 * 512);
            assert_eq!(bytes % bs as u128, 0);
            assert_eq!((sector as u128 * 512) % bs as u128, 0);
            assert!(!(ro && r.op == OP_WRITE));
            for s in segs {
                assert!(s.gpa as u128 >= pool().gpa as u128);
                assert!(s.gpa as u128 + s.len as u128 <= pool().gpa as u128 + pool().size as u128);
                assert_eq!(s.flags, if r.op == OP_READ { SEG_WRITE } else { 0 });
            }
        }
    }
    assert!(accepted > 100);
}

#[test]
fn dom0_partition_windows_preserve_offsets_and_reject_unsafe_ranges() {
    let (w, len) = DiskWindow::parse_list::<4>("2099200:134217728,10240:217088,227328:1869824", 1887436800).unwrap();
    assert_eq!(len, 3);
    assert_eq!(w[0], DiskWindow { start: 2099200, sectors: 134217728 });
    for invalid in ["", "0:0", "8:0", "1:8", "8:7", "8:16,16:16", "8:18446744073709551608", "8:8,16:8,24:8,32:8,40:8", "8:8,", "8:8:8"] {
        assert!(DiskWindow::parse_list::<4>(invalid, 1887436800).is_none(), "{invalid}");
    }
    assert!(DiskWindow::parse_list::<4>("1887436800:8", 1887436800).is_none());
    let mut req = request();
    req.op = OP_WRITE;
    req.segs[0].flags = 0;
    assert_eq!(w[0].check_request(&req, pool(), 512, false), Ok(2099200));
    req.sector = w[0].sectors;
    assert_eq!(w[0].check_request(&req, pool(), 512, false), Err(STATUS_IOERR));
}

// Who may use which sectors: blk::Reservations with the attached clients,
// as blkd decides it.

const UNKNOWN: u64 = u64::MAX & !7;
fn ext(start: u64, sectors: u64) -> Extent { Extent { start, sectors, offset: 0 } }
fn reserved(unit: usize, start: u64, sectors: u64, read_only: bool) -> Reserved {
    Reserved { unit, window: DiskWindow::new(start, sectors, UNKNOWN).unwrap(), read_only }
}
fn none(_: usize) -> Option<Hold<'static>> { None }

#[test]
fn an_unusable_whole_disk_reservation_keeps_every_range() {
    let mut r = Reservations::<1>::new();
    assert_eq!(r.reserve(&none, reserved(0, 0, 0, false)), Ok(0));
    for start in [0, 8, UNKNOWN - 8] {
        for ro in [false, true] {
            let e = [ext(start, 8)];
            assert_eq!(r.slot(&none, &Hold { unit: 0, extents: &e, read_only: ro }, false), Err(EBUSY));
        }
        assert!(!r.unattached(&none, 0, DiskWindow { start, sectors: 8 }));
    }
}

#[test]
fn only_dom0_can_claim_the_exact_reserved_range_even_when_table_is_full() {
    let mut r = Reservations::<1>::new();
    assert_eq!(r.reserve(&none, reserved(0, 8, 16, false)), Ok(0));
    let w = [ext(8, 16)];
    fn want(unit: usize, extents: &[Extent], read_only: bool) -> Hold<'_> { Hold { unit, extents, read_only } }
    assert_eq!(r.slot(&none, &want(0, &w, false), true), Ok(0));
    for ro in [false, true] {
        assert_eq!(r.slot(&none, &want(0, &w, ro), false), Err(EBUSY));
        for other in [[ext(8, 8)], [ext(0, 32)]] {
            assert_eq!(r.slot(&none, &want(0, &other, ro), true), Err(EBUSY));
        }
    }
    // The same range as two extents, or on another unit, is no claim.
    let split = [ext(8, 8), ext(16, 8)];
    assert_eq!(r.slot(&none, &want(0, &split, false), true), Err(EBUSY));
    assert_eq!(r.slot(&none, &want(1, &w, false), true), Err(ENOSPC));
}

#[test]
fn an_active_dom0_window_cannot_be_claimed_twice_and_returns_on_detach() {
    let mut r = Reservations::<1>::new();
    r.reserve(&none, reserved(0, 8, 16, false)).unwrap();
    let w = [ext(8, 16)];
    let want = Hold { unit: 0, extents: &w, read_only: false };
    let active = |i: usize| (i == 0).then_some(want);
    assert_eq!(r.slot(&active, &want, true), Err(EBUSY));
    assert!(!r.unattached(&active, 0, DiskWindow { start: 8, sectors: 16 }));
    // Detached: the reservation still holds the range for dom0 alone.
    assert_eq!(r.slot(&none, &want, false), Err(EBUSY));
    assert_eq!(r.slot(&none, &want, true), Ok(0));
    assert!(!r.unattached(&none, 0, DiskWindow { start: 8, sectors: 16 }));
}

#[test]
fn volumes_conflict_where_any_extents_meet() {
    let a = [ext(0, 8192), ext(16384, 8192)];
    let active = |i: usize| (i == 0).then_some(Hold { unit: 0, extents: &a, read_only: false });
    let r = Reservations::<4>::new();
    // In the gap between a's extents, or on another unit: free.
    for (unit, e) in [(0, [ext(8192, 8192)]), (1, [ext(0, 8192)])] {
        assert_eq!(r.slot(&active, &Hold { unit, extents: &e, read_only: false }, false), Ok(1));
    }
    let b = [ext(8192, 8192), ext(24568, 8192)];
    assert_eq!(r.slot(&active, &Hold { unit: 0, extents: &b, read_only: false }, false), Err(EBUSY));
    assert!(r.unattached(&active, 0, DiskWindow { start: 8192, sectors: 8192 }));
    assert!(!r.unattached(&active, 0, DiskWindow { start: 24568, sectors: 8 }));
    // Read-only volumes may share sectors, as read-only windows do.
    let ro = |i: usize| (i == 0).then_some(Hold { unit: 0, extents: &a, read_only: true });
    assert_eq!(r.slot(&ro, &Hold { unit: 0, extents: &b, read_only: true }, false), Ok(1));
}

#[test]
fn reservations_conflict_like_windows() {
    let mut r = Reservations::<4>::new();
    r.reserve(&none, reserved(0, 0, 16, true)).unwrap();
    // Read-only ranges may share sectors; a writable one may not.
    assert_eq!(r.reserve(&none, reserved(0, 8, 16, true)), Ok(1));
    assert_eq!(r.reserve(&none, reserved(0, 8, 8, false)), Err(EBUSY));
    assert_eq!(r.reserve(&none, reserved(1, 8, 8, false)), Ok(2));
    let e = [ext(24, 8)];
    assert_eq!(r.slot(&none, &Hold { unit: 0, extents: &e, read_only: false }, false), Ok(3));
    assert!(r.unattached(&none, 0, DiskWindow { start: 24, sectors: 8 }));
    assert!(!r.unattached(&none, 0, DiskWindow { start: 16, sectors: 8 }));
}

/// Random reserve, attach, detach and provisioning against a model that
/// tracks the holders of each 4 KiB block.  Clients hold one or two
/// extents.
#[test]
fn randomized_decisions_match_a_per_block_model() {
    const N: usize = 6;
    const BLOCKS: u64 = 12;
    let mut state = 0x2545f4914f6cdd1du64;
    let mut next = move |n: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % n
    };
    for _ in 0..2000 {
        let mut r = Reservations::<N>::new();
        let mut active: [Option<(usize, Vec<Extent>, bool)>; N] = Default::default();
        for _ in 0..40 {
            let unit = next(2) as usize;
            let first = next(BLOCKS);
            let len = 1 + next(BLOCKS - first);
            let mut extents = vec![ext(first * 8, len * 8)];
            // Sometimes a second extent after a gap.
            if next(3) == 0 && first + len + 1 < BLOCKS {
                let second = first + len + 1 + next(BLOCKS - first - len - 1);
                extents.push(ext(second * 8, (1 + next(BLOCKS - second)) * 8));
            }
            let read_only = next(2) == 0;
            let dom0 = next(2) == 0;
            let want = Hold { unit, extents: &extents, read_only };
            let blocks = |e: &[Extent]| e.iter().flat_map(|x| x.start / 8..(x.start + x.sectors) / 8).collect::<Vec<_>>();
            let mine = blocks(&extents);
            let shares = |u: usize, e: &[Extent]| u == unit && blocks(e).iter().any(|b| mine.contains(b));
            let expect = |dom0: bool| {
                let claimable = |i: usize| dom0 && active[i].is_none() && extents.len() == 1
                    && r.slots[i].is_some_and(|h| h.unit == unit && (h.window.start, h.window.sectors) == (extents[0].start, extents[0].sectors));
                // Holders of the wanted blocks that exclude it: clients, and
                // reservations that are neither claimed nor claimable now.
                let excluded = (0..N).any(|i| match &active[i] {
                    Some((u, e, ro)) => shares(*u, e) && !(*ro && read_only),
                    None => r.slots[i].filter(|_| !claimable(i)).is_some_and(|h| {
                        shares(h.unit, &[ext(h.window.start, h.window.sectors)]) && !(h.read_only && read_only)
                    }),
                });
                if excluded { return Err(EBUSY); }
                (0..N).find(|&i| claimable(i))
                    .or_else(|| (0..N).find(|&i| active[i].is_none() && r.slots[i].is_none())).ok_or(ENOSPC)
            };
            let lookup = |i: usize| active[i].as_ref().map(|(unit, e, read_only)| Hold { unit: *unit, extents: e, read_only: *read_only });
            match next(4) {
                0 if extents.len() == 1 => {
                    let expected = expect(false);
                    let res = Reserved { unit, window: DiskWindow { start: extents[0].start, sectors: extents[0].sectors }, read_only };
                    assert_eq!(r.reserve(&lookup, res), expected);
                }
                0 | 1 => {
                    let got = r.slot(&lookup, &want, dom0);
                    assert_eq!(got, expect(dom0));
                    if let Ok(i) = got { active[i] = Some((unit, extents.clone(), read_only)); }
                }
                2 => active[next(N as u64) as usize] = None,
                _ => {
                    let w = DiskWindow { start: extents[0].start, sectors: extents[0].sectors };
                    let probe = [extents[0]];
                    let held = (0..N).any(|i| active[i].as_ref().is_some_and(|(u, e, _)| *u == unit && blocks(e).iter().any(|b| blocks(&probe).contains(b)))
                        || r.slots[i].is_some_and(|h| h.unit == unit && h.window.overlaps(w)));
                    assert_eq!(r.unattached(&lookup, unit, w), !held);
                }
            }
        }
    }
}

// Disks made of extents: blk::Volume.

const CAP: u64 = 1 << 30;
fn build(raw: &[(u64, u64)]) -> Result<(Vec<u16>, Vec<Extent>), u64> {
    let (mut order, mut extents) = (vec![0; raw.len()], vec![Extent::default(); raw.len()]);
    Volume::build(raw.iter().copied(), &mut order, &mut extents, CAP)?;
    Ok((order, extents))
}
fn vol<'a>(t: &'a (Vec<u16>, Vec<Extent>)) -> Volume<'a> { Volume { order: &t.0, extents: &t.1 } }
fn read(sector: u64, segs: &[u32]) -> Req {
    let mut r = Req { op: OP_READ, nr_segs: segs.len() as u32, sector, ..Default::default() };
    for (i, &len) in segs.iter().enumerate() {
        r.segs[i] = Seg { gpa: pool().gpa + i as u64 * (256 << 10), len, flags: SEG_WRITE };
    }
    r
}

#[test]
fn volumes_keep_guest_order_and_physical_sort() {
    // Guest order: 40960, then 8192, then 24576 on the disk.
    let t = build(&[(40960, 8192), (8192, 16384), (24576, 8192)]).unwrap();
    let v = vol(&t);
    assert_eq!(v.extents.iter().map(|e| e.start).collect::<Vec<_>>(), [8192, 24576, 40960]);
    assert_eq!((0..3).map(|k| v.nth(k).unwrap().start).collect::<Vec<_>>(), [40960, 8192, 24576]);
    assert_eq!((0..3).map(|k| v.nth(k).unwrap().offset).collect::<Vec<_>>(), [0, 8192, 24576]);
    assert_eq!(v.sectors(), 32768);
    assert!(v.check(CAP).is_ok());
}

#[test]
fn volumes_refuse_what_is_no_disk() {
    let short = MIN_EXTENT_SECTORS - 8;
    for raw in [
        vec![],
        vec![(1, 8192)],
        vec![(0, 8191)],
        vec![(0, 0)],
        vec![(CAP - 8, 16)],
        vec![(0, 8192), (4096, 8192)],
        vec![(0, short), (16384, 8192)],
        vec![(u64::MAX - 7, 8192), (0, 8192)],
    ] {
        assert_eq!(build(&raw).err(), Some(EINVAL), "{raw:?}");
    }
    // One extent keeps a window's 4 KiB minimum.
    assert!(build(&[(8, 8)]).is_ok());
    assert!(build(&vec![(0, 8192); MAX_EXTENTS + 1]).is_err());
    let many: Vec<_> = (0..MAX_EXTENTS as u64).rev().map(|k| (k * 8192, 8192)).collect();
    let t = build(&many).unwrap();
    assert_eq!(vol(&t).nth(MAX_EXTENTS - 1).unwrap().start, 0);
}

#[test]
fn tampered_tables_fail_the_check() {
    let t = build(&[(40960, 8192), (8192, 16384), (24576, 8192)]).unwrap();
    let mut order = t.0.clone();
    order.swap(0, 1);
    assert!(Volume { order: &order, extents: &t.1 }.check(CAP).is_err());
    let repeat = [t.0[0], t.0[0], t.0[2]];
    assert!(Volume { order: &repeat, extents: &t.1 }.check(CAP).is_err());
    let mut unsorted = t.1.clone();
    unsorted.swap(0, 1);
    assert!(Volume { order: &t.0, extents: &unsorted }.check(CAP).is_err());
    let big = [9u16, 0, 1];
    assert!(Volume { order: &big, extents: &t.1 }.check(CAP).is_err());
}

#[test]
fn requests_split_at_most_once_where_extents_meet() {
    // Guest sectors 0..8192 are disk 40960.., 8192..16384 are disk 8192...
    let t = build(&[(40960, 8192), (8192, 8192), (100000 & !7, 8192)]).unwrap();
    let v = vol(&t);
    let p = |r: &Req| v.map(r, pool(), 512, false);
    assert_eq!(p(&read(0, &[4096])), Ok(([(40960, 4096), (0, 0)], 1)));
    // Ending exactly at the boundary.
    assert_eq!(p(&read(8184, &[4096])), Ok(([(49144, 4096), (0, 0)], 1)));
    // Crossing it, inside one segment and between two.
    assert_eq!(p(&read(8184, &[8192])), Ok(([(49144, 4096), (8192, 4096)], 2)));
    assert_eq!(p(&read(8184, &[4096, 4096])), Ok(([(49144, 4096), (8192, 4096)], 2)));
    // The last sector, and one past the end.
    assert_eq!(p(&read(24568, &[4096])), Ok(([(100000 + 8184, 4096), (0, 0)], 1)));
    assert!(p(&read(24576, &[512])).is_err());
    let mut flush = Req { op: OP_FLUSH, ..Default::default() };
    flush.nr_segs = 0;
    assert_eq!(p(&flush), Ok(([(0, 0); 2], 0)));
}

#[test]
fn a_request_that_would_need_three_pieces_fails() {
    // A one-block middle extent is not allowed with several extents, so
    // build the table by hand: blkd's check would refuse it, and map must
    // not trust that.
    let extents = [Extent { start: 0, sectors: 8, offset: 0 }, Extent { start: 64, sectors: 8, offset: 8 },
        Extent { start: 128, sectors: 64, offset: 16 }];
    let v = Volume { order: &[0, 1, 2], extents: &extents };
    assert_eq!(v.map(&read(0, &[12288]), pool(), 512, false), Err(STATUS_IOERR));
}

#[test]
fn randomized_mapping_covers_each_byte_once() {
    let t = build(&[(81920, 8192), (16384, 16384), (0, 8192), (57344, 8192)]).unwrap();
    let v = vol(&t);
    let total = v.sectors();
    let mut state = 0x9e3779b97f4a7c15u64;
    let mut next = move |n: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % n
    };
    for _ in 0..20000 {
        let segs: Vec<u32> = (0..1 + next(14)).map(|_| (1 + next(64)) as u32 * 4096).collect();
        let bytes: u64 = segs.iter().map(|&s| s as u64).sum();
        let sector = next(total / 8) * 8;
        let Ok((pieces, n)) = v.map(&read(sector, &segs), Pool { size: 64 << 20, ..pool() }, 4096, false) else {
            assert!(sector + bytes / 512 > total);
            continue;
        };
        // Each guest sector maps through the extent that holds it.
        let mut g = sector;
        for &(dev, len) in &pieces[..n] {
            let e = (0..4).map(|k| v.nth(k).unwrap()).find(|e| e.offset <= g && g < e.offset + e.sectors).unwrap();
            assert_eq!(dev, e.start + g - e.offset);
            assert!(g + len / 512 <= e.offset + e.sectors);
            g += len / 512;
        }
        assert_eq!(g, sector + bytes / 512);
    }
}

#[test]
fn table_pages_cover_the_entries() {
    let order = core::mem::offset_of!(ExtentTable, order);
    let extents = core::mem::offset_of!(ExtentTable, extents);
    for n in [1, 2, 170, 171, 2000, MAX_EXTENTS] {
        let [a, b] = table_pages(n);
        assert!(a.end <= b.start);
        let mapped = |byte: usize| a.contains(&(byte / 4096)) || b.contains(&(byte / 4096));
        assert!((order..order + 2 * n).all(mapped) && (extents..extents + 24 * n).all(mapped), "{n}");
        assert!(b.end * 4096 <= EXTENT_STRIDE);
    }
    assert_eq!(table_pages(1).into_iter().map(|r| r.len()).sum::<usize>(), 2);
    let pages: usize = table_pages(MAX_EXTENTS).into_iter().map(|r| r.len()).sum();
    assert_eq!(pages, size_of::<ExtentTable>().div_ceil(4096));
}

#[test]
fn extent_lists_overlap_by_merge() {
    let a = [ext(0, 8), ext(64, 8), ext(128, 8)];
    assert!(!overlap(&a, &[ext(8, 56), ext(72, 56)]));
    assert!(overlap(&a, &[ext(8, 56), ext(127, 2)]));
    assert!(!overlap(&a, &[]));
}
