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
// as blkd decides it (formerly l4h-root's attachment_slot).

const UNKNOWN: u64 = u64::MAX & !7;
fn hold(unit: usize, start: u64, sectors: u64, read_only: bool) -> Hold {
    Hold { unit, window: DiskWindow::new(start, sectors, UNKNOWN).unwrap(), read_only }
}
fn none(_: usize) -> Option<Hold> { None }

#[test]
fn an_unusable_whole_disk_reservation_keeps_every_range() {
    let mut r = Reservations::<1>::new();
    assert_eq!(r.reserve(&none, hold(0, 0, 0, false)), Ok(0));
    for start in [0, 8, UNKNOWN - 8] {
        for ro in [false, true] {
            assert_eq!(r.slot(&none, &hold(0, start, 8, ro), false), Err(EBUSY));
        }
        assert!(!r.unattached(&none, 0, hold(0, start, 8, false).window));
    }
}

#[test]
fn only_dom0_can_claim_the_exact_reserved_range_even_when_table_is_full() {
    let mut r = Reservations::<1>::new();
    let w = hold(0, 8, 16, false);
    assert_eq!(r.reserve(&none, w), Ok(0));
    assert_eq!(r.slot(&none, &w, true), Ok(0));
    for ro in [false, true] {
        assert_eq!(r.slot(&none, &Hold { read_only: ro, ..w }, false), Err(EBUSY));
        for other in [hold(0, 8, 8, ro), hold(0, 0, 32, ro)] {
            assert_eq!(r.slot(&none, &other, true), Err(EBUSY));
        }
    }
    // Another unit's same range is no claim, and the only slot is taken.
    assert_eq!(r.slot(&none, &Hold { unit: 1, ..w }, true), Err(ENOSPC));
}

#[test]
fn an_active_dom0_window_cannot_be_claimed_twice_and_returns_on_detach() {
    let mut r = Reservations::<1>::new();
    let w = hold(0, 8, 16, false);
    r.reserve(&none, w).unwrap();
    let active = |i: usize| (i == 0).then_some(w);
    assert_eq!(r.slot(&active, &w, true), Err(EBUSY));
    assert!(!r.unattached(&active, 0, w.window));
    // Detached: the reservation still holds the range for dom0 alone.
    assert_eq!(r.slot(&none, &w, false), Err(EBUSY));
    assert_eq!(r.slot(&none, &w, true), Ok(0));
    assert!(!r.unattached(&none, 0, w.window));
}

#[test]
fn reservations_conflict_like_windows() {
    let mut r = Reservations::<4>::new();
    r.reserve(&none, hold(0, 0, 16, true)).unwrap();
    // Read-only ranges may share sectors; a writable one may not.
    assert_eq!(r.reserve(&none, hold(0, 8, 16, true)), Ok(1));
    assert_eq!(r.reserve(&none, hold(0, 8, 8, false)), Err(EBUSY));
    assert_eq!(r.reserve(&none, hold(1, 8, 8, false)), Ok(2));
    assert_eq!(r.slot(&none, &hold(0, 24, 8, false), false), Ok(3));
    assert!(r.unattached(&none, 0, hold(0, 24, 8, false).window));
    assert!(!r.unattached(&none, 0, hold(0, 16, 8, false).window));
}

/// Random reserve, attach, detach and provisioning against a model that
/// tracks the holders of each 4 KiB block.
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
        let mut active: [Option<Hold>; N] = [None; N];
        for _ in 0..40 {
            let first = next(BLOCKS);
            let want = Hold {
                unit: next(2) as usize,
                window: DiskWindow { start: first * 8, sectors: (1 + next(BLOCKS - first)) * 8 },
                read_only: next(2) == 0,
            };
            let dom0 = next(2) == 0;
            let blocks = |h: &Hold| h.window.start / 8..(h.window.start + h.window.sectors) / 8;
            let shares = |h: &Hold| h.unit == want.unit && blocks(h).any(|b| blocks(&want).contains(&b));
            let expect = |dom0: bool| {
                let claimable = |i: usize| dom0 && active[i].is_none()
                    && r.slots[i].is_some_and(|h| h.unit == want.unit && h.window == want.window);
                // Holders of the wanted blocks that exclude it: clients, and
                // reservations that are neither claimed nor claimable now.
                let excluded = (0..N).any(|i| {
                    let holder = active[i].or(r.slots[i].filter(|_| !claimable(i)));
                    holder.is_some_and(|h| shares(&h) && !(h.read_only && want.read_only))
                });
                if excluded { return Err(EBUSY); }
                (0..N).find(|&i| claimable(i))
                    .or_else(|| (0..N).find(|&i| active[i].is_none() && r.slots[i].is_none())).ok_or(ENOSPC)
            };
            let lookup = |i: usize| active[i];
            match next(4) {
                0 => {
                    let expected = expect(false);
                    assert_eq!(r.reserve(&lookup, want), expected);
                    if let Ok(i) = expected { assert_eq!(r.slots[i], Some(want)); }
                }
                1 => {
                    let got = r.slot(&lookup, &want, dom0);
                    assert_eq!(got, expect(dom0));
                    if let Ok(i) = got { active[i] = Some(want); }
                }
                2 => active[next(N as u64) as usize] = None,
                _ => {
                    let held = (0..N).flat_map(|i| [active[i], r.slots[i]]).flatten().any(|h| shares(&h));
                    assert_eq!(r.unattached(&lookup, want.unit, want.window), !held);
                }
            }
        }
    }
}
