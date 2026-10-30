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

#[test]
fn crypto_work_and_bounce_use_are_bounded_by_the_advertised_maximum() {
    let pool = Pool { gpa: 0, paddr: 0x10000000, size: 256 << 20 };
    let window = DiskWindow::new(0, pool.size / 512, pool.size / 512).unwrap();
    for op in [OP_READ, OP_WRITE] {
        let mut req = Req { op, nr_segs: 1, ..Default::default() };
        req.segs[0] = Seg { gpa: 0, len: MAX_REQUEST_BYTES as u32, flags: if op == OP_READ { SEG_WRITE } else { 0 } };
        assert_eq!(window.check_request(&req, pool, 4096, false), Ok(0));
        req.segs[0].len += 4096;
        assert_eq!(window.check_request(&req, pool, 4096, false), Err(STATUS_IOERR));
    }
}

#[test]
fn xts_key_halves_must_differ() {
    assert!(!valid_xts_key(&[0; 64]));
    assert!(!valid_xts_key(&[0xa5; 64]));
    for i in 0..64 {
        let mut key = [0xa5; 64];
        key[i] ^= 1;
        assert!(valid_xts_key(&key));
    }
}
