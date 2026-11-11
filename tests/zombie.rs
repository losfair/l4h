//! l4h-root's zombies (vmmgr.rs): what a deleted guest leaves while its
//! drivers finish, and when its I/O pool may be reused.  A pool cut off from
//! the IOMMU goes only once every disk of the guest is drained, whatever the
//! other removals do: a controller may still run the guest's commands, and
//! its domain could map the next pool at the same addresses.  With mocked
//! allocator calls.
#![allow(dead_code)]

const MAX_GUESTS: usize = 64;
mod mem {
    pub const GLOBAL: u64 = 1 << 20;
}
macro_rules! log {
    ($($t:tt)*) => { crate::logged(format!($($t)*)) };
}
thread_local! {
    static LOG: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}
fn logged(s: String) {
    LOG.with(|l| l.borrow_mut().push(s));
}

include!(env!("L4H_ZOMBIE_TEST_SRC"));

/// An arena: the regions it owns, (slot, paddr, size bits).
#[derive(Debug, Default, PartialEq)]
pub struct Arena {
    owned: Vec<(usize, usize, usize)>,
}
impl Arena {
    fn new() -> Self {
        Self::default()
    }
    fn own(&mut self, slot: usize, paddr: usize, bits: usize) {
        self.owned.push((slot, paddr, bits));
    }
}
#[derive(Default)]
pub struct Slots {
    freed: Vec<usize>,
}
impl Slots {
    fn free_owned(&mut self, owner: usize) {
        self.freed.push(owner);
    }
}
/// What was given back, in order: each region's paddr, and the pinned ones.
#[derive(Default)]
pub struct Alloc {
    reclaimed: Vec<usize>,
    pinned: Vec<usize>,
    slots: Slots,
}
impl Alloc {
    fn reclaim(&mut self, a: Arena) {
        self.reclaimed.extend(a.owned.iter().map(|o| o.1));
    }
    fn reclaim_pinning(&mut self, a: Arena, pin: impl Fn(usize) -> bool) -> usize {
        let mut kept = 0;
        for (_, p, bits) in a.owned {
            if pin(p) {
                self.pinned.push(p);
                kept += 1 << bits;
            } else {
                self.reclaimed.push(p);
            }
        }
        kept
    }
}
pub struct Host {
    zombies: Vec<Option<Zombie>>,
    alloc: Alloc,
}

const POOL: usize = 0x4000_0000;
const CHANNELS: usize = 0x5000_0000;

/// Guest memory: its channels' region and its I/O pool.
fn arena() -> Arena {
    let mut a = Arena::new();
    a.own(1, CHANNELS, 21);
    a.own(2, POOL, 24);
    a
}

/// Zombie 0 of a guest with `disks` disks and `ports` ports, its pool
/// `cut` off or not: the host, and what was reclaimed at deletion.
fn host(disks: usize, ports: usize, cut: bool) -> Host {
    let mut h = Host { zombies: (0..MAX_GUESTS).map(|_| None).collect(), alloc: Alloc::default() };
    let mut a = arena();
    let (pool, now) = ZombiePool::at_deletion(&mut a, POOL, cut, disks != 0, true);
    if let Some(now) = now {
        h.alloc.reclaim(now);
    }
    h.zombies[0] = Some(Zombie { arena: a, waits: disks + ports, disk_waits: disks, pool, pin: false });
    h
}

#[test]
fn a_cut_pool_waits_for_every_disk_and_not_for_netd() {
    let mut h = host(2, 1, true);
    assert!(h.alloc.reclaimed.is_empty(), "nothing goes while disks may run commands");
    zombie_done(&mut h, Some(0), true);
    zombie_disk_done(&mut h, Some(0), true);
    assert!(h.alloc.reclaimed.is_empty(), "one disk still drains");
    zombie_disk_done(&mut h, Some(0), true);
    assert_eq!(h.alloc.reclaimed, [POOL, CHANNELS], "the pool, then the rest with the zombie");
    assert!(h.zombies[0].is_none());
    assert_eq!(h.alloc.slots.freed, [MAX_GUESTS]);
}

#[test]
fn a_cut_pool_goes_before_a_port_netd_has_not_let_go() {
    let mut h = host(1, 1, true);
    zombie_disk_done(&mut h, Some(0), true);
    assert_eq!(h.alloc.reclaimed, [POOL]);
    assert!(h.zombies[0].is_some(), "netd still maps the port");
    zombie_done(&mut h, Some(0), true);
    assert_eq!(h.alloc.reclaimed, [POOL, CHANNELS]);
}

/// guest_del's choice for every case: the pool is freed at once only if no
/// device's domain maps it and no disk can still run the guest's commands,
/// and leaves the arena to wait for drains only if a zombie counts them.
#[test]
fn where_the_pool_goes_at_deletion() {
    for cut in [false, true] {
        for disks in [false, true] {
            for zombie in [false, true] {
                let mut a = arena();
                let (pool, now) = ZombiePool::at_deletion(&mut a, POOL, cut, disks, zombie);
                let case = format!("cut {cut}, disks {disks}, zombie {zombie}");
                match (cut, disks, zombie) {
                    (false, ..) | (true, true, false) => {
                        assert!(matches!(pool, ZombiePool::InArena(POOL)), "{case}");
                        assert!(now.is_none() && a == arena(), "{case}: nothing leaves the arena");
                    }
                    (true, false, _) => {
                        assert!(matches!(pool, ZombiePool::Gone), "{case}");
                        assert_eq!(now, Some(Arena { owned: vec![(2, POOL, 24)] }), "{case}: freed at once");
                        assert_eq!(a.owned, [(1, CHANNELS, 21)], "{case}");
                    }
                    (true, true, true) => {
                        assert!(matches!(&pool, ZombiePool::Cut(p) if p.owned == [(2, POOL, 24)]), "{case}");
                        assert!(now.is_none(), "{case}: not freed while disks drain");
                        assert_eq!(a.owned, [(1, CHANNELS, 21)], "{case}");
                    }
                }
            }
        }
    }
    // A pool the arena does not own is not the zombie's to free.
    let mut a = Arena::new();
    let (pool, now) = ZombiePool::at_deletion(&mut a, POOL, true, true, true);
    assert!(matches!(pool, ZombiePool::Gone) && now.is_none());
}

#[test]
fn a_pool_no_iommu_cut_off_stays_and_is_pinned_if_a_disk_was_not_stopped() {
    let mut h = host(1, 0, false);
    assert!(matches!(h.zombies[0].as_ref().unwrap().pool, ZombiePool::InArena(POOL)));
    zombie_disk_done(&mut h, Some(0), false);
    assert_eq!((h.alloc.reclaimed.as_slice(), h.alloc.pinned.as_slice()), (&[CHANNELS][..], &[POOL][..]));
}

/// A disk removal the zombie does not wait for counts for nothing: not for
/// the pool again, and not as a removal of another driver's, whose memory
/// (netd's ports) must stay until that driver has let go of it.
#[test]
fn a_removal_more_than_the_disks_changes_nothing() {
    let mut h = host(1, 2, true);
    zombie_disk_done(&mut h, Some(0), true);
    assert_eq!(h.alloc.reclaimed, [POOL]);
    zombie_disk_done(&mut h, Some(0), true);
    zombie_disk_done(&mut h, Some(0), false);
    assert!(LOG.with(|l| l.borrow().iter().any(|s| s.contains("more than it has disks"))));
    let zb = h.zombies[0].as_ref().unwrap();
    assert_eq!((zb.waits, zb.disk_waits, zb.pin), (2, 0, false), "nothing counted");
    zombie_done(&mut h, Some(0), true);
    assert_eq!(h.alloc.reclaimed, [POOL], "one port is still netd's");
    zombie_done(&mut h, Some(0), true);
    assert_eq!(h.alloc.reclaimed, [POOL, CHANNELS]);
    assert!(h.zombies[0].is_none());
}

/// Whatever the order the drivers answer in, the pool goes at the last
/// disk and the rest at the last removal, each once.
#[test]
fn every_order_of_removals() {
    // 2 disks (D) and 2 ports (P), in every order.
    let mut orders = vec![vec![]];
    for _ in 0..4 {
        orders = orders.into_iter().flat_map(|o: Vec<char>| ['D', 'P'].into_iter().map(move |c| {
            let mut o = o.clone();
            o.push(c);
            o
        })).filter(|o| o.iter().filter(|&&c| c == 'D').count() <= 2 && o.iter().filter(|&&c| c == 'P').count() <= 2).collect();
    }
    assert_eq!(orders.len(), 6);
    for o in orders {
        let mut h = host(2, 2, true);
        let (mut disks, mut all) = (0, 0);
        for &c in &o {
            if c == 'D' { zombie_disk_done(&mut h, Some(0), true); disks += 1 } else { zombie_done(&mut h, Some(0), true) }
            all += 1;
            let pool_freed = h.alloc.reclaimed.contains(&POOL);
            assert_eq!(pool_freed, disks == 2, "{o:?}: the pool goes at the last disk");
            assert_eq!(h.alloc.reclaimed.contains(&CHANNELS), all == 4, "{o:?}: the rest at the last removal");
        }
        assert_eq!(h.alloc.reclaimed.len(), 2, "{o:?}: each once");
    }
}

#[test]
fn no_zombie_is_no_op() {
    let mut h = host(1, 0, true);
    zombie_disk_done(&mut h, None, true);
    zombie_disk_done(&mut h, Some(5), true);
    assert!(h.alloc.reclaimed.is_empty() && h.zombies[0].is_some());
}
