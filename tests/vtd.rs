// Run with tests/run-vtdtest.sh; no seL4 runtime is needed.
extern crate self as l4h_host;
#[path = "../host/l4h-host/src/fixed.rs"]
pub mod fixed;
#[path = "../host/l4h-root/src/vtd/dmar.rs"]
mod dmar;
#[path = "../host/l4h-root/src/vtd/format.rs"]
mod format;
#[path = "../host/l4h-root/src/vtd/requester.rs"]
mod requester;
#[path = "../host/l4h-root/src/iommu/mappings.rs"]
mod mappings;
use dmar::Dmar;
use mappings::Access;

#[test]
fn shared_dma_pool_is_unmapped_only_after_its_last_user() {
    let mut m = mappings::Mappings::<2>::new();
    assert!(m.acquire(1, 0x1000, 0x4000, Access::ReadWrite));
    assert!(!m.acquire(1, 0x1000, 0x4000, Access::ReadWrite));
    assert!(m.acquire(2, 0x1000, 0x4000, Access::ReadWrite));
    assert!(!m.release(1, 0x1000, 0x4000));
    assert!(m.release(2, 0x1000, 0x4000));
    assert!(!m.acquire(1, 0x1000, 0x4000, Access::ReadWrite));
    assert!(!m.release(1, 0x1000, 0x4000));
    assert!(m.release(1, 0x1000, 0x4000));
    assert!(m.acquire(1, 0x1000, 0x4000, Access::Read)); // reusable after final release
    assert!(m.release(1, 0x1000, 0x4000));
    assert!(!m.acquire(1, 0x1000, 0, Access::Write));
    assert!(!m.release(1, 0x1000, 0));
}

#[test]
fn shared_dma_tracking_rejects_ambiguous_ranges_and_permissions() {
    for (pa, len, access) in [(0x2000, 0x4000, Access::ReadWrite), (0x1000, 0x4000, Access::Read), (0x1000, 0x4000, Access::Write)] {
        let result = std::panic::catch_unwind(|| {
            let mut m = mappings::Mappings::<2>::new();
            m.acquire(1, 0x1000, 0x4000, Access::ReadWrite);
            m.acquire(1, pa, len, access);
        });
        assert!(result.is_err());
    }
}

fn bridge_config(sid: u16, secondary: u8, subordinate: u8, pcie_type: Option<u8>) -> (u16, [u32; 64]) {
    let mut c = [0; 64];
    c[0] = 0x1234_8086;
    c[2] = 0x0604_0000;
    c[3] = 1 << 16;
    c[6] = (sid as u32 >> 8) | (secondary as u32) << 8 | (subordinate as u32) << 16;
    if let Some(kind) = pcie_type {
        c[1] = 1 << 20;
        c[0x34 / 4] = 0x80;
        c[0x80 / 4] = 0x10 | (kind as u32) << 20;
    }
    (sid, c)
}

fn requesters(config: &[(u16, [u32; 64])]) -> Option<requester::Requesters> {
    requester::Requesters::discover(|b, d, f, o| {
        let sid = (b as u16) << 8 | (d as u16) << 3 | f as u16;
        config.iter().find(|(s, _)| *s == sid).map_or(u32::MAX, |(_, c)| c[o as usize / 4])
    })
}

#[test]
fn pcie_ports_preserve_requester_ids() {
    let r = requesters(&[
        bridge_config(0x28, 1, 3, Some(4)),
        bridge_config(0x100, 2, 3, Some(5)),
        bridge_config(0x200, 3, 3, Some(6)),
    ]).unwrap();
    for sid in [0x18, 0x118, 0x200, 0x318, 0x319, 0xfff8] { assert_eq!(r.requester(sid), sid); }
}

#[test]
fn conventional_bridges_share_the_outer_bridge_requester() {
    let r = requesters(&[
        bridge_config(0xf0, 1, 2, None),
        bridge_config(0x110, 2, 2, None),
    ]).unwrap();
    for sid in [0x110, 0x118, 0x119, 0x218, 0x2ff] { assert_eq!(r.requester(sid), 0xf0); }
    assert_eq!(r.requester(0xf0), 0xf0);
    assert_eq!(r.requester(0x318), 0x318);
}

#[test]
fn pcie_to_pci_uses_secondary_bus_zero_devfn() {
    let r = requesters(&[
        bridge_config(0x28, 1, 3, Some(4)),
        bridge_config(0x100, 2, 3, Some(7)),
        bridge_config(0x210, 3, 3, None),
    ]).unwrap();
    for sid in [0x200, 0x210, 0x218, 0x219, 0x318] { assert_eq!(r.requester(sid), 0x200); }
    assert_eq!(r.requester(0x100), 0x100);
    assert_eq!(r.requester(0x28), 0x28);
}

#[test]
fn bridge_on_a_nonzero_function_is_discovered() {
    let mut f0 = [0; 64];
    f0[0] = 0x1234_8086;
    f0[3] = 1 << 23;
    let r = requesters(&[(0xe8, f0), bridge_config(0xe9, 1, 1, None)]).unwrap();
    assert_eq!(r.requester(0x118), 0xe9);
}

#[test]
fn reserved_memory_follows_requester_groups() {
    let r = requesters(&[bridge_config(0xf0, 1, 1, None)]).unwrap();
    let reserved = dmar::Scope { first: 0x118, last: 0x118 };
    assert!(r.scope_contains(reserved, r.requester(0x120)));
    assert!(!r.scope_contains(reserved, 0x218));
    let reserved = dmar::Scope { first: 0x200, last: 0x2ff };
    assert!(r.scope_contains(reserved, 0x218));
    assert!(!r.scope_contains(reserved, 0xf0));
}

#[test]
fn rejects_bad_bridge_topology_and_capability_loops() {
    for config in [
        vec![bridge_config(0x28, 1, 1, None), bridge_config(0x30, 1, 1, None)],
        vec![bridge_config(0x128, 1, 1, None)],
        vec![bridge_config(0x28, 2, 1, None)],
        vec![bridge_config(0x128, 2, 2, None), bridge_config(0x228, 1, 2, None)],
    ] { assert!(requesters(&config).is_none()); }
    let (sid, mut c) = bridge_config(0x28, 1, 1, Some(4));
    c[0x80 / 4] |= 0x80 << 8;
    assert!(requesters(&[(sid, c)]).is_none());
    c[0x34 / 4] = 0x20;
    assert!(requesters(&[(sid, c)]).is_none());
    let r = requesters(&[bridge_config(0x28, 0, 0, None)]).unwrap();
    assert_eq!(r.requester(0x118), 0x118);
}

fn table(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0; 48];
    b[..4].copy_from_slice(b"DMAR");
    b[36] = 47;
    b[37] = 1;
    for block in blocks { b.extend(block); }
    let len = b.len() as u32;
    b[4..8].copy_from_slice(&len.to_le_bytes());
    checksum(&mut b);
    b
}

fn checksum(b: &mut [u8]) {
    b[9] = 0;
    b[9] = 0u8.wrapping_sub(b.iter().fold(0u8, |s, b| s.wrapping_add(*b)));
}

fn scope(kind: u8, bus: u8, path: &[(u8, u8)]) -> Vec<u8> {
    let mut s = vec![kind, 6 + 2 * path.len() as u8, 0, 0, 0, bus];
    for &(dev, func) in path { s.extend([dev, func]); }
    s
}

fn drhd(all: bool, segment: u16, base: u64, scopes: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0; 16];
    b[4] = all as u8;
    b[6..8].copy_from_slice(&segment.to_le_bytes());
    b[8..16].copy_from_slice(&base.to_le_bytes());
    for s in scopes { b.extend(s); }
    let len = b.len() as u16;
    b[2..4].copy_from_slice(&len.to_le_bytes());
    b
}

fn rmrr(first: u64, last: u64, scopes: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0; 24];
    b[0] = 1;
    b[8..16].copy_from_slice(&first.to_le_bytes());
    b[16..24].copy_from_slice(&last.to_le_bytes());
    for s in scopes { b.extend(s); }
    let len = b.len() as u16;
    b[2..4].copy_from_slice(&len.to_le_bytes());
    b
}

// Existing PCI functions, endpoint class unless a test overrides it.
fn pci(_: u8, _: u8, _: u8, off: u8) -> u32 { if off == 0 { 0x1234_8086 } else { 0 } }

#[test]
fn explicit_unit_wins_over_include_all_in_either_order() {
    for reverse in [false, true] {
        let mut blocks = vec![drhd(true, 0, 0xfed9_0000, &[]),
            drhd(false, 0, 0xfed9_1000, &[scope(1, 2, &[(3, 1)])])];
        if reverse { blocks.reverse(); }
        let d = Dmar::parse(&table(&blocks), pci).unwrap();
        assert_eq!(d.haw, 48);
        assert!(d.interrupt_remapping);
        assert_eq!(d.units[d.owner(0x219).unwrap()].base, 0xfed9_1000);
        assert_eq!(d.units[d.owner(0x218).unwrap()].base, 0xfed9_0000);
    }
}

#[test]
fn segment_zero_only_and_uncovered_devices() {
    let d = Dmar::parse(&table(&[drhd(true, 1, 0xfed9_0000, &[]),
        drhd(false, 0, 0xfed9_1000, &[scope(1, 0, &[(2, 0)])])]), pci).unwrap();
    assert_eq!(d.units.len(), 1);
    assert_eq!(d.owner(16), Some(0));
    assert_eq!(d.owner(17), None);
}

#[test]
fn resolves_multihop_endpoints_and_subordinate_bus_ranges() {
    let read = |b, d, f, off| match (b, d, f, off) {
        (0, 1, 0, 8) | (2, 3, 0, 8) => 0x0604_0000,
        (0, 1, 0, 0x18) => 0x0009_0200,
        (2, 3, 0, 0x18) => 0x0009_0502,
        _ => pci(b, d, f, off),
    };
    let d = Dmar::parse(&table(&[drhd(false, 0, 0xfed9_0000,
        &[scope(1, 0, &[(1, 0), (4, 2)]), scope(2, 0, &[(1, 0), (3, 0)])])]), read).unwrap();
    assert_eq!(d.owner(0x222), Some(0));
    for id in [0x500, 0x678, 0x9ff] { assert_eq!(d.owner(id), Some(0)); }
    for id in [0x221, 0x4ff, 0xa00] { assert_eq!(d.owner(id), None); }
}

#[test]
fn absent_paths_do_not_cover_other_requesters() {
    let read = |b, d, f, off| if (b, d, f, off) == (0, 1, 0, 0) { u32::MAX } else { pci(b, d, f, off) };
    let d = Dmar::parse(&table(&[drhd(false, 0, 0xfed9_0000,
        &[scope(1, 0, &[(1, 0), (4, 0)]), scope(1, 0, &[(2, 0)])])]), read).unwrap();
    assert_eq!(d.owner(32), None);
    assert_eq!(d.owner(16), Some(0));
}

#[test]
fn reserved_ranges_are_inclusive_in_firmware_and_scoped() {
    let d = Dmar::parse(&table(&[drhd(true, 0, 0xfed9_0000, &[]),
        rmrr(0xa0000, 0xbffff, &[scope(1, 0, &[(2, 0)]), scope(1, 0, &[(3, 0)])])]), pci).unwrap();
    assert_eq!(d.reserved.len(), 2);
    let r = d.reserved[0];
    assert_eq!((r.start, r.end), (0xa0000, 0xc0000));
    assert!(r.scope.contains(16));
    assert!(!r.scope.contains(24));
}

#[test]
fn rejects_truncated_tables_and_checks_checksum() {
    let b = table(&[drhd(true, 0, 0xfed9_0000, &[])]);
    for len in 0..b.len() { assert!(Dmar::parse(&b[..len], pci).is_none(), "length {len}"); }
    for at in 0..b.len() {
        let mut corrupt = b.clone();
        corrupt[at] ^= 1;
        assert!(Dmar::parse(&corrupt, pci).is_none(), "checksum at {at}");
    }
}

#[test]
fn rejects_malformed_block_and_scope_lengths_without_panicking() {
    for len in [0, 1, 3, 15, 65535] {
        let mut block = drhd(true, 0, 0xfed9_0000, &[]);
        block[2..4].copy_from_slice(&(len as u16).to_le_bytes());
        assert!(Dmar::parse(&table(&[block]), pci).is_none());
    }
    for len in [0, 1, 6, 7, 9, 255] {
        let mut s = scope(1, 0, &[(2, 0)]);
        s[1] = len;
        assert!(Dmar::parse(&table(&[drhd(false, 0, 0xfed9_0000, &[s])]), pci).is_none());
    }
}

#[test]
fn rejects_ambiguous_ownership_and_capacity_overflow() {
    let explicit = || drhd(false, 0, 0xfed9_1000, &[scope(1, 0, &[(2, 0)])]);
    for blocks in [vec![explicit(), explicit()],
        vec![drhd(true, 0, 0xfed9_0000, &[]), drhd(true, 0, 0xfed9_1000, &[])],
        vec![explicit(), drhd(false, 0, 0xfed9_2000, &[scope(1, 0, &[(2, 0)])])]] {
        assert!(Dmar::parse(&table(&blocks), pci).is_none());
    }
    let blocks: Vec<_> = (0..=dmar::MAX_UNITS).map(|n| drhd(false, 0, 0xfed9_0000 + n as u64 * 4096, &[])).collect();
    assert!(Dmar::parse(&table(&blocks), pci).is_none());
}

#[test]
fn rejects_bad_addresses_paths_and_reserved_ranges() {
    for base in [0, 0xfed9_0001, u64::MAX & !4095] {
        assert!(Dmar::parse(&table(&[drhd(true, 0, base, &[])]), pci).is_none());
    }
    for s in [scope(1, 0, &[(32, 0)]), scope(1, 0, &[(2, 8)]), scope(5, 0, &[(2, 0)]),
        scope(1, 0, &[(2, 0), (3, 0)]), scope(2, 0, &[(2, 0)])] {
        assert!(Dmar::parse(&table(&[drhd(false, 0, 0xfed9_0000, &[s])]), pci).is_none());
    }
    for (start, end) in [(4096, 4095), (1, 4095), (4096, 8192), (0, u64::MAX)] {
        assert!(Dmar::parse(&table(&[rmrr(start, end, &[scope(1, 0, &[(2, 0)])])]), pci).is_none());
    }
}

#[test]
fn interrupt_scopes_never_grant_dma_access() {
    let d = Dmar::parse(&table(&[vec![99, 0, 4, 0], drhd(false, 0, 0xfed9_0000,
        &[scope(3, 0, &[(31, 0)]), scope(4, 0, &[(31, 1)])])]), pci).unwrap();
    assert_eq!(d.owner(248), None);
    assert_eq!(d.owner(249), None);
    assert_eq!(d.ioapics.len(), 1);
    assert_eq!((d.ioapics[0].id, d.ioapics[0].sid, d.ioapics[0].unit), (0, 248, 0));
}

#[test]
fn ioapic_sources_use_firmware_ids_and_do_not_require_a_pci_function() {
    let mut a = scope(3, 0, &[(1, 0), (7, 3)]);
    a[4] = 12;
    let mut b = scope(3, 0, &[(31, 0)]);
    b[4] = 2;
    let read = |bus, dev, func, off| match (bus, dev, func, off) {
        (0, 1, 0, 0) => 0x1234_8086,
        (0, 1, 0, 8) => 0x0604_0000,
        (0, 1, 0, 0x18) => 0x0005_0200,
        _ => u32::MAX,
    };
    let d = Dmar::parse(&table(&[drhd(true, 0, 0xfed9_0000, &[b]),
        drhd(false, 0, 0xfed9_1000, &[a])]), read).unwrap();
    assert_eq!(d.ioapics.len(), 2);
    assert_eq!((d.ioapics[0].id, d.ioapics[0].sid, d.ioapics[0].unit), (2, 248, 0));
    assert_eq!((d.ioapics[1].id, d.ioapics[1].sid, d.ioapics[1].unit), (12, 0x23b, 1));
    // The interrupt scope does not divert PCI DMA from INCLUDE_PCI_ALL.
    assert_eq!(d.owner(0x23b), Some(0));
}

#[test]
fn rejects_ambiguous_ioapic_ids_and_interrupt_scopes_in_reserved_memory() {
    let a = scope(3, 0, &[(31, 0)]);
    let b = scope(3, 1, &[(2, 0)]);
    for blocks in [
        vec![drhd(true, 0, 0xfed9_0000, &[a.clone(), b.clone()])],
        vec![drhd(true, 0, 0xfed9_0000, &[a.clone()]), drhd(false, 0, 0xfed9_1000, &[b])],
        vec![rmrr(0xa0000, 0xbffff, &[a])],
    ] {
        assert!(Dmar::parse(&table(&blocks), pci).is_none());
    }
}

fn madt(entries: &[&[u8]]) -> Vec<u8> {
    let mut b = vec![0; 44];
    b[..4].copy_from_slice(b"APIC");
    for e in entries { b.extend_from_slice(e); }
    let len = b.len() as u32;
    b[4..8].copy_from_slice(&len.to_le_bytes());
    checksum(&mut b);
    b
}

#[test]
fn madt_ioapic_indices_follow_table_order_not_firmware_ids() {
    let a = [1, 12, 12, 0, 0, 0, 0xc0, 0xfe, 0, 0, 0, 0];
    let b = [1, 12, 2, 0, 0, 0x10, 0xc0, 0xfe, 24, 0, 0, 0];
    let ids = dmar::madt_ioapics(&madt(&[&[99, 2], &a, &b])).unwrap();
    assert_eq!(&*ids, &[12, 2]);
    assert!(dmar::madt_ioapics(&madt(&[&a, &a])).is_none());
}

#[test]
fn madt_rejects_bad_lengths_and_checksum() {
    let mut b = madt(&[&[1, 12, 0, 0, 0, 0, 0xc0, 0xfe, 0, 0, 0, 0]]);
    for len in 0..b.len() { assert!(dmar::madt_ioapics(&b[..len]).is_none()); }
    b[9] ^= 1;
    assert!(dmar::madt_ioapics(&b).is_none());
    for entry in [&[1, 2][..], &[99, 0][..], &[1, 255][..], &[0][..]] {
        assert!(dmar::madt_ioapics(&madt(&[entry])).is_none());
    }
}

#[test]
fn remappable_msi_encodes_all_handle_bits_without_subhandles() {
    for index in [0, 1, 255, 32767, 32768, 65535] {
        let (addr, data) = format::msi(index);
        assert_eq!(addr & 0xfff0_001b, 0xfee0_0010);
        assert_eq!((((addr >> 5) & 0x7fff) | ((addr & 4) << 13)) as u16, index);
        assert_eq!(data, 0);
    }
    assert_eq!(format::IR_ENTRIES, 1 << (format::IR_SIZE + 1));
}

#[test]
fn interrupt_entries_require_exact_source_and_fixed_edge_delivery() {
    for (sid, vector) in [(0x1234, 0x40), (0xffff, 0x7f), (0, 0x30)] {
        let [lo, hi] = format::irte(sid, vector);
        assert_eq!(lo, (vector as u64) << 16 | 1);
        assert_eq!(hi & 0xffff, sid as u64);
        assert_eq!((hi >> 18) & 3, 1); // SVT: validate requester
        assert_eq!((hi >> 16) & 3, 0); // SQ: all 16 bits
        assert_eq!(hi >> 20, 0);
    }
}

#[test]
fn contexts_translate_only_and_choose_supported_page_depth() {
    assert_eq!(format::levels(1 << 9), Some(3));
    assert_eq!(format::levels((1 << 9) | (1 << 10)), Some(4));
    assert_eq!(format::levels(0), None);
    let [lo, hi] = format::context(0x1234_5000, 0xabcd, 4);
    assert_eq!(lo, 0x1234_5001); // TT=00, ATS forbidden
    assert_eq!(hi, 0xabcd02);
}

#[test]
fn invalidations_include_domain_draining_and_completion_store() {
    assert_eq!(format::invalidate_context(), [0x11, 0]);
    assert_eq!(format::invalidate_iotlb(None, 0xc0), [0xd2, 0]);
    assert_eq!(format::invalidate_iotlb(Some(123), 0xc0), [(123 << 16) | 0xe2, 0]);
    assert_eq!(format::invalidate_interrupts(), [4, 0]);
    assert_eq!(format::wait(0x123400, 42), [(42 << 32) | 0x65, 0x123400]);
}

#[test]
fn dma_ranges_cannot_wrap_or_alias_upper_address_bits() {
    assert_eq!(format::range((1 << 39) - 4096, 4096, 39), Some((1 << 39) - 4096..1 << 39));
    for (start, len) in [(1, 4096), (4096, 1), (1 << 39, 4096), (usize::MAX - 4095, 8192)] {
        assert_eq!(format::range(start, len, 39), None);
    }
    assert!(format::range(1 << 39, 4096, 48).is_some());
    assert_eq!(format::ADDR & 4095, 0);
    assert_eq!(format::PRESENT, format::READ);
    assert_eq!(format::WRITE, 2);
    assert_eq!(format::SNOOP, 1 << 11);
}

#[test]
fn device_permissions_distinguish_bounce_pools_and_queues() {
    assert!(Access::Read.read());
    assert!(!Access::Read.write());
    assert!(!Access::Write.read());
    assert!(Access::Write.write());
    assert!(Access::ReadWrite.read() && Access::ReadWrite.write());
    let mut mappings = mappings::Mappings::<1>::new();
    assert!(mappings.acquire(1, 0x1000, 4096, Access::Write));
    assert!(!mappings.acquire(1, 0x1000, 4096, Access::Write));
    assert!(!mappings.release(1, 0x1000, 4096));
    assert!(mappings.release(1, 0x1000, 4096));
}
