//! AMD-Vi last-level entries (host/l4h-root/src/amdvi.rs `leaf_pte`),
//! extracted unchanged by tests/run-devicetest.sh.
#![allow(dead_code)]
include!(env!("L4H_AMDVI_PTE_TEST_SRC"));

#[test]
fn an_entry_maps_its_own_page() {
    let e = leaf_pte(0, 0x1234_5000, false);
    assert_eq!(e & PTE_ADDR, 0x1234_5000);
    assert_eq!(e & (PTE_PR | PTE_IR | PTE_IW), PTE_PR | PTE_IR);
    // Mapped again, written too: the union of the permissions, one page.
    let e = leaf_pte(e, 0x1234_5000, true);
    assert_eq!((e & PTE_ADDR, e & PTE_IW), (0x1234_5000, PTE_IW));
    // The highest page the tables reach.
    assert_eq!(leaf_pte(0, IOVA_END - 0x1000, true) & PTE_ADDR, (IOVA_END - 0x1000) as u64);
    assert_eq!(IOVA_END, 1 << 48);
}

#[test]
#[should_panic(expected = "over an entry for")]
fn an_entry_for_another_page_is_not_merged() {
    // A page 256 TiB up lands in the same entry modulo the tables' reach:
    // never or-ed into it.
    let e = leaf_pte(0, 0x1000, true);
    leaf_pte(e, IOVA_END + 0x1000, true);
}

#[test]
#[should_panic(expected = "not one an entry maps")]
fn an_address_past_the_entry_format_is_refused() {
    leaf_pte(0, 1 << 52, true);
}
