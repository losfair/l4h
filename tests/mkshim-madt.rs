// Run with tests/run-acstest.sh; no hardware is needed.
#[path = "../boot/l4h-mkshim/src/madt.rs"]
mod madt;

use madt::keep;

const LAPIC: u8 = 0;
const IOAPIC: u8 = 1;
const ISO: u8 = 2;
const NMI_SOURCE: u8 = 3;
const LAPIC_NMI: u8 = 4;
const LAPIC_OVERRIDE: u8 = 5;
const IOSAPIC: u8 = 6;
const X2APIC: u8 = 9;
const X2APIC_NMI: u8 = 10;

#[test]
fn every_partition_keeps_the_ioapics() {
    // A secondary kernel (no_legacy_irq) drives no I/O APIC but keeps the
    // pages of those its MADT lists out of user device memory: one left
    // out of its copy is device memory its root hands out, whose
    // redirection entries reach every CPU of the machine.
    for k in 0..8 {
        assert!(keep(IOAPIC, k), "partition {k} lost the I/O APICs");
    }
}

#[test]
fn interrupt_routing_is_partition_0s() {
    for ty in [ISO, NMI_SOURCE, IOSAPIC] {
        assert!(keep(ty, 0), "type {ty}");
        for k in 1..8 {
            assert!(!keep(ty, k), "type {ty} in partition {k}");
        }
    }
}

#[test]
fn local_apics_come_from_the_shim() {
    for k in 0..8 {
        assert!(!keep(LAPIC, k));
        assert!(!keep(X2APIC, k));
        for ty in [LAPIC_NMI, LAPIC_OVERRIDE, X2APIC_NMI, 0x7f, 0xff] {
            assert!(keep(ty, k), "type {ty} in partition {k}");
        }
    }
}
