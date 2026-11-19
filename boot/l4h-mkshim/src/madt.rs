//! Which of the firmware's MADT entries a partition's copy keeps
//! (build_acpi).  No hardware access: tests/mkshim-madt.rs runs it on the
//! host.

/// Whether partition `k`'s MADT keeps an entry of type `ty`.  Every
/// partition gets its own CPUs' local APIC entries (types 0 and 9) from
/// the shim instead.  Partition 0 drives the interrupt controllers, so it
/// alone keeps the interrupt source overrides, NMI sources and I/O SAPICs
/// (types 2, 3, 6).  Every partition keeps the I/O APICs (type 1): the
/// others' kernels boot with no_legacy_irq and drive none of them, but
/// keep each one's registers out of user device memory (kernel patch
/// 0046, and FL4), and only by the MADT do they know where they are.
pub fn keep(ty: u8, k: usize) -> bool {
    match ty {
        0 | 9 => false,
        1 => true,
        // Interrupt source override, NMI source, I/O SAPIC.
        2 | 3 | 6 => k == 0,
        _ => true,
    }
}
