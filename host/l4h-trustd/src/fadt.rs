//! The FADT as the `acpi` crate reads it, from the table root gave us.

use acpi::sdt::fadt::Fadt;

/// ACPI 1.0's FADT, through the PM1 blocks and their lengths and beyond
/// (to the reset register): what every FADT has.
pub const FADT_MIN: usize = 116;

/// The `acpi` crate's view of the FADT `table` (header included, as long
/// as the header says), copied: a FADT older or shorter than the crate's
/// struct reads as zero past its end (no extended address, so the crate
/// takes the 32-bit fields), never as the table after it.
pub fn fadt(table: &[u8]) -> Result<Fadt, &'static str> {
    if table.len() < FADT_MIN {
        return Err("FADT too short");
    }
    let mut buf = [0u8; core::mem::size_of::<Fadt>()];
    let n = table.len().min(buf.len());
    buf[..n].copy_from_slice(&table[..n]);
    // Fadt is packed (alignment 1) and all integers: any bytes are one.
    Ok(unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Fadt) })
}
