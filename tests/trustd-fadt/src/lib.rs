//! trustd's copy of the FADT (host/l4h-trustd/src/fadt.rs), compiled
//! unchanged.  Run with tests/run-trusttest.sh.
#[path = "../../../host/l4h-trustd/src/fadt.rs"]
mod fadt;

#[cfg(test)]
mod tests {
    use super::fadt::fadt;

    /// A FADT of `len` bytes and revision `revision`, PM1a at port 0x400
    /// (event) and 0x404 (control), 4 and 2 bytes, then the rest of root's
    /// copy of the tables: the DSDT, here bytes that read as an X_PM1a
    /// event block in system memory at 0x4141414141414141.
    fn tables(len: usize, revision: u8) -> Vec<u8> {
        let mut t = vec![0u8; len];
        t[..4].copy_from_slice(b"FACP");
        t[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        t[8] = revision;
        t[56..60].copy_from_slice(&0x400u32.to_le_bytes());
        t[64..68].copy_from_slice(&0x404u32.to_le_bytes());
        t[88] = 4;
        t[89] = 2;
        let mut dsdt = vec![0x41u8; 300];
        dsdt[..4].copy_from_slice(b"DSDT");
        t.extend(dsdt);
        t
    }

    #[test]
    fn a_full_fadt_is_read() {
        let all = tables(276, 6);
        let f = fadt(&all[..276]).unwrap();
        let a = f.pm1a_event_block().unwrap();
        assert_eq!((a.address, a.bit_width), (0x400, 32));
        assert_eq!(f.pm1a_control_block().unwrap().address, 0x404);
    }

    #[test]
    fn a_short_fadt_is_read_only_as_far_as_it_goes() {
        // ACPI 1.0's 116 bytes, and a revision 2 table cut before its
        // X_PM1a fields: nothing comes from the bytes after it.
        for (len, revision) in [(116, 1), (132, 2), (148, 3)] {
            let all = tables(len, revision);
            let f = fadt(&all[..len]).unwrap();
            let a = f.pm1a_event_block().unwrap();
            assert_eq!(a.address, 0x400, "{len} bytes, revision {revision}");
            assert_eq!(f.pm1a_control_block().unwrap().address, 0x404, "{len}");
            assert!(f.pm1b_event_block().unwrap().is_none(), "{len}");
        }
    }

    #[test]
    fn a_fadt_without_the_pm1_blocks_is_refused() {
        for len in [36, 60, 115] {
            let all = tables(len.max(92), 1);
            assert!(fadt(&all[..len]).is_err(), "{len} bytes");
        }
    }
}
