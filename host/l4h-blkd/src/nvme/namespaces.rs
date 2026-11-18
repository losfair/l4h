use l4h_rt::host::{blk::MAX_UNITS, fixed::ArrayVec};

pub(super) fn ids<I: Iterator<Item = u32>>(
    version: u32, max_nsid: u32, active_list: impl FnOnce() -> Option<I>,
) -> ArrayVec<u32, MAX_UNITS> {
    if version >= 0x0001_0100 && let Some(active) = active_list() {
        let mut ids = ArrayVec::new();
        let mut last = 0;
        for id in active.take(MAX_UNITS) {
            // The active namespace list is ascending, with zero padding.
            if id <= last || id == u32::MAX {
                break;
            }
            let _ = ids.push(id);
            last = id;
        }
        return ids;
    }
    // NVMe 1.0 has no active namespace list. Probe IDs up to the
    // controller's reported maximum and our unit limit.
    (1..=max_nsid.min(MAX_UNITS as u32)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvme_1_0_probes_ids_without_requesting_the_active_list() {
        let probes = ids::<core::iter::Empty<u32>>(0x0001_0000, 3, || {
            panic!("NVMe 1.0 must not receive Identify Active Namespace List");
        });
        assert_eq!(&probes[..], &[1, 2, 3]);
    }

    #[test]
    fn failed_active_list_falls_back_to_bounded_probes() {
        let probes = ids::<core::iter::Empty<u32>>(0x0001_0400, u32::MAX, || None);
        assert!(probes.iter().copied().eq(1..=MAX_UNITS as u32));
    }

    #[test]
    fn active_list_keeps_nonconsecutive_ids_and_stops_at_padding() {
        let active = ids(0x0001_0400, 16, || Some([1, 3, 0, 4].into_iter()));
        assert_eq!(&active[..], &[1, 3]);
    }
}
