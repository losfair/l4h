//! Production control handlers with a backend that records attachments.
use l4h_abi as abi;
use l4h_host as host;

const MAX_GUESTS: usize = 64;
const ENOENT: i64 = 2;
const EINVAL: i64 = 22;

#[derive(Debug, PartialEq, Eq)]
struct Attachment {
    id: usize,
    disk: usize,
    flags: u64,
    start: u64,
    sectors: u64,
    extents: (u64, u64),
}

#[derive(Default)]
struct Vmmgr { attached: Vec<Attachment> }
impl Vmmgr {
    fn attach_disk(&mut self, id: usize, disk: usize, flags: u64, start: u64, sectors: u64,
        extents: (u64, u64)) -> Result<(), i64> {
        self.attached.push(Attachment { id, disk, flags, start, sectors, extents });
        Ok(())
    }
}

include!(env!("L4H_BLK_ATTACH_TEST_SRC"));

#[test]
fn invalid_extent_counts_never_reach_the_backend() {
    let mut h = Vmmgr::default();
    for n in [0, host::blk::MAX_EXTENTS as u64 + 1, u64::MAX] {
        assert_eq!(execute(&mut h, 0, abi::CTL_BLK_ATTACH_EXTENTS, &[1, 0, 0, 0, n, 0]), Err(EINVAL));
        assert!(h.attached.is_empty(), "extent count {n} reached the backend");
    }
}

#[test]
fn valid_extent_counts_preserve_offset_flags_and_target() {
    let mut h = Vmmgr::default();
    let flags = abi::BLK_RO | abi::BLK_VOLATILE;
    for n in [1, 2, host::blk::MAX_EXTENTS as u64] {
        assert_eq!(execute(&mut h, 0, abi::CTL_BLK_ATTACH_EXTENTS, &[1, 3, flags, 64, n, 0]), Ok(()));
        assert_eq!(h.attached.pop(), Some(Attachment {
            id: 1, disk: 3, flags, start: 0, sectors: 0, extents: (n, 64),
        }));
    }
}

#[test]
fn window_attachments_keep_zero_means_to_the_end() {
    let mut h = Vmmgr::default();
    for (start, sectors) in [(0, 0), (8192, 0), (8192, 16384)] {
        assert_eq!(execute(&mut h, 0, abi::CTL_BLK_ATTACH, &[1, 3, 0, start, sectors, 0]), Ok(()));
        assert_eq!(h.attached.pop(), Some(Attachment {
            id: 1, disk: 3, flags: 0, start, sectors, extents: (0, 0),
        }));
    }
}

#[test]
fn both_operations_reject_self_attachment_and_unknown_flags() {
    let mut h = Vmmgr::default();
    for op in [abi::CTL_BLK_ATTACH, abi::CTL_BLK_ATTACH_EXTENTS] {
        assert_eq!(execute(&mut h, 0, op, &[0, 0, 0, 0, 1, 0]), Err(EINVAL));
        assert_eq!(execute(&mut h, 0, op, &[1, 0, 4, 0, 1, 0]), Err(EINVAL));
    }
    assert!(h.attached.is_empty());
}
