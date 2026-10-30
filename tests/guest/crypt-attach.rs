//! Rejected attachments must reclaim their allocations before VM destroy.
#[path = "../../tools/l4hctl/src/lib.rs"]
#[allow(dead_code)]
mod ctl;
use ctl::*;

fn main() {
    let c = Ctl::open().unwrap();
    let key = DiskKey::read("/bin/cryptblk.key").unwrap();
    let wrong = DiskKey::read("/bin/cryptblk-wrong.key").unwrap();
    // The runner already holds two read-only views with the right key.
    for pool in [1 << 20, 4 << 20] {
        let id = c.call(CTL_VM_CREATE, &[128 << 20, 1, 0, 0, pool], b"reject-attach", &[]).unwrap().vals[0];
        let reject = |n| {
            let (start, sectors, k) = match n % 3 {
                0 => (2048, 16384, Some(&wrong.0)),
                1 => (2056, 16376, Some(&key.0)),
                _ => (2048, 16384, None),
            };
            let error = c.blk_attach(id, 0, BLK_RO, start, sectors, k).unwrap_err();
            assert!(error.0.contains("busy"), "{}", error.0);
        };
        // First use can allocate persistent blkd/IOMMU page tables.
        reject(0);
        let free = c.host_info().unwrap().free;
        for n in 0..256 { reject(n); }
        assert!(c.host_info().unwrap().free >= free, "failed attaches retained memory in the live VM");
        assert!(c.disk_attachments(0).unwrap().iter().all(|a| a.vm != id));
        let r = c.call(CTL_BLK_ATTACH, &[id, 0, BLK_RO | BLK_ENCRYPT, 2048, 16384], &key.0, &[]).unwrap();
        assert_eq!(r.vals[0], BLK_RO | BLK_ENCRYPT, "applied flags must survive blkd/root/vmmgr IPC");
        assert!(c.disk_attachments(0).unwrap().iter().any(|a| a.vm == id && a.encrypted));
        c.vm_destroy(id).unwrap();
    }
    println!("CRYPTBLK: rejected attaches reclaim memory before VM destroy");
}
