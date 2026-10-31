//! Sizing a guest's I/O pool (DESIGN.md §8.1).  Every buffer a guest's
//! virtio devices use bounces through the pool, and a virtio-net driver
//! keeps its receive ring full: those buffers stay allocated, and must not
//! leave the pool too small or too fragmented for a disk request, which
//! would then be requeued for ever (a full pool is silent).

/// What one receive buffer holds of the pool while it waits for a packet.
/// l4h-vmm offers GUEST_TSO4/6 without MRG_RXBUF or indirect descriptors,
/// so Linux posts "big" buffers: a header and MAX_SKB_FRAGS (17) pages,
/// 18 pages in 19 descriptors.
pub const RX_BUF_BYTES: usize = 18 * 4096;
pub const RX_BUF_DESCS: usize = 19;
/// The largest and smallest receive queue a VMM offers.
pub const RX_QUEUE_MAX: u32 = 256;
pub const RX_QUEUE_MIN: u32 = 32;

/// The receive queue size for each of a guest's `nics` virtio-net
/// devices: the largest power of two in RX_QUEUE_MIN..=RX_QUEUE_MAX whose
/// full rings, for every NIC together, hold at most half of an I/O pool of
/// `pool` bytes.  A disk request takes at most a quarter (the VMM's
/// size_max), so one always fits once other requests complete.
pub const fn rx_queue_size(pool: usize, nics: usize) -> u32 {
    let nics = if nics == 0 { 1 } else { nics };
    let buffers = pool / 2 / nics / RX_BUF_BYTES;
    let mut q = RX_QUEUE_MAX;
    while q > RX_QUEUE_MIN && q as usize / RX_BUF_DESCS > buffers {
        q /= 2;
    }
    q
}

/// The smallest power-of-two I/O pool, at least `min`, that gives each of
/// `nics` virtio-net devices a full receive queue (RX_QUEUE_MAX).
pub const fn for_nics(nics: usize, min: usize) -> usize {
    let standing = nics * (RX_QUEUE_MAX as usize / RX_BUF_DESCS) * RX_BUF_BYTES;
    let pool = (2 * standing).next_power_of_two();
    if pool > min { pool } else { min }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rx_rings_leave_half_the_pool() {
        // A sandbox: 4 MiB and one NIC keep a full queue (13 buffers).
        assert_eq!(rx_queue_size(4 << 20, 1), RX_QUEUE_MAX);
        // dom0 on a host with two uplinks and an internal switch.
        assert_eq!(rx_queue_size(4 << 20, 3), 128);
        assert_eq!(rx_queue_size(1 << 20, 3), RX_QUEUE_MIN);
        for pool in [1 << 20, 2 << 20, 4 << 20, 8 << 20, 64 << 20] {
            for nics in 1..=4 {
                let q = rx_queue_size(pool, nics) as usize;
                assert!(
                    q == RX_QUEUE_MIN as usize || nics * (q / RX_BUF_DESCS) * RX_BUF_BYTES <= pool / 2,
                    "{pool} {nics}"
                );
            }
        }
        assert_eq!(for_nics(3, 4 << 20), 8 << 20);
        assert_eq!(rx_queue_size(for_nics(3, 4 << 20), 3), RX_QUEUE_MAX);
        assert_eq!(for_nics(1, 4 << 20), 4 << 20);
        assert_eq!(for_nics(0, 4 << 20), 4 << 20);
    }
}
