//! Run the production creation checks before any guest allocation occurs.
use l4h_abi as abi;
use l4h_host as host;
const BLOCK: usize = 2 << 20;
const PAGE: usize = 4096;
const MAX_VSPACES: usize = 64;
const IO_POOL_MIN: usize = 1 << 20;
const IO_POOL_MAX: usize = 256 << 20;
struct GuestConfig { vcpus: usize, ram: usize, vspaces: usize, ram_base: usize, io_pool: usize }
struct Kernel { ram_base: usize }
include!(env!("L4H_GUEST_POOL_TEST_SRC"));

#[test]
fn pool_frame_alignment_is_checked_before_guest_creation() {
    for io_pool in [1 << 20, 2 << 20, 4 << 20, 256 << 20] {
        for offset in [0, 1, PAGE, BLOCK - PAGE, BLOCK] {
            let ram_base = (1 << 32) + offset;
            let cfg = GuestConfig { vcpus: 1, ram: 128 << 20, vspaces: 64, ram_base, io_pool };
            let expected = if offset % PAGE != 0 || (io_pool >= BLOCK && offset % BLOCK != 0) { Err(None) } else { Ok(()) };
            assert_eq!(validate(&cfg, &Kernel { ram_base }), expected, "pool={io_pool}, base={ram_base:#x}");
        }
    }
}
