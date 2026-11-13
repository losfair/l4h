//! The NIC driver SDK as a driver's device code sees it
//! (host/l4h-nicdrv/src/driver.rs, compiled unchanged), for the VFIO
//! harnesses (ena-vfio, ixgbe-vfio, mlx5-vfio): they run the production
//! drivers on Linux, with VFIO standing in for root.  A harness includes
//! this as `mod sdk`, next to `extern crate self as l4h_rt` with
//! `pub use l4h_host as host`, and the driver's own source.

#[allow(dead_code, unused_imports)]
#[path = "../../host/l4h-nicdrv/src/driver.rs"]
mod driver;
#[allow(unused_imports)]
pub use driver::*;

#[allow(dead_code)]
/// What root would give a driver of `bdf` (bus << 8 | dev << 3 | func):
/// BAR b at `bars[b]`, its MSI-X table (VFIO owns the device's, so the
/// harness passes a copy), its DMA region.
pub fn config(bdf: u32, revision: u32, bars: [PciRegion; 6], msix_table: PciRegion, dma_paddr: u64, dma_size: u64) -> Config {
    Config { uplink: 0, pci_bdf: bdf, revision, bars, msix_table, dma_paddr, dma_size, ..Default::default() }
}

#[allow(dead_code)]
/// The hardware a driver sees, for `config`, which lives for the test.
pub fn hw(config: Config, tsc_hz: u64) -> Hw {
    Hw { config: Box::leak(Box::new(config)), tsc_hz }
}
