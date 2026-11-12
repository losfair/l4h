//! What a driver's device code sees of the SDK: the NicDriver trait and
//! Hw, the hardware root gave it.  Free of the seL4 loop (lib.rs), so that
//! a driver's own source compiles into a Linux test harness too, with VFIO
//! standing in for root (tests/nicdrv-vfio).

pub use l4h_netcore::Frame;
pub use l4h_netcore::offload;
pub use l4h_rt::host::blk::PciRegion;
pub use l4h_rt::host::net::{HDR_SIZE as HDR, LinkState, MAX_FRAME};
pub use l4h_rt::host::nicd::{self, Config, Manifest, PciMatch};
pub use l4h_rt::host::uplink::Offer;

/// A frame that spans receive buffers while they arrive: drivers that
/// assemble frames (gVNIC, ENA, X550) keep one.
pub type Partial = l4h_rt::host::fixed::ArrayVec<u8, { MAX_FRAME }>;

/// A NIC's device code.  The methods are those netd's drivers had, and
/// mean what they did there.
pub trait NicDriver: Sized {
    /// Probe the device and bring it up, with its receive buffers posted:
    /// Err refuses it (root unbinds it).
    fn start(hw: &Hw) -> Result<Self, &'static str>;
    /// What the device takes and gives (written to the channel once).
    fn offer(&self) -> Offer;
    /// RX interrupts off while the loop drains the device.
    fn rx_begin(&mut self);
    /// RX interrupts on again; false if frames arrived meanwhile (the loop
    /// comes back).  Returns buffers to the device.
    fn rx_done(&mut self) -> bool;
    /// The next received frame, into `out`, its virtio-net header into
    /// `hdr` (num_buffers cleared): its length.
    fn receive(&mut self, out: &mut [u8], hdr: &mut [u8; HDR]) -> Option<usize>;
    /// Queue a frame (within the offer); false if the device has no room.
    fn transmit(&mut self, frame: &[u8], hdr: &[u8; HDR]) -> bool;
    /// TX completion interrupts on or off; true if completions came
    /// meanwhile (try transmit again).
    fn tx_interrupts(&mut self, on: bool) -> bool;
    /// Tell the device about what was queued since the last call.
    fn kick_tx(&mut self);
    fn link(&self) -> LinkState {
        LinkState::VIRTUAL
    }
    /// Root's tick, if the manifest asks for one (nicd::F_TIMER).
    fn timer(&mut self) {}
    /// A control message from dom0: the answer's length in `resp`, or None
    /// to refuse it.
    fn ctl(&mut self, _req: &[u8], _resp: &mut [u8]) -> Option<usize> {
        None
    }
    /// Quiesce: no more DMA.  Root does not rely on it.
    fn stop(&mut self) {}
}

/// What root gave this driver: its configuration and the means to reach
/// its device.
pub struct Hw {
    pub config: &'static Config,
    pub tsc_hz: u64,
}

impl Hw {
    /// BAR b's mapping.
    pub fn bar(&self, b: usize) -> PciRegion {
        self.config.bars[b]
    }

    /// The DMA region.
    pub fn dma(&self) -> l4h_virtio::Dma {
        l4h_virtio::Dma::new(nicd::DMA_VA, self.config.dma_paddr, self.config.dma_size as usize)
    }

    /// Point MSI-X entries [0, n) at this driver's vector (and unmask
    /// them).  n is at most the table's size.
    pub fn program_msix(&self, n: usize) {
        let c = self.config;
        let msix = l4h_virtio::Mmio(c.msix_table.va as usize);
        for e in 0..n.min((c.msix_table.len / 16) as usize) {
            msix.w32(e * 16, c.msi_address as u32);
            msix.w32(e * 16 + 4, (c.msi_address >> 32) as u32);
            msix.w32(e * 16 + 8, c.msi_data);
            msix.w32(e * 16 + 12, 0);
        }
    }

    /// Bytes of the configuration space as root snapshotted it at bind.
    pub fn cfg_snapshot(&self) -> &'static [u8; 4096] {
        unsafe { &*(nicd::CFG_VA as *const [u8; 4096]) }
    }

    /// The driver is confined: outside the TCB (nicd::CONFINED).
    pub fn confined(&self) -> bool {
        self.config.flags & nicd::CONFINED != 0
    }
}
