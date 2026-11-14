//! NIC driver components (nicd, DESIGN.md §9.8): one per bound network
//! device, outside netd.  A nicd joins netd through an uplink channel
//! (crate::uplink) and root through a mailbox (crate::mailbox), and gets
//! only its own device's resources: the BARs its manifest names, a DMA
//! region in the device's IOMMU domain, one interrupt vector, and a
//! read-only snapshot of the device's configuration space.
//!
//! A driver is data to root: its manifest (`Manifest`, in the ELF section
//! MANIFEST_SECTION) says which devices it drives and what it needs, and
//! root binds devices to drivers from it (l4h-root's nicd.rs).  Root knows
//! no device kind.

use core::sync::atomic::{AtomicU32, AtomicU64};

use crate::blk::PciRegion;

/// Component ids: NICD_ID_BASE + uplink.
pub const NICD_ID_BASE: u32 = 0x800;
/// Uplinks, and so nicds, at most.
pub const MAX_UPLINKS: usize = crate::net::MAX_UPLINKS;

// ---------------------------------------------------------------------
// The manifest.

/// The ELF section a driver's manifest is in: the driver's
/// `l4h_nicdrv::driver!` puts it there, root reads it before anything
/// else (l4h_task::elf::Elf::section), with bounds checks.
pub const MANIFEST_SECTION: &str = ".l4h.driver";
pub const MANIFEST_MAGIC: u32 = 0x4e43_4434; // "4DCN"
/// 2: eight firmware names (MAX_FIRMWARE), for the RTL8125's five.
pub const MANIFEST_ABI: u32 = 2;

/// Manifest::class.
pub const CLASS_ETHERNET: u32 = 1;
pub const CLASS_WIFI: u32 = 2;

/// Manifest::flags.
/// The device is a virtio device: root maps the BARs its virtio
/// capabilities name and gives their regions (Config::virtio).
pub const F_VIRTIO: u32 = 1 << 0;
/// The driver may take a legacy (I/O port) BAR 0: root gives the device's
/// own range of ports (Config::legacy_io).
pub const F_LEGACY_IO: u32 = 1 << 1;
/// The driver wants a deadline timer (watchdogs, management timeouts):
/// root signals it badges::nicd::TIMER every TIMER_MS.
pub const F_TIMER: u32 = 1 << 2;

/// Matches all of a field.
pub const ANY: u16 = 0xffff;

/// A device the driver drives: each id matches if it is ANY or equal;
/// class/class_mask on the 24-bit class code; revision at least.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciMatch {
    pub vendor: u16,
    pub device: u16,
    pub subvendor: u16,
    pub subdevice: u16,
    pub class: u32,
    pub class_mask: u32,
    pub min_revision: u8,
    pub pad: [u8; 3],
}

impl PciMatch {
    pub const NONE: Self = Self::id(0, 0);

    pub const fn id(vendor: u16, device: u16) -> Self {
        PciMatch { vendor, device, subvendor: ANY, subdevice: ANY, class: 0, class_mask: 0, min_revision: 0, pad: [0; 3] }
    }

    /// Whether a device of these identifiers matches.
    pub fn matches(&self, d: &Ids) -> bool {
        let eq = |want: u16, have: u16| want == ANY || want == have;
        self.vendor != 0
            && eq(self.vendor, d.vendor)
            && eq(self.device, d.device)
            && eq(self.subvendor, d.subvendor)
            && eq(self.subdevice, d.subdevice)
            && d.class & self.class_mask == self.class & self.class_mask
            && d.revision >= self.min_revision
    }
}

/// A device's identifiers, as root read them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ids {
    pub vendor: u16,
    pub device: u16,
    pub subvendor: u16,
    pub subdevice: u16,
    /// Base class << 16 | subclass << 8 | programming interface.
    pub class: u32,
    pub revision: u8,
}

/// Configuration-space bytes [offset, offset + len) the driver may write
/// (DESIGN.md §9.8, "Configuration space"); root still refuses its deny
/// list inside them.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CfgWindow {
    pub offset: u16,
    pub len: u16,
}

impl CfgWindow {
    pub const NONE: Self = CfgWindow { offset: 0, len: 0 };
}

pub const MAX_MATCHES: usize = 32;
pub const MAX_FIRMWARE: usize = 8;
pub const FIRMWARE_NAME: usize = 48;
pub const MAX_CFG_WINDOWS: usize = 4;
pub const NAME_LEN: usize = 16;

/// What a driver is for and what it needs: plain integers, any bit
/// pattern of which root can read, and refuse.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Manifest {
    pub magic: u32,
    pub abi: u32,
    /// Its name ("virtio-net", "ixgbe"), NUL padded.
    pub name: [u8; NAME_LEN],
    pub class: u32,
    pub flags: u32,
    pub matches: [PciMatch; MAX_MATCHES],
    pub nr_matches: u32,
    /// Memory BARs it needs (bit b for BAR b): a device without them is
    /// not bound.  And those root maps if the device has them.
    pub bars: u8,
    pub bars_opt: u8,
    /// BARs mapped write-combining.
    pub bars_wc: u8,
    /// The most of a BAR root maps, 2^bits (from its start); a larger
    /// optional BAR is not mapped, a larger required one is mapped up to
    /// this.  At most MAX_BAR_WINDOW_BITS.
    pub bar_window_bits: u8,
    /// MSI-X table entries the device must have.  The driver gets one
    /// vector, remapped for its device: it may point every entry at it.
    pub msix_min: u16,
    pub pad0: u16,
    /// Its DMA region, 2^dma_bits bytes (MIN..=MAX_DMA_BITS).
    pub dma_bits: u8,
    /// Its uplink channel's data areas, 2^channel_bits each
    /// (uplink::MIN..=MAX_DATA_BITS; 0: the default).
    pub channel_bits: u8,
    /// 0: no heap; else a fixed heap of 2^heap_bits (MAX_HEAP_BITS at
    /// most), part of its image.
    pub heap_bits: u8,
    pub pad1: u8,
    /// Bundle names of firmware blobs it may be given (NUL padded).
    pub firmware: [[u8; FIRMWARE_NAME]; MAX_FIRMWARE],
    pub config_writes: [CfgWindow; MAX_CFG_WINDOWS],
    /// Its image, at most 2^image_max_bits bytes of memory.
    pub image_max_bits: u8,
    pub pad2: [u8; 7],
}

pub const MIN_DMA_BITS: u8 = 16;
pub const MAX_DMA_BITS: u8 = 26;
pub const MAX_BAR_WINDOW_BITS: u8 = 26;
pub const MAX_HEAP_BITS: u8 = 24;
pub const MAX_IMAGE_BITS: u8 = 26;

impl Manifest {
    /// A manifest with nothing in it but its header: drivers fill it in
    /// (l4h_nicdrv::manifest!).
    pub const fn empty() -> Self {
        Manifest {
            magic: MANIFEST_MAGIC,
            abi: MANIFEST_ABI,
            name: [0; NAME_LEN],
            class: CLASS_ETHERNET,
            flags: 0,
            matches: [PciMatch::NONE; MAX_MATCHES],
            nr_matches: 0,
            bars: 0,
            bars_opt: 0,
            bars_wc: 0,
            bar_window_bits: 24,
            msix_min: 1,
            pad0: 0,
            dma_bits: 22,
            channel_bits: 0,
            heap_bits: 0,
            pad1: 0,
            firmware: [[0; FIRMWARE_NAME]; MAX_FIRMWARE],
            config_writes: [CfgWindow::NONE; MAX_CFG_WINDOWS],
            image_max_bits: 22,
            pad2: [0; 7],
        }
    }

    pub const fn with_name(mut self, name: &str) -> Self {
        let b = name.as_bytes();
        assert!(b.len() < NAME_LEN);
        let mut i = 0;
        while i < b.len() {
            self.name[i] = b[i];
            i += 1;
        }
        self
    }

    pub const fn with_matches(mut self, m: &[PciMatch]) -> Self {
        assert!(m.len() <= MAX_MATCHES);
        let mut i = 0;
        while i < m.len() {
            self.matches[i] = m[i];
            i += 1;
        }
        self.nr_matches = m.len() as u32;
        self
    }

    pub const fn with_firmware(mut self, names: &[&str]) -> Self {
        assert!(names.len() <= MAX_FIRMWARE);
        let mut i = 0;
        while i < names.len() {
            let b = names[i].as_bytes();
            assert!(b.len() < FIRMWARE_NAME);
            let mut k = 0;
            while k < b.len() {
                self.firmware[i][k] = b[k];
                k += 1;
            }
            i += 1;
        }
        self
    }

    /// Read a manifest from `bytes` (an ELF section): None unless it is
    /// whole, of this ABI, and within every bound.
    pub fn parse(bytes: &[u8]) -> Option<Manifest> {
        if bytes.len() < core::mem::size_of::<Manifest>() {
            return None;
        }
        // Any bit pattern is a Manifest: integers and byte arrays.
        let m: Manifest = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Manifest) };
        m.valid().then_some(m)
    }

    pub fn valid(&self) -> bool {
        let channel = self.channel_bits == 0
            || (crate::uplink::MIN_DATA_BITS..=crate::uplink::MAX_DATA_BITS).contains(&(self.channel_bits as u32));
        self.magic == MANIFEST_MAGIC
            && self.abi == MANIFEST_ABI
            && self.name[0] != 0
            && self.name.contains(&0)
            && matches!(self.class, CLASS_ETHERNET | CLASS_WIFI)
            && self.flags & !(F_VIRTIO | F_LEGACY_IO | F_TIMER) == 0
            && self.nr_matches as usize <= MAX_MATCHES
            && self.bars & !0x3f == 0
            && self.bars_opt & !0x3f == 0
            && self.bars_wc & !(self.bars | self.bars_opt) == 0
            && (12..=MAX_BAR_WINDOW_BITS).contains(&self.bar_window_bits)
            && (1..=2048).contains(&self.msix_min)
            && (MIN_DMA_BITS..=MAX_DMA_BITS).contains(&self.dma_bits)
            && channel
            && self.heap_bits <= MAX_HEAP_BITS
            && (self.heap_bits == 0 || self.heap_bits >= 12)
            && (16..=MAX_IMAGE_BITS).contains(&self.image_max_bits)
            && self.config_writes.iter().all(|w| w.offset as usize + w.len as usize <= 4096)
            && self.firmware.iter().all(|f| f.contains(&0))
    }

    /// The name, up to its NUL.
    pub fn name(&self) -> &str {
        let n = self.name.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
        core::str::from_utf8(&self.name[..n]).unwrap_or("?")
    }

    /// The first of its matches that `d` matches, if any.
    pub fn matching(&self, d: &Ids) -> Option<usize> {
        self.matches[..(self.nr_matches as usize).min(MAX_MATCHES)].iter().position(|m| m.matches(d))
    }

    /// Its channel's data area bits.
    pub fn channel_bits(&self) -> u32 {
        if self.channel_bits == 0 { crate::uplink::DEFAULT_DATA_BITS } else { self.channel_bits as u32 }
    }
}

// ---------------------------------------------------------------------
// What root gives a nicd.

/// The nicd's address space: BAR b, the DMA region, the uplink channel,
/// the control page and the configuration-space snapshot.
pub const fn bar_va(b: usize) -> usize {
    crate::MMIO_VA + b * (1 << MAX_BAR_WINDOW_BITS)
}
pub const DMA_VA: usize = crate::DMA_VA;
pub const CHANNEL_VA: usize = crate::SHARED_VA;
pub const CTL_VA: usize = crate::SHARED_VA + 0x200_0000;
pub const CFG_VA: usize = CTL_VA + 0x1000;
pub const CTL_MAX: usize = 4096;
/// Firmware blob i the manifest names, read-only (Config::firmware).
pub const fn firmware_va(i: usize) -> usize {
    crate::SHARED_VA + 0x1000_0000 + i * FIRMWARE_MAX
}
pub const FIRMWARE_MAX: usize = 64 << 20;
const _: () = assert!(CHANNEL_VA + crate::uplink::MAX_CHANNEL_SIZE <= CTL_VA && bar_va(6) <= crate::DMA_VA);

/// nicd CSpace: its device's IRQ handler, its legacy I/O ports, and netd's
/// notification (badged badges::netd::UPLINK) for its channel.  A
/// configuration-space request (`Published::cfg_req`) is signalled on
/// SLOT_MAILBOX_DONE, as an answer is: root looks at both.
pub const NICD_SLOT_IRQ: u64 = 16;
pub const NICD_SLOT_IOPORT: u64 = 17;
pub const NICD_SLOT_NETD: u64 = 18;

/// Config::flags.
/// Root found the device confined (IOMMU domain, interrupt remapping, an
/// isolation group of its own): the driver is outside the TCB.
pub const CONFINED: u32 = 1 << 0;

/// A nicd's configuration (its info page).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Config {
    /// Its uplink: netd's channel n.
    pub uplink: u32,
    pub pci_bdf: u32,
    pub vendor: u16,
    pub device: u16,
    pub subvendor: u16,
    pub subdevice: u16,
    pub class: u32,
    pub revision: u32,
    pub flags: u32,
    /// The device's MSI: what to write into its MSI-X entries (every entry
    /// it uses, all the same vector).
    pub msi_address: u64,
    pub msi_data: u32,
    pub msix_entries: u32,
    pub msix_table: PciRegion,
    /// BAR b, as mapped at bar_va(b); len 0 if not mapped.
    pub bars: [PciRegion; 6],
    /// Legacy virtio: the I/O port base of BAR 0, the capability in
    /// NICD_SLOT_IOPORT; 0 for none.
    pub legacy_io: u32,
    pub notify_off_multiplier: u32,
    /// F_VIRTIO, a modern device: its capabilities' regions.
    pub common: PciRegion,
    pub notify: PciRegion,
    pub isr: PciRegion,
    pub device_cfg: PciRegion,
    /// The DMA region, mapped at DMA_VA, its bus address `dma_paddr`.
    pub dma_paddr: u64,
    pub dma_size: u64,
    /// The channel, mapped at CHANNEL_VA: data areas of 2^channel_bits.
    pub channel_bits: u32,
    pub reserved: u32,
    /// The firmware blobs the manifest names, at firmware_va(i); len 0 if
    /// the bundle has none of that name.
    pub firmware: [PciRegion; MAX_FIRMWARE],
}

impl Config {
    pub fn bar(&self, b: usize) -> PciRegion {
        self.bars[b]
    }
}

// ---------------------------------------------------------------------
// Root's requests.

use crate::badges::driver as recv;

crate::senders! {
    /// Who posts in the mailbox: l4h-root alone.
    pub enum Sender in recv {
        Root: mailbox;
    }
}

crate::protocol! {
    /// Root's requests to a nicd (crate::mailbox; a failed nicd answers
    /// wire::FAILED).  Root never waits for one, and relies on no answer
    /// for safety: on a fault, a refusal or a restart it turns the
    /// device's bus mastering off itself.
    pub mod call (from: Sender) {
        /// Bring the device up.  Answered once the channel's offer is
        /// written and `ready` set; an error refuses the device (root
        /// unbinds it).
        Start / start = 1 from [Root] () -> ();
        /// Quiesce: stop the device's DMA and stop producing.
        Stop / stop = 2 from [Root] () -> ();
        /// An opaque control message of `len` bytes in the control page
        /// (CTL_VA), from dom0; the answer's bytes replace it there.
        Ctl / ctl = 3 from [Root] (len: usize) -> CtlDone;
        /// Answer: the loop runs.  Root asks every second, and restarts a
        /// nicd that leaves one unanswered (a link that is down stops the
        /// device, not the loop).
        Ping / ping = 4 from [Root] () -> ();
        /// `crate::TEST_INJECT` only: panic.
        TestPanic / test_panic = 0x7e57 from [Root] () -> ();
        /// `crate::TEST_INJECT` only: stop for good without failing.
        TestHang / test_hang = 0x7e58 from [Root] () -> ();
    }
}
const _: () = assert!(call::Request::MAX_WORDS <= crate::mailbox::ARGS
    && call::Request::MAX_REPLY_WORDS <= crate::mailbox::ANSWER);

crate::wire_struct! {
    /// A control message's answer: its bytes in the control page.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct CtlDone {
        pub len: u64,
    }
}

/// Counters a nicd publishes (Published::counters).
pub const RX_FRAMES: usize = 0;
pub const TX_FRAMES: usize = 1;
/// Received frames the channel had no room for.
pub const RX_DROPS: usize = 2;
/// Frames the device refused, or that netd sent outside the offer.
pub const TX_DROPS: usize = 3;
pub const DEVICE_EVENTS: usize = 4;
pub const COUNTERS: usize = 8;

/// Configuration-space requests (Published::cfg_req): kind in bits 0..4,
/// size in bytes (1, 2, 4) in 4..8, offset in 16..28, the request's
/// sequence number in 32..64.
pub const CFG_READ: u64 = 1;
pub const CFG_WRITE: u64 = 2;

/// What a nicd publishes for root (host::mailbox::PUBLISHED_OFFSET).
#[repr(C)]
pub struct Published {
    pub counters: [AtomicU64; COUNTERS],
    /// A configuration-space request, its value (a write's), and root's
    /// answer: the request's sequence number << 32 | 0 (done) or an
    /// errno, and the value read.  One at a time: the driver waits for
    /// the answer's sequence number before its next.
    pub cfg_req: AtomicU64,
    pub cfg_value: AtomicU32,
    pub cfg_pad: AtomicU32,
    pub cfg_ans: AtomicU64,
    pub cfg_ans_value: AtomicU32,
    /// A short status line (NUL padded), for `l4hctl nic list`.
    pub status: [AtomicU32; 16],
}
const _: () = assert!(core::mem::size_of::<Published>() <= 4096);

/// Pack a configuration-space request.
pub const fn cfg_request(seq: u32, kind: u64, offset: u16, size: u8) -> u64 {
    (seq as u64) << 32 | (offset as u64 & 0xfff) << 16 | (size as u64 & 0xf) << 4 | kind & 0xf
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn m() -> Manifest {
        Manifest::empty().with_name("test").with_matches(&[PciMatch::id(0x8086, 0x1563), PciMatch {
            class: 0x02_0000,
            class_mask: 0xff_ff00,
            ..PciMatch::id(0x1af4, ANY)
        }])
    }

    #[test]
    fn matching() {
        let m = m();
        assert!(m.valid());
        let ids = |vendor, device, class| Ids { vendor, device, class, ..Default::default() };
        assert_eq!(m.matching(&ids(0x8086, 0x1563, 0)), Some(0));
        assert_eq!(m.matching(&ids(0x8086, 0x1564, 0)), None);
        assert_eq!(m.matching(&ids(0x1af4, 0x1000, 0x02_0000)), Some(1));
        assert_eq!(m.matching(&ids(0x1af4, 0x1001, 0x01_0000)), None);
        // An empty slot matches nothing, not every device of vendor 0.
        assert_eq!(m.matching(&ids(0, 0, 0)), None);
    }

    #[test]
    fn parse_refuses_what_is_out_of_bounds() {
        let good = m();
        let bytes = |m: &Manifest| unsafe {
            core::slice::from_raw_parts(m as *const Manifest as *const u8, core::mem::size_of::<Manifest>())
        };
        assert!(Manifest::parse(bytes(&good)).is_some());
        assert!(Manifest::parse(&bytes(&good)[..100]).is_none());
        for f in [
            |m: &mut Manifest| m.magic = 0,
            |m: &mut Manifest| m.dma_bits = 40,
            |m: &mut Manifest| m.nr_matches = 33,
            |m: &mut Manifest| m.name = [b'a'; NAME_LEN],
            |m: &mut Manifest| m.bars = 0x40,
            |m: &mut Manifest| m.bars_wc = 1,
            |m: &mut Manifest| m.channel_bits = 30,
            |m: &mut Manifest| m.config_writes[0] = CfgWindow { offset: 4000, len: 200 },
            |m: &mut Manifest| m.flags = 1 << 31,
        ] {
            let mut bad = good;
            f(&mut bad);
            assert!(Manifest::parse(bytes(&bad)).is_none());
        }
    }
}
