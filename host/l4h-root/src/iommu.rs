//! Device DMA and interrupt confinement, selected from the firmware tables.

use crate::{amdvi, mem::Alloc, pci};
#[cfg(target_arch = "x86_64")]
use crate::vtd;

pub mod mappings;
pub mod shared;


// One pool per guest device, one DMA allocation per controller/NIC, and
// the balloon. Backends keep these records out of root's stack.
pub const MAX_MAPPINGS: usize = crate::MAX_GUESTS * crate::vmmgr::MAX_GUEST_DEVICES
    + pci::MAX_DISK_CTRLS + l4h_host::net::MAX_UPLINKS + l4h_host::usb::MAX_USB_CTRLS + 1;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    None,
    Amd(amdvi::Domain),
    #[cfg(target_arch = "x86_64")]
    Intel(vtd::Domain),
}

impl Domain {
    pub const NONE: Self = Self::None;
}

pub enum Iommu {
    Amd(amdvi::AmdVi),
    #[cfg(target_arch = "x86_64")]
    Intel(vtd::Vtd),
}

impl Iommu {
    #[cfg(not(target_arch = "x86_64"))]
    pub fn none() -> Self { Self::Amd(amdvi::AmdVi::none()) }
    pub fn off() -> Self { Self::Amd(amdvi::AmdVi::off()) }

    /// `enabled` is `iommu`, `intremap` `iommu_intremap`. With several
    /// partitions the primary decides both for all (shared.rs).
    #[cfg(target_arch = "x86_64")]
    pub fn init(bootinfo: &sel4::BootInfoPtr, phys: &mut crate::acpi::Phys, pci: &pci::Pci,
        ticks_per_ms: u64, enabled: bool, intremap: bool) -> Self {
        let shared = shared::get();
        let (mut enabled, mut intremap) = (enabled, intremap);
        if let Some(s) = shared.filter(|s| !s.primary) {
            let (ready, units, remap) = s.wait_ready();
            match ready {
                l4h_partition::IOMMU_READY_ON => {
                    if !enabled {
                        log!("l4h-root: iommu=0 ignored: partition 0 enabled the IOMMU for every partition");
                    }
                    info!("l4h-root: partition 0 enabled {} IOMMU unit(s), interrupts {}remapped",
                        units, if remap { "" } else { "not " });
                    (enabled, intremap) = (true, remap);
                }
                l4h_partition::IOMMU_READY_ABSENT => {
                    info!("l4h-root: no IOMMU (partition 0): DMA is not confined");
                    return Self::Amd(amdvi::AmdVi::none());
                }
                _ => {
                    log!("l4h-root: partition 0 left the IOMMU off: DMA is not confined");
                    return Self::off();
                }
            }
        }
        let me = if !enabled {
            log!("l4h-root: iommu=0: DMA is not confined");
            Self::off()
        } else if let Some(vtd) = vtd::Vtd::init(bootinfo, phys, pci, ticks_per_ms, intremap, shared) {
            Self::Intel(vtd)
        } else {
            Self::Amd(amdvi::AmdVi::init(bootinfo, phys, pci, ticks_per_ms, intremap, shared))
        };
        me
    }

    /// Tell the other partitions, which wait for it in `init`, what the
    /// primary made of the IOMMU: once it has also set ACS in the bridges,
    /// which are all its (main.rs), so that no partition enables a device
    /// below a port that does not yet isolate it.
    #[cfg(target_arch = "x86_64")]
    pub fn publish(&self) {
        if let Some(s) = shared::get().filter(|s| s.primary) {
            let [state, remap, units, ..] = self.info();
            s.set_ready(state, units as usize, remap != 0);
        }
    }

    /// The requester ID function `bdf`'s DMA is translated as: its own,
    /// or one it shares with others (a conventional PCI bridge's, a
    /// firmware alias), whose functions then share one domain.
    pub fn requester(&self, bdf: u16) -> u16 {
        match self {
            Self::Amd(a) => a.requester(bdf),
            #[cfg(target_arch = "x86_64")]
            Self::Intel(i) => i.requester(bdf),
        }
    }

    pub fn info(&self) -> [u64; 6] {
        match self {
            Self::Amd(a) => a.info(),
            #[cfg(target_arch = "x86_64")]
            Self::Intel(i) => i.info(),
        }
    }

    /// None selects a legacy entry; Some contains a VT-d remapping index.
    #[cfg(target_arch = "x86_64")]
    pub fn ioapic_irq(&mut self, index: usize, vector: u64) -> Result<Option<u16>, &'static str> {
        match self {
            Self::Intel(i) => i.ioapic_irq(index, vector),
            _ => Ok(None),
        }
    }

    pub fn attach(&mut self, alloc: &mut Alloc, device: &pci::Device) -> Domain {
        match self {
            Self::Amd(a) => match a.attach(alloc, device) {
                amdvi::Domain::NONE => Domain::None,
                d => Domain::Amd(d),
            },
            #[cfg(target_arch = "x86_64")]
            Self::Intel(i) => i.attach(alloc, device).map_or(Domain::None, Domain::Intel),
        }
    }

    pub fn map(&mut self, alloc: &mut Alloc, domain: Domain, pa: usize, len: usize, write: bool) {
        match (self, domain) {
            (_, Domain::None) => {},
            (Self::Amd(a), Domain::Amd(d)) => a.map(alloc, d, pa, len, write),
            #[cfg(target_arch = "x86_64")]
            (Self::Intel(i), Domain::Intel(d)) => i.map(alloc, d, pa, len, write),
            #[cfg(target_arch = "x86_64")]
            _ => panic!("IOMMU domain belongs to another backend"),
        }
    }

    pub fn unmap(&mut self, domain: Domain, pa: usize, len: usize) {
        match (self, domain) {
            (_, Domain::None) => {},
            (Self::Amd(a), Domain::Amd(d)) => a.unmap(d, pa, len),
            #[cfg(target_arch = "x86_64")]
            (Self::Intel(i), Domain::Intel(d)) => i.unmap(d, pa, len),
            #[cfg(target_arch = "x86_64")]
            _ => panic!("IOMMU domain belongs to another backend"),
        }
    }

    /// The address AND data to put in an MSI/MSI-X entry. Intel carries
    /// the remapping index in the address; AMD carries it in the data.
    pub fn msi(&mut self, domain: Domain, vector: u64) -> (u64, u32) {
        match (self, domain) {
            (_, Domain::None) => (pci::msi_address(), pci::msi_data(vector)),
            (Self::Amd(a), Domain::Amd(d)) => (pci::msi_address(), a.msi_data(d, vector)),
            #[cfg(target_arch = "x86_64")]
            (Self::Intel(i), Domain::Intel(d)) => i.msi(d, vector),
            #[cfg(target_arch = "x86_64")]
            _ => panic!("IOMMU domain belongs to another backend"),
        }
    }

    pub fn poll(&mut self) {
        match self {
            Self::Amd(a) => a.poll(),
            #[cfg(target_arch = "x86_64")]
            Self::Intel(i) => i.poll(),
        }
    }
}
