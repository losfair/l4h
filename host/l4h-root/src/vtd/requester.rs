//! Requester IDs visible above conventional PCI bridges. These bridges
//! cannot identify each downstream function: DMA and MSI share an alias.
//! See QEMU's pci_device_get_iommu_bus_devfn / pci_req_id_cache_get:
//! https://github.com/qemu/qemu/blob/v10.0.0/hw/pci/pci.c

use super::dmar::Scope;

#[derive(Clone, Copy)]
struct Bridge {
    sid: u16,
    // None for PCIe ports, bridge BDF for PCI, secondary-bus:00.0 for
    // PCIe-to-PCI (PCIe-to-PCI/PCI-X Bridge Specification, section 2.3).
    alias: Option<u16>,
}

pub struct Requesters {
    aliases: [Option<u16>; 256],
}

impl Requesters {
    pub const fn empty() -> Self { Self { aliases: [None; 256] } }

    /// Read only configuration headers; do not size BARs or enable devices.
    pub fn discover(mut read: impl FnMut(u8, u8, u8, u8) -> u32) -> Option<Self> {
        let mut parents = [None::<Bridge>; 256];
        for bus in 0..=255 {
            for dev in 0..32 {
                if read(bus, dev, 0, 0) & 0xffff == 0xffff { continue; }
                let funcs = if read(bus, dev, 0, 0x0c) & (1 << 23) != 0 { 8 } else { 1 };
                for func in 0..funcs {
                    if func != 0 && read(bus, dev, func, 0) & 0xffff == 0xffff { continue; }
                    if read(bus, dev, func, 8) >> 16 != 0x0604 { continue; }
                    if read(bus, dev, func, 0x0c) >> 16 & 0x7f != 1 { return None; }
                    let buses = read(bus, dev, func, 0x18);
                    let secondary = (buses >> 8) as u8;
                    if secondary == 0 { continue; } // disabled bridge
                    if buses as u8 != bus || secondary == bus || secondary > (buses >> 16) as u8
                        || parents[secondary as usize].is_some() { return None; }
                    let sid = (bus as u16) << 8 | (dev as u16) << 3 | func as u16;
                    let mut alias = Some(sid);
                    if read(bus, dev, func, 4) & (1 << 20) != 0 {
                        let mut cap = (read(bus, dev, func, 0x34) & 0xfc) as u8;
                        let mut seen = 0u64;
                        while cap != 0 {
                            if cap < 0x40 || seen & (1 << (cap / 4)) != 0 { return None; }
                            seen |= 1 << (cap / 4);
                            let header = read(bus, dev, func, cap);
                            if header as u8 == 0x10 {
                                // PCIe ports preserve IDs; a PCIe-to-PCI
                                // bridge substitutes its secondary bus.
                                alias = (header >> 20 & 15 == 7).then_some((secondary as u16) << 8);
                            }
                            cap = (header >> 8 & 0xfc) as u8;
                        }
                    }
                    parents[secondary as usize] = Some(Bridge { sid, alias });
                }
            }
        }
        let mut me = Self::empty();
        for bus in 0..256 {
            let mut at = bus;
            let mut hops = 0;
            while let Some(parent) = parents[at] {
                hops += 1;
                if hops >= 256 { return None; }
                // An outer conventional bridge overrides an inner alias.
                if parent.alias.is_some() { me.aliases[bus] = parent.alias; }
                at = (parent.sid >> 8) as usize;
            }
        }
        Some(me)
    }

    pub fn requester(&self, sid: u16) -> u16 {
        self.aliases[(sid >> 8) as usize].unwrap_or(sid)
    }

    /// An RMRR for any member remains reserved for the whole alias group.
    pub fn scope_contains(&self, scope: Scope, requester: u16) -> bool {
        (scope.first >> 8..=scope.last >> 8).any(|bus| match self.aliases[bus as usize] {
            Some(alias) => alias == requester,
            None => requester >> 8 == bus && scope.contains(requester),
        })
    }
}
