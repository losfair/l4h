//! The driver bundle (DESIGN.md §9.8): NIC driver images and the firmware
//! blobs they may be given, which root binds devices to by their manifests
//! (l4h_host::nicd::Manifest).  Root knows no device kind: a new driver is a
//! new entry here.
//!
//! The bundle is the boot module `l4h-drivers` (measured with the boot
//! image), or, without one, the bundle built into root's own image
//! (tools/build-host.sh, tools/mkdrivers.py).  Its format:
//!
//! ```text
//! header:  magic "L4HDRVS1", count: u32, reserved: u32
//! entries: count x { name: [u8; 48], kind: u32, reserved: u32, offset: u64, size: u64 }
//! data:    the entries' bytes, at their offsets
//! ```
//!
//! Root checks every bound before it uses an entry: an entry outside the
//! bundle, a driver whose ELF or manifest does not parse, is skipped and
//! logged.  dom0 can load more drivers at runtime (CTL_DRIVER_LOAD), into
//! memory of root's; those are not measured, and are refused unless the
//! host confines NIC drivers (an IOMMU with interrupt remapping).  dom0
//! loads firmware the same way (CTL_FIRMWARE_LOAD), from its own
//! /lib/firmware, so that l4h's image need not carry blobs it may not
//! redistribute; only confined drivers are given it.

use l4h_host::fixed::ArrayVec;
use l4h_host::nicd::{self, Manifest};
use sha2::{Digest, Sha256};

use l4h_task::elf::Elf;

static BUNDLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-drivers.bin"));

pub const MAGIC: &[u8; 8] = b"L4HDRVS1";
pub const NAME: usize = 48;
const ENTRY: usize = NAME + 4 + 4 + 8 + 8;
/// Entry kinds.
pub const KIND_DRIVER: u32 = 1;
pub const KIND_FIRMWARE: u32 = 2;

/// Drivers and firmware blobs, at most.
pub const MAX_DRIVERS: usize = 16;
pub const MAX_FIRMWARE: usize = 16;

pub struct Driver {
    pub manifest: Manifest,
    pub elf: &'static [u8],
    pub sha256: [u8; 32],
    /// From the boot bundle: measured with the boot image.  Otherwise
    /// dom0 loaded it.
    pub boot: bool,
}

pub struct Firmware {
    pub name: [u8; NAME],
    pub data: &'static [u8],
    pub sha256: [u8; 32],
    /// From the boot bundle; otherwise dom0 loaded it.
    pub boot: bool,
}

pub struct Drivers {
    pub drivers: ArrayVec<Driver, MAX_DRIVERS>,
    pub firmware: ArrayVec<Firmware, MAX_FIRMWARE>,
}

fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}

/// The manifest of driver image `elf`, checked, or why it has none.
pub fn manifest(elf: &[u8]) -> Result<Manifest, &'static str> {
    let e = Elf::parse(elf)?;
    let s = e.section(nicd::MANIFEST_SECTION).ok_or("no manifest section")?;
    let m = Manifest::parse(s).ok_or("its manifest is out of bounds or of another ABI")?;
    // The image's memory, within what the manifest says, below the info
    // area and in ascending order, as l4h_task::component::create loads
    // images (it refuses others, which root must never ask it to).
    let (lo, hi) = e.bounds();
    if e.segments().next().is_none() || !e.segments().any(|s| (s.vaddr..s.vaddr + s.memsz).contains(&e.entry)) {
        return Err("its entry point is in no loadable segment");
    }
    if hi.saturating_sub(lo) > 1 << m.image_max_bits {
        return Err("its image is larger than its manifest says");
    }
    if lo < 0x1000 || hi > l4h_host::INFO_VA as u64 {
        return Err("its image is outside a component's image area");
    }
    let mut end = 0;
    for s in e.segments() {
        if s.vaddr & !0xfff < end & !0xfff {
            return Err("its segments are out of order");
        }
        end = s.vaddr + s.memsz;
    }
    Ok(m)
}

impl Drivers {
    pub const fn new() -> Self {
        Drivers { drivers: ArrayVec::new(), firmware: ArrayVec::new() }
    }

    /// Read the boot bundle: the `l4h-drivers` module if there is one,
    /// else root's own.
    pub fn load(&mut self, module: Option<&'static [u8]>) {
        let (bundle, from) = match module {
            Some(m) => (m, "module l4h-drivers"),
            None => (BUNDLE, "root's image"),
        };
        if bundle.is_empty() {
            log!("l4h-root: no NIC driver bundle: NICs stay unbound");
            return;
        }
        if bundle.len() < 16 || &bundle[..8] != MAGIC {
            log!("l4h-root: the driver bundle in {} is not one: NICs stay unbound", from);
            return;
        }
        let count = u32_at(bundle, 8) as usize;
        let Some(toc_end) = count.checked_mul(ENTRY).and_then(|n| n.checked_add(16)).filter(|&e| e <= bundle.len()) else {
            log!("l4h-root: the driver bundle in {} has a broken table: NICs stay unbound", from);
            return;
        };
        for i in 0..count {
            let e = &bundle[16 + i * ENTRY..16 + (i + 1) * ENTRY];
            let name: [u8; NAME] = e[..NAME].try_into().unwrap();
            let (kind, off, size) = (u32_at(e, NAME), u64_at(e, NAME + 8), u64_at(e, NAME + 16));
            let data = usize::try_from(off).ok().zip(usize::try_from(size).ok())
                .filter(|&(o, s)| o >= toc_end && o.checked_add(s).is_some_and(|end| end <= bundle.len()))
                .map(|(o, s)| &bundle[o..o + s]);
            let Some(data) = data else {
                log!("l4h-root: driver bundle entry {} outside the bundle: skipped", i);
                continue;
            };
            match kind {
                KIND_DRIVER => {
                    if let Err(why) = self.add(data, true) {
                        log!("l4h-root: driver bundle entry {}: {}: skipped", i, why);
                    }
                }
                KIND_FIRMWARE => {
                    if let Err(why) = self.add_firmware(name, data, true) {
                        log!("l4h-root: driver bundle entry {}: firmware not kept: {}", i, why);
                    }
                }
                _ => log!("l4h-root: driver bundle entry {}: unknown kind {}", i, kind),
            }
        }
        info!("l4h-root: {} NIC drivers and {} firmware blobs from {}", self.drivers.len(), self.firmware.len(), from);
    }

    /// Add driver image `elf`: its index.  A driver of the same name as
    /// one there is refused.
    pub fn add(&mut self, elf: &'static [u8], boot: bool) -> Result<usize, &'static str> {
        let manifest = manifest(elf)?;
        if self.find(manifest.name()).is_some() {
            return Err("a driver of that name is there already");
        }
        let sha256: [u8; 32] = Sha256::digest(elf).into();
        self.drivers.push(Driver { manifest, elf, sha256, boot }).map_err(|_| "too many drivers")?;
        let d = self.drivers.last().unwrap();
        info!("l4h-root: NIC driver {} ({}), sha256 {:02x}{:02x}{:02x}{:02x}...", d.manifest.name(),
            if boot { "boot bundle" } else { "loaded by dom0" }, sha256[0], sha256[1], sha256[2], sha256[3]);
        Ok(self.drivers.len() - 1)
    }

    pub fn find(&self, name: &str) -> Option<usize> {
        self.drivers.iter().position(|d| d.manifest.name() == name)
    }

    /// The first driver whose manifest matches `ids`, of those `allowed`.
    pub fn matching(&self, ids: &nicd::Ids, allowed: impl Fn(&Driver) -> bool) -> Option<usize> {
        self.drivers.iter().position(|d| allowed(d) && d.manifest.matching(ids).is_some())
    }

    /// Add firmware blob `name` (NUL padded): its index.  A name there
    /// already is refused.
    pub fn add_firmware(&mut self, name: [u8; NAME], data: &'static [u8], boot: bool) -> Result<usize, &'static str> {
        if name[0] == 0 || name[nicd::FIRMWARE_NAME - 1] != 0 || name[nicd::FIRMWARE_NAME..].iter().any(|&b| b != 0) {
            return Err("its name is empty or too long");
        }
        if self.firmware.iter().any(|f| f.name == name) {
            return Err("a blob of that name is there already");
        }
        let sha256: [u8; 32] = Sha256::digest(data).into();
        self.firmware.push(Firmware { name, data, sha256, boot }).map_err(|_| "too many firmware blobs")?;
        info!("l4h-root: firmware {} ({}, {} bytes), sha256 {:02x}{:02x}{:02x}{:02x}...", self::name(&name),
            if boot { "boot bundle" } else { "loaded by dom0" }, data.len(), sha256[0], sha256[1], sha256[2], sha256[3]);
        Ok(self.firmware.len() - 1)
    }

    /// Firmware blob `name` (NUL padded, as a manifest names it), for a
    /// driver that is `confined` or not: one dom0 loaded only for a
    /// confined one, as dom0's drivers run only confined.
    pub fn firmware(&self, name: &[u8; nicd::FIRMWARE_NAME], confined: bool) -> Option<&'static [u8]> {
        self.firmware.iter().find(|f| f.name[..nicd::FIRMWARE_NAME] == name[..] && (f.boot || confined)).map(|f| f.data)
    }
}

const _: () = assert!(nicd::FIRMWARE_NAME <= NAME && l4h_abi::FIRMWARE_NAME == nicd::FIRMWARE_NAME);

/// A NUL-padded name, for the log.
pub fn name(n: &[u8]) -> &str {
    let len = n.iter().position(|&b| b == 0).unwrap_or(n.len());
    core::str::from_utf8(&n[..len]).unwrap_or("?")
}
