//! Spawning a guest's l4h-vmm and giving it access to the guest: its I/O
//! pool (not its RAM), event pages, device pages and the vCPU
//! notifications.

use core::ops::Range;

use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use l4h_abi as abi;
use l4h_host as host;
use l4h_host::fixed::{ArrayVec, Scratch};

use crate::component::{self, Component, SpawnArgs};
use crate::guest::{Guest, dev_event};
use crate::mem::{Alloc, Arena, Slot};
use crate::window::Window;
use crate::{AsidPools, HostInfo};

static VMM_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-vmm.elf"));

const PAGE: usize = 4096;

/// The VMM's large objects, made at guest creation before loading RAM can
/// fragment or fill the arena.  Everything allocated at start is then
/// small enough for Arena::reserve's guarantee.
pub struct Cnodes {
    cspace: cap::CNode,
    /// Keeps the I/O pool's mappings: slot i = page i (radix `pool_radix`).
    pool: cap::CNode,
    pool_radix: usize,
    /// Keeps the other mappings (radix host::CNODE_BITS).
    small: cap::CNode,
}

impl Cnodes {
    pub fn new(arena: &mut Arena, alloc: &mut Alloc, io_pool: usize) -> Option<Self> {
        let mut make = |bits| {
            let s = arena.try_object(alloc, ObjectBlueprint::CNode { size_bits: bits })?;
            Some(sel4::init_thread::Slot::<cap_type::CNode>::from_index(s).cap())
        };
        let pool_radix = ((io_pool / PAGE).trailing_zeros() as usize).max(1);
        Some(Self {
            cspace: make(host::CNODE_BITS)?,
            pool: make(pool_radix)?,
            pool_radix,
            small: make(host::CNODE_BITS)?,
        })
    }
}

/// Bytes needed at start, besides the CNodes made at guest creation:
/// page tables for the I/O pool, the VMM image and stack, and mappings of
/// event pages, device pages and backend channels (including alignment).
pub fn start_bytes(io_pool: usize, vcpus: usize, devices: usize) -> usize {
    io_pool / 512 + (3 << 19) + (vcpus + devices * 16) * 2 * PAGE
}

/// Untyped memory a guest's arena is expected to need for its l4h-vmm.
pub fn arena_bytes(io_pool: usize, vcpus: usize, devices: usize) -> usize {
    start_bytes(io_pool, vcpus, devices) + io_pool / 128 + 2 * (32 << host::CNODE_BITS)
}

/// A device's host-side backend.
pub enum Backend {
    Blk {
        /// Frames of the blkd channel, mapped at vmm_chan_va(d).
        chan: ArrayVec<cap::Granule, { host::blk::CHANNEL_PAGES }>,
        /// Notification of blkd (badged for this client).
        kick: cap::Notification,
    },
    Net {
        /// Slots of the frames of the netd port, mapped at vmm_chan_va(d).
        chan: Range<Slot>,
        /// Notification of netd (badged for this port).
        kick: cap::Notification,
        mac: [u8; 6],
        /// CNode (radix 10) for the VMM's mapping capabilities of the port.
        keep: cap::CNode,
    },
    /// virtio-gpu (gpu.rs): frame i < display_pages is page i of the
    /// display area, the others are the VMM's tables.
    Gpu {
        frames: cap::CNode,
        /// For the VMM's mapping capabilities, slot i = frame i.
        keep: cap::CNode,
        radix: usize,
        display_pages: usize,
        width: u32,
        height: u32,
    },
}

impl Backend {
    /// Host memory, besides start_bytes, mapping it in the VMM takes.
    pub fn map_bytes(&self) -> usize {
        match self {
            Backend::Gpu { display_pages, .. } => {
                crate::gpu::table_bytes(*display_pages) + crate::gpu::table_bytes(host::gpu::STATE_PAGES)
            }
            _ => 0,
        }
    }
}

const SLOT_KICK_BASE: u64 = 32;

/// The VMM's configuration under construction.
static CONFIG: Scratch<core::mem::MaybeUninit<host::VmmConfig>> = Scratch::new(core::mem::MaybeUninit::zeroed());

/// Create the guest's l4h-vmm (not started) for its devices and backends.
pub fn spawn(
    g: &mut Guest,
    alloc: &mut Alloc,
    win: &mut Window,
    asids: &mut AsidPools,
    host_info: &HostInfo,
) -> Component {
    let backends = core::mem::take(&mut g.backends);
    let comp = CONFIG.with(|cfg| {
        *cfg = core::mem::MaybeUninit::zeroed();
        create(g, unsafe { cfg.assume_init_mut() }, &backends, alloc, win, asids, host_info)
    });
    map(g, &comp, &backends, alloc);
    g.backends = backends;
    comp
}

/// Write the VMM's configuration into `cfg` and create it.
fn create(
    g: &mut Guest,
    cfg: &mut host::VmmConfig,
    backends: &[(usize, Backend)],
    alloc: &mut Alloc,
    win: &mut Window,
    asids: &mut AsidPools,
    host_info: &HostInfo,
) -> Component {
    cfg.guest_id = g.id as u32;
    cfg.nr_vcpus = g.vcpus.len() as u32;
    cfg.io_pool_gpa = g.pool.gpa as u64;
    cfg.io_pool_size = g.pool.size as u64;
    cfg.dom0 = g.dom0 as u32;
    // Guest consoles go to the serial port only when verbose: each byte is a
    // kernel print (host::VERBOSE).
    cfg.serial = host::VERBOSE as u32;
    cfg.epoch_ns = host_info.epoch_ns;
    cfg.epoch_ticks = host_info.epoch_ticks;
    assert!(backends.len() <= host::VMM_MAX_DEVICES);
    cfg.nr_devices = backends.len() as u32;
    for (i, (d, b)) in backends.iter().enumerate() {
        let d = *d;
        let dev = &mut cfg.devices[i];
        dev.guest_index = d as u32;
        dev.event = dev_event(d);
        dev.page_va = host::vmm_device_page_va(d) as u64;
        match b {
            Backend::Blk { chan, .. } => {
                dev.kind = host::VDEV_BLK;
                dev.chan_va = host::vmm_chan_va(d) as u64;
                dev.chan_size = (chan.len() * PAGE) as u64;
                dev.chan_kick_slot = SLOT_KICK_BASE + d as u64;
            }
            Backend::Net { chan, mac, .. } => {
                dev.kind = host::VDEV_NET;
                dev.chan_va = host::vmm_chan_va(d) as u64;
                dev.chan_size = (chan.len() * PAGE) as u64;
                dev.chan_kick_slot = SLOT_KICK_BASE + d as u64;
                dev.mac[..6].copy_from_slice(mac);
            }
            Backend::Gpu { display_pages, width, height, .. } => {
                dev.kind = host::VDEV_GPU;
                dev.chan_va = host::gpu::VMM_DISPLAY_VA as u64;
                dev.chan_size = (display_pages * PAGE) as u64;
                dev.width = *width;
                dev.height = *height;
            }
        }
    }
    let cfg_bytes = unsafe {
        core::slice::from_raw_parts(cfg as *const host::VmmConfig as *const u8, core::mem::size_of::<host::VmmConfig>())
    };

    let core = g.vcpus[0].core;
    let args = SpawnArgs {
        id: g.id as u32,
        kind: host::KIND_VMM,
        elf: VMM_ELF,
        core,
        prio: abi::PRIO_KERNEL + 1,
        budget_us: host_info.timeslice_us,
        period_us: host_info.timeslice_us,
        config: cfg_bytes,
        ntfn: Some(g.vmm_ntfn),
        service_ep: Some(g.vmm_ep),
        cnode: Some(g.vmm_cnodes.as_ref().expect("VMM CNodes").cspace),
        cnode_bits: None,
    };
    component::create(&args, alloc, &mut g.arena, win, asids, host_info)
}

/// Map the guest's I/O pool, event, device and channel pages into its VMM.
fn map(g: &mut Guest, comp: &Component, backends: &[(usize, Backend)], alloc: &mut Alloc) {
    // ---- The I/O pool at IO_POOL_VA, the only guest memory the VMM maps.
    // The mapping capabilities are kept in a CNode of the guest's arena.
    let pages = g.pool.pages();
    let cnodes = g.vmm_cnodes.as_ref().expect("VMM CNodes");
    let (keep, radix, small) = (cnodes.pool, cnodes.pool_radix, cnodes.small);
    let attrs = VmAttributes::DEFAULT;
    for i in 0..pages {
        let dst = keep.absolute_cptr_from_bits_with_depth(i as u64, radix);
        let frame = g.pool.frame(i);
        comp.map_copy(alloc, &mut g.arena, &frame, host::IO_POOL_VA + i * PAGE, CapRights::read_write(), attrs, dst);
    }

    // ---- Event pages, notifications and device pages.
    let mut small_next = 0u64;
    let mut keep_slot = || {
        let s = small.absolute_cptr_from_bits_with_depth(small_next, host::CNODE_BITS);
        small_next += 1;
        s
    };
    for (v, vcpu) in g.vcpus.iter().enumerate() {
        let ev = crate::component::abs_of(vcpu.event);
        comp.map_copy(alloc, &mut g.arena, &ev, host::vmm_event_page_va(v), CapRights::read_write(), attrs, keep_slot());
        comp.give_badged(host::VCPU_NTFN_SLOT_BASE + v as u64, vcpu.ntfn, CapRights::write_only(), abi::BADGE_EVENT);
    }
    for (d, dev) in g.devices.iter().enumerate() {
        let p = crate::component::abs_of(dev.page);
        comp.map_copy(alloc, &mut g.arena, &p, host::vmm_device_page_va(d), CapRights::read_write(), attrs, keep_slot());
    }
    for (i, f) in g.console_ring.iter().enumerate() {
        let p = crate::component::abs_of(*f);
        comp.map_copy(alloc, &mut g.arena, &p, host::VMM_CONSOLE_RING_VA + i * PAGE, CapRights::read_write(), attrs, keep_slot());
    }
    for &(d, ref b) in backends.iter() {
        match b {
            Backend::Blk { chan, kick } => {
                for (i, f) in chan.iter().enumerate() {
                    let fc = crate::component::abs_of(*f);
                    comp.map_copy(alloc, &mut g.arena, &fc, host::vmm_chan_va(d) + i * PAGE, CapRights::read_write(), attrs, keep_slot());
                }
                comp.give(SLOT_KICK_BASE + d as u64, *kick, CapRights::write_only());
            }
            Backend::Net { chan, kick, keep, .. } => {
                for (i, f) in chan.clone().enumerate() {
                    let fc = crate::component::abs_of(sel4::init_thread::Slot::<cap_type::Granule>::from_index(f).cap());
                    let dst = keep.absolute_cptr_from_bits_with_depth(i as u64, 10);
                    comp.map_copy(alloc, &mut g.arena, &fc, host::vmm_chan_va(d) + i * PAGE, CapRights::read_write(), attrs, dst);
                }
                comp.give(SLOT_KICK_BASE + d as u64, *kick, CapRights::write_only());
            }
            Backend::Gpu { frames, keep, radix, display_pages, .. } => {
                for i in 0..display_pages + host::gpu::STATE_PAGES {
                    let va = match i.checked_sub(*display_pages) {
                        None => host::gpu::VMM_DISPLAY_VA + i * PAGE,
                        Some(j) => host::gpu::VMM_GPU_STATE_VA + j * PAGE,
                    };
                    let f = frames.absolute_cptr_from_bits_with_depth(i as u64, *radix);
                    let dst = keep.absolute_cptr_from_bits_with_depth(i as u64, *radix);
                    comp.map_copy(alloc, &mut g.arena, &f, va, CapRights::read_write(), attrs, dst);
                }
            }
        }
    }
}
