//! Assigning a whole xHCI controller to a guest (DESIGN.md §9.7): an
//! l4h-usbd drives it, and the guest sends it host-controller operations
//! and URBs through a queue area of host frames.
//!
//! At boot root only lists the controllers and leaves them to the firmware
//! (legacy keyboard emulation, BMC virtual devices).  The first attach
//! claims one: root starts its usbd, which takes it from the firmware and
//! resets it.  From then on the controller and its usbd stay until reboot,
//! `idle` (halted, bus mastering off) whenever no guest has it.
//!
//! Every DMA address the controller sees is written by usbd, into its own
//! DMA region (which root allocates and the guest never maps) or the
//! owner's I/O pool, whose addresses root gives usbd from its own table.
//!
//! A guest can keep usbd busy, so root never waits for it (DESIGN.md
//! §10, "Root never waits on a driver"): claim, attach and remove are
//! mailbox requests (host::mailbox), and at GUEST_DEL root cuts the
//! controller off from the pool itself (bus mastering off, the IOMMU
//! mapping gone) before usbd has even seen the request.  The queue area is
//! root's until usbd has zeroed it (REMOVE answered), when root frees it;
//! the next guest meanwhile gets the other area, and its ATTACH is posted
//! (bus mastering back on) once the CLAIM or REMOVE before it is answered.

use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;

use l4h_host::errno::Errno;
use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use l4h_abi::{self as abi, usb as uabi};
use l4h_host::usb::call::{Request, reply};
use l4h_host::{self as host, usb, wire, wiring};
use l4h_host::fixed::ArrayVec;

use crate::blkd::{BarCache, DEVICE_ATTRS, bar_frames, keep_bits};
use crate::component::{self, Component, SpawnArgs, abs_of, root_cap};
use crate::iommu::Domain;
use crate::mailbox::{self, Mailbox};
use crate::mem::{Arena, Dest, Slot};
use crate::vmmgr::RootGuest;
use crate::vspace::FRAME_BP;
use crate::{Host, ctl, pci};

static USBD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-usbd.elf"));

const PAGE: usize = 4096;
/// Radix of the CNodes of a client's queue frames (vmmgr's copies, and
/// usbd's mapping capabilities).
pub const QUEUE_RADIX: usize = host::vmmgr::USB_QUEUE_RADIX;
const _: () = assert!(uabi::AREA_PAGES <= 1 << QUEUE_RADIX);

/// How long root waits for a controller after a reset (CNR) before it
/// reads its capabilities.
const CAP_WAIT_MS: u64 = 1000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Not claimed: the firmware's.
    Firmware,
    /// Claimed, no guest: halted, bus mastering off (or a REMOVE runs).
    Idle,
    /// Guest `vm` has it (its ATTACH may still wait for a REMOVE).
    Vm(usize),
    /// Claim, reset or drain failed: quarantined until reboot.
    Failed,
    Unsupported(&'static str),
}

/// An xHCI controller root found at boot.
pub struct Ctrl {
    pub pci: pci::Device,
    pub state: State,
    /// USB 2 and USB 3 ports, 64-bit addressing: known once usbd has
    /// answered the CLAIM.
    claimed: bool,
    pub usb2: u16,
    pub usb3: u16,
    ac64: bool,
    bars: BarCache,
    driver: Option<Usbd>,
    dom: Domain,
    /// The owner's pool, while one is attached: (GPA, paddr, size).
    pool: Option<(usize, usize, usize)>,
}

struct Usbd {
    comp: Component,
    arena: Arena,
    mailbox: Mailbox,
    /// The requests posted and not answered, oldest first: at most a
    /// CLAIM, or an ATTACH and its REMOVE (an ATTACH waits for the others).
    ops: ArrayVec<Op, 2>,
    areas: [Option<Area>; usb::AREAS],
    /// The attached guest's area (State::Vm).
    idx: usize,
    /// The attached guest's ATTACH waits for the requests posted before.
    waiting: bool,
}

#[derive(Clone, Copy)]
enum Op {
    Claim,
    Attach,
    Remove(usize),
}

/// A client's queue area: root's frames, mapped into usbd while the area
/// lives, and the copies the guest's are made from.
struct Area {
    arena: Arena,
    /// Copies of the frames (radix QUEUE_RADIX), vmmgr's to give the
    /// guest: revoked at GUEST_DEL.
    guest: cap::CNode,
    /// Root's slots of the arena's CNodes (the frames, usbd's mapping
    /// copies, `guest`): empty once the arena is released.
    slots: [Slot; 3],
}

/// The controllers, in .bss with the disk controllers.
static mut CTRLS: ArrayVec<Ctrl, { usb::MAX_USB_CTRLS }> = ArrayVec::new();

pub fn ctrls() -> &'static mut ArrayVec<Ctrl, { usb::MAX_USB_CTRLS }> {
    // main takes the only reference once.
    unsafe { &mut *(&raw mut CTRLS) }
}

/// An xHCI controller: class 0c/03/30.
pub fn is_xhci(d: &pci::Device) -> bool {
    d.class == 0x0c && d.subclass == 0x03 && d.prog_if == 0x30
}

/// Why `d` cannot be driven, or None.
fn unsupported(d: &pci::Device, pci: &pci::Pci) -> Option<&'static str> {
    let bar = d.bars[0];
    if bar.is_io || bar.size < 0x1000 || bar.size as usize > crate::blkd::BAR_STRIDE {
        return Some("no usable BAR 0");
    }
    if d.msix.is_none() && d.msi.is_none() {
        return Some("no MSI or MSI-X");
    }
    // Renesas uPD720201/2 without a firmware ROM: their driver loads the
    // firmware through configuration space (Linux's renesas_xhci).
    if d.vendor == 0x1912 && matches!(d.device, 0x0014 | 0x0015) {
        let fw_loaded = pci.read32(d.bus, d.dev, d.func, 0xf4) & (1 << 4) != 0;
        let rom = pci.read32(d.bus, d.dev, d.func, 0xf4) >> 16 & (1 << 15) != 0;
        if !fw_loaded && !rom {
            return Some("Renesas uPD72020x without firmware ROM");
        }
    }
    if cfg!(target_arch = "aarch64") && d.msix.is_none() {
        return Some("no MSI-X");
    }
    None
}

/// Boot: list `d`, leaving it to the firmware.
pub fn found(d: pci::Device, pci: &pci::Pci) {
    let cs = ctrls();
    if cs.is_full() {
        log!("l4h-root: more than {} xHCI controllers, {:02x}:{:02x}.{} ignored", usb::MAX_USB_CTRLS, d.bus, d.dev, d.func);
        return;
    }
    let state = match unsupported(&d, pci) {
        Some(why) => State::Unsupported(why),
        None => State::Firmware,
    };
    info!("l4h-root: xHCI {:02x}:{:02x}.{} {:04x}:{:04x}: left to the firmware{}", d.bus, d.dev, d.func,
        d.vendor, d.device, if let State::Unsupported(w) = state { w } else { "" });
    cs.must_push(Ctrl { pci: d, state, claimed: false, usb2: 0, usb3: 0, bars: [const { None }; 6], driver: None, dom: Domain::NONE, pool: None, ac64: false });
}

/// Stop the controller for good: usbd suspended, no DMA, no decoding, no
/// interrupts.
fn quarantine(c: &mut Ctrl, pci: &pci::Pci) {
    c.state = State::Failed;
    if let Some(d) = &c.driver {
        let _ = d.comp.tcb.tcb_suspend();
    }
    pci.disable(&c.pci);
    let p = &c.pci;
    log!("l4h-root: xHCI {:02x}:{:02x}.{}: quarantined until reboot", p.bus, p.dev, p.func);
}

/// The controller's capability registers, through a temporary mapping of
/// BAR 0's first page: (max slots, scratchpad buffers, page size).
fn caps(h: &mut Host, i: usize) -> Option<(u32, u32, u32)> {
    let c = &mut ctrls()[i];
    let frames = bar_frames(&mut h.alloc, &mut h.devmem, &c.pci, &mut c.bars, 0);
    h.pci.enable_memory(&c.pci);
    let frame = crate::devmem::granule(frames.start);
    let ticks_per_ms = h.info.tsc_hz / 1000;
    h.wins.a.with_frame_attrs(&abs_of(frame), DEVICE_ATTRS, |page| unsafe {
        let r32 = |o: usize| (page.add(o) as *const u32).read_volatile();
        let cap0 = r32(0);
        if cap0 == u32::MAX {
            return None;
        }
        let caplength = (cap0 & 0xff) as usize;
        if caplength < 0x20 || caplength + 0x40 > PAGE {
            return None;
        }
        // The firmware may be resetting it: wait for Controller Not Ready.
        let end = host::ticks::now() + CAP_WAIT_MS * ticks_per_ms;
        while r32(caplength + 0x04) & (1 << 11) != 0 {
            if host::ticks::now() > end {
                return None;
            }
            core::hint::spin_loop();
        }
        let (hcs1, hcs2) = (r32(4), r32(8));
        let slots = hcs1 & 0xff;
        let scratch = ((hcs2 >> 21) & 0x1f) << 5 | (hcs2 >> 27);
        let pagesize = (r32(caplength + 0x08) & 0xffff).trailing_zeros();
        if slots == 0 || pagesize > 4 {
            return None;
        }
        Some((slots, scratch, 4096 << pagesize))
    })
}

/// Intel PCH controllers that share ports with an EHCI: route them all to
/// the xHCI, as Linux's usb_enable_intel_xhci_ports does.
fn route_intel_ports(d: &pci::Device, pci: &pci::Pci) {
    const SWITCHABLE: [u16; 5] = [0x1e31, 0x8c31, 0x9c31, 0x9cb1, 0x8cb1];
    if d.vendor != 0x8086 || !SWITCHABLE.contains(&d.device) {
        return;
    }
    let (b, dv, f) = (d.bus, d.dev, d.func);
    // USB3_PSSEN from USB3PRM, XUSB2PR from XUSB2PRM.
    pci.write32(b, dv, f, 0xd8, pci.read32(b, dv, f, 0xdc));
    pci.write32(b, dv, f, 0xd0, pci.read32(b, dv, f, 0xd4));
}

/// Program the controller's interrupt (MSI-X entry 0, or MSI) for
/// `vector` in `dom`.
fn program_irq(h: &mut Host, i: usize, vector: u64, dom: Domain) {
    let (addr, data) = h.iommu.msi(dom, vector);
    let c = &mut ctrls()[i];
    match c.pci.msix {
        Some(m) => {
            let frames = bar_frames(&mut h.alloc, &mut h.devmem, &c.pci, &mut c.bars, m.table_bar);
            let off = m.table_offset as usize;
            let frame = crate::devmem::granule(frames.start + off / PAGE);
            h.wins.a.with_frame_attrs(&abs_of(frame), DEVICE_ATTRS, |page| unsafe {
                let e = page.add(off % PAGE) as *mut u32;
                e.write_volatile(addr as u32);
                e.add(1).write_volatile((addr >> 32) as u32);
                e.add(2).write_volatile(data);
                e.add(3).write_volatile(0);
            });
            h.pci.disable_msi(&c.pci);
            h.pci.enable_msix(&c.pci);
        }
        None => h.pci.enable_msi(&c.pci, addr, data),
    }
}

/// Claim controller `i` from the firmware: start its usbd and post the
/// CLAIM, which does the legacy handoff and resets it.  ENOMEM leaves it
/// with the firmware; EIO marks it failed.  A CLAIM usbd refuses
/// quarantines the controller (the handoff cannot be undone), and the
/// guest that got it meanwhile sees no controller (no magic).
fn claim(h: &mut Host, i: usize) -> Result<(), Errno> {
    let claimed = ctrls().iter().filter(|c| c.driver.is_some()).count();
    let Some(&vector) = pci::VECTORS_USB.get(claimed) else { return Err(ctl::ENOSPC) };
    let Some((slots, scratch, page)) = caps(h, i) else {
        let p = &ctrls()[i].pci;
        log!("l4h-root: xHCI {:02x}:{:02x}.{}: no capabilities", p.bus, p.dev, p.func);
        ctrls()[i].state = State::Failed;
        return Err(ctl::EIO);
    };
    let dma = usb::dma_bytes(slots, scratch, page);
    if !h.can_afford(dma + (8 << 20), 1, 4096) {
        return Err(ctl::ENOMEM);
    }
    // usbd's image, stacks and tables (about 1 MiB of statics).
    let mut arena = h.alloc.arena(4 << 20).ok_or(ctl::ENOMEM)?;
    let bits = dma.trailing_zeros() as usize;
    let dma_slot = h.alloc.slots.alloc();
    let Some(mut region) = h.alloc.split(bits, dma_slot) else {
        h.alloc.slots.free(dma_slot);
        h.alloc.reclaim(arena);
        return Err(ctl::ENOMEM);
    };
    let dma_paddr = region.paddr;
    arena.own(dma_slot, dma_paddr, bits);
    let n_dma = dma / PAGE;
    let dma_cn = arena.object_cap::<cap_type::CNode>(&mut h.alloc, ObjectBlueprint::CNode { size_bits: bits - 12 });
    region.retype(&FRAME_BP, n_dma, Dest { cnode: abs_of(dma_cn), offset: 0 }).expect("usbd DMA frames");

    let c = &mut ctrls()[i];
    let d = c.pci;
    // The device reaches this memory, and an attached client's pool.
    let dom = h.iommu.attach(&mut h.alloc, &d);
    h.iommu.map(&mut h.alloc, dom, dma_paddr, dma, true);
    let mut cfg = usb::UsbdConfig {
        bar0_va: host::MMIO_VA as u64,
        bar0_len: d.bars[0].size,
        pci_bdf: crate::netd::bdf(&d),
        force_handoff_timeout: (host::TEST_INJECT && h.cfg.test_usb_handoff_timeout) as u32,
        dma_va: host::DMA_VA as u64,
        dma_paddr: dma_paddr as u64,
        dma_size: dma as u64,
    };
    let cfg_bytes = unsafe {
        core::slice::from_raw_parts(addr_of_mut!(cfg) as *const u8, core::mem::size_of::<usb::UsbdConfig>())
    };
    let args = SpawnArgs {
        id: usb::USBD_ID_BASE + i as u32,
        kind: host::KIND_USBD,
        elf: USBD_ELF,
        prio: host::PRIO_SERVICE,
        budget_us: h.info.timeslice_us,
        period_us: h.info.timeslice_us,
        config: cfg_bytes,
        ntfn: None,
        service_ep: None,
        cnode: None,
        cnode_bits: None,
    };
    let comp = component::create(
        &args, &mut h.alloc, &mut arena, &mut h.wins.a, &mut |alloc, vspace| h.asids.assign(alloc, vspace),
        &h.info.spawn_context(0),
    );
    let bar_pages = (d.bars[0].size as usize).div_ceil(PAGE);
    let kb = keep_bits(n_dma + bar_pages + host::mailbox::MAILBOX_PAGES);
    let keep = arena.object_cap::<cap_type::CNode>(&mut h.alloc, ObjectBlueprint::CNode { size_bits: kb });
    let mut next = 0u64;
    let mut keep_slot = || {
        next += 1;
        keep.absolute_cptr_from_bits_with_depth(next - 1, kb)
    };
    // BAR 0, uncached, and the DMA region.
    let bar = bar_frames(&mut h.alloc, &mut h.devmem, &d, &mut c.bars, 0);
    for (p, f) in bar.map(crate::devmem::granule).enumerate() {
        comp.map_copy(&mut h.alloc, &mut arena, &abs_of(f), host::MMIO_VA + p * PAGE, CapRights::read_write(), DEVICE_ATTRS, keep_slot());
    }
    for p in 0..n_dma {
        let f = dma_cn.absolute_cptr_from_bits_with_depth(p as u64, bits - 12);
        comp.map_copy(&mut h.alloc, &mut arena, &f, host::DMA_VA + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, keep_slot());
    }
    let mbox = Mailbox::new(&comp, mailbox::usbd_mailbox(i), &wiring::ROOT_USBD_CALL, &wiring::USBD_DONE, &mut h.alloc, &mut arena, &mut keep_slot);
    // The interrupt.
    let irq_slot = h.alloc.slots.global(|s| s.alloc());
    pci::msi_irq(&d, vector, &abs_of(root_cap::<cap_type::Null>(irq_slot)));
    let irq = root_cap::<cap_type::IrqHandler>(irq_slot);
    let irq_ntfn = root_cap::<cap_type::Notification>(h.alloc.slots.alloc());
    component::mint_edge(&abs_of(irq_ntfn), &wiring::IRQ_USBD, 0, &comp.obj()).expect("usbd IRQ notification");
    irq.irq_handler_set_notification(irq_ntfn).expect("usbd IRQ set notification");
    comp.give(usb::USBD_SLOT_IRQ, irq, CapRights::all());
    c.dom = dom;
    program_irq(h, i, vector, dom);
    let c = &mut ctrls()[i];
    // The firmware may be using it (keyboard emulation): bus mastering
    // stays as it is until usbd has it halted.
    h.pci.enable_memory(&c.pci);
    component::start(&comp);
    let mut u = Usbd { comp, arena, mailbox: mbox, ops: ArrayVec::new(), areas: [const { None }; usb::AREAS], idx: 0, waiting: false };
    send(&mut u, Request::Claim {}, Op::Claim);
    c.driver = Some(u);
    c.state = State::Idle;
    info!("l4h-root: xHCI {:02x}:{:02x}.{}: claiming it, {} KiB of DMA memory", d.bus, d.dev, d.func, dma >> 10);
    Ok(())
}

/// usbd answered the CLAIM.
fn claimed(h: &mut Host, i: usize, w: &[u64; host::mailbox::ANSWER]) {
    let c = &mut ctrls()[i];
    let d = c.pci;
    if c.state == State::Failed {
        return;
    }
    let got = match wire::reply::<reply::Claim>(w) {
        Ok(got) => got,
        Err(e) => {
            log!("l4h-root: xHCI {:02x}:{:02x}.{}: claim failed ({:#x})", d.bus, d.dev, d.func, e);
            quarantine(c, &h.pci);
            return;
        }
    };
    (c.usb2, c.usb3, c.ac64) = (got.usb2, got.usb3, got.ac64);
    c.claimed = true;
    route_intel_ports(&d, &h.pci);
    // An owner's ATTACH turns it back on.
    h.pci.bus_master(&d, false);
    info!("l4h-root: xHCI {:02x}:{:02x}.{}: claimed, {} USB 2 and {} USB 3 ports", d.bus, d.dev, d.func, c.usb2, c.usb3);
}

/// What a guest's VMM and vmmgr get for an attached controller.
pub struct Attached {
    /// A CNode (radix QUEUE_RADIX) of the queue area's frames.
    pub frames: cap::CNode,
    /// usbd's kick notification, badged for the client.
    pub kick: cap::Notification,
}

/// Claim controller `i` if the firmware still has it: outside any
/// guest's slot tracking, since usbd outlives the guest.
pub fn ensure_claimed(h: &mut Host, i: usize) -> Result<(), Errno> {
    match ctrls().get(i).ok_or(ctl::ENOENT)?.state {
        State::Firmware => claim(h, i),
        _ => Ok(()),
    }
}

/// Post a request to usbd.  Root posts at most two before they are
/// answered (Usbd::ops), so the ring has room.
fn send(d: &mut Usbd, req: Request, op: Op) {
    d.mailbox.send(&req).expect("usbd mailbox room");
    d.ops.must_push(op);
}

/// The owner's ATTACH, once usbd has answered what came before: bus
/// mastering back on.
fn post_attach(h: &mut Host, i: usize) {
    let c = &mut ctrls()[i];
    let (Some(d), Some(pool)) = (c.driver.as_mut(), c.pool) else { return };
    h.iommu.map(&mut h.alloc, c.dom, pool.1, pool.2, true);
    h.pci.bus_master(&c.pci, true);
    d.waiting = false;
    send(d, Request::Attach { area: d.idx, gpa: pool.0 as u64, paddr: pool.1 as u64, size: pool.2 as u64 }, Op::Attach);
}

/// Free area `idx`: usbd no longer uses it (REMOVE done, never attached,
/// or usbd suspended).
fn free_area(h: &mut Host, d: &mut Usbd, idx: usize) {
    if let Some(a) = d.areas[idx].take() {
        h.alloc.global(|alloc| {
            alloc.release(a.arena);
            a.slots.iter().for_each(|&s| alloc.slots.free(s));
        });
    }
}

/// Component `id`'s fault, if it is a usbd's: quarantine its controller and
/// finish what it has not answered.  Whether it was one.
pub fn fault(h: &mut Host, id: u32) -> bool {
    let Some(i) = id.checked_sub(usb::USBD_ID_BASE).map(|i| i as usize).filter(|&i| i < ctrls().len()) else { return false };
    let c = &mut ctrls()[i];
    if c.driver.is_none() {
        return false;
    }
    if c.state != State::Failed {
        let p = c.pci;
        log!("l4h-root: xHCI {:02x}:{:02x}.{}: usbd failed", p.bus, p.dev, p.func);
        quarantine(c, &h.pci);
    }
    poll(h);
    true
}

/// What usbd has answered (from the serve loop, on badges::root::MAILBOX).
/// A quarantined usbd is suspended: its requests are given up at once.
pub fn poll(h: &mut Host) {
    for i in 0..ctrls().len() {
        loop {
            let c = &mut ctrls()[i];
            let Some(d) = c.driver.as_mut() else { break };
            let failed = c.state == State::Failed;
            let w = if failed {
                d.mailbox.abandon().map(|_| [wire::FAILED; host::mailbox::ANSWER])
            } else {
                d.mailbox.answer().map(|(_, w)| w)
            };
            let Some(w) = w else { break };
            let p = c.pci;
            match d.ops.remove(0) {
                Op::Claim => claimed(h, i, &w),
                // The guest finds no magic.
                Op::Attach => {
                    if let (Err(e), false) = (wire::reply::<reply::Attach>(&w), failed) {
                        log!("l4h-root: xHCI {:02x}:{:02x}.{}: usbd refused the attachment ({:#x})", p.bus, p.dev, p.func, e);
                    }
                }
                Op::Remove(idx) => {
                    if let (Err(e), false) = (wire::reply::<reply::Remove>(&w), failed) {
                        log!("l4h-root: xHCI {:02x}:{:02x}.{}: usbd could not stop it ({:#x})", p.bus, p.dev, p.func, e);
                        quarantine(c, &h.pci);
                    }
                    free_area(h, ctrls()[i].driver.as_mut().unwrap(), idx);
                }
            }
            let c = &ctrls()[i];
            let d = c.driver.as_ref().unwrap();
            if d.waiting && d.ops.is_empty() && c.state != State::Failed {
                post_attach(h, i);
            }
        }
    }
}

/// `usb_attach`: give guest `g` controller `i`, claimed already
/// (ensure_claimed).  The guest's USB device number is `g.usbs.len()`
/// (its VMM's badge).  usbd starts the controller when it gets to it
/// (after the CLAIM or the previous guest's REMOVE): the guest waits for
/// the magic.
pub fn attach(h: &mut Host, i: usize, g: &mut RootGuest) -> Result<Attached, Errno> {
    let state = ctrls().get(i).ok_or(ctl::ENOENT)?.state;
    match state {
        State::Firmware => return Err(ctl::EIO),
        State::Idle => {}
        State::Vm(_) => return Err(ctl::EBUSY),
        State::Failed => return Err(ctl::EIO),
        State::Unsupported(_) => return Err(ctl::ENODEV),
    }
    if g.usbs.len() >= usb::MAX_GUEST_USB {
        return Err(ctl::ENOSPC);
    }
    let c = &mut ctrls()[i];
    // usbd checks it too, if it has not answered the CLAIM yet.
    if c.claimed && !c.ac64 && g.pool.paddr.checked_add(g.pool.size).is_none_or(|e| e > 1 << 32) {
        return Err(ctl::EINVAL);
    }
    let d = c.driver.as_mut().expect("claimed usbd");
    let Some(idx) = (0..usb::AREAS).find(|&k| d.areas[k].is_none()) else { return Err(ctl::EBUSY) };
    if !h.can_afford((uabi::AREA_PAGES + 8) * PAGE, 0, 2 * (1 << QUEUE_RADIX) + 8) {
        return Err(ctl::ENOMEM);
    }
    // The queue area: root's frames, in an arena outside the guest's
    // (usbd may use them after the guest is gone, until REMOVE is done).
    let area = h.alloc.global(|alloc| -> Option<Area> {
        let mut arena = alloc.arena((uabi::AREA_PAGES + 4) * PAGE)?;
        let frames = arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: QUEUE_RADIX });
        let keep = arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: QUEUE_RADIX });
        let guest = arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: QUEUE_RADIX });
        let ok = arena.retype(alloc, &FRAME_BP, uabi::AREA_PAGES, Dest { cnode: abs_of(frames), offset: 0 }).is_some();
        if !ok {
            alloc.release(arena);
            [frames.bits(), keep.bits(), guest.bits()].iter().for_each(|&s| alloc.slots.free(s as Slot));
            return None;
        }
        for p in 0..uabi::AREA_PAGES {
            let at = |cn: cap::CNode| cn.absolute_cptr_from_bits_with_depth(p as u64, QUEUE_RADIX);
            d.comp.map_copy(alloc, &mut d.arena, &at(frames), usb::queue_va(idx) + p * PAGE,
                CapRights::read_write(), VmAttributes::DEFAULT, at(keep));
            at(guest).copy(&at(frames), CapRights::all()).expect("USB queue frame copy");
        }
        let slots = [frames.bits() as Slot, keep.bits() as Slot, guest.bits() as Slot];
        Some(Area { arena, guest, slots })
    });
    let area = area.ok_or(ctl::ENOMEM)?;
    let n = g.usbs.len();
    let guest_frames = area.guest;
    d.areas[idx] = Some(area);
    // Completions go to the guest's VMM, which raises the device's event.
    let irq_slot = usb::USBD_SLOT_CLIENT_IRQ + idx as u64;
    let _ = d.comp.slot(irq_slot).delete();
    d.comp.give_edge(&wiring::USBD_VMM, idx, n, &g.vmm_ntfn);
    let kick = root_cap::<cap_type::Notification>(h.alloc.slots.alloc());
    component::mint_edge(&abs_of(kick), &wiring::VMM_USBD_KICK, 0, &d.comp.obj()).expect("usbd kick");
    d.idx = idx;
    c.pool = Some((g.pool.gpa, g.pool.paddr, g.pool.size));
    c.state = State::Vm(g.id);
    g.usbs.must_push(i);
    if d.ops.is_empty() {
        post_attach(h, i);
    } else {
        d.waiting = true;
    }
    Ok(Attached { frames: guest_frames, kick })
}

/// GUEST_DEL: take controller `i` back from its guest before the guest's
/// memory is reused, without waiting for usbd: the guest's queue frames
/// are revoked, the controller loses bus mastering and its IOMMU mapping
/// of the pool, and usbd's notification of the VMM goes.  Then REMOVE
/// (usbd may be busy; poll frees the area when it is done).  Whether the
/// controller can no longer reach the guest's pool.
pub fn remove(h: &mut Host, i: usize) -> bool {
    let c = &mut ctrls()[i];
    let attached = matches!(c.state, State::Vm(_));
    let Some(d) = c.driver.as_mut() else { return c.dom != Domain::NONE };
    let idx = d.idx;
    if let Some(a) = &d.areas[idx] {
        // vmmgr's copy of the CNode, then whatever was made of the frames.
        let _ = abs_of(a.guest).revoke();
        for p in 0..uabi::AREA_PAGES {
            let _ = a.guest.absolute_cptr_from_bits_with_depth(p as u64, QUEUE_RADIX).revoke();
        }
    }
    // A waiting ATTACH never turned bus mastering on: during a CLAIM it is
    // the firmware's until usbd has halted the controller.
    if !d.waiting {
        h.pci.bus_master(&c.pci, false);
    }
    let _ = d.comp.slot(usb::USBD_SLOT_CLIENT_IRQ + idx as u64).delete();
    let pool = c.pool.take();
    if let Some((_, pa, len)) = pool.filter(|_| !d.waiting) {
        h.iommu.unmap(c.dom, pa, len);
    }
    if !attached {
        // Quarantined: usbd is suspended.
        free_area(h, d, idx);
        return c.dom != Domain::NONE;
    }
    c.state = State::Idle;
    if d.waiting {
        // usbd never saw it.
        d.waiting = false;
        free_area(h, d, idx);
    } else {
        // After the ATTACH, if usbd has not answered it yet.
        send(d, Request::Remove { area: idx }, Op::Remove(idx));
    }
    true
}

/// Claim the controllers named by `dom0_usb` (BDFs) before dom0 starts:
/// their indices, for vmmgr to attach to every dom0.
pub fn dom0_ctrls(h: &Host) -> ArrayVec<u64, { usb::MAX_GUEST_USB }> {
    let mut v = ArrayVec::new();
    for bdf in h.cfg.dom0_usb.iter().flatten() {
        match ctrls().iter().position(|c| crate::netd::bdf(&c.pci) == *bdf) {
            Some(i) => {
                if v.push(i as u64).is_err() {
                    log!("l4h-root: dom0_usb: more than {} controllers", usb::MAX_GUEST_USB);
                }
            }
            None => log!("l4h-root: dom0_usb: no xHCI controller at {:02x}:{:02x}.{}", bdf >> 8, (bdf >> 3) & 0x1f, bdf & 7),
        }
    }
    v
}

/// CTL_USB_INFO for controller `i`.
pub fn info(i: usize, data: &mut [u8; abi::CTL_DATA_MAX]) -> Result<[u64; 6], Errno> {
    let c = ctrls().get(i).ok_or(ctl::ENOENT)?;
    let p = &c.pci;
    let (state, owner) = match c.state {
        State::Firmware => (abi::USB_STATE_FIRMWARE, u64::MAX),
        State::Idle => (abi::USB_STATE_IDLE, u64::MAX),
        State::Vm(vm) => (abi::USB_STATE_VM, vm as u64),
        State::Failed => (abi::USB_STATE_FAILED, u64::MAX),
        State::Unsupported(why) => {
            data[..why.len()].copy_from_slice(why.as_bytes());
            (abi::USB_STATE_UNSUPPORTED, u64::MAX)
        }
    };
    // What usbd last published: root does not wait for it.
    let refused = match &c.driver {
        Some(d) => d.mailbox.published::<usb::Published>().refused.load(Ordering::Relaxed),
        None => 0,
    };
    Ok([
        crate::netd::bdf(p) as u64,
        p.vendor as u64 | (p.device as u64) << 16,
        c.usb2 as u64 | (c.usb3 as u64) << 16,
        state,
        owner,
        refused,
    ])
}

/// The slot root's allocator gave a capability it moved away.
pub fn free_slot(h: &mut Host, c: cap::Notification) {
    h.alloc.slots.free(c.bits() as Slot);
}
