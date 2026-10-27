//! Spawning host components as separate seL4 processes with the layout
//! defined in `l4h-host`: root spawns blkd, netd, trustd, memd and vmmgr,
//! and vmmgr spawns guests' l4h-vmm.

use core::ptr;

use sel4::{CNodeCapData, CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use l4h_host as host;

use crate::cap_at;
use crate::elf::Elf;
use crate::mem::{Alloc, Arena, ObjCtx};
use crate::vspace::{FRAME_BP, PML4_BP, map_frame};
use crate::window::Window;

const PAGE: usize = 4096;

/// Badge bits on the root endpoint for messages from components.
pub const ROOT_BADGE_COMPONENT: u64 = 1 << 25;

pub fn component_badge(id: u32) -> u64 {
    ROOT_BADGE_COMPONENT | id as u64
}

pub struct Component {
    local_cnode: cap::CNode,
    pub id: u32,
    pub tcb: cap::Tcb,
    pub cnode: cap::CNode,
    pub vspace: cap::VSpace,
    pub ntfn: cap::Notification,
    pub service_ep: cap::Endpoint,
    pub sc: cap::SchedContext,
    /// Radix of its CNode.
    pub cnode_bits: usize,
}

impl Component {
    /// Destination for a capability in the component's CNode.
    pub fn slot(&self, idx: u64) -> sel4::AbsoluteCPtr {
        self.cnode.absolute_cptr_from_bits_with_depth(idx, self.cnode_bits)
    }

    pub fn give(&self, idx: u64, src: impl sel4::HasCPtrWithDepth, rights: CapRights) {
        self.slot(idx)
            .copy(&self.local_cnode.absolute_cptr(src), rights)
            .unwrap_or_else(|e| panic!("component {} slot {} copy: {:?}", self.id, idx, e));
    }

    pub fn give_badged(&self, idx: u64, src: impl sel4::HasCPtrWithDepth, rights: CapRights, badge: u64) {
        self.slot(idx)
            .mint(&self.local_cnode.absolute_cptr(src), rights, badge)
            .unwrap_or_else(|e| panic!("component {} slot {} mint: {:?}", self.id, idx, e));
    }

    /// Map `frame` (a capability anywhere in the parent's CSpace) into the
    /// component at `va`.  The mapping capability is a fresh copy that is
    /// moved into `keep` (a CNode slot that must outlive the mapping).
    pub fn map_copy(
        &self,
        alloc: &mut Alloc,
        arena: &mut Arena,
        frame: &sel4::AbsoluteCPtr,
        va: usize,
        rights: CapRights,
        attrs: VmAttributes,
        keep: sel4::AbsoluteCPtr,
    ) {
        let s = alloc.slots.alloc();
        self.local_cnode.absolute_cptr(cap_at::<cap_type::Null>(s)).copy(frame, CapRights::all()).expect("copy frame");
        let f = cap_at::<cap_type::Granule>(s);
        map_frame(&mut ObjCtx::arena(alloc, arena), self.vspace, f, va, rights, attrs);
        keep.move_(&self.local_cnode.absolute_cptr(f)).expect("keep mapping cap");
        alloc.slots.free(s);
    }
}

pub struct SpawnArgs<'a> {
    pub id: u32,
    pub kind: u32,
    pub elf: &'a [u8],
    pub prio: u64,
    pub budget_us: u64,
    pub period_us: u64,
    /// Kind-specific configuration written to the info page.
    pub config: &'a [u8],
    /// Pre-made bound notification / service endpoint (created if None).
    pub ntfn: Option<cap::Notification>,
    pub service_ep: Option<cap::Endpoint>,
    /// A CNode allocated in advance (the VMM's); otherwise made here.
    pub cnode: Option<cap::CNode>,
    /// Radix of its CNode, if not host::CNODE_BITS (memd's holds every
    /// Untyped).
    pub cnode_bits: Option<usize>,
}

/// Capabilities and clock supplied by the spawning task. The scheduling
/// control selects the child's CPU; the caller owns placement policy.
pub struct SpawnContext {
    pub authority: cap::Tcb,
    pub sched_control: cap::SchedControl,
    pub parent_ep: cap::Endpoint,
    pub tsc_hz: u64,
}

/// Create a component, without starting it.  Objects come from `arena`.
pub fn create(
    args: &SpawnArgs,
    alloc: &mut Alloc,
    arena: &mut Arena,
    win: &mut Window,
    assign_asid: &mut dyn FnMut(&mut Alloc, cap::VSpace),
    context: &SpawnContext,
) -> Component {
    let local_cnode = alloc.slots.cnode();
    let elf = Elf::parse(args.elf).expect("component ELF");
    let mut ctx = ObjCtx::arena(alloc, arena);

    let vspace = ctx.cap::<cap_type::VSpace>(PML4_BP);
    let cnode_bits = args.cnode_bits.unwrap_or(host::CNODE_BITS);
    let cnode = args.cnode.unwrap_or_else(|| ctx.cap::<cap_type::CNode>(ObjectBlueprint::CNode { size_bits: cnode_bits }));
    let tcb = ctx.cap::<cap_type::Tcb>(ObjectBlueprint::Tcb);
    let ntfn = args.ntfn.unwrap_or_else(|| ctx.cap::<cap_type::Notification>(ObjectBlueprint::Notification));
    let service_ep = args.service_ep.unwrap_or_else(|| ctx.cap::<cap_type::Endpoint>(ObjectBlueprint::Endpoint));
    let reply = ctx.cap::<cap_type::Reply>(ObjectBlueprint::Reply);
    let sc = ctx.cap::<cap_type::SchedContext>(ObjectBlueprint::SchedContext {
        size_bits: sel4::sys::seL4_MinSchedContextBits as usize,
    });
    let ipcbuf = ctx.cap::<cap_type::Granule>(FRAME_BP);
    // A keeper: its thread, scheduling context, the endpoint and reply
    // object it takes the main thread's faults with, and IPC buffer.
    let keeper = host::has_keeper(args.kind).then(|| {
        (
            ctx.cap::<cap_type::Tcb>(ObjectBlueprint::Tcb),
            ctx.cap::<cap_type::SchedContext>(ObjectBlueprint::SchedContext {
                size_bits: sel4::sys::seL4_MinSchedContextBits as usize,
            }),
            ctx.cap::<cap_type::Endpoint>(ObjectBlueprint::Endpoint),
            ctx.cap::<cap_type::Reply>(ObjectBlueprint::Reply),
            ctx.cap::<cap_type::Granule>(FRAME_BP),
        )
    });
    drop(ctx);
    assign_asid(alloc, vspace);

    let c = Component { local_cnode, id: args.id, tcb, cnode, vspace, ntfn, service_ep, sc, cnode_bits };

    // ---- Load the ELF image, one fresh frame per page; pages are writable
    // only if a writable segment covers them.  Segments come in ascending
    // order of address (as the ELF spec requires of PT_LOAD), so a page
    // two segments share is the last one's: the page before is reused.
    let page_range = |vaddr: u64, memsz: u64| (vaddr as usize & !(PAGE - 1))..(vaddr + memsz) as usize;
    let writable = |page: usize| elf.segments().any(|s| s.writable && page_range(s.vaddr, s.memsz).contains(&page));
    let mut last: Option<(usize, cap::Granule)> = None;
    for seg in elf.segments() {
        let range = page_range(seg.vaddr, seg.memsz);
        assert!(last.is_none_or(|(p, _)| p <= range.start), "component ELF segments out of order");
        assert!(range.end <= host::INFO_VA, "component ELF reaches its info area and stacks");
        for page in range.step_by(PAGE) {
            let frame = match last {
                Some((p, f)) if p == page => f,
                _ => {
                    let mut ctx = ObjCtx::arena(alloc, &mut *arena);
                    let f = ctx.cap::<cap_type::Granule>(FRAME_BP);
                    let rights = if writable(page) { CapRights::read_write() } else { CapRights::read_only() };
                    map_frame(&mut ctx, vspace, f, page, rights, VmAttributes::DEFAULT);
                    last = Some((page, f));
                    f
                }
            };
            // Copy the part of the segment's file data that lies in this page.
            let seg_lo = seg.vaddr as usize;
            let lo = page.max(seg_lo);
            let hi = (page + PAGE).min(seg_lo + seg.data.len());
            if lo < hi {
                let src = &seg.data[lo - seg_lo..hi - seg_lo];
                // A mapped frame cannot be mapped again: copy the cap for the window.
                win.with_frame(&local_cnode.absolute_cptr(frame), |p| unsafe {
                    ptr::copy_nonoverlapping(src.as_ptr(), p.add(lo - page), src.len());
                });
            }
        }
    }

    // ---- Info pages and IPC buffer.  The header and the configuration are
    // written straight into the info frames (fresh, so zeroed).
    let hdr = host::InfoHeader {
        magic: host::INFO_MAGIC,
        kind: args.kind,
        id: args.id,
        tsc_hz: context.tsc_hz,
        reserved: [0; 5],
    };
    let hdr = unsafe {
        core::slice::from_raw_parts(&hdr as *const host::InfoHeader as *const u8, core::mem::size_of::<host::InfoHeader>())
    };
    assert!(host::CONFIG_OFFSET + args.config.len() <= host::INFO_SIZE, "component config too large");
    for i in 0..host::INFO_SIZE / PAGE {
        let mut ctx = ObjCtx::arena(alloc, &mut *arena);
        let f = ctx.cap::<cap_type::Granule>(FRAME_BP);
        map_frame(&mut ctx, vspace, f, host::INFO_VA + i * PAGE, CapRights::read_only(), VmAttributes::DEFAULT);
        let page = i * PAGE..(i + 1) * PAGE;
        win.with_frame(&local_cnode.absolute_cptr(f), |p| {
            // The part of `src`, at `at` in the info area, in this page.
            for (at, src) in [(0, hdr), (host::CONFIG_OFFSET, args.config)] {
                let (lo, hi) = (at.max(page.start), (at + src.len()).min(page.end));
                if lo < hi {
                    unsafe { ptr::copy_nonoverlapping(src[lo - at..].as_ptr(), p.add(lo - page.start), hi - lo) };
                }
            }
        });
    }
    map_frame(
        &mut ObjCtx::arena(alloc, &mut *arena),
        vspace,
        ipcbuf,
        host::IPCBUF_VA,
        CapRights::read_write(),
        VmAttributes::DEFAULT,
    );

    if let Some((.., kipcbuf)) = keeper {
        map_frame(
            &mut ObjCtx::arena(alloc, &mut *arena),
            vspace,
            kipcbuf,
            host::KEEPER_IPCBUF_VA,
            CapRights::read_write(),
            VmAttributes::DEFAULT,
        );
    }

    // ---- Stacks: fresh frames, with nothing mapped below them.
    let mut stacks = [(host::STACK_TOP, host::stack_size(args.kind)), (0, 0)];
    if keeper.is_some() {
        stacks[1] = (host::KEEPER_STACK_TOP, host::KEEPER_STACK_SIZE);
    }
    for (top, size) in stacks {
        for va in (top - size..top).step_by(PAGE) {
            let mut ctx = ObjCtx::arena(alloc, &mut *arena);
            let f = ctx.cap::<cap_type::Granule>(FRAME_BP);
            map_frame(&mut ctx, vspace, f, va, CapRights::read_write(), VmAttributes::DEFAULT);
        }
    }

    // ---- CSpace.
    let guard = CNodeCapData::new(0, 64 - cnode_bits);
    c.give_badged(host::SLOT_CNODE, cnode, CapRights::all(), guard.into_word());
    c.give(host::SLOT_VSPACE, vspace, CapRights::all());
    c.give(host::SLOT_TCB, tcb, CapRights::all());
    c.give_badged(
        host::SLOT_ROOT_EP,
        context.parent_ep,
        sel4::CapRightsBuilder::none().write(true).grant_reply(true).build(),
        component_badge(args.id),
    );
    c.give(host::SLOT_NTFN, ntfn, CapRights::all());
    c.give(host::SLOT_SERVICE_EP, service_ep, CapRights::all());
    c.give(host::SLOT_REPLY, reply, CapRights::all());

    // ---- Thread.
    tcb.tcb_configure(cnode, CNodeCapData::new(0, 64 - cnode_bits), vspace, host::IPCBUF_VA as u64, ipcbuf)
        .expect("component TCB configure");
    context.sched_control
        .sched_control_configure_flags(sc, args.budget_us, args.period_us, 0, 0, 0)
        .expect("component SC");
    let fault_slot = alloc.slots.alloc();
    local_cnode.absolute_cptr(cap_at::<cap_type::Null>(fault_slot))
        .mint(&local_cnode.absolute_cptr(context.parent_ep), CapRights::all(), component_badge(args.id) | host::BADGE_FAULT)
        .expect("component fault ep");
    let root_fault = cap_at::<cap_type::Endpoint>(fault_slot);
    // The keeper is left suspended: the main thread starts it, on its own
    // stack and TLS (l4h_rt::init).
    if let Some((ktcb, ksc, kep, kreply, kipcbuf)) = keeper {
        c.give(host::SLOT_KEEPER, ktcb, CapRights::all());
        c.give(host::SLOT_FAULT_EP, kep, CapRights::all());
        c.give(host::SLOT_KEEPER_REPLY, kreply, CapRights::all());
        ktcb.tcb_configure(cnode, CNodeCapData::new(0, 64 - cnode_bits), vspace, host::KEEPER_IPCBUF_VA as u64, kipcbuf)
            .expect("keeper TCB configure");
        context.sched_control
            .sched_control_configure_flags(ksc, args.budget_us, args.period_us, 0, 0, 0)
            .expect("keeper SC");
        ktcb.tcb_set_sched_params(context.authority, args.prio, args.prio, ksc, root_fault)
            .expect("keeper sched params");
    }
    let fault_ep = keeper.map_or(root_fault, |(_, _, kep, ..)| kep);
    tcb.tcb_set_sched_params(context.authority, args.prio, args.prio, sc, fault_ep)
        .expect("component sched params");
    tcb.tcb_bind_notification(ntfn).expect("component bind notification");
    let mut regs = sel4::UserContext::default();
    *regs.pc_mut() = elf.entry;
    tcb.tcb_write_all_registers(false, &mut regs).expect("component registers");
    c
}

pub fn start(c: &Component) {
    c.tcb.tcb_resume().expect("start component");
}
