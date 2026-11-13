//! Networking: the netd component (the switches), the ports that connect
//! guests' virtio-net devices to it, the uplinks (channels to the nicds
//! that drive NICs, nicd.rs) and the links to other partitions' netds.

use core::sync::atomic::Ordering;

use l4h_host::errno::Errno;
use sel4::{CapRights, ObjectBlueprint, VmAttributes, cap, cap_type};

use l4h_host::{badges, wiring};
use l4h_host::net::call::Request;
use l4h_host::fixed::ArrayVec;
use l4h_host::{self as host, net};

use crate::blkd::keep_bits;
use crate::component::{self, Component, SpawnArgs, abs_of};
use crate::devmem::DevMem;
use crate::mailbox::{self, Mailbox};
use l4h_host::mailbox::RING;
use crate::mem::{Alloc, Arena, Dest, Slot, UtRegion};
use crate::pci::{self, Pci};
use crate::vmmgr::RootGuest;
use crate::vspace::FRAME_BP;
use crate::window::Window;
use crate::{AsidPools, Host, HostInfo, ctl};

static NETD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l4h-netd.elf"));

const PAGE: usize = 4096;
/// Port memory: the channel plus three CNodes, of its frames (root's),
/// of netd's mappings of them, and of the copies vmmgr gets.
const PORT_BITS: usize = 22;
const PORT_KEEP_BITS: usize = l4h_host::vmmgr::PORT_RADIX;
const PORT_CNODES: usize = 3;
const _: () = assert!(net::PORT_PAGES <= 1 << PORT_KEEP_BITS);
// The CNodes (64 bytes a slot at most) and the frames fit the memory.
const _: () = assert!(PORT_CNODES * (64 << PORT_KEEP_BITS) + net::PORT_PAGES * PAGE <= 1 << PORT_BITS);
// A link's channel is whole pages, and fits where netd maps it.
const _: () = assert!(
    l4h_partition::LINK_CHANNEL_SIZE as usize % PAGE == 0 && l4h_partition::LINK_CHANNEL_SIZE as usize <= net::LINK_CHANNEL_MAX
);
const NETD_ID: u32 = 0x200;

pub struct PortInfo {
    pub vm: usize,
    pub switch: u32,
    pub mac: u64,
}

/// A steering endpoint (DESIGN.md §9.3): an address on a switch and the
/// peer its steered traffic comes from and returns to.
#[derive(Clone, Copy)]
pub struct Endpoint {
    pub switch: u32,
    pub mac: u64,
    pub peer: u64,
}

/// A steering rule: an endpoint's frames matching (IP, proto, port) go to
/// a target port.  `matches` and `ip` as CTL_STEER_SET's args.
#[derive(Clone, Copy)]
pub struct SteerRule {
    pub ep: usize,
    pub matches: u64,
    pub ip: (u64, u64),
    pub targets: u64,
}

/// A link to another partition (`link.pA-pB` in l4h-mk.conf, DESIGN.md
/// §11.4): a channel of its own that the two netds write and read
/// directly.  Root never touches the frames: it maps the channel into
/// netd, points the receive doorbell at netd, and rings the peer's
/// doorbell when netd asks (only root holds IRQControl), which netd does
/// only when the peer's netd said it is going to sleep.
pub struct Link {
    pub peer: u32,
    peer_slot: u32,
    peer_vector: u32,
}

pub struct Netd {
    comp: Component,
    #[allow(dead_code)]
    arena: Arena,
    /// Commands to netd, which it does not answer: root validates them
    /// and keeps their state (net::call::add_port).
    mailbox: Mailbox<net::call::Proto>,
    /// netd faulted (`fault`): it is suspended, and commands to it go
    /// nowhere.
    failed: bool,
    /// Removals in the ring, by number mod RING: a port and what waits
    /// for netd to let go of its memory (vmmgr::Zombie), or an uplink.
    removals: [Option<Removal>; RING],
    /// Ports being removed: netd may still use them (held), and the
    /// removal may wait for room in the ring (backlog), with its zombie.
    held: u64,
    backlog: u64,
    /// Uplink removals waiting for room in the ring (bit n: uplink n).
    uplink_backlog: u32,
    zombies: [Option<usize>; net::MAX_PORTS],
    /// Each uplink's switch (nicd.rs numbers the uplinks).
    uplinks: [Option<u32>; net::MAX_UPLINKS],
    pub ports: [Option<PortInfo>; net::MAX_PORTS],
    /// Switches 0..switches exist (they are never deleted).
    pub switches: u32,
    /// Mirrors of netd's steering tables, by id.
    pub endpoints: [Option<Endpoint>; net::MAX_STEER_ENDPOINTS],
    pub rules: [Option<SteerRule>; net::MAX_STEER_RULES],
    pub links: ArrayVec<Link, { net::MAX_LINKS }>,
}

#[derive(Clone, Copy)]
enum Removal {
    Port(usize, Option<usize>),
    Uplink(usize),
}

pub fn bdf(d: &pci::Device) -> u32 {
    ((d.bus as u32) << 8) | ((d.dev as u32) << 3) | d.func as u32
}

/// Make netd panic, for tests/run-logdtest.sh.  It has no keeper: its
/// fault comes to root, which fails it (`fault`).
pub fn inject_panic(h: &mut Host) {
    let _ = h.netd.post(Request::TestPanic {});
}

/// Make netd stop, for tests/run-logdtest.sh, as a compromised netd
/// might: root goes on, and what waits for netd stays pending.
pub fn inject_hang(h: &mut Host) {
    let _ = h.netd.post(Request::TestHang {});
}

/// Start netd, which has no device: uplinks come as nicds start.
pub fn spawn(alloc: &mut Alloc, win: &mut Window, asids: &mut AsidPools, info: &HostInfo) -> Netd {
    let mut arena = alloc.arena(16 << 20).expect("netd arena");
    let args = SpawnArgs {
        id: NETD_ID,
        kind: host::KIND_NETD,
        elf: NETD_ELF,
        prio: host::PRIO_SERVICE,
        budget_us: info.timeslice_us,
        period_us: info.timeslice_us,
        config: &[],
        ntfn: None,
        service_ep: None,
        cnode: None,
        cnode_bits: None,
    };
    let comp = component::create(
        &args, alloc, &mut arena, win, &mut |alloc, vspace| asids.assign(alloc, vspace),
        &info.spawn_context(0),
    );
    let keep_bits = keep_bits(host::mailbox::MAILBOX_PAGES);
    let keep = arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: keep_bits });
    let mut keep_next = 0u64;
    let mut keep_slot = || {
        let s = keep.absolute_cptr_from_bits_with_depth(keep_next, keep_bits);
        keep_next += 1;
        s
    };
    let mailbox = Mailbox::new(&comp, mailbox::NETD_MAILBOX, &wiring::ROOT_NETD_CALL, &wiring::NETD_DONE, alloc, &mut arena, &mut keep_slot);
    component::start(&comp);
    Netd {
        comp,
        arena,
        mailbox,
        removals: [None; RING],
        failed: false,
        held: 0,
        backlog: 0,
        uplink_backlog: 0,
        zombies: [None; net::MAX_PORTS],
        uplinks: [None; net::MAX_UPLINKS],
        ports: [const { None }; net::MAX_PORTS],
        switches: 0,
        endpoints: [None; net::MAX_STEER_ENDPOINTS],
        rules: [None; net::MAX_STEER_RULES],
        links: ArrayVec::new(),
    }
}

impl Netd {
    /// Post a command; EBUSY if netd has left the ring full.
    /// Post a command: dropped once netd has failed, as root keeps the
    /// state commands set and reads nothing back.
    fn post(&mut self, req: Request) -> Result<(), Errno> {
        if self.failed {
            return Ok(());
        }
        self.mailbox.send(&req).map(|_| ()).ok_or(ctl::EBUSY)
    }

    /// Whether a command can be posted now.
    pub fn room(&self) -> bool {
        self.mailbox.room()
    }

    /// Whether netd has failed (`fail`): NicAdd refuses then.
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Whether netd serves, or never will.
    pub fn ready(&self) -> bool {
        self.failed || self.published().ready.load(Ordering::Acquire) != 0
    }

    fn published(&self) -> &net::Published {
        self.mailbox.published::<net::Published>()
    }

    /// A new switch; ENOSPC once there are MAX_SWITCHES, the size of
    /// netd's table of them.
    pub fn try_create_switch(&mut self) -> Result<u32, Errno> {
        if self.switches as usize >= net::MAX_SWITCHES {
            return Err(ctl::ENOSPC);
        }
        self.switches += 1;
        Ok(self.switches - 1)
    }

    /// A switch of the boot configuration.
    pub fn create_switch(&mut self) -> u32 {
        self.try_create_switch().expect("l4h-root: more switches than MAX_SWITCHES")
    }

    /// Put uplink `nic` (nicd.rs) on `switch`.  Its MAC, if it has one
    /// yet, must not be a port's of the switch (root gives dom0's uplink
    /// port that MAC: two would be ambiguous).
    pub fn attach_uplink(&mut self, switch: u32, nic: usize) -> Result<(), Errno> {
        if switch >= self.switches {
            return Err(ctl::ENOENT);
        }
        if nic >= crate::nicd::nics().len() {
            return Err(ctl::ENOENT);
        }
        if self.uplinks[nic].is_some() {
            return Err(ctl::EBUSY);
        }
        if let Some(mac) = crate::nicd::mac(nic) {
            if self.ports.iter().flatten().any(|p| p.switch == switch && p.mac == mac) {
                return Err(ctl::EEXIST);
            }
        }
        if !self.failed {
            self.mailbox.send(&Request::AttachUplink { nic, switch: switch as usize }).ok_or(ctl::EBUSY)?;
        }
        self.uplinks[nic] = Some(switch);
        Ok(())
    }

    /// The switch of uplink `nic`.
    pub fn uplink_switch(&self, nic: usize) -> Option<u32> {
        *self.uplinks.get(nic)?
    }

    /// The uplink on `switch`, if any.
    pub fn uplink_on(&self, switch: u32) -> Option<usize> {
        self.uplinks.iter().position(|&s| s == Some(switch))
    }

    /// Map uplink `nic`'s channel (root's frames in `frames`, radix
    /// `bits`) into netd, for good.
    pub fn map_uplink(&mut self, nic: usize, frames: cap::CNode, bits: usize, pages: usize, alloc: &mut Alloc) -> Result<(), Errno> {
        if pages * PAGE > net::UPLINK_CHANNEL_MAX {
            return Err(ctl::EINVAL);
        }
        let keep = self.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: bits });
        let (comp, arena) = (&self.comp, &mut self.arena);
        alloc.global(|alloc| {
            for p in 0..pages {
                let f = frames.absolute_cptr_from_bits_with_depth(p as u64, bits);
                let dst = keep.absolute_cptr_from_bits_with_depth(p as u64, bits);
                comp.map_copy(alloc, arena, &f, net::uplink_va(nic) + p * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, dst);
            }
        });
        Ok(())
    }

    /// Give nicd `c` netd's notification, badged for uplinks.
    pub fn give_uplink_peer(&self, c: &Component) {
        c.give_edge(&wiring::NICD_NETD, 0, 0, &self.comp.obj());
    }

    /// Give netd uplink `nic`'s nicd's notification, replacing the last
    /// instance's.  Err (and netd failed) if netd keeps filling the slot.
    pub fn signal_uplink(&mut self, nic: usize, c: &Component) -> Result<(), Errno> {
        if self.failed {
            return Ok(());
        }
        if self.comp.give_edge_live(&wiring::NETD_NICD, nic, 0, &c.obj()).is_err() {
            self.fail_inner();
            return Err(ctl::EIO);
        }
        Ok(())
    }

    /// Post AddUplink: netd takes uplink `nic`'s fresh channel.
    pub fn add_uplink(&mut self, nic: usize, data_bits: u32) -> Result<(), Errno> {
        self.post(Request::AddUplink { nic, data_bits })
    }

    /// Post RemoveUplink: true if netd must answer it before the channel
    /// is reused (nicd::netd_released then); false if netd has failed and
    /// touches nothing.
    pub fn remove_uplink(&mut self, nic: usize) -> bool {
        if self.failed {
            return false;
        }
        // A full ring waits for room, as port removals do (`poll`).
        self.uplink_backlog |= 1 << nic;
        self.flush_backlog();
        true
    }

    /// Uplink `nic`'s channel as netd published it: (UPLINK_* state, the
    /// AddUplink generation it is of, MAC | mac_mode << 48).
    pub fn uplink_state(&self, nic: usize) -> Option<(u64, u32, u64)> {
        if self.failed {
            return None;
        }
        let w = self.published().uplinks.get(nic)?;
        let s = w[net::UPLINK_STATE].load(Ordering::Acquire);
        Some((s & 0xff, (s >> 8 & 0xff_ffff) as u32, w[net::UPLINK_MAC].load(Ordering::Relaxed)))
    }

    /// The port a new port on `switch` would be.
    pub fn free_port(&self, switch: u32) -> Result<usize, Errno> {
        if switch >= self.switches {
            return Err(ctl::ENOENT);
        }
        // A port being removed is netd's until it says it is done.
        let p = (0..net::MAX_PORTS).find(|&p| self.ports[p].is_none() && self.held & (1 << p) == 0).ok_or(ctl::ENOSPC)?;
        Ok(p)
    }

    /// A port's memory, in its own root slot: taken before the guest's
    /// device, so that running out leaves nothing behind.
    pub fn port_memory(alloc: &mut Alloc) -> Result<(Slot, UtRegion), Errno> {
        let s = alloc.slots.alloc();
        match alloc.split(PORT_BITS, s) {
            Some(region) => Ok((s, region)),
            None => {
                alloc.slots.free(s);
                Err(ctl::ENOMEM)
            }
        }
    }

    /// Connect a guest device of `g` to `switch` as port `p` (free_port,
    /// then give_port_done), using `memory` (port_memory).  Returns for the guest's l4h-vmm a
    /// CNode of copies of the port's frames (radix PORT_KEEP_BITS) and a
    /// kick capability, in a slot of its own.
    #[allow(clippy::too_many_arguments)]
    pub fn add_port(
        &mut self,
        g: &mut RootGuest,
        p: usize,
        switch: u32,
        mac: u64,
        lock: bool,
        isolated: bool,
        (s, region): (Slot, UtRegion),
        alloc: &mut Alloc,
    ) -> (cap::CNode, cap::Notification) {
        // Port memory is the guest's: it is reclaimed with it.
        g.arena.own(s, region.paddr, PORT_BITS);
        let mut pool = region;
        // CNodes of the port's frames, of netd's mappings of them, and of
        // the copies the guest's VMM maps.  The frames themselves stay
        // root's: whoever held them could revoke one, which unmaps it from
        // netd, and netd would fault for every guest.  A copy revokes
        // nothing.
        let cnodes = alloc.slots.alloc_range(PORT_CNODES);
        pool.retype(&ObjectBlueprint::CNode { size_bits: PORT_KEEP_BITS }, PORT_CNODES, Dest::new(crate::slot::CNODE.cap(), cnodes.start))
            .expect("port CNodes");
        let cnode = |k: usize| sel4::init_thread::Slot::<cap_type::CNode>::from_index(cnodes.start + k).cap();
        let (frames, keep, chan) = (cnode(0), cnode(1), cnode(2));
        pool.retype(&FRAME_BP, net::PORT_PAGES, Dest { cnode: abs_of(frames), offset: 0 }).expect("port frames");
        for i in 0..net::PORT_PAGES {
            let f = frames.absolute_cptr_from_bits_with_depth(i as u64, PORT_KEEP_BITS);
            let dst = keep.absolute_cptr_from_bits_with_depth(i as u64, PORT_KEEP_BITS);
            chan.absolute_cptr_from_bits_with_depth(i as u64, PORT_KEEP_BITS).copy(&f, CapRights::all()).expect("port frame copy");
            // Paging structures for the port come from netd's own pool, and
            // outlive the guest: their root slots must not be tracked into
            // it, or destroying it deletes them (and the arena regions they
            // grew into) while other ports still use them.
            let (comp, arena) = (&self.comp, &mut self.arena);
            alloc.global(|alloc| {
                comp.map_copy(alloc, arena, &f, net::port_va(p) + i * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, dst)
            });
        }
        let kick_slot = alloc.slots.alloc();
        let kick = sel4::init_thread::Slot::<cap_type::Notification>::from_index(kick_slot).cap();
        component::mint_edge(&abs_of(kick), &wiring::VMM_NETD_KICK, p, &self.comp.obj()).expect("port kick");
        // Only root grants a dom0 port the physical uplink's identity.
        // A bond keeps both permanent MACs but can send with either
        // member's MAC on either link. Do not unlock arbitrary sources.
        let uplink = self.uplink_on(switch);
        let physical = g.dom0 && uplink.is_some_and(|n| self.nic_mac(n) == Some(mac))
            && !self.ports.iter().flatten().any(|p| p.vm == g.id && p.switch == switch && p.mac == mac);
        let alias = if physical && switch < 2 {
            self.uplink_on(1 - switch).and_then(|n| self.nic_mac(n)).unwrap_or(0)
        } else { 0 };
        let flags = if lock { net::NETD_PORT_MAC_LOCK } else { 0 }
            | if isolated { net::NETD_PORT_ISOLATED } else { 0 }
            | if physical { net::NETD_PORT_UPLINK } else { 0 };
        // The caller made sure of room in the ring (`room`).
        if self.post(Request::AddPort { port: p, switch: switch as usize, mac, flags, alias }).is_err() {
            log!("l4h-root: netd has no room for port {}", p);
        }
        self.ports[p] = Some(PortInfo { vm: g.id, switch, mac });
        (chan, kick)
    }

    /// Disconnect port `p`.  netd stops using its memory, and `zombie`
    /// (vmmgr::Zombie), which holds it, is told once netd has said so
    /// (`poll`).
    pub fn remove_port(h: &mut Host, p: usize, zombie: Option<usize>) {
        let n = &mut h.netd;
        if n.ports.get_mut(p).and_then(|i| i.take()).is_none() {
            crate::vmmgr::zombie_done(h, zombie, true);
            return;
        }
        // The port leaves every rule; netd does the same.
        for r in n.rules.iter_mut() {
            if r.is_some_and(|r| r.targets & (1 << p) != 0) {
                *r = None;
            }
        }
        n.held |= 1 << p;
        n.backlog |= 1 << p;
        n.zombies[p] = zombie;
        n.flush_backlog();
    }

    /// Post the removals that wait for room in the ring.  A failed netd
    /// keeps them for `poll`.
    fn flush_backlog(&mut self) {
        while self.uplink_backlog != 0 && !self.failed {
            let nic = self.uplink_backlog.trailing_zeros() as usize;
            let Some(k) = self.mailbox.send(&Request::RemoveUplink { nic }) else { break };
            self.removals[k as usize % RING] = Some(Removal::Uplink(nic));
            self.uplink_backlog &= !(1 << nic);
        }
        while self.backlog != 0 && !self.failed {
            let p = self.backlog.trailing_zeros() as usize;
            let Some(k) = self.mailbox.send(&Request::RemovePort { port: p }) else { break };
            self.removals[k as usize % RING] = Some(Removal::Port(p, self.zombies[p].take()));
            self.backlog &= !(1 << p);
        }
    }

    /// Ports netd has let go of: their memory can be reclaimed.  A
    /// failed netd, suspended, lets go of every port at once.
    pub fn poll(h: &mut Host) {
        loop {
            let n = &mut h.netd;
            let next = if n.failed { n.mailbox.abandon() } else { n.mailbox.answer().map(|(k, _)| k) };
            let Some(k) = next else { break };
            match n.removals[k as usize % RING].take() {
                Some(Removal::Port(p, zombie)) => Self::released(h, p, zombie),
                Some(Removal::Uplink(nic)) => crate::nicd::netd_released(h, nic),
                None => {}
            }
        }
        while h.netd.failed && h.netd.uplink_backlog != 0 {
            let nic = h.netd.uplink_backlog.trailing_zeros() as usize;
            h.netd.uplink_backlog &= !(1 << nic);
            crate::nicd::netd_released(h, nic);
        }
        while h.netd.failed && h.netd.backlog != 0 {
            let p = h.netd.backlog.trailing_zeros() as usize;
            h.netd.backlog &= !(1 << p);
            let zombie = h.netd.zombies[p].take();
            Self::released(h, p, zombie);
        }
        h.netd.flush_backlog();
    }

    /// netd no longer uses port `p`'s memory.
    fn released(h: &mut Host, p: usize, zombie: Option<usize>) {
        h.netd.take_port_done(p);
        h.netd.held &= !(1 << p);
        crate::vmmgr::zombie_done(h, zombie, true);
    }

    /// Component `id`'s fault, if it is netd's: suspend it, and let go of
    /// what it has not answered.  Whether it was netd's.
    pub fn fault(h: &mut Host, id: u32) -> bool {
        if id != NETD_ID {
            return false;
        }
        h.netd.fail(&h.pci);
        Self::poll(h);
        true
    }

    /// Stop using netd until reboot (it faulted, or misbehaved): suspend
    /// it, and cut the uplink NICs off from memory, as blkd's and usbd's
    /// quarantines disable their controllers: a suspended driver must not
    /// leave devices it programmed still bus-mastering.  `poll` then lets
    /// go of what it has not answered.
    pub fn fail(&mut self, _pci: &Pci) {
        self.fail_inner();
    }

    /// netd has no device: suspended, it touches nothing more, and the
    /// nicds' channels are free of it (`poll` answers their removals).
    fn fail_inner(&mut self) {
        if self.failed {
            return;
        }
        log!("l4h-root: netd failed: guest networking stops until reboot");
        self.failed = true;
        let _ = self.comp.tcb.tcb_suspend();
    }

    /// Give netd port `p`'s done notification, to guest `g`'s VMM, before
    /// anything is allocated for the port (`add_port`).  EIO, netd failed,
    /// if netd keeps filling the slot.
    pub fn give_port_done(&mut self, p: usize, g: &RootGuest, pci: &Pci) -> Result<(), Errno> {
        if self.comp.give_edge_live(&wiring::NETD_VMM_DONE, p, 0, &g.vmm_ntfn).is_err() {
            self.fail(pci);
            return Err(ctl::EIO);
        }
        Ok(())
    }

    /// Take back port `p`'s done notification (`give_port_done`): netd is
    /// done with the port, or it is not added after all.
    pub fn take_port_done(&self, p: usize) {
        let _ = self.comp.slot(net::NETD_SLOT_CLIENT_BASE + p as u64).delete();
    }

    /// Put the link channel `ch` of partition `me` on `switch`, as netd's
    /// link l (returned).  netd gets the channel mapped (by the CPU only:
    /// no device reaches it), its doorbell's IRQ handler, and `ntfn`
    /// badged for the link, to ask root to ring the peer's doorbell.
    pub fn add_link(
        &mut self,
        ch: &l4h_partition::Channel,
        me: u32,
        switch: u32,
        ntfn: cap::Notification,
        alloc: &mut Alloc,
        devmem: &mut DevMem,
        pci: &Pci,
    ) -> Result<usize, Errno> {
        let l = self.links.len();
        if l >= net::MAX_LINKS || switch >= self.switches {
            return Err(ctl::ENOSPC);
        }
        // One size, as a control channel's is (channel.rs): netd's record
        // limits are that size's, and it refuses another.
        if ch.size != l4h_partition::LINK_CHANNEL_SIZE {
            return Err(ctl::EINVAL);
        }
        let size = ch.size as usize;
        // Room for the command before anything is set up for the link:
        // nothing else posts before it does, so a full ring refuses the
        // link here, with nothing mapped or given yet.
        if !self.failed && !self.mailbox.room() {
            return Err(ctl::EBUSY);
        }
        let bits = keep_bits(size / PAGE);
        let keep = self.arena.object_cap::<cap_type::CNode>(alloc, ObjectBlueprint::CNode { size_bits: bits });
        let (comp, arena) = (&self.comp, &mut self.arena);
        let mut i = 0;
        devmem
            .frames_range(alloc, ch.paddr as usize, size, |alloc, frames| {
                for s in frames {
                    let dst = keep.absolute_cptr_from_bits_with_depth(i as u64, bits);
                    let f = abs_of(crate::devmem::granule(s));
                    comp.map_copy(alloc, arena, &f, net::link_va(l) + i * PAGE, CapRights::read_write(), VmAttributes::DEFAULT, dst);
                    i += 1;
                }
            })
            .ok_or(ctl::ENOMEM)?;
        // The doorbell wakes netd directly, badged as the link; netd acks
        // it.  netd's kick to itself carries the same badge.
        let badged = alloc.slots.alloc();
        let badged = sel4::init_thread::Slot::<cap_type::Notification>::from_index(badged).cap();
        component::mint_edge(&abs_of(badged), &wiring::DOORBELL_NETD, l, &self.comp.obj()).expect("link doorbell badge");
        let mut given = match crate::channel::doorbell(alloc, ch.vector, badged) {
            Some(irq) => self.comp.give_live(net::NETD_SLOT_LINK_IRQ_BASE + l as u64, irq, CapRights::all(), "link doorbell"),
            None => {
                log!("l4h-root: no doorbell from partition {} for the link", ch.peer);
                Ok(())
            }
        };
        given = given.and_then(|()| self.comp.give_edge_live(&wiring::NETD_LINK_SELF, l, l, &self.comp.obj()));
        given = given.and_then(|()| self.comp.give_edge_live(&wiring::NETD_LINK_RING, l, l, &component::root_ntfn(ntfn)));
        // A netd that keeps filling these slots misbehaves: what was set up
        // for the link stays with it, stopped until reboot.
        if given.is_err() {
            self.fail(pci);
            return Err(ctl::EIO);
        }
        // There is room (checked above).
        self.post(Request::AddLink { link: l, switch: switch as usize, size: ch.size as u64, me: me as u32, peer: ch.peer as u32 })?;
        self.links.must_push(Link { peer: ch.peer, peer_slot: ch.peer_slot, peer_vector: ch.peer_vector });
        Ok(l)
    }

    /// netd asked for the doorbells of the links in `badge` (root's
    /// notification): ring them.  Constant work per link, however many
    /// frames netd wrote, and the notification merges repeated asks.
    pub fn link_ring(&self, badge: u64) {
        for (l, k) in self.links.iter().enumerate() {
            if badge & badges::root::LINK.nth(l) != 0 {
                crate::channel::ring(k.peer_slot, k.peer_vector);
            }
        }
    }

    /// CPU time netd used since the last call, in timer ticks.
    pub fn consumed(&self) -> u64 {
        crate::sched_consumed(self.comp.sc)
    }

    /// The MAC address of host NIC `n`, as root checked it (nicd.rs).
    pub fn nic_mac(&self, n: usize) -> Option<u64> {
        crate::nicd::mac(n)
    }

    /// (rx frames, tx frames, drops) of port `p`, as netd published them.
    pub fn port_stats(&self, p: usize) -> Option<(u64, u64, u64)> {
        let [rx, tx, drops] = self.published().ports.get(p)?.each_ref().map(|c| c.load(Ordering::Relaxed));
        Some((rx, tx, drops))
    }
}

fn is_unicast_mac(m: u64) -> bool {
    m != 0 && m >> 48 == 0 && (m >> 40) & 1 == 0
}

/// An IP a rule may match: not unspecified, multicast or broadcast.
fn steerable_ip(v6: bool, hi: u64, lo: u64) -> bool {
    if v6 {
        (hi, lo) != (0, 0) && hi >> 56 != 0xff
    } else {
        lo != 0 && lo != 0xffff_ffff && lo >> 28 != 0xe
    }
}

impl Netd {
    /// The MAC of switch `sw`'s uplink NIC, if it has one.
    fn uplink_mac(&self, sw: u32) -> Option<u64> {
        self.nic_mac(self.uplink_on(sw)?)
    }

    /// Set the endpoint (switch, mac): a new one, or a new peer for an
    /// existing one.  Returns its id.
    pub fn ep_set(&mut self, switch: u32, mac: u64, peer: u64) -> Result<usize, Errno> {
        if switch >= self.switches {
            return Err(ctl::ENOENT);
        }
        if !is_unicast_mac(mac) || !is_unicast_mac(peer) || mac == peer {
            return Err(ctl::EINVAL);
        }
        // An address on the switch: never one behind its uplink.
        let on_switch = self.ports.iter().flatten().any(|p| p.switch == switch && p.mac == mac);
        if !on_switch && self.uplink_mac(switch) != Some(mac) {
            return Err(ctl::EINVAL);
        }
        let id = match self.endpoints.iter().position(|e| e.is_some_and(|e| e.switch == switch && e.mac == mac)) {
            Some(id) => id,
            None => self.endpoints.iter().position(|e| e.is_none()).ok_or(ctl::ENOSPC)?,
        };
        self.post(Request::EpSet { ep: id, switch: switch as usize, mac, peer })?;
        self.endpoints[id] = Some(Endpoint { switch, mac, peer });
        Ok(id)
    }

    /// Delete endpoint `id` and its rules.
    pub fn ep_del(&mut self, id: usize) -> Result<(), Errno> {
        self.endpoints.get(id).copied().flatten().ok_or(ctl::ENOENT)?;
        self.post(Request::EpDel { ep: id })?;
        self.endpoints[id] = None;
        for r in self.rules.iter_mut() {
            if r.is_some_and(|r| r.ep == id) {
                *r = None;
            }
        }
        Ok(())
    }

    /// Set the rule (ep, matches, ip): a new one, or new targets for an
    /// existing one.  Returns its id.
    pub fn steer_set(&mut self, ep: usize, matches: u64, ip: (u64, u64), targets: u64) -> Result<usize, Errno> {
        let e = self.endpoints.get(ep).copied().flatten().ok_or(ctl::ENOENT)?;
        let (family, proto, port) = (matches as u8, (matches >> 8) as u8, (matches >> 16) as u16);
        let v6 = match family {
            4 if ip.0 == 0 && ip.1 >> 32 == 0 => false,
            6 => true,
            _ => return Err(ctl::EINVAL),
        };
        if matches >> 32 != 0 || (proto == 0 && port != 0) || (port != 0 && proto != 6 && proto != 17) {
            return Err(ctl::EINVAL);
        }
        if !steerable_ip(v6, ip.0, ip.1) || targets.count_ones() != 1 {
            return Err(ctl::EINVAL);
        }
        let t = targets.trailing_zeros() as usize;
        let target = self.ports.get(t).and_then(|p| p.as_ref()).ok_or(ctl::ENOENT)?;
        if target.mac == e.mac {
            return Err(ctl::EINVAL);
        }
        let same = |r: &SteerRule| r.matches == matches && r.ip == ip;
        // A target takes an address from one endpoint only: its frames
        // from that address must leave through the endpoint whose rule
        // steered the request in, which the most specific return match
        // then always names.
        let same_ip = |r: &SteerRule| r.matches as u8 == family && r.ip == ip;
        if self.rules.iter().flatten().any(|r| same_ip(r) && r.ep != ep && r.targets & targets != 0) {
            return Err(ctl::EEXIST);
        }
        let id = match self.rules.iter().position(|r| r.is_some_and(|r| r.ep == ep && same(&r))) {
            Some(id) => id,
            None => self.rules.iter().position(|r| r.is_none()).ok_or(ctl::ENOSPC)?,
        };
        self.post(Request::SteerSet { rule: id, ep: ep as usize, matches: matches as u64, ip_hi: ip.0, ip_lo: ip.1, targets })?;
        self.rules[id] = Some(SteerRule { ep, matches, ip, targets });
        Ok(id)
    }

    pub fn steer_del(&mut self, id: usize) -> Result<(), Errno> {
        self.rules.get(id).copied().flatten().ok_or(ctl::ENOENT)?;
        self.post(Request::SteerDel { rule: id })?;
        self.rules[id] = None;
        Ok(())
    }

    /// (inbound frames, return frames) of rule `id`, as netd published
    /// them.
    pub fn steer_stats(&self, id: usize) -> Option<(u64, u64)> {
        let [i, o] = self.published().rules.get(id)?.each_ref().map(|c| c.load(Ordering::Relaxed));
        Some((i, o))
    }
}
