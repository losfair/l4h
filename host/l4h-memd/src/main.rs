//! l4h-memd: the owner of the host's free memory and of every guest's RAM
//! (DESIGN.md §8.4).
//!
//! At boot, l4h-root moves every free RAM Untyped of 2 MiB or more here.
//! From then on it asks for memory for its own objects (`alloc`) and
//! returns it when it is free again (`free`), and guest RAM is taken,
//! given and revoked here: memd keeps the original Untyped of every 2 MiB
//! block of a guest, hands copies to l4h-root (for the boot blocks it
//! fills with frames) and to the guest, and revokes the originals when the
//! guest is destroyed, which deletes everything made of them.  memd also
//! reports free memory to the hypervisor l4h runs in (balloon.rs).
//!
//! Guest RAM also comes and goes while the guest runs, in hotplug blocks
//! of 128 MiB (DESIGN.md §8.5): l4h-vmmgr sets each guest's target, and the
//! guest's l4h-vmm asks to plug and unplug hotplug blocks, which memd
//! checks against the target and its own state only.
//!
//! memd serves l4h-root, l4h-vmmgr and the VMMs, one call at a time, and never calls
//! anyone.  Its calls, and who may make each, are declared in
//! l4h_host::memd::call; it implements their `Server` trait.  It cannot
//! read memory: every Untyped it has handed out has a child, so it
//! cannot retype it, and revoking it first makes seL4 clear the memory
//! before it is used again.
//!
//! memd has no heap: its state is the table l4h-root mapped (mem.rs) and
//! fixed arrays, so no request, however large, can exhaust it.

#![no_std]
#![no_main]

mod balloon;
mod exchange;
mod mem;

use l4h_rt::host::errno::Errno;
use l4h_rt::host::badges::memd as recv;
use l4h_rt::host::fixed::{ArrayVec, Scratch};
use l4h_rt::host::memd::{self, BalloonConfig, GuestHp, HpState, MemdConfig, Sender, Status, call, BLOCK_BITS, HP_MAP_WORDS, HP_MAX, MAX_GUESTS, XCHG_SLOTS};
use l4h_rt::host::wire::{self, Tail};
use l4h_rt::{Info, cap, host, sel4};
use sel4::{CapRights, cap_type};

use crate::balloon::Balloon;
use crate::mem::{List, Mem, State, abs};

use l4h_rt::host::errno::{EBUSY, EINVAL, ENODEV, ENOMEM, ENOSPC, check as errno};

/// 2 MiB blocks of a hotplug block, and the depth that names slot
/// (m, i) in a guest's hotplug CNode.
const HP_BLOCKS: usize = 1 << (l4h_abi::HP_SHIFT - BLOCK_BITS);
const HP_DEPTH: usize = l4h_abi::HP_L1_BITS + l4h_abi::HP_BITS;

/// How often the free page reports are made and polled.
const TICK_MS: u64 = 100;

/// A guest's RAM: its 2 MiB blocks, in order, on a list through the table.
#[derive(Clone, Copy)]
struct GuestRam {
    blocks: List,
    /// Radix of its block CNode.
    radix: usize,
    live: bool,
    hp: Hotplug,
}

/// A guest's hotplug region: its size, target and plugged hotplug blocks
/// (in hotplug blocks), and the token bucket that limits how fast it plugs
/// and unplugs, in thousandths of a hotplug block.
#[derive(Clone, Copy)]
struct Hotplug {
    count: usize,
    target: usize,
    plugged: usize,
    map: [u64; HP_MAP_WORDS],
    tokens: u64,
    last_ms: u64,
}

impl Hotplug {
    const EMPTY: Hotplug = Hotplug { count: 0, target: 0, plugged: 0, map: [0; HP_MAP_WORDS], tokens: 0, last_ms: 0 };

    fn is_plugged(&self, m: usize) -> bool {
        self.map[m / 64] & (1 << (m % 64)) != 0
    }

    /// Take a token for one plug or unplug at `now_ms`, if there is one.
    fn take_token(&mut self, now_ms: u64) -> bool {
        let refill = now_ms.saturating_sub(self.last_ms).saturating_mul(memd::HP_RATE);
        self.tokens = self.tokens.saturating_add(refill).min(memd::HP_BURST * 1000);
        self.last_ms = now_ms;
        if self.tokens < 1000 {
            return false;
        }
        self.tokens -= 1000;
        true
    }
}

/// The units of each plugged hotplug block, by guest and hotplug block:
/// the head of a list of its 64 blocks through the table.  Static: 128 KiB
/// would not fit on the stack.
static HP_HEADS: Scratch<[[u32; HP_MAX]; MAX_GUESTS]> = Scratch::new([[u32::MAX; HP_MAX]; MAX_GUESTS]);

struct Memd {
    mem: Mem,
    guests: [GuestRam; MAX_GUESTS],
    ticks_per_ms: u64,
}

/// Who calls for memory of its own: l4h-root, or l4h-vmmgr.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Client {
    Root,
    Vmmgr,
}

impl Client {
    /// The protocol lets only these make the calls that take a Client.
    fn of(from: Sender) -> Result<Client, Errno> {
        match from {
            Sender::Root => Ok(Client::Root),
            Sender::Vmmgr => Ok(Client::Vmmgr),
            Sender::Vmm(_) => Err(EINVAL),
        }
    }
}

/// The guest of a VMM's call.
fn vmm_guest(from: Sender) -> Result<usize, Errno> {
    match from {
        Sender::Vmm(g) => Ok(g),
        _ => Err(EINVAL),
    }
}

/// Slot `i` of the caller's exchange area (memd::call::XCHG): root's in
/// our CNode, vmmgr's the CNode we share with it.
fn area(c: Client, i: usize) -> sel4::AbsoluteCPtr {
    assert!(i < memd::XCHG_AREA);
    match c {
        Client::Root => abs(memd::SLOT_XCHG + i as u64),
        Client::Vmmgr => cap::<cap_type::CNode>(memd::SLOT_XCHG_CNODE).absolute_cptr_from_bits_with_depth(i as u64, memd::XCHG_RADIX),
    }
}

/// Where an `alloc` passes its n-th block to the caller.
fn granted(c: Client, n: usize) -> sel4::AbsoluteCPtr {
    area(c, call::caps::alloc::BLOCKS.passed_out(n, wire::Cap::Untyped))
}

/// Where a `free`'s caller passed its n-th block.
fn returned(c: Client, n: usize) -> sel4::AbsoluteCPtr {
    area(c, call::caps::free::BLOCKS.passed_in(n, wire::Cap::Untyped))
}

impl Memd {
    fn guest(&self, g: usize) -> Option<&GuestRam> {
        self.guests.get(g).filter(|r| r.live)
    }

    /// Block `b` of guest `g`: its unit.
    fn guest_block(&self, g: usize, b: usize) -> Option<u32> {
        self.guest(g).and_then(|r| self.mem.iter(r.blocks).nth(b))
    }

    fn guest_create(&mut self, g: usize, n: usize, radix: usize, hp_count: usize) -> u64 {
        if g >= MAX_GUESTS || self.guests[g].live || n == 0 || radix > 20 || n > 1 << radix || hp_count > HP_MAX {
            return EINVAL;
        }
        // The guest's CNodes, from vmmgr's exchange area.
        let (bcn, hcn) = (abs(memd::SLOT_GUEST_BCN + g as u64), abs(memd::SLOT_GUEST_HCN + g as u64));
        let _ = (bcn.delete(), hcn.delete());
        use call::caps::guest_create::{BLOCK_CNODE, HP_CNODE};
        if bcn.move_(&area(Client::Vmmgr, BLOCK_CNODE.passed_in(0, wire::Cap::CNode))).is_err()
            || hcn.move_(&area(Client::Vmmgr, HP_CNODE.passed_in(0, wire::Cap::CNode))).is_err()
        {
            return EINVAL;
        }
        let mut blocks = List::EMPTY;
        while blocks.len < n {
            match self.mem.take(0, State::Guest) {
                Some(i) => self.mem.add_guest(&mut blocks, i),
                None => {
                    while let Some(i) = self.mem.pop_guest(&mut blocks) {
                        self.mem.add(i, 0);
                    }
                    return ENOMEM;
                }
            }
        }
        let hp = Hotplug { count: hp_count, last_ms: self.now_ms(), tokens: memd::HP_BURST * 1000, ..Hotplug::EMPTY };
        self.guests[g] = GuestRam { blocks, radix, live: true, hp };
        0
    }

    fn now_ms(&self) -> u64 {
        host::ticks::now() / self.ticks_per_ms.max(1)
    }

    fn set_target(&mut self, g: usize, target: usize) -> u64 {
        let Some(r) = self.guests.get_mut(g).filter(|r| r.live) else { return EINVAL };
        r.hp.target = target.min(r.hp.count);
        0
    }

    /// `hp_plug` from guest g's VMM: hotplug block m.
    fn hp_plug(&mut self, g: usize, m: usize) -> u64 {
        let now = self.now_ms();
        let Some(r) = self.guests.get_mut(g).filter(|r| r.live) else { return EINVAL };
        if m >= r.hp.count || r.hp.is_plugged(m) {
            return EINVAL;
        }
        if r.hp.plugged >= r.hp.target {
            return ENOSPC;
        }
        // Only blocks that need no report to come back: the guest must not
        // hold memd waiting.
        if self.mem.available_bytes() < HP_BLOCKS << BLOCK_BITS || !r.hp.take_token(now) {
            return EBUSY;
        }
        let hcn = cap::<cap_type::CNode>(memd::SLOT_GUEST_HCN + g as u64);
        let mut blocks = List::EMPTY;
        let mut ok = true;
        for i in 0..HP_BLOCKS {
            let Some(u) = self.mem.take(0, State::Guest) else {
                ok = false;
                break;
            };
            self.mem.add_guest(&mut blocks, u);
            // Fails if the guest left no level-2 CNode in slot m, or put
            // something in this slot of it.
            let to = hcn.absolute_cptr_from_bits_with_depth(((m << l4h_abi::HP_BITS) | i) as u64, HP_DEPTH);
            if to.copy(&abs(self.mem.slot(u, 0)), CapRights::all()).is_err() {
                ok = false;
                break;
            }
        }
        if !ok {
            // Revoking deletes the copies already made.
            while let Some(u) = self.mem.pop_guest(&mut blocks) {
                abs(self.mem.slot(u, 0)).revoke().expect("memd: revoke failed plug");
                self.mem.add(u, 0);
            }
            return EINVAL;
        }
        let r = &mut self.guests[g];
        r.hp.map[m / 64] |= 1 << (m % 64);
        r.hp.plugged += 1;
        HP_HEADS.with(|h| h[g][m] = blocks.head());
        0
    }

    /// Revoke and free hotplug block m of guest g, which is plugged.  That
    /// deletes the guest's copies and everything it made of them.
    fn hp_free(&mut self, g: usize, m: usize) {
        let head = HP_HEADS.with(|h| core::mem::replace(&mut h[g][m], u32::MAX));
        let mut blocks = List::from_head(head);
        while let Some(u) = self.mem.pop_guest(&mut blocks) {
            abs(self.mem.slot(u, 0)).revoke().expect("memd: revoke hotplug block");
            self.mem.add(u, 0);
        }
        let r = &mut self.guests[g];
        r.hp.map[m / 64] &= !(1 << (m % 64));
        r.hp.plugged -= 1;
    }

    /// `hp_unplug` from guest g's VMM: hotplug block m.
    fn hp_unplug(&mut self, g: usize, m: usize) -> u64 {
        let now = self.now_ms();
        let Some(r) = self.guests.get_mut(g).filter(|r| r.live) else { return EINVAL };
        if m >= r.hp.count || !r.hp.is_plugged(m) {
            return EINVAL;
        }
        if !r.hp.take_token(now) {
            return EBUSY;
        }
        self.hp_free(g, m);
        0
    }

    /// `hp_state`: target, plugged and the bitmap.
    fn hp_state(&self, g: usize) -> Result<HpState, Errno> {
        let r = self.guest(g).ok_or(EINVAL)?;
        let map: [u64; HP_MAP_WORDS] = r.hp.map;
        Ok(HpState { target: r.hp.target as u64, plugged: r.hp.plugged as u64, map })
    }

    /// `guest_copy`: the block's physical address.
    fn guest_copy(&mut self, g: usize, b: usize) -> Result<u64, Errno> {
        let i = self.guest_block(g, b).ok_or(EINVAL)?;
        // Fails if the block already has a copy.
        let out = area(Client::Vmmgr, call::caps::guest_copy::BLOCK.passed_out(0, wire::Cap::Untyped));
        let _ = out.delete();
        if out.copy(&abs(self.mem.slot(i, 0)), CapRights::all()).is_err() {
            return Err(EINVAL);
        }
        Ok((i as u64) << BLOCK_BITS)
    }

    fn guest_give(&mut self, g: usize, first: usize, skip: usize) -> u64 {
        let Some(r) = self.guest(g) else { return EINVAL };
        if r.blocks.len + skip > 1 << r.radix {
            return EINVAL;
        }
        let bcn = cap::<cap_type::CNode>(memd::SLOT_GUEST_BCN + g as u64);
        for (b, i) in self.mem.iter(r.blocks).enumerate().skip(first) {
            // A block without children: its copy is a sibling Untyped
            // that the guest can retype and revoke, and revoking the
            // original still deletes everything made from either.
            let to = bcn.absolute_cptr_from_bits_with_depth((b + skip) as u64, r.radix);
            if to.copy(&abs(self.mem.slot(i, 0)), CapRights::all()).is_err() {
                return EINVAL;
            }
        }
        0
    }

    fn guest_destroy(&mut self, g: usize) -> u64 {
        if g >= MAX_GUESTS {
            return EINVAL;
        }
        if self.guests[g].live {
            for m in 0..self.guests[g].hp.count {
                if self.guests[g].hp.is_plugged(m) {
                    self.hp_free(g, m);
                }
            }
            let mut blocks = self.guests[g].blocks;
            while let Some(i) = self.mem.pop_guest(&mut blocks) {
                abs(self.mem.slot(i, 0)).revoke().expect("memd: revoke guest block");
                self.mem.add(i, 0);
            }
            self.guests[g].live = false;
        }
        let _ = abs(memd::SLOT_GUEST_BCN + g as u64).delete();
        let _ = abs(memd::SLOT_GUEST_HCN + g as u64).delete();
        self.guests[g].hp = Hotplug::EMPTY;
        0
    }

    fn balloon(&mut self, cfg: BalloonConfig) -> u64 {
        if self.mem.balloon.is_some() {
            return EINVAL;
        }
        self.mem.balloon = Balloon::new(&cfg, self.ticks_per_ms);
        if self.mem.balloon.is_none() {
            return ENODEV;
        }
        arm_timer(self.ticks_per_ms);
        0
    }

    fn write_status(&self) {
        let (blocks, largest) = self.mem.block_stats();
        let guest_blocks: usize = self.guests.iter().filter(|r| r.live).map(|r| r.blocks.len).sum();
        let plugged: usize = self.guests.iter().filter(|r| r.live).map(|r| r.hp.plugged * HP_BLOCKS).sum();
        let st = Status {
            free_bytes: self.mem.free_bytes() as u64,
            reported_bytes: self.mem.reported_bytes() as u64,
            free_blocks: blocks as u64,
            largest_block: largest as u64,
            guest_bytes: ((guest_blocks + plugged) << BLOCK_BITS) as u64,
            plugged_bytes: (plugged << BLOCK_BITS) as u64,
            hp: core::array::from_fn(|g| {
                let h = &self.guests[g].hp;
                GuestHp { target: h.target as u16, plugged: h.plugged as u16, count: h.count as u16, reserved: 0 }
            }),
        };
        unsafe { (memd::STATUS_VA as *mut Status).write_volatile(st) };
    }
}

fn arm_timer(ticks_per_ms: u64) {
    let tcb = cap::<cap_type::Tcb>(host::SLOT_TCB);
    let deadline = host::ticks::now() + TICK_MS * ticks_per_ms;
    sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_TCB_SetTimer(tcb.bits(), deadline, recv::TIMER));
}

fn main(info: &'static Info) -> ! {
    let cfg: &MemdConfig = unsafe { info.config() };
    let mut d = Memd {
        mem: Mem::new(cfg.units as usize),
        guests: [GuestRam { blocks: List::EMPTY, radix: 0, live: false, hp: Hotplug::EMPTY }; MAX_GUESTS],
        ticks_per_ms: info.header().tsc_hz / 1000,
    };
    d.write_status();
    let ep = cap::<cap_type::Endpoint>(host::SLOT_SERVICE_EP);
    let reply = cap::<cap_type::Reply>(host::SLOT_REPLY);

    l4h_rt::ipc::run(ep, reply, &mut d)
}

/// memd's thread: the calls, and its timer.
impl l4h_rt::ipc::Server for Memd {
    const SIGNALS: u64 = recv::SIGNALS;
    type Sender = Sender;

    /// The timer.
    fn signal(&mut self, _: u64) {
        let delay = balloon::REPORT_DELAY_MS * self.ticks_per_ms;
        self.mem.report_free(host::ticks::now(), delay);
        self.write_status();
        arm_timer(self.ticks_per_ms);
    }

    fn call(&mut self, from: Sender, _: u64, info: &sel4::MessageInfo) -> Option<sel4::MessageInfo> {
        let answer = l4h_rt::ipc::serve::<call::Proto>(info, |label, args, out| call::serve(self, label, args, from, out));
        self.write_status();
        answer
    }
}

/// The calls, as l4h_host::memd::call declares them.  Each may be made
/// only by the senders the declaration allows: `serve` refuses the others.
impl call::Server for Memd {
    fn alloc(&mut self, from: Sender, bits: usize, count: usize) -> Result<Tail<u64, XCHG_SLOTS>, Errno> {
        Memd::alloc(self, Client::of(from)?, bits, count).map(Tail)
    }

    fn free(&mut self, from: Sender, blocks: ArrayVec<(usize, usize), XCHG_SLOTS>) -> Result<(), Errno> {
        errno(Memd::free(self, Client::of(from)?, &blocks))
    }

    fn guest_create(&mut self, _: Sender, guest: usize, blocks: usize, radix: usize, hp_count: usize) -> Result<(), Errno> {
        errno(Memd::guest_create(self, guest, blocks, radix, hp_count))
    }

    fn guest_copy(&mut self, _: Sender, guest: usize, block: usize) -> Result<u64, Errno> {
        Memd::guest_copy(self, guest, block)
    }

    fn guest_give(&mut self, _: Sender, guest: usize, first: usize, skip: usize) -> Result<(), Errno> {
        errno(Memd::guest_give(self, guest, first, skip))
    }

    fn guest_destroy(&mut self, _: Sender, guest: usize) -> Result<(), Errno> {
        errno(Memd::guest_destroy(self, guest))
    }

    fn balloon(&mut self, _: Sender, cfg: BalloonConfig) -> Result<(), Errno> {
        errno(Memd::balloon(self, cfg))
    }

    fn set_target(&mut self, _: Sender, guest: usize, target: usize) -> Result<(), Errno> {
        errno(Memd::set_target(self, guest, target))
    }

    fn hp_plug(&mut self, from: Sender, m: usize) -> Result<(), Errno> {
        errno(Memd::hp_plug(self, vmm_guest(from)?, m))
    }

    fn hp_unplug(&mut self, from: Sender, m: usize) -> Result<(), Errno> {
        errno(Memd::hp_unplug(self, vmm_guest(from)?, m))
    }

    fn hp_state(&mut self, from: Sender) -> Result<HpState, Errno> {
        Memd::hp_state(self, vmm_guest(from)?)
    }
}

l4h_rt::component!(main, no_heap);
