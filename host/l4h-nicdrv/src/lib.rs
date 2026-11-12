//! The NIC driver SDK: everything a nicd (l4h_host::nicd, DESIGN.md §9.8)
//! has but its device code.  A driver implements `NicDriver` and declares
//! itself with `driver!`, which puts its manifest where root reads it and
//! runs `run`: the main loop, which owns the uplink channel
//! (l4h_host::uplink), root's mailbox, the interrupt and the receive
//! offload.
//!
//! The loop moves frames between the device and the channel:
//!
//! - receive: up to RX_BUDGET frames a turn straight into the channel's RX
//!   area, merged by GRO where they can be (netd checks them again).  A
//!   channel without room stops receiving: the frames wait in the device,
//!   which drops what does not fit, as a NIC whose host is slow does.
//! - transmit: frames netd queued, in order, while the device takes them.
//!   One it refuses stays in the channel, and the device's TX interrupt
//!   brings the loop back: the channel is the driver's backlog.
//!
//! A driver trusts netd (it is in the TCB), and nothing it does is trusted
//! by netd or root.  It may panic: root stops it, turns its device's bus
//! mastering off and may start a new instance (l4h-root's nicd.rs).

#![no_std]

mod driver;
pub use driver::*;
pub use l4h_rt;

use core::sync::atomic::{AtomicU64, Ordering};

use l4h_rt::host::{self, badges, net, uplink};
use l4h_rt::sel4;
use l4h_rt::{cap, Info};
use sel4::cap_type;

/// Frames taken from the device a turn, before the loop looks at netd's
/// frames and root's requests and comes back for the rest.
const RX_BUDGET: usize = 256;
/// Frames handed to the device a turn.
const TX_BUDGET: usize = 256;
/// How long a configuration-space request may wait for root.
const CFG_WAIT_MS: u64 = 1000;

static CFG_SEQ: AtomicU64 = AtomicU64::new(0);
/// Badges the loop received while it waited for root (cfg requests).
static HELD_BADGE: AtomicU64 = AtomicU64::new(0);

/// What goes through seL4 and root.
impl Hw {
    /// The device's legacy I/O ports, if root gave them.
    pub fn io_ports(&self) -> Option<l4h_rt::ioport::Ports> {
        (self.config.legacy_io != 0)
            .then(|| l4h_rt::ioport::Ports { cap: nicd::NICD_SLOT_IOPORT, base: self.config.legacy_io as u16 })
    }

    /// Read `size` bytes (1, 2 or 4) of configuration space at `offset`,
    /// now, through root.
    pub fn cfg_read(&self, offset: u16, size: u8) -> Result<u32, u64> {
        cfg_request(nicd::CFG_READ, offset, size, 0)
    }

    /// Write them, within the manifest's config_writes windows and outside
    /// root's deny list.
    pub fn cfg_write(&self, offset: u16, size: u8, value: u32) -> Result<(), u64> {
        cfg_request(nicd::CFG_WRITE, offset, size, value).map(|_| ())
    }
}

/// One configuration-space request, waited for: root answers it on its
/// loop, after which it signals our notification (badges::driver::CALL).
fn cfg_request(kind: u64, offset: u16, size: u8, value: u32) -> Result<u32, u64> {
    let p = l4h_rt::mailbox::published::<nicd::Published>();
    let seq = (CFG_SEQ.fetch_add(1, Ordering::Relaxed) + 1) as u32;
    p.cfg_value.store(value, Ordering::Relaxed);
    p.cfg_req.store(nicd::cfg_request(seq, kind, offset, size), Ordering::Release);
    l4h_rt::mailbox::signal();
    let ntfn = cap::<cap_type::Notification>(host::SLOT_NTFN);
    let mut expired = l4h_rt::timeout_ms(CFG_WAIT_MS);
    loop {
        let ans = p.cfg_ans.load(Ordering::Acquire);
        if (ans >> 32) as u32 == seq {
            return match ans & 0xffff_ffff {
                0 => Ok(p.cfg_ans_value.load(Ordering::Relaxed)),
                e => Err(e),
            };
        }
        if expired() {
            return Err(host::errno::EIO);
        }
        // Keep what else came for the loop.
        let (_, badge) = ntfn.poll();
        HELD_BADGE.fetch_or(badge & !badges::driver::CALL, Ordering::Relaxed);
        if badge & badges::driver::CALL != 0 {
            // A posted request too: the loop serves it.
            HELD_BADGE.fetch_or(badges::driver::CALL, Ordering::Relaxed);
        }
        core::hint::spin_loop();
    }
}

/// Counters the driver publishes (nicd::Published::counters).
fn count(i: usize, n: u64) {
    if n != 0 {
        l4h_rt::mailbox::published::<nicd::Published>().counters[i].fetch_add(n, Ordering::Relaxed);
    }
}

/// Write a status line for `l4hctl nic list`.
pub fn status(s: &str) {
    let p = l4h_rt::mailbox::published::<nicd::Published>();
    let b = s.as_bytes();
    for (i, w) in p.status.iter().enumerate() {
        let word = core::array::from_fn::<u8, 4, _>(|k| b.get(i * 4 + k).copied().unwrap_or(0));
        w.store(u32::from_le_bytes(word), Ordering::Relaxed);
    }
}

/// The receive offload's run, and a frame to hold while it flushes: too
/// large for the stack.
static mut GRO: core::mem::MaybeUninit<offload::Gro> = core::mem::MaybeUninit::uninit();
static mut SCRATCH: [u8; net::MAX_FRAME] = [0; net::MAX_FRAME];
static mut SEG: [u8; net::MAX_FRAME] = [0; net::MAX_FRAME];
static mut RX_W: uplink::Writer = uplink::Writer::new();
static mut TX_R: uplink::Reader = uplink::Reader::new();

/// The loop's state: the channel and its sides, and the driver once
/// started.
struct Loop<D> {
    hw: Hw,
    chan: uplink::Channel,
    rx: &'static mut uplink::Writer,
    tx: &'static mut uplink::Reader,
    gro: &'static mut offload::Gro,
    scratch: &'static mut [u8; net::MAX_FRAME],
    seg: &'static mut [u8; net::MAX_FRAME],
    dev: Option<D>,
    offer: Offer,
    /// Frames were received and not yet handed over (budget spent, or no
    /// room in the channel).
    rx_more: bool,
    rx_blocked: bool,
    /// The device refused a frame: its TX interrupt is on.
    tx_blocked: bool,
    stopped: bool,
    /// netd must be signalled at the end of this turn if it waits; and
    /// whatever it does (the link changed).
    signal_netd: bool,
    wake_netd: bool,
    link: u32,
}

impl<D: NicDriver> Loop<D> {
    /// Hand a received frame to netd: merged by GRO if it can be, else
    /// written to the channel.  The frame is in `scratch` (`len` bytes).
    /// netd takes coherent frames, and GSO frames whose segments are
    /// MIN_MSS at least (it cuts none smaller): the device's other GSO
    /// frames are segmented here, on the driver's own time.  False if the
    /// channel had no room.
    fn deliver(&mut self, len: usize, hdr: &mut [u8; HDR]) -> bool {
        let rx = self.chan.rx();
        let coherent = offload::sanitize_rx(hdr, &self.scratch[..len], offload::UPLINK_MIN_MSS);
        let mss = u16::from_le_bytes([hdr[4], hdr[5]]) as usize;
        if coherent && (!offload::is_gso(hdr) || mss >= offload::MIN_MSS) {
            if self.gro.add(&self.scratch[..len], hdr) {
                return true;
            }
            if !self.gro_flush() {
                return false;
            }
            if self.gro.add(&self.scratch[..len], hdr) {
                return true;
            }
            if !self.rx.write(&rx, &self.scratch[..len], hdr) {
                return false;
            }
            count(nicd::RX_FRAMES, 1);
            return true;
        }
        if !self.gro_flush() {
            return false;
        }
        if offload::is_gso(hdr) {
            let (w, mut wrote, mut lost) = (&mut *self.rx, 0, 0);
            offload::segment(&self.scratch[..len], hdr, &mut self.seg[..], |f, h| {
                if w.write(&rx, f, h) { wrote += 1 } else { lost += 1 }
            });
            count(nicd::RX_FRAMES, wrote);
            count(nicd::RX_DROPS, lost);
        } else {
            count(nicd::RX_DROPS, 1);
        }
        true
    }

    /// Write the GRO run into the channel: false (and the run kept) if it
    /// does not fit.
    fn gro_flush(&mut self) -> bool {
        let rx = self.chan.rx();
        let (w, mut ok) = (&mut *self.rx, true);
        let mut wrote = 0;
        let g = &mut *self.gro;
        if !g.pending() {
            return true;
        }
        if !w.fits(&rx, g.pending_len()) {
            return false;
        }
        g.flush(|f, h| {
            ok &= w.write(&rx, f, h);
            wrote += 1;
        });
        count(nicd::RX_FRAMES, wrote);
        if !ok {
            count(nicd::RX_DROPS, 1);
        }
        true
    }

    /// Take what the device received, RX_BUDGET frames at most.
    fn receive(&mut self) {
        let Some(dev) = self.dev.as_mut() else { return };
        let rx = self.chan.rx();
        dev.rx_begin();
        let mut budget = RX_BUDGET;
        let mut blocked = false;
        let more = loop {
            while budget != 0 {
                // Room for the largest frame and the run it may end, each
                // with the padding it may need, and for its segments.
                let need = self.gro.pending_len() + 3 * net::MAX_FRAME;
                if self.rx.free_bytes(&rx, 8) < need {
                    blocked = true;
                    break;
                }
                let mut hdr = [0u8; HDR];
                let dev = self.dev.as_mut().unwrap();
                let Some(len) = dev.receive(&mut self.scratch[..], &mut hdr) else { break };
                budget -= 1;
                let len = len.min(net::MAX_FRAME);
                if len < 14 {
                    count(nicd::RX_DROPS, 1);
                    continue;
                }
                if !self.deliver(len, &mut hdr) {
                    // Checked above: only a frame GRO could not take on
                    // top of a run that no longer fits.
                    count(nicd::RX_DROPS, 1);
                }
            }
            if !blocked && !self.gro_flush() {
                blocked = true;
            }
            // Blocked: the device's RX interrupt stays off until netd frees
            // room (its signal brings the loop back), else a device that
            // re-arms with completions waiting would interrupt at once.
            if blocked {
                break true;
            }
            let dev = self.dev.as_mut().unwrap();
            if dev.rx_done() {
                break false;
            }
            if budget == 0 {
                break true;
            }
        };
        self.rx_more = more;
        self.rx_blocked = blocked;
        if self.rx.pending(&rx) != 0 {
            self.signal_netd = true;
        }
        if blocked {
            // netd signals once it frees room, if it sees the flag.
            let w = &*self.rx;
            let need = self.gro.pending_len() + 3 * net::MAX_FRAME;
            if !uplink::arm(&self.chan.header().rx_full, || w.free_bytes(&rx, 8) >= need) {
                self.rx_blocked = false;
            }
        }
    }

    /// Hand netd's frames to the device while it takes them.
    fn transmit(&mut self) {
        let Some(dev) = self.dev.as_mut() else { return };
        let tx = self.chan.tx();
        let (mut sent, mut drops, mut freed) = (0u64, 0u64, false);
        let o = &self.offer;
        for _ in 0..TX_BUDGET {
            match self.tx.next(&tx) {
                uplink::Next::Frame(f, hdr) => {
                    let ok_len = (o.tx_frame_min as usize..=o.tx_frame_max as usize).contains(&f.len())
                        || (offload::is_gso(&hdr) && f.len() <= o.tx_gso_max as usize);
                    if ok_len && !dev.transmit(f, &hdr) {
                        // Completions may have come before the interrupt
                        // was on.
                        if dev.tx_interrupts(true) && dev.transmit(f, &hdr) {
                            dev.tx_interrupts(false);
                        } else {
                            self.tx_blocked = true;
                            break;
                        }
                    }
                    if ok_len { sent += 1 } else { drops += 1 }
                    self.tx.release(&tx);
                    freed = true;
                }
                uplink::Next::Dropped => {
                    drops += 1;
                    freed = true;
                }
                uplink::Next::Empty | uplink::Next::Broken => break,
            }
        }
        if !self.tx_blocked {
            dev.tx_interrupts(false);
        }
        dev.kick_tx();
        count(nicd::TX_FRAMES, sent);
        count(nicd::TX_DROPS, drops);
        if freed {
            self.signal_netd = true;
        }
    }

    fn publish_link(&mut self) {
        let Some(dev) = self.dev.as_ref() else { return };
        let l = dev.link().0;
        if l != self.link {
            self.link = l;
            self.chan.header().link_state.store(l, Ordering::Release);
            self.wake_netd = true;
        }
    }

    /// Signal netd if it waits for what this turn did.
    fn notify_netd(&mut self) {
        let mut wake = core::mem::take(&mut self.wake_netd);
        if core::mem::take(&mut self.signal_netd) {
            let h = self.chan.header();
            wake |= uplink::take_waiter(&h.rx_idle) | uplink::take_waiter(&h.tx_full);
        }
        if wake {
            l4h_rt::mailbox::notify(cap::<cap_type::Notification>(nicd::NICD_SLOT_NETD));
        }
    }

    /// Root's requests.
    fn serve(&mut self) {
        let mut cmds = Commands { l: self };
        if l4h_rt::mailbox::serve(|label, args, out| nicd::call::serve(&mut cmds, label, args, nicd::Sender::Root, out)) {
            l4h_rt::mailbox::signal();
        }
    }
}

struct Commands<'a, D> {
    l: &'a mut Loop<D>,
}

impl<D: NicDriver> nicd::call::Server for Commands<'_, D> {
    fn start(&mut self, _: nicd::Sender) -> Result<(), host::errno::Errno> {
        let l = &mut *self.l;
        if l.dev.is_some() || l.stopped {
            return Err(host::errno::EINVAL);
        }
        match D::start(&l.hw) {
            Ok(d) => {
                let offer = d.offer();
                let Some(checked) = offer.checked() else {
                    l4h_rt::log!("nicd {}: the driver's offer is out of bounds", l.hw.config.uplink);
                    return Err(host::errno::EIO);
                };
                l.offer = checked;
                l.chan.header().link_state.store(d.link().0, Ordering::Relaxed);
                l.link = d.link().0;
                l.chan.header().publish_offer(&offer);
                l.dev = Some(d);
                l.wake_netd = true;
                l.chan.header().rx_full.store(0, Ordering::Relaxed);
                // Frames may be waiting already.
                l.rx_more = true;
                Ok(())
            }
            Err(why) => {
                l4h_rt::log!("nicd {}: device refused: {}", l.hw.config.uplink, why);
                status(why);
                Err(host::errno::EIO)
            }
        }
    }

    fn stop(&mut self, _: nicd::Sender) -> Result<(), host::errno::Errno> {
        let l = &mut *self.l;
        if let Some(mut d) = l.dev.take() {
            d.stop();
        }
        l.stopped = true;
        Ok(())
    }

    fn ctl(&mut self, _: nicd::Sender, len: usize) -> Result<nicd::CtlDone, host::errno::Errno> {
        let l = &mut *self.l;
        let d = l.dev.as_mut().ok_or(host::errno::EINVAL)?;
        if len > nicd::CTL_MAX {
            return Err(host::errno::EINVAL);
        }
        // The request is root's copy of dom0's bytes: copy it out of the
        // page the answer goes into.
        let page = unsafe { &mut *(nicd::CTL_VA as *mut [u8; nicd::CTL_MAX]) };
        let mut req = [0u8; nicd::CTL_MAX];
        req[..len].copy_from_slice(&page[..len]);
        let n = d.ctl(&req[..len], &mut page[..]).ok_or(host::errno::ENOSYS)?;
        Ok(nicd::CtlDone { len: n.min(nicd::CTL_MAX) as u64 })
    }

    fn ping(&mut self, _: nicd::Sender) -> Result<(), host::errno::Errno> {
        Ok(())
    }

    fn test_panic(&mut self, _: nicd::Sender) -> Result<(), host::errno::Errno> {
        if host::TEST_INJECT {
            panic!("injected panic");
        }
        Err(host::errno::EINVAL)
    }

    fn test_hang(&mut self, _: nicd::Sender) -> Result<(), host::errno::Errno> {
        if host::TEST_INJECT {
            l4h_rt::test_hang();
        }
        Err(host::errno::EINVAL)
    }
}

/// The main loop of driver D.
pub fn run<D: NicDriver>(info: &'static Info) -> ! {
    let config: &'static Config = unsafe { info.config() };
    let hw = Hw { config, tsc_hz: info.header().tsc_hz };
    let bits = config.channel_bits.clamp(uplink::MIN_DATA_BITS, uplink::MAX_DATA_BITS);
    let chan = unsafe { uplink::Channel::new(nicd::CHANNEL_VA as *mut u8, bits) };
    let mut l: Loop<D> = Loop {
        hw,
        chan,
        rx: unsafe { &mut *core::ptr::addr_of_mut!(RX_W) },
        tx: unsafe { &mut *core::ptr::addr_of_mut!(TX_R) },
        gro: offload::Gro::init(unsafe { &mut *core::ptr::addr_of_mut!(GRO) }),
        scratch: unsafe { &mut *core::ptr::addr_of_mut!(SCRATCH) },
        seg: unsafe { &mut *core::ptr::addr_of_mut!(SEG) },
        dev: None,
        offer: Offer::default(),
        rx_more: false,
        rx_blocked: false,
        tx_blocked: false,
        stopped: false,
        signal_netd: false,
        wake_netd: false,
        link: 0,
    };
    let ntfn = cap::<cap_type::Notification>(host::SLOT_NTFN);
    let irq = cap::<cap_type::IrqHandler>(nicd::NICD_SLOT_IRQ);
    let mut badge = badges::driver::CALL;
    loop {
        badge |= HELD_BADGE.swap(0, Ordering::Relaxed);
        if badge & badges::driver::CALL != 0 {
            l.serve();
        }
        if l.dev.is_some() {
            let irq_seen = badge & badges::nicd::IRQ != 0;
            // netd freed room: receive again.
            if irq_seen || l.rx_more || (l.rx_blocked && badge & badges::nicd::NETD != 0) {
                l.receive();
            }
            // Frames netd queued (signalled or not: the budget may have
            // left some), or room the device made for a refused one.
            let tx = l.chan.tx();
            if badge & (badges::nicd::NETD | badges::nicd::IRQ) != 0 || l.tx_blocked || l.tx.has_next(&tx) {
                l.tx_blocked = false;
                l.transmit();
            }
            if badge & badges::nicd::TIMER != 0 {
                l.dev.as_mut().unwrap().timer();
            }
            l.publish_link();
            l.notify_netd();
            if irq_seen {
                let _ = irq.irq_handler_ack();
            }
        } else if badge & badges::nicd::IRQ != 0 {
            let _ = irq.irq_handler_ack();
        }
        // Sleep, unless work is left: frames netd queued, frames the
        // device has, root's requests.
        let tx = l.chan.tx();
        let busy = l.dev.is_some() && (l.rx_more && !l.rx_blocked || (!l.tx_blocked && l.tx.has_next(&tx)));
        badge = if busy || HELD_BADGE.load(Ordering::Relaxed) != 0 {
            ntfn.poll().1
        } else if l.dev.is_some() && !l.tx_blocked {
            let r = &*l.tx;
            if uplink::arm(&l.chan.header().tx_idle, || r.has_next(&tx)) { ntfn.wait().1 } else { ntfn.poll().1 }
        } else {
            ntfn.wait().1
        };
    }
}

/// Declare a driver: its manifest (in the section root reads) and its
/// component entry, with or without a heap (manifest heap_bits).
///
/// ```ignore
/// l4h_nicdrv::driver!(VirtioNet, MANIFEST);
/// ```
#[macro_export]
macro_rules! driver {
    ($ty:ty, $manifest:expr) => {
        #[used]
        #[unsafe(link_section = ".l4h.driver")]
        static __L4H_DRIVER_MANIFEST: $crate::Manifest = $manifest;

        fn __l4h_nicd_main(info: &'static $crate::l4h_rt::Info) -> ! {
            $crate::run::<$ty>(info)
        }
        $crate::l4h_rt::component!(__l4h_nicd_main, no_heap);
    };
}
