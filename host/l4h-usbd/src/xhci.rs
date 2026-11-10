//! The xHCI controller: registers, the capability walk and handoff from
//! the firmware, halt, reset and start, the command ring and the event
//! ring (xHCI 1.2 §4, §5).  Every structure the controller fetches lives in
//! usbd's DMA region, laid out once here.

use core::sync::atomic::Ordering;

use l4h_rt::host::usb::{self as proto, MAX_SLOTS, Trb};
use l4h_virtio::{Mmio, dma_fence};

pub const PAGE: usize = 4096;

// Capability registers.
const CAPLENGTH: usize = 0x00;
const HCSPARAMS1: usize = 0x04;
const HCSPARAMS2: usize = 0x08;
const HCCPARAMS1: usize = 0x10;
const DBOFF: usize = 0x14;
const RTSOFF: usize = 0x18;

// Operational registers.
const USBCMD: usize = 0x00;
const USBSTS: usize = 0x04;
const CRCR: usize = 0x18;
const DCBAAP: usize = 0x30;
const CONFIG: usize = 0x38;
const PORTSC: usize = 0x400;

const CMD_RS: u32 = 1 << 0;
const CMD_HCRST: u32 = 1 << 1;
const CMD_INTE: u32 = 1 << 2;
const CMD_HSEE: u32 = 1 << 3;
const STS_HCH: u32 = 1 << 0;
pub const STS_HSE: u32 = 1 << 2;
const STS_EINT: u32 = 1 << 3;
const STS_CNR: u32 = 1 << 11;
pub const STS_HCE: u32 = 1 << 12;

// Interrupter 0, in the runtime registers.
const IR0: usize = 0x20;
const IMAN: usize = 0x00;
const IMOD: usize = 0x04;
const ERSTSZ: usize = 0x08;
const ERSTBA: usize = 0x10;
const ERDP: usize = 0x18;
const IMAN_IP: u32 = 1 << 0;
const IMAN_IE: u32 = 1 << 1;
const ERDP_EHB: u64 = 1 << 3;
/// 40 us, in 250 ns units: the guest cannot make the controller interrupt
/// more often.
const IMOD_40US: u32 = 160;

// TRB types of commands and events.
pub const CMD_ENABLE_SLOT: u32 = 9;
pub const CMD_DISABLE_SLOT: u32 = 10;
pub const CMD_ADDRESS_DEVICE: u32 = 11;
pub const CMD_CONFIGURE_EP: u32 = 12;
pub const CMD_EVALUATE_CTX: u32 = 13;
pub const CMD_RESET_EP: u32 = 14;
pub const CMD_STOP_EP: u32 = 15;
pub const CMD_SET_TR_DEQ: u32 = 16;
pub const CMD_RESET_DEVICE: u32 = 17;
pub const EV_TRANSFER: u32 = 32;
pub const EV_COMMAND: u32 = 33;
pub const EV_PORT: u32 = 34;
pub const EV_HOST: u32 = 37;

// Completion codes.
pub const CC_SUCCESS: u32 = 1;
pub const CC_BABBLE: u32 = 3;
pub const CC_TRANSACTION: u32 = 4;
pub const CC_TRB: u32 = 5;
pub const CC_STALL: u32 = 6;
pub const CC_RESOURCE: u32 = 7;
pub const CC_BANDWIDTH: u32 = 8;
pub const CC_NO_SLOTS: u32 = 9;
pub const CC_INVALID_STREAM_TYPE: u32 = 10;
pub const CC_SHORT_PACKET: u32 = 13;
pub const CC_RING_UNDERRUN: u32 = 14;
pub const CC_RING_OVERRUN: u32 = 15;
pub const CC_EVENT_RING_FULL: u32 = 21;
pub const CC_MISSED_SERVICE: u32 = 23;
pub const CC_STOPPED: u32 = 26;
pub const CC_STOPPED_LENGTH_INVALID: u32 = 27;
pub const CC_STOPPED_SHORT: u32 = 28;
pub const CC_INVALID_STREAM_ID: u32 = 34;

/// USBLEGCTLSTS: SMI enables cleared, the RW1C SMI events written back.
const LEGACY_DISABLE_SMI: u32 = (0x7 << 1) | (0xff << 5) | (0x7 << 17);
const LEGACY_SMI_EVENTS: u32 = 0x7 << 29;

/// Fixed DMA layout (offsets in the region), FIXED_BYTES in all.
const OFF_DCBAA: usize = 0;
const OFF_SCRATCH_ARRAY: usize = PAGE;
const OFF_ERST: usize = 3 * PAGE;
const OFF_CMD_RING: usize = 4 * PAGE;
const OFF_INPUT_CTX: usize = 5 * PAGE;
/// 64 KiB-aligned (the region is): an event ring segment may not cross a
/// 64 KiB boundary (xHCI 1.2 §6, Table 6-1).
const OFF_EVENT_RING: usize = 0x10000;
const _: () = assert!(OFF_INPUT_CTX + PAGE <= OFF_EVENT_RING && OFF_EVENT_RING % 0x10000 == 0);
const _: () = assert!(proto::EVENT_TRBS * 16 <= 0x10000 && OFF_EVENT_RING + proto::EVENT_TRBS * 16 <= proto::FIXED_BYTES);
const CMD_TRBS: usize = PAGE / 16;

/// Command timeout (xHCI drivers use 5 s).
const CMD_TIMEOUT_MS: u64 = 5000;

/// usbd's DMA region: virtual and physical bases.
#[derive(Clone, Copy)]
pub struct Region {
    pub va: usize,
    pub pa: u64,
    pub size: usize,
}

impl Region {
    pub fn va(&self, off: usize) -> usize {
        self.va + off
    }
    pub fn pa(&self, off: usize) -> u64 {
        self.pa + off as u64
    }
    /// Device context of slot s (one page each).
    pub fn out_ctx(&self, slot: u32) -> usize {
        proto::FIXED_BYTES + (slot as usize - 1) * PAGE
    }
    /// Transfer ring r of the pool.
    pub fn ring(&self, r: usize) -> usize {
        proto::FIXED_BYTES + MAX_SLOTS as usize * PAGE + r * proto::RING_BYTES
    }
    fn scratch(&self, page: usize) -> usize {
        self.ring(proto::USB_RINGS).next_multiple_of(page)
    }
}

/// A batch of events.
pub const EVENT_BATCH: usize = 64;
pub type Events = l4h_rt::host::fixed::ArrayVec<Trb, EVENT_BATCH>;

/// What the controller is: from its capability registers and extended
/// capabilities.
pub struct Caps {
    pub max_slots: u32,
    pub max_ports: u32,
    pub scratch: u32,
    pub page: usize,
    pub ctx_size: usize,
    pub ac64: bool,
    pub hci_version: u32,
    /// Isochronous Scheduling Threshold, in microframes; Contiguous Frame
    /// ID Capability (Frame IDs are used only with it, as Linux does).
    pub ist: u32,
    pub cfc: bool,
    /// Streams per endpoint usbd offers (a power of two, at most 16; 0:
    /// none).
    pub max_streams: u32,
    /// Major revision of each port (index = port number).
    pub port_proto: [u8; 256],
    pub usb2: u32,
    pub usb3: u32,
}

pub struct Xhci {
    pub base: Mmio,
    op: Mmio,
    rt: Mmio,
    db: Mmio,
    pub dma: Region,
    pub caps: Caps,
    legacy: Option<usize>,
    cmd_enq: usize,
    cmd_cycle: u32,
    ev_deq: usize,
    ev_cycle: u32,
    ticks_per_ms: u64,
    /// The controller failed (HSE, HCE, all-ones, a command timed out):
    /// it must be reset before it is used again.
    pub broken: bool,
}

/// The result of a command: (completion code, slot ID).
pub type CmdResult = (u32, u32);

impl Xhci {
    /// Read the capabilities (bounded walk of the extended list).
    pub fn new(bar: usize, bar_len: usize, dma: Region, tsc_hz: u64) -> Option<Self> {
        let base = Mmio(bar);
        // Capability registers read as dwords: some controllers (QEMU's)
        // answer nothing else.
        let cap0 = base.r32(CAPLENGTH);
        let caplen = (cap0 & 0xff) as usize;
        let hcs1 = base.r32(HCSPARAMS1);
        let hcs2 = base.r32(HCSPARAMS2);
        let hcc1 = base.r32(HCCPARAMS1);
        let (dboff, rtsoff) = (base.r32(DBOFF) as usize & !3, base.r32(RTSOFF) as usize & !0x1f);
        let max_ports = (hcs1 >> 24) & 0xff;
        if hcs1 == u32::MAX || caplen < 0x20 || dboff + 4 * 256 > bar_len || rtsoff + IR0 + 0x20 > bar_len
            || caplen + PORTSC + 0x10 * max_ports as usize > bar_len {
            return None;
        }
        let op = Mmio(bar + caplen);
        let pagesize = op.r32(0x08) & 0xffff;
        let page = PAGE << pagesize.trailing_zeros().min(4);
        let scratch = ((hcs2 >> 21) & 0x1f) << 5 | (hcs2 >> 27);
        let max_psa = (hcc1 >> 12) & 0xf;
        let mut caps = Caps {
            max_slots: (hcs1 & 0xff).min(MAX_SLOTS),
            max_ports,
            scratch,
            page,
            ctx_size: if hcc1 & (1 << 2) != 0 { 64 } else { 32 },
            ac64: hcc1 & 1 != 0,
            hci_version: cap0 >> 16,
            ist: if hcs2 & 8 != 0 { (hcs2 & 7) << 3 } else { hcs2 & 7 },
            cfc: hcc1 & (1 << 11) != 0,
            max_streams: if max_psa == 0 { 0 } else { (2u32 << max_psa).min(l4h_abi::usb::MAX_STREAMS) },
            port_proto: [0; 256],
            usb2: 0,
            usb3: 0,
        };
        if caps.max_slots == 0 || dma.pa & 0xffff != 0 || dma.scratch(page) + scratch as usize * page > dma.size {
            return None;
        }
        // Extended capabilities: a bounded walk inside BAR 0.
        let x = proto::xcaps(|o| base.r32(o), ((hcc1 >> 16) as usize) << 2, bar_len, max_ports);
        let legacy = x.legacy;
        caps.port_proto = x.port_proto;
        caps.usb2 = caps.port_proto.iter().filter(|&&p| p == 2).count() as u32;
        caps.usb3 = caps.port_proto.iter().filter(|&&p| p == 3).count() as u32;
        Some(Xhci {
            base, op, rt: Mmio(bar + rtsoff), db: Mmio(bar + dboff), dma, caps, legacy,
            cmd_enq: 0, cmd_cycle: 1, ev_deq: 0, ev_cycle: 1, ticks_per_ms: tsc_hz / 1000, broken: false,
        })
    }

    fn wait(&self, ms: u64, mut done: impl FnMut() -> bool) -> bool {
        let end = l4h_rt::host::ticks::now() + ms * self.ticks_per_ms;
        loop {
            if done() {
                return true;
            }
            if l4h_rt::host::ticks::now() > end {
                return done();
            }
            core::hint::spin_loop();
        }
    }

    fn delay_ms(&self, ms: u64) {
        self.wait(ms, || false);
    }

    pub fn sts(&self) -> u32 {
        self.op.r32(USBSTS)
    }

    /// Take the controller from the firmware (USB Legacy Support): OS
    /// Owned, then up to 1 s for BIOS Owned to clear, else clear it
    /// ourselves as Linux does; legacy SMIs off.  `force_timeout`: a test
    /// build's handoff that never completes.
    pub fn handoff(&self, force_timeout: bool) -> bool {
        let Some(off) = self.legacy else { return true };
        const BIOS_OWNED: u32 = 1 << 16;
        const OS_OWNED: u32 = 1 << 24;
        let v = self.base.r32(off);
        let mut clean = true;
        if v & BIOS_OWNED != 0 || force_timeout {
            self.base.w32(off, v | OS_OWNED);
            let ok = !force_timeout && self.wait(1000, || self.base.r32(off) & BIOS_OWNED == 0);
            if !ok {
                l4h_rt::log!("l4h-usbd: the firmware did not hand the controller over in 1 s; taking it");
                self.base.w32(off, (self.base.r32(off) & !BIOS_OWNED) | OS_OWNED);
                clean = false;
            }
        }
        let ctl = self.base.r32(off + 4);
        self.base.w32(off + 4, (ctl & LEGACY_DISABLE_SMI) | LEGACY_SMI_EVENTS);
        clean
    }

    /// Halt (HCH within 16 ms) and reset (HCRST, then CNR clear, within
    /// 1 s).  After this the controller fetches nothing.
    pub fn halt_reset(&mut self) -> bool {
        let cmd = self.op.r32(USBCMD);
        if cmd == u32::MAX {
            return false;
        }
        self.op.w32(USBCMD, cmd & !(CMD_RS | CMD_INTE | CMD_HSEE));
        if !self.wait(32, || self.sts() & STS_HCH != 0) {
            l4h_rt::log!("l4h-usbd: the controller did not halt");
            return false;
        }
        self.op.w32(USBCMD, CMD_HCRST);
        // Some Intel controllers hang if read during the first ms of a reset.
        self.delay_ms(1);
        let ok = self.wait(1000, || self.op.r32(USBCMD) & CMD_HCRST == 0 && self.sts() & STS_CNR == 0);
        if !ok {
            l4h_rt::log!("l4h-usbd: the controller did not reset");
        }
        self.broken = !ok;
        ok
    }

    /// Program the fixed structures and run: DCBAA (with the scratchpad),
    /// command ring, event ring, interrupter 0 with IMOD, then R/S.
    pub fn start(&mut self) -> bool {
        let d = self.dma;
        let c = &self.caps;
        unsafe {
            core::ptr::write_bytes(d.va as *mut u8, 0, proto::FIXED_BYTES);
            for s in 1..=c.max_slots {
                core::ptr::write_bytes(d.va(d.out_ctx(s)) as *mut u8, 0, PAGE);
            }
        }
        let dcbaa = Mmio(d.va(OFF_DCBAA));
        if c.scratch > 0 {
            let arr = Mmio(d.va(OFF_SCRATCH_ARRAY));
            let base = d.scratch(c.page);
            for i in 0..c.scratch as usize {
                arr.w64(8 * i, d.pa(base + i * c.page));
            }
            dcbaa.w64(0, d.pa(OFF_SCRATCH_ARRAY));
        }
        self.op.w32(CONFIG, (self.op.r32(CONFIG) & !0xff) | c.max_slots);
        self.op.w64(DCBAAP, d.pa(OFF_DCBAA));
        // Command ring: one segment, a Link TRB back to its start.
        self.cmd_enq = 0;
        self.cmd_cycle = 1;
        let link = Mmio(d.va(OFF_CMD_RING + (CMD_TRBS - 1) * 16));
        link.w64(0, d.pa(OFF_CMD_RING));
        link.w32(12, (proto::TRB_LINK << 10) | proto::TRB_TC);
        self.op.w64(CRCR, d.pa(OFF_CMD_RING) | 1);
        // Event ring: one segment.
        self.ev_deq = 0;
        self.ev_cycle = 1;
        let erst = Mmio(d.va(OFF_ERST));
        erst.w64(0, d.pa(OFF_EVENT_RING));
        erst.w32(8, proto::EVENT_TRBS as u32);
        let ir = Mmio(self.rt.0 + IR0);
        ir.w32(ERSTSZ, 1);
        ir.w64(ERDP, d.pa(OFF_EVENT_RING));
        ir.w64(ERSTBA, d.pa(OFF_ERST));
        ir.w32(IMOD, IMOD_40US);
        ir.w32(IMAN, IMAN_IE | IMAN_IP);
        dma_fence(Ordering::SeqCst);
        self.op.w32(USBCMD, CMD_RS | CMD_INTE | CMD_HSEE);
        let ok = self.wait(100, || self.sts() & STS_HCH == 0);
        self.broken = !ok;
        ok
    }

    pub fn portsc(&self, port: u32) -> u32 {
        self.op.r32(PORTSC + 0x10 * (port as usize - 1))
    }

    pub fn set_portsc(&self, port: u32, v: u32) {
        self.op.w32(PORTSC + 0x10 * (port as usize - 1), v);
    }

    pub fn mfindex(&self) -> u32 {
        self.rt.r32(0) & 0x3fff
    }

    /// DCBAA entry of slot s: its device context, or 0.
    pub fn set_dcbaa(&self, slot: u32, ctx: Option<u64>) {
        Mmio(self.dma.va(OFF_DCBAA)).w64(8 * slot as usize, ctx.unwrap_or(0));
    }

    /// The input context, zeroed: (va, pa).
    pub fn input_ctx(&self) -> (Mmio, u64) {
        unsafe { core::ptr::write_bytes(self.dma.va(OFF_INPUT_CTX) as *mut u8, 0, PAGE) };
        (Mmio(self.dma.va(OFF_INPUT_CTX)), self.dma.pa(OFF_INPUT_CTX))
    }

    pub fn ring_db(&self, slot: u32, target: u32) {
        dma_fence(Ordering::SeqCst);
        self.db.w32(4 * slot as usize, target);
    }

    /// Write a command and ring doorbell 0: the address its completion
    /// event names.  None if the controller is broken.
    pub fn submit_command(&mut self, trb: Trb) -> Option<u64> {
        if self.broken {
            return None;
        }
        let at = self.cmd_enq;
        let pa = self.dma.pa(OFF_CMD_RING + at * 16);
        let e = Mmio(self.dma.va(OFF_CMD_RING + at * 16));
        e.w64(0, trb.param);
        e.w32(8, trb.status);
        dma_fence(Ordering::Release);
        e.w32(12, (trb.control & !proto::TRB_CYCLE) | self.cmd_cycle);
        self.cmd_enq += 1;
        if self.cmd_enq == CMD_TRBS - 1 {
            let link = Mmio(self.dma.va(OFF_CMD_RING + (CMD_TRBS - 1) * 16));
            link.w32(12, (proto::TRB_LINK << 10) | proto::TRB_TC | self.cmd_cycle);
            self.cmd_cycle ^= 1;
            self.cmd_enq = 0;
        }
        self.ring_db(0, 0);
        Some(pa)
    }

    /// The deadline of a command submitted now, in ticks.
    pub fn command_deadline(&self) -> u64 {
        l4h_rt::host::ticks::now() + CMD_TIMEOUT_MS * self.ticks_per_ms
    }

    /// Take up to out's capacity of events off the event ring, then move
    /// the dequeue pointer and clear the interrupt.  Whether any came.
    pub fn take_events(&mut self, out: &mut Events) -> bool {
        out.clear();
        let mut any = false;
        while !out.is_full() {
            let e = Mmio(self.dma.va(OFF_EVENT_RING + self.ev_deq * 16));
            let control = e.r32(12);
            if control & 1 != self.ev_cycle {
                break;
            }
            dma_fence(Ordering::Acquire);
            let ev = Trb { param: e.r64(0), status: e.r32(8), control };
            self.ev_deq += 1;
            if self.ev_deq == proto::EVENT_TRBS {
                self.ev_deq = 0;
                self.ev_cycle ^= 1;
            }
            any = true;
            out.must_push(ev);
        }
        let ir = Mmio(self.rt.0 + IR0);
        if any {
            let v = self.dma.pa(OFF_EVENT_RING + self.ev_deq * 16) | ERDP_EHB;
            ir.w64(ERDP, v);
        }
        let iman = ir.r32(IMAN);
        if iman & IMAN_IP != 0 {
            ir.w32(IMAN, iman | IMAN_IP);
        }
        if self.op.r32(USBSTS) & STS_EINT != 0 {
            self.op.w32(USBSTS, STS_EINT);
        }
        any
    }
}
