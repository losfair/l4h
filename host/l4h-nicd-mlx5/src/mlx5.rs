//! ConnectX-5 firmware command transport (NVIDIA Ethernet PRM, command interface).
//! All firmware-visible storage belongs to the caller's IOMMU-mapped DMA arena.

use crate::sdk::{Frame, Hw, Offer};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::Ordering;
use l4h_virtio::{Dma, Mmio, dma_fence};
use l4h_rt::host::net::LinkState;

/// What the driver drives and needs (l4h_host::nicd::Manifest).
pub const MANIFEST: crate::sdk::Manifest = crate::sdk::Manifest {
    bars: 1 << 0,
    bar_window_bits: 24,
    msix_min: 1,
    dma_bits: 25,
    ..crate::sdk::Manifest::empty().with_name("mlx5").with_matches(&[crate::sdk::PciMatch::id(0x15b3, 0x1017)])
};

const HDR: usize = l4h_rt::host::net::HDR_SIZE;

const BLOCK: usize = 4096;
const BLOCKS: usize = 16;
const MAX_COMMAND: usize = 16 + BLOCKS * 512;

fn read32(p: usize) -> u32 {
    u32::from_be(unsafe { read_volatile(p as *const u32) })
}
fn write32(p: usize, v: u32) {
    unsafe { write_volatile(p as *mut u32, v.to_be()) }
}
fn write64(p: usize, v: u64) {
    write32(p, (v >> 32) as u32);
    write32(p + 4, v as u32);
}
fn xor(p: usize, len: usize) -> u8 {
    (0..len).fold(0, |sum, i| {
        sum ^ unsafe { read_volatile((p + i) as *const u8) }
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Timeout,
    InvalidLength,
    Delivery(u8),
    Firmware {
        opcode: u16,
        status: u8,
        syndrome: u32,
    },
    DmaExhausted,
    UnsupportedInterface,
    Poisoned,
    InvalidCompletion {
        opcode: u8,
        syndrome: u8,
    },
    InvalidUar,
    InvalidPageReturn,
}

/// One synchronous command slot. A timed-out slot cannot be reused: firmware
/// may still DMA into it. Recovery must reset the PCI function before unmapping.
struct Commands {
    regs: Mmio,
    entry: usize,
    input: (usize, u64),
    output: (usize, u64),
    token: u8,
    timeout_ticks: u64,
    poisoned: bool,
    firmware: (usize, u64),
    owned: [u64; FW_PAGES / 64],
}

fn put(b: &mut [u8], offset: usize, value: u32) {
    b[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn get(b: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(b[offset..offset + 4].try_into().unwrap())
}
fn address(b: &mut [u8], offset: usize, value: u64) {
    put(b, offset, (value >> 32) as u32);
    put(b, offset + 4, value as u32);
}
fn request<const N: usize>(opcode: u16) -> [u8; N] {
    let mut b = [0; N];
    b[..2].copy_from_slice(&opcode.to_be_bytes());
    b
}

const FW_PAGES: usize = (24 << 20) / 4096;
const QUEUE: usize = 64;
const BUFFER: usize = 2048;

struct Completion {
    ring: usize,
    db: usize,
    number: u32,
    consumer: u32,
    sequence: u32,
}

impl Completion {
    fn ready(&self) -> bool {
        let p = self.ring + (self.consumer as usize % QUEUE) * 64 + 63;
        let v = unsafe { read_volatile(p as *const u8) };
        v & 1 == ((self.consumer / QUEUE as u32) as u8 & 1)
    }
    fn pop(&mut self) -> Result<Option<(usize, usize)>, Error> {
        if !self.ready() {
            return Ok(None);
        }
        dma_fence(Ordering::Acquire);
        let p = self.ring + (self.consumer as usize % QUEUE) * 64;
        let opcode = (read32(p + 60) & 0xff) as u8 >> 4;
        let len = read32(p + 44) as usize;
        let slot = (read32(p + 60) >> 16) as usize % QUEUE;
        self.consumer = self.consumer.wrapping_add(1);
        write32(self.db, self.consumer & 0xffffff);
        if !matches!(opcode, 0 | 1 | 2) {
            return Err(Error::InvalidCompletion {
                opcode,
                syndrome: unsafe { read_volatile((p + 55) as *const u8) },
            });
        }
        Ok(Some((slot, len)))
    }
    fn arm(&mut self, uar: usize) {
        let v = (self.sequence & 3) << 28 | (self.consumer & 0xffffff);
        write32(self.db + 4, v);
        dma_fence(Ordering::Release);
        // A single 64-bit MMIO write preserves the CI/CQN doorbell pair.
        let bytes = ((v as u64) << 32 | self.number as u64).to_be();
        unsafe { write_volatile((uar + 0x20) as *mut u64, bytes) };
    }
}

/// Single-queue Ethernet data path. Checksum and segmentation remain in netd.
pub struct Mlx5 {
    commands: Commands,
    pub mac: [u8; 6],
    pub link: LinkState,
    uar: usize,
    eq: usize,
    eqn: u32,
    eq_consumer: u32,
    rx: Completion,
    tx: Completion,
    sq: usize,
    buffers_rx: (usize, u64),
    buffers_tx: (usize, u64),
    queue_db: usize,
    sqn: u32,
    #[cfg(not(target_os = "none"))]
    rqn: u32,
    #[cfg(not(target_os = "none"))]
    tir: u32,
    #[cfg(not(target_os = "none"))]
    table: u32,
    lkey: u32,
    rx_producer: u32,
    tx_producer: u32,
    tx_completed: u32,
    tx_kicked: u32,
    blueflame: usize,
}

impl Commands {
    fn new(regs: usize, dma: &mut Dma, hz: u64) -> Result<Self, Error> {
        let regs = Mmio(regs);
        let start = l4h_rt::host::ticks::now();
        while regs.r32(0x1fc).to_be() & (1 << 31) != 0 {
            if l4h_rt::host::ticks::now().wrapping_sub(start) > hz * 10 {
                return Err(Error::Timeout);
            }
            core::hint::spin_loop();
        }
        let config = regs.r32(0x14).to_be() & 0xfff;
        let stride = 1usize << (config & 15);
        let count = 1usize << ((config >> 4) & 15);
        if stride != 64 || count > 32 {
            return Err(Error::UnsupportedInterface);
        }
        if dma.remaining() < 4096 + 2 * BLOCKS * BLOCK + FW_PAGES * 4096 {
            return Err(Error::DmaExhausted);
        }
        let (entry, pa) = dma.alloc(4096, 4096);
        let input = dma.alloc(BLOCKS * BLOCK, 4096);
        let output = dma.alloc(BLOCKS * BLOCK, 4096);
        let firmware = dma.alloc(FW_PAGES * 4096, 4096);
        regs.w32(0x10, ((pa >> 32) as u32).to_be());
        dma_fence(Ordering::Release);
        // Low geometry bits describe the interface on reads, but must be zero
        // on address writes. Echoing them breaks firmware mailbox processing.
        regs.w32(0x14, (pa as u32).to_be());
        Ok(Self {
            regs,
            entry,
            input,
            output,
            token: 0,
            timeout_ticks: hz * 10,
            poisoned: false,
            firmware,
            owned: [0; FW_PAGES / 64],
        })
    }

    fn mailboxes(base: (usize, u64), len: usize, token: u8) {
        let count = len.saturating_sub(16).div_ceil(512);
        unsafe { core::ptr::write_bytes(base.0 as *mut u8, 0, count * BLOCK) };
        for i in 0..count {
            let b = base.0 + i * BLOCK;
            write32(b + 0x238, i as u32);
            write32(b + 0x23c, (token as u32) << 16);
            if i + 1 < count {
                write64(b + 0x230, base.1 + ((i + 1) * BLOCK) as u64);
            }
        }
    }

    fn execute(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if input.len() < 16
            || output.len() < 16
            || input.len() > MAX_COMMAND
            || output.len() > MAX_COMMAND
        {
            return Err(Error::InvalidLength);
        }
        self.token = 0;
        unsafe { core::ptr::write_bytes((self.entry + 0x10) as *mut u8, 0, 32) };
        Self::mailboxes(self.input, input.len(), self.token);
        Self::mailboxes(self.output, output.len(), self.token);
        for (i, &v) in input.iter().enumerate() {
            let p = if i < 16 {
                self.entry + 0x10 + i
            } else {
                self.input.0 + (i - 16) / 512 * BLOCK + (i - 16) % 512
            };
            unsafe { write_volatile(p as *mut u8, v) };
        }
        write32(self.entry, 7 << 24);
        write32(self.entry + 4, input.len() as u32);
        write64(self.entry + 8, self.input.1);
        write64(self.entry + 0x30, self.output.1);
        write32(self.entry + 0x38, output.len() as u32);
        write32(self.entry + 0x3c, (self.token as u32) << 24);
        for (base, len) in [(self.input.0, input.len()), (self.output.0, output.len())] {
            for i in 0..len.saturating_sub(16).div_ceil(512) {
                let p = base + i * BLOCK;
                unsafe {
                    write_volatile((p + 574) as *mut u8, !xor(p + 512, 62));
                }
                unsafe {
                    write_volatile((p + 575) as *mut u8, !xor(p, 575));
                }
            }
        }
        unsafe {
            write_volatile((self.entry + 61) as *mut u8, !(xor(self.entry, 64) ^ 1));
        }
        dma_fence(Ordering::SeqCst);
        unsafe {
            write_volatile((self.entry + 63) as *mut u8, 1);
        }
        dma_fence(Ordering::Release);
        self.regs.w32(0x18, 1u32.to_be());
        let start = l4h_rt::host::ticks::now();
        while read32(self.entry + 0x3c) & 1 != 0 {
            if l4h_rt::host::ticks::now().wrapping_sub(start) > self.timeout_ticks {
                self.poisoned = true;
                return Err(Error::Timeout);
            }
            core::hint::spin_loop();
        }
        dma_fence(Ordering::Acquire);
        let delivery = ((read32(self.entry + 0x3c) >> 1) & 0x7f) as u8;
        if delivery != 0 {
            return Err(Error::Delivery(delivery));
        }
        for (i, v) in output.iter_mut().enumerate() {
            let p = if i < 16 {
                self.entry + 0x20 + i
            } else {
                self.output.0 + (i - 16) / 512 * BLOCK + (i - 16) % 512
            };
            *v = unsafe { read_volatile(p as *const u8) };
        }
        if output[0] != 0 {
            return Err(Error::Firmware {
                opcode: u16::from_be_bytes(input[..2].try_into().unwrap()),
                status: output[0],
                syndrome: get(output, 4),
            });
        }
        Ok(())
    }

    fn command(&mut self, opcode: u16, opmod: u16, output: &mut [u8]) -> Result<(), Error> {
        let mut input = request::<16>(opcode);
        input[6..8].copy_from_slice(&opmod.to_be_bytes());
        self.execute(&input, output)
    }

    fn give_pages(&mut self, kind: u16) -> Result<usize, Error> {
        let mut out = [0u8; 16];
        self.command(0x107, kind, &mut out)?;
        let function = get(&out, 8);
        let count = get(&out, 12) as i32;
        l4h_rt::info!(
            "mlx5 page request kind={} function={:x} pages={}",
            kind,
            function,
            count
        );
        if count <= 0 {
            return Ok(0);
        }
        self.give_count(function, count as usize)
    }

    fn give_count(&mut self, function: u32, count: usize) -> Result<usize, Error> {
        let mut out = [0u8; 16];
        if function != 0 {
            return Err(Error::UnsupportedInterface);
        }
        if count
            > FW_PAGES
                - self
                    .owned
                    .iter()
                    .map(|v| v.count_ones() as usize)
                    .sum::<usize>()
        {
            return Err(Error::DmaExhausted);
        }
        let mut left = count;
        while left > 0 {
            let n = left.min(512);
            let mut input = request::<4112>(0x108);
            input[6..8].copy_from_slice(&1u16.to_be_bytes());
            put(&mut input, 8, function);
            put(&mut input, 12, n as u32);
            for i in 0..n {
                let word = self
                    .owned
                    .iter()
                    .position(|v| *v != u64::MAX)
                    .ok_or(Error::DmaExhausted)?;
                let bit = self.owned[word].trailing_ones() as usize;
                self.owned[word] |= 1 << bit;
                let index = word * 64 + bit;
                let va = self.firmware.0 + index * 4096;
                let pa = self.firmware.1 + (index * 4096) as u64;
                unsafe { core::ptr::write_bytes(va as *mut u8, 0, 4096) };
                address(&mut input, 16 + i * 8, pa);
            }
            self.execute(&input[..16 + n * 8], &mut out)?;
            left -= n;
        }
        Ok(count)
    }

    fn reclaim_pages(&mut self, function: u32, count: usize) -> Result<(), Error> {
        if function != 0 {
            return Err(Error::UnsupportedInterface);
        }
        let mut left = count;
        while left != 0 {
            let available = self
                .owned
                .iter()
                .map(|v| v.count_ones() as usize)
                .sum::<usize>();
            let n = left.min(512).min(available);
            if n == 0 {
                break;
            }
            let mut input = request::<16>(0x108);
            input[6..8].copy_from_slice(&2u16.to_be_bytes());
            put(&mut input, 8, function);
            put(&mut input, 12, n as u32);
            let mut output = [0u8; 4112];
            self.execute(&input, &mut output[..16 + n * 8])?;
            let returned = get(&output, 8) as usize;
            // Firmware can return fewer pages than requested, including zero.
            // This event requests reclamation. It does not promise that many free pages.
            if returned == 0 {
                break;
            }
            if returned > n {
                return Err(Error::InvalidPageReturn);
            }
            for i in 0..returned {
                let pa =
                    ((get(&output, 16 + i * 8) as u64) << 32) | get(&output, 20 + i * 8) as u64;
                let offset = pa
                    .checked_sub(self.firmware.1)
                    .ok_or(Error::InvalidPageReturn)?;
                if offset % 4096 != 0 || offset >= (FW_PAGES * 4096) as u64 {
                    return Err(Error::InvalidPageReturn);
                }
                let index = offset as usize / 4096;
                let mask = 1 << (index % 64);
                if self.owned[index / 64] & mask == 0 {
                    return Err(Error::InvalidPageReturn);
                }
                self.owned[index / 64] &= !mask;
            }
            left -= returned;
        }
        Ok(())
    }

    fn submit(&mut self, input: &[u8]) -> Result<u32, Error> {
        let mut out = [0u8; 16];
        self.execute(input, &mut out)?;
        Ok(get(&out, 8) & 0xffffff)
    }

    fn completion(&mut self, dma: &mut Dma, uar: u32, eqn: u32) -> Result<Completion, Error> {
        let (ring, pa) = dma.alloc(4096, 4096);
        let (db, db_pa) = dma.alloc(64, 64);
        unsafe { core::ptr::write_bytes(ring as *mut u8, 0xff, 4096) };
        let mut b = request::<0x118>(0x400);
        put(&mut b, 0x10, 1 << 17);
        put(&mut b, 0x1c, 6 << 24 | uar);
        put(&mut b, 0x24, eqn);
        address(&mut b, 0x48, db_pa);
        address(&mut b, 0x110, pa);
        let number = self.submit(&b)?;
        Ok(Completion {
            ring,
            db,
            number,
            consumer: 0,
            sequence: 0,
        })
    }
}

impl Mlx5 {
    /// No offloads; the device sends frames of 14..=1518 bytes.
    pub fn offer(&self) -> Offer {
        let mut o = Offer::plain(self.mac);
        o.tx_frame_max = 1518;
        o
    }

    /// Bring the device up; Err if the firmware refuses a command.
    pub fn new(hw: &Hw) -> Result<Self, &'static str> {
        let (cfg, hz) = (hw.config, hw.tsc_hz);
        let n = cfg.uplink;
        let table = Mmio(cfg.msix_table.va as usize);
        for entry in 0..(cfg.msix_table.len / 16) as usize {
            table.w32(entry * 16 + 12, 1);
        }
        table.w32(0, cfg.msi_address as u32);
        table.w32(4, (cfg.msi_address >> 32) as u32);
        table.w32(8, cfg.msi_data);
        table.w32(12, 0);
        let dma = hw.dma();
        let nic = match Self::open(cfg.bars[0].va as usize, cfg.bars[0].len as usize, dma, hz) {
            Ok(nic) => nic,
            Err(e) => {
                l4h_rt::log!("nicd {}: mlx5 initialization failed: {:?}", n, e);
                return Err("mlx5 initialization failed");
            }
        };
        l4h_rt::info!("nicd {}: mlx5 MAC {:02x?}", n, nic.mac);
        Ok(nic)
    }

    pub fn open(regs: usize, regs_len: usize, mut dma: Dma, hz: u64) -> Result<Self, Error> {
        let mut c = Commands::new(regs, &mut dma, hz)?;
        let mut out = [0u8; 16];
        c.command(0x104, 0, &mut out)?;
        let mut issi = request::<16>(0x10b);
        put(&mut issi, 8, 1);
        c.execute(&issi, &mut out)?;
        let mut query_issi = [0u8; 0x70];
        c.command(0x10a, 0, &mut query_issi)?;
        l4h_rt::info!(
            "mlx5 ISSI current={} supported={:x}",
            get(&query_issi, 8),
            get(&query_issi, 0x6c)
        );
        c.give_pages(1)?;
        let mut caps = [0u8; 0x1010];
        c.command(0x100, 0, &mut caps)?;
        c.command(0x100, 1, &mut caps)?;
        let mut endian = request::<32>(0x805);
        put(&mut endian, 8, 0x7004);
        let mut endian_out = [0u8; 32];
        c.execute(&endian, &mut endian_out)?;
        caps[..16].fill(0);
        caps[..2].copy_from_slice(&0x109u16.to_be_bytes());
        let flags = get(&caps, 0x50) & !(3 << 14);
        put(&mut caps, 0x50, flags);
        c.submit(&caps)?;
        c.give_pages(2)?;
        c.submit(&request::<16>(0x102))?;
        let uar_page = c.submit(&request::<16>(0x802))?;
        if (uar_page as usize + 1) * 4096 > regs_len {
            return Err(Error::InvalidUar);
        }
        let uar = regs + uar_page as usize * 4096;
        let (eq, eq_pa) = dma.alloc(4096, 4096);
        for i in 0..QUEUE {
            write32(eq + i * 64 + 60, 1);
        }
        let mut b = request::<0x118>(0x301);
        put(&mut b, 0x10, 1 << 17);
        put(&mut b, 0x1c, 6 << 24 | uar_page);
        put(&mut b, 0x24, 0); // MSI-X entry 0.
        put(&mut b, 0x5c, (1 << 4) | (1 << 9) | (1 << 11));
        address(&mut b, 0x110, eq_pa);
        let eqn = c.submit(&b)? & 255;
        let mut context = [0u8; 0x110];
        c.command(0x754, 0, &mut context)?;
        let mac: [u8; 6] = context[0x106..0x10c].try_into().unwrap();
        let mut b = request::<0x208>(0x755);
        put(&mut b, 12, 4);
        put(&mut b, 0x1f0, 1);
        b[0x202..0x208].copy_from_slice(&mac);
        c.submit(&b)?;
        let mut b = request::<0x200>(0x755);
        // Do not return transmitted broadcasts to the software switch: that
        // would relearn a guest's source MAC on the physical uplink.
        put(&mut b, 12, 0xc10);
        put(&mut b, 0x100, 6); // Disable multicast and unicast local loopback.
        put(&mut b, 0x1f0, 1 << 29);
        c.submit(&b)?;
        c.command(0x754, 0, &mut context)?;

        c.command(0x203, 0, &mut out)?;
        let lkey = get(&out, 12);
        let pd = c.submit(&request::<16>(0x800))?;
        let td = c.submit(&request::<16>(0x816))?;
        let rx = c.completion(&mut dma, uar_page, eqn)?;
        let tx = c.completion(&mut dma, uar_page, eqn)?;
        let (queue_db, db_pa) = dma.alloc(64, 64);
        let (rq, rq_pa) = dma.alloc(4096, 4096);
        let (sq, sq_pa) = dma.alloc(4096, 4096);
        let buffers_rx = dma.alloc(QUEUE * BUFFER, 4096);
        let buffers_tx = dma.alloc(QUEUE * BUFFER, 4096);
        let mut b = request::<0x118>(0x908);
        put(&mut b, 0x20, (1 << 31) | (1 << 28));
        put(&mut b, 0x28, rx.number);
        put(&mut b, 0x50, 1 << 28);
        put(&mut b, 0x58, pd);
        address(&mut b, 0x60, db_pa);
        put(&mut b, 0x70, 4 << 16 | 6);
        address(&mut b, 0x110, rq_pa);
        let rqn = c.submit(&b)?;
        let mut b = request::<0x118>(0x909);
        put(&mut b, 8, rqn);
        put(&mut b, 0x20, 1 << 20);
        c.submit(&b)?;
        let mut b = request::<0x110>(0x900);
        put(&mut b, 0x3c, rqn);
        put(&mut b, 0x44, td);
        let tir = c.submit(&b)?;
        let mut b = request::<0xc0>(0x912);
        put(&mut b, 0x44, td);
        let tis = c.submit(&b)?;
        let mut b = request::<0x118>(0x904);
        put(&mut b, 0x20, (1 << 31) | (1 << 29) | (1 << 28) | (1 << 24));
        put(&mut b, 0x28, tx.number);
        put(&mut b, 0x40, 1 << 16);
        put(&mut b, 0x4c, tis);
        put(&mut b, 0x50, 1 << 28);
        put(&mut b, 0x58, pd);
        put(&mut b, 0x5c, uar_page);
        address(&mut b, 0x60, db_pa);
        put(&mut b, 0x70, 6 << 16 | 6);
        address(&mut b, 0x110, sq_pa);
        let sqn = c.submit(&b)?;
        let mut b = request::<0x118>(0x905);
        put(&mut b, 8, sqn);
        put(&mut b, 0x20, 1 << 20);
        c.submit(&b)?;
        let mut b = request::<0x40>(0x930);
        put(&mut b, 0x18, 0);
        let table = c.submit(&b)?;
        let mut b = request::<0x400>(0x933);
        put(&mut b, 0x14, table);
        let group = c.submit(&b)?;
        let mut b = request::<0x348>(0x936);
        put(&mut b, 0x14, table);
        put(&mut b, 0x44, group);
        put(&mut b, 0x4c, 4);
        put(&mut b, 0x50, 1);
        put(&mut b, 0x340, 2 << 24 | tir);
        c.submit(&b)?;
        let mut b = request::<0x40>(0x92f);
        put(&mut b, 0x14, table);
        c.submit(&b)?;
        for i in 0..QUEUE {
            write32(rq + i * 16, BUFFER as u32);
            write32(rq + i * 16 + 4, lkey);
            write64(rq + i * 16 + 8, buffers_rx.1 + (i * BUFFER) as u64);
        }
        dma_fence(Ordering::Release);
        write32(queue_db, QUEUE as u32);
        let mut nic = Self {
            commands: c,
            mac,
            link: LinkState::DOWN,
            uar,
            eq,
            eqn,
            eq_consumer: 0,
            rx,
            tx,
            sq,
            buffers_rx,
            buffers_tx,
            queue_db,
            sqn,
            #[cfg(not(target_os = "none"))]
            rqn,
            #[cfg(not(target_os = "none"))]
            tir,
            #[cfg(not(target_os = "none"))]
            table,
            lkey,
            rx_producer: QUEUE as u32,
            tx_producer: 0,
            tx_completed: 0,
            tx_kicked: 0,
            blueflame: 0,
        };
        nic.refresh_link()?;
        nic.arm();
        Ok(nic)
    }

    fn refresh_link(&mut self) -> Result<(), Error> {
        let mut state = [0u8; 16];
        self.commands.command(0x750, 0, &mut state)?;
        if state[15] & 15 != 1 {
            self.link = LinkState::DOWN;
            return Ok(());
        }
        // ACCESS_REG, PTYS, Ethernet, local port 1 of this function.
        // Layout: Linux mlx5_ifc.h (PTYS register and QUERY_VPORT_STATE).
        let mut input = request::<0x50>(0x805);
        input[7] = 1;
        put(&mut input, 8, 0x5004);
        input[0x11] = 1;
        input[0x13] = 4;
        let mut output = [0u8; 0x50];
        self.commands.execute(&input, &mut output)?;
        let legacy = get(&output, 0x34);
        let extended = get(&output, 0x30);
        let legacy_speeds = [1000, 1000, 10000, 10000, 10000, 20000, 40000, 40000,
            56000, 0, 0, 0, 10000, 10000, 10000, 40000, 40000, 0, 50000, 0,
            100000, 100000, 100000, 100000, 100, 1000, 10000, 25000, 25000, 25000, 50000, 50000];
        let ext_speeds = [100, 1000, 0, 5000, 10000, 40000, 25000, 50000, 50000,
            100000, 100000, 200000, 400000, 100000, 200000, 400000, 800000,
            200000, 400000, 800000];
        let speed = if legacy.count_ones() == 1 {
            legacy_speeds[legacy.trailing_zeros() as usize]
        } else if extended.count_ones() == 1 {
            ext_speeds.get(extended.trailing_zeros() as usize).copied().unwrap_or(0)
        } else { 0 };
        self.link = LinkState::ethernet(true, speed);
        l4h_rt::info!("mlx5 link up speed={} Mbps", speed);
        Ok(())
    }

    fn arm(&mut self) {
        self.rx.arm(self.uar);
        self.tx.arm(self.uar);
        dma_fence(Ordering::Release);
        write32(
            self.uar + 0x40,
            self.eqn << 24 | (self.eq_consumer & 0xffffff),
        );
    }

    pub fn poll_events(&mut self) -> Result<usize, Error> {
        let mut count = 0;
        while count < QUEUE {
            let p = self.eq + (self.eq_consumer as usize % QUEUE) * 64;
            if read32(p + 60) & 1 != (self.eq_consumer / QUEUE as u32) & 1 {
                break;
            }
            dma_fence(Ordering::Acquire);
            let event = (read32(p) >> 16) & 255;
            if event == 0 {
                let cqn = read32(p + 56) & 0xffffff;
                if cqn == self.rx.number {
                    self.rx.sequence = self.rx.sequence.wrapping_add(1);
                }
                if cqn == self.tx.number {
                    self.tx.sequence = self.tx.sequence.wrapping_add(1);
                }
            } else if event == 9 {
                self.refresh_link()?;
            } else if event == 11 {
                // Page-request events are serviced before rearming the EQ.
                let function = read32(p + 32) & 0xffff;
                let count = read32(p + 36) as i32;
                l4h_rt::info!("mlx5 async pages function={} count={}", function, count);
                if count > 0 {
                    self.commands.give_count(function, count as usize)?;
                } else if count < 0 {
                    self.commands
                        .reclaim_pages(function, count.unsigned_abs() as usize)?;
                }
            } else if event == 4 {
                return Err(Error::InvalidCompletion {
                    opcode: 0xff,
                    syndrome: 4,
                });
            }
            self.eq_consumer = self.eq_consumer.wrapping_add(1);
            count += 1;
        }
        write32(
            self.uar + 0x48,
            self.eqn << 24 | (self.eq_consumer & 0xffffff),
        );
        Ok(count)
    }

    pub fn receive(&mut self, out: &mut [u8], hdr: &mut [u8; 12]) -> Option<usize> {
        let (slot, len) = self.rx.pop().expect("mlx5 RX completion")?;
        assert!(len <= BUFFER && len <= out.len(), "mlx5 oversized receive");
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.buffers_rx.0 + slot * BUFFER) as *const u8,
                out.as_mut_ptr(),
                len,
            )
        };
        hdr.fill(0);
        self.rx_producer = self.rx_producer.wrapping_add(1);
        dma_fence(Ordering::Release);
        write32(self.queue_db, self.rx_producer & 0xffff);
        Some(len)
    }

    fn reclaim(&mut self) {
        while self.tx.pop().expect("mlx5 TX completion").is_some() {
            self.tx_completed = self.tx_completed.wrapping_add(1);
        }
    }

    pub fn transmit(&mut self, frame: &(impl Frame + ?Sized), _hdr: &[u8; 12]) -> bool {
        self.reclaim();
        if self.tx_producer.wrapping_sub(self.tx_completed) >= QUEUE as u32 {
            return false;
        }
        assert!((14..=1518).contains(&frame.len()), "mlx5 frame size");
        let wire_len = frame.len().max(60);
        let slot = self.tx_producer as usize % QUEUE;
        let p = self.sq + slot * 64;
        unsafe {
            core::ptr::write_bytes(p as *mut u8, 0, 64);
        }
        write32(p, (self.tx_producer & 0xffff) << 8 | 0xa);
        write32(p + 4, self.sqn << 8 | 4);
        write32(p + 8, 2 << 2);
        unsafe {
            write_volatile((p + 28) as *mut u16, 16u16.to_be());
        }
        let buf = self.buffers_tx.0 + slot * BUFFER;
        let data = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, wire_len) };
        data.fill(0);
        frame.copy_to(&mut data[..frame.len()]);
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), (p + 30) as *mut u8, 16);
        }
        write32(p + 48, (wire_len - 16) as u32);
        write32(p + 52, self.lkey);
        write64(p + 56, self.buffers_tx.1 + (slot * BUFFER + 16) as u64);
        self.tx_producer = self.tx_producer.wrapping_add(1);
        true
    }

    pub fn kick_tx(&mut self) {
        if self.tx_kicked == self.tx_producer {
            return;
        }
        dma_fence(Ordering::Release);
        write32(self.queue_db + 4, self.tx_producer & 0xffff);
        dma_fence(Ordering::Release);
        let p = self.sq + ((self.tx_producer.wrapping_sub(1) as usize) % QUEUE) * 64;
        let value = unsafe { read_volatile(p as *const u64) };
        unsafe {
            write_volatile((self.uar + 0x800 + self.blueflame) as *mut u64, value);
        }
        self.blueflame ^= 0x100;
        self.tx_kicked = self.tx_producer;
    }
    pub fn rx_begin(&mut self) {
        self.poll_events().expect("mlx5 events");
    }
    pub fn rx_done(&mut self) -> bool {
        self.arm();
        dma_fence(Ordering::SeqCst);
        !self.rx.ready()
    }
    pub fn tx_interrupts(&mut self, _waiting: bool) -> bool {
        self.reclaim();
        self.arm();
        self.tx_producer.wrapping_sub(self.tx_completed) < QUEUE as u32
    }
    #[cfg(not(target_os = "none"))]
    pub fn completed_tx(&mut self) -> u32 {
        self.reclaim();
        self.tx_completed
    }

    /// Hardware self-test only: enable PF-local packet loopback without
    /// changing the physical port or the sibling function's configuration.
    #[cfg(not(target_os = "none"))]
    pub fn set_local_loopback(&mut self, enabled: bool) -> Result<(), Error> {
        let mut b = request::<0x200>(0x755);
        put(&mut b, 12, 0xc10);
        put(&mut b, 0x1f0, 1 << 29);
        put(&mut b, 0x100, if enabled { 0 } else { 6 });
        self.commands.submit(&b)?;
        let mut b = request::<0x110>(0x901);
        put(&mut b, 8, self.tir);
        put(&mut b, 0x14, 1 << 4);
        put(&mut b, 0x44, if enabled { 1 << 24 } else { 0 });
        self.commands.submit(&b)?;
        Ok(())
    }

    #[cfg(not(target_os = "none"))]
    pub fn diagnostics(&mut self) {
        l4h_rt::info!(
            "mlx5 firmware pages owned={} capacity={}",
            self.commands
                .owned
                .iter()
                .map(|v| v.count_ones() as usize)
                .sum::<usize>(),
            FW_PAGES
        );
        let mut context = [0u8; 0x110];
        let mut b = request::<16>(0x903);
        put(&mut b, 8, self.tir);
        let result = self.commands.execute(&b, &mut context);
        l4h_rt::info!(
            "mlx5 TIR {} {:?}: rqn={:x} td/lb={:x}",
            self.tir,
            result,
            get(&context, 0x3c),
            get(&context, 0x44)
        );
        self.commands.command(0x754, 0, &mut context).unwrap();
        l4h_rt::info!(
            "mlx5 vport flags={:x} mtu={} promisc={:x}",
            get(&context, 0x10),
            get(&context, 0x34),
            get(&context, 0x100)
        );
        let mut b = request::<0x40>(0x937);
        put(&mut b, 0x14, self.table);
        let mut fte = [0u8; 0x348];
        let result = self.commands.execute(&b, &mut fte);
        l4h_rt::info!(
            "mlx5 FTE {} {:?}: action={} count={} destination={:x}",
            self.table,
            result,
            get(&fte, 0x4c),
            get(&fte, 0x50),
            get(&fte, 0x340)
        );
        let mut b = request::<16>(0x90b);
        put(&mut b, 8, self.rqn);
        let mut rq = [0u8; 0x118];
        let result = self.commands.execute(&b, &mut rq);
        l4h_rt::info!(
            "mlx5 RQ {} {:?}: state={:x} hw={} sw={} dbr={:x}/{:x}",
            self.rqn,
            result,
            get(&rq, 0x20),
            get(&rq, 0x68),
            get(&rq, 0x6c),
            get(&rq, 0x60),
            get(&rq, 0x64)
        );
    }
}

/// The SDK's view of the driver (l4h_nicdrv::NicDriver).
impl crate::sdk::NicDriver for Mlx5 {
    fn start(hw: &Hw) -> Result<Self, &'static str> {
        Mlx5::new(hw)
    }
    fn offer(&self) -> Offer {
        Mlx5::offer(self)
    }
    fn rx_begin(&mut self) {
        Mlx5::rx_begin(self)
    }
    fn rx_done(&mut self) -> bool {
        Mlx5::rx_done(self)
    }
    fn receive(&mut self, out: &mut [u8], hdr: &mut [u8; HDR]) -> Option<usize> {
        Mlx5::receive(self, out, hdr)
    }
    fn transmit(&mut self, frame: &[u8], hdr: &[u8; HDR]) -> bool {
        Mlx5::transmit(self, frame, hdr)
    }
    fn tx_interrupts(&mut self, on: bool) -> bool {
        Mlx5::tx_interrupts(self, on)
    }
    fn kick_tx(&mut self) {
        Mlx5::kick_tx(self)
    }
    fn link(&self) -> LinkState {
        self.link
    }
}
