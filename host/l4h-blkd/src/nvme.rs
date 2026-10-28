//! NVMe PCI driver: one I/O queue pair, namespace 1.
//!
//! A request becomes one or more NVMe commands: pieces join a command as
//! long as they fit one PRP list (every piece but the first starts on a
//! page, every piece but the last ends on one).

use core::sync::atomic::Ordering;

use l4h_rt::host::blk::{self, BlkdConfig};
use l4h_rt::host::fixed::ArrayVec;
use l4h_virtio::{dma_fence, Dma, Mmio};

use crate::{DevInfo, Driver, MAX_PIECES, Seg};

const PAGE: u64 = 4096;

const REG_CAP: usize = 0x00;
const REG_CC: usize = 0x14;
const REG_CSTS: usize = 0x1c;
const REG_AQA: usize = 0x24;
const REG_ASQ: usize = 0x28;
const REG_ACQ: usize = 0x30;

const ADMIN_DEPTH: u16 = 16;
const IO_DEPTH: u16 = 256;
/// A command's PRP list fits in one page.
const MAX_CMD_PAGES: usize = 512;

const OP_FLUSH: u8 = 0x00;
const OP_WRITE: u8 = 0x01;
const OP_READ: u8 = 0x02;
const ADMIN_CREATE_SQ: u8 = 0x01;
const ADMIN_CREATE_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const ADMIN_SET_FEATURES: u8 = 0x09;

struct Sq {
    va: usize,
    depth: u16,
    tail: u16,
    doorbell: Mmio,
}

struct Cq {
    va: usize,
    depth: u16,
    head: u16,
    phase: u16,
    doorbell: Mmio,
}

#[derive(Default, Clone, Copy)]
struct Cmd {
    opcode: u8,
    cid: u16,
    nsid: u32,
    prp1: u64,
    prp2: u64,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
}

impl Sq {
    fn push(&mut self, c: &Cmd) {
        let e = Mmio(self.va + 64 * self.tail as usize);
        for i in 0..16 {
            e.w32(4 * i, 0);
        }
        e.w32(0, c.opcode as u32 | ((c.cid as u32) << 16));
        e.w32(4, c.nsid);
        e.w64(24, c.prp1);
        e.w64(32, c.prp2);
        e.w32(40, c.cdw10);
        e.w32(44, c.cdw11);
        e.w32(48, c.cdw12);
        self.tail = (self.tail + 1) % self.depth;
    }

    fn ring(&self) {
        dma_fence(Ordering::SeqCst);
        self.doorbell.w32(0, self.tail as u32);
    }
}

impl Cq {
    /// Next completion: (command id, status code; 0 = success).
    fn pop(&mut self) -> Option<(u16, u16)> {
        let e = Mmio(self.va + 16 * self.head as usize);
        let st = e.r16(14);
        if st & 1 != self.phase {
            return None;
        }
        dma_fence(Ordering::Acquire);
        let cid = e.r16(12);
        self.head += 1;
        if self.head == self.depth {
            self.head = 0;
            self.phase ^= 1;
        }
        Some((cid, st >> 1))
    }

    fn ring(&self) {
        self.doorbell.w32(0, self.head as u32);
    }
}

#[derive(Clone, Copy, Default)]
struct Request {
    tag: u64,
    pending: u32,
    status: u32,
}

pub struct Nvme {
    id: u32,
    io_errors: l4h_rt::ErrorLimit,
    asq: Sq,
    acq: Cq,
    sq: Sq,
    cq: Cq,
    ident: (usize, u64),
    /// Per command id (below the queue depth): the request it belongs to,
    /// its PRP list page, whether the device has it.
    cmd_req: [u16; IO_DEPTH as usize],
    prp: [(usize, u64); IO_DEPTH as usize],
    cid_busy: [bool; IO_DEPTH as usize],
    free_cids: ArrayVec<u16, { IO_DEPTH as usize }>,
    reqs: [Request; IO_DEPTH as usize],
    free_reqs: ArrayVec<u16, { IO_DEPTH as usize }>,
    lba_shift: u32,
    nsze: u64,
    max_bytes: u64,
    flush: bool,
}

fn spin_until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200_000_000u64 {
        if f() {
            return;
        }
        core::hint::spin_loop();
    }
    panic!("nvme: timeout waiting for {}", what);
}

impl Nvme {
    pub fn new(id: u32, cfg: &BlkdConfig) -> Self {
        let regs = Mmio(cfg.bar0.va as usize);
        let mut dma = Dma::new(cfg.dma_va as usize, cfg.dma_paddr, cfg.dma_size as usize);
        let cap = regs.r64(REG_CAP);
        let stride = 4usize << ((cap >> 32) & 0xf);
        let db = |i: usize| Mmio(regs.0 + 0x1000 + i * stride);

        // Reset, then set up the admin queues.
        regs.w32(REG_CC, regs.r32(REG_CC) & !1);
        spin_until("controller disable", || regs.r32(REG_CSTS) & 1 == 0);
        let (asq_va, asq_pa) = dma.alloc(64 * ADMIN_DEPTH as usize, 4096);
        let (acq_va, acq_pa) = dma.alloc(16 * ADMIN_DEPTH as usize, 4096);
        regs.w32(REG_AQA, ((ADMIN_DEPTH as u32 - 1) << 16) | (ADMIN_DEPTH as u32 - 1));
        regs.w64(REG_ASQ, asq_pa);
        regs.w64(REG_ACQ, acq_pa);
        // 64-byte SQ entries, 16-byte CQ entries, 4 KiB pages, NVM command set.
        regs.w32(REG_CC, (4 << 20) | (6 << 16) | 1);
        spin_until("controller ready", || regs.r32(REG_CSTS) & 3 != 0);
        if regs.r32(REG_CSTS) & 2 != 0 {
            panic!("nvme {:#x}: controller fatal status", id);
        }
        // MSI-X table entry 0 -> our interrupt, unmasked.
        let msix = Mmio(cfg.msix_table.va as usize);
        msix.w32(0, cfg.msi_address as u32);
        msix.w32(4, (cfg.msi_address >> 32) as u32);
        msix.w32(8, cfg.msi_data);
        msix.w32(12, 0);

        // CAP.MQES is zero-based: 0xffff means 65536 entries.
        let depth = (IO_DEPTH as u64).min((cap & 0xffff) + 1) as u16;
        let (sq_va, sq_pa) = dma.alloc(64 * depth as usize, 4096);
        let (cq_va, cq_pa) = dma.alloc(16 * depth as usize, 4096);
        let ident = dma.alloc(4096, 4096);
        let mut prp = [(0, 0); IO_DEPTH as usize];
        for p in &mut prp[..depth as usize] {
            *p = dma.alloc(4096, 4096);
        }
        // One cid stays free: a full SQ has tail == head - 1.
        let (mut free_cids, mut free_reqs) = (ArrayVec::new(), ArrayVec::new());
        for i in (0..depth).rev() {
            if i != depth - 1 {
                let _ = free_cids.push(i);
            }
            let _ = free_reqs.push(i);
        }
        let mut n = Nvme {
            id,
            io_errors: l4h_rt::ErrorLimit::new(),
            asq: Sq { va: asq_va, depth: ADMIN_DEPTH, tail: 0, doorbell: db(0) },
            acq: Cq { va: acq_va, depth: ADMIN_DEPTH, head: 0, phase: 1, doorbell: db(1) },
            sq: Sq { va: sq_va, depth, tail: 0, doorbell: db(2) },
            cq: Cq { va: cq_va, depth, head: 0, phase: 1, doorbell: db(3) },
            ident,
            cmd_req: [0; IO_DEPTH as usize],
            prp,
            cid_busy: [false; IO_DEPTH as usize],
            free_cids,
            reqs: [Request::default(); IO_DEPTH as usize],
            free_reqs,
            lba_shift: 9,
            nsze: 0,
            max_bytes: (MAX_CMD_PAGES as u64 - 1) * PAGE,
            flush: false,
        };

        // Identify controller: transfer limit, volatile write cache.
        n.admin(Cmd { opcode: ADMIN_IDENTIFY, prp1: n.ident.1, cdw10: 1, ..Default::default() });
        let id_ctrl = Mmio(n.ident.0);
        let mdts = id_ctrl.r8(77);
        if mdts != 0 {
            let mpsmin = 1u64 << (12 + ((cap >> 48) & 0xf));
            n.max_bytes = n.max_bytes.min(mpsmin << mdts);
        }
        n.flush = id_ctrl.r8(525) & 1 != 0;
        // Identify namespace 1: size and LBA format.
        n.admin(Cmd { opcode: ADMIN_IDENTIFY, nsid: 1, prp1: n.ident.1, cdw10: 0, ..Default::default() });
        let id_ns = Mmio(n.ident.0);
        n.nsze = id_ns.r64(0);
        let flbas = (id_ns.r8(26) & 0xf) as usize;
        n.lba_shift = id_ns.r8(128 + 4 * flbas + 2) as u32;
        if !(9..=12).contains(&n.lba_shift) {
            panic!("nvme {:#x}: unsupported LBA size 2^{}", id, n.lba_shift);
        }
        // One I/O queue pair on interrupt vector 0.
        n.admin(Cmd { opcode: ADMIN_SET_FEATURES, cdw10: 7, cdw11: 0, ..Default::default() });
        n.admin(Cmd {
            opcode: ADMIN_CREATE_CQ,
            prp1: cq_pa,
            cdw10: ((depth as u32 - 1) << 16) | 1,
            cdw11: (1 << 1) | 1,
            ..Default::default()
        });
        n.admin(Cmd {
            opcode: ADMIN_CREATE_SQ,
            prp1: sq_pa,
            cdw10: ((depth as u32 - 1) << 16) | 1,
            cdw11: (1 << 16) | 1,
            ..Default::default()
        });
        n
    }

    /// Run an admin command to completion (polled).
    fn admin(&mut self, mut c: Cmd) {
        c.cid = 0xffff;
        self.asq.push(&c);
        self.asq.ring();
        let mut res = None;
        spin_until("admin command", || {
            res = self.acq.pop();
            res.is_some()
        });
        self.acq.ring();
        let (_, status) = res.unwrap();
        if status != 0 {
            panic!("nvme {:#x}: admin command {:#x} failed: status {:#x}", self.id, c.opcode, status);
        }
    }

    /// Issue one I/O command for `pieces` (PRP-compatible) at `lba`.
    fn issue(&mut self, req: u16, opcode: u8, lba: u64, pieces: &[Seg]) -> Result<(), u32> {
        let bytes: u64 = pieces.iter().map(|p| p.len as u64).sum();
        if bytes & ((1 << self.lba_shift) - 1) != 0 {
            return Err(blk::STATUS_IOERR);
        }
        let cid = self.free_cids.pop().ok_or(blk::STATUS_IOERR)?;
        let (list_va, list_pa) = self.prp[cid as usize];
        // Page addresses after the first.
        let mut n = 0usize;
        let mut first = true;
        for p in pieces {
            let mut page = p.pa & !(PAGE - 1);
            let end = p.pa + p.len as u64;
            while page < end {
                if !first {
                    Mmio(list_va).w64(8 * n, page);
                    n += 1;
                }
                first = false;
                page += PAGE;
            }
        }
        let prp2 = match n {
            0 => 0,
            1 => Mmio(list_va).r64(0),
            _ => list_pa,
        };
        let nlb = (bytes >> self.lba_shift) as u32 - 1;
        self.sq.push(&Cmd {
            opcode,
            cid,
            nsid: 1,
            prp1: pieces[0].pa,
            prp2,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: nlb,
        });
        self.cmd_req[cid as usize] = req;
        self.cid_busy[cid as usize] = true;
        self.reqs[req as usize].pending += 1;
        Ok(())
    }
}

impl Driver for Nvme {
    fn units(&self) -> usize {
        1
    }

    fn info(&self, _unit: usize) -> DevInfo {
        DevInfo {
            capacity: self.nsze << (self.lba_shift - 9),
            block_size: 1 << self.lba_shift,
            read_only: false,
            flush: self.flush,
            address: 0,
        }
    }

    fn can_start(&self) -> bool {
        !self.free_reqs.is_empty() && self.free_cids.len() >= MAX_PIECES
    }

    fn start(&mut self, tag: u64, _unit: usize, op: u32, sector: u64, data: &[Seg]) -> Result<(), u32> {
        let r = self.free_reqs.pop().ok_or(blk::STATUS_IOERR)?;
        self.reqs[r as usize] = Request { tag, pending: 0, status: blk::STATUS_OK };
        let result = (|| {
            if op == blk::OP_FLUSH {
                return self.issue_flush(r);
            }
            let opcode = if op == blk::OP_READ { OP_READ } else { OP_WRITE };
            // Never round a sector down to the block holding it.
            if (sector << 9) & ((1 << self.lba_shift) - 1) != 0 {
                return Err(blk::STATUS_IOERR);
            }
            let mut lba = (sector << 9) >> self.lba_shift;
            // The pieces of the command being built.
            let mut cmd = [Seg { pa: 0, len: 0 }; MAX_PIECES];
            let (mut n, mut bytes, mut pages) = (0usize, 0u64, 0u64);
            for &p in data {
                let (mut pa, mut len) = (p.pa, p.len as u64);
                while len > 0 {
                    let joins = n == 0 || (pa % PAGE == 0 && (cmd[n - 1].pa + cmd[n - 1].len as u64) % PAGE == 0);
                    // Room left in the command, by bytes and by PRP entries;
                    // a partial piece must end on a page.  With every PRP
                    // entry used there is none: the piece starts a command.
                    let room = (self.max_bytes - bytes).min(((MAX_CMD_PAGES as u64 - pages) * PAGE).saturating_sub(pa % PAGE));
                    let mut take = len.min(room);
                    if take < len {
                        take = ((pa + take) & !(PAGE - 1)).saturating_sub(pa);
                    }
                    if !joins || take == 0 || n == MAX_PIECES {
                        self.issue(r, opcode, lba, &cmd[..n])?;
                        lba += bytes >> self.lba_shift;
                        (n, bytes, pages) = (0, 0, 0);
                        continue;
                    }
                    cmd[n] = Seg { pa, len: take as u32 };
                    n += 1;
                    bytes += take;
                    pages += (pa + take).div_ceil(PAGE) - pa / PAGE;
                    pa += take;
                    len -= take;
                }
            }
            self.issue(r, opcode, lba, &cmd[..n])
        })();
        match result {
            Ok(()) => Ok(()),
            Err(e) if self.reqs[r as usize].pending == 0 => {
                let _ = self.free_reqs.push(r);
                Err(e)
            }
            Err(e) => {
                // Commands already issued: complete the request with the
                // error once they are done.
                self.reqs[r as usize].status = e;
                Ok(())
            }
        }
    }

    fn kick(&mut self) {
        self.sq.ring();
    }

    fn reap(&mut self, done: &mut dyn FnMut(u64, u32)) {
        let mut any = false;
        while let Some((cid, status)) = self.cq.pop() {
            any = true;
            // Only a command the device has can complete: a cid it
            // completes twice, or never had, would go on the free list
            // twice and be issued for two commands at once.
            if !self.cid_busy.get(cid as usize).is_some_and(|&b| b) {
                continue;
            }
            self.cid_busy[cid as usize] = false;
            let _ = self.free_cids.push(cid);
            let r = self.cmd_req[cid as usize] as usize;
            let req = &mut self.reqs[r];
            if status != 0 {
                if self.io_errors.allow() {
                    l4h_rt::log!("nvme {:#x}: command {} failed: status {:#x}", self.id, cid, status);
                }
                req.status = blk::STATUS_IOERR;
            }
            req.pending -= 1;
            if req.pending == 0 {
                done(req.tag, req.status);
                let _ = self.free_reqs.push(r as u16);
            }
        }
        if any {
            self.cq.ring();
        }
    }
}

impl Nvme {
    fn issue_flush(&mut self, r: u16) -> Result<(), u32> {
        let cid = self.free_cids.pop().ok_or(blk::STATUS_IOERR)?;
        self.sq.push(&Cmd { opcode: OP_FLUSH, cid, nsid: 1, ..Default::default() });
        self.cmd_req[cid as usize] = r;
        self.cid_busy[cid as usize] = true;
        self.reqs[r as usize].pending += 1;
        Ok(())
    }
}
