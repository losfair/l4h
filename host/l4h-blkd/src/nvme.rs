//! NVMe PCI driver: one I/O queue pair shared by the controller's namespaces.
//!
//! A request becomes one or more NVMe commands: pieces join a command as
//! long as they fit one PRP list (every piece but the first starts on a
//! page, every piece but the last ends on one).  A request is started only
//! with a command id for each of its commands, so none fails part way.

use core::sync::atomic::Ordering;

use l4h_rt::host::blk::{self, BlkdConfig};
use l4h_rt::host::fixed::ArrayVec;
use l4h_virtio::{dma_fence, Dma, Mmio};

use crate::{DevInfo, Driver, MAX_PIECES, MAX_REQUEST, Seg};

mod namespaces;

const PAGE: u64 = 4096;

const REG_CAP: usize = 0x00;
const REG_VS: usize = 0x08;
const REG_CC: usize = 0x14;
const REG_CSTS: usize = 0x1c;
const REG_AQA: usize = 0x24;
const REG_ASQ: usize = 0x28;
const REG_ACQ: usize = 0x30;

const ADMIN_DEPTH: u16 = 16;
/// I/O queue entries, at most: with an 8 KiB transfer limit a request of
/// MAX_REQUEST needs 544 commands.
const IO_DEPTH: u16 = 1024;
/// Requests in flight.
const MAX_REQS: usize = 256;
/// A command's PRP list fits in one page.
const MAX_CMD_PAGES: usize = 512;
/// The PRP lists: one slice per command id, sized for the transfer limit.
const PRP_BYTES: usize = 1 << 20;

const OP_FLUSH: u8 = 0x00;
const OP_WRITE: u8 = 0x01;
const OP_READ: u8 = 0x02;
const OP_WRITE_ZEROES: u8 = 0x08;
const OP_DATASET_MANAGEMENT: u8 = 0x09;
const DSM_DEALLOCATE: u32 = 1 << 2;
const ONCS_DSM: u16 = 1 << 2;
const ONCS_WRITE_ZEROES: u16 = 1 << 3;
/// Write Zeroes CDW12: deallocate the blocks (they read zero all the same).
const WZ_DEAC: u32 = 1 << 25;
/// A Write Zeroes covers at most 2^16 blocks (NLB is 16 bits).
const WZ_MAX_BLOCKS: u64 = 1 << 16;
/// Write Zeroes commands one request may take: a request is started only
/// with a command id for each (can_start keeps max_cmds free).
const WZ_MAX_CMDS: u64 = 64;
const ADMIN_CREATE_SQ: u8 = 0x01;
const ADMIN_CREATE_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const ADMIN_SET_FEATURES: u8 = 0x09;
const IDENTIFY_NAMESPACE: u32 = 0;
const IDENTIFY_CONTROLLER: u32 = 1;
const IDENTIFY_ACTIVE_NAMESPACES: u32 = 2;
/// The I/O command set specific controller data (NVMe 2.0), for CSI 0 (NVM).
const IDENTIFY_CONTROLLER_NVM: u32 = 6;

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

#[derive(Clone, Copy)]
struct Namespace {
    id: u32,
    lba_shift: u32,
    blocks: u64,
    /// Write Zeroes may deallocate: the namespace says deallocated blocks
    /// read zero and Write Zeroes may deallocate them (DLFEAT).
    deac: bool,
    /// Write Zeroes is used: no end-to-end protection information, whose
    /// fields it would have to set.
    write_zeroes: bool,
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
    /// whether the device has it.  Its PRP list is at `prp` + id * prp_len.
    cmd_req: [u16; IO_DEPTH as usize],
    cid_busy: [bool; IO_DEPTH as usize],
    free_cids: ArrayVec<u16, { IO_DEPTH as usize }>,
    prp: (usize, u64),
    prp_len: usize,
    reqs: [Request; MAX_REQS],
    free_reqs: ArrayVec<u16, MAX_REQS>,
    namespaces: ArrayVec<Namespace, { blk::MAX_UNITS }>,
    max_bytes: u64,
    /// Pages a command may span: its PRP list has one entry fewer.
    cmd_pages: u64,
    /// Command ids a request of up to MAX_REQUEST bytes needs.
    max_cmds: usize,
    flush: bool,
    discard: bool,
    /// The most bytes one Write Zeroes may cover (0: the controller has
    /// none).
    write_zeroes_bytes: u64,
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
        // CAP.DSTRD is the device's: its four doorbells must be in BAR 0.
        if 0x1000 + 4 * stride > cfg.bar0.len as usize {
            panic!("nvme {:#x}: doorbell stride {} beyond BAR 0", id, stride);
        }
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
        let prp = dma.alloc(PRP_BYTES, 4096);
        let mut free_reqs = ArrayVec::new();
        for i in (0..MAX_REQS as u16).rev() {
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
            cid_busy: [false; IO_DEPTH as usize],
            free_cids: ArrayVec::new(),
            prp,
            prp_len: 0,
            reqs: [Request::default(); MAX_REQS],
            free_reqs,
            namespaces: ArrayVec::new(),
            max_bytes: (MAX_CMD_PAGES as u64 - 1) * PAGE,
            cmd_pages: 0,
            max_cmds: 0,
            flush: false,
            discard: false,
            write_zeroes_bytes: 0,
        };

        // Identify controller: transfer limit, volatile write cache.
        n.admin(Cmd { opcode: ADMIN_IDENTIFY, prp1: n.ident.1, cdw10: IDENTIFY_CONTROLLER, ..Default::default() });
        let id_ctrl = Mmio(n.ident.0);
        let mdts = id_ctrl.r8(77);
        // MDTS (the device's) in units of 2^(12 + CAP.MPSMIN): from 2^64 on, no limit.
        let mps_shift = 12 + ((cap >> 48) & 0xf) as u32;
        let mdts_shift = mps_shift + mdts as u32;
        if mdts != 0 && mdts_shift < 64 {
            n.max_bytes = n.max_bytes.min(1 << mdts_shift);
        }
        n.flush = id_ctrl.r8(525) & 1 != 0;
        n.discard = id_ctrl.r16(520) & ONCS_DSM != 0;
        let write_zeroes = id_ctrl.r16(520) & ONCS_WRITE_ZEROES != 0;
        let (version, max_nsid) = (regs.r32(REG_VS), id_ctrl.r32(516));
        if write_zeroes {
            // As Linux: Write Zeroes within MDTS, unless the controller
            // states its own limit (WZSL, in the same units).
            let mut shift = if mdts != 0 && mdts_shift < 64 { Some(mdts_shift) } else { None };
            if version >= 0x0002_0000 {
                let status = n.admin_status(Cmd {
                    opcode: ADMIN_IDENTIFY, prp1: n.ident.1, cdw10: IDENTIFY_CONTROLLER_NVM, ..Default::default()
                });
                let wzsl = Mmio(n.ident.0).r8(1);
                if status == 0 && wzsl != 0 && mps_shift + (wzsl as u32) < 64 {
                    shift = Some(mps_shift + wzsl as u32);
                }
            }
            n.write_zeroes_bytes = shift.map_or(u64::MAX, |s| 1 << s);
        }
        // A command that starts mid-page spans one page more than it fills
        // (max_bytes is whole pages, at least two).
        let entries = (n.max_bytes / PAGE) as usize;
        n.prp_len = (8 * entries).next_power_of_two();
        n.cmd_pages = entries as u64 + 1;
        // One cid stays free: a full SQ has tail == head - 1.
        let cids = (depth as usize - 1).min(PRP_BYTES / n.prp_len);
        for i in (0..cids as u16).rev() {
            let _ = n.free_cids.push(i);
        }
        // Every piece may start a command and end one cut short (it starts
        // or ends mid-page); the other commands carry max_bytes each.
        let need = 2 * MAX_PIECES + (MAX_REQUEST / n.max_bytes) as usize;
        n.max_cmds = need.min(cids);
        if need > cids {
            l4h_rt::log!("nvme {:#x}: {} command ids for up to {} per request: large requests may fail", id, cids, need);
        }
        n.discover_namespaces(version, max_nsid);
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

    fn discover_namespaces(&mut self, version: u32, max_nsid: u32) {
        let data = Mmio(self.ident.0);
        let ids = namespaces::ids(version, max_nsid, || {
            let status = self.admin_status(Cmd {
                opcode: ADMIN_IDENTIFY, prp1: self.ident.1, cdw10: IDENTIFY_ACTIVE_NAMESPACES, ..Default::default()
            });
            (status == 0).then_some((0..blk::MAX_UNITS).map(|i| data.r32(4 * i)))
        });
        for &id in &ids {
            let status = self.admin_status(Cmd {
                opcode: ADMIN_IDENTIFY, nsid: id, prp1: self.ident.1, cdw10: IDENTIFY_NAMESPACE, ..Default::default()
            });
            if status != 0 {
                l4h_rt::log!("nvme {:#x}: namespace {} identify failed: status {:#x}", self.id, id, status);
                continue;
            }
            let blocks = data.r64(0);
            if blocks == 0 {
                continue;
            }
            let flbas = (data.r8(26) & 0xf) as usize;
            let lba_shift = data.r8(128 + 4 * flbas + 2) as u32;
            if !(9..=12).contains(&lba_shift) {
                l4h_rt::log!("nvme {:#x}: namespace {} has unsupported LBA size 2^{}", self.id, id, lba_shift);
                continue;
            }
            // DLFEAT: bits 2:0 001b, deallocated blocks read zero; bit 3,
            // Write Zeroes may deallocate.  DPS: protection information.
            let dlfeat = data.r8(33);
            let deac = dlfeat & 0x7 == 1 && dlfeat & (1 << 3) != 0;
            let write_zeroes = data.r8(29) & 0x7 == 0;
            let _ = self.namespaces.push(Namespace { id, lba_shift, blocks, deac, write_zeroes });
        }
        l4h_rt::info!("nvme {:#x}: version {:#x}, {} namespaces found", self.id, version, self.namespaces.len());
    }

    fn admin(&mut self, c: Cmd) {
        let status = self.admin_status(c);
        if status != 0 {
            panic!("nvme {:#x}: admin command {:#x} failed: status {:#x}", self.id, c.opcode, status);
        }
    }

    /// Run an admin command to completion (polled).
    fn admin_status(&mut self, mut c: Cmd) -> u16 {
        c.cid = 0xffff;
        self.asq.push(&c);
        self.asq.ring();
        let mut res = None;
        spin_until("admin command", || {
            res = self.acq.pop();
            res.is_some()
        });
        self.acq.ring();
        res.unwrap().1
    }

    /// Issue one I/O command for `pieces` (PRP-compatible) at `lba`.
    fn issue(&mut self, req: u16, opcode: u8, ns: Namespace, lba: u64, pieces: &[Seg]) -> Result<(), u32> {
        let bytes: u64 = pieces.iter().map(|p| p.len as u64).sum();
        if bytes & ((1 << ns.lba_shift) - 1) != 0 {
            return Err(blk::STATUS_IOERR);
        }
        let cid = self.free_cids.pop().ok_or(blk::STATUS_IOERR)?;
        let (list_va, list_pa) = self.prp_slot(cid);
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
        let nlb = (bytes >> ns.lba_shift) as u32 - 1;
        self.submit_io(req, Cmd {
            opcode,
            cid,
            nsid: ns.id,
            prp1: pieces[0].pa,
            prp2,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: nlb,
        });
        Ok(())
    }
}

impl Driver for Nvme {
    fn units(&self) -> usize {
        self.namespaces.len()
    }

    fn info(&self, unit: usize) -> DevInfo {
        let ns = self.namespaces[unit];
        DevInfo {
            capacity: ns.blocks.min(u64::MAX >> 3) << (ns.lba_shift - 9),
            block_size: 1 << ns.lba_shift,
            read_only: false,
            flush: self.flush,
            address: u64::from(ns.id - 1),
            seg_max: MAX_PIECES,
        }
    }

    fn can_start(&self) -> bool {
        !self.free_reqs.is_empty() && self.free_cids.len() >= self.max_cmds
    }

    fn start(&mut self, tag: u64, unit: usize, op: u32, sector: u64, data: &[Seg]) -> Result<(), u32> {
        let ns = *self.namespaces.get(unit).ok_or(blk::STATUS_IOERR)?;
        let r = self.free_reqs.pop().ok_or(blk::STATUS_IOERR)?;
        self.reqs[r as usize] = Request { tag, pending: 0, status: blk::STATUS_OK };
        let result = (|| {
            if op == blk::OP_FLUSH {
                return self.issue_flush(r, ns.id);
            }
            let opcode = if op == blk::OP_READ { OP_READ } else { OP_WRITE };
            // Never round a sector down to the block holding it.
            if (sector << 9) & ((1 << ns.lba_shift) - 1) != 0 {
                return Err(blk::STATUS_IOERR);
            }
            let mut lba = (sector << 9) >> ns.lba_shift;
            let (max_bytes, cmd_pages, block) = (self.max_bytes, self.cmd_pages, (1u64 << ns.lba_shift) - 1);
            let len = |cmd: &[Seg]| cmd.iter().map(|p| p.len as u64).sum::<u64>();
            // Count the commands first: all are issued, or none.
            let mut cmds = 0;
            split(data, max_bytes, cmd_pages, |cmd| {
                cmds += 1;
                if cmd.is_empty() || len(cmd) & block != 0 { Err(blk::STATUS_IOERR) } else { Ok(()) }
            })?;
            if cmds > self.free_cids.len() {
                return Err(blk::STATUS_IOERR);
            }
            split(data, max_bytes, cmd_pages, |cmd| {
                self.issue(r, opcode, ns, lba, cmd)?;
                lba += len(cmd) >> ns.lba_shift;
                Ok(())
            })
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

    fn discard_max(&self, unit: usize) -> u32 {
        if !self.discard { return 0; }
        let align = 1u32 << (self.namespaces[unit].lba_shift - 9);
        u32::MAX & !(align - 1)
    }

    fn start_discard(&mut self, tag: u64, unit: usize, sector: u64, sectors: u32) -> Result<(), u32> {
        if !self.discard { return Err(blk::STATUS_UNSUPP); }
        let ns = *self.namespaces.get(unit).ok_or(blk::STATUS_IOERR)?;
        let shift = ns.lba_shift - 9;
        let align = (1u32 << shift) - 1;
        if sectors == 0 || sectors & align != 0 || sector & u64::from(align) != 0 {
            return Err(blk::STATUS_IOERR);
        }
        let req = self.free_reqs.pop().ok_or(blk::STATUS_IOERR)?;
        let Some(cid) = self.free_cids.pop() else {
            let _ = self.free_reqs.push(req);
            return Err(blk::STATUS_IOERR);
        };
        self.reqs[req as usize] = Request { tag, pending: 0, status: blk::STATUS_OK };
        // The list for this command is otherwise unused. The range is
        // 16 bytes and stays pinned until the command completes.
        let (va, pa) = self.prp_slot(cid);
        let range = Mmio(va);
        range.w32(0, 0);
        range.w32(4, sectors >> shift);
        range.w64(8, sector >> shift);
        self.submit_io(req, Cmd {
            opcode: OP_DATASET_MANAGEMENT,
            cid,
            nsid: ns.id,
            prp1: pa,
            cdw10: 0, // One range, zero-based.
            cdw11: DSM_DEALLOCATE,
            ..Default::default()
        });
        Ok(())
    }

    fn write_zeroes_max(&self, unit: usize) -> u32 {
        let ns = self.namespaces[unit];
        if self.write_zeroes_bytes == 0 || !ns.write_zeroes { return 0; }
        let per_cmd = (self.write_zeroes_bytes >> ns.lba_shift).clamp(1, WZ_MAX_BLOCKS);
        let cmds = WZ_MAX_CMDS.min(self.max_cmds as u64).max(1);
        let blocks = (per_cmd * cmds).min(u64::from(u32::MAX) >> (ns.lba_shift - 9));
        (blocks << (ns.lba_shift - 9)) as u32
    }

    fn start_write_zeroes(&mut self, tag: u64, unit: usize, sector: u64, sectors: u32) -> Result<(), u32> {
        let max = self.write_zeroes_max(unit);
        if max == 0 { return Err(blk::STATUS_UNSUPP); }
        let ns = *self.namespaces.get(unit).ok_or(blk::STATUS_IOERR)?;
        let shift = ns.lba_shift - 9;
        let align = (1u64 << shift) - 1;
        if sectors == 0 || sectors > max || u64::from(sectors) & align != 0 || sector & align != 0 {
            return Err(blk::STATUS_IOERR);
        }
        let (lba, blocks) = (sector >> shift, u64::from(sectors) >> shift);
        let per_cmd = (self.write_zeroes_bytes >> ns.lba_shift).clamp(1, WZ_MAX_BLOCKS);
        // All of the request's commands are issued, or none.
        let cmds = blocks.div_ceil(per_cmd) as usize;
        if cmds > self.free_cids.len() { return Err(blk::STATUS_IOERR); }
        let req = self.free_reqs.pop().ok_or(blk::STATUS_IOERR)?;
        self.reqs[req as usize] = Request { tag, pending: 0, status: blk::STATUS_OK };
        let deac = if ns.deac { WZ_DEAC } else { 0 };
        let mut at = 0;
        while at < blocks {
            let n = (blocks - at).min(per_cmd);
            let cid = self.free_cids.pop().unwrap();
            self.submit_io(req, Cmd {
                opcode: OP_WRITE_ZEROES,
                cid,
                nsid: ns.id,
                cdw10: (lba + at) as u32,
                cdw11: ((lba + at) >> 32) as u32,
                cdw12: deac | (n - 1) as u32,
                ..Default::default()
            });
            at += n;
        }
        Ok(())
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

/// Cut `data` into commands of at most `max_bytes` and `cmd_pages` pages
/// that each fit one PRP list, and pass each to `f`, in order.
fn split(data: &[Seg], max_bytes: u64, cmd_pages: u64, mut f: impl FnMut(&[Seg]) -> Result<(), u32>) -> Result<(), u32> {
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
            let room = (max_bytes - bytes).min(((cmd_pages - pages) * PAGE).saturating_sub(pa % PAGE));
            let mut take = len.min(room);
            if take < len {
                take = ((pa + take) & !(PAGE - 1)).saturating_sub(pa);
            }
            if !joins || take == 0 || n == MAX_PIECES {
                f(&cmd[..n])?;
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
    f(&cmd[..n])
}

impl Nvme {
    fn issue_flush(&mut self, r: u16, nsid: u32) -> Result<(), u32> {
        let cid = self.free_cids.pop().ok_or(blk::STATUS_IOERR)?;
        self.submit_io(r, Cmd { opcode: OP_FLUSH, cid, nsid, ..Default::default() });
        Ok(())
    }

    fn prp_slot(&self, cid: u16) -> (usize, u64) {
        let off = cid as usize * self.prp_len;
        (self.prp.0 + off, self.prp.1 + off as u64)
    }

    fn submit_io(&mut self, req: u16, cmd: Cmd) {
        self.sq.push(&cmd);
        self.cmd_req[cmd.cid as usize] = req;
        self.cid_busy[cmd.cid as usize] = true;
        self.reqs[req as usize].pending += 1;
    }
}
