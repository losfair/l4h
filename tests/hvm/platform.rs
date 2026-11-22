// SPDX-License-Identifier: GPL-2.0-only
//! An HVM guest's whole machine on the build host: l4h-hvm's vCPU code
//! (vcpu.rs) entering a scripted guest through a model of seL4's VCPU
//! (`Guest`, the hw::Hw seL4's VT-x and AMD-V backends implement), its
//! I/O thread's code (io.rs) called as the I/O thread would, and blkd and
//! netd modelled on their channels.  The guest does what Linux does to
//! boot and use the machine, an exit at a time: it starts at the kernel's
//! entry with the boot protocol's state, asks CPUID and MSRs, enumerates
//! PCI by 0xcf8/0xcfc and ECAM, brings up virtio-blk and virtio-net with
//! MSI-X, writes and reads its disk, sends and receives a frame, starts
//! vCPU 1 by INIT and SIPI, uses its UART both ways, and takes the ACPI
//! power button down to S5.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use l4h_abi as abi;
use l4h_rt::host::hvm::{self as hv, HvmConfig};
use l4h_rt::host::{self, badges, blk, net};

use crate::boot::Entry;
use crate::guest::GuestMem;
use crate::hw::{Event, Exit, Gprs, Hw};
use crate::sys::{self, as_thread};
use crate::vcpu::Vcpu;
use crate::vm::vm;
use crate::x86::decode::{Mode, Seg};
use crate::x86::walk::{self, Paging};

const MIB: u64 = 1 << 20;
const RAM: u64 = 64 * MIB;
/// Where the scripted guest's MMIO instructions are.
const CODE: u64 = 0x20_0000;
const IF: u64 = 1 << 9;
const LAPIC: u64 = 0xfee0_0000;

/// seL4's VCPU, as l4h-hvm sees it, running a script of exits.
#[derive(Default)]
struct Guest {
    g: Gprs,
    rip: u64,
    rflags: u64,
    cr0: u64,
    cr3: u64,
    cr4: u64,
    efer: u64,
    /// The length the CPU gives for the next exit's instruction.
    len: u64,
    exits: VecDeque<Exit>,
    /// What each entry injected.
    events: Vec<Event>,
    long: Option<Entry>,
    real: Option<u8>,
}

impl Hw for Guest {
    fn enter(&mut self, ev: Option<Event>, _irq_window: bool, _nmi_window: bool) -> Exit {
        if let Some(e) = ev {
            self.events.push(e);
        }
        self.exits.pop_front().expect("the guest ran past its script")
    }
    fn take_pending(&mut self) -> Option<Event> {
        None
    }
    fn gprs(&mut self) -> &mut Gprs {
        &mut self.g
    }
    fn rsp(&mut self) -> u64 {
        self.g[4]
    }
    fn set_rsp(&mut self, v: u64) {
        self.g[4] = v;
    }
    fn mark_gprs(&mut self) {}
    fn rip(&self) -> u64 {
        self.rip
    }
    fn rflags(&self) -> u64 {
        self.rflags
    }
    fn set_rflags(&mut self, v: u64) {
        self.rflags = v;
    }
    fn instr_len(&self) -> u64 {
        self.len
    }
    fn skip(&mut self, len: u64) {
        self.rip += len;
    }
    fn interruptible(&self) -> bool {
        self.rflags & IF != 0
    }
    fn nmi_blocked(&self) -> bool {
        false
    }
    fn paging(&mut self) -> Paging {
        Paging { cr0: self.cr0, cr3: self.cr3, cr4: self.cr4, efer: self.efer }
    }
    fn mode(&mut self) -> Mode {
        if self.efer & walk::EFER_LMA != 0 { Mode::Bits64 } else { Mode::Bits16 }
    }
    fn cpl(&mut self) -> u8 {
        0
    }
    fn seg_base(&mut self, _s: Seg) -> u64 {
        0
    }
    fn cr0(&mut self) -> u64 {
        self.cr0
    }
    fn cr4(&mut self) -> u64 {
        self.cr4
    }
    fn set_cr0(&mut self, v: u64) -> bool {
        self.cr0 = v;
        true
    }
    fn set_cr4(&mut self, v: u64) -> bool {
        self.cr4 = v;
        true
    }
    fn rdmsr(&mut self, msr: u32) -> Option<Option<u64>> {
        (msr == 0xc000_0080).then_some(Some(self.efer))
    }
    fn wrmsr(&mut self, msr: u32, v: u64) -> Option<bool> {
        (msr == 0xc000_0080).then(|| {
            self.efer = v;
            true
        })
    }
    fn set_xcr0(&mut self, _v: u64) -> bool {
        true
    }
    fn set_tsc_offset(&mut self, _off: u64) {}
    fn flush_tlb(&mut self) {}
    fn start_real_mode(&mut self, vector: u8) {
        self.real = Some(vector);
        (self.rip, self.cr0, self.efer, self.rflags) = (0, 0x10, 0, 2);
    }
    fn start_long_mode(&mut self, e: &Entry) {
        self.long = Some(*e);
        self.rip = e.rip;
        self.g[6] = e.rsi;
        self.cr3 = e.cr3;
        self.cr0 = walk::CR0_PE | walk::CR0_PG;
        self.cr4 = walk::CR4_PAE;
        self.efer = walk::EFER_LME | walk::EFER_LMA;
        self.rflags = 2;
    }
}

unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
}

/// Anonymous memory, at `at` if not 0 (where l4h-hvm has it mapped).
fn map(at: usize, len: usize) -> usize {
    const PROT_RW: i32 = 3;
    const MAP_PRIVATE_ANON: i32 = 0x02 | 0x20;
    const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;
    let flags = MAP_PRIVATE_ANON | if at != 0 { MAP_FIXED_NOREPLACE } else { 0 };
    let p = unsafe { mmap(at as *mut u8, len, PROT_RW, flags, -1, 0) } as usize;
    assert!(p != usize::MAX && (at == 0 || p == at), "mmap at {at:#x}");
    p
}

fn leak_zeroed<T>() -> &'static mut T {
    unsafe { &mut *(std::alloc::alloc_zeroed(std::alloc::Layout::new::<T>()) as *mut T) }
}

/// A bzImage (boot protocol 2.15, 64-bit) whose payload starts with `mark`.
fn bzimage(mark: &[u8]) -> Vec<u8> {
    let mut k = vec![0u8; 5 * 512 + 4096];
    k[0x1f1] = 4;
    k[0x1fe..0x200].copy_from_slice(&0xaa55u16.to_le_bytes());
    k[0x200] = 0xeb;
    k[0x201] = 0x6a;
    k[0x202..0x206].copy_from_slice(b"HdrS");
    k[0x206..0x208].copy_from_slice(&0x020fu16.to_le_bytes());
    k[0x22c..0x230].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
    k[0x230..0x234].copy_from_slice(&(2 * MIB as u32).to_le_bytes());
    k[0x234] = 1;
    k[0x236..0x238].copy_from_slice(&3u16.to_le_bytes());
    k[0x238..0x23c].copy_from_slice(&2047u32.to_le_bytes());
    k[0x258..0x260].copy_from_slice(&(16 * MIB).to_le_bytes());
    k[0x260..0x264].copy_from_slice(&(8 * MIB as u32).to_le_bytes());
    k[5 * 512..5 * 512 + mark.len()].copy_from_slice(mark);
    k
}

/// One turn of vCPU `v`, on its thread.
fn turn(c: &mut Vcpu<Guest>, v: usize) {
    as_thread(Some(v), || c.turn());
}

/// The guest does port I/O: what an IN read.
fn pio(c: &mut Vcpu<Guest>, v: usize, port: u16, size: u8, out: Option<u32>) -> u32 {
    let h = c.hw();
    let rip = h.rip;
    h.g[0] = out.unwrap_or(0xffff_ffff) as u64;
    h.len = 1;
    h.exits.push_back(Exit::Io { port, size, input: out.is_none(), string: false, rep: false, addr: 8 });
    turn(c, v);
    assert_eq!(c.hw().rip, rip + 1, "port {port:#x}: stepped over");
    (c.hw().g[0] & (u64::MAX >> (64 - 8 * size as u32))) as u32
}

/// The guest moves `size` bytes to or from guest-physical `gpa` (outside
/// RAM): the instruction is decoded and emulated.
fn mmio(c: &mut Vcpu<Guest>, v: usize, gpa: u64, size: u8, write: Option<u64>) -> u64 {
    let code: &[u8] = match (size, write.is_some()) {
        (1, true) => &[0x88, 0x03],
        (2, true) => &[0x66, 0x89, 0x03],
        (4, true) => &[0x89, 0x03],
        (8, true) => &[0x48, 0x89, 0x03],
        (1, false) => &[0x8a, 0x03],
        (2, false) => &[0x66, 0x8b, 0x03],
        (4, false) => &[0x8b, 0x03],
        _ => &[0x48, 0x8b, 0x03],
    };
    let code_at = CODE + 0x100 * v as u64;
    assert!(vm().mem.write_bytes(code_at, code));
    let h = c.hw();
    h.rip = code_at;
    h.g[3] = gpa;
    h.g[0] = write.unwrap_or(0x5a5a_5a5a_5a5a_5a5a);
    h.len = 0;
    h.exits.push_back(Exit::Mmio { gpa, write: write.is_some() });
    turn(c, v);
    assert_eq!(c.hw().rip, code_at + code.len() as u64, "{gpa:#x}: emulated");
    c.hw().g[0] & (u64::MAX >> (64 - 8 * size as u32))
}

/// Configuration space of slot `slot` by ECAM.
fn cfg_read(c: &mut Vcpu<Guest>, slot: u64, off: u64, size: u8) -> u64 {
    mmio(c, 0, hv::ECAM_BASE + (slot << 15) + off, size, None)
}

fn cfg_write(c: &mut Vcpu<Guest>, slot: u64, off: u64, size: u8, v: u64) {
    mmio(c, 0, hv::ECAM_BASE + (slot << 15) + off, size, Some(v));
}

/// A capability of slot `slot`'s function: its offset.
fn find_cap(c: &mut Vcpu<Guest>, slot: u64, id: u8, cfg_type: Option<u8>) -> u64 {
    let mut at = cfg_read(c, slot, 0x34, 1);
    while at != 0 {
        let hdr = cfg_read(c, slot, at, 4);
        if hdr as u8 == id && cfg_type.is_none_or(|t| cfg_read(c, slot, at + 3, 1) as u8 == t) {
            return at;
        }
        at = (hdr >> 8) & 0xff;
    }
    panic!("slot {slot}: no capability {id:#x}");
}

/// A virtio-pci device brought up as Linux does: VERSION_1, MSI-X with a
/// vector per queue (entry i: vector `base + i`, to vCPU 0), `queues`
/// queues of 16 at `rings` + 0x1000 * i.  BAR0's address.
fn virtio_up(c: &mut Vcpu<Guest>, slot: u64, base: u8, queues: u16, rings: u64) -> u64 {
    let bar0 = cfg_read(c, slot, 0x10, 4) & !0xf | cfg_read(c, slot, 0x14, 4) << 32;
    let bar2 = cfg_read(c, slot, 0x18, 4) & !0xf | cfg_read(c, slot, 0x1c, 4) << 32;
    assert!(bar0 >= hv::PCI_MMIO_BASE && bar2 >= hv::PCI_MMIO_BASE);
    // Memory decoding and bus mastering; MSI-X on.
    cfg_write(c, slot, 0x04, 2, 0x6);
    let msix = find_cap(c, slot, 0x11, None);
    let table = cfg_read(c, slot, msix + 4, 4);
    assert_eq!(table & 7, 2, "the MSI-X table is in BAR2");
    cfg_write(c, slot, msix + 2, 2, 1 << 15);
    for i in 0..queues as u64 + 1 {
        let e = bar2 + (table & !7) + 16 * i;
        mmio(c, 0, e, 4, Some(LAPIC));
        mmio(c, 0, e + 4, 4, Some(0));
        mmio(c, 0, e + 8, 4, Some(base as u64 + i));
        mmio(c, 0, e + 12, 4, Some(0));
    }
    // The common configuration, where its capability says.
    let common_cap = find_cap(c, slot, 0x09, Some(1));
    assert_eq!(cfg_read(c, slot, common_cap + 4, 1), 0, "in BAR0");
    let common = bar0 + cfg_read(c, slot, common_cap + 8, 4);
    mmio(c, 0, common + 0x14, 1, Some(0));
    mmio(c, 0, common + 0x14, 1, Some(1 | 2));
    mmio(c, 0, common, 4, Some(1));
    assert_eq!(mmio(c, 0, common + 4, 4, None) & 1, 1, "VERSION_1 offered");
    mmio(c, 0, common + 8, 4, Some(1));
    mmio(c, 0, common + 0xc, 4, Some(1));
    mmio(c, 0, common + 0x14, 1, Some(1 | 2 | 8));
    assert_eq!(mmio(c, 0, common + 0x14, 1, None), 1 | 2 | 8, "FEATURES_OK stays");
    assert_eq!(mmio(c, 0, common + 0x12, 2, None), queues as u64);
    mmio(c, 0, common + 0x10, 2, Some(queues as u64));
    for q in 0..queues as u64 {
        mmio(c, 0, common + 0x16, 2, Some(q));
        assert!(mmio(c, 0, common + 0x18, 2, None) >= 16);
        mmio(c, 0, common + 0x18, 2, Some(16));
        mmio(c, 0, common + 0x1a, 2, Some(q));
        assert_eq!(mmio(c, 0, common + 0x1a, 2, None), q, "vector taken");
        let r = rings + 0x1000 * q;
        mmio(c, 0, common + 0x20, 8, Some(r));
        mmio(c, 0, common + 0x28, 8, Some(r + 0x100));
        mmio(c, 0, common + 0x30, 8, Some(r + 0x200));
        mmio(c, 0, common + 0x1c, 2, Some(1));
    }
    mmio(c, 0, common + 0x14, 1, Some(1 | 2 | 4 | 8));
    bar0
}

/// Notify queue `q` of a device at `bar0`, as the guest does: a write to
/// the notify area, which posts a kick and signals the I/O thread.
fn notify(c: &mut Vcpu<Guest>, slot: u64, bar0: u64, q: u64) {
    sys::IO_SIGNALS.store(0, Ordering::SeqCst);
    let common = bar0;
    mmio(c, 0, common + 0x16, 2, Some(q));
    let off = mmio(c, 0, common + 0x1e, 2, None);
    mmio(c, 0, bar0 + crate::dev::virtio_pci::NOTIFY + off * crate::dev::virtio_pci::NOTIFY_MULTIPLIER, 2, Some(q));
    assert_ne!(sys::IO_SIGNALS.load(Ordering::SeqCst) & badges::hvm::KICK, 0, "the I/O thread signalled");
    assert_ne!(vm().kicks.0[slot as usize].load(Ordering::SeqCst) & (1 << q), 0, "the queue's kick posted");
}

/// A descriptor `i` of the ring at `rings`, and the chain's head posted at
/// avail index `idx`.
fn desc(mem: &GuestMem, rings: u64, i: u64, gpa: u64, len: u32, flags: u16, next: u16) {
    let d = rings + 16 * i;
    mem.write::<u64>(d, gpa);
    mem.write::<u32>(d + 8, len);
    mem.write::<u16>(d + 12, flags);
    mem.write::<u16>(d + 14, next);
}

fn post(mem: &GuestMem, rings: u64, head: u16, idx: u16) {
    mem.write::<u16>(rings + 0x100 + 4 + 2 * ((idx - 1) % 16) as u64, head);
    mem.write::<u16>(rings + 0x100 + 2, idx);
}

/// blkd: the requests on `chan`, done on `disk`, through the I/O pool.
fn blkd(chan: &mut blk::Channel, disk: &mut [u8]) -> usize {
    let head = chan.sq.head.load(Ordering::Acquire);
    let mut n = 0;
    while chan.sq.tail.load(Ordering::Relaxed) != head {
        let t = chan.sq.tail.load(Ordering::Relaxed);
        let r = chan.reqs[t as usize % blk::RING_SIZE];
        let mut at = r.sector as usize * 512;
        for s in &r.segs[..r.nr_segs as usize] {
            assert!(s.gpa >= hv::IO_POOL_GPA && s.gpa + s.len as u64 <= hv::IO_POOL_GPA + 8 * MIB, "blkd is given only the pool");
            let p = (hv::IO_POOL_VA as u64 + (s.gpa - hv::IO_POOL_GPA)) as *mut u8;
            let len = s.len as usize;
            unsafe {
                match r.op {
                    blk::OP_WRITE => std::ptr::copy_nonoverlapping(p, disk[at..].as_mut_ptr(), len),
                    blk::OP_READ => std::ptr::copy_nonoverlapping(disk[at..].as_ptr(), p, len),
                    _ => {}
                }
            }
            at += len;
        }
        let c = chan.cq.head.load(Ordering::Relaxed);
        chan.resps[c as usize % blk::RING_SIZE] = blk::Resp { id: r.id, status: blk::STATUS_OK, reserved: 0 };
        chan.cq.head.store(c + 1, Ordering::Release);
        chan.sq.tail.store(t + 1, Ordering::Release);
        n += 1;
    }
    n
}

/// vCPU 0's next entry: the interrupt it injects.
fn next_interrupt(c: &mut Vcpu<Guest>) -> Option<Event> {
    c.hw().exits.push_back(Exit::Notified(0));
    let before = c.hw().events.len();
    turn(c, 0);
    c.hw().events.get(before).copied()
}

fn eoi(c: &mut Vcpu<Guest>) {
    mmio(c, 0, LAPIC + 0xb0, 4, Some(0));
}

#[test]
fn guest_boots_and_uses_the_machine() {
    // What vmmgr maps for l4h-hvm: its shared pages (event pages, console
    // ring and page) and the I/O pool, at their addresses.
    map(host::SHARED_VA, 16 << 20);
    map(hv::IO_POOL_VA, 8 << 20);
    let ram = map(0, RAM as usize);
    let mapped: &'static [std::sync::atomic::AtomicU64] =
        Vec::leak((0..abi::MAX_BLOCKS / 64).map(|_| std::sync::atomic::AtomicU64::new(u64::MAX)).collect());
    let mem = GuestMem { base: ram, low: RAM, high: 0, mapped, map: sys::map };

    // dom0 loaded a kernel at 40 MiB and an initrd at 48 MiB.
    let kernel = bzimage(b"payload!");
    assert!(mem.write_bytes(40 * MIB, &kernel));
    assert!(mem.write_bytes(48 * MIB, b"initrd"));
    let chan: &'static mut blk::Channel = leak_zeroed();
    chan.capacity_sectors = 2048;
    chan.block_size = 512;
    chan.seg_max = 16;
    chan.ready = 1;
    let chan_ptr = chan as *mut blk::Channel;
    let port: &'static mut net::Port = leak_zeroed();
    let port_ptr = port as *mut net::Port;
    let cfg: &'static mut HvmConfig = leak_zeroed();
    cfg.guest_id = 7;
    cfg.nr_vcpus = 2;
    cfg.low_ram = RAM;
    cfg.boot_blocks = (RAM / (2 * MIB)) as u32;
    cfg.io_pool_gpa = hv::IO_POOL_GPA;
    cfg.io_pool_size = 8 * MIB;
    (cfg.kernel_gpa, cfg.kernel_size) = (40 * MIB, kernel.len() as u64);
    (cfg.initrd_gpa, cfg.initrd_size) = (48 * MIB, 6);
    cfg.cmdline[..13].copy_from_slice(b"console=ttyS0");
    // 2026-01-01T00:00:00Z at tick 0.
    cfg.epoch_ns = 1_767_225_600 * 1_000_000_000;
    cfg.nr_devices = 2;
    cfg.devices[0].kind = host::VDEV_BLK;
    cfg.devices[0].chan_va = chan_ptr as u64;
    cfg.devices[1].kind = host::VDEV_NET;
    cfg.devices[1].chan_va = port_ptr as u64;
    cfg.devices[1].mac[..6].copy_from_slice(&[2, 0, 0, 0, 0, 7]);
    let tsc_hz = 1_000_000_000;
    crate::vm::build(cfg, tsc_hz, mem, true, 7).expect("the machine");
    crate::io::init();
    let mem = &vm().mem;

    // ---- Boot: vCPU 0 at the kernel's 64-bit entry, vCPU 1 waits.
    let mut c0 = as_thread(Some(0), || Vcpu::new(0, Guest::default()));
    let mut c1 = as_thread(Some(1), || Vcpu::new(1, Guest::default()));
    let e = c0.hw().long.expect("vCPU 0 starts in long mode");
    assert_eq!((e.rip, e.rsi), (16 * MIB + 0x200, crate::boot::ZERO_PAGE));
    assert_eq!(c1.hw().long, None);
    assert_eq!(c1.state(), (true, false));
    let mut payload = [0u8; 8];
    mem.read_bytes(16 * MIB, &mut payload);
    assert_eq!(&payload, b"payload!", "the payload moved to its address");
    let zp = crate::boot::ZERO_PAGE;
    assert_eq!(mem.read::<u32>(zp + 0x228) as u64, crate::boot::CMDLINE);
    let mut line = [0u8; 14];
    mem.read_bytes(crate::boot::CMDLINE, &mut line);
    assert_eq!(&line, b"console=ttyS0\0");
    assert_eq!((mem.read::<u32>(zp + 0x218), mem.read::<u32>(zp + 0x21c)), ((48 * MIB) as u32, 6));
    assert_eq!(mem.read::<u64>(zp + 0x70), crate::acpi::RSDP, "acpi_rsdp_addr");
    let mut sig = [0u8; 8];
    mem.read_bytes(crate::acpi::RSDP, &mut sig);
    assert_eq!(&sig, b"RSD PTR ");
    let e820 = mem.read::<u8>(zp + 0x1e8) as u64;
    let last = (0..e820).map(|i| (mem.read::<u64>(zp + 0x2d0 + 20 * i), mem.read::<u64>(zp + 0x2d8 + 20 * i), mem.read::<u32>(zp + 0x2e0 + 20 * i)))
        .filter(|e| e.2 == 1).map(|e| e.0 + e.1).max();
    assert_eq!(last, Some(RAM), "E820 RAM up to the end of RAM");

    // ---- CPUID and the APIC base.
    let h = c0.hw();
    (h.g[0], h.g[1], h.len) = (1, 0, 2);
    h.exits.push_back(Exit::Cpuid);
    turn(&mut c0, 0);
    assert_ne!(c0.hw().g[1] & (1 << 21), 0, "x2APIC");
    assert_eq!(c0.hw().g[3] >> 24 & 0xff, 0, "initial APIC ID");
    let h = c0.hw();
    (h.g[1], h.len) = (0x1b, 2);
    h.exits.push_back(Exit::Rdmsr);
    turn(&mut c0, 0);
    assert_eq!(c0.hw().g[0], LAPIC | 0x900, "APIC base: enabled, BSP");

    // ---- The local APIC on, and an interrupt-enabled guest.
    mmio(&mut c0, 0, LAPIC + 0xf0, 4, Some(0x1ff));
    mmio(&mut c0, 0, LAPIC + 0x80, 4, Some(0));
    c0.hw().rflags |= IF;

    // ---- PCI: the host bridge and the devices by 0xcf8/0xcfc, then ECAM.
    let mut ids = vec![];
    for slot in 0..4u32 {
        pio(&mut c0, 0, 0xcf8, 4, Some(0x8000_0000 | slot << 11));
        ids.push(pio(&mut c0, 0, 0xcfc, 4, None));
    }
    assert_eq!(ids, [0x0008_1b36, 0x1042_1af4, 0x1041_1af4, 0xffff_ffff]);
    assert_eq!(cfg_read(&mut c0, 1, 0, 4), 0x1042_1af4);
    assert_eq!(cfg_read(&mut c0, 3, 0, 2), 0xffff, "an empty slot");

    // ---- virtio-blk: a write of 1 KiB at sector 4, read back.
    let rings = 0x10_0000;
    let bar0 = virtio_up(&mut c0, 1, 0x40, 1, rings);
    mem.write::<u32>(0x30_0000, 1);
    mem.write::<u64>(0x30_0008, 4);
    mem.write_bytes(0x31_0000, &[0xa5; 1024]);
    desc(mem, rings, 0, 0x30_0000, 16, 1, 1);
    desc(mem, rings, 1, 0x31_0000, 1024, 1, 2);
    desc(mem, rings, 2, 0x30_0100, 1, 2, 0);
    post(mem, rings, 0, 1);
    notify(&mut c0, 1, bar0, 0);
    let mut disk = vec![0u8; 2048 * 512];
    as_thread(None, crate::io::kicked);
    assert_eq!(blkd(chan_ptr_mut(chan_ptr), &mut disk), 1, "the request reached blkd");
    sys::WOKEN.store(0, Ordering::SeqCst);
    as_thread(None, crate::io::completed);
    assert!(disk[2048..3072].iter().all(|&b| b == 0xa5), "on the disk");
    assert_eq!(mem.read::<u8>(0x30_0100), 0, "status OK");
    assert_eq!(mem.read::<u16>(rings + 0x200 + 2), 1, "used");
    assert_ne!(sys::WOKEN.load(Ordering::SeqCst) & 1, 0, "vCPU 0 woken for its MSI-X");
    assert_eq!(next_interrupt(&mut c0), Some(Event::Ext(0x40)));
    eoi(&mut c0);
    mem.write::<u32>(0x30_0000, 0);
    desc(mem, rings, 1, 0x32_0000, 1024, 3, 2);
    post(mem, rings, 0, 2);
    notify(&mut c0, 1, bar0, 0);
    as_thread(None, crate::io::kicked);
    assert_eq!(blkd(chan_ptr_mut(chan_ptr), &mut disk), 1);
    as_thread(None, crate::io::completed);
    let mut back = vec![0u8; 1024];
    mem.read_bytes(0x32_0000, &mut back);
    assert!(back.iter().all(|&b| b == 0xa5), "read back");
    assert_eq!(next_interrupt(&mut c0), Some(Event::Ext(0x40)));
    eoi(&mut c0);

    // ---- virtio-net: a frame out, a frame in.
    let rings = 0x40_0000;
    let bar0 = virtio_up(&mut c0, 2, 0x50, 2, rings);
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = mmio(&mut c0, 0, bar0 + 0x3000 + i as u64, 1, None) as u8;
    }
    assert_eq!(mac, [2, 0, 0, 0, 0, 7]);
    let tx = rings + 0x1000;
    mem.write_bytes(0x50_0000, &[0; 12]);
    mem.write_bytes(0x50_0100, &[0x11; 60]);
    desc(mem, tx, 0, 0x50_0000, 12, 1, 1);
    desc(mem, tx, 1, 0x50_0100, 60, 0, 0);
    post(mem, tx, 0, 1);
    notify(&mut c0, 2, bar0, 1);
    as_thread(None, crate::io::kicked);
    assert_eq!(port.tx.head.load(Ordering::Acquire), 1, "netd has the frame");
    assert_eq!(port.tx_slots[0].len, 60);
    assert_eq!(port.tx_slots[0].data[59], 0x11);
    assert_eq!(mem.read::<u16>(tx + 0x200 + 2), 1, "the frame's buffers returned");
    assert_eq!(next_interrupt(&mut c0), Some(Event::Ext(0x51)), "TX's vector");
    eoi(&mut c0);
    desc(mem, rings, 0, 0x51_0000, 2048, 2, 0);
    post(mem, rings, 0, 1);
    notify(&mut c0, 2, bar0, 0);
    as_thread(None, crate::io::kicked);
    port.rx_slots[0].len = 64;
    port.rx_slots[0].data[..64].fill(0x22);
    port.rx.head.store(1, Ordering::Release);
    as_thread(None, crate::io::completed);
    assert_eq!(mem.read::<u32>(rings + 0x200 + 8), 12 + 64, "received");
    assert_eq!(mem.read::<u8>(0x51_0000 + 12 + 63), 0x22);
    assert_eq!(next_interrupt(&mut c0), Some(Event::Ext(0x50)), "RX's vector");
    eoi(&mut c0);
    assert_eq!(next_interrupt(&mut c0), None);

    // ---- SMP: INIT and SIPI start vCPU 1 in real mode at 0x9a000.
    sys::WOKEN.store(0, Ordering::SeqCst);
    mmio(&mut c0, 0, LAPIC + 0x310, 4, Some(1 << 24));
    mmio(&mut c0, 0, LAPIC + 0x300, 4, Some(0x4500));
    mmio(&mut c0, 0, LAPIC + 0x300, 4, Some(0x4600 | 0x9a));
    assert_ne!(sys::WOKEN.load(Ordering::SeqCst) & 2, 0, "vCPU 1 woken");
    c1.hw().len = 1;
    c1.hw().exits.push_back(Exit::Hlt);
    turn(&mut c1, 1);
    assert_eq!(c1.hw().real, Some(0x9a));
    assert_eq!(c1.state(), (false, true), "running, then halted");

    // ---- The UART: output into the console ring, input from the page.
    for &b in b"hi\n" {
        pio(&mut c0, 0, 0x3f8, 1, Some(b as u32));
    }
    let ring = host::VMM_CONSOLE_RING_VA as *const host::ConsoleRing;
    unsafe {
        assert_eq!((*ring).head.load(Ordering::Acquire), 3);
        assert_eq!(&(&(*ring).data)[..3], b"hi\n");
    }
    let page = hv::CONSOLE_PAGE_VA as *mut abi::ConsolePage;
    unsafe {
        (*page).input[0] = b'x';
        (*page).in_head = 1;
    }
    as_thread(None, crate::io::control);
    assert_eq!(pio(&mut c0, 0, 0x3fd, 1, None) & 1, 1, "data ready");
    assert_eq!(pio(&mut c0, 0, 0x3f8, 1, None), b'x' as u32);
    assert_eq!(pio(&mut c0, 0, 0x3fd, 1, None) & 1, 0);

    // ---- ACPI: the power button (l4hctl shutdown) as an SCI, then S5.
    mmio(&mut c0, 0, 0xfec0_0000, 4, Some(0x10 + 2 * 9));
    mmio(&mut c0, 0, 0xfec0_0010, 4, Some(0x29 | 1 << 15));
    pio(&mut c0, 0, crate::dev::pm::PM1_EVT + 2, 2, Some(1 << 8));
    unsafe { (*page).power_request = abi::POWER_OFF as u32 + 1 };
    sys::WOKEN.store(0, Ordering::SeqCst);
    as_thread(None, crate::io::control);
    assert_ne!(sys::WOKEN.load(Ordering::SeqCst) & 1, 0, "vCPU 0 woken for the SCI");
    assert_eq!(next_interrupt(&mut c0), Some(Event::Ext(0x29)));
    assert_ne!(pio(&mut c0, 0, crate::dev::pm::PM1_EVT, 2, None) & 1 << 8, 0, "PWRBTN_STS");
    pio(&mut c0, 0, crate::dev::pm::PM1_EVT, 2, Some(1 << 8));
    eoi(&mut c0);
    assert_eq!(next_interrupt(&mut c0), None, "the SCI is down once acknowledged");
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pio(&mut c0, 0, crate::dev::pm::PM1_CNT, 2, Some((crate::dev::pm::SLP_TYP_S5 << 10 | 1 << 13) as u32));
    }));
    assert!(stopped.is_err());
    assert_eq!(sys::POWER.load(Ordering::SeqCst), abi::POWER_OFF + 1, "powered off");
}

fn chan_ptr_mut(p: *mut blk::Channel) -> &'static mut blk::Channel {
    unsafe { &mut *p }
}
