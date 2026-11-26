// SPDX-License-Identifier: GPL-2.0-only
//! An AArch64 HVM guest's whole machine on the build host: l4h-hvm's vCPU
//! code (arm/vcpu.rs) entering a scripted guest through a model of FL4's
//! VCPU (`Guest`, the arm::hw::Hw that seL4_ARM_VCPU_Run implements), its
//! I/O thread's code (io.rs) called as the I/O thread would, and blkd
//! modelled on its channel.  The guest does what Linux does to boot and use
//! the machine, an exit at a time.  One machine per process: `L4H_TEST_GIC`
//! (3 or 2) says which (tests/run-hvmunit.sh runs both).

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use l4h_abi as abi;
use l4h_rt::host::hvm::{self as hv, HvmConfig, arm};
use l4h_rt::host::{self, badges, blk};

use crate::arm::fdt::tests::{parse, prop};
use crate::arm::hw::{Exit, Hw};
use crate::arm::regs::*;
use crate::arm::vgic::PPI_VTIMER;
use crate::guest::GuestMem;
use crate::sys::{self, as_thread};
use crate::vcpu::Vcpu;
use crate::vm::vm;

const MIB: u64 = 1 << 20;
const RAM: u64 = 64 * MIB;
const RAM_BASE: u64 = arm::RAM_BASE;
/// The scripted guest's exception vectors.
const VBAR: u64 = RAM_BASE + 0x10_0000;

const EC_WFX: u64 = 0x01;
const EC_HVC: u64 = 0x16;
const EC_SMC: u64 = 0x17;
const EC_SYSREG: u64 = 0x18;
const EC_DABT: u64 = 0x24;
const EC_IABT: u64 = 0x20;
const IL: u64 = 1 << 25;
const ISV: u64 = 1 << 24;
const SF: u64 = 1 << 15;
const WNR: u64 = 1 << 6;
const SSE: u64 = 1 << 21;

const LR3_PENDING: u64 = 1 << 62;
const LR3_EOI: u64 = 1 << 41;
const LR2_PENDING: u64 = 1 << 28;
const LR2_EOI: u64 = 1 << 19;

const PSCI_VERSION: u64 = 0x8400_0000;
const PSCI_CPU_OFF: u64 = 0x8400_0002;
const PSCI_CPU_ON: u64 = 0xc400_0003;
const PSCI_AFFINITY_INFO: u64 = 0xc400_0004;
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
const ICC_SGI1R: (u64, u64, u64, u64, u64) = (3, 0, 12, 11, 5);

fn gicv3() -> bool {
    std::env::var("L4H_TEST_GIC").as_deref() != Ok("2")
}

/// FL4's VCPU, as l4h-hvm sees it, running a script of exits.
struct Guest {
    s: Box<State>,
    exits: VecDeque<Exit>,
    /// The groups each entry loaded, and the list registers it ran with.
    loads: Vec<u64>,
    lrs: Vec<[u64; 4]>,
    /// FL4's copy of what no group here carries.
    regs: [u64; 64],
}

impl Default for Guest {
    fn default() -> Self {
        let mut regs = [0; 64];
        regs[reg::VBAR] = VBAR;
        Guest { s: Box::new(State::zeroed()), exits: VecDeque::new(), loads: Vec::new(), lrs: Vec::new(), regs }
    }
}

impl Hw for Guest {
    fn state(&mut self) -> &mut State {
        &mut self.s
    }
    fn run(&mut self, load: u64, _save: u64) -> Exit {
        self.loads.push(load);
        let l = reg::VGIC_LR0;
        self.lrs.push([self.s.regs[l], self.s.regs[l + 1], self.s.regs[l + 2], self.s.regs[l + 3]]);
        self.exits.pop_front().expect("the guest ran past its script")
    }
    fn read_reg(&mut self, r: usize) -> u64 {
        self.regs[r]
    }
    fn write_reg(&mut self, r: usize, v: u64) {
        self.regs[r] = v;
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

/// An arm64 Image of `size` bytes as it runs, whose body starts with `mark`.
fn image(size: u64, mark: &[u8]) -> Vec<u8> {
    let mut k = vec![0u8; 4096];
    k[16..24].copy_from_slice(&size.to_le_bytes());
    k[24..32].copy_from_slice(&2u64.to_le_bytes());
    k[56..60].copy_from_slice(&0x644d_5241u32.to_le_bytes());
    k[64..64 + mark.len()].copy_from_slice(mark);
    k
}

fn turn(c: &mut Vcpu<Guest>, v: usize) {
    as_thread(Some(v), || c.turn());
}

/// The guest runs until `exit`.
fn step(c: &mut Vcpu<Guest>, v: usize, exit: Exit) {
    c.hw().exits.push_back(exit);
    turn(c, v);
}

fn pc(c: &mut Vcpu<Guest>) -> u64 {
    c.hw().s.gprs[GPR_PC]
}

/// The guest loads or stores `size` bytes at `gpa` with x3: what it read.
fn mmio(c: &mut Vcpu<Guest>, v: usize, gpa: u64, size: u8, write: Option<u64>) -> u64 {
    let before = pc(c);
    let esr = EC_DABT << 26 | IL | ISV | (size.trailing_zeros() as u64) << 22 | 3 << 16 | SF
        | if write.is_some() { WNR } else { 0 };
    c.hw().s.gprs[3] = write.unwrap_or(0x5a5a_5a5a_5a5a_5a5a);
    step(c, v, Exit::VmFault { esr, ipa: gpa, far: 0xffff_0000_0000_0000 | gpa });
    assert_eq!(pc(c), before + 4, "{gpa:#x}: past the access");
    c.hw().s.gprs[3]
}

fn sysreg_esr((op0, op1, crn, crm, op2): (u64, u64, u64, u64, u64), rt: u64, read: bool) -> u64 {
    EC_SYSREG << 26 | IL | op0 << 20 | op2 << 17 | op1 << 14 | crn << 10 | rt << 5 | crm << 1 | read as u64
}

/// The guest calls its firmware with HVC: x0 afterwards.
fn hvc(c: &mut Vcpu<Guest>, v: usize, fid: u64, a: [u64; 3]) -> u64 {
    let g = &mut c.hw().s.gprs;
    (g[0], g[1], g[2], g[3]) = (fid, a[0], a[1], a[2]);
    let before = g[GPR_PC];
    step(c, v, Exit::VcpuFault { esr: EC_HVC << 26 | IL });
    assert_eq!(pc(c), before, "HVC's return address is past it already");
    c.hw().s.gprs[0]
}

fn cfg_read(c: &mut Vcpu<Guest>, slot: u64, off: u64, size: u8) -> u64 {
    mmio(c, 0, arm::ECAM_BASE + (slot << 15) + off, size, None)
}

fn cfg_write(c: &mut Vcpu<Guest>, slot: u64, off: u64, size: u8, v: u64) {
    mmio(c, 0, arm::ECAM_BASE + (slot << 15) + off, size, Some(v));
}

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

/// The doorbell and first SPI of the guest's MSIs.
fn doorbell() -> u64 {
    if gicv3() { arm::GICD_BASE + 0x40 } else { arm::V2M_BASE + 0x40 }
}

/// A virtio-pci device brought up as Linux does, with MSI-X vectors from
/// SPI `spi`: BAR0's address.
fn virtio_up(c: &mut Vcpu<Guest>, slot: u64, spi: u32, queues: u16, rings: u64) -> u64 {
    let bar0 = cfg_read(c, slot, 0x10, 4) & !0xf | cfg_read(c, slot, 0x14, 4) << 32;
    let bar2 = cfg_read(c, slot, 0x18, 4) & !0xf | cfg_read(c, slot, 0x1c, 4) << 32;
    assert!(bar0 >= arm::PCI_MMIO_BASE && bar2 < arm::PCI_MMIO_BASE + arm::PCI_MMIO_SIZE, "in the window");
    cfg_write(c, slot, 0x04, 2, 0x6);
    let msix = find_cap(c, slot, 0x11, None);
    let table = cfg_read(c, slot, msix + 4, 4);
    cfg_write(c, slot, msix + 2, 2, 1 << 15);
    for i in 0..queues as u64 + 1 {
        let e = bar2 + (table & !7) + 16 * i;
        mmio(c, 0, e, 4, Some(doorbell() & 0xffff_ffff));
        mmio(c, 0, e + 4, 4, Some(doorbell() >> 32));
        mmio(c, 0, e + 8, 4, Some(spi as u64 + i));
        mmio(c, 0, e + 12, 4, Some(0));
    }
    let common_cap = find_cap(c, slot, 0x09, Some(1));
    let common = bar0 + cfg_read(c, slot, common_cap + 8, 4);
    mmio(c, 0, common + 0x14, 1, Some(0));
    mmio(c, 0, common + 0x14, 1, Some(1 | 2));
    mmio(c, 0, common, 4, Some(1));
    assert_eq!(mmio(c, 0, common + 4, 4, None) & 1, 1, "VERSION_1 offered");
    mmio(c, 0, common + 8, 4, Some(1));
    mmio(c, 0, common + 0xc, 4, Some(1));
    mmio(c, 0, common + 0x14, 1, Some(1 | 2 | 8));
    assert_eq!(mmio(c, 0, common + 0x14, 1, None), 1 | 2 | 8, "FEATURES_OK stays");
    mmio(c, 0, common + 0x10, 2, Some(queues as u64));
    for q in 0..queues as u64 {
        mmio(c, 0, common + 0x16, 2, Some(q));
        mmio(c, 0, common + 0x18, 2, Some(16));
        mmio(c, 0, common + 0x1a, 2, Some(q));
        let r = rings + 0x1000 * q;
        mmio(c, 0, common + 0x20, 8, Some(r));
        mmio(c, 0, common + 0x28, 8, Some(r + 0x100));
        mmio(c, 0, common + 0x30, 8, Some(r + 0x200));
        mmio(c, 0, common + 0x1c, 2, Some(1));
    }
    mmio(c, 0, common + 0x14, 1, Some(1 | 2 | 4 | 8));
    bar0
}

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
            assert!(s.gpa >= hv::IO_POOL_GPA, "blkd is given only the pool");
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

/// The next entry: the INTIDs its list registers have pending.
fn pending_lrs(c: &mut Vcpu<Guest>, v: usize) -> Vec<u32> {
    step(c, v, Exit::Interrupt(0));
    let lrs = *c.hw().lrs.last().unwrap();
    let pend = if gicv3() { LR3_PENDING } else { LR2_PENDING };
    lrs.iter().filter(|&&l| l & pend != 0).map(|&l| l as u32 & 0x3ff).collect()
}

/// The guest takes and ends INTID `id`: its list register is empty after
/// the next exit, as FL4 hands it back.
fn guest_ends(c: &mut Vcpu<Guest>, v: usize, id: u32) {
    let s = &mut c.hw().s;
    for i in 0..4 {
        if s.regs[reg::VGIC_LR0 + i] as u32 & 0x3ff == id {
            s.regs[reg::VGIC_LR0 + i] = 0;
        }
    }
    step(c, v, Exit::VgicMaint);
}

fn enable_spi(c: &mut Vcpu<Guest>, id: u32) {
    mmio(c, 0, arm::GICD_BASE + 0x100 + 4 * (id as u64 / 32), 4, Some(1 << (id % 32)));
}

/// Set SPI `id` edge-triggered, to vCPU 0, as Linux configures an MSI.
fn edge_spi(c: &mut Vcpu<Guest>, id: u32) {
    let reg = arm::GICD_BASE + 0xc00 + 4 * (id as u64 / 16);
    let old = mmio(c, 0, reg, 4, None);
    mmio(c, 0, reg, 4, Some(old | 2 << (2 * (id % 16))));
    if gicv3() {
        mmio(c, 0, arm::GICD_BASE + 0x6000 + 8 * id as u64, 8, Some(0));
    } else {
        mmio(c, 0, arm::GICD_BASE + 0x800 + id as u64, 1, Some(1));
    }
    enable_spi(c, id);
}

fn enable_local(c: &mut Vcpu<Guest>, v: usize, id: u32) {
    if gicv3() {
        let rd = arm::GICR_BASE + v as u64 * arm::GICR_STRIDE;
        mmio(c, v, rd + 0x1_0000 + 0x100, 4, Some(1 << id));
    } else {
        mmio(c, v, arm::GICD_BASE + 0x100, 4, Some(1 << id));
    }
}

#[test]
fn guest_boots_and_uses_the_machine() {
    let v3 = gicv3();
    // What vmmgr maps for l4h-hvm: its shared pages and the I/O pool.
    map(host::SHARED_VA, 16 << 20);
    map(hv::IO_POOL_VA, 8 << 20);
    let ram = map(0, RAM as usize);
    let mapped: &'static [std::sync::atomic::AtomicU64] =
        Vec::leak((0..abi::MAX_BLOCKS / 64).map(|_| std::sync::atomic::AtomicU64::new(u64::MAX)).collect());
    let mem = GuestMem { base: ram - RAM_BASE as usize, ram_base: RAM_BASE, low: RAM, high: 0, mapped, map: sys::map };

    // dom0 loaded a kernel at 40 MiB and an initrd at 48 MiB of RAM.
    let kernel = image(16 * MIB, b"payload!");
    assert!(mem.write_bytes(RAM_BASE + 40 * MIB, &kernel));
    assert!(mem.write_bytes(RAM_BASE + 48 * MIB, b"initrd"));
    let chan: &'static mut blk::Channel = leak_zeroed();
    chan.capacity_sectors = 2048;
    chan.block_size = 512;
    chan.seg_max = 16;
    chan.ready = 1;
    let chan_ptr = chan as *mut blk::Channel;
    let cfg: &'static mut HvmConfig = leak_zeroed();
    cfg.guest_id = 7;
    cfg.nr_vcpus = 2;
    cfg.low_ram = RAM;
    cfg.ram_base = RAM_BASE;
    cfg.boot_blocks = (RAM / (2 * MIB)) as u32;
    cfg.io_pool_gpa = hv::IO_POOL_GPA;
    cfg.io_pool_size = 32 << 10;
    (cfg.kernel_gpa, cfg.kernel_size) = (RAM_BASE + 40 * MIB, kernel.len() as u64);
    (cfg.initrd_gpa, cfg.initrd_size) = (RAM_BASE + 48 * MIB, 6);
    cfg.cmdline[..15].copy_from_slice(b"console=ttyAMA0");
    cfg.epoch_ns = 1_767_225_600 * 1_000_000_000;
    cfg.arm_virt.gic_version = if v3 { 3 } else { 2 };
    cfg.arm_virt.vgic_vtr = 3;
    cfg.arm_virt.ipa_bits = 40;
    cfg.arm_virt.midr_el1 = 0x410f_d083;
    cfg.arm_virt.id_aa64mmfr0 = 5;
    cfg.cpu_id = [0x11, 0xf0, 0xf, u64::MAX, 0xf00];
    cfg.nr_devices = 1;
    cfg.devices[0].kind = host::VDEV_BLK;
    cfg.devices[0].chan_va = chan_ptr as u64;
    let hz = 1_000_000_000;
    crate::vm::make(cfg, hz, mem).expect("the machine");
    crate::io::init();
    let mem = &vm().mem;

    // ---- Boot: vCPU 0 at the Image's entry, x0 at the tree; vCPU 1 off.
    let mut c0 = as_thread(Some(0), || Vcpu::new(0, Guest::default()));
    let mut c1 = as_thread(Some(1), || Vcpu::new(1, Guest::default()));
    let entry = RAM_BASE + 2 * MIB;
    assert_eq!(pc(&mut c0), entry);
    assert_eq!(c0.hw().s.gprs[0], RAM_BASE, "x0: the device tree");
    assert_eq!(c0.hw().s.gprs[GPR_PSTATE], PSTATE_EL1H_MASKED);
    assert_eq!(c0.hw().s.regs[reg::SCTLR], SCTLR_RESET, "MMU and caches off");
    assert_eq!(c0.hw().s.regs[reg::VMPIDR], 0x8000_0000);
    assert_eq!(c1.hw().s.regs[reg::VMPIDR], 0x8000_0001);
    assert_eq!(c0.hw().s.regs[reg::VPIDR], 0x410f_d083, "the host's MIDR");
    assert_eq!(c0.hw().s.regs[reg::HCR] & HCR_GUEST, HCR_GUEST, "traps WFI and the ID registers");
    assert_eq!(c1.power_state(), (false, false));
    let mut payload = [0u8; 8];
    assert!(mem.read_bytes(entry + 64, &mut payload));
    assert_eq!(&payload, b"payload!", "the Image moved to where it runs");
    let cleaned = sys::CLEANED.lock().unwrap().clone();
    assert!(cleaned.iter().any(|&(g, l)| g == entry && l == 16 * MIB), "the kernel is clean to PoC: {cleaned:x?}");
    assert!(cleaned.iter().any(|&(g, l)| g == RAM_BASE && l != 0), "the tree too");
    assert!(cleaned.contains(&(RAM_BASE + 48 * MIB, 6)), "the initrd too");
    let mut fdt = vec![0u8; 1 << 16];
    assert!(mem.read_bytes(RAM_BASE, &mut fdt));
    let t = parse(&fdt);
    assert_eq!(prop(&t, "chosen", "bootargs").unwrap(), b"console=ttyAMA0\0");
    assert_eq!(prop(&t, "chosen", "linux,initrd-start").unwrap(), (RAM_BASE + 48 * MIB).to_be_bytes());
    let gic: &[u8] = if v3 { b"arm,gic-v3\0" } else { b"arm,cortex-a15-gic\0" };
    assert_eq!(prop(&t, "intc@8000000", "compatible").unwrap(), gic);

    // vCPU 1 waits for CPU_ON; it does not enter the guest.
    let waits = sys::WAITS.load(Ordering::SeqCst);
    turn(&mut c1, 1);
    assert_eq!(sys::WAITS.load(Ordering::SeqCst), waits + 1);
    assert!(c1.hw().loads.is_empty());

    // ---- The first entry loads everything; later ones only what changed.
    step(&mut c0, 0, Exit::Interrupt(0));
    assert_eq!(c0.hw().loads[0], S_ALL);
    step(&mut c0, 0, Exit::Interrupt(0));
    assert_eq!(*c0.hw().loads.last().unwrap(), 0, "nothing changed");

    // ---- RAM not yet touched is mapped, and the access retried.
    let before = pc(&mut c0);
    step(&mut c0, 0, Exit::VmFault { esr: EC_DABT << 26 | IL | 0x7, ipa: RAM_BASE + 20 * MIB, far: 0 });
    assert_eq!(pc(&mut c0), before, "retried");

    // ---- PSCI: discovery, and vCPU 1 started.
    assert_eq!(hvc(&mut c0, 0, PSCI_VERSION, [0; 3]), 1 << 16);
    assert_eq!(hvc(&mut c0, 0, PSCI_AFFINITY_INFO, [1, 0, 0]), 1, "off");
    sys::WOKEN.store(0, Ordering::SeqCst);
    assert_eq!(hvc(&mut c0, 0, PSCI_CPU_ON, [1, RAM_BASE + 0x8000, 0xc0de]), 0);
    assert_ne!(sys::WOKEN.load(Ordering::SeqCst) & 2, 0, "vCPU 1 woken");
    assert_eq!(hvc(&mut c0, 0, PSCI_CPU_ON, [1, 0, 0]) as i64, -5, "on pending");
    step(&mut c1, 1, Exit::Interrupt(0));
    assert_eq!(c1.power_state().0, true);
    assert_eq!(pc(&mut c1), RAM_BASE + 0x8000);
    assert_eq!(c1.hw().s.gprs[0], 0xc0de, "CPU_ON's context in x0");
    assert_eq!(c1.hw().s.gprs[GPR_PSTATE], PSTATE_EL1H_MASKED);
    assert_ne!(c1.hw().loads[0] & S_EL1, 0);
    assert_eq!(hvc(&mut c0, 0, PSCI_AFFINITY_INFO, [1, 0, 0]), 0, "on");
    assert_eq!(hvc(&mut c0, 0, PSCI_CPU_ON, [1, 0, 0]) as i64, -4, "already on");

    // ---- SMC's return address is the SMC: it is stepped over.
    let before = pc(&mut c0);
    c0.hw().s.gprs[0] = PSCI_VERSION;
    step(&mut c0, 0, Exit::VcpuFault { esr: EC_SMC << 26 | IL });
    assert_eq!((pc(&mut c0), c0.hw().s.gprs[0]), (before + 4, 1 << 16));

    // ---- System registers: the ID registers, and what is UNDEFINED.
    let before = pc(&mut c0);
    step(&mut c0, 0, Exit::VcpuFault { esr: sysreg_esr((3, 0, 0, 4, 0), 5, true) });
    assert_eq!(pc(&mut c0), before + 4);
    let pfr0 = c0.hw().s.gprs[5];
    assert_eq!(pfr0 & 0xffff, 0x0011, "EL0 and EL1 only");
    assert_eq!((pfr0 >> 32) & 0xf, 0, "no SVE");
    assert_eq!((pfr0 >> 24) & 0xf, v3 as u64, "the GIC's system registers");
    let (old_pc, old_pstate) = (pc(&mut c0), c0.hw().s.gprs[GPR_PSTATE]);
    step(&mut c0, 0, Exit::VcpuFault { esr: sysreg_esr((3, 0, 0, 4, 0), 5, false) });
    assert_eq!(pc(&mut c0), VBAR + 0x200, "a write to it: UNDEFINED, from EL1h");
    assert_eq!(c0.hw().regs[reg::ELR_EL1], old_pc);
    assert_eq!(c0.hw().regs[reg::SPSR_EL1], old_pstate);
    assert_eq!(c0.hw().regs[reg::ESR] >> 26, 0);
    assert_ne!(c0.hw().regs[reg::ESR] & IL, 0);
    c0.hw().s.gprs[GPR_PC] = old_pc;
    c0.hw().s.gprs[GPR_PSTATE] = 0x3c5;
    // From EL0, the vector is the lower EL's.
    c0.hw().s.gprs[GPR_PSTATE] = 0;
    step(&mut c0, 0, Exit::VcpuFault { esr: sysreg_esr((3, 3, 11, 0, 0), 5, true) });
    assert_eq!(pc(&mut c0), VBAR + 0x400);
    c0.hw().s.gprs[GPR_PC] = old_pc;
    c0.hw().s.gprs[GPR_PSTATE] = 0x3c5;
    // EL0 has no firmware to call, nor the GIC's registers.
    c0.hw().s.gprs[GPR_PSTATE] = 0;
    c0.hw().s.gprs[0] = PSCI_SYSTEM_OFF;
    step(&mut c0, 0, Exit::VcpuFault { esr: EC_SMC << 26 | IL });
    assert_eq!(pc(&mut c0), VBAR + 0x400, "SMC from EL0: UNDEFINED");
    assert_eq!(c0.hw().regs[reg::ESR] >> 26, 0);
    assert_eq!(c0.hw().regs[reg::ELR_EL1], old_pc, "at the SMC");
    assert_eq!(sys::POWER.load(Ordering::SeqCst), 0, "and nothing stopped");
    c0.hw().s.gprs[GPR_PC] = old_pc + 4;
    c0.hw().s.gprs[GPR_PSTATE] = 0;
    step(&mut c0, 0, Exit::VcpuFault { esr: EC_HVC << 26 | IL });
    assert_eq!(pc(&mut c0), VBAR + 0x400, "HVC from EL0 too");
    assert_eq!(c0.hw().regs[reg::ELR_EL1], old_pc, "at the HVC");
    assert_eq!(sys::POWER.load(Ordering::SeqCst), 0);
    c0.hw().s.gprs[GPR_PC] = old_pc;
    c0.hw().s.gprs[GPR_PSTATE] = 0;
    c0.hw().s.gprs[6] = 5 << 24 | 1 << 1;
    sys::WOKEN.store(0, Ordering::SeqCst);
    step(&mut c0, 0, Exit::VcpuFault { esr: sysreg_esr(ICC_SGI1R, 6, false) });
    assert_eq!(pc(&mut c0), VBAR + 0x400, "ICC_SGI1R_EL1 from EL0");
    assert_eq!(sys::WOKEN.load(Ordering::SeqCst), 0, "no SGI");
    c0.hw().s.gprs[GPR_PC] = old_pc;
    c0.hw().s.gprs[GPR_PSTATE] = 0x3c5;
    // ACTLR_EL1, which FL4 traps, is RAZ/WI.
    c0.hw().s.gprs[7] = 0xdead;
    step(&mut c0, 0, Exit::VcpuFault { esr: sysreg_esr((3, 0, 1, 0, 1), 7, true) });
    assert_eq!(c0.hw().s.gprs[7], 0);
    assert_eq!(pc(&mut c0), old_pc + 4);

    // ---- MMIO: the register and width the syndrome names.
    let at = arm::UART_BASE + 0x024;
    let esr = EC_DABT << 26 | IL | ISV | 2 << 22 | 9 << 16 | WNR;
    c0.hw().s.gprs[9] = 0xffff_ffff_0000_0034;
    step(&mut c0, 0, Exit::VmFault { esr, ipa: at, far: 0 });
    assert_eq!(mmio(&mut c0, 0, at, 4, None), 0x34, "IBRD");
    // A sign-extending byte load into a 32-bit register.
    mmio(&mut c0, 0, arm::UART_BASE + 0x024, 4, Some(0xff));
    let esr = EC_DABT << 26 | IL | ISV | 0 << 22 | SSE | 4 << 16;
    step(&mut c0, 0, Exit::VmFault { esr, ipa: at, far: 0 });
    assert_eq!(c0.hw().s.gprs[4], 0xffff_ffff, "sign-extended, in a W register");
    let esr = EC_DABT << 26 | IL | ISV | SSE | 4 << 16 | SF;
    step(&mut c0, 0, Exit::VmFault { esr, ipa: at, far: 0 });
    assert_eq!(c0.hw().s.gprs[4], u64::MAX, "in an X register");
    // XZR: a load discards, a store writes zero.
    let before = c0.hw().s.gprs;
    let esr = EC_DABT << 26 | IL | ISV | 2 << 22 | 31 << 16 | SF;
    step(&mut c0, 0, Exit::VmFault { esr, ipa: at, far: 0 });
    assert_eq!(c0.hw().s.gprs[..31], before[..31]);
    let esr = EC_DABT << 26 | IL | ISV | 2 << 22 | 31 << 16 | WNR;
    step(&mut c0, 0, Exit::VmFault { esr, ipa: at, far: 0 });
    assert_eq!(mmio(&mut c0, 0, at, 4, None), 0);
    // No syndrome for a device: an external abort, not a guess.
    let old = pc(&mut c0);
    step(&mut c0, 0, Exit::VmFault { esr: EC_DABT << 26 | IL, ipa: arm::UART_BASE, far: 0x77 });
    assert_eq!(pc(&mut c0), VBAR + 0x200);
    assert_eq!(c0.hw().regs[reg::ESR] >> 26, 0x25, "from the same EL");
    assert_eq!(c0.hw().regs[reg::FAR], 0x77);
    c0.hw().s.gprs[GPR_PC] = old;
    c0.hw().s.gprs[GPR_PSTATE] = 0x3c5;
    // A fetch from where no RAM is.
    let old = pc(&mut c0);
    step(&mut c0, 0, Exit::VmFault { esr: EC_IABT << 26 | IL, ipa: 0x1000, far: 0x1000 });
    assert_eq!(c0.hw().regs[reg::ESR] >> 26, 0x21);
    c0.hw().s.gprs[GPR_PC] = old;
    c0.hw().s.gprs[GPR_PSTATE] = 0x3c5;
    // A cache maintenance instruction on a device is stepped over.
    let old = pc(&mut c0);
    step(&mut c0, 0, Exit::VmFault { esr: EC_DABT << 26 | IL | 1 << 8 | WNR, ipa: arm::UART_BASE, far: 0 });
    assert_eq!(pc(&mut c0), old + 4);
    // But one whose stage-1 walk hit a device is that walk's abort.
    let old = pc(&mut c0);
    step(&mut c0, 0, Exit::VmFault { esr: EC_DABT << 26 | IL | 1 << 8 | 1 << 7 | WNR, ipa: arm::UART_BASE, far: 0x88 });
    assert_eq!(pc(&mut c0), VBAR + 0x200, "not stepped over");
    assert_eq!(c0.hw().regs[reg::ESR] >> 26, 0x25);
    assert_eq!(c0.hw().regs[reg::ESR] & WNR, 0, "the walk's, not the access's");
    assert_eq!(c0.hw().regs[reg::FAR], 0x88);
    c0.hw().s.gprs[GPR_PC] = old;
    c0.hw().s.gprs[GPR_PSTATE] = 0x3c5;
    // A write the syndrome does not describe: its abort says it was one.
    step(&mut c0, 0, Exit::VmFault { esr: EC_DABT << 26 | IL | WNR, ipa: arm::UART_BASE, far: 0x99 });
    assert_ne!(c0.hw().regs[reg::ESR] & WNR, 0);
    c0.hw().s.gprs[GPR_PC] = old;
    c0.hw().s.gprs[GPR_PSTATE] = 0x3c5;
    // The flags survive an exception taken from EL1.
    c0.hw().s.gprs[GPR_PSTATE] = 0x6000_03c5;
    step(&mut c0, 0, Exit::VmFault { esr: EC_DABT << 26 | IL, ipa: arm::UART_BASE, far: 0 });
    assert_eq!(c0.hw().regs[reg::SPSR_EL1], 0x6000_03c5);
    assert_eq!(c0.hw().s.gprs[GPR_PSTATE], 0x6000_03c5);
    c0.hw().s.gprs[GPR_PC] = old;
    c0.hw().s.gprs[GPR_PSTATE] = 0x3c5;
    // Nothing there reads as ones.
    assert_eq!(mmio(&mut c0, 0, 0x0904_0000, 4, None), 0xffff_ffff);

    // ---- The GIC, as Linux sets it up.
    if v3 {
        for v in 0..2u64 {
            let rd = arm::GICR_BASE + v * arm::GICR_STRIDE;
            assert_eq!(mmio(&mut c0, 0, rd + 0xffe8, 4, None) >> 4 & 0xf, 3);
            mmio(&mut c0, 0, rd + 0x14, 4, Some(0));
            assert_eq!(mmio(&mut c0, 0, rd + 0x14, 4, None), 0, "awake");
        }
        assert_eq!(mmio(&mut c0, 0, arm::GICD_BASE + 0xffe8, 4, None) >> 4 & 0xf, 3);
        mmio(&mut c0, 0, arm::GICD_BASE, 4, Some(0x12));
    } else {
        assert_eq!(mmio(&mut c0, 0, arm::GICD_BASE + 0xfe8, 4, None) >> 4 & 0xf, 2);
        assert_eq!(mmio(&mut c0, 0, arm::V2M_BASE + 8, 4, None), (arm::MSI_BASE as u64) << 16 | arm::MSI_COUNT as u64);
        mmio(&mut c0, 0, arm::GICD_BASE, 4, Some(1));
    }

    // ---- The UART both ways, by its level-sensitive SPI.
    let uart = 32 + arm::UART_SPI;
    enable_spi(&mut c0, uart);
    if !v3 {
        mmio(&mut c0, 0, arm::GICD_BASE + 0x800 + uart as u64, 1, Some(1));
    }
    mmio(&mut c0, 0, arm::UART_BASE + 0x38, 4, Some(1 << 4 | 1 << 6));
    for b in b"hi\n" {
        mmio(&mut c0, 0, arm::UART_BASE, 1, Some(*b as u64));
    }
    assert_eq!(vm().console.head(), 3, "in the console ring");
    let page = hv::CONSOLE_PAGE_VA as *mut abi::ConsolePage;
    unsafe {
        (*page).input[0] = b'!';
        std::ptr::addr_of_mut!((*page).in_head).write_volatile(1);
    }
    sys::WOKEN.store(0, Ordering::SeqCst);
    as_thread(None, crate::io::control);
    assert_ne!(sys::WOKEN.load(Ordering::SeqCst) & 1, 0, "vCPU 0 woken for its input");
    assert_eq!(pending_lrs(&mut c0, 0), [uart], "the UART's interrupt");
    let lr = c0.hw().lrs.last().unwrap()[0];
    assert_ne!(lr & if v3 { LR3_EOI } else { LR2_EOI }, 0, "level-sensitive: looked at again at EOI");
    assert_eq!(mmio(&mut c0, 0, arm::UART_BASE + 0x18, 4, None) & (1 << 4), 0, "RX not empty");
    assert_eq!(mmio(&mut c0, 0, arm::UART_BASE, 4, None), b'!' as u64);
    guest_ends(&mut c0, 0, uart);
    assert_eq!(pending_lrs(&mut c0, 0), [0u32; 0], "the line is down");

    // ---- PCI, and a virtio disk over MSI-X (MBI or GICv2m).
    assert_eq!(cfg_read(&mut c0, 0, 0, 4), 0x0008_1b36, "the host bridge");
    assert_eq!(cfg_read(&mut c0, 1, 0, 4), 0x1042_1af4);
    assert_eq!(cfg_read(&mut c0, 2, 0, 2), 0xffff, "an empty slot");
    assert_eq!(cfg_read(&mut c0, 30, 0, 4), 0x1043_1af4, "the kernel configuration port's console");
    let spi = arm::MSI_BASE;
    edge_spi(&mut c0, spi);
    edge_spi(&mut c0, spi + 1);
    let rings = RAM_BASE + 0x100_0000;
    let bar0 = virtio_up(&mut c0, 1, spi, 1, rings);
    let (req, data, st) = (RAM_BASE + 0x130_0000, RAM_BASE + 0x131_0000, RAM_BASE + 0x130_0100);
    mem.write::<u32>(req, 1);
    mem.write::<u64>(req + 8, 4);
    mem.write_bytes(data, &[0xa5; 1024]);
    desc(mem, rings, 0, req, 16, 1, 1);
    desc(mem, rings, 1, data, 1024, 1, 2);
    desc(mem, rings, 2, st, 1, 2, 0);
    post(mem, rings, 0, 1);
    sys::IO_SIGNALS.store(0, Ordering::SeqCst);
    mmio(&mut c0, 0, bar0 + 0x16, 2, Some(0));
    let off = mmio(&mut c0, 0, bar0 + 0x1e, 2, None);
    mmio(&mut c0, 0, bar0 + crate::dev::virtio_pci::NOTIFY + off * crate::dev::virtio_pci::NOTIFY_MULTIPLIER, 2, Some(0));
    assert_ne!(sys::IO_SIGNALS.load(Ordering::SeqCst) & badges::hvm::KICK, 0, "a notification only signals");
    assert_ne!(vm().kicks.0[1].load(Ordering::SeqCst) & 1, 0, "and posts the queue's bit");
    let mut disk = vec![0u8; 2048 * 512];
    as_thread(None, crate::io::kicked);
    assert_eq!(blkd(unsafe { &mut *chan_ptr }, &mut disk), 1, "the request reached blkd");
    sys::WOKEN.store(0, Ordering::SeqCst);
    as_thread(None, crate::io::completed);
    assert!(disk[2048..3072].iter().all(|&b| b == 0xa5), "on the disk");
    assert_eq!(mem.read::<u8>(st), 0, "status OK");
    assert_ne!(sys::WOKEN.load(Ordering::SeqCst) & 1, 0, "vCPU 0 woken for its MSI-X");
    assert_eq!(pending_lrs(&mut c0, 0), [spi], "queue 0's vector");
    let lr = *c0.hw().lrs.last().unwrap();
    let lr = lr.iter().find(|&&l| l as u32 & 0x3ff == spi).unwrap();
    assert_eq!(lr & if v3 { LR3_EOI } else { LR2_EOI }, 0, "an edge: no maintenance interrupt");
    guest_ends(&mut c0, 0, spi);

    // ---- An SGI from vCPU 0 to vCPU 1.
    enable_local(&mut c1, 1, 5);
    sys::WOKEN.store(0, Ordering::SeqCst);
    if v3 {
        c0.hw().s.gprs[6] = 5 << 24 | 1 << 1;
        step(&mut c0, 0, Exit::VcpuFault { esr: sysreg_esr(ICC_SGI1R, 6, false) });
    } else {
        mmio(&mut c0, 0, arm::GICD_BASE + 0xf00, 4, Some(2 << 16 | 5));
    }
    assert_ne!(sys::WOKEN.load(Ordering::SeqCst) & 2, 0, "vCPU 1 woken");
    assert_eq!(pending_lrs(&mut c1, 1), [5]);
    guest_ends(&mut c1, 1, 5);

    // ---- The virtual timer: its PPI while it holds, masked at the host's
    // GIC so that it is one exit per tick.
    enable_local(&mut c0, 0, PPI_VTIMER);
    let t0 = sys::now() + 1000;
    {
        let s = &mut c0.hw().s;
        s.regs[reg::CNTV_CTL] = CNTV_ENABLE;
        s.regs[reg::CNTV_CVAL] = t0;
    }
    step(&mut c0, 0, Exit::Interrupt(0));
    assert_eq!(*c0.hw().loads.last().unwrap() & S_TIMER, 0, "not due: no change");
    sys::NOW.store(t0, Ordering::SeqCst);
    c0.hw().s.vppi_masked = 1;
    assert_eq!(pending_lrs(&mut c0, 0), [PPI_VTIMER], "due");
    assert_eq!(c0.hw().s.vppi_masked, 1, "stays masked while it holds");
    // The handler moves it on and ends the interrupt: unmasked.
    c0.hw().s.regs[reg::CNTV_CVAL] = t0 + 5000;
    guest_ends(&mut c0, 0, PPI_VTIMER);
    assert_eq!(c0.hw().s.vppi_masked, 0);
    assert_ne!(*c0.hw().loads.last().unwrap() & S_TIMER, 0, "unmasked by that entry");

    // ---- WFI: with nothing pending it waits, its seL4 timer at the tick.
    let before = pc(&mut c0);
    step(&mut c0, 0, Exit::VcpuFault { esr: EC_WFX << 26 | IL });
    assert_eq!(pc(&mut c0), before + 4);
    assert_eq!(c0.power_state().1, true, "in WFI");
    let (waits, entries) = (sys::WAITS.load(Ordering::SeqCst), c0.hw().loads.len());
    turn(&mut c0, 0);
    assert_eq!(sys::WAITS.load(Ordering::SeqCst), waits + 1, "it waited");
    assert_eq!(c0.hw().loads.len(), entries, "and did not enter the guest");
    assert_eq!(sys::VCPU_TIMERS[0].load(Ordering::SeqCst), t0 + 5000, "until the guest's deadline");
    // The deadline passes: it goes back in, with the tick.
    sys::NOW.store(t0 + 5000, Ordering::SeqCst);
    assert_eq!(pending_lrs(&mut c0, 0), [PPI_VTIMER]);
    assert_eq!(c0.power_state().1, false);
    c0.hw().s.regs[reg::CNTV_CTL] = 0;
    guest_ends(&mut c0, 0, PPI_VTIMER);

    // ---- vCPU 1 sets the RTC's match; vCPU 0, which watches it, is in WFI.
    let rtc = 32 + arm::RTC_SPI;
    enable_spi(&mut c0, rtc);
    if !v3 {
        mmio(&mut c0, 0, arm::GICD_BASE + 0x800 + rtc as u64, 1, Some(1));
    }
    step(&mut c0, 0, Exit::VcpuFault { esr: EC_WFX << 26 | IL });
    turn(&mut c0, 0);
    let secs = mmio(&mut c1, 1, arm::RTC_BASE, 4, None);
    mmio(&mut c1, 1, arm::RTC_BASE + 0x10, 4, Some(1));
    sys::WOKEN.store(0, Ordering::SeqCst);
    mmio(&mut c1, 1, arm::RTC_BASE + 0x04, 4, Some(secs + 5));
    assert_ne!(sys::WOKEN.load(Ordering::SeqCst) & 1, 0, "vCPU 0 is told of the new match");
    let waits = sys::WAITS.load(Ordering::SeqCst);
    turn(&mut c0, 0);
    assert_eq!(sys::WAITS.load(Ordering::SeqCst), waits + 1, "and waits again");
    let due = sys::VCPU_TIMERS[0].load(Ordering::SeqCst);
    assert_eq!(due, sys::now() + 5 * hz, "until it");
    sys::NOW.store(due, Ordering::SeqCst);
    assert_eq!(pending_lrs(&mut c0, 0), [rtc]);
    mmio(&mut c0, 0, arm::RTC_BASE + 0x1c, 4, Some(1));
    guest_ends(&mut c0, 0, rtc);

    // ---- vCPU 1 powers itself off, and can be started again.
    assert_eq!(hvc(&mut c1, 1, PSCI_CPU_OFF, [0; 3]), 0);
    assert_eq!(c1.power_state().0, false);
    assert_eq!(hvc(&mut c0, 0, PSCI_AFFINITY_INFO, [1, 0, 0]), 1);
    assert_eq!(hvc(&mut c0, 0, PSCI_CPU_ON, [1, RAM_BASE + 0x9000, 3]), 0);
    step(&mut c1, 1, Exit::Interrupt(0));
    assert_eq!((pc(&mut c1), c1.hw().s.gprs[0]), (RAM_BASE + 0x9000, 3));

    // ---- The power button: a GPIO edge the guest takes, then PSCI.
    let gpio = 32 + arm::GPIO_SPI;
    enable_spi(&mut c0, gpio);
    if !v3 {
        mmio(&mut c0, 0, arm::GICD_BASE + 0x800 + gpio as u64, 1, Some(1));
    }
    let pin = 1u64 << crate::arm::pl061::PIN_POWER;
    mmio(&mut c0, 0, arm::GPIO_BASE + 0x408, 4, Some(pin));
    mmio(&mut c0, 0, arm::GPIO_BASE + 0x410, 4, Some(pin));
    unsafe { std::ptr::addr_of_mut!((*page).power_request).write_volatile(abi::POWER_OFF as u32 + 1) };
    sys::WOKEN.store(0, Ordering::SeqCst);
    as_thread(None, crate::io::control);
    assert_ne!(sys::WOKEN.load(Ordering::SeqCst) & 1, 0, "vCPU 0 woken for the button");
    assert_eq!(pending_lrs(&mut c0, 0), [gpio]);
    assert_eq!(mmio(&mut c0, 0, arm::GPIO_BASE + (pin << 2), 4, None), pin, "the pin reads pressed");
    assert_eq!(mmio(&mut c0, 0, arm::GPIO_BASE + 0x418, 4, None), pin);
    mmio(&mut c0, 0, arm::GPIO_BASE + 0x41c, 4, Some(pin));
    guest_ends(&mut c0, 0, gpio);
    assert_eq!(pending_lrs(&mut c0, 0), [0u32; 0], "the edge was cleared");
    // A second press is a new edge, though the pin stayed high.
    unsafe { std::ptr::addr_of_mut!((*page).power_request).write_volatile(abi::POWER_OFF as u32 + 1) };
    as_thread(None, crate::io::control);
    assert_eq!(pending_lrs(&mut c0, 0), [gpio], "pressed again");
    assert_eq!(mmio(&mut c0, 0, arm::GPIO_BASE + (pin << 2), 4, None), pin);
    mmio(&mut c0, 0, arm::GPIO_BASE + 0x41c, 4, Some(pin));
    guest_ends(&mut c0, 0, gpio);
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        hvc(&mut c0, 0, PSCI_SYSTEM_OFF, [0; 3]);
    }));
    assert!(stopped.is_err());
    assert_eq!(sys::POWER.load(Ordering::SeqCst), abi::POWER_OFF + 1, "powered off");
}
