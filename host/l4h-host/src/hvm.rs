//! l4h-hvm, a guest's hardware-virtualized machine monitor (DESIGN.md
//! §5.11): its configuration, address space and CSpace layout, and the
//! calls its vCPU threads make to its I/O thread.
//!
//! An HVM guest runs an unmodified kernel in hardware guest mode (x86-64 on
//! VT-x or AMD-V, AArch64 at EL1 under FL4 at EL2: its layout is `arm`), on
//! seL4 VCPUs that l4h-hvm's own threads enter: one thread per
//! vCPU, and one I/O thread that serves the devices' backends (blkd,
//! netd), the console and the slow paths of the virtual platform.  Unlike
//! l4h-vmm it maps its guest's RAM, which it reads to emulate devices and
//! instructions; it is trusted by its guest only, and confined like the
//! guest: its threads have a maximum controlled priority of PRIO_KERNEL,
//! below the debug syscalls' threshold (DESIGN.md §4.1).

use l4h_abi as abi;

use crate::badges::hvm as recv;

/// The I/O thread's priority (as a VMM's) and the maximum controlled
/// priority of every thread of the component: a guest that took over its
/// l4h-hvm gets no more authority than a guest kernel has.
pub const PRIO_IO: u64 = crate::PRIO_VMM;
pub const MCP: u64 = abi::PRIO_KERNEL;
const _: () = assert!(MCP == abi::PRIO_KERNEL && PRIO_IO > MCP);

/// Guest-physical layout.  RAM below the 32-bit hole, [0, LOW_RAM_MAX),
/// and the rest from 4 GiB on; the hole holds the PCI MMIO window, ECAM,
/// the I/O APIC and the local APICs, which the EPT never maps.
pub const LOW_RAM_MAX: u64 = 3 << 30;
pub const HIGH_RAM_BASE: u64 = 4 << 30;
pub const PCI_MMIO_BASE: u64 = 0xc000_0000;
pub const PCI_MMIO_SIZE: u64 = 0x2000_0000;
pub const ECAM_BASE: u64 = 0xe000_0000;
pub const ECAM_SIZE: u64 = 1 << 20;
pub const IOAPIC_BASE: u64 = 0xfec0_0000;
pub const LAPIC_BASE: u64 = 0xfee0_0000;
const _: () = assert!(PCI_MMIO_BASE >= LOW_RAM_MAX && PCI_MMIO_BASE + PCI_MMIO_SIZE <= ECAM_BASE);
const _: () = assert!(ECAM_BASE + ECAM_SIZE <= IOAPIC_BASE && IOAPIC_BASE < LAPIC_BASE);

/// Guest RAM of an HVM guest: at least this much, and at most RAM_MAX
/// (whole 2 MiB blocks), which the block CNodes' radix bounds.
pub const RAM_MIN: u64 = 32 << 20;
pub const RAM_MAX: u64 = (abi::MAX_BLOCKS * abi::BLOCK_SIZE) as u64;
/// An HVM guest's default I/O pool: its disks bounce whole requests
/// through it (DESIGN.md §5.11).
pub const IO_POOL_DEFAULT: u64 = 8 << 20;
/// Devices an HVM guest has at most: PCI slots 1 to 31 of bus 0 (slot 0 is
/// the host bridge).
pub const MAX_DEVICES: usize = 31;
/// vCPUs at most: their APIC IDs fit xAPIC's 8 bits, and MSI and the I/O
/// APIC can address every one in physical mode.
pub const MAX_VCPUS: usize = abi::MAX_VCPUS;
const _: () = assert!(MAX_VCPUS < 255);

/// The guest-physical address an HVM guest's I/O pool has for blkd: outside
/// any guest's RAM, as no guest maps the pool.  l4h-hvm bounces disk data
/// through the pool, at HVM's IO_POOL_VA.
pub const IO_POOL_GPA: u64 = 1 << 46;
const _: () = assert!(IO_POOL_GPA >= HIGH_RAM_BASE + RAM_MAX);

/// An AArch64 HVM guest's guest-physical layout: devices below 1 GiB, and
/// its RAM in one range from RAM_BASE (no hole).  Nothing here is mapped
/// but the RAM and, on GICv2, the GICC page: the host's GICV, which the
/// guest uses directly.
pub mod arm {
    pub const GICD_BASE: u64 = 0x0800_0000;
    pub const GICD_SIZE: u64 = 0x1_0000;
    /// GICv2: the CPU interface, the host's two GICV frames.
    pub const GICC_BASE: u64 = 0x0801_0000;
    pub const GICC_SIZE: u64 = 0x2000;
    /// GICv2: the GICv2m MSI frame.
    pub const V2M_BASE: u64 = 0x0802_0000;
    pub const V2M_SIZE: u64 = 0x1000;
    /// GICv3: the redistributors, GICR_STRIDE each.
    pub const GICR_BASE: u64 = 0x080a_0000;
    pub const GICR_STRIDE: u64 = 0x2_0000;
    pub const GICR_SIZE: u64 = super::MAX_VCPUS as u64 * GICR_STRIDE;
    pub const UART_BASE: u64 = 0x0900_0000;
    pub const RTC_BASE: u64 = 0x0901_0000;
    pub const GPIO_BASE: u64 = 0x0903_0000;
    pub const PRIMECELL_SIZE: u64 = 0x1000;
    pub const PCI_MMIO_BASE: u64 = 0x1000_0000;
    pub const PCI_MMIO_SIZE: u64 = 0x2000_0000;
    pub const ECAM_BASE: u64 = 0x3f00_0000;
    pub const ECAM_SIZE: u64 = 1 << 20;
    pub const RAM_BASE: u64 = 0x4000_0000;

    /// SPIs (INTID - 32) of the platform's devices, and of PCI's INTA#-INTD#
    /// (QEMU virt's numbers for the first three).
    pub const UART_SPI: u32 = 1;
    pub const RTC_SPI: u32 = 2;
    pub const GPIO_SPI: u32 = 3;
    pub const PCI_INTX_SPI: u32 = 4;
    pub const PCI_INTX_LINES: u32 = 4;
    /// The SPIs MSIs may use (GICv3's MBI, GICv2m): INTIDs from MSI_BASE.
    pub const MSI_BASE: u32 = 64;
    pub const MSI_COUNT: u32 = NR_IRQS - MSI_BASE;
    /// The INTIDs a guest's GIC has (GICD_TYPER.ITLinesNumber's granule).
    pub const NR_IRQS: u32 = 512;
    /// The most vCPUs GICv2 can target (ITARGETSR's 8 bits).
    pub const GICV2_MAX_VCPUS: usize = 8;

    /// The VCPU state area in a vCPU thread's IPC buffer frame
    /// (seL4_ARM_VCPU_Run), after the message registers.
    pub const VCPU_STATE_OFFSET: usize = 2048;
    pub const VCPU_STATE_SIZE: usize = 1024;

    /// vCPU `v`'s MPIDR affinity: Aff0 has 16 vCPUs, as GICv3's SGI target
    /// lists do; Aff1 the rest.
    pub const fn mpidr_aff(v: usize) -> u64 {
        ((v as u64 >> 4) << 8) | (v as u64 & 0xf)
    }

    /// The vCPU whose MPIDR affinity is `aff`, if it has one (`nr` vCPUs).
    pub const fn vcpu_of_aff(aff: u64, nr: usize) -> Option<usize> {
        if aff & !0xffff != 0 || aff & 0xf0 != 0 {
            return None;
        }
        let v = (((aff >> 8) & 0xff) << 4 | (aff & 0xf)) as usize;
        if v < nr { Some(v) } else { None }
    }

    const _: () = assert!(GICD_BASE + GICD_SIZE <= GICC_BASE && GICC_BASE + GICC_SIZE <= V2M_BASE);
    const _: () = assert!(V2M_BASE + V2M_SIZE <= GICR_BASE && GICR_BASE + GICR_SIZE <= UART_BASE);
    const _: () = assert!(UART_BASE + PRIMECELL_SIZE <= RTC_BASE && RTC_BASE + PRIMECELL_SIZE <= GPIO_BASE);
    const _: () = assert!(GPIO_BASE + PRIMECELL_SIZE <= PCI_MMIO_BASE);
    const _: () = assert!(PCI_MMIO_BASE + PCI_MMIO_SIZE <= ECAM_BASE && ECAM_BASE + ECAM_SIZE <= RAM_BASE);
    const _: () = assert!(RAM_BASE + super::RAM_MAX <= super::IO_POOL_GPA);
    const _: () = assert!(RAM_BASE as usize + super::RAM_MAX as usize <= super::RAM_VA);
    const _: () = assert!(VCPU_STATE_OFFSET + VCPU_STATE_SIZE <= 4096 && VCPU_STATE_OFFSET.is_multiple_of(64));
    const _: () = assert!(MSI_BASE >= 32 + PCI_INTX_SPI + PCI_INTX_LINES && NR_IRQS <= 1020 && NR_IRQS.is_multiple_of(32));
}

/// The guest-physical address of RAM offset `off` (the RAM's byte `off`,
/// in block order): low RAM first, the rest above 4 GiB.
pub const fn ram_gpa(low_ram: u64, off: u64) -> u64 {
    if off < low_ram { off } else { off - low_ram + HIGH_RAM_BASE }
}

/// RAM below the hole for `ram` bytes of guest RAM.
pub const fn low_ram(ram: u64) -> u64 {
    if ram < LOW_RAM_MAX { ram } else { LOW_RAM_MAX }
}

// ---- Its address space, besides the component layout (crate::INFO_VA, the
// I/O thread's stack, crate::SHARED_VA for its device, event and channel
// pages as the VMM's).

/// Guest RAM: GPA g at RAM_VA + g, low and high RAM alike (the hole is not
/// mapped).  vmmgr maps the boot blocks, l4h-hvm the others as the guest
/// first touches them.
pub const RAM_VA: usize = 0x5000_0000_0000;
const _: () = assert!(RAM_VA as u64 + HIGH_RAM_BASE + RAM_MAX <= 0x6000_0000_0000);
const _: () = assert!(RAM_VA as u64 + arm::RAM_BASE + RAM_MAX <= 0x6000_0000_0000);
/// The I/O pool, for blkd's bounce buffers.
pub const IO_POOL_VA: usize = crate::IO_POOL_VA;
/// vCPU v's stack, TLS and IPC buffer: VCPU_VA + v * VCPU_STRIDE, a guard
/// page below the stack.
pub const VCPU_VA: usize = 0x1200_0000;
pub const VCPU_STRIDE: usize = 0x2_0000;
pub const VCPU_STACK_SIZE: usize = 64 << 10;
pub const VCPU_TLS_SIZE: usize = 4096;
pub const fn vcpu_stack_top(v: usize) -> usize {
    VCPU_VA + v * VCPU_STRIDE + 4096 + VCPU_STACK_SIZE
}
pub const fn vcpu_tls_va(v: usize) -> usize {
    vcpu_stack_top(v)
}
pub const fn vcpu_ipcbuf_va(v: usize) -> usize {
    vcpu_tls_va(v) + VCPU_TLS_SIZE
}
const _: () = assert!(vcpu_ipcbuf_va(0) + 4096 <= VCPU_VA + VCPU_STRIDE);
const _: () = assert!(VCPU_VA >= crate::STACK_TOP && VCPU_VA + MAX_VCPUS * VCPU_STRIDE <= crate::SHARED_VA);
/// The console device's page (abi::ConsolePage): vmmgr writes input and
/// power requests there.
pub const CONSOLE_PAGE_VA: usize = crate::SHARED_VA + 0x90_0000;
const _: () = assert!(CONSOLE_PAGE_VA >= crate::VMM_CONSOLE_RING_VA + crate::CONSOLE_RING_PAGES * 4096);
const _: () = assert!(CONSOLE_PAGE_VA + 4096 <= crate::vmm_device_page_va(0));

// ---- Its CSpace, after the standard slots (crate::SLOT_*).  SLOT_ROOT_EP
// calls vmmgr, as a VMM's does; SLOT_SERVICE_EP is the I/O thread's
// endpoint, which its vCPU threads call (SLOT_SELF_CALL).

/// The guest's EPT root (an EPT PML4).
pub const SLOT_EPT: u64 = 16;
/// memd's block CNode (radix HvmConfig::block_radix, no guard): block b's
/// Untyped at index b, for b >= boot_blocks.
pub const SLOT_BLOCKS: u64 = 17;
/// The 2 MiB frames of the blocks, slot b each, as mapped in the EPT and
/// here (radix block_radix, no guard).
pub const SLOT_KEEP_EPT: u64 = 18;
pub const SLOT_KEEP_HVM: u64 = 19;
/// Scratch slots for mapping a block: its Untyped while it is retyped, and
/// its two frames until they are mapped.
pub const SLOT_SCRATCH_UT: u64 = 20;
pub const SLOT_SCRATCH_EPT: u64 = 21;
pub const SLOT_SCRATCH_HVM: u64 = 22;
/// The vCPU threads' signals to the I/O thread: a device kick, console
/// output (wiring::HVM_KICK, HVM_CONSOLE).
pub const SLOT_SELF_KICK: u64 = 24;
pub const SLOT_SELF_CONSOLE: u64 = 25;
/// The vCPU threads' calls to the I/O thread (wiring::HVM_CALL, `call`).
pub const SLOT_SELF_CALL: u64 = 26;
/// vCPU v's notification, to signal it (wiring::HVM_VCPU):
/// crate::VCPU_NTFN_SLOT_BASE + v.  Backend kicks follow, as for a VMM,
/// at crate::VMM_KICK_SLOT_BASE + device.
pub use crate::{VCPU_NTFN_SLOT_BASE, VMM_KICK_SLOT_BASE};
/// vCPU v's bound notification, which its thread waits on in HLT (its
/// own: wiring::OWN), its TCB and its VCPU object.
pub const SLOT_VCPU_WAIT: u64 = 256;
pub const SLOT_VCPU_TCB: u64 = SLOT_VCPU_WAIT + MAX_VCPUS as u64;
pub const SLOT_VCPU_OBJ: u64 = SLOT_VCPU_TCB + MAX_VCPUS as u64;
const _: () = assert!(VMM_KICK_SLOT_BASE + abi::MAX_DEVICES as u64 <= SLOT_VCPU_WAIT);
const _: () = assert!(SLOT_VCPU_OBJ + MAX_VCPUS as u64 <= 1 << crate::CNODE_BITS);

/// One device, as for a VMM (crate::VmmDevice): VDEV_BLK, VDEV_NET or
/// VDEV_BLK_UNAVAILABLE.  It is PCI device `index + 1` of bus 0.
pub use crate::VmmDevice as HvmDevice;

/// l4h-hvm's configuration, which vmmgr writes into its info page.
#[repr(C)]
pub struct HvmConfig {
    pub guest_id: u32,
    pub nr_vcpus: u32,
    /// Bytes of RAM below the hole and from 4 GiB on (2 MiB multiples).
    pub low_ram: u64,
    pub high_ram: u64,
    /// Blocks [0, boot_blocks) vmmgr mapped, in the EPT and here; memd gave
    /// the others to SLOT_BLOCKS.
    pub boot_blocks: u32,
    /// Radix of the block CNodes.
    pub block_radix: u32,
    /// The I/O pool, as blkd knows it (IO_POOL_GPA), mapped at IO_POOL_VA.
    pub io_pool_gpa: u64,
    pub io_pool_size: u64,
    /// What dom0 loaded (CTL_VM_START): the kernel image (bzImage or ELF)
    /// and the initrd, in guest RAM.
    pub kernel_gpa: u64,
    pub kernel_size: u64,
    pub initrd_gpa: u64,
    pub initrd_size: u64,
    /// abi::HVM_BOOT_*.
    pub boot_flags: u64,
    /// Wall clock (ns since the Unix epoch, 0 if unknown) at tick count
    /// epoch_ticks, for the RTC.
    pub epoch_ns: u64,
    pub epoch_ticks: u64,
    pub nr_devices: u32,
    /// Copy console output to the host serial port (with a prefix).
    pub serial: u32,
    pub devices: [HvmDevice; MAX_DEVICES],
    /// The kernel command line, NUL-terminated.
    pub cmdline: [u8; abi::CMDLINE_SIZE],
    /// The GPA of the RAM's first byte: 0 on x86-64, arm::RAM_BASE on
    /// AArch64, whose RAM is all in `low_ram`.
    pub ram_base: u64,
    /// AArch64: the host's virtualization and ID registers, which what the
    /// guest reads of them is made from.  Zero on x86-64.
    pub arm_virt: abi::ArmVirtInfo,
    pub cpu_id: [u64; 5],
}
const _: () = assert!(crate::CONFIG_OFFSET + core::mem::size_of::<HvmConfig>() <= crate::INFO_SIZE);

/// Whether the guest-physical range [gpa, gpa + len) is RAM of a guest
/// with `low` and `high` bytes below and above the hole, all on one side.
pub const fn is_ram(low: u64, high: u64, gpa: u64, len: u64) -> bool {
    let Some(end) = gpa.checked_add(len) else { return false };
    (end <= low) || (gpa >= HIGH_RAM_BASE && end - HIGH_RAM_BASE <= high)
}

crate::senders! {
    /// Who calls the I/O thread: its own vCPU threads (SLOT_SELF_CALL).
    pub enum Sender in recv {
        Vcpu: [CALL];
    }
}

crate::protocol! {
    /// The vCPU threads' calls to the I/O thread, for what only it may
    /// change: the PCI devices' registers and configuration space, whose
    /// state the device models and their backends share (DESIGN.md §5.11).
    pub mod call (from: Sender) {
        /// Read (`write` false) or write `size` bytes at `addr` of device
        /// space `space` (SPACE_*): what a read returns.
        Access / access = 1 from [Vcpu] (vcpu: usize, space: u32, addr: u64, size: u8, write: bool, value: u64) -> u64;
        /// Map RAM block `block` (its 2 MiB frame, in the EPT and here), if
        /// it is not yet: the I/O thread maps every block, so that no
        /// thread waits for another that a higher priority keeps off its
        /// core.
        Map / map = 2 from [Vcpu] (block: usize) -> ();
    }
}

/// Address spaces of call::Access: PCI configuration space (ECAM offset,
/// bus 0), and guest-physical MMIO of the PCI devices' BARs.
pub const SPACE_CONFIG: u32 = 0;
pub const SPACE_MMIO: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ram_layout() {
        assert_eq!(low_ram(1 << 30), 1 << 30);
        assert_eq!(low_ram(8 << 30), LOW_RAM_MAX);
        assert_eq!(ram_gpa(LOW_RAM_MAX, 0), 0);
        assert_eq!(ram_gpa(LOW_RAM_MAX, LOW_RAM_MAX), HIGH_RAM_BASE);
        assert!(is_ram(1 << 30, 0, 0, 1 << 30));
        assert!(!is_ram(1 << 30, 0, 0, (1 << 30) + 1));
        assert!(!is_ram(LOW_RAM_MAX, 1 << 30, LOW_RAM_MAX - 4096, 8192));
        assert!(is_ram(LOW_RAM_MAX, 1 << 30, HIGH_RAM_BASE, 1 << 30));
        assert!(!is_ram(LOW_RAM_MAX, 1 << 30, HIGH_RAM_BASE, (1 << 30) + 1));
        assert!(!is_ram(LOW_RAM_MAX, 1 << 30, u64::MAX - 1, 4));
        assert_eq!(Sender::of_badge(recv::CALL), Some(Sender::Vcpu));
    }

    #[test]
    fn arm_affinity() {
        for v in 0..MAX_VCPUS {
            assert_eq!(arm::vcpu_of_aff(arm::mpidr_aff(v), MAX_VCPUS), Some(v));
        }
        assert_eq!(arm::mpidr_aff(17), 0x101);
        assert_eq!(arm::vcpu_of_aff(0x101, 17), None, "past the last vCPU");
        assert_eq!(arm::vcpu_of_aff(0x10, MAX_VCPUS), None, "Aff0 has 16");
        assert_eq!(arm::vcpu_of_aff(1 << 16, MAX_VCPUS), None, "no Aff2");
    }
}
