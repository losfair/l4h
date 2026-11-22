//! l4h-hvm, a guest's hardware-virtualized machine monitor (DESIGN.md
//! §5.11): its configuration, address space and CSpace layout, and the
//! calls its vCPU threads make to its I/O thread.
//!
//! An HVM guest runs an unmodified x86-64 kernel in VT-x or AMD-V guest
//! mode, on seL4 VCPUs that l4h-hvm's own threads enter: one thread per
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
}
