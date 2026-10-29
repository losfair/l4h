//! The root task's own address space: every region that l4h-root maps at
//! a fixed address, in one table.  A region's size is the most that may be
//! mapped in it, and whoever maps there keeps within it.  The regions are
//! checked at compile time to be disjoint and below the top of user
//! address space: two modules once chose the same address for different
//! mappings, and root failed at boot only on hosts with a module image.
//!
//! Component address spaces are laid out in `l4h_host` (vmmgr's also in its
//! layout.rs), guests' in `include/l4h/abi.h`.

/// A region of the root task's address space: [base, base + size).
pub struct Region {
    pub base: usize,
    pub size: usize,
}

impl Region {
    pub const fn end(&self) -> usize {
        self.base + self.size
    }
}

const PAGE: usize = 4096;
const MIB: usize = 1 << 20;
const GIB: usize = 1 << 30;

/// seL4_UserTop: x86_64, and aarch64 without hypervisor mode.
const USER_TOP: usize = 0x0000_7fff_ffff_f000;

macro_rules! regions {
    ($($(#[$doc:meta])* $name:ident = $base:expr, $size:expr;)*) => {
        $($(#[$doc])* pub const $name: Region = Region { base: $base, size: $size };)*

        const ALL: &[(&str, Region)] = &[$((stringify!($name), $name)),*];

        $(const _: () = assert!(
            is_free($name.base, $name.size, stringify!($name)),
            concat!("root address space: ", stringify!($name), " overlaps another region or user space ends below it"),
        );)*
    };
}

/// Whether [base, base + size), the region called `name`, is within user
/// space and overlaps no other region.
const fn is_free(base: usize, size: usize, name: &str) -> bool {
    if size == 0 || base.checked_add(size).is_none() || base + size > USER_TOP {
        return false;
    }
    let mut i = 0;
    while i < ALL.len() {
        let (other, r) = (ALL[i].0, &ALL[i].1);
        if !same(other, name) && base < r.end() && r.base < base + size {
            return false;
        }
        i += 1;
    }
    true
}

const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

regions! {
    /// The root task's image, its IPC buffer and boot info, which seL4
    /// places right after the image (`check_image` at boot).
    IMAGE = 0, 0x1000_0000_0000;
    /// aarch64: PCI ECAM, 16 MiB for buses 0-15 (QEMU virt).
    ECAM = 0x6000_0000_0000, 16 * MIB;
    /// aarch64: the PL011 UART of the serial monitor.
    UART = 0x6000_0200_0000, PAGE;
    /// The two windows on frames of guests and components (window.rs).
    WINDOWS = 0x7000_0000_0000, 2 * PAGE;
    /// The events, status, result and attestation pages root shares with
    /// vmmgr (vmmgr.rs).
    VMMGR_PAGES = 0x7100_0000_0000, 4 * PAGE;
    /// dom0's control data area (CTL_BLK_WRITE source), read-only.
    CTL_DATA = 0x7180_0000_0000, l4h_abi::CTL_LOAD_MAX as usize;
    /// The boot framebuffer (dashboard.rs).
    FRAMEBUFFER = 0x7200_0000_0000, GIB;
    /// The boot loader's modules, one after another (bootmod.rs).
    MODULES = 0x7300_0000_0000, 64 * GIB;
    /// Temporary contiguous views of the files staged for host kexec.
    KEXEC_LOAD = 0x7400_0000_0000, 129 * MIB;
    /// trustd's guest registry (trustd.rs).
    TRUSTD_REGISTRY = 0x7500_0000_0000, PAGE;
    /// trustd flags, read-only in root.
    TRUSTD_FLAGS = 0x7500_0001_0000, l4h_host::trust::FLAGS_SIZE;
    /// trustd's private kexec state, shared only with root.
    TRUSTD_KEXEC = 0x7500_0002_0000, PAGE;
    /// One asynchronous disk flush request page per controller.
    BLKD_FLUSH = 0x7500_0003_0000, crate::pci::MAX_DISK_CTRLS * PAGE;
    /// memd's status page (memd.rs).
    MEMD_STATUS = 0x7700_0000_0000, PAGE;
    /// IOMMU registers: 16 KiB per AMD-Vi unit, 64 KiB per VT-d unit.
    IOMMU_MMIO = 0x7800_0000_0000, MIB;
    /// The IOMMUs' device table, I/O page tables, command buffers and
    /// event logs, in 2 MiB chunks (amdvi.rs, vtd.rs): page tables for 4 TiB.
    IOMMU_TABLES = 0x7900_0000_0000, 8 * GIB;
}

/// Check that what seL4 mapped for the root task (image, IPC buffer, boot
/// info) lies in IMAGE.
pub fn check_image(bootinfo: &sel4::BootInfoPtr) {
    let ipc = bootinfo.ipc_buffer() as usize;
    let bi = bootinfo.ptr() as usize;
    for (what, va) in [("IPC buffer", ipc), ("boot info", bi)] {
        assert!(va < IMAGE.end(), "l4h-root: {} at {:#x}, outside its region", what, va);
    }
}

/// The lowest page of the root task's image, where its ELF header is:
/// seL4 gives the image's frames in order from it (`user_image_frames`).
pub fn image_base() -> usize {
    unsafe extern "C" {
        static __ehdr_start: u8;
    }
    (&raw const __ehdr_start) as usize & !(PAGE - 1)
}

/// Unmap the lowest whole page of the root task's stack, which is in
/// .bss among other statics: an overflow then faults instead of writing
/// over them.  Stack probes touch every page of a large frame in order,
/// so one page catches any overflow.
pub fn guard_stack(bootinfo: &sel4::BootInfoPtr) {
    unsafe extern "C" {
        /// The top of the stack (declare_stack!).
        static __sel4_runtime_common__stack_bottom: *const u8;
    }
    let top = unsafe { __sel4_runtime_common__stack_bottom } as usize;
    let guard = (top - crate::ROOT_STACK).next_multiple_of(PAGE);
    let frames = bootinfo.user_image_frames();
    let i = (guard - image_base()) / PAGE;
    assert!(guard + PAGE <= top && i < frames.len(), "l4h-root: no stack guard page");
    frames.index(i).cap().frame_unmap().expect("unmap the stack guard page");
}
