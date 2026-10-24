//! VFIO transport only. Packet handling and ENA queue programming are
//! compiled from the production driver. EC2 VMs without an IOMMU use one
//! pinned, physically contiguous 2 MiB hugepage, verified through pagemap.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::FileExt;

use l4h_host::{blk::PciRegion, net};

const fn request(n: u64) -> u64 {
    (b';' as u64) << 8 | (100 + n)
}
const DMA_SIZE: usize = 2 << 20;
const IOVA: u64 = 0x4000_0000;

#[repr(C)]
#[derive(Default)]
struct Region {
    argsz: u32,
    flags: u32,
    index: u32,
    cap_offset: u32,
    size: u64,
    offset: u64,
}

#[repr(C)]
struct DmaMap {
    argsz: u32,
    flags: u32,
    vaddr: u64,
    iova: u64,
    size: u64,
}

#[repr(C)]
struct Irqs {
    argsz: u32,
    flags: u32,
    index: u32,
    start: u32,
    count: u32,
    fds: [i32; 2],
}

fn ioctl(fd: RawFd, n: u64, arg: u64) -> i32 {
    let r = unsafe { libc::ioctl(fd, request(n) as _, arg) };
    assert!(
        r >= 0,
        "VFIO ioctl {n}: {}",
        std::io::Error::last_os_error()
    );
    r
}

fn open(path: &str) -> File {
    File::options()
        .read(true)
        .write(true)
        .open(path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
}

pub struct Vfio {
    // Retained until the driver is stopped, including on panic.
    container: File,
    group: File,
    device: File,
    config_offset: u64,
    pub regs: PciRegion,
    pub llq: PciRegion,
    pub revision: u32,
    pub dma_paddr: u64,
    pub irq: [RawFd; 2],
}

impl Vfio {
    pub fn open(bdf: &str, host_queue: bool) -> Self {
        use std::os::fd::FromRawFd;
        let path = format!("/sys/bus/pci/devices/{bdf}");
        assert_eq!(
            std::fs::read_to_string(format!("{path}/vendor"))
                .unwrap()
                .trim(),
            "0x1d0f",
            "not an Amazon device"
        );
        let id = std::fs::read_to_string(format!("{path}/device")).unwrap();
        assert!(
            ["0x0ec2", "0x1ec2", "0xec20", "0xec21", "0x0051"].contains(&id.trim()),
            "not an ENA: {id}"
        );
        let group = std::fs::read_link(format!("{path}/iommu_group"))
            .expect("bind the ENI to vfio-pci first");
        let group = group.file_name().unwrap().to_str().unwrap();
        let no_iommu = std::path::Path::new(&format!("/dev/vfio/noiommu-{group}")).exists();
        let container = open("/dev/vfio/vfio");
        assert_eq!(ioctl(container.as_raw_fd(), 0, 0), 0);
        let group = open(&format!(
            "/dev/vfio/{}{group}",
            if no_iommu { "noiommu-" } else { "" }
        ));
        let mut status = [8u32, 0];
        ioctl(group.as_raw_fd(), 3, status.as_mut_ptr() as u64);
        assert!(status[1] & 1 != 0, "VFIO group is not viable");
        let cfd = container.as_raw_fd();
        ioctl(group.as_raw_fd(), 4, &cfd as *const _ as u64);
        ioctl(cfd, 2, if no_iommu { 8 } else { 3 });
        let name = CString::new(bdf).unwrap();
        let device =
            unsafe { File::from_raw_fd(ioctl(group.as_raw_fd(), 6, name.as_ptr() as u64)) };
        let region = |index: u32| {
            let mut r = Region {
                argsz: size_of::<Region>() as u32,
                index,
                ..Default::default()
            };
            ioctl(device.as_raw_fd(), 8, &mut r as *mut _ as u64);
            r
        };
        let map_bar = |r: &Region| {
            assert!(
                r.size != 0 && r.flags & 4 != 0,
                "BAR {} cannot be mapped",
                r.index
            );
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    r.size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    device.as_raw_fd(),
                    r.offset as i64,
                )
            };
            assert!(
                p != libc::MAP_FAILED,
                "mmap BAR {}: {}",
                r.index,
                std::io::Error::last_os_error()
            );
            PciRegion {
                va: p as u64,
                len: r.size,
            }
        };
        let regs = map_bar(&region(0));
        let bar2 = region(2);
        let llq = if host_queue || bar2.size == 0 {
            PciRegion::default()
        } else {
            // A prefetchable BAR can be mapped WC via sysfs. Stock VFIO
            // otherwise maps it uncached; report that limitation explicitly.
            let wc = File::options()
                .read(true)
                .write(true)
                .open(format!("{path}/resource2_wc"));
            let p = wc
                .as_ref()
                .map(|f| unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        bar2.size as usize,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        f.as_raw_fd(),
                        0,
                    )
                })
                .unwrap_or(libc::MAP_FAILED);
            if p == libc::MAP_FAILED {
                println!("LLQ mapping: uncached VFIO (functional test, not a WC performance test)");
                map_bar(&bar2)
            } else {
                println!("LLQ mapping: write-combining resource2_wc");
                PciRegion {
                    va: p as u64,
                    len: bar2.size,
                }
            }
        };
        let config_offset = region(7).offset;
        let mut config = [0u8; 16];
        device.read_exact_at(&mut config, config_offset).unwrap();
        let revision = config[8] as u32;
        let va = net::nic_dma_va(0);
        let flags = libc::MAP_PRIVATE
            | libc::MAP_ANONYMOUS
            | libc::MAP_FIXED_NOREPLACE
            | libc::MAP_LOCKED
            | libc::MAP_POPULATE
            | if no_iommu {
                libc::MAP_HUGETLB | (21 << libc::MAP_HUGE_SHIFT)
            } else {
                0
            };
        let p = unsafe {
            libc::mmap(
                va as *mut _,
                DMA_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
        assert_eq!(
            p as usize,
            va,
            "mmap DMA: {} (reserve a 2 MiB hugepage and allow locked memory)",
            std::io::Error::last_os_error()
        );
        unsafe { std::ptr::write_bytes(p, 0, DMA_SIZE) };
        let dma_paddr = if no_iommu {
            let pagemap = File::open("/proc/self/pagemap").unwrap();
            let physical = |addr: usize| {
                let mut entry = [0u8; 8];
                pagemap
                    .read_exact_at(&mut entry, (addr / 4096 * 8) as u64)
                    .unwrap();
                let entry = u64::from_ne_bytes(entry);
                assert!(
                    entry >> 63 != 0 && entry & ((1 << 55) - 1) != 0,
                    "pagemap needs CAP_SYS_ADMIN"
                );
                (entry & ((1 << 55) - 1)) * 4096
            };
            let pa = physical(va);
            for offset in (0..DMA_SIZE).step_by(4096) {
                assert_eq!(
                    physical(va + offset),
                    pa + offset as u64,
                    "DMA is not physically contiguous"
                );
            }
            pa
        } else {
            let map = DmaMap {
                argsz: size_of::<DmaMap>() as u32,
                flags: 3,
                vaddr: va as u64,
                iova: IOVA,
                size: DMA_SIZE as u64,
            };
            ioctl(cfd, 13, &map as *const _ as u64);
            IOVA
        };
        // Memory decoding and bus mastering.
        let command = u16::from_le_bytes([config[4], config[5]]) | 6;
        device
            .write_all_at(&command.to_le_bytes(), config_offset + 4)
            .unwrap();
        let irq =
            [0, 1].map(|_| unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) });
        assert!(irq.iter().all(|&fd| fd >= 0), "eventfd");
        let s = Self {
            container,
            group,
            device,
            config_offset,
            regs,
            llq,
            revision,
            dma_paddr,
            irq,
        };
        s.enable_irqs();
        println!(
            "VFIO: {bdf}, revision {revision}, {}, DMA {dma_paddr:#x} + {DMA_SIZE:#x}",
            if no_iommu {
                "no IOMMU, contiguous hugepage"
            } else {
                "IOMMU"
            }
        );
        s
    }

    pub fn dma_size(&self) -> u64 {
        DMA_SIZE as u64
    }

    pub fn enable_irqs(&self) {
        let set = Irqs {
            argsz: size_of::<Irqs>() as u32,
            flags: (1 << 2) | (1 << 5),
            index: 2,
            start: 0,
            count: 2,
            fds: self.irq,
        };
        ioctl(self.device.as_raw_fd(), 10, &set as *const _ as u64);
    }

    pub fn events(&self, index: usize) -> u64 {
        let mut count = 0u64;
        let r = unsafe { libc::read(self.irq[index], &mut count as *mut _ as *mut _, 8) };
        if r == 8 { count } else { 0 }
    }
}

impl Drop for Vfio {
    fn drop(&mut self) {
        // Stop DMA before the process releases its hugepage, even when a
        // driver assertion unwinds. The wrapper then rebinds Linux ena.
        let mut command = [0u8; 2];
        if self
            .device
            .read_exact_at(&mut command, self.config_offset + 4)
            .is_ok()
        {
            let disabled = u16::from_le_bytes(command) & !4;
            let _ = self
                .device
                .write_all_at(&disabled.to_le_bytes(), self.config_offset + 4);
        }
        unsafe { std::ptr::write_volatile((self.regs.va + 0x54) as *mut u32, 1) };
        std::thread::sleep(std::time::Duration::from_millis(100));
        for &fd in &self.irq {
            unsafe {
                libc::close(fd);
            }
        }
        // These FDs deliberately remain open until after DMA is disabled.
        let _ = (&self.container, &self.group);
    }
}
