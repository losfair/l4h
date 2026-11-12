extern crate alloc;
extern crate self as l4h_rt;

pub use l4h_host as host;

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}

#[allow(dead_code)]
#[path = "../../../host/l4h-nicd-mlx5/src/mlx5.rs"]
mod mlx5;
#[path = "../../nicdrv-vfio/sdk.rs"]
mod sdk;

use std::ffi::CString;

use std::os::fd::RawFd;
use std::time::{Duration, Instant};


// VFIO ioctls: _IO(';', 100 + n).
const fn vfio(n: u64) -> u64 {
    (b';' as u64) << 8 | (100 + n)
}
const VFIO_GET_API_VERSION: u64 = vfio(0);
const VFIO_SET_IOMMU: u64 = vfio(2);
const VFIO_GROUP_GET_STATUS: u64 = vfio(3);
const VFIO_GROUP_SET_CONTAINER: u64 = vfio(4);
const VFIO_GROUP_GET_DEVICE_FD: u64 = vfio(6);
const VFIO_DEVICE_GET_REGION_INFO: u64 = vfio(8);
const VFIO_DEVICE_SET_IRQS: u64 = vfio(10);
const VFIO_IOMMU_MAP_DMA: u64 = vfio(13);
const VFIO_TYPE1V2_IOMMU: u64 = 3;
const VFIO_PCI_CONFIG_REGION_INDEX: u32 = 7;
const VFIO_PCI_MSIX_IRQ_INDEX: u32 = 2;
const VFIO_IRQ_SET_DATA_EVENTFD: u32 = 1 << 2;
const VFIO_IRQ_SET_ACTION_TRIGGER: u32 = 1 << 5;
const DMA_IOVA: u64 = 0x0020_0000;
const DMA_SIZE: usize = 32 << 20;

#[repr(C)]
#[derive(Default)]
struct RegionInfo {
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
struct IrqSet {
    argsz: u32,
    flags: u32,
    index: u32,
    start: u32,
    count: u32,
    fds: [i32; 2],
}

fn ioctl(fd: RawFd, req: u64, arg: u64) -> i64 {
    let r = unsafe { libc::ioctl(fd, req as _, arg) };
    if r < 0 {
        panic!("ioctl {:#x}: {}", req, std::io::Error::last_os_error());
    }
    r as i64
}

fn open(path: &str) -> RawFd {
    let c = CString::new(path).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR) };
    assert!(fd >= 0, "{path}: {}", std::io::Error::last_os_error());
    fd
}

struct Vfio {
    dev: RawFd,
    regs: usize,
    irq: [RawFd; 2],
}

/// Open the device, map BAR 0 and DMA memory at netd's address for NIC 0,
/// enable bus mastering and wire MSI-X entries 0 and 1 to eventfds.
fn vfio_open(bdf: &str) -> Vfio {
    let group =
        std::fs::read_link(format!("/sys/bus/pci/devices/{bdf}/iommu_group")).expect("iommu group");
    let group = group.file_name().unwrap().to_str().unwrap().to_string();
    let container = open("/dev/vfio/vfio");
    assert_eq!(ioctl(container, VFIO_GET_API_VERSION, 0), 0);
    let gfd = open(&format!("/dev/vfio/{group}"));
    let mut status = [8u32, 0];
    ioctl(gfd, VFIO_GROUP_GET_STATUS, status.as_mut_ptr() as u64);
    assert!(
        status[1] & 1 != 0,
        "group {group} is not viable: unbind its other devices"
    );
    ioctl(
        gfd,
        VFIO_GROUP_SET_CONTAINER,
        &container as *const i32 as u64,
    );
    ioctl(container, VFIO_SET_IOMMU, VFIO_TYPE1V2_IOMMU);
    let name = CString::new(bdf).unwrap();
    let dev = ioctl(gfd, VFIO_GROUP_GET_DEVICE_FD, name.as_ptr() as u64) as RawFd;

    let region = |index: u32| {
        let mut r = RegionInfo {
            argsz: size_of::<RegionInfo>() as u32,
            index,
            ..Default::default()
        };
        ioctl(dev, VFIO_DEVICE_GET_REGION_INFO, &mut r as *mut _ as u64);
        r
    };
    let bar0 = region(0);
    let regs = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            bar0.size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            dev,
            bar0.offset as i64,
        )
    };
    assert!(regs != libc::MAP_FAILED, "mmap BAR 0");

    // DMA memory where netd has it, so that the driver's addresses work.
    let va = l4h_host::DMA_VA;
    let p = unsafe {
        libc::mmap(
            va as *mut _,
            DMA_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE
                | libc::MAP_ANONYMOUS
                | libc::MAP_FIXED_NOREPLACE
                | libc::MAP_LOCKED
                | libc::MAP_POPULATE,
            -1,
            0,
        )
    };
    assert_eq!(p as usize, va, "mmap DMA memory");
    let map = DmaMap {
        argsz: size_of::<DmaMap>() as u32,
        flags: 3,
        vaddr: va as u64,
        iova: DMA_IOVA,
        size: DMA_SIZE as u64,
    };
    ioctl(container, VFIO_IOMMU_MAP_DMA, &map as *const _ as u64);

    // Memory decoding and bus mastering (PCI command register).
    let cfg = region(VFIO_PCI_CONFIG_REGION_INDEX);
    let mut cmd = [0u8; 2];
    unsafe { libc::pread(dev, cmd.as_mut_ptr() as *mut _, 2, cfg.offset as i64 + 4) };
    let v = u16::from_le_bytes(cmd) | 0x6;
    unsafe {
        libc::pwrite(
            dev,
            v.to_le_bytes().as_ptr() as *const _,
            2,
            cfg.offset as i64 + 4,
        )
    };

    let irq = [0, 1].map(|_| unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) });
    let set = IrqSet {
        argsz: size_of::<IrqSet>() as u32,
        flags: VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER,
        index: VFIO_PCI_MSIX_IRQ_INDEX,
        start: 0,
        count: 2,
        fds: irq,
    };
    ioctl(dev, VFIO_DEVICE_SET_IRQS, &set as *const _ as u64);
    Vfio {
        dev,
        regs: regs as usize,
        irq,
    }
}

fn tsc_hz() -> u64 {
    let (t, c) = (Instant::now(), l4h_host::ticks::now());
    std::thread::sleep(Duration::from_millis(200));
    ((l4h_host::ticks::now() - c) as f64 / t.elapsed().as_secs_f64()) as u64
}

/// Interrupts counted on an eventfd since the last call.
fn events(fd: RawFd) -> u64 {
    let mut v = 0u64;
    let r = unsafe { libc::read(fd, &mut v as *mut u64 as *mut _, 8) };
    if r == 8 { v } else { 0 }
}

fn main() {
    let bdf = std::env::args().nth(1).expect("PCI address");
    let device = format!("/sys/bus/pci/devices/{bdf}");
    assert_eq!(
        std::fs::read_to_string(format!("{device}/vendor"))
            .unwrap()
            .trim(),
        "0x15b3"
    );
    assert_eq!(
        std::fs::read_to_string(format!("{device}/device"))
            .unwrap()
            .trim(),
        "0x1017"
    );
    eprintln!("Destructive hardware test of already VFIO-bound PF {bdf}");
    let hz = tsc_hz();
    let vf = vfio_open(&bdf);
    let result = std::panic::catch_unwind(|| {
        let dma = l4h_virtio::Dma::new(l4h_host::DMA_VA, DMA_IOVA, DMA_SIZE);
        let mut nic =
            mlx5::Mlx5::open(vf.regs, 32 << 20, dma, hz).expect("initialize Ethernet queues");
        println!("MAC {:02x?}, Ethernet queues initialized", nic.mac);
        nic.set_local_loopback(true)
            .expect("enable PF-local loopback");
        let sizes = [64, 128, 512, 1514];
        let mut expected = std::collections::BTreeMap::new();
        let mut received = std::collections::BTreeSet::new();
        let mut background = 0usize;
        let mut data = [0u8; 2048];
        let mut interrupts = 0;
        let mut next = 0u32;
        // 2048 batches cross the queue ownership wrap and the 16-bit WQE
        // counter twice. Each batch
        // starts after rearming, and payloads identify every returned frame.
        for batch in 0..2048 {
            for _ in 0..64 {
                let size = sizes[next as usize % sizes.len()];
                let mut frame = vec![0u8; size];
                frame[..6].copy_from_slice(&nic.mac);
                frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
                frame[14] = 0x45;
                frame[16..18].copy_from_slice(&((size - 14) as u16).to_be_bytes());
                frame[22] = 32;
                frame[23] = 17;
                frame[34..36].copy_from_slice(&9u16.to_be_bytes());
                frame[36..38].copy_from_slice(&9u16.to_be_bytes());
                frame[38..40].copy_from_slice(&((size - 34) as u16).to_be_bytes());
                let sum: u32 = frame[14..34]
                    .chunks_exact(2)
                    .map(|v| u16::from_be_bytes([v[0], v[1]]) as u32)
                    .sum();
                let sum = (sum & 0xffff) + (sum >> 16);
                frame[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
                frame[42..50].copy_from_slice(b"l4h-mlx5");
                frame[50..54].copy_from_slice(&next.to_be_bytes());
                for (i, v) in frame[54..].iter_mut().enumerate() {
                    *v = (i as u8).wrapping_add(next as u8);
                }
                assert!(
                    nic.transmit(&frame[..], &[0; 12]),
                    "TX backpressure batch={batch}"
                );
                expected.insert(next, frame);
                next += 1;
            }
            assert!(
                !nic.transmit(&expected[&(next - 1)][..], &[0; 12]),
                "full TX queue must apply backpressure"
            );
            nic.kick_tx();
            let mut wake = libc::pollfd {
                fd: vf.irq[0],
                events: libc::POLLIN,
                revents: 0,
            };
            assert!(
                unsafe { libc::poll(&mut wake, 1, 1000) } > 0,
                "idle IRQ wake batch={batch}"
            );
            let start = Instant::now();
            while received.len() < expected.len() || nic.completed_tx() < next {
                assert!(
                    start.elapsed() < Duration::from_secs(3),
                    "batch={batch} TX={} RX={}/{}",
                    nic.completed_tx(),
                    received.len(),
                    expected.len()
                );
                nic.rx_begin();
                while let Some(n) = nic.receive(&mut data, &mut [0; 12]) {
                    if n >= 54 && &data[42..50] == b"l4h-mlx5" {
                        let id = u32::from_be_bytes(data[50..54].try_into().unwrap());
                        assert_eq!(&data[..n], expected.get(&id).expect("known packet id"));
                        assert!(received.insert(id), "duplicate RX packet");
                    } else {
                        background += 1;
                    }
                }
                nic.rx_done();
                interrupts += events(vf.irq[0]);
                std::thread::sleep(Duration::from_millis(1));
            }
            nic.tx_interrupts(false);
            // Test idle-to-interrupt wake, rather than only busy polling.
            std::thread::sleep(Duration::from_millis(2));
        }
        let idle = Instant::now();
        while idle.elapsed() < Duration::from_secs(5) {
            nic.rx_begin();
            while nic.receive(&mut data, &mut [0; 12]).is_some() {
                background += 1;
            }
            nic.rx_done();
            std::thread::sleep(Duration::from_millis(10));
        }
        nic.diagnostics();
        interrupts += events(vf.irq[0]);
        println!(
            "PASS TX={} RX={} MSI-X={} background={} sizes={sizes:?}",
            nic.completed_tx(),
            received.len(),
            interrupts,
            background
        );
        assert_eq!(received.len(), 131072);
        assert!(interrupts > 64, "repeated interrupt delivery");
        nic.set_local_loopback(false)
            .expect("disable PF-local loopback");
    });
    // Reset while DMA is still mapped, including the timeout/error path.
    ioctl(vf.dev, vfio(11), 0);
    if result.is_err() {
        std::process::exit(1);
    }
}
