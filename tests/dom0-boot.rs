//! Exercise the production dom0 boot sequence with mocked guest operations.
//! Device counts come from guest creation, including optional built-in devices.
#![allow(dead_code)]

extern crate self as l4h_rt;

use l4h_host::errno::Errno;
use l4h_host::{MAX_GUEST_DEVICES, blk::DiskWindow, vmmgr::{DOM0_MAX_DISKS, Dom0Disk, Dom0Nic, VmmgrConfig}};

thread_local! {
    static LOG: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    static NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[macro_export]
macro_rules! log { ($($a:tt)*) => {{ $crate::LOG.with(|l| l.borrow_mut().push(format!($($a)*))); }}; }

/// The tick counter, which the tests move (`Info::tsc_hz` ticks a second).
fn rdtsc() -> u64 { NOW.with(|n| n.get()) }

mod ctl {
    pub const EBUSY: l4h_host::errno::Errno = l4h_host::errno::EBUSY;
    pub const EINVAL: l4h_host::errno::Errno = l4h_host::errno::EINVAL;
}

struct GuestConfig {
    name: &'static str,
    ram: usize,
    vcpus: usize,
    io_pool: usize,
    vspaces: usize,
    ram_base: usize,
    dom0: bool,
}
struct Kernel { ram_base: usize }
struct Windows { a: () }
struct Info { tsc_hz: u64 }
struct Guest { devices: Vec<()>, booted: bool, instance: u64 }
#[derive(Clone, Copy)]
enum Then { Dom0Boot { k: usize } }

pub struct Vmmgr {
    cfg: &'static VmmgrConfig,
    kernel: Option<Kernel>,
    dom0_initrd: &'static [u8],
    alloc: (),
    wins: Windows,
    info: Info,
    guest: Option<Guest>,
    dom0_wait: Option<Dom0Wait>,
    dom0_usb_wait: Option<Dom0Wait>,
    /// USB controllers root says are busy (EBUSY): (controller, how often
    /// still).
    busy_usbs: Vec<(usize, usize)>,
    /// The attaches made, of whatever outcome: (controller, when).
    usb_attempts: Vec<(usize, u64)>,
    /// Boot disks root has yet to answer: (k, the answer it gives).
    pending: Vec<(usize, Result<(), Errno>)>,
    /// Boot disks root answers EBUSY for, as many times each.
    busy_disks: Vec<(usize, usize)>,
    destroyed: bool,
    builtins: usize,
    disk_attempts: Vec<(usize, u64, u64)>,
    disks: Vec<Option<(usize, u64, u64)>>,
    nics: Vec<u32>,
    fail_disks: Vec<usize>,
    usbs: Vec<usize>,
    fail_usbs: Vec<usize>,
    started: bool,
}

impl Vmmgr {
    fn create_guest(&mut self, _: &GuestConfig) -> Option<usize> {
        self.guest = Some(Guest { devices: vec![(); self.builtins], booted: false, instance: 1 });
        Some(0)
    }
    fn destroy_guest(&mut self, _: usize) -> Result<(), Errno> {
        self.destroyed = true;
        Ok(())
    }
    fn guest(&self, _: usize) -> Option<&Guest> { self.guest.as_ref() }
    fn with_guest<R>(&mut self, _: usize, f: impl FnOnce(&mut Self, &mut Guest) -> R) -> Option<R> {
        let mut g = self.guest.take()?;
        let result = f(self, &mut g);
        self.guest = Some(g);
        Some(result)
    }
    fn add_device(&mut self) -> Result<(), Errno> {
        let g = self.guest.as_mut().unwrap();
        if g.devices.len() == MAX_GUEST_DEVICES { return Err(28); }
        g.devices.push(());
        Ok(())
    }
    fn attach_disk(&mut self, _: usize, disk: usize, flags: u64, start: u64, sectors: u64, extents: (u64, u64),
        then: Then) -> Result<(), Errno> {
        assert_eq!(extents, (0, 0), "boot disks are windows");
        assert_eq!(flags, 0);
        assert!(self.pending.is_empty(), "one boot disk at a time");
        let Then::Dom0Boot { k } = then;
        if let Some(b) = self.busy_disks.iter_mut().find(|b| b.0 == k && b.1 > 0) {
            b.1 -= 1;
            return Err(ctl::EBUSY);
        }
        assert_eq!(k, self.disk_attempts.len(), "boot disks attach in order");
        self.disk_attempts.push((disk, start, sectors));
        // Root answers later (vmmgr's root_done): an error, or the disk.
        let r = if self.fail_disks.contains(&k) { Err(5) } else {
            self.add_device()?;
            self.disks.push(Some((disk, start, sectors)));
            Ok(())
        };
        self.pending.push((k, r));
        Ok(())
    }
    fn attach_dummy_disk(&mut self, _: usize) -> Result<(), Errno> {
        self.add_device()?;
        self.disks.push(None);
        Ok(())
    }
    fn create_nic(&mut self, _: usize, switch: u32, _: u64, _: u64) -> Result<(), Errno> {
        self.add_device()?;
        self.nics.push(switch);
        Ok(())
    }
    fn attach_usb(&mut self, _: usize, ctrl: usize) -> Result<(), Errno> {
        self.usb_attempts.push((ctrl, rdtsc()));
        if self.fail_usbs.contains(&ctrl) { return Err(5); }
        if let Some(b) = self.busy_usbs.iter_mut().find(|b| b.0 == ctrl && b.1 != 0) {
            b.1 -= 1;
            return Err(16);
        }
        self.add_device()?;
        self.usbs.push(ctrl);
        Ok(())
    }
    fn start_guest(&mut self, _: usize) -> Result<(), Errno> {
        assert!(self.guest.as_ref().unwrap().booted);
        self.started = true;
        Ok(())
    }
}

mod guest {
    use super::*;
    pub fn boot_with(g: &mut Guest, _: &mut (), _: &mut (), _: &Info, _: &Kernel, _: &[u8], _: &[u8]) -> bool {
        g.booted = true;
        true
    }
}

include!(env!("L4H_DOM0_BOOT_TEST_SRC"));

fn fixture(builtins: usize, windows: usize, other_disks: usize, nics: usize) -> Vmmgr {
    let mut cfg: Box<VmmgrConfig> = Box::new(unsafe { core::mem::zeroed() });
    cfg.dom0_disks = (windows + other_disks) as u64;
    if windows != 0 {
        let text = (0..windows).map(|i| format!("{}:8", 8 + 16 * i)).collect::<Vec<_>>().join(",");
        let (ranges, len) = DiskWindow::parse_list::<DOM0_MAX_DISKS>(&text, 4096).unwrap();
        assert_eq!(len, windows);
        for (d, w) in cfg.dom0_disk.iter_mut().zip(&ranges[..len]) {
            *d = Dom0Disk { disk: 0, start: w.start, sectors: w.sectors };
        }
    }
    for i in 0..other_disks {
        cfg.dom0_disk[windows + i] = Dom0Disk { disk: (i + 1) as u64, start: 0, sectors: 0 };
    }
    cfg.dom0_nics = nics as u64;
    for i in 0..nics { cfg.dom0_nic[i] = Dom0Nic { switch: i as u64, mac: 0 }; }
    Vmmgr {
        cfg: Box::leak(cfg), kernel: Some(Kernel { ram_base: 0 }), dom0_initrd: &[],
        alloc: (), wins: Windows { a: () }, info: Info { tsc_hz: 1000 }, guest: None, builtins,
        dom0_wait: None, dom0_usb_wait: None, busy_usbs: Vec::new(), usb_attempts: Vec::new(), pending: Vec::new(), busy_disks: Vec::new(), destroyed: false,
        disk_attempts: Vec::new(), disks: Vec::new(), nics: Vec::new(), fail_disks: Vec::new(),
        usbs: Vec::new(), fail_usbs: Vec::new(), started: false,
    }
}

/// Boot dom0 as vmmgr does: root answers each boot disk later, and the
/// timer (every 100 ms) retries one root was busy for.
fn boot(h: &mut Vmmgr) {
    boot_dom0(h);
    for _ in 0..10_000 {
        if let Some((k, r)) = h.pending.pop() {
            dom0_disk_done(h, 0, 1, k, r);
        } else if h.dom0_wait.is_some() || h.dom0_usb_wait.is_some() {
            NOW.with(|n| n.set(n.get() + 100));
            dom0_retry(h);
        } else {
            return;
        }
    }
    panic!("dom0's boot did not finish");
}

/// dom0 is given back, with `message` logged, before it starts.
fn fails_before_boot(h: &mut Vmmgr, message: &str) {
    LOG.with(|l| l.borrow_mut().clear());
    boot(h);
    let log = LOG.with(|l| l.borrow().join("\n"));
    assert!(log.contains(message), "unexpected failure: {log}");
    assert!(h.destroyed);
    assert!(!h.started);
    assert!(!h.guest.as_ref().unwrap().booted);
}

#[test]
fn oversized_explicit_layout_fails_before_any_attachment() {
    // Console and control, with memory/attestation devices present or absent.
    for builtins in 2..=4 {
        for nics in 0..=2 {
            for other_disks in 0..=1 {
                let windows = MAX_GUEST_DEVICES - builtins - nics - other_disks + 1;
                let mut h = fixture(builtins, windows, other_disks, nics);
                fails_before_boot(&mut h, "dom0 device plan needs 65 slots");
                assert!(h.disk_attempts.is_empty());
                assert!(h.nics.is_empty());
            }
        }
    }
    // The parser's 64-window limit is larger than dom0's available budget.
    let mut h = fixture(4, 64, 0, 1);
    fails_before_boot(&mut h, "dom0 device plan needs 69 slots");
    assert!(h.disk_attempts.is_empty());
}

#[test]
fn exact_fit_keeps_all_windows_other_disks_and_nics() {
    for builtins in 2..=4 {
        for nics in 0..=2 {
            let windows = MAX_GUEST_DEVICES - builtins - nics - 1;
            let mut h = fixture(builtins, windows, 1, nics);
            boot(&mut h);
            assert!(h.started);
            assert_eq!(h.guest.as_ref().unwrap().devices.len(), MAX_GUEST_DEVICES);
            let expected: Vec<_> = h.cfg.dom0_disk[..windows + 1].iter()
                .map(|d| Some((d.disk as usize, d.start, d.sectors))).collect();
            assert_eq!(h.disks, expected);
            assert_eq!(h.nics, (0..nics as u32).collect::<Vec<_>>());
        }
    }
}

#[test]
fn failed_disks_keep_their_positions_and_allow_dom0_to_boot() {
    for (windows, other_disks) in [(2, 1), (0, 3)] {
        for failed in [vec![0], vec![1], vec![2], vec![0, 1, 2]] {
            let mut h = fixture(4, windows, other_disks, 1);
            h.fail_disks = failed.clone();
            boot(&mut h);
            assert!(h.started);
            assert_eq!(h.disk_attempts.len(), 3);
            assert_eq!(h.disks.len(), 3);
            for (i, disk) in h.disks.iter().enumerate() {
                let expected = (!failed.contains(&i)).then_some(h.disk_attempts[i]);
                assert_eq!(*disk, expected, "disk {i} moved or lost its placeholder");
            }
            assert_eq!(h.nics, [0]);
            assert_eq!(h.guest.as_ref().unwrap().devices.len(), 8);
        }
    }
}

#[test]
fn placeholders_fit_at_high_device_indices() {
    let mut h = fixture(4, 59, 0, 1);
    h.fail_disks = vec![0, 16, 32, 58];
    boot(&mut h);
    assert!(h.started);
    assert_eq!(h.guest.as_ref().unwrap().devices.len(), 64);
    assert_eq!(h.disks.len(), 59);
    for (i, disk) in h.disks.iter().enumerate() {
        assert_eq!(*disk, (!h.fail_disks.contains(&i)).then_some(h.disk_attempts[i]));
    }
    assert_eq!(h.nics, [0]);
}

#[test]
fn oversized_whole_disk_plan_is_also_rejected() {
    let mut h = fixture(4, 0, 64, 1);
    fails_before_boot(&mut h, "dom0 device plan needs 69 slots");
    assert!(h.disk_attempts.is_empty());
    assert!(h.nics.is_empty());
}

#[test]
fn dom0_usb_controllers_are_attached_and_a_failure_is_not_fatal() {
    let mut h = fixture(2, 0, 1, 1);
    let mut cfg: Box<VmmgrConfig> = Box::new(unsafe { core::ptr::read(h.cfg) });
    cfg.dom0_usbs = 3;
    cfg.dom0_usb[..3].copy_from_slice(&[2, 0, 5]);
    h.cfg = Box::leak(cfg);
    h.fail_usbs.push(0);
    boot(&mut h);
    assert!(h.started);
    assert_eq!(h.usbs, [2, 5]);
    // Console, control, the disk, the NIC and two controllers.
    assert_eq!(h.guest.as_ref().unwrap().devices.len(), 6);
    // A controller root refuses for good is not asked for again.
    assert_eq!(h.usb_attempts.iter().filter(|a| a.0 == 0).count(), 1);
}

#[test]
fn a_usb_controller_the_firmware_is_resetting_is_waited_for() {
    let with = |busy: Vec<(usize, usize)>| {
        let mut h = fixture(2, 0, 1, 1);
        let mut cfg: Box<VmmgrConfig> = Box::new(unsafe { core::ptr::read(h.cfg) });
        cfg.dom0_usbs = 3;
        cfg.dom0_usb[..3].copy_from_slice(&[2, 0, 5]);
        h.cfg = Box::leak(cfg);
        h.busy_usbs = busy;
        let begun = rdtsc();
        boot(&mut h);
        assert!(h.started);
        (h, begun)
    };
    // Busy at three looks (the timer's, 100 ms apart): attached at the
    // fourth, in its place among the others, which is its number in dom0.
    let (h, _) = with(vec![(0, 3)]);
    assert_eq!(h.usbs, [2, 0, 5]);
    assert_eq!(h.usb_attempts.iter().map(|a| a.0).collect::<Vec<_>>(), [2, 0, 0, 0, 0, 5]);
    // Busy for good: dom0 starts without it after DOM0_USB_WAIT_MS, with
    // the controllers after it, and the NIC it got before is not made
    // again.
    let (h, begun) = with(vec![(0, usize::MAX)]);
    assert_eq!((h.usbs.as_slice(), h.nics.len()), (&[2, 5][..], 1));
    let tried: Vec<u64> = h.usb_attempts.iter().filter(|a| a.0 == 0).map(|a| a.1 - begun).collect();
    assert_eq!((tried.first(), tried.last()), (Some(&0), Some(&DOM0_USB_WAIT_MS)), "{tried:?}");
    assert!(h.dom0_usb_wait.is_none());
}

#[test]
fn a_busy_controller_is_waited_for_then_a_placeholder_taken() {
    // Busy for 2 s: the disk is waited for and attached.
    let mut h = fixture(2, 0, 2, 0);
    h.busy_disks = vec![(0, 20)];
    boot(&mut h);
    assert!(h.started);
    assert_eq!(h.disks.len(), 2);
    assert!(h.disks.iter().all(Option::is_some), "a disk lost to a busy controller");
    // Busy for good: after DOM0_DISK_WAIT_MS, a placeholder in its place.
    let mut h = fixture(2, 0, 2, 0);
    h.busy_disks = vec![(1, usize::MAX)];
    boot(&mut h);
    assert!(h.started);
    assert_eq!(h.disks, [Some(h.disk_attempts[0]), None]);
}
