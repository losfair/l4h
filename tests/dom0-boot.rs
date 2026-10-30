//! Exercise the production dom0 boot sequence with mocked guest operations.
//! Device counts come from guest creation, including optional built-in devices.
#![allow(dead_code)]

extern crate self as l4h_rt;

use l4h_host::{MAX_GUEST_DEVICES, blk::DiskWindow, vmmgr::{DOM0_MAX_DISKS, Dom0Disk, Dom0Nic, VmmgrConfig}};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[macro_export]
macro_rules! log { ($($a:tt)*) => {{ let _ = format_args!($($a)*); }}; }

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
struct Guest { devices: Vec<()>, booted: bool }

pub struct Vmmgr {
    cfg: &'static VmmgrConfig,
    kernel: Option<Kernel>,
    dom0_initrd: &'static [u8],
    alloc: (),
    wins: Windows,
    info: (),
    guest: Option<Guest>,
    builtins: usize,
    disk_attempts: Vec<(usize, u64, u64)>,
    disks: Vec<Option<(usize, u64, u64)>>,
    nics: Vec<u32>,
    fail_disks: Vec<usize>,
    started: bool,
}

impl Vmmgr {
    fn create_guest(&mut self, _: &GuestConfig) -> Option<usize> {
        self.guest = Some(Guest { devices: vec![(); self.builtins], booted: false });
        Some(0)
    }
    fn guest(&self, _: usize) -> Option<&Guest> { self.guest.as_ref() }
    fn with_guest<R>(&mut self, _: usize, f: impl FnOnce(&mut Self, &mut Guest) -> R) -> Option<R> {
        let mut g = self.guest.take()?;
        let result = f(self, &mut g);
        self.guest = Some(g);
        Some(result)
    }
    fn add_device(&mut self) -> Result<(), i64> {
        let g = self.guest.as_mut().unwrap();
        if g.devices.len() == MAX_GUEST_DEVICES { return Err(28); }
        g.devices.push(());
        Ok(())
    }
    fn attach_disk(&mut self, _: usize, disk: usize, flags: u64, start: u64, sectors: u64, _: &[u8; 64]) -> Result<u64, i64> {
        assert_eq!(flags, 0);
        let attempt = self.disk_attempts.len();
        self.disk_attempts.push((disk, start, sectors));
        if self.fail_disks.contains(&attempt) { return Err(5); }
        self.add_device()?;
        self.disks.push(Some((disk, start, sectors)));
        Ok(0)
    }
    fn attach_dummy_disk(&mut self, _: usize) -> Result<(), i64> {
        self.add_device()?;
        self.disks.push(None);
        Ok(())
    }
    fn create_nic(&mut self, _: usize, switch: u32, _: u64, _: bool, _: bool) -> Result<(), i64> {
        self.add_device()?;
        self.nics.push(switch);
        Ok(())
    }
    fn start_guest(&mut self, _: usize) -> Result<(), i64> {
        assert!(self.guest.as_ref().unwrap().booted);
        self.started = true;
        Ok(())
    }
}

mod guest {
    use super::*;
    pub fn boot_with(g: &mut Guest, _: &mut (), _: &mut (), _: &(), _: &Kernel, _: &[u8], _: &[u8]) -> bool {
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
        alloc: (), wins: Windows { a: () }, info: (), guest: None, builtins,
        disk_attempts: Vec::new(), disks: Vec::new(), nics: Vec::new(), fail_disks: Vec::new(), started: false,
    }
}

fn fails_before_boot(h: &mut Vmmgr, message: &str) {
    let error = catch_unwind(AssertUnwindSafe(|| boot_dom0(h))).expect_err("dom0 must not start");
    let text = error.downcast_ref::<String>().map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied()).unwrap_or("");
    assert!(text.contains(message), "unexpected failure: {text}");
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
            boot_dom0(&mut h);
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
            boot_dom0(&mut h);
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
    boot_dom0(&mut h);
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
