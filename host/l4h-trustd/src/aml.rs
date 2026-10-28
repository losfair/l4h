//! The ACPI start method (AMD fTPM; TPM2 start methods 2 and 8): each
//! command starts with the TPM device's _DSM, firmware code in AML, which
//! we run with the `acpi` crate's interpreter.  Running it here rather than
//! in root confines what a firmware bug or an interpreter panic can harm
//! to attestation (root then revokes our endpoint).  Accesses outside our
//! own TPM ranges go to root (ROOT_CALL_HW), which refuses RAM and
//! hardware in use.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::str::FromStr;
use core::sync::atomic::{AtomicU32, Ordering};

use acpi::aml::namespace::{AmlName, NamespaceLevelKind};
use acpi::aml::object::{Object, WrappedObject};
use acpi::aml::{AmlError, NoSendInterpreter};
use acpi::registers::FixedRegisters;
use acpi::sdt::fadt::Fadt;
use acpi::{Handle, PciAddress, RawPhysicalMapping};

use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::trust::{self, TrustdConfig};
use l4h_rt::{cap, host, sel4};
use sel4::cap_type;

use crate::time;

/// The start function of the CRB _DSM (TCG PC Client PTP): its UUID,
/// 6bbf6cab-5463-4714-b7cd-f0203c0368d4, as ToUUID lays it out.
const START_UUID: [u8; 16] = [
    0xab, 0x6c, 0xbf, 0x6b, 0x63, 0x54, 0x14, 0x47, 0xb7, 0xcd, 0xf0, 0x20, 0x3c, 0x03, 0x68, 0xd4,
];
const START_REVISION: u64 = 1;
const START_FUNCTION: u64 = 1;

/// trustd's heap, which only the interpreter uses (DESIGN.md §9: the one
/// allocator in trustd, as the `acpi` crate allocates and cannot do
/// otherwise).  It holds the namespace the firmware's AML builds at start,
/// where each method keeps a copy of its bytecode and each named object
/// takes a node of about a hundred bytes, and, for each command, what the
/// _DSM's evaluation takes and gives back.  What it needs is up to the
/// firmware, never a guest, and only roughly bounded by the tables' size
/// (AML_LIMIT, a quarter of the heap): a few bytes of AML can declare a
/// buffer of megabytes.  AML that exhausts the heap makes trustd panic,
/// which root contains (trustd::fault): the host runs on without
/// attestation.  A typical DSDT and its SSDTs are 100-300 KiB.
pub const HEAP: usize = 2 << 20;
const AML_LIMIT: usize = HEAP / 4;
/// The deepest TPM device whose parents' _INI we run.
const MAX_DEPTH: usize = 16;

/// Hardware for the interpreter: our TPM ranges directly, the rest through
/// root.
#[derive(Clone)]
pub struct Hw {
    /// (physical address, size, VA) of each range we have mapped.
    ranges: ArrayVec<(usize, usize, usize), { trust::MAX_RANGES }>,
    hz: u64,
}

/// The mutex handles the interpreter has made (one thread: they only
/// need to differ).
static MUTEXES: AtomicU32 = AtomicU32::new(0);

/// What the interpreter maps that is none of our ranges (the PM1 blocks,
/// in system memory on some machines): it only touches them for the
/// firmware's global lock, which we do not take.
static mut SCRATCH: [u8; 4096] = [0; 4096];

impl Hw {
    fn local(&self, paddr: usize, width: usize) -> Option<usize> {
        self.ranges.iter().find(|&&(p, n, _)| p <= paddr && paddr + width <= p + n).map(|&(p, _, va)| va + (paddr - p))
    }

    /// One access through root.
    fn root(&self, op: u64, addr: u64, off: u64, width: usize, value: u64) -> u64 {
        for (i, v) in [op, addr, off, width as u64, value].into_iter().enumerate() {
            sel4::with_ipc_buffer_mut(|b| b.msg_regs_mut()[i] = v);
        }
        cap::<cap_type::Endpoint>(host::SLOT_ROOT_EP).call(sel4::MessageInfo::new(host::ROOT_CALL_HW, 0, 0, 5));
        sel4::with_ipc_buffer(|b| b.msg_regs()[0])
    }

    fn read(&self, paddr: usize, width: usize) -> u64 {
        match self.local(paddr, width) {
            Some(va) => unsafe {
                match width {
                    1 => (va as *const u8).read_volatile() as u64,
                    2 => (va as *const u16).read_volatile() as u64,
                    4 => (va as *const u32).read_volatile() as u64,
                    _ => (va as *const u64).read_volatile(),
                }
            },
            None => self.root(trust::HW_MEM_READ, paddr as u64, 0, width, 0),
        }
    }

    fn write(&self, paddr: usize, width: usize, v: u64) {
        match self.local(paddr, width) {
            Some(va) => unsafe {
                match width {
                    1 => (va as *mut u8).write_volatile(v as u8),
                    2 => (va as *mut u16).write_volatile(v as u16),
                    4 => (va as *mut u32).write_volatile(v as u32),
                    _ => (va as *mut u64).write_volatile(v),
                }
            },
            None => {
                self.root(trust::HW_MEM_WRITE, paddr as u64, 0, width, v);
            }
        }
    }

    fn pci(&self, op: u64, a: PciAddress, off: u16, width: usize, v: u64) -> u64 {
        if a.segment() != 0 {
            return u64::MAX;
        }
        let f = (a.bus() as u64) << 8 | (a.device() as u64) << 3 | a.function() as u64;
        self.root(op, f, off as u64, width, v)
    }

    fn spin_ns(&self, ns: u64) {
        let end = host::ticks::now() + (ns as u128 * self.hz as u128 / 1_000_000_000) as u64;
        while host::ticks::now() < end {
            core::hint::spin_loop();
        }
    }
}

impl acpi::Handler for Hw {
    unsafe fn map_physical_region<T>(&self, paddr: usize, size: usize) -> RawPhysicalMapping<T> {
        let va = self.local(paddr, size).unwrap_or(core::ptr::addr_of_mut!(SCRATCH) as usize);
        unsafe { RawPhysicalMapping::new(paddr, NonNull::new(va as *mut T).unwrap(), size, size) }
    }

    unsafe fn unmap_physical_region<T>(&self, _region: RawPhysicalMapping<T>) {}

    fn read_u8(&self, a: usize) -> u8 {
        self.read(a, 1) as u8
    }
    fn read_u16(&self, a: usize) -> u16 {
        self.read(a, 2) as u16
    }
    fn read_u32(&self, a: usize) -> u32 {
        self.read(a, 4) as u32
    }
    fn read_u64(&self, a: usize) -> u64 {
        self.read(a, 8)
    }
    fn write_u8(&self, a: usize, v: u8) {
        self.write(a, 1, v as u64)
    }
    fn write_u16(&self, a: usize, v: u16) {
        self.write(a, 2, v as u64)
    }
    fn write_u32(&self, a: usize, v: u32) {
        self.write(a, 4, v as u64)
    }
    fn write_u64(&self, a: usize, v: u64) {
        self.write(a, 8, v)
    }
    fn read_io_u8(&self, port: u16) -> u8 {
        self.root(trust::HW_IO_READ, port as u64, 0, 1, 0) as u8
    }
    fn read_io_u16(&self, port: u16) -> u16 {
        self.root(trust::HW_IO_READ, port as u64, 0, 2, 0) as u16
    }
    fn read_io_u32(&self, port: u16) -> u32 {
        self.root(trust::HW_IO_READ, port as u64, 0, 4, 0) as u32
    }
    fn write_io_u8(&self, port: u16, v: u8) {
        self.root(trust::HW_IO_WRITE, port as u64, 0, 1, v as u64);
    }
    fn write_io_u16(&self, port: u16, v: u16) {
        self.root(trust::HW_IO_WRITE, port as u64, 0, 2, v as u64);
    }
    fn write_io_u32(&self, port: u16, v: u32) {
        self.root(trust::HW_IO_WRITE, port as u64, 0, 4, v as u64);
    }
    fn read_pci_u8(&self, a: PciAddress, off: u16) -> u8 {
        self.pci(trust::HW_PCI_READ, a, off, 1, 0) as u8
    }
    fn read_pci_u16(&self, a: PciAddress, off: u16) -> u16 {
        self.pci(trust::HW_PCI_READ, a, off, 2, 0) as u16
    }
    fn read_pci_u32(&self, a: PciAddress, off: u16) -> u32 {
        self.pci(trust::HW_PCI_READ, a, off, 4, 0) as u32
    }
    fn write_pci_u8(&self, a: PciAddress, off: u16, v: u8) {
        self.pci(trust::HW_PCI_WRITE, a, off, 1, v as u64);
    }
    fn write_pci_u16(&self, a: PciAddress, off: u16, v: u16) {
        self.pci(trust::HW_PCI_WRITE, a, off, 2, v as u64);
    }
    fn write_pci_u32(&self, a: PciAddress, off: u16, v: u32) {
        self.pci(trust::HW_PCI_WRITE, a, off, 4, v as u64);
    }
    fn nanos_since_boot(&self) -> u64 {
        (host::ticks::now() as u128 * 1_000_000_000 / self.hz.max(1) as u128) as u64
    }
    // Stall is a busy wait by the ACPI specification (at most 100 us);
    // Sleep need not be.
    fn stall(&self, us: u64) {
        self.spin_ns(us * 1000);
    }
    fn sleep(&self, ms: u64) {
        time::sleep_ns(self.hz, ms * 1_000_000);
    }
    // One thread: mutexes are always free.
    fn create_mutex(&self) -> Handle {
        Handle(MUTEXES.fetch_add(1, Ordering::Relaxed) + 1)
    }
    fn acquire(&self, _mutex: Handle, _timeout: u16) -> Result<(), AmlError> {
        Ok(())
    }
    fn release(&self, _mutex: Handle) {}
    fn handle_fatal_error(&self, fatal_type: u8, fatal_code: u32, fatal_arg: u64) {
        l4h_rt::log!("l4h-trustd: AML Fatal ({:#x}, {:#x}, {:#x})", fatal_type, fatal_code, fatal_arg);
    }
}

/// Warnings and errors of the interpreter, on the serial port.
struct Log;

impl log::Log for Log {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Warn
    }
    fn log(&self, r: &log::Record) {
        if self.enabled(r.metadata()) {
            l4h_rt::log!("l4h-trustd: aml: {}", r.args());
        }
    }
    fn flush(&self) {}
}

static LOG: Log = Log;

/// The TPM device's _DSM, ready to start commands.
pub struct Start {
    interp: NoSendInterpreter<Hw>,
    dsm: AmlName,
}

/// The _DSM's arguments for `function`.  They are made afresh for each
/// call, as the interpreter passes objects by reference: a _DSM that
/// writes its Arg would otherwise change what the next command passes.
/// That is a few small allocations per command, in the interpreter's
/// heap (HEAP), whose use the firmware bounds.
fn dsm_args(function: u64) -> Vec<WrappedObject> {
    let mut args = Vec::with_capacity(4);
    args.push(Object::Buffer(START_UUID.to_vec()).wrap());
    args.push(Object::Integer(START_REVISION).wrap());
    args.push(Object::Integer(function).wrap());
    args.push(Object::Package(Vec::new()).wrap());
    args
}

/// The ACPI tables in `all`, one after the other.
fn tables(all: &[u8]) -> impl Iterator<Item = Result<&[u8], &'static str>> {
    let mut at = 0;
    core::iter::from_fn(move || {
        if at + 36 > all.len() {
            return None;
        }
        let len = u32::from_le_bytes(all[at + 4..at + 8].try_into().unwrap()) as usize;
        if len < 36 || at + len > all.len() {
            at = all.len();
            return Some(Err("bad ACPI table"));
        }
        at += len;
        Some(Ok(&all[at - len..at]))
    })
}

fn aml_err(what: &'static str) -> impl FnOnce(AmlError) -> &'static str {
    move |e| {
        l4h_rt::log!("l4h-trustd: {}: {:?}", what, e);
        what
    }
}

/// Is `id` (a _HID or _CID) the TPM's, MSFT0101?
fn is_tpm(id: &Object) -> bool {
    match id {
        Object::String(s) => s.as_str() == "MSFT0101",
        Object::Package(p) => p.iter().any(|o| is_tpm(o)),
        _ => false,
    }
}

impl Start {
    /// Load the tables root gave us and find the TPM device whose _DSM
    /// has the start function.
    pub fn new(cfg: &TrustdConfig, hz: u64) -> Result<Start, &'static str> {
        let _ = log::set_logger(&LOG).map(|()| log::set_max_level(log::LevelFilter::Warn));
        if cfg.aml_size as usize > AML_LIMIT {
            return Err("ACPI tables too large for the interpreter's heap");
        }
        let all: &'static [u8] = unsafe { core::slice::from_raw_parts(trust::AML_VA as *const u8, cfg.aml_size as usize) };
        let mut tables = tables(all);
        let (Some(Ok(fadt)), Some(Ok(dsdt))) = (tables.next(), tables.next()) else { return Err("no FADT or DSDT") };
        if &fadt[..4] != b"FACP" || &dsdt[..4] != b"DSDT" {
            return Err("no FADT or DSDT");
        }
        let mut ranges = ArrayVec::new();
        for (i, r) in cfg.ranges.iter().enumerate().filter(|(_, r)| r.size != 0) {
            // No more than cfg.ranges has: always fits.
            let _ = ranges.push((r.paddr as usize, r.size as usize, trust::TPM_VA + i * trust::RANGE_STRIDE));
        }
        let hw = Hw { ranges, hz };
        // The FADT as the crate reads it (a packed struct).
        let fadt: &Fadt = unsafe { &*(fadt.as_ptr() as *const Fadt) };
        let registers = FixedRegisters::new(fadt, hw.clone()).map_err(|_| "FADT PM1 registers")?;
        let interp = NoSendInterpreter::new(hw, dsdt[8], Arc::new(registers), None);
        interp.load_table(&dsdt[36..]).map_err(aml_err("loading the DSDT"))?;
        for t in tables {
            let t = t?;
            if &t[..4] == b"SSDT" {
                interp.load_table(&t[36..]).map_err(aml_err("loading an SSDT"))?;
            }
        }

        // The devices' paths (on the heap, as all the namespace is): their
        // objects are evaluated with the namespace unlocked.
        let mut devices = Vec::new();
        interp
            .namespace
            .lock()
            .traverse(|path, level| {
                if matches!(level.kind, NamespaceLevelKind::Device) {
                    devices.push(path.clone());
                }
                Ok(true)
            })
            .map_err(aml_err("walking the namespace"))?;
        let name = |s: &str, dev: &AmlName| AmlName::from_str(s).and_then(|n| n.resolve(dev));
        for dev in devices {
            let id = |s| name(s, &dev).and_then(|n| interp.evaluate_if_present(n, Vec::new()));
            let tpm = |s| id(s).ok().flatten().is_some_and(|o| is_tpm(&o));
            if !tpm("_HID") && !tpm("_CID") {
                continue;
            }
            // Its _INI, and its parents' (only these: other devices' are
            // none of our business).
            let mut path = dev.clone();
            let mut scopes = ArrayVec::<AmlName, MAX_DEPTH>::new();
            let _ = scopes.push(dev.clone());
            while let Ok(p) = path.parent() {
                if p == AmlName::root() || scopes.contains(&p) {
                    break;
                }
                scopes.push(p.clone()).map_err(|_| "TPM device too deep in the namespace")?;
                path = p;
            }
            for s in scopes.iter().rev() {
                if let Ok(ini) = name("_INI", s) {
                    interp.evaluate_if_present(ini, Vec::new()).map_err(aml_err("_INI"))?;
                }
            }
            let dsm = name("_DSM", &dev).map_err(aml_err("_DSM name"))?;
            // Function 0: the functions it has, a bit each.
            let supported = interp.evaluate_if_present(dsm.clone(), dsm_args(0)).ok().flatten();
            let has_start = supported.as_ref().and_then(|o| o.as_buffer().ok()).is_some_and(|b| b.first().is_some_and(|f| f & (1 << START_FUNCTION) != 0));
            if has_start {
                return Ok(Start { interp, dsm });
            }
        }
        Err("no MSFT0101 device with the CRB start _DSM")
    }

    /// Start the command in the CRB buffer.
    pub fn start(&self) -> Result<(), &'static str> {
        let r = self.interp.evaluate(self.dsm.clone(), dsm_args(START_FUNCTION)).map_err(aml_err("_DSM start"))?;
        match r.as_integer() {
            Ok(0) => Ok(()),
            _ => Err("_DSM start failed"),
        }
    }
}
