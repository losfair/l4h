//! FL4's Intel TDX control (seL4_X86_TdxControl), which a TD's kernel
//! gives the initial task in its CNode slot seL4_CapSMC (ROOT_SLOT), and
//! root hands on to trustd: TDG.MR.REPORT, TDG.MR.RTMR.EXTEND and
//! TDG.VP.VMCALL<GetQuote>.  A kernel without the extension (seL4, FL4
//! built for another machine) refuses every call (seL4_IllegalOperation),
//! so callers build and run unchanged either way; SUPPORTED says which.
//!
//! The words of REPORTDATA and of an RTMR extension are the bytes in
//! memory order: word i is bytes 8i..8i+8, little-endian.

/// Whether the kernel's interface has TdxControl.
pub const SUPPORTED: bool = cfg!(l4h_kernel_tdx);

/// seL4_CapSMC: where a TD's kernel puts the TdxControl capability.
pub const ROOT_SLOT: usize = 15;

/// TDREPORT_STRUCT's size, as TDG.MR.REPORT writes it.
pub const REPORT_SIZE: usize = 1024;

/// Why a call failed: the kernel refused it, or the TDX module (or, for
/// GetQuote, the VMM) answered this status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Kernel(sel4::Error),
    Status(u64),
}

/// TDG.VP.VMCALL_RETRY: the VMM is busy; ask again later.
pub const VMCALL_RETRY: u64 = 1;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Kernel(e) => write!(f, "kernel error {:?}", e),
            Error::Status(s) => write!(f, "status {:#x}", s),
        }
    }
}

#[cfg_attr(not(l4h_kernel_tdx), allow(dead_code))]
fn words<const N: usize>(b: &[u8]) -> [u64; N] {
    core::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()))
}

#[cfg_attr(not(l4h_kernel_tdx), allow(dead_code))]
fn result(error: u64, status: u64) -> Result<(), Error> {
    if let Some(e) = sel4::Error::from_sys(error as _) {
        return Err(Error::Kernel(e));
    }
    if status != 0 { Err(Error::Status(status)) } else { Ok(()) }
}

/// TDG.MR.REPORT with `data` as REPORTDATA: the TDREPORT_STRUCT
/// (REPORT_SIZE bytes) into the private frame `frame` (a 4 KiB frame
/// capability, `tdx` the TdxControl capability, both as CPtrs).
#[cfg(l4h_kernel_tdx)]
pub fn get_report(tdx: u64, frame: u64, data: &[u8; 64]) -> Result<(), Error> {
    let d: [u64; 8] = words(data);
    let r = sel4::with_ipc_buffer_mut(|ipc| {
        ipc.inner_mut().seL4_X86_TdxControl_GetReport(tdx, frame, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7])
    });
    result(r.error as u64, r.tdx_status as u64)
}

/// TDG.MR.RTMR.EXTEND of RTMR `index` (0-3) with `digest`.
#[cfg(l4h_kernel_tdx)]
pub fn extend_rtmr(tdx: u64, index: u64, digest: &[u8; 48]) -> Result<(), Error> {
    let d: [u64; 6] = words(digest);
    let r = sel4::with_ipc_buffer_mut(|ipc| {
        ipc.inner_mut().seL4_X86_TdxControl_ExtendRTMR(tdx, index, d[0], d[1], d[2], d[3], d[4], d[5])
    });
    result(r.error as u64, r.tdx_status as u64)
}

/// TDG.VP.VMCALL<GetQuote> on the first `len` bytes (a multiple of 4 KiB)
/// of the shared frame `frame`, which hold the GHCI header and the
/// TDREPORT.  The VMM answers in the frame later; Status(VMCALL_RETRY) if
/// it is busy.
#[cfg(l4h_kernel_tdx)]
pub fn get_quote(tdx: u64, frame: u64, len: u64) -> Result<(), Error> {
    let r = sel4::with_ipc_buffer_mut(|ipc| ipc.inner_mut().seL4_X86_TdxControl_GetQuote(tdx, frame, len));
    result(r.error as u64, r.vmcall_status as u64)
}

/// A kernel without TdxControl refuses it.
#[cfg(not(l4h_kernel_tdx))]
pub fn get_report(_tdx: u64, _frame: u64, _data: &[u8; 64]) -> Result<(), Error> {
    Err(Error::Kernel(sel4::Error::IllegalOperation))
}

#[cfg(not(l4h_kernel_tdx))]
pub fn extend_rtmr(_tdx: u64, _index: u64, _digest: &[u8; 48]) -> Result<(), Error> {
    Err(Error::Kernel(sel4::Error::IllegalOperation))
}

#[cfg(not(l4h_kernel_tdx))]
pub fn get_quote(_tdx: u64, _frame: u64, _len: u64) -> Result<(), Error> {
    Err(Error::Kernel(sel4::Error::IllegalOperation))
}
