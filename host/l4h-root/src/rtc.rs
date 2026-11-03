//! The machine RTC: the wall-clock seed at boot and dom0's RTC_SET.
//! Keep the hardware capability in root; guests never receive it.

#[cfg(target_arch = "x86_64")]
mod cmos;

use crate::{ctl, devmem::DevMem, mem::Alloc, window::Window};

pub struct Rtc {
    #[cfg(target_arch = "x86_64")]
    port: Option<sel4::cap::Null>,
    #[cfg(target_arch = "x86_64")]
    century: Option<u8>,
    #[cfg(target_arch = "aarch64")]
    frame: Option<sel4::cap::Granule>,
}

impl Rtc {
    pub fn new(alloc: &mut Alloc, _devmem: &mut DevMem) -> Self {
        #[cfg(target_arch = "x86_64")]
        { Self { port: crate::pci::io_ports(alloc, 0x70, 2), century: None } }
        #[cfg(target_arch = "aarch64")]
        { Self { frame: _devmem.frames(&mut alloc.slots, 0x0901_0000, 4096).map(|f| crate::devmem::granule(f.start)) } }
    }

    /// No RTC: a multikernel partition other than 0, whose clock comes
    /// from the shim's reading (partition.rs).
    pub fn none() -> Self {
        #[cfg(target_arch = "x86_64")]
        { Self { port: None, century: None } }
        #[cfg(target_arch = "aarch64")]
        { Self { frame: None } }
    }

    /// Only write a century register that firmware advertises: 0x32 can
    /// be ordinary battery-backed NVRAM on machines without one.
    #[cfg(target_arch = "x86_64")]
    pub fn find_century(&mut self, bootinfo: &sel4::BootInfoPtr, phys: &mut crate::acpi::Phys) {
        let mut fadt = [0; crate::acpi::FADT_LEN];
        self.century = crate::acpi::find(bootinfo, phys, b"FACP", &mut fadt)
            .and_then(|t| t.get(108).copied())
            .filter(|&r| (0x0e..0x80).contains(&r));
    }

    /// Nanoseconds since the Unix epoch, or 0 if no usable RTC exists.
    pub fn read_ns(&self, _win: &mut Window) -> u64 {
        #[cfg(target_arch = "x86_64")]
        { self.port.and_then(|p| cmos::read_ns(&mut Port(p.bits()), self.century)).unwrap_or(0) }
        #[cfg(target_arch = "aarch64")]
        { self.frame.map_or(0, |f| _win.with_frame_attrs(&crate::component::abs_of(f), crate::blkd::DEVICE_ATTRS,
            |p| unsafe { (p as *const u32).read_volatile() as u64 * 1_000_000_000 })) }
    }

    /// Set the RTC only: the boot-time anchor used by VMMs is unchanged.
    pub fn set_secs(&self, _win: &mut Window, seconds: u64) -> Result<(), i64> {
        #[cfg(target_arch = "x86_64")]
        {
            let port = self.port.ok_or(ctl::ENOSYS)?;
            cmos::set_secs(&mut Port(port.bits()), self.century, seconds).map_err(|e| match e {
                cmos::Error::Invalid => ctl::EINVAL,
                cmos::Error::Io => ctl::EIO,
            })
        }
        #[cfg(target_arch = "aarch64")]
        {
            let frame = self.frame.ok_or(ctl::ENOSYS)?;
            let seconds = u32::try_from(seconds).map_err(|_| ctl::EINVAL)?;
            // PL031: DR is read-only; LR (0x08) loads the seconds counter.
            _win.with_frame_attrs(&crate::component::abs_of(frame), crate::blkd::DEVICE_ATTRS, |p| unsafe {
                (p.add(0x08) as *mut u32).write_volatile(seconds);
            });
            Ok(())
        }
    }
}

#[cfg(target_arch = "x86_64")]
struct Port(u64);

#[cfg(target_arch = "x86_64")]
impl cmos::Registers for Port {
    fn read(&mut self, reg: u8) -> Result<u8, ()> {
        sel4::with_ipc_buffer_mut(|ipc| {
            let ipc = ipc.inner_mut();
            if ipc.seL4_X86_IOPort_Out8(self.0, 0x70, reg as u64) != 0 { return Err(()); }
            let r = ipc.seL4_X86_IOPort_In8(self.0, 0x71);
            if r.error == 0 { Ok(r.result as u8) } else { Err(()) }
        })
    }

    fn write(&mut self, reg: u8, value: u8) -> Result<(), ()> {
        sel4::with_ipc_buffer_mut(|ipc| {
            let ipc = ipc.inner_mut();
            if ipc.seL4_X86_IOPort_Out8(self.0, 0x70, reg as u64) != 0 { return Err(()); }
            if ipc.seL4_X86_IOPort_Out8(self.0, 0x71, value as u64) == 0 { Ok(()) } else { Err(()) }
        })
    }
}
