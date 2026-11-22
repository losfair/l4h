// SPDX-License-Identifier: GPL-2.0-only
// Derived from Monoid Machine's native FL4 EFI slot loader.
#![no_std]
#![no_main]

extern crate alloc;
use alloc::{vec, vec::Vec};
use fl4_efi::Firmware;
use uefi::{
    Status, boot,
    proto::tcg::{
        EventType, PcrIndex,
        v2::{HashLogExtendEventFlags, PcrEventInputs, Tcg},
    },
};
mod policy;
mod volume;

const KERNEL: &[u8] = include_bytes!(env!("L4H_EFI_KERNEL"));
const ROOT_TASK: &[u8] = include_bytes!(env!("L4H_EFI_ROOT_TASK"));
const GUEST_KERNEL: &[u8] = include_bytes!(env!("L4H_EFI_GUEST_KERNEL"));
const SDK: &[u8] = include_bytes!(env!("L4H_EFI_SDK"));

fn measure(firmware: &Firmware<'_>, files: &[(&[u8], &[u8])]) -> Result<(), Status> {
    if files.is_empty() {
        return Ok(());
    }
    let mut tpm = match boot::get_handle_for_protocol::<Tcg>() {
        Ok(handle) => Some(volume::protocol::<Tcg>(handle).map_err(|e| e.status())?),
        Err(e) if e.status() == Status::NOT_FOUND => None,
        Err(e) => return Err(e.status()),
    };
    for &(name, bytes) in files {
        // TDX measures external bytes independently of an optional vTPM.
        firmware.measure_cc_file(name, bytes).map_err(Status)?;
        if let Some(tpm) = &mut tpm {
            // Match Monoid's EV_IPL events: the module name padded to 16 bytes.
            let mut label = [0; 16];
            label[..name.len()].copy_from_slice(name);
            let mut buffer = [0; 64];
            let event =
                PcrEventInputs::new_in_buffer(&mut buffer, PcrIndex(9), EventType::IPL, &label)
                    .map_err(|e| e.status())?;
            match tpm.hash_log_extend_event(HashLogExtendEventFlags::empty(), bytes, event) {
                Ok(()) => {}
                // EFI_VOLUME_FULL means the register was extended but the log is full.
                Err(e) if e.status() == Status::VOLUME_FULL => {}
                Err(e) => return Err(e.status()),
            }
        }
    }
    Ok(())
}

fn boot_l4h(fw: &Firmware<'_>) -> Result<(), &'static str> {
    fw.print(format_args!("l4h-efi: native FL4 loader"));
    let (config, initrd) = match volume::selected_volume().map_err(|reason| {
        fw.print(format_args!("l4h-efi: {reason}"));
        "boot partition selection failed"
    })? {
        Some(mut root) => (
            volume::read_optional(&mut root, volume::CONFIG)
                .map_err(|_| "cannot read /l4h/l4h.conf")?,
            volume::read_optional(&mut root, volume::INITRD)
                .map_err(|_| "cannot read /l4h/dom0/initrd")?,
        ),
        None => (None, None),
    };
    let mut modules: Vec<(&[u8], &[u8])> =
        vec![(b"rootserver", ROOT_TASK), (b"guest-kernel", GUEST_KERNEL)];
    if !SDK.is_empty() {
        modules.push((b"guest-sdk", SDK));
    }
    let embedded = modules.len();
    if let Some(bytes) = &config {
        modules.push((b"l4h-config", bytes));
    }
    if let Some(bytes) = &initrd {
        modules.push((b"dom0-initrd", bytes));
    }
    if let Err(status) = measure(fw, &modules[embedded..]) {
        fw.print(format_args!(
            "l4h-efi: boot file measurement failed ({status:?})"
        ));
        return Err("cannot measure external boot files");
    }
    let fb = policy::fb_console(
        config.as_deref().unwrap_or_default(),
        env!("L4H_EFI_FB_CONSOLE") == "1",
    );
    let cmdline = if fb { c"fb_console" } else { c"" };
    // Only the embedded, revision-matched FL4 kernel and root task get
    // executable authority here. Load options cannot substitute either.
    unsafe { fw.boot_with_cmdline(KERNEL, &modules, cmdline) }
}

#[uefi::entry]
fn main() -> Status {
    let image = boot::image_handle().as_ptr();
    let system = uefi::table::system_table_raw().unwrap().as_ptr().cast();
    // The entry macro has installed the firmware's image handle and system table.
    Status(unsafe {
        fl4_efi::with_firmware(image, system, |fw| match boot_l4h(fw) {
            Ok(()) => Status::SUCCESS.0,
            Err(reason) => {
                fw.print(format_args!("l4h-efi: {reason}"));
                Status::LOAD_ERROR.0
            }
        })
    })
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // FL4 may have exited boot services by the time the panic is raised.
    if let Some(st) = uefi::table::system_table_raw() {
        let st = unsafe { st.as_ref() };
        if !st.boot_services.is_null() && !st.stdout.is_null() {
            uefi::system::with_stdout(|out| {
                let _ = out.output_string(uefi::cstr16!("l4h-efi: panic\r\n"));
            });
        }
    }
    loop {
        unsafe { core::arch::asm!("hlt") };
    }
}
