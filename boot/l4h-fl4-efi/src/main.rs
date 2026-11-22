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

/// Measure every external slot, in order, into PCR 9 (with a TPM) and
/// RTMR[2] (in a trust domain): a present file as its slot's `present`
/// prefix and its bytes (`buffer`, read after that prefix), a missing one as
/// its slot's `absent` bytes. Never zero bytes, and never nothing.
fn measure(
    firmware: &Firmware<'_>,
    slots: &[(&policy::Slot, Option<&[u8]>)],
) -> Result<(), Status> {
    let mut tpm = match boot::get_handle_for_protocol::<Tcg>() {
        Ok(handle) => Some(volume::protocol::<Tcg>(handle).map_err(|e| e.status())?),
        Err(e) if e.status() == Status::NOT_FOUND => None,
        Err(e) => return Err(e.status()),
    };
    for &(slot, buffer) in slots {
        let bytes = buffer.unwrap_or(slot.absent);
        // The one buffer is what policy::measured describes in pieces.
        debug_assert!(
            policy::measured(slot, buffer.and_then(|b| b.strip_prefix(slot.present))).concat()
                == bytes
        );
        // TDX measures external bytes independently of an optional vTPM.
        firmware.measure_cc_file(slot.name, bytes).map_err(Status)?;
        if let Some(tpm) = &mut tpm {
            // Match Monoid's EV_IPL events: the module name padded to 16 bytes.
            let mut label = [0; 16];
            label[..slot.name.len()].copy_from_slice(slot.name);
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
    use policy::{CONFIG_SLOT, INITRD_SLOT};
    fw.print(format_args!("l4h-efi: native FL4 loader"));
    // Each file after its slot's `present` prefix: the buffer is what is
    // measured, the file past the prefix what is booted.
    let (config, initrd) = match volume::selected_volume().map_err(|reason| {
        fw.print(format_args!("l4h-efi: {reason}"));
        "boot partition selection failed"
    })? {
        Some(mut root) => (
            volume::read_optional_with_prefix(&mut root, volume::CONFIG, CONFIG_SLOT.present)
                .map_err(|_| "cannot read /l4h/l4h.conf")?,
            volume::read_optional_with_prefix(&mut root, volume::INITRD, INITRD_SLOT.present)
                .map_err(|_| "cannot read /l4h/dom0/initrd")?,
        ),
        None => (None, None),
    };
    let slots = [
        (&CONFIG_SLOT, config.as_deref()),
        (&INITRD_SLOT, initrd.as_deref()),
    ];
    // Both slots, present or not, in policy::SLOTS order.
    debug_assert!(slots.iter().map(|s| s.0).eq(policy::SLOTS));
    if let Err(status) = measure(fw, &slots) {
        fw.print(format_args!(
            "l4h-efi: boot file measurement failed ({status:?})"
        ));
        return Err("cannot measure external boot files");
    }
    let mut modules: Vec<(&[u8], &[u8])> =
        vec![(b"rootserver", ROOT_TASK), (b"guest-kernel", GUEST_KERNEL)];
    if !SDK.is_empty() {
        modules.push((b"guest-sdk", SDK));
    }
    for (slot, buffer) in slots {
        if let Some(buffer) = buffer {
            // The file's exact bytes, past the measured prefix.
            modules.push((slot.name, &buffer[slot.present.len()..]));
        }
    }
    let fb = policy::fb_console(
        config
            .as_deref()
            .map_or(&[][..], |b| &b[CONFIG_SLOT.present.len()..]),
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
