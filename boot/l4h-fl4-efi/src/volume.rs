// SPDX-License-Identifier: GPL-2.0-only
// Adapted from Monoid Machine's native slot loader.
use alloc::{string::ToString, vec::Vec};
use uefi::{
    CStr16, Handle, Status, boot,
    proto::{
        ProtocolPointer,
        loaded_image::LoadedImage,
        media::{
            block::BlockIO,
            disk::DiskIo,
            file::{
                Directory, File, FileAttribute, FileInfo, FileMode, FileSystemInfo, RegularFile,
            },
            fs::SimpleFileSystem,
        },
    },
};

use crate::policy::{self, Selector};

const SELECTOR: &CStr16 = uefi::cstr16!("\\EFI\\L4H\\grubenv");
pub const CONFIG: &CStr16 = uefi::cstr16!("\\l4h\\l4h.conf");
pub const INITRD: &CStr16 = uefi::cstr16!("\\l4h\\dom0\\initrd");

pub fn protocol<P: ProtocolPointer>(handle: Handle) -> uefi::Result<boot::ScopedProtocol<P>> {
    // Use the installed driver alongside the chainloader and the FAT driver.
    // These handles are used synchronously and dropped before any controller
    // reconnect or ExitBootServices.
    unsafe {
        boot::open_protocol(
            boot::OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            boot::OpenProtocolAttributes::GetProtocol,
        )
    }
}

fn volumes() -> uefi::Result<Vec<Handle>> {
    match boot::find_handles::<SimpleFileSystem>() {
        Err(e) if e.status() == Status::NOT_FOUND => Ok(Vec::new()),
        result => result,
    }
}

fn open_root(handle: Handle) -> uefi::Result<Directory> {
    protocol::<SimpleFileSystem>(handle)?.open_volume()
}

fn open_file(root: &mut Directory, path: &CStr16) -> uefi::Result<Option<RegularFile>> {
    match root.open(path, FileMode::Read, FileAttribute::empty()) {
        Ok(file) => file
            .into_regular_file()
            .map(Some)
            .ok_or(Status::LOAD_ERROR.into()),
        Err(e) if e.status() == Status::NOT_FOUND => Ok(None),
        Err(e) => Err(e),
    }
}

fn contents(mut file: RegularFile) -> uefi::Result<Vec<u8>> {
    let len = usize::try_from(file.get_boxed_info::<FileInfo>()?.file_size())
        .map_err(|_| Status::BAD_BUFFER_SIZE)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| Status::OUT_OF_RESOURCES)?;
    bytes.resize(len, 0);
    if file.read(&mut bytes)? != len {
        return Err(Status::END_OF_FILE.into());
    }
    Ok(bytes)
}

pub fn read_optional(root: &mut Directory, path: &CStr16) -> uefi::Result<Option<Vec<u8>>> {
    open_file(root, path)?.map(contents).transpose()
}

fn selector_device(handles: &[Handle]) -> uefi::Result<Option<Handle>> {
    let mut selector = None;
    for &handle in handles {
        let mut root = match open_root(handle) {
            Err(e) if e.status() == Status::NO_MEDIA => continue,
            result => result?,
        };
        if open_file(&mut root, SELECTOR)?.is_some() && selector.replace(handle).is_some() {
            return Err(Status::LOAD_ERROR.into());
        }
    }
    Ok(selector)
}

fn matches_selector(device: Handle, selected: &Selector<'_>) -> bool {
    match selected {
        Selector::Label(label) => open_root(device)
            .and_then(|mut root| root.get_boxed_info::<FileSystemInfo>())
            .is_ok_and(|info| info.volume_label().to_string() == *label),
        Selector::Uuid(serial) => {
            let Ok(block) = protocol::<BlockIO>(device) else {
                return false;
            };
            let Ok(disk) = protocol::<DiskIo>(device) else {
                return false;
            };
            let mut sector = [0; 512];
            disk.read_disk(block.media().media_id(), 0, &mut sector)
                .is_ok()
                && policy::fat_serial(&sector) == Some(*serial)
        }
    }
}

pub fn selected_volume() -> Result<Option<Directory>, &'static str> {
    let handles = volumes().map_err(|_| "cannot enumerate EFI filesystems")?;
    if let Some(device) =
        selector_device(&handles).map_err(|_| "unreadable or multiple boot selectors")?
    {
        // A front GRUB may have just used save_env via raw disk I/O. Drop the
        // firmware FAT driver's cache before reading the updated selector.
        if protocol::<BlockIO>(device).is_ok() {
            boot::disconnect_controller(device, None, None)
                .map_err(|_| "cannot refresh selector volume")?;
            boot::connect_controller(device, &[], None, false)
                .map_err(|_| "cannot reopen selector volume")?;
        }
        let mut root = open_root(device).map_err(|_| "cannot open selector volume")?;
        let data = read_optional(&mut root, SELECTOR)
            .map_err(|_| "cannot read boot selector")?
            .ok_or("missing boot selector")?;
        drop(root);
        let selected = policy::selector(&data).ok_or("invalid boot selector")?;
        let handles = volumes().map_err(|_| "cannot enumerate slot filesystems")?;
        let mut matches = handles
            .into_iter()
            .filter(|&h| matches_selector(h, &selected));
        let device = matches.next().ok_or("selected boot partition is missing")?;
        if matches.next().is_some() {
            return Err("multiple partitions match the boot selector");
        }
        return open_root(device)
            .map(Some)
            .map_err(|_| "cannot open selected boot partition");
    }

    let loaded =
        protocol::<LoadedImage>(boot::image_handle()).map_err(|_| "cannot open loaded image")?;
    if let Some(device) = loaded.device().filter(|h| handles.contains(h)) {
        return open_root(device)
            .map(Some)
            .map_err(|_| "cannot open loading partition");
    }
    // Some firmware supplies no filesystem device. Preserve the release's
    // search order: a partition with an initramfs, then one with a config.
    for path in [INITRD, CONFIG] {
        for &device in &handles {
            if let Ok(mut root) = open_root(device)
                && open_file(&mut root, path)
                    .map_err(|_| "cannot inspect boot partition")?
                    .is_some()
            {
                return Ok(Some(root));
            }
        }
    }
    Ok(None)
}
