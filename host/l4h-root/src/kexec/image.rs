//! Parse the uncompressed files in an l4h standalone EFI application.

use super::grub::Grub;
use super::kernel::KernelImage;
use super::pe::{Pe, u64_at};

pub struct Image<'a> {
    pub grub: Grub,
    pub kernel: KernelImage<'a>,
    pub root: &'a [u8],
    pub guest_kernel: &'a [u8],
    pub guest_kmods: Option<&'a [u8]>,
}

fn memdisk(mods: &[u8]) -> Result<&[u8], &'static str> {
    if mods.len() < 24 || &mods[..8] != b"mimg\0\0\0\0" {
        return Err("GRUB mods section has no mimg header");
    }
    let mut offset =
        usize::try_from(u64_at(mods, 8)?).map_err(|_| "mimg offset does not fit the host")?;
    let end = usize::try_from(u64_at(mods, 16)?).map_err(|_| "mimg size does not fit the host")?;
    if offset < 24
        || offset % 8 != 0
        || end > mods.len()
        || offset > end
        || mods[end..].iter().any(|&b| b != 0)
    {
        return Err("bad mimg bounds");
    }
    let mut result = None;
    while offset < end {
        if end - offset < 8 {
            return Err("truncated mimg entry");
        }
        let kind = u32::from_le_bytes(mods[offset..offset + 4].try_into().unwrap());
        let size = u32::from_le_bytes(mods[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if size < 8 || size % 8 != 0 || size > end - offset {
            return Err("bad mimg entry size");
        }
        let body = &mods[offset + 8..offset + size];
        match kind {
            0 | 3 => {}
            1 => {
                if result.replace(body).is_some() {
                    return Err("multiple GRUB memdisks");
                }
            }
            _ => return Err("unknown mimg entry type"),
        }
        offset += size;
    }
    result.ok_or("GRUB image has no memdisk")
}

fn octal(field: &[u8]) -> Result<usize, &'static str> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        return Err("base-256 tar numbers are unsupported");
    }
    let mut value = 0usize;
    let mut digits = false;
    let mut tail = false;
    for &b in field {
        match b {
            b'0'..=b'7' if !tail => {
                digits = true;
                value = value
                    .checked_mul(8)
                    .and_then(|v| v.checked_add((b - b'0') as usize))
                    .ok_or("tar number overflow")?;
            }
            0 | b' ' => tail = true,
            _ => return Err("bad tar number"),
        }
    }
    if digits { Ok(value) } else { Ok(0) }
}

fn tar_files<'a>(
    tar: &'a [u8],
) -> Result<(&'a [u8], &'a [u8], &'a [u8], &'a [u8], Option<&'a [u8]>), &'static str> {
    let mut grub_cfg = None;
    let mut kernel = None;
    let mut root = None;
    let mut guest_kernel = None;
    let mut guest_kmods = None;
    let mut offset = 0usize;
    loop {
        if tar.len() - offset < 512 {
            return Err("unterminated tar memdisk");
        }
        let header = &tar[offset..offset + 512];
        if header.iter().all(|&b| b == 0) {
            if tar[offset..].iter().any(|&b| b != 0) {
                return Err("data follows the tar end marker");
            }
            break;
        }
        if &header[257..262] != b"ustar" || header[345] != 0 {
            return Err("unsupported tar header");
        }
        let size = octal(&header[124..136])?;
        let stored = octal(&header[148..156])?;
        let checksum: usize = header
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if (148..156).contains(&i) {
                    b' ' as usize
                } else {
                    b as usize
                }
            })
            .sum();
        if checksum != stored {
            return Err("bad tar header checksum");
        }
        let name_end = header[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let name = &header[..name_end];
        if name.starts_with(b"/") || name.split(|&b| b == b'/').any(|part| part == b"..") {
            return Err("unsafe tar path");
        }
        let kind = header[156];
        if kind != 0 && kind != b'0' && kind != b'5' {
            return Err("unsupported tar entry type");
        }
        let data_at = offset + 512;
        let data_end = data_at.checked_add(size).ok_or("tar file overflow")?;
        let next = data_end
            .checked_add(511)
            .map(|v| v & !511)
            .ok_or("tar file overflow")?;
        if next > tar.len() {
            return Err("truncated tar file");
        }
        if kind == b'5' && size != 0 {
            return Err("tar directory has file data");
        }
        let data = &tar[data_at..data_end];
        let slot = match name {
            b"boot/grub/grub.cfg" => &mut grub_cfg,
            b"boot/kernel.elf" => &mut kernel,
            b"boot/l4h-root.elf" => &mut root,
            b"boot/vmlinux" => &mut guest_kernel,
            b"boot/kmods.erofs" => &mut guest_kmods,
            _ if kind != b'5' && name.starts_with(b"boot/") && !name.starts_with(b"boot/grub/") => {
                return Err("unknown file in the EFI boot directory");
            }
            _ => {
                offset = next;
                continue;
            }
        };
        if kind == b'5' || slot.replace(data).is_some() {
            return Err("duplicate or non-regular boot file");
        }
        offset = next;
    }
    Ok((
        grub_cfg.ok_or("missing boot/grub/grub.cfg")?,
        kernel.ok_or("missing boot/kernel.elf")?,
        root.ok_or("missing boot/l4h-root.elf")?,
        guest_kernel.ok_or("missing boot/vmlinux")?,
        guest_kmods,
    ))
}

impl<'a> Image<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let pe = Pe::parse(data)?;
        let (grub_cfg, kernel, root, guest_kernel, guest_kmods) = tar_files(memdisk(pe.mods)?)?;
        if root.is_empty() || guest_kernel.is_empty() {
            return Err("empty host boot file");
        }
        let grub = Grub::parse(grub_cfg, guest_kmods.is_some())?;
        Ok(Self {
            grub,
            kernel: KernelImage::parse(kernel)?,
            root,
            guest_kernel,
            guest_kmods,
        })
    }
}
