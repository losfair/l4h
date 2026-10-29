//! The PE/COFF details needed for an l4h EFI application: GRUB's `mods`
//! section and the Authenticode byte stream measured into PCR 4.

use core::ops::Range;

const MAX_SECTIONS: usize = 64;
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;

#[derive(Clone, Copy, Default)]
struct Section {
    offset: usize,
    size: usize,
}

#[derive(Clone, Copy)]
pub enum PeLayoutError {
    Incomplete,
    Invalid,
}

/// The owned part of PE parsing, independent of the mapped image bytes.
#[derive(Clone)]
pub struct PeLayout {
    checksum: usize,
    security_entry: Option<usize>,
    headers_size: usize,
    sections: [Section; MAX_SECTIONS],
    section_count: usize,
    certificate: Option<Range<usize>>,
    hashed_size: usize,
    image_len: usize,
}

/// Progress through Authenticode ranges, whose file offsets need not increase.
#[derive(Clone, Copy, Default)]
pub struct RangeCursor {
    range: usize,
    offset: usize,
}

pub struct Pe<'a> {
    pub mods: &'a [u8],
}

fn range(data: &[u8], offset: usize, size: usize) -> Result<Range<usize>, &'static str> {
    range_len(data.len(), offset, size)
}

fn range_len(len: usize, offset: usize, size: usize) -> Result<Range<usize>, &'static str> {
    let end = offset.checked_add(size).ok_or("PE offset overflow")?;
    if end > len {
        return Err("PE offset outside the file");
    }
    Ok(offset..end)
}

pub fn u16_at(data: &[u8], offset: usize) -> Result<u16, &'static str> {
    let r = range(data, offset, 2)?;
    Ok(u16::from_le_bytes(data[r].try_into().unwrap()))
}

pub fn u32_at(data: &[u8], offset: usize) -> Result<u32, &'static str> {
    let r = range(data, offset, 4)?;
    Ok(u32::from_le_bytes(data[r].try_into().unwrap()))
}

pub fn u64_at(data: &[u8], offset: usize) -> Result<u64, &'static str> {
    let r = range(data, offset, 8)?;
    Ok(u64::from_le_bytes(data[r].try_into().unwrap()))
}

pub fn usize_at(data: &[u8], offset: usize) -> Result<usize, &'static str> {
    usize::try_from(u64_at(data, offset)?).map_err(|_| "PE value does not fit the host")
}

impl PeLayout {
    /// Feed Authenticode ranges in hash order, without borrowing image data.
    /// The trailing SUM_OF_BYTES_HASHED range can overlap earlier offsets.
    pub fn for_each_range(&self, mut f: impl FnMut(Range<usize>)) {
        f(0..self.checksum);
        let after_checksum = self.checksum + 4;
        match self.security_entry {
            Some(entry) => {
                f(after_checksum..entry);
                f(entry + 8..self.headers_size);
            }
            None => f(after_checksum..self.headers_size),
        }
        for section in &self.sections[..self.section_count] {
            f(section.offset..section.offset + section.size);
        }
        match &self.certificate {
            Some(cert) => {
                f(self.hashed_size..cert.start);
                f(cert.end..self.image_len);
            }
            None => f(self.hashed_size..self.image_len),
        }
    }

    /// Feed newly available bytes from successive prefixes of one image.
    /// Unlike a file-offset high-water mark, the cursor still works when the
    /// specified trailing range starts before the end of the last section.
    pub fn stream(&self, cursor: &mut RangeCursor, data: &[u8], mut f: impl FnMut(&[u8])) {
        let mut index = cursor.range;
        let mut offset = cursor.offset;
        let mut skip = index;
        let mut waiting = false;
        self.for_each_range(|range| {
            if waiting {
                return;
            }
            if skip != 0 {
                skip -= 1;
                return;
            }
            if range.is_empty() {
                index += 1;
                offset = 0;
                return;
            }
            let start = range.start.max(offset);
            let end = range.end.min(data.len());
            if start < end {
                f(&data[start..end]);
                offset = end;
            }
            if offset < range.end {
                waiting = true;
            } else {
                index += 1;
                offset = 0;
            }
        });
        cursor.range = index;
        cursor.offset = offset;
    }
}

fn parse_impl(data: &[u8], image_len: usize, need_mods: bool) -> Result<(PeLayout, Option<Range<usize>>), &'static str> {
    if data.len() < 64 || &data[..2] != b"MZ" {
        return Err("not a PE application");
    }
    let pe = u32_at(data, 0x3c)? as usize;
    if range(data, pe, 24)?.is_empty() || &data[pe..pe + 4] != b"PE\0\0" {
        return Err("bad PE signature");
    }
    if u16_at(data, pe + 4)? != 0x8664 {
        return Err("not an x86_64 PE application");
    }
    let section_count = u16_at(data, pe + 6)? as usize;
    let optional_size = u16_at(data, pe + 20)? as usize;
    let optional = pe + 24;
    range(data, optional, optional_size)?;
    if optional_size < 72 || u16_at(data, optional)? != 0x20b {
        return Err("not a PE32+ application");
    }
    if section_count == 0 || section_count > MAX_SECTIONS {
        return Err("unsupported PE section count");
    }

    let checksum = optional + 64;
    let directory_count = if optional_size >= 112 {
        u32_at(data, optional + 108)? as usize
    } else {
        0
    };
    let directories = optional + 112;
    let available_directories = optional_size.saturating_sub(112) / 8;
    if directory_count > available_directories {
        return Err("bad PE data directories");
    }
    let security_entry = (directory_count > IMAGE_DIRECTORY_ENTRY_SECURITY)
        .then_some(directories + IMAGE_DIRECTORY_ENTRY_SECURITY * 8);
    let certificate = match security_entry {
        Some(entry) => {
            let offset = u32_at(data, entry)? as usize;
            let size = u32_at(data, entry + 4)? as usize;
            if offset == 0 && size == 0 {
                None
            } else if offset == 0 || size == 0 {
                return Err("bad PE certificate table");
            } else {
                Some(range_len(image_len, offset, size)?)
            }
        }
        None => None,
    };

    let headers_size = u32_at(data, optional + 60)? as usize;
    let section_table = optional + optional_size;
    range(
        data,
        section_table,
        section_count.checked_mul(40).ok_or("PE section overflow")?,
    )?;
    if headers_size < section_table + section_count * 40 || headers_size > data.len() {
        return Err("bad PE header size");
    }
    let mut sections = [Section::default(); MAX_SECTIONS];
    let mut count = 0;
    let mut mods = None;
    for i in 0..section_count {
        let at = section_table + i * 40;
        let size = u32_at(data, at + 16)? as usize;
        let offset = u32_at(data, at + 20)? as usize;
        let bytes = range_len(image_len, offset, size)?;
        if size != 0 && offset < headers_size {
            return Err("PE section overlaps the headers");
        }
        if need_mods && &data[at..at + 8] == b"mods\0\0\0\0" {
            if mods.replace(bytes).is_some() {
                return Err("duplicate PE mods section");
            }
        }
        if size != 0 {
            sections[count] = Section { offset, size };
            count += 1;
        }
    }
    let sections = &mut sections[..count];
    sections.sort_unstable_by_key(|s| s.offset);
    let mut sections_end = headers_size;
    for section in sections.iter() {
        if section.offset < sections_end {
            return Err("overlapping PE sections");
        }
        if let Some(cert) = &certificate {
            if section.offset < cert.end && cert.start < section.offset + section.size {
                return Err("PE certificate table overlaps a section");
            }
        }
        sections_end = section.offset + section.size;
    }
    if certificate
        .as_ref()
        .is_some_and(|cert| cert.start < sections_end)
    {
        return Err("PE certificate table is not after the sections");
    }
    let mut layout_sections = [Section::default(); MAX_SECTIONS];
    layout_sections[..count].copy_from_slice(sections);
    let hashed_size = headers_size + sections.iter().map(|section| section.size).sum::<usize>();
    Ok((PeLayout {
        checksum,
        security_entry,
        headers_size,
        sections: layout_sections,
        section_count: count,
        certificate,
        hashed_size,
        image_len,
    }, mods))
}

fn incomplete_prefix(data: &[u8]) -> bool {
    if data.len() < 64 {
        return true;
    }
    let Ok(pe) = u32_at(data, 0x3c) else { return true };
    let Some(optional) = (pe as usize).checked_add(24) else { return true };
    if optional > data.len() {
        return true;
    }
    let Ok(optional_size) = u16_at(data, pe as usize + 20) else { return true };
    let Some(section_table) = optional.checked_add(optional_size as usize) else { return true };
    if section_table > data.len() {
        return true;
    }
    let Ok(section_count) = u16_at(data, pe as usize + 6) else { return true };
    let Some(table_end) = section_table.checked_add(section_count as usize * 40) else { return true };
    if table_end > data.len() {
        return true;
    }
    let Ok(headers_size) = u32_at(data, optional + 60) else { return true };
    headers_size as usize > data.len()
}

impl<'a> Pe<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let (_, mods) = parse_impl(data, data.len(), true)?;
        let mods = mods.ok_or("PE application has no mods section")?;
        Ok(Self { mods: &data[mods] })
    }

    /// Parse layout from a prefix of an image of `image_len` bytes. Section
    /// and certificate bounds are checked against the complete image size,
    /// while the returned layout owns no borrow of the prefix.
    pub fn parse_layout(data: &[u8], image_len: usize) -> Result<PeLayout, PeLayoutError> {
        if incomplete_prefix(data) {
            return Err(PeLayoutError::Incomplete);
        }
        parse_impl(data, image_len, false).map(|(layout, _)| layout).map_err(|e| {
            if e == "PE offset outside the file" { PeLayoutError::Incomplete } else { PeLayoutError::Invalid }
        })
    }

}
