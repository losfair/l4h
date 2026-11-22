// SPDX-License-Identifier: GPL-2.0-only

#[derive(Debug, PartialEq)]
pub enum Selector<'a> {
    Uuid(u32),
    Label(&'a str),
}

pub fn selector(bytes: &[u8]) -> Option<Selector<'_>> {
    let mut block = bytes.strip_prefix(b"# GRUB Environment Block\n")?;
    let mut uuid = None;
    let mut label = None;
    while let Some(end) = record_end(block) {
        let line = &block[..end];
        block = &block[end + 1..];
        if let Some(value) = line.strip_prefix(b"l4h_esp_uuid=") {
            if uuid.replace(value).is_some() {
                return None;
            }
        } else if let Some(value) = line.strip_prefix(b"l4h_esp_label=") {
            if label.replace(value).is_some() {
                return None;
            }
        }
    }
    // grub-editenv pads the rest of the file with '#'.
    if !block.iter().all(|&b| b == b'#') {
        return None;
    }
    match (uuid.unwrap_or_default(), label.unwrap_or_default()) {
        (uuid, b"") if uuid.len() == 9 && uuid[4] == b'-' => {
            let hex = |s| u16::from_str_radix(core::str::from_utf8(s).ok()?, 16).ok();
            if !uuid[..4]
                .iter()
                .chain(&uuid[5..])
                .all(u8::is_ascii_hexdigit)
            {
                return None;
            }
            Some(Selector::Uuid(
                (u32::from(hex(&uuid[..4])?) << 16) | u32::from(hex(&uuid[5..])?),
            ))
        }
        (b"", label) if !label.is_empty() => {
            Some(Selector::Label(core::str::from_utf8(label).ok()?))
        }
        _ => None,
    }
}

// GRUB escapes newlines and backslashes in values. A continuation of an
// unrelated variable must never be interpreted as another selector.
fn record_end(block: &[u8]) -> Option<usize> {
    let mut bytes = block.iter().enumerate();
    while let Some((i, &byte)) = bytes.next() {
        match byte {
            b'\\' => {
                bytes.next();
            }
            b'\n' => return Some(i),
            _ => {}
        }
    }
    None
}

// FAT filesystem UUIDs in GRUB are the 32-bit volume serial in the BPB,
// independent of the partition number and of the GPT partition GUID.
pub fn fat_serial(sector: &[u8; 512]) -> Option<u32> {
    let bps = u16::from_le_bytes([sector[11], sector[12]]);
    if sector[510..] != [0x55, 0xaa]
        || !matches!(bps, 512 | 1024 | 2048 | 4096)
        || !sector[13].is_power_of_two()
        || sector[16] == 0
    {
        return None;
    }
    let sig = if sector[22..24] == [0, 0] { 66 } else { 38 };
    matches!(sector[sig], 0x28 | 0x29)
        .then(|| u32::from_le_bytes(sector[sig + 1..sig + 5].try_into().unwrap()))
}

// Only this setting is consumed by the FL4 kernel itself. The root task
// receives the original file and parses all of its settings as usual.
pub fn fb_console(config: &[u8], default: bool) -> bool {
    let mut enabled = default;
    for line in config.split(|&b| b == b'\n') {
        let Ok(line) = core::str::from_utf8(line) else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() == "fb_console" {
            let value = value.trim();
            let unquoted = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')));
            enabled = unquoted.unwrap_or(value) == "1";
        }
    }
    enabled
}
