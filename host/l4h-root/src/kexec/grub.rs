//! The one grub.cfg logic root can reproduce without running GRUB script.

#[derive(Clone, Copy)]
pub struct SerialPort {
    pub text: [u8; 16],
    pub len: usize,
}

impl SerialPort {
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let bytes = text.as_bytes();
        if bytes.is_empty() || bytes.len() > 16 {
            return Err("bad serial_port");
        }
        let (digits, radix) = match bytes {
            [b'0', b'x', rest @ ..] if !rest.is_empty() => (rest, 16),
            _ => (bytes, 10),
        };
        let mut value = 0u32;
        for &b in digits {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' if radix == 16 => b - b'a' + 10,
                b'A'..=b'F' if radix == 16 => b - b'A' + 10,
                _ => return Err("bad serial_port"),
            };
            if digit as u32 >= radix {
                return Err("bad serial_port");
            }
            value = value
                .checked_mul(radix)
                .and_then(|v| v.checked_add(digit as u32))
                .ok_or("bad serial_port")?;
        }
        if value > 0xfff8 {
            return Err("serial_port is out of range");
        }
        let mut stored = [0; 16];
        stored[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            text: stored,
            len: bytes.len(),
        })
    }

    pub fn text(&self) -> &[u8] {
        &self.text[..self.len]
    }
}

pub struct Grub {
    pub serial_port: SerialPort,
    pub fb_console: bool,
}

// Effective lines after serial_port/fb_console, shared with mkefi.sh.
// Empty lines, comments and indentation do not change the script. ACPI is
// rejected below; the kmods line is conditional on the memdisk containing it.
const FIXED_SCRIPT: &str = include_str!("../../../../tools/l4h-grub-fixed.cfg");
const KMODS_LINE: &str = "module2 (memdisk)/boot/kmods.erofs guest-kmods";

fn fixed_lines() -> impl Iterator<Item = &'static str> {
    FIXED_SCRIPT
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && *line != "@ACPI@")
        .map(|line| if line == "@KMODS@" { KMODS_LINE } else { line })
}

impl Grub {
    pub fn parse(script: &[u8], has_kmods: bool) -> Result<Self, &'static str> {
        let script = core::str::from_utf8(script).map_err(|_| "grub.cfg is not UTF-8")?;
        let mut lines = script.lines();
        if lines.next() != Some("# l4h-boot 1") {
            return Err("grub.cfg is not l4h-boot version 1");
        }
        let mut active = lines.filter_map(|line| {
            let line = line.trim();
            (!line.is_empty() && !line.starts_with('#')).then_some(line)
        });
        if active.next() != Some("set timeout=0") {
            return Err("unsupported grub.cfg timeout");
        }
        let serial = active
            .next()
            .and_then(|line| line.strip_prefix("serial_port="))
            .ok_or("missing grub.cfg serial_port")?;
        let serial_port = SerialPort::parse(serial)?;
        let fb_console = match active
            .next()
            .and_then(|line| line.strip_prefix("fb_console="))
        {
            Some("0") => false,
            Some("1") => true,
            _ => return Err("missing or bad grub.cfg fb_console"),
        };
        let mut fixed = fixed_lines();
        for line in active {
            let mut expected = fixed.next();
            if expected == Some(KMODS_LINE) && !has_kmods {
                expected = fixed.next();
            }
            if expected != Some(line) {
                if line.starts_with("acpi") {
                    return Err("kexec does not replace ACPI tables");
                }
                return Err("grub.cfg has commands root does not reproduce");
            }
        }
        if fixed.next().is_some() {
            return Err("truncated grub.cfg");
        }
        Ok(Self {
            serial_port,
            fb_console,
        })
    }
}
