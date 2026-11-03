//! What the boot loader gives the shim: multiboot2 (GRUB) or multiboot1
//! (QEMU's -kernel), reduced to the memory map, the modules, the command
//! line, the ACPI RSDP and the framebuffer.

use crate::io::{Str, Vec, phys, rd16, rd32, rd64};

pub const MB1_MAGIC: u32 = 0x2badb002;
pub const MB2_MAGIC: u32 = 0x36d76289;

pub const E820_RAM: u32 = 1;
pub const E820_RESERVED: u32 = 2;

#[derive(Clone, Copy)]
pub struct E820 {
    pub base: u64,
    pub len: u64,
    pub kind: u32,
}

#[derive(Clone, Copy)]
pub struct Module {
    pub start: u64,
    pub end: u64,
    /// The last word of the module's string, which names its role.
    pub name: Str<64>,
}

impl Module {
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    pub fn bytes(&self) -> &'static [u8] {
        unsafe { phys(self.start, self.len() as usize) }
    }
}

pub struct BootInfo {
    pub mmap: Vec<E820, 256>,
    pub mods: Vec<Module, 64>,
    pub cmdline: Str<1024>,
    /// A copy of the RSDP (36 bytes; ACPI 1.0 ones use the first 20).
    pub rsdp: Option<[u8; 36]>,
    /// The multiboot2 framebuffer tag, as is, for partition 0.
    pub fb_tag: Vec<u8, 256>,
}

impl BootInfo {
    pub fn parse(magic: u32, info: u64) -> BootInfo {
        let mut b = BootInfo { mmap: Vec::new(), mods: Vec::new(), cmdline: Str::new(), rsdp: None, fb_tag: Vec::new() };
        match magic {
            MB2_MAGIC => b.mb2(info),
            MB1_MAGIC => b.mb1(info),
            _ => crate::fail(format_args!("not booted by a multiboot loader (magic {:#x})", magic)),
        }
        if b.rsdp.is_none() {
            b.rsdp = scan_rsdp();
        }
        b
    }

    fn mb2(&mut self, info: u64) {
        let total = rd32(unsafe { phys(info, 8) }, 0) as usize;
        let all = unsafe { phys(info, total) };
        let mut off = 8;
        while off + 8 <= total {
            let (ty, size) = (rd32(all, off), rd32(all, off + 4) as usize);
            if ty == 0 || size < 8 || off + size > total {
                break;
            }
            let t = &all[off..off + size];
            match ty {
                1 => self.cmdline.push(cstr(&t[8..])),
                3 => {
                    let (start, end) = (rd32(t, 8) as u64, rd32(t, 12) as u64);
                    self.add_module(start, end, cstr(&t[16..]));
                }
                6 => {
                    let esize = rd32(t, 8) as usize;
                    let mut e = 16;
                    while esize >= 20 && e + esize <= size {
                        self.mmap.must_push(E820 { base: rd64(t, e), len: rd64(t, e + 8), kind: rd32(t, e + 16) });
                        e += esize;
                    }
                }
                14 | 15 if self.rsdp.is_none() || ty == 15 => {
                    let mut r = [0; 36];
                    let n = (size - 8).min(36);
                    r[..n].copy_from_slice(&t[8..8 + n]);
                    self.rsdp = Some(r);
                }
                8 => {
                    for &x in t {
                        self.fb_tag.push(x);
                    }
                }
                _ => {}
            }
            off += (size + 7) & !7;
        }
    }

    fn mb1(&mut self, info: u64) {
        let i = unsafe { phys(info, 88) };
        let flags = rd32(i, 0);
        if flags & 4 != 0 {
            self.cmdline.push(cstr(unsafe { phys(rd32(i, 16) as u64, 1024) }));
        }
        if flags & 8 != 0 {
            let (count, addr) = (rd32(i, 20) as usize, rd32(i, 24) as u64);
            let list = unsafe { phys(addr, count * 16) };
            for m in 0..count {
                let e = &list[m * 16..];
                let s = cstr(unsafe { phys(rd32(e, 8) as u64, 256) });
                self.add_module(rd32(e, 0) as u64, rd32(e, 4) as u64, s);
            }
        }
        if flags & 0x40 != 0 {
            let (len, addr) = (rd32(i, 44) as u64, rd32(i, 48) as u64);
            let mut p = addr;
            while p < addr + len {
                let e = unsafe { phys(p, 24) };
                let size = rd32(e, 0) as u64;
                self.mmap.must_push(E820 { base: rd64(e, 4), len: rd64(e, 12), kind: rd32(e, 20) });
                p += size + 4;
            }
        } else {
            crate::fail(format_args!("no memory map from the boot loader"));
        }
    }

    fn add_module(&mut self, start: u64, end: u64, s: &str) {
        let name = s.split_whitespace().last().unwrap_or("");
        // A file name names the module by its last path component.
        let name = name.rsplit('/').next().unwrap_or(name);
        self.mods.must_push(Module { start, end, name: Str::from(name) });
    }

    pub fn module(&self, name: &str) -> Option<&Module> {
        self.mods.iter().find(|m| m.name.as_str() == name)
    }
}

fn cstr(b: &[u8]) -> &str {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    core::str::from_utf8(&b[..n]).unwrap_or("")
}

/// The RSDP in the EBDA's first KiB or the BIOS area (ACPI 5.2.5.1).
fn scan_rsdp() -> Option<[u8; 36]> {
    let ebda = (rd16(unsafe { phys(0x40e, 2) }, 0) as u64) << 4;
    let ranges = [(ebda, 1024u64), (0xe0000, 0x20000)];
    for (base, len) in ranges {
        if base == 0 {
            continue;
        }
        let mut p = base;
        while p + 20 <= base + len {
            let b = unsafe { phys(p, 36) };
            if &b[..8] == b"RSD PTR " && b[..20].iter().fold(0u8, |a, &x| a.wrapping_add(x)) == 0 {
                let mut r = [0; 36];
                let n = if b[15] >= 2 { 36 } else { 20 };
                r[..n].copy_from_slice(&b[..n]);
                return Some(r);
            }
            p += 16;
        }
    }
    None
}
