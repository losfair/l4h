extern crate self as l4h_host;

#[allow(dead_code)]
#[path = "../host/l4h-host/src/fixed.rs"]
pub mod fixed;
#[allow(dead_code)]
#[path = "../host/l4h-root/src/kexec/grub.rs"]
mod grub;
#[allow(dead_code)]
#[path = "../host/l4h-root/src/kexec/image.rs"]
mod image;
#[allow(dead_code)]
#[path = "../host/l4h-root/src/kexec/kernel.rs"]
mod kernel;
#[allow(dead_code)]
#[path = "../host/l4h-root/src/kexec/mbi.rs"]
mod mbi;
#[allow(dead_code)]
#[path = "../host/l4h-root/src/kexec/pe.rs"]
mod pe;

const GRUB_CFG: &str = r#"# l4h-boot 1
set timeout=0
serial_port=0x3f8
fb_console=0
# a comment has no effect
esp=
regexp --set=1:esp '^\(([^)]*)\)' "$cmdpath"
if [ -z "$esp" ]; then search --no-floppy --set=esp --file /l4h/dom0/initrd; fi
if [ -z "$esp" ]; then search --no-floppy --set=esp --file /l4h/l4h.conf; fi
if [ -n "$esp" ]; then
    if [ -f "($esp)/l4h/l4h.conf" ]; then source "($esp)/l4h/l4h.conf"; fi
fi
serial --port=$serial_port --speed=115200
terminal_input serial
fbcon=
if [ "$fb_console" = 1 ]; then
    terminal_output serial console
    fbcon=" fb_console"
else
    terminal_output serial
fi
if load_env --file (memdisk)/boot/vmlinux; then true; fi
multiboot2 (memdisk)/boot/kernel.elf console_port=$serial_port debug_port=$serial_port$fbcon
module2 (memdisk)/boot/l4h-root.elf
module2 (memdisk)/boot/vmlinux guest-kernel
module2 (memdisk)/boot/kmods.erofs guest-kmods
if [ -n "$esp" ]; then
    if [ -f "($esp)/l4h/dom0/initrd" ]; then module2 "($esp)/l4h/dom0/initrd" dom0-initrd; fi
    if [ -f "($esp)/l4h/l4h.conf" ]; then module2 "($esp)/l4h/l4h.conf" l4h-config; fi
fi
boot
echo "l4h: boot failed"
"#;

fn u16_at(data: &mut [u8], at: usize, value: usize) {
    data[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes());
}
fn u32_at(data: &mut [u8], at: usize, value: usize) {
    data[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
}
fn u64_at(data: &mut [u8], at: usize, value: usize) {
    data[at..at + 8].copy_from_slice(&(value as u64).to_le_bytes());
}

fn kernel() -> Vec<u8> {
    let mut data = vec![0; 0x4000];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 2;
    data[5] = 1;
    u16_at(&mut data, 16, 2);
    u16_at(&mut data, 18, 62);
    u64_at(&mut data, 24, 0x100000);
    u64_at(&mut data, 32, 64);
    u16_at(&mut data, 54, 56);
    u16_at(&mut data, 56, 1);
    u32_at(&mut data, 64, 1);
    u64_at(&mut data, 64 + 16, 0x100000);
    u64_at(&mut data, 64 + 24, 0x100000);
    u64_at(&mut data, 64 + 32, 0x4000);
    u64_at(&mut data, 64 + 40, 0x8000);
    u64_at(&mut data, 64 + 48, 0x1000);
    let mb = 0x100;
    u32_at(&mut data, mb, 0xe85250d6);
    u32_at(&mut data, mb + 8, 24);
    u32_at(
        &mut data,
        mb + 12,
        0u32.wrapping_sub(0xe85250d6 + 24) as usize,
    );
    u32_at(&mut data, mb + 20, 8);
    data
}

fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut data = Vec::new();
    for (name, contents) in entries {
        let at = data.len();
        data.resize(at + 512, 0);
        data[at..at + name.len()].copy_from_slice(name.as_bytes());
        data[at + 257..at + 263].copy_from_slice(b"ustar\0");
        let size = format!("{:011o}\0", contents.len());
        data[at + 124..at + 136].copy_from_slice(size.as_bytes());
        data[at + 148..at + 156].fill(b' ');
        let checksum: usize = data[at..at + 512].iter().map(|&b| b as usize).sum();
        data[at + 148..at + 156].copy_from_slice(format!("{:06o}\0 ", checksum).as_bytes());
        data.extend_from_slice(contents);
        data.resize(data.len().next_multiple_of(512), 0);
    }
    data.resize(data.len() + 512, 0);
    data
}

fn image_with(kernel: &[u8], extra: bool) -> Vec<u8> {
    let mut entries = vec![
        ("boot/grub/grub.cfg", GRUB_CFG.as_bytes()),
        ("boot/kernel.elf", kernel),
        ("boot/l4h-root.elf", &b"root"[..]),
        ("boot/vmlinux", &b"guest"[..]),
        ("boot/kmods.erofs", &b"kmods"[..]),
    ];
    if extra {
        entries.push(("boot/surprise", b"no"));
    }
    let tar = tar(&entries);
    let entry_size = 8 + tar.len();
    let end = 24 + entry_size;
    let mut mods = vec![0; 32];
    mods[..8].copy_from_slice(b"mimg\0\0\0\0");
    u64_at(&mut mods, 8, 24);
    u64_at(&mut mods, 16, end);
    u32_at(&mut mods, 24, 1);
    u32_at(&mut mods, 28, entry_size);
    mods.extend_from_slice(&tar);

    let mut data = vec![0; 0x200];
    data[..2].copy_from_slice(b"MZ");
    u32_at(&mut data, 0x3c, 0x80);
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    u16_at(&mut data, 0x84, 0x8664);
    u16_at(&mut data, 0x86, 1);
    u16_at(&mut data, 0x94, 0xf0);
    let optional = 0x98;
    u16_at(&mut data, optional, 0x20b);
    u32_at(&mut data, optional + 60, 0x200);
    u32_at(&mut data, optional + 108, 16);
    let section = optional + 0xf0;
    data[section..section + 8].copy_from_slice(b"mods\0\0\0\0");
    u32_at(&mut data, section + 8, mods.len());
    u32_at(&mut data, section + 16, mods.len());
    u32_at(&mut data, section + 20, 0x200);
    data.extend_from_slice(&mods);
    data
}

fn gapped_image() -> (Vec<u8>, usize, usize, usize) {
    let mut data = image_with(&kernel(), false);
    let first_end = data.len();
    let second_offset = first_end + 0x80;
    let second_size = 0x40;
    data.resize(second_offset, 0x5a);
    data.extend((0..second_size).map(|i| (i as u8).wrapping_add(0x80)));
    u16_at(&mut data, 0x86, 2);
    let second = 0x98 + 0xf0 + 40;
    data[second..second + 8].copy_from_slice(b"second\0\0");
    u32_at(&mut data, second + 8, second_size);
    u32_at(&mut data, second + 16, second_size);
    u32_at(&mut data, second + 20, second_offset);
    (data, first_end, second_offset, second_size)
}

/// The bytes Authenticode hashes, in hash order.
fn authenticode_bytes(data: &[u8]) -> Vec<u8> {
    let layout = pe::Pe::parse_layout(data, data.len()).ok().expect("PE layout");
    let mut hashed = Vec::new();
    layout.for_each_range(|range| hashed.extend_from_slice(&data[range]));
    hashed
}

#[test]
fn authenticode_gapped_sections_match_streaming_and_spec() {
    let (data, first_end, second_offset, second_size) = gapped_image();
    assert!(pe::Pe::parse(&data).is_ok());
    let one_shot = authenticode_bytes(&data);

    let checksum = 0x98 + 64;
    let security = 0x98 + 112 + 4 * 8;
    let hashed_size = 0x200 + (first_end - 0x200) + second_size;
    assert!(hashed_size < second_offset);
    let mut expected = Vec::new();
    expected.extend_from_slice(&data[..checksum]);
    expected.extend_from_slice(&data[checksum + 4..security]);
    expected.extend_from_slice(&data[security + 8..0x200]);
    expected.extend_from_slice(&data[0x200..first_end]);
    expected.extend_from_slice(&data[second_offset..second_offset + second_size]);
    expected.extend_from_slice(&data[hashed_size..]);
    assert_eq!(one_shot, expected);

    let layout = pe::Pe::parse_layout(&data, data.len()).ok().expect("PE layout");
    let mut cursor = pe::RangeCursor::default();
    let mut streamed = Vec::new();
    let mut end = 0;
    while end < data.len() {
        end = (end + 137).min(data.len());
        layout.stream(&mut cursor, &data[..end], |chunk| streamed.extend_from_slice(chunk));
    }
    assert_eq!(streamed, expected);
    let len = streamed.len();
    layout.stream(&mut cursor, &data, |chunk| streamed.extend_from_slice(chunk));
    assert_eq!(streamed.len(), len);
}

#[test]
fn parses_and_hashes_an_l4h_image() {
    let data = image_with(&kernel(), false);
    let image = image::Image::parse(&data).unwrap();
    assert_eq!(image.kernel.segments.len(), 1);
    assert_eq!(image.grub.serial_port.text(), b"0x3f8");
    assert_eq!(image.kernel.entry, 0x100000);
    assert_eq!(image.root, b"root");
    assert_eq!(image.guest_kernel, b"guest");
    assert_eq!(image.guest_kmods, Some(&b"kmods"[..]));
    let hashed = authenticode_bytes(&data);
    let checksum = 0x98 + 64;
    let security = 0x98 + 112 + 4 * 8;
    let mut expected = Vec::new();
    expected.extend_from_slice(&data[..checksum]);
    expected.extend_from_slice(&data[checksum + 4..security]);
    expected.extend_from_slice(&data[security + 8..]);
    assert_eq!(hashed, expected);
}

#[test]
fn rejects_unknown_boot_files_and_bad_tar_checksums() {
    assert_eq!(
        image::Image::parse(&image_with(&kernel(), true)).unwrap_err(),
        "unknown file in the EFI boot directory"
    );
    let mut data = image_with(&kernel(), false);
    let magic = data.windows(5).position(|w| w == b"ustar").unwrap();
    data[magic - 257] ^= 1;
    assert_eq!(
        image::Image::parse(&data).unwrap_err(),
        "bad tar header checksum"
    );
}

#[test]
fn rejects_a_bad_multiboot_checksum() {
    let mut kernel = kernel();
    kernel[0x10c] ^= 1;
    assert_eq!(
        image::Image::parse(&image_with(&kernel, false)).unwrap_err(),
        "bad multiboot2 header checksum"
    );
}

#[test]
fn truncated_images_return_errors() {
    let data = image_with(&kernel(), false);
    for at in [0, 1, 63, 64, 0x80, 0x200, data.len() - 1] {
        assert!(
            image::Image::parse(&data[..at]).is_err(),
            "accepted truncation at {at}"
        );
    }
}

#[test]
fn short_pe_prefixes_are_incomplete_not_invalid() {
    let data = image_with(&kernel(), false);
    for n in [1, 16, 63, 64, 128] {
        assert!(matches!(pe::Pe::parse_layout(&data[..n], data.len()), Err(pe::PeLayoutError::Incomplete)));
    }
    assert!(pe::Pe::parse_layout(&data, data.len()).is_ok());
}

#[test]
fn rejects_other_grub_logic() {
    assert!(
        grub::Grub::parse(
            GRUB_CFG.strip_prefix("# l4h-boot 1\n").unwrap().as_bytes(),
            true
        )
        .is_err()
    );
    let acpi = GRUB_CFG.replace("if load_env", "acpi (memdisk)/boot/acpi/0.aml\nif load_env");
    assert_eq!(
        grub::Grub::parse(acpi.as_bytes(), true).err().unwrap(),
        "kexec does not replace ACPI tables"
    );
    let no_kmods = GRUB_CFG.replace("module2 (memdisk)/boot/kmods.erofs guest-kmods\n", "");
    assert!(grub::Grub::parse(no_kmods.as_bytes(), false).is_ok());
    assert!(grub::Grub::parse(no_kmods.as_bytes(), true).is_err());
}
#[test]
fn builds_multiboot2_information() {
    let mut content = vec![0; 4 + 2 * 24];
    u32_at(&mut content, 0, 48);
    u32_at(&mut content, 4, 20);
    u64_at(&mut content, 8, 1 << 20);
    u64_at(&mut content, 16, 15 << 20);
    u32_at(&mut content, 24, 1);
    u32_at(&mut content, 28, 20);
    u64_at(&mut content, 32, 16 << 20);
    u64_at(&mut content, 40, 1 << 20);
    u32_at(&mut content, 48, 2);
    let map = mbi::FirmwareMap::parse(&content).unwrap();
    assert_eq!(map.count, 2);
    assert_eq!(map.usable().count(), 1);
    let mut builder = mbi::MbiBuilder::new();
    builder.command_line(b"console_port=0x3f8").unwrap();
    builder
        .module(&mbi::Module {
            start: 16 << 20,
            size: 4,
            command: b"(memdisk)/boot/l4h-root.elf",
        })
        .unwrap();
    builder.firmware_map(&map).unwrap();
    builder.framebuffer(&[0; 22]).unwrap();
    let mut acpi = [0; 36];
    acpi[..8].copy_from_slice(b"RSD PTR ");
    builder.acpi(&(acpi, 20)).unwrap();
    let bytes = builder.finish().unwrap();
    let len = bytes.len();
    assert_eq!(
        u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize,
        len
    );
    assert_eq!(len % 8, 0);
    let mut at = 8;
    let mut kinds = Vec::new();
    while at < len {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        kinds.push(kind);
        if kind == 3 {
            assert_eq!(
                u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()),
                16 << 20
            );
            assert_eq!(
                u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap()),
                (16 << 20) + 4
            );
        }
        if kind == 6 {
            assert_eq!(size, 16 + 2 * 24);
            assert_eq!(
                u64::from_le_bytes(bytes[at + 16..at + 24].try_into().unwrap()),
                1 << 20
            );
            assert_eq!(
                u32::from_le_bytes(bytes[at + 32..at + 36].try_into().unwrap()),
                1
            );
        }
        at += size.next_multiple_of(8);
        if kind == 0 {
            assert_eq!(at, len);
        }
    }
    assert_eq!(kinds, [1, 3, 6, 8, 14, 0]);
    let mut truncated = content.clone();
    u32_at(&mut truncated, 0, 48 | mbi::MMAP_TRUNCATED as usize);
    assert!(mbi::FirmwareMap::parse(&truncated).is_err());
    let mut overlapping = content.clone();
    u64_at(&mut overlapping, 32, 15 << 20);
    assert!(mbi::FirmwareMap::parse(&overlapping).is_err());
}

#[test]
fn reserves_the_control_block_in_the_next_memory_map() {
    let mut map = mbi::FirmwareMap {
        entries: [mbi::MapEntry::default(); mbi::MAX_MMAP_ENTRIES],
        count: 2,
    };
    map.entries[0] = mbi::MapEntry { base: 1 << 20, length: 15 << 20, kind: 1 };
    map.entries[1] = mbi::MapEntry { base: 16 << 20, length: 1 << 20, kind: 2 };
    let mut uncovered = map;
    assert!(map.covers_usable((4 << 20)..(6 << 20)));
    assert!(!map.covers_usable(0..(32 << 20)));
    let mut nvs = map;
    nvs.entries[1].kind = 4;
    assert!(nvs.covers_boot_ram((16 << 20)..(17 << 20)));
    assert!(!nvs.covers_usable((16 << 20)..(17 << 20)));
    map.reserve((4 << 20)..(6 << 20)).unwrap();
    assert_eq!(map.count, 4);
    assert_eq!((map.entries[0].base, map.entries[0].kind), (1 << 20, 1));
    assert_eq!((map.entries[1].base, map.entries[1].length, map.entries[1].kind), (4 << 20, 2 << 20, 2));
    assert_eq!((map.entries[2].base, map.entries[2].length, map.entries[2].kind), (6 << 20, 10 << 20, 1));
    assert_eq!((map.entries[3].base, map.entries[3].kind), (16 << 20, 2));
    map.unreserve((4 << 20)..(6 << 20)).unwrap();
    assert_eq!(map.count, 2);
    assert_eq!((map.entries[0].base, map.entries[0].length, map.entries[0].kind), (1 << 20, 15 << 20, 1));
    assert_eq!((map.entries[1].base, map.entries[1].kind), (16 << 20, 2));
    assert!(uncovered.reserve(0..(32 << 20)).is_err());
}

impl core::fmt::Debug for image::Image<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Image").finish_non_exhaustive()
    }
}

#[test]
fn root_task_span_covers_every_load_segment() {
    let mut elf = vec![0; 64 + 3 * 56];
    elf[..5].copy_from_slice(b"\x7fELF\x02");
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[56..58].copy_from_slice(&3u16.to_le_bytes());
    // Two PT_LOADs and a header without memory, which does not count.
    for (i, (kind, vaddr, memsz)) in [(1u32, 0x403000u64, 0x10u64), (4, 0x900000, 0), (1, 0x400000, 0x1800)].into_iter().enumerate() {
        let at = 64 + i * 56;
        elf[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        elf[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
        elf[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
    }
    assert_eq!(kernel::image_span(&elf), Ok(0x4000));
    elf[56..58].copy_from_slice(&4u16.to_le_bytes());
    assert!(kernel::image_span(&elf).is_err());
}

#[test]
fn root_task_span_counts_every_header_with_memory() {
    // seL4 bounds a TLS header past the last PT_LOAD too.
    let mut elf = vec![0; 64 + 2 * 56];
    elf[..5].copy_from_slice(b"\x7fELF\x02");
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[56..58].copy_from_slice(&2u16.to_le_bytes());
    for (i, (kind, vaddr, memsz)) in [(1u32, 0x400000u64, 0x1800u64), (7, 0x402000, 0x2001)].into_iter().enumerate() {
        let at = 64 + i * 56;
        elf[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        elf[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
        elf[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
    }
    assert_eq!(kernel::image_span(&elf), Ok(0x5000));
}
