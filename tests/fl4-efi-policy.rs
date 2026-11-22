// SPDX-License-Identifier: GPL-2.0-only
#[path = "../boot/l4h-fl4-efi/src/policy.rs"]
mod policy;
use policy::{Selector, fat_serial, fb_console, selector};

#[test]
fn grub_environment_records() {
    let block = |records: &str| format!("# GRUB Environment Block\n{records}####");
    assert_eq!(
        selector(block("l4h_esp_uuid=AbCd-0123\nl4h_esp_label=\n").as_bytes()),
        Some(Selector::Uuid(0xabcd_0123))
    );
    let value = block("ignored=boot\\\nl4h_esp_uuid=1111-1111\nl4h_esp_label=L4H$`A\n");
    assert_eq!(selector(value.as_bytes()), Some(Selector::Label("L4H$`A")));
    for invalid in [
        "ignored=boot\\\nl4h_esp_uuid=1111-1111\n",
        "l4h_esp_uuid=+123-4567\n",
        "l4h_esp_uuid=1234-5678\nl4h_esp_label=A\n",
        "l4h_esp_label=A\nl4h_esp_label=A\n",
        "l4h_esp_label=A",
    ] {
        assert_eq!(selector(block(invalid).as_bytes()), None);
    }
}

#[test]
fn fat_volume_serial() {
    let mut sector = [0u8; 512];
    sector[11..13].copy_from_slice(&512u16.to_le_bytes());
    sector[13] = 8;
    sector[16] = 2;
    sector[510..].copy_from_slice(&[0x55, 0xaa]);
    for (fat_size_16, offset) in [(9, 38), (0, 66)] {
        sector[22..24].copy_from_slice(&u16::to_le_bytes(fat_size_16));
        assert_eq!(fat_serial(&sector), None);
        sector[offset] = 0x29;
        sector[offset + 1..offset + 5].copy_from_slice(&0xabcd_0123u32.to_le_bytes());
        assert_eq!(fat_serial(&sector), Some(0xabcd_0123));
    }
    sector[510] = 0;
    assert_eq!(fat_serial(&sector), None);
}

#[test]
fn framebuffer_setting() {
    assert!(fb_console(b"# fb_console=0\nother=1\n", true));
    assert!(fb_console(b"fb_console = \"1\"\r\n", false));
    assert!(!fb_console(b"fb_console=1\nfb_console='0'\n", true));
}
