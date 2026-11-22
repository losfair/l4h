// SPDX-License-Identifier: GPL-2.0-only
#[path = "../boot/l4h-fl4-efi/src/policy.rs"]
mod policy;
use policy::{
    CONFIG_SLOT, INITRD_SLOT, SLOTS, Selector, fat_serial, fb_console, measured, selector,
};

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

/// What the loader measures for each slot, in order (one event each).
fn events(config: Option<&[u8]>, initrd: Option<&[u8]>) -> Vec<Vec<u8>> {
    [(&CONFIG_SLOT, config), (&INITRD_SLOT, initrd)]
        .into_iter()
        .map(|(slot, file)| measured(slot, file).concat())
        .collect()
}

#[test]
fn slots_are_fixed_and_named() {
    assert_eq!(SLOTS, [&CONFIG_SLOT, &INITRD_SLOT]);
    for slot in SLOTS {
        assert_eq!(slot.present, [slot.name, b"\0present\0"].concat());
        assert_eq!(slot.absent, [slot.name, b"\0absent"].concat());
    }
}

#[test]
fn renamed_file_measures_differently() {
    // The same bytes as the config or as the initramfs: an attacker who
    // renames one to the other cannot keep PCR 9 and RTMR[2].
    let x = b"console=serial\nfb_console=1\n";
    assert_ne!(events(Some(x), None), events(None, Some(x)));
    assert_ne!(events(Some(x), Some(x)), events(Some(x), None));
    // Nothing at all is still two events.
    assert_eq!(
        events(None, None),
        vec![
            b"l4h-config\0absent".to_vec(),
            b"dom0-initrd\0absent".to_vec()
        ]
    );
}

#[test]
fn empty_file_is_not_a_missing_one() {
    for (empty, missing) in [
        (events(Some(b""), None), events(None, None)),
        (events(None, Some(b"")), events(None, None)),
    ] {
        assert_ne!(empty, missing);
    }
    // A file whose bytes are another slot's absent marker or prefix is no
    // other state.
    let all: Vec<Vec<Vec<u8>>> = [None, Some(&b""[..]), Some(b"absent"), Some(b"\0absent")]
        .into_iter()
        .flat_map(|c| {
            [None, Some(&b""[..]), Some(b"absent")]
                .into_iter()
                .map(move |i| events(c, i))
        })
        .collect();
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn nothing_measured_is_empty() {
    // EDK2's TdTcg2Dxe refuses DataToHashLen 0 (EFI_INVALID_PARAMETER).
    for slot in SLOTS {
        for file in [None, Some(&b""[..]), Some(b"x")] {
            let bytes = measured(slot, file).concat();
            assert!(bytes.len() > slot.name.len(), "{:?}", slot);
            assert!(!bytes.is_empty());
        }
    }
}
