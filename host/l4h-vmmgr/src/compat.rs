//! Check declared guest requirements before booting. Provider slots are
//! append-only; shared layouts and meanings stay fixed within ABI versions.

pub fn check(requirements: &[u8], provider: &[u8], guest_abi: u64) -> Result<(), &'static str> {
    if requirements.len() != 40 || &requirements[..8] != b"L4HGABI1" {
        return Err("invalid guest ABI metadata");
    }
    if provider.len() < 32 || &provider[..8] != b"L4HPVDR1" {
        return Err("invalid host provider metadata");
    }
    let word = |bytes: &[u8], offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    if word(requirements, 8) != guest_abi {
        return Err("guest ABI version does not match host");
    }
    if word(requirements, 16) != word(provider, 8) {
        return Err("guest provider ABI version does not match host");
    }
    let required = word(requirements, 24);
    let available = word(provider, 16);
    if required < 32 || required % 8 != 0 || available > provider.len() as u64 || required > available {
        return Err("guest requires a newer provider table");
    }
    if word(requirements, 32) & !word(provider, 24) != 0 {
        return Err("host lacks required guest provider features");
    }
    Ok(())
}
