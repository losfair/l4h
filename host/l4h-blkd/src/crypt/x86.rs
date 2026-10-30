// SysV integer/pointer ABI, including on the host's soft-float target.
core::arch::global_asm!(include_str!("x86.S"));
unsafe extern "C" {
    #[link_name = "l4h_aes256_expand"]
    pub fn expand(key: *const u8, enc: *mut u8, dec: *mut u8);
    #[link_name = "l4h_xts_encrypt"]
    pub fn encrypt(keys: *const u8, tweak: *const u8, src: *const u8, dst: *mut u8, unit: u64);
    #[link_name = "l4h_xts_decrypt"]
    pub fn decrypt(keys: *const u8, tweak: *const u8, src: *const u8, dst: *mut u8, unit: u64);
}
