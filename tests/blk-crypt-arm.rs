//! Observe registers immediately on return, before Rust can reuse them.
use super::*;

core::arch::global_asm!(r#"
.text
.global l4h_arm_scrub_probe
.type l4h_arm_scrub_probe,%function
l4h_arm_scrub_probe:
    sub sp, sp, #112
    stp x19, x20, [sp]
    stp x21, x22, [sp, #16]
    str x30, [sp, #32]
    stp d8, d9, [sp, #48]
    stp d10, d11, [sp, #64]
    stp d12, d13, [sp, #80]
    stp d14, d15, [sp, #96]
    mov x19, x2
    mov x20, x3
    mov x21, x0
    mov x22, x1
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        movi v\n\().16b, #0x5a
    .endr
    ldp x0, x1, [x22]
    ldp x2, x3, [x22, #16]
    ldr x4, [x22, #32]
    blr x21
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        str q\n, [x19, #16*\n]
    .endr
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
        str x\n, [x20, #8*\n]
    .endr
    ldp d8, d9, [sp, #48]
    ldp d10, d11, [sp, #64]
    ldp d12, d13, [sp, #80]
    ldp d14, d15, [sp, #96]
    ldr x30, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp]
    add sp, sp, #112
    ret
.size l4h_arm_scrub_probe, .-l4h_arm_scrub_probe
"#);

unsafe extern "C" {
    fn l4h_arm_scrub_probe(function: usize, args: *const u64, vectors: *mut u8, gp: *mut u64);
}

#[test]
fn arm_scrubs_scratch_registers_and_preserves_the_callers_state() {
    if !std::arch::is_aarch64_feature_detected!("aes") { return; }
    let key: [u8; 64] = core::array::from_fn(|i| i as u8);
    let mut k = Xts::empty();
    unsafe { k.init(&key); }
    let input = [0x23u8; UNIT];
    let mut output = [0u8; UNIT];
    for (function, args) in [
        (backend::encrypt as *const () as usize, [k.enc.as_ptr() as u64, k.tweak.as_ptr() as u64,
            input.as_ptr() as u64, output.as_mut_ptr() as u64, 91]),
        (backend::decrypt as *const () as usize, [k.dec.as_ptr() as u64, k.tweak.as_ptr() as u64,
            input.as_ptr() as u64, output.as_mut_ptr() as u64, 91]),
        (backend::expand as *const () as usize, [key.as_ptr() as u64, k.enc.as_mut_ptr() as u64, k.dec.as_mut_ptr() as u64, 0, 0]),
    ] {
        let mut vectors = [[0xffu8; 16]; 32];
        let mut gp = [u64::MAX; 18];
        unsafe { l4h_arm_scrub_probe(function, args.as_ptr(), vectors.as_mut_ptr().cast(), gp.as_mut_ptr()); }
        assert_eq!(gp, [0; 18]);
        for (n, v) in vectors.iter().enumerate() {
            let mut expected = [0; 16];
            if (8..16).contains(&n) { expected[..8].fill(0x5a); }
            assert_eq!(*v, expected, "v{n}: scratch cleared, AAPCS64 lower halves preserved");
        }
    }
}
