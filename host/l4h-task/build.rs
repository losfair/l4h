// Shared DMA frames (seL4_Untyped_RetypeShared) and Intel TDX control
// (seL4_X86_TdxControl) are FL4 extensions that seL4 omits.  Inspect the
// interface used to generate the bindings, as l4h-root does for its
// multikernel doorbells.
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(l4h_kernel_shared_dma)");
    println!("cargo:rustc-check-cfg=cfg(l4h_kernel_tdx)");
    println!("cargo:rerun-if-env-changed=SEL4_PREFIX");
    let prefix = PathBuf::from(env::var("SEL4_PREFIX").expect("SEL4_PREFIX"));
    let arch_xml = prefix.join("libsel4/include/interfaces/object-api-arch.xml");
    println!("cargo:rerun-if-changed={}", arch_xml.display());
    let xml = fs::read_to_string(&arch_xml).expect("kernel architecture interface");
    if xml.contains("id=\"UntypedRetypeShared\"") {
        println!("cargo:rustc-cfg=l4h_kernel_shared_dma");
    }
    // FL4 lists its extensions in every architecture's interface; rust-sel4
    // generates the x86 ones for x86_64 alone.
    let x86 = env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64");
    if x86 && xml.contains("id=\"X86TdxControlGetReport\"") {
        println!("cargo:rustc-cfg=l4h_kernel_tdx");
    }
}
