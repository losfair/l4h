// Shared DMA frames (seL4_Untyped_RetypeShared) are an FL4 extension that
// seL4 omits.  Inspect the interface used to generate the bindings, as
// l4h-root does for its multikernel doorbells.
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(l4h_kernel_shared_dma)");
    println!("cargo:rerun-if-env-changed=SEL4_PREFIX");
    let prefix = PathBuf::from(env::var("SEL4_PREFIX").expect("SEL4_PREFIX"));
    let arch_xml = prefix.join("libsel4/include/interfaces/object-api-arch.xml");
    println!("cargo:rerun-if-changed={}", arch_xml.display());
    if fs::read_to_string(&arch_xml).expect("kernel architecture interface").contains("id=\"UntypedRetypeShared\"") {
        println!("cargo:rustc-cfg=l4h_kernel_shared_dma");
    }
}
