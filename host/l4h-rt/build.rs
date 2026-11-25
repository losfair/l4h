// FL4's seL4_KernelConfig (syscall -24, kconfig.rs) is a call seL4 does not
// have: FL4's libsel4 defines seL4_KernelConfig_Arch for programs to test
// for it.  Inspect the headers the bindings are generated from, as
// l4h-task does for FL4's invocations.
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(l4h_kernel_config)");
    println!("cargo:rerun-if-env-changed=SEL4_PREFIX");
    let prefix = PathBuf::from(env::var("SEL4_PREFIX").expect("SEL4_PREFIX"));
    let constants = prefix.join("libsel4/include/sel4/constants.h");
    println!("cargo:rerun-if-changed={}", constants.display());
    let h = fs::read_to_string(&constants).expect("libsel4 constants");
    if h.lines().any(|l| l.split_whitespace().take(2).eq(["#define", "seL4_KernelConfig_Arch"])) {
        println!("cargo:rustc-cfg=l4h_kernel_config");
    }
}
