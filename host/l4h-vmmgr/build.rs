// Embeds guests' l4h-vmm ($L4H_VMM_ELF, built by tools/build-host.sh), an
// empty placeholder when unset.
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=L4H_VERSION");
    println!("cargo:rerun-if-env-changed=SEL4_PREFIX");
    let prefix = PathBuf::from(env::var("SEL4_PREFIX").expect("SEL4_PREFIX"));
    println!("cargo:rerun-if-changed={}", prefix.join("libsel4/include/sel4/config.h").display());
    let fl4 = prefix.join("fl4-revision");
    let kernel = if fl4.is_file() {
        println!("cargo:rerun-if-changed={}", fl4.display());
        "FL4"
    } else {
        "seL4"
    };
    let version = env::var("L4H_VERSION").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=L4H_HOST_VERSION={version} ({kernel})");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-env-changed=L4H_VMM_ELF");
    let data = match env::var("L4H_VMM_ELF") {
        Ok(path) if !path.is_empty() => {
            println!("cargo:rerun-if-changed={path}");
            fs::read(&path).unwrap_or_else(|e| panic!("L4H_VMM_ELF={path}: {e}"))
        }
        _ => Vec::new(),
    };
    fs::write(out.join("l4h-vmm.elf"), data).unwrap();
}
