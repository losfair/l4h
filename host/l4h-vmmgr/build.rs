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
    // Build only the small ABI-dependent provider when SEL4_PREFIX changes.
    // The Linux image and module SDK never include libsel4.
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    for path in ["guest/provider", "include/l4h", "tools/build-guest-provider.sh"] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    println!("cargo:rerun-if-changed={}", prefix.join("libsel4/include").display());
    let status = std::process::Command::new(root.join("tools/build-guest-provider.sh"))
        .env("L4H_ARCH", env::var("CARGO_CFG_TARGET_ARCH").unwrap())
        .env("SEL4_PREFIX", &prefix)
        .status()
        .expect("build guest provider");
    assert!(status.success(), "guest provider build failed");
    println!("cargo:rustc-env=L4H_GUEST_PROVIDER={}", prefix.join("guest-provider/provider.bin").display());
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
