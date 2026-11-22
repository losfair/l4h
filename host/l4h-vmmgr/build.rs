// Embeds guests' l4h-vmm ($L4H_VMM_ELF) and HVM guests' l4h-hvm
// ($L4H_HVM_ELF, x86_64 only), built by tools/build-host.sh: an empty
// placeholder when unset (no HVM guests then).
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=L4H_VERSION");
    println!("cargo:rerun-if-env-changed=SEL4_PREFIX");
    let prefix = PathBuf::from(env::var("SEL4_PREFIX").expect("SEL4_PREFIX"));
    println!("cargo:rerun-if-changed={}", prefix.join("libsel4/include/sel4/config.h").display());
    // FL4's AArch64 VCPUs and Stage-2 VSpaces, which a C seL4 built
    // without them does not name.
    println!("cargo:rustc-check-cfg=cfg(l4h_arm_virt)");
    let arm_objtype = prefix.join("libsel4/include/sel4/arch/objecttype.h");
    println!("cargo:rerun-if-changed={}", arm_objtype.display());
    if fs::read_to_string(&arm_objtype).is_ok_and(|s| s.contains("seL4_ARM_Stage2VSpaceObject")) {
        println!("cargo:rustc-cfg=l4h_arm_virt");
    }
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
    for (var, file) in [("L4H_VMM_ELF", "l4h-vmm.elf"), ("L4H_HVM_ELF", "l4h-hvm.elf")] {
        println!("cargo:rerun-if-env-changed={var}");
        let data = match env::var(var) {
            Ok(path) if !path.is_empty() => {
                println!("cargo:rerun-if-changed={path}");
                fs::read(&path).unwrap_or_else(|e| panic!("{var}={path}: {e}"))
            }
            _ => Vec::new(),
        };
        fs::write(out.join(file), data).unwrap();
    }
}
