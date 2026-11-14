// Embeds the host components ($L4H_VMMGR_ELF, which embeds l4h-vmm, $L4H_BLKD_ELF, $L4H_NETD_ELF,
// $L4H_TRUSTD_ELF, $L4H_MEMD_ELF, $L4H_LOGD_ELF, $L4H_USBD_ELF, and the NIC driver bundle
// $L4H_DRIVERS_BIN; built by tools/build-host.sh), empty
// placeholders when unset.  dom0 is not built in: it comes as boot
// modules, or appended to the built ELF by tools/add-modules.py.  The other variables are the settings' defaults
// (src/config.rs).
use std::{env, fs, path::PathBuf};

fn main() {
    // Multikernel doorbells are an l4h seL4 extension that FL4 omits.
    // Inspect the interface used to generate the bindings, so this also
    // follows a different kernel's actual capabilities.
    println!("cargo:rustc-check-cfg=cfg(l4h_kernel_multikernel)");
    println!("cargo:rerun-if-env-changed=SEL4_PREFIX");
    let prefix = PathBuf::from(env::var("SEL4_PREFIX").expect("SEL4_PREFIX"));
    let arch_xml = prefix.join("libsel4/include/interfaces/object-api-arch.xml");
    println!("cargo:rerun-if-changed={}", arch_xml.display());
    if fs::read_to_string(&arch_xml).expect("kernel architecture interface").contains("id=\"X86IRQControlSendPeer\"") {
        println!("cargo:rustc-cfg=l4h_kernel_multikernel");
    }
    println!("cargo:rerun-if-env-changed=L4H_VERSION");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    for (var, file) in [
        ("L4H_VMMGR_ELF", "l4h-vmmgr.elf"),
        ("L4H_BLKD_ELF", "l4h-blkd.elf"),
        ("L4H_NETD_ELF", "l4h-netd.elf"),
        ("L4H_TRUSTD_ELF", "l4h-trustd.elf"),
        ("L4H_MEMD_ELF", "l4h-memd.elf"),
        ("L4H_LOGD_ELF", "l4h-logd.elf"),
        ("L4H_USBD_ELF", "l4h-usbd.elf"),
        ("L4H_DRIVERS_BIN", "l4h-drivers.bin"),
    ] {
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
    println!("cargo:rerun-if-env-changed=L4H_DOM0_CMDLINE");
    println!("cargo:rerun-if-env-changed=L4H_DOM0_MEM_MB");
    println!("cargo:rerun-if-env-changed=L4H_DOM0_VCPUS");
    println!("cargo:rerun-if-env-changed=L4H_DOM0_IO_POOL_MB");
    println!("cargo:rerun-if-env-changed=L4H_WATCHDOG_SECS");
    println!("cargo:rerun-if-env-changed=L4H_DOM0_DISKS");
    println!("cargo:rerun-if-env-changed=L4H_DOM0_DISK0_MB");
    println!("cargo:rerun-if-env-changed=L4H_DOM0_DISK0_WINDOWS");
    println!("cargo:rerun-if-env-changed=L4H_DOM0_NICS");
    println!("cargo:rerun-if-env-changed=L4H_DOM0_INTERNAL_SWITCHES");
    println!("cargo:rerun-if-env-changed=L4H_UPLINK_NIC");
    println!("cargo:rerun-if-env-changed=L4H_UPLINK2_NIC");
    println!("cargo:rerun-if-env-changed=L4H_BOOT_DISK");
    println!("cargo:rerun-if-env-changed=L4H_SERIAL_PORT");
    println!("cargo:rerun-if-env-changed=L4H_SERIAL_IRQ");
    println!("cargo:rerun-if-env-changed=L4H_FB_CONSOLE");
    println!("cargo:rerun-if-env-changed=L4H_NIC_AUTO");
    println!("cargo:rerun-if-env-changed=L4H_NIC_MAX_RESTARTS");
}
