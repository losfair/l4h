// Embeds the host components ($L4H_VMMGR_ELF, which embeds l4h-vmm, $L4H_BLKD_ELF, $L4H_NETD_ELF,
// $L4H_TRUSTD_ELF, $L4H_MEMD_ELF, $L4H_LOGD_ELF; built by tools/build-host.sh), empty
// placeholders when unset.  dom0 is not built in: it comes as boot
// modules, or appended to the built ELF by tools/add-modules.py.  The other variables are the settings' defaults
// (src/config.rs).
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=L4H_VERSION");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    for (var, file) in [
        ("L4H_VMMGR_ELF", "l4h-vmmgr.elf"),
        ("L4H_BLKD_ELF", "l4h-blkd.elf"),
        ("L4H_NETD_ELF", "l4h-netd.elf"),
        ("L4H_TRUSTD_ELF", "l4h-trustd.elf"),
        ("L4H_MEMD_ELF", "l4h-memd.elf"),
        ("L4H_LOGD_ELF", "l4h-logd.elf"),
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
}
