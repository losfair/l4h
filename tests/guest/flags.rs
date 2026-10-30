// SPDX-License-Identifier: GPL-2.0-only
//! End-to-end flags checks, run as dom0 and in its guests.
#[path = "../../tools/l4hctl/src/lib.rs"]
#[allow(dead_code)]
mod ctl;
use ctl::{attest, *};
use std::{fs, io, io::BufRead, os::fd::AsRawFd, process::Command, time::{Duration, Instant}};

unsafe extern "C" { fn ioctl(fd: i32, req: u64, ...) -> i32; }
#[repr(C)]
struct AttestIoc { op: u32, blob_len: u32, secret_len: u32, out_len: u32, data: u64, out: u64 }

fn raw_attest(op: u32, data: &[u8]) -> std::result::Result<Vec<u8>, i32> {
    let f = fs::File::options().read(true).write(true).open("/dev/l4h-attest").unwrap();
    let mut out = vec![0u8; 512];
    let mut c = AttestIoc { op, blob_len: if op >= 4 { data.len() as u32 } else { 0 }, secret_len: 0,
        out_len: out.len() as u32, data: data.as_ptr() as u64, out: out.as_mut_ptr() as u64 };
    let cmd = (3u64 << 30) | (32 << 16) | ((b'L' as u64) << 8) | 2;
    if unsafe { ioctl(f.as_raw_fd(), cmd, &mut c as *mut AttestIoc) } < 0 {
        return Err(io::Error::last_os_error().raw_os_error().unwrap());
    }
    out.truncate(c.out_len as usize);
    Ok(out)
}
fn bits(ns: &[&str]) -> [u8; 32] { attest::bitmap(ns).unwrap() }
fn has(b: &[u8], n: usize) -> bool { b[n / 8] & (1 << (n % 8)) != 0 }
fn pause() { std::thread::sleep(Duration::from_millis(20)); }
fn wait(mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(90);
    while !f() { assert!(Instant::now() < deadline, "timed out"); pause(); }
}
fn record(label: &str, no_tpm: bool) {
    if no_tpm {
        assert_eq!(raw_attest(1, &[0; 64]), Err(19));
        assert_eq!(raw_attest(2, &[]), Err(19));
        assert_eq!(raw_attest(3, &[]), Err(19));
    } else {
        let cmdline = fs::read_to_string("/proc/cmdline").unwrap();
        let nonce = cmdline.split_whitespace().find_map(|s| s.strip_prefix("attest_nonce=")).unwrap_or("");
        let nonce: Vec<_> = nonce.as_bytes().chunks_exact(2).map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap()).collect();
        let report = attest::report(&nonce).unwrap();
        assert!(report.len() <= 512);
        println!("FLAGVM: {label} report {}", report.iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
}
fn guest(mode: &str, no_tpm: bool) {
    let f = attest::flags().unwrap();
    assert_eq!(f.seal, [0; 32]);
    if mode == "queued" {
        assert_eq!(f.taint[0], 1);
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "queued");
        record("queued", no_tpm);
        return;
    }
    assert_eq!(f.taint, [0; 32]);
    if mode == "fresh" { record("fresh", no_tpm); return; }
    let f = attest::seal(&bits(&["console-out"])).unwrap();
    assert_eq!(f.taint, [0; 32]);
    assert_eq!(f.seal[0], 2);
    if mode == "clean" { record("clean", no_tpm); return; }
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "provisioned");
    assert_eq!(attest::flags().unwrap().taint[0], 1);
    record("injected", no_tpm);
    let f = attest::seal(&bits(&["console-in"])).unwrap();
    assert_eq!((f.taint[0], f.seal[0]), (1, 3));

    fs::write("/proc/sys/kernel/tainted", b"2\n").unwrap();
    attest::act(&bits(&["200"]), false).unwrap();
    assert_eq!(raw_attest(4, &bits(&["70"])), Err(1));
    assert_eq!(raw_attest(4, &bits(&["0"])), Err(1));
    assert_eq!(raw_attest(5, &bits(&["65"])), Err(22));
    assert_eq!(raw_attest(5, &bits(&["2"])), Err(22));
    assert_eq!(raw_attest(4, &[0; 31]), Err(22));
    let mut act = [0u8; 36];
    act[32] = 2;
    assert_eq!(raw_attest(4, &act), Err(22));
    act[..32].copy_from_slice(&bits(&["70"]));
    act[32] = 1;
    assert_eq!(raw_attest(4, &act), Err(1));

    attest::seal(&bits(&["130"])).unwrap();
    assert_eq!(raw_attest(4, &bits(&["130"])), Err(1));
    assert_eq!(raw_attest(4, &bits(&["131", "130"])), Err(1));
    assert!(!has(&attest::flags().unwrap().taint, 131));
    attest::act(&bits(&["140"]), true).unwrap();
    act[..32].copy_from_slice(&bits(&["140"]));
    assert_eq!(raw_attest(4, &act), Err(1));
    assert_eq!(raw_attest(4, &bits(&["140"])), Err(1));

    // Two processes ready before the start flag: precisely one can act.
    let mut one = Command::new("/bin/flags-test").arg("take").spawn().unwrap();
    let mut two = Command::new("/bin/flags-test").arg("take").spawn().unwrap();
    fs::write("/tmp/race-start", b"go").unwrap();
    let (a, b) = (one.wait().unwrap().code().unwrap(), two.wait().unwrap().code().unwrap());
    assert!((a == 0 && b == 1) || (a == 1 && b == 0));
    let f = attest::flags().unwrap();
    for n in [0, 65, 140, 141, 200] { assert!(has(&f.taint, n), "missing taint {n}"); }
    for n in [0, 1, 130, 140, 141] { assert!(has(&f.seal, n), "missing seal {n}"); }
    assert!(fs::read_to_string("/sys/kernel/l4h/attest/taint").unwrap().trim().split(',').any(|s| s == "65"));
    assert!(fs::read_to_string("/sys/kernel/l4h/attest/seal").unwrap().trim().split(',').any(|s| s == "130"));
    record("gates", no_tpm);
    println!("FLAGVM: PASS{}", if no_tpm { " no TPM" } else { "" });
}
fn stopped(c: &Ctl, vm: u64) { wait(|| c.vm_list().unwrap().iter().any(|v| v.id == vm && v.state == 3)); }
fn dom0(no_tpm: bool) {
    let c = Ctl::open().unwrap();
    let initrd = fs::read("/bin/flagsvm.cpio.gz").unwrap();
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap();
    let nonce = cmdline.split_whitespace().find(|s| s.starts_with("attest_nonce=")).unwrap_or("");
    let cmd = |mode| format!("console=hvc0 flags_mode={mode} flags_no_tpm={} {nonce}", no_tpm as u32);
    let clean_cmd = cmd("clean");
    let sealed_cmd = cmd("sealed");
    let fresh_cmd = cmd("fresh");
    let spec = |mode| VmSpec { name: "flags", mem: 128 << 20, vcpus: 2, initrd: &initrd,
        cmdline: mode, disks: vec![], volumes: vec![], nics: vec![], io_pool: 0, gpu: Some((64, 64)) };
    // A separate clean instance avoids racing its report against input:
    // dom0 cannot observe completion through a sealed output console.
    let (id, _) = c.create_vm(&spec(&clean_cmd)).unwrap();
    wait(|| c.vm_trust(id).unwrap().1 == 2);
    assert_eq!(c.vm_trust(id).unwrap(), (0, 2));
    assert_eq!(c.call_out(CTL_CONSOLE_READ, &[id, 0], &mut []).unwrap().status, -1);
    assert_eq!(c.call_out(CTL_GPU_READ, &[id, 0], &mut [0; 64 * 64 * 4]).unwrap().status, -1);
    stopped(&c, id);
    c.vm_destroy(id).unwrap();
    let (next, _) = c.create_vm(&spec(&sealed_cmd)).unwrap();
    assert_eq!(next, id);
    wait(|| c.vm_trust(id).unwrap().1 == 2);
    assert_eq!(c.call(CTL_CONSOLE_WRITE, &[id, 12], b"provisioned\n", &[]).unwrap().vals[0], 12);
    wait(|| c.vm_trust(id).unwrap().1 == 3);
    assert_eq!(c.call_out(CTL_CONSOLE_WRITE, &[id, 1], &mut []).unwrap().status, -1);
    assert_eq!(c.vm_trust(id).unwrap(), (1, 3));
    stopped(&c, id);
    c.vm_destroy(id).unwrap();
    let (next, _) = c.create_vm(&spec(&fresh_cmd)).unwrap();
    assert_eq!(next, id);
    assert_eq!(c.vm_trust(next).unwrap(), (0, 0));
    stopped(&c, next);
    c.vm_destroy(next).unwrap();

    // A new instance is already assigned at CREATE. Empty reads/writes
    // do not taint; queued input before START must taint that instance.
    let r = c.call(CTL_VM_CREATE, &[128 << 20, 1], b"queued", &[]).unwrap();
    let (next, gpa) = (r.vals[0], r.vals[1]);
    assert_eq!(next, id);
    assert_eq!(c.vm_trust(next).unwrap(), (0, 0));
    c.call(CTL_CONSOLE_READ, &[next, 0], &[], &[]).unwrap();
    c.call(CTL_CONSOLE_WRITE, &[next, 0], &[], &[]).unwrap();
    assert_eq!(c.vm_trust(next).unwrap(), (0, 0));
    c.call(CTL_CONSOLE_WRITE, &[next, 7], b"queued\n", &[]).unwrap();
    assert_eq!(c.vm_trust(next).unwrap(), (1, 0));
    for (i, chunk) in initrd.chunks(CTL_LOAD_MAX).enumerate() {
        c.call(CTL_VM_LOAD, &[next, gpa + (i * CTL_LOAD_MAX) as u64, 0, chunk.len() as u64], &[], chunk).unwrap();
    }
    c.call(CTL_VM_START, &[next, gpa, initrd.len() as u64], cmd("queued").as_bytes(), &[]).unwrap();
    stopped(&c, next);
    c.vm_destroy(next).unwrap();
    // dom0's own reads and writes are exempt, even after it seals them.
    attest::seal(&bits(&["console-in", "console-out"])).unwrap();
    c.call(CTL_CONSOLE_READ, &[0, 0], &[], &[]).unwrap();
    c.call(CTL_CONSOLE_WRITE, &[0, 1], b"\n", &[]).unwrap();
    assert_eq!(c.vm_trust(0).unwrap(), (0, 3));
    println!("FLAGS: PASS{}", if no_tpm { " no TPM" } else { "" });
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("take") => {
            wait(|| std::path::Path::new("/tmp/race-start").exists());
            let mut act = [0; 36]; act[..32].copy_from_slice(&bits(&["141"])); act[32] = 1;
            std::process::exit(match raw_attest(4, &act) { Ok(_) => 0, Err(1) => 1, Err(_) => 2 });
        }
        Some("dom0") => dom0(args.get(2).is_some_and(|s| s == "no-tpm")),
        Some("guest") => {
            let cmd = fs::read_to_string("/proc/cmdline").unwrap();
            let mode = cmd.split_whitespace().find_map(|s| s.strip_prefix("flags_mode=")).unwrap();
            guest(mode, cmd.split_whitespace().any(|s| s == "flags_no_tpm=1"));
        }
        _ => panic!("flags-test dom0 [no-tpm] | guest | take"),
    }
}
