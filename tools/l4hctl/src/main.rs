// SPDX-License-Identifier: BSD-2-Clause

//! l4hctl: command-line client of the l4h control API (DESIGN.md §9.1).

use std::io::{self, Write};
use std::process::exit;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use l4hctl::*;

struct CreateOpts {
    name: String,
    mem: u64,
    vcpus: u64,
    initrd: Option<String>,
    cmdline: String,
    disks: Vec<(u64, bool, u64, u64)>,
    volumes: Vec<(u64, bool, Vec<(u64, u64)>)>,
    io_pool: u64,
    nics: Vec<(u64, u64, u64)>,
    gpu: Option<(u64, u64)>,
}

/// Where the PV on `disk` starts: dom0's only window on it, which holds
/// the PV's label and metadata.
fn dom0_pv_start(ctl: &Ctl, disk: u64) -> Result<u64> {
    let windows: Vec<_> = ctl.disk_attachments(disk)?.into_iter().filter(|a| a.vm == 0).collect();
    match &windows[..] {
        [w] => Ok(w.start),
        _ => err(format!("disk {disk}: dom0 has {} windows on it; give the PV's start (pv-start=)", windows.len())),
    }
}

fn cmd_create(ctl: &Ctl, o: &CreateOpts) -> Result<u64> {
    let initrd = match &o.initrd {
        Some(p) => read_file(p)?,
        None => Vec::new(),
    };
    let (vm, macs) = ctl.create_vm(&VmSpec {
        name: &o.name,
        mem: o.mem,
        vcpus: o.vcpus,
        initrd: &initrd,
        cmdline: &o.cmdline,
        disks: o.disks.clone(),
        volumes: o.volumes.clone(),
        io_pool: o.io_pool,
        nics: o.nics.clone(),
        gpu: o.gpu,
    })?;
    for (&(sw, _, _), mac) in o.nics.iter().zip(macs) {
        eprintln!("vm {vm}: nic on switch {sw}, mac {}", fmt_mac(mac));
    }
    Ok(vm)
}

fn cmd_console(ctl: &Ctl, vm: u64, follow: bool, until: Option<&str>, timeout: Option<Duration>) -> Result<bool> {
    if ctl.vm_trust(vm).is_ok_and(|(_, seal)| seal & 1 != 0) {
        eprintln!("input sealed by the guest");
    }
    let start = Instant::now();
    let mut off = 0u64;
    let mut seen = Vec::new();
    let out = io::stdout();
    loop {
        let r = ctl.call(CTL_CONSOLE_READ, &[vm, off], &[], &[])?;
        let n = r.vals[1] as usize;
        if r.vals[2] != 0 {
            eprintln!("[l4hctl: {} console bytes lost]", r.vals[2]);
        }
        off = r.vals[0];
        let mut o = out.lock();
        let _ = o.write_all(&r.data[..n]);
        let _ = o.flush();
        if let Some(u) = until {
            seen.extend_from_slice(&r.data[..n]);
            if seen.windows(u.len()).any(|w| w == u.as_bytes()) {
                return Ok(true);
            }
            if seen.len() > 2 * u.len() + 4096 {
                seen.drain(..seen.len() - u.len());
            }
        }
        if n == 0 {
            if !follow && until.is_none() {
                return Ok(true);
            }
            if timeout.is_some_and(|t| start.elapsed() > t) {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn cmd_logs(ctl: &Ctl, follow: bool) -> Result<()> {
    let (mut cursor, mut end) = (0, 0);
    let out = io::stdout();
    loop {
        let (next, data, lost, snapshot) = ctl.logs_read(cursor, end)?;
        if lost != 0 {
            eprintln!("[l4hctl: {lost} host log records unavailable (overwritten or incomplete)]");
        }
        let mut o = out.lock();
        o.write_all(&data).and_then(|_| o.flush()).map_err(|e| Error(e.to_string()))?;
        drop(o);
        cursor = next;
        if !follow {
            if cursor == snapshot { return Ok(()); }
            end = snapshot;
        } else if cursor == snapshot {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

const USAGE: &str = "usage: l4hctl <command>
  version                      running host's build version
  logs [--follow]              retained host diagnostics, faults and VM stops
  info                         host resources
  iommu                        IOMMU state: DMA and interrupts confined,
                               devices, logged faults
  host-reboot                  reset the machine (every guest stops; sync
                               dom0's disks first)
  rtc-set [UNIX_SECONDS]       set the machine RTC in UTC (default: dom0's
                               current time, e.g. after NTP synchronizes)
  disks                        host disks, owners, capacities and attachments
  disk-zero DISK START SECTORS zero an unattached region
  disk-write DISK START FILE   seed an unattached region, then flush
  lv-extents DISK VG/LV [--pv-start SECTOR]
                               extents of a linear LVM volume on DISK, whose
                               PV starts at SECTOR (default: dom0's only
                               window on DISK, the PV's metadata)
  list (or vms)                VMs and their host seals
  create NAME [--initrd F] [--mem MB] [--vcpus N]
         [--cmdline S] [--disk I[,ro][,start=SECTOR][,sectors=N]]...
                               create and start a VM, which runs the
                               host's kernel; prints its id
         [--disk I[,ro],extents=START:N+START:N...]...
                               a disk made of extents of disk I, in order
         [--lv I:VG/LV[,ro][,pv-start=SECTOR]]...
                               a linear LVM volume on disk I (see
                               lv-extents); disks of extents come last
         [--nic SWITCH[,mac=MAC][,nolock][,isolated]]...
         [--io-pool MB]        device I/O buffer pool (power of two, 1-256;
                               default 4, or room for the GPU's buffers)
         [--gpu WxH]           a virtio-gpu display of W x H pixels
  shutdown VM [--reboot]       ask the VM to shut down (or reboot) cleanly
  destroy VM                   stop a VM and free its resources
  sched VM CAP                 cap each vCPU of VM at CAP% of a core (0: none)
  mem VM [MB] [--wait[=SECS]]  memory of VM (boot/target/plugged/region, MiB);
                               with MB, plug or unplug 128 MiB hotplug blocks
                               until it has MB; --wait for the guest to get
                               there (default 60 s)
  cores VM                     host core of each vCPU of VM
  top                          CPU use of each VM
  nics                         host NICs
  switch-create                create an L2 switch; prints its id
  uplink SWITCH NIC            make host NIC the uplink of SWITCH
  switch SWITCH                ports and counters of SWITCH
  console VM [--follow] [--until STR] [--timeout SECS]
                               print the VM's console output
  screenshot VM FILE           save the VM's display as a PPM image
  send VM [--wait PAT [--timeout SECS]] TEXT
                               type TEXT (plus newline) on the VM's console;
                               with --wait, print the time until PAT appears
In any guest (flags work without a TPM):
  attest flags                show taint and seal bit lists
  attest seal FLAG...         seal console-in, console-out or bits 128-255
  attest act [--seal] BIT...   act on bits 128-255; --seal takes them once;
                               a refusal exits with status 1
  attest report [HEX] [-o F]   report on this guest with HEX (up to 64
                               bytes) as its data; hex, or binary to F
  attest evidence [-o F]       the host evidence; hex, or binary to F
  attest activate F            decrypt the credential F (tpm2_makecredential
                               format) for the host's attestation key";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return err(format!("bad hex: {s}"));
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| Error(format!("bad hex: {s}")))).collect()
}

/// `attest ...`: these need no /dev/l4hctl.
fn cmd_attest(args: &[String]) -> Result<i32> {
    let (mut out, mut pos) = (None, Vec::new());
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "-o" {
            out = Some(it.next().ok_or(Error("-o: missing file".into()))?.clone());
        } else {
            pos.push(a.as_str());
        }
    }
    let action = args.first().map(String::as_str);
    if matches!(action, Some("flags" | "seal" | "act")) {
        if out.is_some() { return err("flags commands print bit lists; -o is for reports and evidence"); }
        let f = match action {
            Some("flags") if pos.is_empty() => attest::flags()?,
            Some("seal") if !pos.is_empty() => attest::seal(&attest::bitmap(&pos)?)?,
            Some("act") => {
                let seal = pos.first() == Some(&"--seal");
                let bits = if seal { &pos[1..] } else { &pos[..] };
                if bits.is_empty() { return err("act: missing bits"); }
                attest::act(&attest::bitmap(bits)?, seal)?
            }
            _ => return err("attest flags | seal FLAG... | act [--seal] BIT..."),
        };
        println!("taint={} seal={}", attest::format_bits(&f.taint), attest::format_bits(&f.seal));
        return Ok(0);
    }
    let result = match (args.first().map(|s| s.as_str()), pos.as_slice()) {
        (Some("report"), []) => attest::report(&[])?,
        (Some("report"), [data]) => attest::report(&unhex(data)?)?,
        (Some("evidence"), []) => attest::evidence()?,
        (Some("activate"), [file]) => attest::activate(&read_file(file)?)?,
        _ => {
            eprintln!("{USAGE}");
            return Ok(2);
        }
    };
    match out {
        Some(f) => std::fs::write(&f, &result).map_err(|e| Error(format!("{f}: {e}")))?,
        None => println!("{}", hex(&result)),
    }
    Ok(0)
}

fn run(args: &[String]) -> Result<i32> {
    let Some(cmd) = args.first() else {
        eprintln!("{USAGE}");
        return Ok(2);
    };
    if cmd == "attest" {
        return cmd_attest(&args[1..]);
    }
    if cmd == "lv-extents" {
        // Only the default PV start needs the host.
        let (disk, lv, pv_start) = match &args[1..] {
            [d, lv] => (parse_num(d)?, lv, None),
            [d, lv, flag, p] if flag == "--pv-start" => (parse_num(d)?, lv, Some(parse_num(p)?)),
            _ => return err("lv-extents DISK VG/LV [--pv-start SECTOR]"),
        };
        let pv_start = match pv_start {
            Some(p) => p,
            None => dom0_pv_start(&Ctl::open()?, disk)?,
        };
        println!("{}", fmt_extents(&lv_extents(lv, pv_start)?));
        return Ok(0);
    }
    let ctl = Ctl::open()?;
    match cmd.as_str() {
        "version" => println!("{}", ctl.host_version()?),
        "logs" => {
            let follow = match &args[1..] {
                [] => false,
                [arg] if arg == "--follow" => true,
                _ => return err("logs [--follow]"),
            };
            cmd_logs(&ctl, follow)?;
        }
        "info" => {
            let r = ctl.call(CTL_HOST_INFO, &[], &[], &[])?;
            println!("cores:  {}", r.vals[0]);
            println!("memory: {} MiB free of {} MiB", r.vals[1] >> 20, r.vals[2] >> 20);
            println!("disks:  {}", r.vals[3]);
            println!("vms:    {}", r.vals[4]);
            // A host that predates CTL_IOMMU_INFO: no line.
            if let Ok(i) = ctl.iommu_info() {
                let irq = if i.state != IOMMU_ON { "" } else if i.intremap { ", interrupts remapped" } else { ", interrupts not remapped" };
                println!("iommu:  {}{irq}", i.state_name());
            }
        }
        "iommu" => {
            let i = ctl.iommu_info()?;
            println!("state:      {}", i.state_name());
            if i.state == IOMMU_ON {
                println!("iommus:     {}", i.units);
                println!("interrupts: {}", if i.intremap { "remapped" } else { "not remapped (disabled or unavailable)" });
                println!("devices:    {} confined, {} behind no IOMMU", i.confined, i.unconfined);
                println!("events:     {}", i.events);
            }
        }
        "host-reboot" => {
            ctl.host_reboot()?;
        }
        "rtc-set" => {
            let seconds = match &args[1..] {
                [] => SystemTime::now().duration_since(UNIX_EPOCH)
                    .map_err(|_| Error("dom0's clock is before the Unix epoch".into()))?.as_secs(),
                [seconds] => parse_num(seconds)?,
                _ => return err("rtc-set [UNIX_SECONDS]"),
            };
            ctl.rtc_set(seconds)?;
        }
        "disks" => {
            let n = ctl.call(CTL_HOST_INFO, &[], &[], &[])?.vals[3];
            for d in 0..n {
                let r = ctl.call(CTL_DISK_INFO, &[d], &[], &[])?;
                let (bdf, addr) = (r.vals[0] & 0xffff, r.vals[0] >> 16);
                let owner = if r.vals[1] == u64::MAX { "-".to_string() } else { format!("vm {}", r.vals[1]) };
                let kind = match r.vals[3] {
                    1 => "nvme".to_string(),
                    // Target and LUN.
                    2 => format!("virtio-scsi {}:{}", addr & 0xff, addr >> 8),
                    _ => "virtio-blk".to_string(),
                };
                let failed = if r.vals[2] != 0 { ", failed (quarantined)" } else { "" };
                println!("disk {d}: pci {:02x}:{:02x}.{} {kind}, owner {owner}{failed}, sectors {}, attachments {}", bdf >> 8, (bdf >> 3) & 0x1f, bdf & 7, r.vals[4], r.vals[5]);
            }
        }
        "disk-zero" => {
            if args.len() != 4 { return err("disk-zero DISK START SECTORS"); }
            let disk = parse_num(&args[1])?;
            ctl.disk_zero(disk, parse_num(&args[2])?, parse_num(&args[3])?)?;
            ctl.disk_flush(disk)?;
        }
        "disk-write" => {
            use std::io::Read;
            if args.len() != 4 { return err("disk-write DISK START FILE"); }
            let disk = parse_num(&args[1])?;
            let mut sector = parse_num(&args[2])?;
            let mut f = std::fs::File::open(&args[3]).map_err(|e| Error(e.to_string()))?;
            let mut data = vec![0; CTL_LOAD_MAX];
            loop {
                let mut len = 0;
                while len < data.len() {
                    let n = f.read(&mut data[len..]).map_err(|e| Error(e.to_string()))?;
                    if n == 0 { break; }
                    len += n;
                }
                if len == 0 { break; }
                ctl.disk_write(disk, sector, &data[..len])?;
                sector = sector.checked_add((len / 512) as u64).ok_or_else(|| Error("sector overflow".into()))?;
            }
            ctl.disk_flush(disk)?;
        }
        "list" | "vms" => {
            println!("{:>3} {:<16} {:>5} {:>8} {}", "ID", "NAME", "VCPUS", "MEM", "STATE / SEAL");
            let mut first = 0u64;
            loop {
                let r = ctl.call(CTL_VM_LIST, &[first], &[], &[])?;
                let n = r.vals[0] as usize;
                if n == 0 {
                    break;
                }
                for i in 0..n {
                    let vm: CtlVm = unsafe {
                        std::ptr::read_unaligned(r.data.as_ptr().add(i * std::mem::size_of::<CtlVm>()) as *const CtlVm)
                    };
                    let name_len = vm.name.iter().position(|&c| c == 0).unwrap_or(CTL_NAME_MAX);
                    let state = match vm.state {
                        1 => "created",
                        2 => "running",
                        3 => "stopped",
                        _ => "?",
                    };
                    let seal = ctl.vm_trust(vm.id as u64).map(|(_, seal)| seal).unwrap_or(0);
                    let seal = if seal != 0 { format!(" seal={}", attest::format_bits(&seal.to_le_bytes())) } else { String::new() };
                    println!(
                        "{:>3} {:<16} {:>5} {:>7}M {}{}",
                        vm.id,
                        String::from_utf8_lossy(&vm.name[..name_len]),
                        vm.vcpus,
                        vm.ram >> 20,
                        state, seal
                    );
                    first = vm.id as u64 + 1;
                }
            }
        }
        "create" => {
            let name = args.get(1).ok_or(Error("create: missing NAME".into()))?.clone();
            let mut o = CreateOpts {
                name,
                mem: 128 << 20,
                vcpus: 1,
                initrd: None,
                cmdline: "console=hvc0".into(),
                disks: Vec::new(),
                volumes: Vec::new(),
                io_pool: 0,
                nics: Vec::new(),
                gpu: None,
            };
            let mut it = args[2..].iter();
            while let Some(a) = it.next() {
                let mut val = || it.next().cloned().ok_or(Error(format!("{a}: missing value")));
                match a.as_str() {
                    "--initrd" => o.initrd = Some(val()?),
                    "--mem" => o.mem = parse_mib(&val()?)?,
                    "--vcpus" => o.vcpus = parse_num(&val()?)?,
                    "--io-pool" => o.io_pool = parse_mib(&val()?)?,
                    "--cmdline" => o.cmdline = val()?,
                    "--disk" => {
                        // DISK[,ro][,start=SECTOR][,sectors=N] (or DISK:ro),
                        // or DISK[,ro],extents=START:N+...
                        let v = val()?.replace(":ro", ",ro");
                        let mut it = v.split(',');
                        let d = parse_num(it.next().unwrap())?;
                        let (mut ro, mut start, mut sectors, mut extents) = (false, 0, 0, None);
                        for opt in it {
                            if opt == "ro" {
                                ro = true;
                            } else if let Some(n) = opt.strip_prefix("start=") {
                                start = parse_num(n)?;
                            } else if let Some(n) = opt.strip_prefix("sectors=") {
                                sectors = parse_num(n)?;
                            } else if let Some(e) = opt.strip_prefix("extents=") {
                                extents = Some(parse_extents(e)?);
                            } else {
                                return err(format!("--disk: unknown option {opt}"));
                            }
                        }
                        match extents {
                            Some(_) if start != 0 || sectors != 0 => return err("--disk: extents= or start=/sectors="),
                            Some(e) => o.volumes.push((d, ro, e)),
                            None => o.disks.push((d, ro, start, sectors)),
                        }
                    }
                    "--lv" => {
                        // DISK:VG/LV[,ro][,pv-start=SECTOR]
                        let v = val()?;
                        let (d, rest) = v.split_once(':').ok_or(Error("--lv DISK:VG/LV".into()))?;
                        let d = parse_num(d)?;
                        let mut it = rest.split(',');
                        let lv = it.next().unwrap().to_string();
                        let (mut ro, mut pv_start) = (false, None);
                        for opt in it {
                            if opt == "ro" {
                                ro = true;
                            } else if let Some(n) = opt.strip_prefix("pv-start=") {
                                pv_start = Some(parse_num(n)?);
                            } else {
                                return err(format!("--lv: unknown option {opt}"));
                            }
                        }
                        let pv_start = match pv_start {
                            Some(p) => p,
                            None => dom0_pv_start(&ctl, d)?,
                        };
                        o.volumes.push((d, ro, lv_extents(&lv, pv_start)?));
                    }
                    "--nic" => {
                        // SWITCH[,mac=MAC][,nolock][,isolated]
                        let v = val()?;
                        let mut it = v.split(',');
                        let sw = parse_num(it.next().unwrap())?;
                        let (mut mac, mut flags) = (0, 0);
                        for opt in it {
                            if let Some(m) = opt.strip_prefix("mac=") {
                                mac = parse_mac(m)?;
                            } else if opt == "nolock" {
                                flags |= NIC_NO_MAC_LOCK;
                            } else if opt == "isolated" {
                                flags |= NIC_ISOLATED;
                            } else {
                                return err(format!("--nic: unknown option {opt}"));
                            }
                        }
                        o.nics.push((sw, mac, flags));
                    }
                    "--gpu" => {
                        let v = val()?;
                        let (w, h) = v.split_once('x').ok_or(Error(format!("--gpu: {v}: not WxH")))?;
                        o.gpu = Some((parse_num(w)?, parse_num(h)?));
                    }
                    _ => return err(format!("create: unknown option {a}")),
                }
            }
            println!("{}", cmd_create(&ctl, &o)?);
        }
        "sched" => {
            let vm = parse_num(args.get(1).ok_or(Error("sched: missing VM".into()))?)?;
            let cap = parse_num(args.get(2).ok_or(Error("sched: missing CAP".into()))?)?;
            ctl.call(CTL_VM_SET_SCHED, &[vm, cap], &[], &[])?;
        }
        "top" => {
            // CPU use of every VM over the last balancer period.
            let mut first = 0u64;
            println!("{:>3} {:<16} {:>6} {:>5}", "ID", "NAME", "CPU%", "CAP%");
            loop {
                let r = ctl.call(CTL_VM_LIST, &[first], &[], &[])?;
                let n = r.vals[0] as usize;
                if n == 0 {
                    break;
                }
                for i in 0..n {
                    let vm: CtlVm = unsafe {
                        std::ptr::read_unaligned(r.data.as_ptr().add(i * std::mem::size_of::<CtlVm>()) as *const CtlVm)
                    };
                    let s = ctl.call(CTL_VM_STATS, &[vm.id as u64], &[], &[])?;
                    let name_len = vm.name.iter().position(|&c| c == 0).unwrap_or(CTL_NAME_MAX);
                    println!(
                        "{:>3} {:<16} {:>6.1} {:>5}",
                        vm.id,
                        String::from_utf8_lossy(&vm.name[..name_len]),
                        s.vals[0] as f64 / 10.0,
                        s.vals[1]
                    );
                    first = vm.id as u64 + 1;
                }
            }
        }
        "cores" => {
            let vm = parse_num(args.get(1).ok_or(Error("cores: missing VM".into()))?)?;
            let r = ctl.call(CTL_VM_INFO, &[vm], &[], &[])?;
            let n = ctl.call(CTL_VM_LIST, &[vm], &[], &[])?;
            let vcpus = if n.vals[0] > 0 {
                unsafe { std::ptr::read_unaligned(n.data.as_ptr() as *const CtlVm) }.vcpus as usize
            } else {
                0
            };
            let cores: Vec<String> = r.vals[..vcpus.min(6)].iter().map(|c| c.to_string()).collect();
            println!("{}", cores.join(" "));
        }
        "nics" => {
            let n = ctl.call(CTL_HOST_INFO, &[], &[], &[])?.vals[5];
            for i in 0..n {
                let r = ctl.call(CTL_NIC_INFO, &[i], &[], &[])?;
                let bdf = r.vals[0];
                let sw = if r.vals[1] == u64::MAX { "-".to_string() } else { format!("switch {}", r.vals[1]) };
                println!(
                    "nic {i}: pci {:02x}:{:02x}.{}, mac {}, uplink of {sw}",
                    bdf >> 8, (bdf >> 3) & 0x1f, bdf & 7, fmt_mac(r.vals[2])
                );
            }
        }
        "switch-create" => {
            println!("{}", ctl.call(CTL_SWITCH_CREATE, &[], &[], &[])?.vals[0]);
        }
        "uplink" => {
            let sw = parse_num(args.get(1).ok_or(Error("uplink: missing SWITCH".into()))?)?;
            let nic = parse_num(args.get(2).ok_or(Error("uplink: missing NIC".into()))?)?;
            ctl.call(CTL_SWITCH_ATTACH_UPLINK, &[sw, nic], &[], &[])?;
        }
        "switch" => {
            let sw = parse_num(args.get(1).ok_or(Error("switch: missing SWITCH".into()))?)?;
            let r = ctl.call(CTL_SWITCH_INFO, &[sw], &[], &[])?;
            if r.vals[1] != u64::MAX {
                println!("switch {sw}: uplink nic {}", r.vals[1]);
            } else {
                println!("switch {sw}: no uplink");
            }
            println!("{:>4} {:>3} {:<17} {:>8} {:>8} {:>6}", "PORT", "VM", "MAC", "RX", "TX", "DROPS");
            for i in 0..r.vals[0] as usize {
                let p: CtlPort = unsafe {
                    std::ptr::read_unaligned(r.data.as_ptr().add(i * std::mem::size_of::<CtlPort>()) as *const CtlPort)
                };
                println!("{:>4} {:>3} {:<17} {:>8} {:>8} {:>6}", p.port, p.vm, fmt_mac(p.mac), p.rx_frames, p.tx_frames, p.drops);
            }
        }
        "shutdown" => {
            let vm = parse_num(args.get(1).ok_or(Error("shutdown: missing VM".into()))?)?;
            let how = if args.get(2).map(|s| s.as_str()) == Some("--reboot") { 1 } else { 0 };
            ctl.call(CTL_VM_SHUTDOWN, &[vm, how], &[], &[])?;
        }
        "mem" => {
            let vm = parse_num(args.get(1).ok_or(Error("mem: missing VM".into()))?)?;
            let (mut size, mut wait) = (None, None);
            for a in &args[2..] {
                match a.as_str() {
                    "--wait" => wait = Some(60),
                    w if w.starts_with("--wait=") => wait = Some(parse_num(&w[7..])?),
                    s => size = Some(parse_mib(s)?),
                }
            }
            if let Some(bytes) = size {
                ctl.set_mem(vm, bytes)?;
            }
            let mut m = ctl.mem_info(vm)?;
            if let Some(secs) = wait {
                let until = std::time::Instant::now() + Duration::from_secs(secs);
                while m.plugged != m.target && std::time::Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(100));
                    m = ctl.mem_info(vm)?;
                }
            }
            println!("{}/{}/{}/{} MiB", m.boot >> 20, (m.boot + m.target) >> 20, (m.boot + m.plugged) >> 20, (m.boot + m.region) >> 20);
            if wait.is_some() && m.plugged != m.target {
                let why = if m.plugged > m.target { "the guest cannot give back more" } else { "the host is short of memory" };
                return err(format!("mem: {} MiB plugged, target {} MiB: {why}", m.plugged >> 20, m.target >> 20));
            }
        }
        "destroy" => {
            let vm = parse_num(args.get(1).ok_or(Error("destroy: missing VM".into()))?)?;
            ctl.call(CTL_VM_DESTROY, &[vm], &[], &[])?;
        }
        "console" => {
            let vm = parse_num(args.get(1).ok_or(Error("console: missing VM".into()))?)?;
            let (mut follow, mut until, mut timeout) = (false, None, None);
            let mut it = args[2..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--follow" | "-f" => follow = true,
                    "--until" => until = Some(it.next().filter(|s| !s.is_empty()).cloned().ok_or(Error("--until: missing pattern".into()))?),
                    "--timeout" => {
                        let s = parse_num(it.next().ok_or(Error("--timeout: missing value".into()))?)?;
                        timeout = Some(Duration::from_secs(s));
                    }
                    _ => return err(format!("console: unknown option {a}")),
                }
            }
            if !cmd_console(&ctl, vm, follow, until.as_deref(), timeout)? {
                eprintln!("l4hctl: timed out");
                return Ok(1);
            }
        }
        "screenshot" => {
            let vm = parse_num(args.get(1).ok_or(Error("screenshot: missing VM".into()))?)?;
            let path = args.get(2).ok_or(Error("screenshot: missing FILE".into()))?;
            let s = ctl.screenshot(vm)?;
            std::fs::write(path, s.ppm()?).map_err(|e| Error(format!("{path}: {e}")))?;
            eprintln!("vm {vm}: {}x{}, frame {}", s.width, s.height, s.frame);
        }
        "send" => {
            let vm = parse_num(args.get(1).ok_or(Error("send: missing VM".into()))?)?;
            // send VM [--wait PATTERN [--timeout SECS]] TEXT...
            let mut rest = &args[2..];
            let (mut wait, mut timeout) = (None, Duration::from_secs(30));
            loop {
                match rest.first().map(|s| s.as_str()) {
                    Some("--wait") if rest.len() > 1 => {
                        if rest[1].is_empty() {
                            return err("--wait: empty pattern");
                        }
                        wait = Some(rest[1].clone());
                        rest = &rest[2..];
                    }
                    Some("--timeout") if rest.len() > 1 => {
                        timeout = Duration::from_secs(parse_num(&rest[1])?);
                        rest = &rest[2..];
                    }
                    _ => break,
                }
            }
            // Skip output so far, so that only the answer is matched.
            let mut con = 0u64;
            if wait.is_some() {
                loop {
                    let r = ctl.call(CTL_CONSOLE_READ, &[vm, con], &[], &[])?;
                    con = r.vals[0];
                    if r.vals[1] == 0 {
                        break;
                    }
                }
            }
            let start = Instant::now();
            let mut text = rest.join(" ").into_bytes();
            text.push(b'\n');
            let mut off = 0;
            while off < text.len() {
                let chunk = &text[off..(off + CTL_DATA_MAX).min(text.len())];
                let r = ctl.call(CTL_CONSOLE_WRITE, &[vm, chunk.len() as u64], chunk, &[])?;
                off += r.vals[0] as usize;
                if r.vals[0] == 0 {
                    // The guest is not reading its console.
                    if start.elapsed() > timeout {
                        eprintln!("l4hctl: timed out writing to the console");
                        return Ok(1);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            if let Some(pat) = wait {
                let mut seen = Vec::new();
                loop {
                    let r = ctl.call(CTL_CONSOLE_READ, &[vm, con], &[], &[])?;
                    con = r.vals[0];
                    seen.extend_from_slice(&r.data[..r.vals[1] as usize]);
                    if seen.windows(pat.len()).any(|w| w == pat.as_bytes()) {
                        println!("{:.1} ms", start.elapsed().as_secs_f64() * 1000.0);
                        break;
                    }
                    if start.elapsed() > timeout {
                        eprintln!("l4hctl: timed out");
                        return Ok(1);
                    }
                    if r.vals[1] == 0 {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            return Ok(2);
        }
    }
    Ok(0)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => exit(code),
        Err(Error(e)) => {
            eprintln!("l4hctl: {e}");
            exit(1);
        }
    }
}
