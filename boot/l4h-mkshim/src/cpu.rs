//! The local APIC, starting a partition's first CPU, the PIT measurements
//! no kernel repeats, the 8259 PIC and the CMOS clock.

use crate::io::{cpuid, inb, outb, rdmsr, rdtsc, wrmsr, pause};
use crate::pci::UC_ALIAS;

const IA32_APIC_BASE: u32 = 0x1b;

fn x2apic() -> bool {
    rdmsr(IA32_APIC_BASE) & (1 << 10) != 0
}

fn xapic_base() -> u64 {
    UC_ALIAS + (rdmsr(IA32_APIC_BASE) & 0xf_ffff_f000)
}

fn lapic_read(reg: u32) -> u32 {
    if x2apic() {
        rdmsr(0x800 + (reg >> 4)) as u32
    } else {
        unsafe { ((xapic_base() + reg as u64) as *const u32).read_volatile() }
    }
}

fn lapic_write(reg: u32, v: u32) {
    if x2apic() {
        wrmsr(0x800 + (reg >> 4), v as u64)
    } else {
        unsafe { ((xapic_base() + reg as u64) as *mut u32).write_volatile(v) }
    }
}

pub fn is_x2apic() -> bool {
    x2apic()
}

/// This CPU's APIC ID.
pub fn apic_id() -> u32 {
    if x2apic() { rdmsr(0x802) as u32 } else { lapic_read(0x20) >> 24 }
}

fn send_ipi(dest: u32, icr: u32) {
    if x2apic() {
        wrmsr(0x830, (dest as u64) << 32 | icr as u64);
    } else {
        lapic_write(0x310, dest << 24);
        lapic_write(0x300, icr);
        let mut n = 0;
        while lapic_read(0x300) & (1 << 12) != 0 && n < 1_000_000 {
            pause();
            n += 1;
        }
    }
}

/// TSC ticks per microsecond, once measured.
static mut TSC_PER_US: u64 = 1000;

pub fn udelay(us: u64) {
    let end = rdtsc() + us * unsafe { TSC_PER_US };
    while rdtsc() < end {
        pause();
    }
}

/// Start the CPU with APIC ID `dest` in real mode at `page` (below 1 MiB):
/// INIT, then two STARTUPs (Intel SDM 8.4.4.1).
pub fn start_cpu(dest: u32, page: u64) {
    send_ipi(dest, 0x4500);
    udelay(10_000);
    for _ in 0..2 {
        send_ipi(dest, 0x4600 | (page >> 12) as u32);
        udelay(200);
    }
}

/// The 8254 PIT, channel 2, counting down `ms` milliseconds with the
/// speaker off; calls `start` as it starts and returns when it ends.
fn pit_wait(ms: u32, start: impl FnOnce()) {
    let count = 1_193_182 * ms / 1000;
    outb(0x61, (inb(0x61) & !0x02) | 0x01);
    outb(0x43, 0xb0);
    outb(0x42, count as u8);
    outb(0x42, (count >> 8) as u8);
    // Gate low then high restarts the count.
    outb(0x61, inb(0x61) & !0x01);
    outb(0x61, inb(0x61) | 0x01);
    start();
    let mut n = 0u64;
    while inb(0x61) & 0x20 == 0 && n < 100_000_000 {
        n += 1;
    }
}

fn median(s: &mut [u64]) -> u64 {
    s.sort_unstable();
    s[s.len() / 2]
}

/// The TSC rate in kHz: from CPUID leaf 0x15 on Intel, as seL4 does
/// (patch 0022), or measured against the PIT.
pub fn tsc_khz() -> u64 {
    let v = cpuid(0, 0);
    let intel = v[1] == 0x756e_6547 && v[3] == 0x4965_6e69 && v[2] == 0x6c65_746e;
    if intel && v[0] >= 0x15 {
        let r = cpuid(0x15, 0);
        if r[0] != 0 && r[1] != 0 {
            let khz = if r[2] != 0 {
                r[2] as u64 * r[1] as u64 / r[0] as u64 / 1000
            } else if v[0] >= 0x16 {
                (cpuid(0x16, 0)[0] & 0xffff) as u64 * 1000
            } else {
                0
            };
            if khz != 0 {
                unsafe { TSC_PER_US = khz / 1000 };
                return khz;
            }
        }
    }
    let mut s = [0u64; 5];
    for x in s.iter_mut() {
        let mut t0 = 0;
        pit_wait(10, || t0 = rdtsc());
        *x = (rdtsc() - t0) / 10;
    }
    let khz = median(&mut s);
    unsafe { TSC_PER_US = (khz / 1000).max(1) };
    khz
}

/// Whether the CPU has the TSC-deadline timer, which needs no APIC
/// timer rate.
pub fn tsc_deadline() -> bool {
    cpuid(1, 0)[2] & (1 << 24) != 0
}

/// The APIC timer rate in kHz with divide-by-1, measured against the PIT.
pub fn apic_khz() -> u64 {
    lapic_write(0x3e0, 0xb);
    lapic_write(0x320, 1 << 16);
    let mut s = [0u64; 5];
    for x in s.iter_mut() {
        pit_wait(10, || lapic_write(0x380, 0xffff_ffff));
        *x = (0xffff_ffff - lapic_read(0x390)) as u64 / 10;
    }
    lapic_write(0x380, 0);
    median(&mut s)
}

/// Mask every 8259 interrupt: partition 0's kernel reprograms the PIC,
/// no other kernel touches it.
pub fn mask_pic() {
    outb(0x21, 0xff);
    outb(0xa1, 0xff);
}

fn cmos(reg: u8) -> u8 {
    outb(0x70, reg);
    inb(0x71)
}

/// The wall clock from the CMOS RTC, in ns since the epoch (0 if it
/// reads nonsense), with `century` the FADT's century register.
pub fn rtc_ns(century: u8) -> u64 {
    let mut n = 0;
    while cmos(0x0a) & 0x80 != 0 && n < 1_000_000 {
        n += 1;
    }
    let read = || {
        let c = if century != 0 { cmos(century) } else { 0 };
        [cmos(0), cmos(2), cmos(4), cmos(7), cmos(8), cmos(9), c]
    };
    let mut a = read();
    loop {
        let b = read();
        if a == b {
            break;
        }
        a = b;
    }
    let status_b = cmos(0x0b);
    let bcd = |v: u8| if status_b & 4 == 0 { (v & 0xf) + (v >> 4) * 10 } else { v };
    let (sec, min) = (bcd(a[0]) as u64, bcd(a[1]) as u64);
    let pm = status_b & 2 == 0 && a[2] & 0x80 != 0;
    let mut hour = bcd(a[2] & 0x7f) as u64;
    if pm {
        hour = (hour % 12) + 12;
    }
    let (day, month) = (bcd(a[3]) as u64, bcd(a[4]) as u64);
    let cent = if century != 0 { bcd(a[6]) as u64 } else { 20 };
    let year = cent * 100 + bcd(a[5]) as u64;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year < 1970 {
        return 0;
    }
    // Days since 1970-01-01 (proleptic Gregorian).
    let (y, m) = if month <= 2 { (year - 1, month + 9) } else { (year, month - 3) };
    let era_days = 365 * y + y / 4 - y / 100 + y / 400 + (153 * m + 2) / 5 + day - 1;
    let days = era_days - 719_468;
    ((days * 86400 + hour * 3600 + min * 60 + sec) as u64) * 1_000_000_000
}
