//! Port I/O, MSRs, CPUID, the TSC, the serial port and a fixed-capacity
//! vector: what the shim runs on.

use core::fmt;

pub fn outb(port: u16, v: u8) {
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nostack, preserves_flags)) }
}

pub fn inb(port: u16) -> u8 {
    let v: u8;
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nostack, preserves_flags)) }
    v
}

pub fn outl(port: u16, v: u32) {
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nostack, preserves_flags)) }
}

pub fn inl(port: u16) -> u32 {
    let v: u32;
    unsafe { core::arch::asm!("in eax, dx", in("dx") port, out("eax") v, options(nostack, preserves_flags)) }
    v
}

pub fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nostack)) }
    (hi as u64) << 32 | lo as u64
}

pub fn wrmsr(msr: u32, v: u64) {
    unsafe { core::arch::asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32, options(nostack)) }
}

pub fn cpuid(leaf: u32, sub: u32) -> [u32; 4] {
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    [r.eax, r.ebx, r.ecx, r.edx]
}

pub fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

pub fn pause() {
    core::hint::spin_loop();
}

/// The serial port the shim reports on (console_port= on its command
/// line, COM1 by default).
pub static mut SERIAL: u16 = 0x3f8;

pub fn serial_init(port: u16) {
    unsafe { SERIAL = port };
    if port == 0 {
        return;
    }
    outb(port + 1, 0);
    outb(port + 3, 0x80);
    outb(port, 1);
    outb(port + 1, 0);
    outb(port + 3, 3);
    outb(port + 4, 0x0b);
}

fn serial_put(c: u8) {
    let port = unsafe { SERIAL };
    if port == 0 {
        return;
    }
    let mut n = 0;
    while inb(port + 5) & 0x20 == 0 && n < 100_000 {
        n += 1;
    }
    outb(port, c);
}

pub struct Serial;

impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                serial_put(b'\r');
            }
            serial_put(b);
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = writeln!($crate::io::Serial, "l4h-mkshim: {}", format_args!($($arg)*));
    }};
}

/// A vector of at most N elements, without allocation.
#[derive(Clone, Copy)]
pub struct Vec<T: Copy, const N: usize> {
    buf: [core::mem::MaybeUninit<T>; N],
    len: usize,
}

impl<T: Copy, const N: usize> Vec<T, N> {
    pub const fn new() -> Self {
        Vec { buf: [const { core::mem::MaybeUninit::uninit() }; N], len: 0 }
    }

    pub fn push(&mut self, v: T) -> bool {
        if self.len == N {
            return false;
        }
        self.buf[self.len].write(v);
        self.len += 1;
        true
    }

    pub fn must_push(&mut self, v: T) {
        if !self.push(v) {
            crate::fail(format_args!("more than {} entries in a table", N));
        }
    }

    pub fn insert(&mut self, i: usize, v: T) {
        if self.len == N {
            crate::fail(format_args!("more than {} entries in a table", N));
        }
        let mut j = self.len;
        while j > i {
            self.buf[j] = self.buf[j - 1];
            j -= 1;
        }
        self.buf[i].write(v);
        self.len += 1;
    }

    pub fn remove(&mut self, i: usize) -> T {
        let v = self[i];
        for j in i..self.len - 1 {
            self.buf[j] = self.buf[j + 1];
        }
        self.len -= 1;
        v
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl<T: Copy, const N: usize> core::ops::Deref for Vec<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.buf.as_ptr() as *const T, self.len) }
    }
}

impl<T: Copy, const N: usize> core::ops::DerefMut for Vec<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.buf.as_mut_ptr() as *mut T, self.len) }
    }
}

/// A NUL-free string of at most N bytes.
#[derive(Clone, Copy)]
pub struct Str<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Str<N> {
    pub const fn new() -> Self {
        Str { buf: [0; N], len: 0 }
    }

    pub fn from(s: &str) -> Self {
        let mut r = Self::new();
        r.push(s);
        r
    }

    pub fn push(&mut self, s: &str) {
        for &b in s.as_bytes() {
            if self.len < N {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl<const N: usize> fmt::Write for Str<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.len + s.len() > N {
            return Err(fmt::Error);
        }
        self.push(s);
        Ok(())
    }
}

/// Bytes at physical address `pa` (identity mapped).
pub unsafe fn phys<'a>(pa: u64, len: usize) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(pa as *const u8, len) }
}

pub unsafe fn phys_mut<'a>(pa: u64, len: usize) -> &'a mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(pa as *mut u8, len) }
}

pub fn rd16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

pub fn rd32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}

pub fn rd64(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}

pub const fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

pub const fn align_down(v: u64, a: u64) -> u64 {
    v & !(a - 1)
}
