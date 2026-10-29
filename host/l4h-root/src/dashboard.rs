//! A read-only status display on the boot framebuffer, when the boot
//! loader set one up (GRUB on UEFI): host resources, VMs, disks and
//! network, refreshed every second.  Only character cells that changed
//! are redrawn.  Nothing on it can be operated: VMs are managed from dom0
//! or the serial monitor.

use core::fmt::{self, Display, Write};
use core::sync::atomic::{AtomicBool, Ordering};

use l4h_host::fixed::ArrayString;
use sel4::{CapRights, VmAttributes};

use crate::Host;
use crate::devmem::DevMem;
use crate::font;
use crate::mem::{Alloc, ObjCtx};
use crate::vspace::map_frame;

/// Where the framebuffer is mapped in the root task.
const FB_VA: usize = crate::layout::FRAMEBUFFER.base;
/// Refresh period in timer ticks of the balancer (100 ms).
const REFRESH_TICKS: u32 = 10;

/// The colors used, as an index so that a cell takes three bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Color {
    Bg,
    Fg,
    Dim,
    Head,
    BarBg,
    BarFg,
    Green,
    Red,
    Yellow,
    Empty,
}

const BG: Color = Color::Bg;
const FG: Color = Color::Fg;
const DIM: Color = Color::Dim;
const HEAD: Color = Color::Head;
const BAR_BG: Color = Color::BarBg;
const BAR_FG: Color = Color::BarFg;
const GREEN: Color = Color::Green;
const RED: Color = Color::Red;
const YELLOW: Color = Color::Yellow;

impl Color {
    fn rgb(self) -> u32 {
        match self {
            Color::Bg => 0x10141c,
            Color::Fg => 0xd0d4d8,
            Color::Dim => 0x7c8590,
            Color::Head => 0x80c0ff,
            Color::BarBg => 0x2a5598,
            Color::BarFg => 0xffffff,
            Color::Green => 0x66d26e,
            Color::Red => 0xe86a6a,
            Color::Yellow => 0xe8c86a,
            Color::Empty => 0x2a3038,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Cell {
    ch: u8,
    fg: Color,
    bg: Color,
}

const BLANK: Cell = Cell { ch: b' ', fg: FG, bg: BG };

/// The largest cell grid; a larger screen keeps a blank margin (8K at
/// scale 2 is 480x270 cells).  4K at scale 2 is 240x135.
const MAX_COLS: usize = 256;
const MAX_ROWS: usize = 160;
const MAX_CELLS: usize = MAX_COLS * MAX_ROWS;

/// The grids of what is on the screen and what should be, in .bss (all
/// zero bytes) rather than on the root task's small stack.
/// `Dashboard::new` takes them, once.
static mut GRIDS: [[Cell; MAX_CELLS]; 2] = [[Cell { ch: 0, fg: BG, bg: BG }; MAX_CELLS]; 2];
static GRIDS_TAKEN: AtomicBool = AtomicBool::new(false);

fn take_grids() -> Option<&'static mut [[Cell; MAX_CELLS]; 2]> {
    if GRIDS_TAKEN.swap(true, Ordering::AcqRel) {
        return None;
    }
    // The flag hands out this one reference only.
    Some(unsafe { &mut *core::ptr::addr_of_mut!(GRIDS) })
}

pub struct Dashboard {
    fb: *mut u8,
    pitch: usize,
    /// Glyph scale: 8x8 font cells are (8 sx) x (8 sy) pixels.
    sx: usize,
    sy: usize,
    cols: usize,
    rows: usize,
    /// What is on the screen, and what should be.
    shown: &'static mut [Cell],
    next: &'static mut [Cell],
    ticks: u32,
}

/// struct multiboot2_fb, as seL4 passes it in the bootinfo.
fn parse_fb(c: &[u8]) -> Option<(u64, usize, usize, usize, u8, u8)> {
    if c.len() < 22 {
        return None;
    }
    let u32_at = |o: usize| u32::from_le_bytes(c[o..o + 4].try_into().unwrap()) as usize;
    let addr = u64::from_le_bytes(c[0..8].try_into().unwrap());
    Some((addr, u32_at(8), u32_at(12), u32_at(16), c[20], c[21]))
}

impl Dashboard {
    #[cfg(not(target_arch = "x86_64"))]
    pub fn new(_bootinfo: &sel4::BootInfoPtr, _alloc: &mut Alloc, _devmem: &mut DevMem, _fb_console: bool, _warm_boot: bool) -> Option<Self> {
        let _ = (parse_fb, map_frame::<>, FB_VA);
        None
    }

    /// Map the boot framebuffer, if there is a usable one (32-bit RGB).
    /// With `fb_console` (the fb_console setting), the kernel copies its
    /// console to the screen and the dashboard keeps to the upper half.
    #[cfg(target_arch = "x86_64")]
    pub fn new(bootinfo: &sel4::BootInfoPtr, alloc: &mut Alloc, devmem: &mut DevMem, fb_console: bool, warm_boot: bool) -> Option<Self> {
        let extra = bootinfo.extra().find(|e| e.id == sel4::BootInfoExtraId::X86FrameBuffer)?;
        let (addr, pitch, width, height, bpp, ty) = parse_fb(extra.content())?;
        if addr == 0 || bpp != 32 || ty != 1 || width < 640 || height < 400 {
            info!("l4h-root: framebuffer {}x{}@{} type {} not supported", width, height, bpp, ty);
            return None;
        }
        // Device frames come in aligned power-of-two blocks.
        let (addr, len) = (addr as usize, pitch * height);
        let mut size = len.next_power_of_two();
        while addr & !(size - 1) < addr + len - size {
            size *= 2;
        }
        let base = addr & !(size - 1);
        let first = (addr - base) / 4096;
        let pages = (addr - base + len).div_ceil(4096) - first;
        if pages * 4096 > crate::layout::FRAMEBUFFER.size {
            info!("l4h-root: framebuffer of {} MiB is too large", len >> 20);
            return None;
        }
        let frames = alloc.slots.global(|slots| devmem.frames(slots, base, size))?;
        let wc = VmAttributes::from_inner(sel4::sys::seL4_X86_VMAttributes::seL4_X86_WriteCombining);
        alloc.global(|alloc| {
            for (i, s) in (frames.start + first..frames.start + first + pages).enumerate() {
                let f = crate::devmem::granule(s);
                map_frame(&mut ObjCtx::global(alloc), sel4::init_thread::slot::VSPACE.cap(), f, FB_VA + i * 4096, CapRights::read_write(), wc);
            }
        });
        let fb = (FB_VA + (addr & 4095)) as *mut u8;
        let full_height = height;
        // The kernel's copy of the console (fb_console) has the lower half.
        let height = if fb_console { height / 2 } else { height };
        // A warm boot clears the previous host's display, including its
        // console; a cold boot preserves the current kernel's boot log.
        let clear_height = if warm_boot { full_height } else { height };
        let sx = if width >= 1280 { 2 } else { 1 };
        let sy = 2;
        let (cols, rows) = ((width / (8 * sx)).min(MAX_COLS), (height / (8 * sy)).min(MAX_ROWS));
        let [shown, next] = take_grids()?;
        let (shown, next) = (&mut shown[..cols * rows], &mut next[..cols * rows]);
        // No character is 0: every cell is drawn the first time.
        shown.fill(Cell { ch: 0, ..BLANK });
        next.fill(BLANK);
        let mut d = Dashboard { fb, pitch, sx, sy, cols, rows, shown, next, ticks: REFRESH_TICKS };
        for y in 0..clear_height {
            for x in 0..width {
                d.put(x, y, BG.rgb());
            }
        }
        info!("l4h-root: dashboard on {}x{} framebuffer ({} columns)", width, height, cols);
        Some(d)
    }

    fn put(&mut self, x: usize, y: usize, rgb: u32) {
        unsafe { (self.fb.add(y * self.pitch + x * 4) as *mut u32).write_volatile(rgb) };
    }

    /// Called on every balancer tick.
    pub fn tick(h: &mut Host) {
        let Some(mut d) = h.dashboard.take() else { return };
        d.ticks += 1;
        if d.ticks >= REFRESH_TICKS {
            d.ticks = 0;
            d.compose(h);
            d.flush();
        }
        h.dashboard = Some(d);
    }

    fn text(&mut self, row: usize, col: usize, s: &str, fg: Color, bg: Color) -> usize {
        if row >= self.rows {
            return col;
        }
        let mut c = col;
        for b in s.bytes() {
            if c >= self.cols {
                break;
            }
            let ch = if (0x20..0x7f).contains(&b) { b } else { b'?' };
            self.next[row * self.cols + c] = Cell { ch, fg, bg };
            c += 1;
        }
        c
    }

    fn fill_row(&mut self, row: usize, bg: Color) {
        if row < self.rows {
            for c in 0..self.cols {
                self.next[row * self.cols + c] = Cell { ch: b' ', fg: FG, bg };
            }
        }
    }

    /// A writer of text into row `row` from column `col` on, as `text`.
    fn at(&mut self, row: usize, col: usize, fg: Color, bg: Color) -> Row<'_> {
        Row { d: self, row, col, fg, bg }
    }

    fn compose(&mut self, h: &Host) {
        self.next.fill(BLANK);
        let hz = h.info.tsc_hz.max(1);
        let up = crate::host::ticks::now().wrapping_sub(h.info.epoch_ticks) / hz;
        // Title bar.
        self.fill_row(0, BAR_BG);
        self.text(0, 1, "l4h", BAR_FG, BAR_BG);
        let utc = (h.info.epoch_ns != 0).then(|| Utc(h.info.epoch_ns / 1_000_000_000 + up));
        let right = |w: &mut dyn Write| match &utc {
            Some(t) => write!(w, "{}   up {}", t, Duration(up)),
            None => write!(w, "up {}", Duration(up)),
        };
        let mut width = Width(0);
        let _ = right(&mut width);
        let col = self.cols.saturating_sub(width.0 + 1);
        let _ = right(&mut self.at(0, col, BAR_FG, BAR_BG));

        let status = |id| h.vmmgr.as_ref().and_then(|v| v.guest(id));
        let guests = (0..crate::MAX_GUESTS).filter_map(status).count();
        let running = (0..crate::MAX_GUESTS).filter_map(status).filter(|g| g.state as u32 == l4h_abi::VM_RUNNING + 1).count();
        let total = h.total_bytes >> 20;
        let free = h.alloc.free_bytes() >> 20;
        let mut r = 2;
        self.text(r, 1, "Host", HEAD, BG);
        r += 1;
        let _ = write!(
            self.at(r, 3, FG, BG),
            "{} cores   memory {} of {} MiB in use ({} MiB free)   {} VMs, {} running",
            h.info.cores, total - free.min(total), total, free, guests, running
        );
        r += 1;
        self.bar(r, 3, (total - free.min(total)) as u64, total as u64);
        r += 2;

        // VMs.
        self.text(r, 1, "Virtual machines", HEAD, BG);
        r += 1;
        let _ = write!(
            self.at(r, 3, DIM, BG),
            "{:>3}  {:<16} {:<8} {:>5} {:>8} {:>6} {:>5}  {}",
            "ID", "NAME", "STATE", "VCPUS", "MEMORY", "CPU%", "CAP%", "CORES"
        );
        r += 1;
        for (n, (id, g)) in (0..crate::MAX_GUESTS).filter_map(|id| Some((id, status(id)?))).enumerate() {
            if r + 8 >= self.rows {
                let _ = write!(self.at(r, 3, DIM, BG), "... and {} more", guests - n);
                r += 1;
                break;
            }
            let (state, color) = match g.state.wrapping_sub(1) as u32 {
                l4h_abi::VM_RUNNING => ("running", GREEN),
                l4h_abi::VM_STOPPED => ("stopped", RED),
                _ => ("created", YELLOW),
            };
            let cpu = g.cpu as u64;
            let mut w = self.at(r, 3, FG, BG);
            let _ = write!(w, "{:>3}  {:<16} ", id, first_chars(crate::monitor::name(&g), 16));
            w.fg = color;
            let _ = write!(w, "{:<8}", state);
            w.fg = FG;
            let _ = write!(w, " {:>5} {:>6}M {:>5}.{} ", g.vcpus, g.ram_mb, cpu / 10, cpu % 10);
            let _ = if g.cap_pct == 0 { write!(w, "{:>5}  ", "-") } else { write!(w, "{:>5}  ", g.cap_pct) };
            let shown = (g.vcpus as usize).min(l4h_host::vmmgr::STATUS_CORES);
            for (i, c) in g.cores[..shown].iter().enumerate() {
                let _ = write!(w, "{}{}", if i == 0 { "" } else { "," }, c);
            }
            let more = if g.vcpus as usize > shown { " ..." } else { "" };
            let _ = write!(w, "{}{}", more, if g.dom0 != 0 { "   dom0" } else { "" });
            r += 1;
        }
        r += 1;

        // Disks.
        self.text(r, 1, "Disks", HEAD, BG);
        r += 1;
        if h.disks.is_empty() {
            self.text(r, 3, "none", DIM, BG);
            r += 1;
        }
        for (i, d) in h.disks.iter().enumerate() {
            if r + 4 >= self.rows {
                break;
            }
            let c = &h.ctrls[d.ctrl];
            let owner = c.owner(i);
            // Long enough for "virtio-scsi 255:<56-bit LUN>".
            let mut kind = ArrayString::<40>::new();
            let _ = if c.kind == crate::host::blk::BLKD_VIRTIO_SCSI {
                write!(kind, "{} {}:{}", c.kind_name(), d.address & 0xff, d.address >> 8)
            } else {
                kind.write_str(c.kind_name())
            };
            let mut w = self.at(r, 3, if owner.is_some() { FG } else { DIM }, BG);
            let _ = write!(w, "disk {:<2} pci {:02x}:{:02x}.{}  {:<15}  ", i, c.pci.bus, c.pci.dev, c.pci.func, kind.as_str());
            let _ = match owner {
                Some(o) => write!(w, "vm {}{}", o, if d.read_only { ", read-only" } else { "" }),
                None => w.write_str("free"),
            };
            r += 1;
        }
        r += 1;

        // Network: switches with their uplink and ports.
        self.text(r, 1, "Network", HEAD, BG);
        r += 1;
        for sw in 0..h.netd.switches {
            if r + 2 >= self.rows {
                break;
            }
            let mut uplink = ArrayString::<32>::new();
            let _ = match h.netd.nics.iter().position(|n| n.switch == Some(sw)) {
                Some(n) => write!(uplink, "uplink nic {}", n),
                None => uplink.write_str("internal"),
            };
            let mut w = self.at(r, 3, FG, BG);
            let _ = write!(w, "switch {:<2} {:<12} ", sw, uplink.as_str());
            let mut ports = 0;
            for (p, i) in h.netd.ports.iter().enumerate() {
                let Some(i) = i.as_ref().filter(|i| i.switch == sw) else { continue };
                let (rx, tx, _) = h.netd.port_stats(p).unwrap_or_default();
                let _ = write!(w, "{}vm {} ({}/{})", if ports == 0 { "" } else { "  " }, i.vm, rx, tx);
                ports += 1;
            }
            if ports == 0 {
                let _ = w.write_str("no ports");
            }
            r += 1;
        }

        // Footer.
        let last = self.rows - 1;
        self.fill_row(last, BAR_BG);
        self.text(last, 1, "Read-only. Manage VMs from dom0 (l4hctl) or the serial monitor.  Port counters: rx/tx frames.", BAR_FG, BAR_BG);
    }

    /// A usage bar of `used` out of `total`.
    fn bar(&mut self, row: usize, col: usize, used: u64, total: u64) {
        let width = (self.cols.saturating_sub(col + 2)).min(60);
        let filled = if total == 0 { 0 } else { (used * width as u64 / total) as usize };
        for i in 0..width {
            let bg = if i < filled { GREEN } else { Color::Empty };
            if row < self.rows && col + i < self.cols {
                self.next[row * self.cols + col + i] = Cell { ch: b' ', fg: FG, bg };
            }
        }
    }

    /// Draw the cells that changed.
    fn flush(&mut self) {
        for i in 0..self.next.len() {
            let c = self.next[i];
            if c != self.shown[i] {
                self.draw(i % self.cols, i / self.cols, c);
                self.shown[i] = c;
            }
        }
    }

    fn draw(&mut self, col: usize, row: usize, c: Cell) {
        let glyph = &font::GLYPHS[(c.ch - font::FIRST) as usize];
        let (x0, y0) = (col * 8 * self.sx, row * 8 * self.sy);
        for (gy, bits) in glyph.iter().enumerate() {
            for dy in 0..self.sy {
                let y = y0 + gy * self.sy + dy;
                for gx in 0..8 {
                    let rgb = if bits & (1 << gx) != 0 { c.fg.rgb() } else { c.bg.rgb() };
                    for dx in 0..self.sx {
                        self.put(x0 + gx * self.sx + dx, y, rgb);
                    }
                }
            }
        }
    }
}

/// Writes text into the cells of a row, from a column on, as `text`: text
/// past the end of the row is dropped.
struct Row<'a> {
    d: &'a mut Dashboard,
    row: usize,
    col: usize,
    fg: Color,
    bg: Color,
}

impl Write for Row<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.col = self.d.text(self.row, self.col, s, self.fg, self.bg);
        Ok(())
    }
}

/// Counts the bytes written: the width of right-aligned text.
struct Width(usize);

impl Write for Width {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0 += s.len();
        Ok(())
    }
}

/// The first `n` characters of `s`.
fn first_chars(s: &str, n: usize) -> &str {
    &s[..s.char_indices().nth(n).map_or(s.len(), |(i, _)| i)]
}

/// Seconds as "3d 04:05:06" or "04:05:06".
struct Duration(u64);

impl Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = self.0;
        let (d, h, m, sec) = (s / 86400, s / 3600 % 24, s / 60 % 60, s % 60);
        if d > 0 { write!(f, "{}d {:02}:{:02}:{:02}", d, h, m, sec) } else { write!(f, "{:02}:{:02}:{:02}", h, m, sec) }
    }
}

/// Seconds since the epoch as "YYYY-MM-DD HH:MM:SS UTC".
struct Utc(u64);

impl Display for Utc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let t = self.0;
        let (days, s) = ((t / 86400) as i64, t % 86400);
        // Civil from days (proleptic Gregorian).
        let z = days + 719468;
        let era = z.div_euclid(146097);
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
        write!(f, "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, m, d, s / 3600, s / 60 % 60, s % 60)
    }
}
