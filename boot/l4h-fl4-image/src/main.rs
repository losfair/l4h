//! Position-independent ARM64 Linux `Image` boot stub for FL4.
//!
//! Compiled once into a reusable flat stub (`l4h-fl4-image.bin`).
//! `tools/pack-fl4-image.py` appends the `FL4IMG01` trailer header at
//! `_stub_end` followed by raw `kernel.elf` and `root-dom0.elf`, and patches
//! the ARM64 `Image` header's `image_size` (offset `0x10`) to
//! `unpack_off + unpack_len` (2 MiB aligned).
#![no_std]
#![no_main]

mod fdt;

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;

use fl4_bootinfo::elf::{self, Layout};
use fl4_bootinfo::{BootInfo, KERNEL_VBASE, MAGIC, MAX_MMAP, MemRegion, RootTask, USER_END, VERSION, mem};

const PAGE: u64 = 4096;
const MB2: u64 = 2 << 20;
const TABLE_PAGES: u64 = 10;
const TRAILER_MAGIC: [u8; 8] = *b"FL4IMG01";
/// WB cacheable RAM (`1`) plus `ZEROED` hint (`2`) for untouched RAM above
/// `touched_hi`. Satisfies `cacheable != 0` on upstream FL4 and activates
/// zeroed-RAM skipping where supported.
const CACHEABLE_WB: u32 = 1;
const CACHEABLE_WB_ZEROED: u32 = 1 | 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct Trailer {
    magic: [u8; 8],
    kernel_off: u64,
    kernel_len: u64,
    root_off: u64,
    root_len: u64,
    unpack_off: u64,
    unpack_len: u64,
}

global_asm!(
    // 64-byte ARM64 Linux Image header (Documentation/arch/arm64/booting.rst).
    // Offset 0x10 (image_size) is patched by tools/pack-fl4-image.py.
    ".section .head, \"ax\"",
    ".global _head",
    "_head:",
    "b _entry",                         // 0x00: code0
    ".long 0",                          // 0x04: code1
    ".quad 0",                          // 0x08: text_offset = 0
    ".quad 0",                          // 0x10: image_size (patched by pack-fl4-image.py)
    ".quad 0x2",                        // 0x18: flags (LE, 4K pages)
    ".quad 0",                          // 0x20: res2
    ".quad 0",                          // 0x28: res3
    ".quad 0",                          // 0x30: res4
    ".long 0x644d5241",                 // 0x38: magic = \"ARM\\x64\"
    ".long 0",                          // 0x3c: res5

    ".section .text.entry, \"ax\"",
    ".global _entry",
    "_entry:",
    "msr daifset, #0xf",
    "mov x19, x0",                      // save dtb_pa
    "adrp x20, _image_start",
    "add x20, x20, :lo12:_image_start", // x20 = runtime image_base_pa

    // Zero .bss before running Rust.
    "adrp x1, __bss_start",
    "add x1, x1, :lo12:__bss_start",
    "adrp x2, __bss_end",
    "add x2, x2, :lo12:__bss_end",
    "1:",
    "cmp x1, x2",
    "b.hs 2f",
    "str xzr, [x1], #8",
    "b 1b",
    "2:",

    // Apply R_AARCH64_RELATIVE (1027) relocations in .rela.dyn.
    "adrp x1, __rela_start",
    "add x1, x1, :lo12:__rela_start",
    "adrp x2, __rela_end",
    "add x2, x2, :lo12:__rela_end",
    "mov x5, #1027",
    "3:",
    "cmp x1, x2",
    "b.hs 4f",
    "ldr x3, [x1, #0]",                 // r_offset
    "ldr x4, [x1, #8]",                 // r_info
    "ldr x6, [x1, #16]",                // r_addend
    "add x1, x1, #24",
    "cmp x4, x5",
    "b.ne 3b",
    "add x3, x3, x20",
    "add x6, x6, x20",
    "str x6, [x3]",
    "b 3b",
    "4:",

    "adrp x1, __stack_top",
    "add x1, x1, :lo12:__stack_top",
    "mov sp, x1",

    "mov x0, x20",
    "mov x1, x19",
    "bl rust_entry",
    "5:",
    "wfi",
    "b 5b",

    // 64 KiB PROGBITS boot stack at the end of the flat stub so objcopy -O
    // binary emits exact page-aligned bytes right up to _stub_end.
    ".section .stack, \"aw\", @progbits",
    ".balign 4096",
    ".global __stack_bottom",
    ".global __stack_top",
    "__stack_bottom:",
    ".space 65536",
    "__stack_top:",
);

unsafe extern "C" {
    static _stub_end: u8;
}

fn halt() -> ! {
    loop {
        unsafe { asm!("msr daifset, #0xf", "wfi", options(nomem, nostack)) };
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    halt()
}

fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

fn align_down(v: u64, a: u64) -> u64 {
    v & !(a - 1)
}

/// Build 2 MiB-block boot page tables matching `fl4-efi`: identity mapping
/// `[pa, pa + len)` in `ttbr0` and `[KERNEL_VBASE, KERNEL_VBASE + len)` in
/// `ttbr1`.
fn build_tables(tables: u64, pa: u64, len: u64) -> (u64, u64) {
    unsafe { core::ptr::write_bytes(tables as *mut u8, 0, (TABLE_PAGES * PAGE) as usize) };
    let mut used = 2u64;
    let mut alloc = || -> u64 {
        if used == TABLE_PAGES {
            halt();
        }
        let t = tables + used * PAGE;
        used += 1;
        t
    };
    let slot = |table: u64, va: u64, shift: u64| (table + ((va >> shift) & 511) * 8) as *mut u64;
    let block = |p: u64| p | 1 | (3 << 8) | (1 << 10);
    let mut next = |table: u64, va: u64, shift: u64| -> u64 {
        let e = slot(table, va, shift);
        let v = unsafe { e.read_volatile() };
        if v & 1 != 0 {
            return v & 0x0000_ffff_ffff_f000;
        }
        let t = alloc();
        unsafe { e.write_volatile(t | 3) };
        t
    };
    for (root, va) in [(tables, pa), (tables + PAGE, KERNEL_VBASE)] {
        let mut off = 0u64;
        while off < len {
            let v = va + off;
            let l1 = next(root, v, 39);
            let l2 = next(l1, v, 30);
            unsafe { slot(l2, v, 21).write_volatile(block(pa + off)) };
            off += MB2;
        }
    }
    (tables, tables + PAGE)
}

fn push_region(mmap: &mut [MemRegion; MAX_MMAP], n: &mut usize, base: u64, len: u64, kind: u32, cacheable: u32) {
    if len == 0 || *n >= MAX_MMAP {
        return;
    }
    mmap[*n] = MemRegion { base, len, kind, cacheable };
    *n += 1;
}

/// Emit `[start, end)` as `mem::FREE`, splitting at `touched_hi` so memory
/// above `touched_hi` carries `CACHEABLE_WB_ZEROED`.
fn emit_free(mmap: &mut [MemRegion; MAX_MMAP], n: &mut usize, start: u64, end: u64, touched_hi: u64) {
    if start >= end {
        return;
    }
    if start < touched_hi {
        let mid = end.min(touched_hi);
        push_region(mmap, n, start, mid - start, mem::FREE, CACHEABLE_WB);
    }
    if end > touched_hi {
        let lo = start.max(touched_hi);
        push_region(mmap, n, lo, end - lo, mem::FREE, CACHEABLE_WB_ZEROED);
    }
}

fn populate_mmap(bi: &mut BootInfo, parsed: &fdt::ParsedFdt, touched_hi: u64) {
    let mut rsv = [(0u64, 0u64); fdt::MAX_RANGES];
    let mut n_rsv = 0usize;
    for &(base, len) in &parsed.reserved[..parsed.n_reserved] {
        let s = align_down(base, PAGE);
        let e = align_up(base.saturating_add(len), PAGE);
        if e > s {
            rsv[n_rsv] = (s, e);
            n_rsv += 1;
        }
    }
    for i in 1..n_rsv {
        let mut j = i;
        while j > 0 && rsv[j].0 < rsv[j - 1].0 {
            rsv.swap(j, j - 1);
            j -= 1;
        }
    }

    let mut n = 0usize;
    for &(base, len) in &parsed.ram[..parsed.n_ram] {
        let r_start = align_up(base, PAGE);
        let r_end = align_down(base.saturating_add(len), PAGE);
        if r_end <= r_start {
            continue;
        }
        let mut cur = r_start;
        for &(rs, re) in &rsv[..n_rsv] {
            if re <= cur {
                continue;
            }
            if rs >= r_end {
                break;
            }
            let ov_s = rs.max(cur);
            let ov_e = re.min(r_end);
            if ov_s > cur {
                emit_free(&mut bi.mmap, &mut n, cur, ov_s, touched_hi);
            }
            if ov_e > ov_s {
                push_region(&mut bi.mmap, &mut n, ov_s, ov_e - ov_s, mem::FIRMWARE, CACHEABLE_WB);
            }
            cur = ov_e;
        }
        if cur < r_end {
            emit_free(&mut bi.mmap, &mut n, cur, r_end, touched_hi);
        }
    }

    for i in 1..n {
        let mut j = i;
        while j > 0 && bi.mmap[j].base < bi.mmap[j - 1].base {
            bi.mmap.swap(j, j - 1);
            j -= 1;
        }
    }
    bi.n_mmap = n as u64;
}

/// Clean D-cache to PoC over `[start, end)`, disable MMU/caches at the current
/// exception level (EL2 or EL1), clean once more, invalidate I-cache, and
/// branch to `entry` with `x0 = arg`.
unsafe fn enter(entry: u64, arg: u64, clean_start: u64, clean_end: u64) -> ! {
    unsafe {
        asm!(
            "msr daifset, #0xf",
            "mrs x14, ctr_el0",
            "ubfx x14, x14, #16, #4",
            "mov x15, #4",
            "lsl x14, x15, x14",         // x14 = dcache line size
            "sub x15, x14, #1",
            "bic x12, x12, x15",         // align clean_start down

            // Pass 1: clean [clean_start, clean_end) with current MMU/cache state.
            "mov x9, x12",
            "1:",
            "cmp x9, x13",
            "b.hs 2f",
            "dc cvac, x9",
            "add x9, x9, x14",
            "b 1b",
            "2:",
            "dsb sy",

            // Disable MMU, D-cache, I-cache at CurrentEL (EL2 or EL1).
            "mov x15, #5",
            "mrs x9, CurrentEL",
            "lsr x9, x9, #2",
            "cmp x9, #2",
            "b.eq 3f",
            "mrs x9, sctlr_el1",
            "tst x9, x15",
            "b.eq 4f",
            "bic x9, x9, #1",
            "bic x9, x9, #(1 << 2)",
            "bic x9, x9, #(1 << 12)",
            "msr sctlr_el1, x9",
            "dsb sy",
            "isb",
            "b 4f",
            "3:",
            "mrs x9, sctlr_el2",
            "tst x9, x15",
            "b.eq 4f",
            "bic x9, x9, #1",
            "bic x9, x9, #(1 << 2)",
            "bic x9, x9, #(1 << 12)",
            "msr sctlr_el2, x9",
            "dsb sy",
            "isb",
            "4:",

            // Pass 2: clean once more with MMU off, then invalidate I-cache.
            "mov x9, x12",
            "5:",
            "cmp x9, x13",
            "b.hs 6f",
            "dc cvac, x9",
            "add x9, x9, x14",
            "b 5b",
            "6:",
            "dsb sy",
            "ic iallu",
            "dsb sy",
            "isb",

            "mov x0, x11",
            "br x10",
            in("x10") entry,
            in("x11") arg,
            in("x12") clean_start,
            in("x13") clean_end,
            options(noreturn),
        );
    }
}

#[unsafe(no_mangle)]
extern "C" fn rust_entry(image_base_pa: u64, dtb_pa: u64) -> ! {
    // Read the FL4IMG01 trailer appended right at _stub_end.
    let trailer = unsafe { &*((&raw const _stub_end) as *const Trailer) };
    if trailer.magic != TRAILER_MAGIC {
        halt();
    }

    let image_size = trailer.unpack_off.checked_add(trailer.unpack_len).unwrap_or_else(|| halt());
    let unpack_start_pa = align_up(image_base_pa.checked_add(trailer.unpack_off).unwrap_or_else(|| halt()), MB2);
    let image_end_pa = image_base_pa.checked_add(image_size).unwrap_or_else(|| halt());

    // Validate and parse the FDT passed in x0.
    if dtb_pa == 0 {
        halt();
    }
    let hdr_bytes = unsafe { core::slice::from_raw_parts(dtb_pa as *const u8, 40) };
    let hdr: &[u8; 40] = hdr_bytes.try_into().unwrap_or_else(|_| halt());
    let fdt_hdr = fl4_bootinfo::fdt_header(hdr).unwrap_or_else(|| halt());
    let dtb_slice = unsafe { core::slice::from_raw_parts(dtb_pa as *const u8, fdt_hdr.total as usize) };
    let parsed = fdt::parse(dtb_slice).unwrap_or_else(|| halt());

    // Appended FL4 kernel and l4h-root ELF slices.
    let kernel_pa = image_base_pa.checked_add(trailer.kernel_off).unwrap_or_else(|| halt());
    let kernel_elf = unsafe { core::slice::from_raw_parts(kernel_pa as *const u8, trailer.kernel_len as usize) };

    let root_pa_src = image_base_pa.checked_add(trailer.root_off).unwrap_or_else(|| halt());
    let root_elf = unsafe { core::slice::from_raw_parts(root_pa_src as *const u8, trailer.root_len as usize) };

    let kl = match elf::check(kernel_elf, KERNEL_VBASE, u64::MAX) {
        Some(l) => Layout { v_start: KERNEL_VBASE, ..l },
        None => halt(),
    };
    let rl = elf::check(root_elf, 0, USER_END - fl4_bootinfo::ROOT_TAIL_MIN).unwrap_or_else(|| halt());

    // Layout inside the reserved unpack arena:
    //   [unpack_start_pa .. unpack_start_pa + region_len): kernel_region (2 MiB aligned)
    //   [root_pa .. root_pa + rl.size()): root task (4 KiB aligned)
    let tables_off = kl.size();
    let bi_off = tables_off + TABLE_PAGES * PAGE;
    let bi_len = align_up(core::mem::size_of::<BootInfo>() as u64, PAGE);
    let region_len = align_up(bi_off + bi_len, MB2);
    let region_pa = unpack_start_pa;
    let root_pa = align_up(region_pa + region_len, PAGE);
    let unpack_end_pa = align_up(root_pa + rl.size(), PAGE);
    if unpack_end_pa > image_end_pa {
        halt();
    }

    // Load kernel and root task segments.
    let k_dst = unsafe { core::slice::from_raw_parts_mut(region_pa as *mut u8, kl.size() as usize) };
    elf::load(kernel_elf, &kl, k_dst);

    let (ttbr0, ttbr1) = build_tables(region_pa + tables_off, region_pa, region_len);

    let r_dst = unsafe { core::slice::from_raw_parts_mut(root_pa as *mut u8, rl.size() as usize) };
    elf::load(root_elf, &rl, r_dst);

    // Populate BootInfo.
    let bi_ptr = (region_pa + bi_off) as *mut BootInfo;
    unsafe { core::ptr::write_bytes(bi_ptr as *mut u8, 0, core::mem::size_of::<BootInfo>()) };
    let bi = unsafe { &mut *bi_ptr };
    bi.magic = MAGIC;
    bi.version = VERSION;
    bi.region_paddr = region_pa;
    bi.region_len = region_len;
    bi.ttbr0 = ttbr0;
    bi.ttbr1 = ttbr1;
    bi.rsdp = 0;
    bi.dtb = dtb_pa;
    bi.dtb_len = parsed.total_size;
    bi.root = RootTask {
        p_start: root_pa,
        p_end: root_pa + rl.size(),
        v_start: rl.v_start,
        entry: rl.entry,
    };
    bi.n_modules = 0;
    bi.cmdline = parsed.cmdline;

    // High-water mark of memory touched by the VMM / loader.
    let mut hi = image_base_pa.saturating_add(image_size);
    hi = hi.max(dtb_pa.saturating_add(parsed.total_size));
    if parsed.initrd.1 > parsed.initrd.0 {
        hi = hi.max(parsed.initrd.1);
    }
    for &(rbase, rlen) in &parsed.reserved[..parsed.n_reserved] {
        hi = hi.max(rbase.saturating_add(rlen));
    }
    let touched_hi = align_up(hi, MB2);

    populate_mmap(bi, &parsed, touched_hi);

    let entry_pa = region_pa + (kl.entry - KERNEL_VBASE);
    unsafe { enter(entry_pa, bi_off, unpack_start_pa, unpack_end_pa) }
}
