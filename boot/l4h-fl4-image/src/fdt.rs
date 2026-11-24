//! Minimal FDT parser for the FL4 ARM64 `Image` boot stub: extracts
//! `/memory` RAM ranges, `memreserve` entries, `/chosen` `bootargs`, and
//! `/chosen` `linux,initrd-{start,end}`.

const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

pub const MAX_RANGES: usize = 32;
pub const CMDLINE_LEN: usize = 256;

#[derive(Clone, Copy)]
pub struct ParsedFdt {
    pub total_size: u64,
    pub ram: [(u64, u64); MAX_RANGES],
    pub n_ram: usize,
    pub reserved: [(u64, u64); MAX_RANGES],
    pub n_reserved: usize,
    pub initrd: (u64, u64),
    pub cmdline: [u8; CMDLINE_LEN],
}

impl ParsedFdt {
    const fn empty() -> Self {
        Self {
            total_size: 0,
            ram: [(0, 0); MAX_RANGES],
            n_ram: 0,
            reserved: [(0, 0); MAX_RANGES],
            n_reserved: 0,
            initrd: (0, 0),
            cmdline: [0; CMDLINE_LEN],
        }
    }
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    Some(u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn read_cells(b: &[u8], off: usize, cells: u32) -> Option<u64> {
    match cells {
        1 => Some(be32(b, off)? as u64),
        2 => be64(b, off),
        _ => None,
    }
}

fn cstr_at(strings: &[u8], off: usize) -> Option<&[u8]> {
    let rest = strings.get(off..)?;
    let end = rest.iter().position(|&c| c == 0)?;
    Some(&rest[..end])
}

fn is_memory_name(name: &[u8]) -> bool {
    name == b"memory" || name.starts_with(b"memory@")
}

pub fn parse(dtb: &[u8]) -> Option<ParsedFdt> {
    if dtb.len() < 40 {
        return None;
    }
    let hdr: &[u8; 40] = dtb[..40].try_into().ok()?;
    let fdt = fl4_bootinfo::fdt_header(hdr)?;
    if (fdt.total as usize) > dtb.len() {
        return None;
    }

    let mut out = ParsedFdt::empty();
    out.total_size = fdt.total;

    // Parse memreserve block: pairs of big-endian (addr, size) ending with (0, 0).
    let mut rsv = fdt.rsv as usize;
    while rsv + 16 <= fdt.total as usize {
        let addr = be64(dtb, rsv)?;
        let size = be64(dtb, rsv + 8)?;
        rsv += 16;
        if addr == 0 && size == 0 {
            break;
        }
        if size > 0 && out.n_reserved < MAX_RANGES {
            out.reserved[out.n_reserved] = (addr, size);
            out.n_reserved += 1;
        }
    }

    let structs = dtb.get(fdt.structs.0 as usize..fdt.structs.1 as usize)?;
    let strings = dtb.get(fdt.strings.0 as usize..fdt.strings.1 as usize)?;

    let mut off = 0usize;
    let mut depth = 0usize;
    let mut root_ac = 2u32;
    let mut root_sc = 2u32;

    // Depth-1 node tracking for /memory and /chosen.
    let mut in_chosen = false;
    let mut is_mem_node = false;
    let mut mem_reg: Option<&[u8]> = None;

    while let Some(tok) = be32(structs, off) {
        off += 4;
        match tok {
            FDT_BEGIN_NODE => {
                let Some(rest) = structs.get(off..) else { break };
                let Some(nul) = rest.iter().position(|&b| b == 0) else { break };
                let name = &rest[..nul];
                off = off.saturating_add((nul + 4) & !3);
                if depth == 1 {
                    in_chosen = name == b"chosen";
                    is_mem_node = is_memory_name(name);
                    mem_reg = None;
                }
                depth += 1;
            }
            FDT_END_NODE => {
                if depth == 0 {
                    break;
                }
                if depth == 2 && is_mem_node {
                    if let Some(reg) = mem_reg {
                        let stride = (root_ac + root_sc) as usize * 4;
                        let mut ro = 0usize;
                        while stride > 0 && ro + stride <= reg.len() {
                            if let (Some(base), Some(len)) = (
                                read_cells(reg, ro, root_ac),
                                read_cells(reg, ro + (root_ac as usize) * 4, root_sc),
                            ) {
                                if len > 0 && out.n_ram < MAX_RANGES {
                                    out.ram[out.n_ram] = (base, len);
                                    out.n_ram += 1;
                                }
                            }
                            ro += stride;
                        }
                    }
                    is_mem_node = false;
                    mem_reg = None;
                }
                if depth == 2 {
                    in_chosen = false;
                }
                depth -= 1;
            }
            FDT_PROP => {
                let Some(len) = be32(structs, off).map(|v| v as usize) else { break };
                let Some(nameoff) = be32(structs, off + 4).map(|v| v as usize) else { break };
                off += 8;
                let Some(val) = structs.get(off..off.saturating_add(len)) else { break };
                off = off.saturating_add((len + 3) & !3);
                let Some(name) = cstr_at(strings, nameoff) else { continue };

                if depth == 1 {
                    match name {
                        b"#address-cells" => {
                            if let Some(v) = be32(val, 0) {
                                root_ac = v;
                            }
                        }
                        b"#size-cells" => {
                            if let Some(v) = be32(val, 0) {
                                root_sc = v;
                            }
                        }
                        _ => {}
                    }
                } else if depth == 2 {
                    if in_chosen {
                        match name {
                            b"bootargs" => {
                                let n = val
                                    .iter()
                                    .position(|&b| b == 0)
                                    .unwrap_or(val.len())
                                    .min(CMDLINE_LEN - 1);
                                out.cmdline[..n].copy_from_slice(&val[..n]);
                                out.cmdline[n] = 0;
                            }
                            b"linux,initrd-start" => {
                                if let Some(v) = if val.len() == 8 { be64(val, 0) } else { be32(val, 0).map(u64::from) } {
                                    out.initrd.0 = v;
                                }
                            }
                            b"linux,initrd-end" => {
                                if let Some(v) = if val.len() == 8 { be64(val, 0) } else { be32(val, 0).map(u64::from) } {
                                    out.initrd.1 = v;
                                }
                            }
                            _ => {}
                        }
                    } else {
                        match name {
                            b"device_type" => {
                                let s = val.split(|&b| b == 0).next().unwrap_or(b"");
                                if s == b"memory" {
                                    is_mem_node = true;
                                }
                            }
                            b"reg" => mem_reg = Some(val),
                            _ => {}
                        }
                    }
                }
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => break,
        }
    }

    Some(out)
}
