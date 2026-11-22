//! Decoding the instructions a guest accesses device memory with, and the
//! few others l4h-hvm emulates (DESIGN.md §5.11): a VM exit for an access to
//! MMIO (an EPT violation, or AMD-V's nested page fault) says where, but not
//! how, and on AMD-V without decode assists neither does one for a control
//! or debug register.
//!
//! Covered: MOV (88-8B, C6, C7, A0-A3), MOVZX and MOVSX (0F B6/B7/BE/BF),
//! MOVS and STOS (A4/A5, AA/AB, with REP), CMP, TEST, OR and AND with a
//! memory operand (38-3B, 84/85, 08-0B, 20-23, 80/81/83 and F6/F7 /0),
//! XCHG (86/87), and MOV to and from CR and DR, CLTS and LMSW (0F 20-23,
//! 0F 06, 0F 01 /6), with the prefixes that apply to them.  Anything else,
//! and anything longer than an instruction can be (15 bytes), is refused:
//! the guest then gets #UD.  Free of seL4: tests/hvm.rs runs it on the
//! build host.

/// The guest's execution mode, which sets default operand and address
/// sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Real mode, or a 16-bit code segment.
    Bits16,
    /// A 32-bit code segment.
    Bits32,
    /// 64-bit mode (IA-32e with CS.L).
    Bits64,
}

/// A general-purpose register operand: x86's number (0 RAX, 1 RCX, 2 RDX,
/// 3 RBX, 4 RSP, 5 RBP, 6 RSI, 7 RDI, 8-15 R8-R15), and whether it is
/// AH, CH, DH or BH (bits 8-15 of registers 0-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reg {
    pub num: u8,
    pub high8: bool,
}

impl Reg {
    const fn new(num: u8) -> Reg {
        Reg { num, high8: false }
    }

    /// Register `num` of an 8-bit operand: without a REX prefix, 4-7 are
    /// AH, CH, DH and BH.
    const fn byte(num: u8, rex: bool) -> Reg {
        if !rex && num >= 4 && num < 8 { Reg { num: num - 4, high8: true } } else { Reg::new(num) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    Reg(Reg),
    Imm(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ext {
    None,
    Zero,
    Sign,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AluOp {
    Cmp,
    Test,
    Or,
    And,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rep {
    None,
    /// F3: REP or REPE (MOVS, STOS: REP).
    Repe,
    /// F2: REPNE, which MOVS and STOS treat as REP.
    Repne,
}

/// Segment registers, in x86's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seg {
    Es = 0,
    Cs = 1,
    Ss = 2,
    Ds = 3,
    Fs = 4,
    Gs = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// reg <- [mem], `size` bytes of memory, extended to `dst` bytes.
    Load { reg: Reg, dst: u8, ext: Ext },
    /// [mem] <- src.
    Store { src: Operand },
    /// An ALU operation with a memory operand: `mem` op `other` when
    /// `mem_first`, else `other` op `mem`; OR and AND write the first
    /// operand, CMP and TEST only the flags.
    Alu { op: AluOp, mem_first: bool, other: Operand },
    /// Exchange [mem] and reg.
    Xchg { reg: Reg },
    /// [ES:rDI] <- [seg:rSI].
    Movs,
    /// [ES:rDI] <- rAX.
    Stos,
    /// MOV to (`write`) or from a control register, from or to `reg`.
    MovCr { write: bool, cr: u8, reg: u8 },
    /// MOV to or from a debug register.
    MovDr { write: bool, dr: u8, reg: u8 },
    Clts,
    /// LMSW from a register, or (`mem`) from memory.
    Lmsw { src: Option<u8> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    /// Bytes, prefixes included.
    pub len: u8,
    pub kind: Kind,
    /// Bytes of the memory access (1, 2, 4 or 8).
    pub size: u8,
    /// Bytes of an address (2, 4 or 8): rSI, rDI and rCX for MOVS and STOS.
    pub addr: u8,
    pub rep: Rep,
    /// A segment override (MOVS's source; ES is always the destination).
    pub seg: Option<Seg>,
    /// ModRM's memory operand, if there is one.
    pub modrm_mem: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Fewer bytes than the instruction takes.
    Truncated,
    /// More than 15 bytes.
    TooLong,
    /// An instruction we do not emulate.
    Unsupported,
}

pub const MAX_LEN: usize = 15;

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Result<u8, Error> {
        if self.at >= MAX_LEN {
            return Err(Error::TooLong);
        }
        let b = *self.bytes.get(self.at).ok_or(Error::Truncated)?;
        self.at += 1;
        Ok(b)
    }

    fn imm(&mut self, n: u8) -> Result<u64, Error> {
        let mut v = 0u64;
        for i in 0..n {
            v |= (self.byte()? as u64) << (8 * i);
        }
        Ok(v)
    }

    fn skip(&mut self, n: usize) -> Result<(), Error> {
        for _ in 0..n {
            self.byte()?;
        }
        Ok(())
    }
}

/// What a ModRM byte (and its SIB and displacement, which are skipped)
/// says: mod, reg (with REX.R) and rm (with REX.B).
struct ModRm {
    mem: bool,
    reg: u8,
    rm: u8,
}

fn modrm(c: &mut Cursor, rex: u8, addr: u8) -> Result<ModRm, Error> {
    let m = c.byte()?;
    let (md, reg, rm) = (m >> 6, (m >> 3) & 7, m & 7);
    let reg = reg | ((rex & 4) << 1);
    if md == 3 {
        return Ok(ModRm { mem: false, reg, rm: rm | ((rex & 1) << 3) });
    }
    if addr == 2 {
        // 16-bit addressing: [bp] alone is a displacement.
        match (md, rm) {
            (0, 6) => c.skip(2)?,
            (1, _) => c.skip(1)?,
            (2, _) => c.skip(2)?,
            _ => {}
        }
    } else {
        let mut base = rm;
        if rm == 4 {
            base = c.byte()? & 7;
        }
        match md {
            0 if base == 5 => c.skip(4)?,
            1 => c.skip(1)?,
            2 => c.skip(4)?,
            _ => {}
        }
    }
    Ok(ModRm { mem: true, reg, rm: rm | ((rex & 1) << 3) })
}

/// Decode the instruction at the start of `bytes` (at most 15 are read),
/// in `mode`.
pub fn decode(bytes: &[u8], mode: Mode) -> Result<Insn, Error> {
    let mut c = Cursor { bytes, at: 0 };
    let (mut opsize16, mut addrsize_ovr) = (false, false);
    let mut rep = Rep::None;
    let mut seg = None;
    let mut rex = 0u8;
    let mut op;
    loop {
        op = c.byte()?;
        match op {
            0x66 => opsize16 = true,
            0x67 => addrsize_ovr = true,
            0xf3 => rep = Rep::Repe,
            0xf2 => rep = Rep::Repne,
            0xf0 => {}
            0x26 => seg = Some(Seg::Es),
            0x2e => seg = Some(Seg::Cs),
            0x36 => seg = Some(Seg::Ss),
            0x3e => seg = Some(Seg::Ds),
            0x64 => seg = Some(Seg::Fs),
            0x65 => seg = Some(Seg::Gs),
            _ => break,
        }
        // A REX prefix counts only right before the opcode.
        rex = 0;
    }
    if mode == Mode::Bits64 && (0x40..0x50).contains(&op) {
        rex = op;
        op = c.byte()?;
        if matches!(op, 0x66 | 0x67 | 0xf2 | 0xf3 | 0xf0 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65) || (0x40..0x50).contains(&op) {
            // A prefix after REX: REX is ignored, which we do not model.
            return Err(Error::Unsupported);
        }
    }
    let has_rex = rex != 0;
    let w = rex & 8 != 0;
    // Operand size of a full-size operand, and address size.
    let osize: u8 = match mode {
        Mode::Bits64 if w => 8,
        Mode::Bits16 => if opsize16 { 4 } else { 2 },
        _ => if opsize16 { 2 } else { 4 },
    };
    let addr: u8 = match mode {
        Mode::Bits64 => if addrsize_ovr { 4 } else { 8 },
        Mode::Bits32 => if addrsize_ovr { 2 } else { 4 },
        Mode::Bits16 => if addrsize_ovr { 4 } else { 2 },
    };
    let byte_or = |b: bool| if b { 1 } else { osize };
    let insn = |kind: Kind, size: u8, m: bool, c: &Cursor| -> Result<Insn, Error> {
        Ok(Insn { len: c.at as u8, kind, size, addr, rep, seg, modrm_mem: m })
    };
    match op {
        // MOV r/m, r and MOV r, r/m.
        0x88..=0x8b => {
            let size = byte_or(op & 1 == 0);
            let m = modrm(&mut c, rex, addr)?;
            if !m.mem {
                return Err(Error::Unsupported);
            }
            let reg = if size == 1 { Reg::byte(m.reg, has_rex) } else { Reg::new(m.reg) };
            let kind = if op & 2 == 0 { Kind::Store { src: Operand::Reg(reg) } } else { Kind::Load { reg, dst: size, ext: Ext::None } };
            insn(kind, size, true, &c)
        }
        // MOV r/m, imm (the imm of a 64-bit operand is 32 bits, sign-extended).
        0xc6 | 0xc7 => {
            let size = byte_or(op == 0xc6);
            let m = modrm(&mut c, rex, addr)?;
            if !m.mem || m.reg & 7 != 0 {
                return Err(Error::Unsupported);
            }
            let imm = imm_of(&mut c, size)?;
            insn(Kind::Store { src: Operand::Imm(imm) }, size, true, &c)
        }
        // MOV AL/rAX, moffs and back: an address of the address size.
        0xa0..=0xa3 => {
            let size = byte_or(op & 1 == 0);
            c.skip(addr as usize)?;
            let reg = Reg::new(0);
            let kind = if op < 0xa2 { Kind::Load { reg, dst: size, ext: Ext::None } } else { Kind::Store { src: Operand::Reg(reg) } };
            insn(kind, size, true, &c)
        }
        0xa4 | 0xa5 => insn(Kind::Movs, byte_or(op == 0xa4), false, &c),
        0xaa | 0xab => insn(Kind::Stos, byte_or(op == 0xaa), false, &c),
        // ALU r/m, r and r, r/m: OR 08-0B, AND 20-23, CMP 38-3B.
        0x08..=0x0b | 0x20..=0x23 | 0x38..=0x3b => {
            let alu = match op & 0xf8 {
                0x08 => AluOp::Or,
                0x20 => AluOp::And,
                _ => AluOp::Cmp,
            };
            let size = byte_or(op & 1 == 0);
            let m = modrm(&mut c, rex, addr)?;
            if !m.mem {
                return Err(Error::Unsupported);
            }
            let reg = if size == 1 { Reg::byte(m.reg, has_rex) } else { Reg::new(m.reg) };
            insn(Kind::Alu { op: alu, mem_first: op & 2 == 0, other: Operand::Reg(reg) }, size, true, &c)
        }
        // TEST r/m, r.
        0x84 | 0x85 => {
            let size = byte_or(op == 0x84);
            let m = modrm(&mut c, rex, addr)?;
            if !m.mem {
                return Err(Error::Unsupported);
            }
            let reg = if size == 1 { Reg::byte(m.reg, has_rex) } else { Reg::new(m.reg) };
            insn(Kind::Alu { op: AluOp::Test, mem_first: true, other: Operand::Reg(reg) }, size, true, &c)
        }
        // XCHG r/m, r.
        0x86 | 0x87 => {
            let size = byte_or(op == 0x86);
            let m = modrm(&mut c, rex, addr)?;
            if !m.mem {
                return Err(Error::Unsupported);
            }
            let reg = if size == 1 { Reg::byte(m.reg, has_rex) } else { Reg::new(m.reg) };
            insn(Kind::Xchg { reg }, size, true, &c)
        }
        // Group 1 with an immediate: /1 OR, /4 AND, /7 CMP.
        0x80 | 0x81 | 0x83 => {
            let size = byte_or(op == 0x80);
            let m = modrm(&mut c, rex, addr)?;
            let alu = match m.reg & 7 {
                1 => AluOp::Or,
                4 => AluOp::And,
                7 => AluOp::Cmp,
                _ => return Err(Error::Unsupported),
            };
            if !m.mem {
                return Err(Error::Unsupported);
            }
            let imm = if op == 0x83 { sext(c.imm(1)?, 1) } else { imm_of(&mut c, size)? };
            insn(Kind::Alu { op: alu, mem_first: true, other: Operand::Imm(imm) }, size, true, &c)
        }
        // Group 3: /0 TEST r/m, imm.
        0xf6 | 0xf7 => {
            let size = byte_or(op == 0xf6);
            let m = modrm(&mut c, rex, addr)?;
            if !m.mem || m.reg & 7 != 0 {
                return Err(Error::Unsupported);
            }
            let imm = imm_of(&mut c, size)?;
            insn(Kind::Alu { op: AluOp::Test, mem_first: true, other: Operand::Imm(imm) }, size, true, &c)
        }
        0x0f => {
            let op2 = c.byte()?;
            match op2 {
                // MOVZX and MOVSX r, r/m8 and r/m16.
                0xb6 | 0xb7 | 0xbe | 0xbf => {
                    let size = if op2 & 1 == 0 { 1 } else { 2 };
                    let m = modrm(&mut c, rex, addr)?;
                    if !m.mem {
                        return Err(Error::Unsupported);
                    }
                    let ext = if op2 < 0xb8 { Ext::Zero } else { Ext::Sign };
                    insn(Kind::Load { reg: Reg::new(m.reg), dst: osize, ext }, size, true, &c)
                }
                // MOV to and from CR and DR: always register operands
                // (mod is ignored), 64-bit in 64-bit mode.
                0x20..=0x23 => {
                    let b = c.byte()?;
                    let (reg, ctl) = ((b & 7) | ((rex & 1) << 3), ((b >> 3) & 7) | ((rex & 4) << 1));
                    let write = op2 & 2 != 0;
                    let size = if mode == Mode::Bits64 { 8 } else { 4 };
                    let kind = if op2 & 1 == 0 {
                        Kind::MovCr { write, cr: ctl, reg }
                    } else {
                        Kind::MovDr { write, dr: ctl, reg }
                    };
                    insn(kind, size, false, &c)
                }
                0x06 => insn(Kind::Clts, 0, false, &c),
                0x01 => {
                    let m = modrm(&mut c, rex, addr)?;
                    if m.reg & 7 != 6 {
                        return Err(Error::Unsupported);
                    }
                    let src = if m.mem { None } else { Some(m.rm) };
                    insn(Kind::Lmsw { src }, 2, m.mem, &c)
                }
                _ => Err(Error::Unsupported),
            }
        }
        _ => Err(Error::Unsupported),
    }
}

/// An immediate of an operand of `size` bytes: 4 bytes, sign-extended,
/// for a 64-bit one.
fn imm_of(c: &mut Cursor, size: u8) -> Result<u64, Error> {
    if size == 8 { Ok(sext(c.imm(4)?, 4)) } else { c.imm(size) }
}

/// `v`, of `size` bytes, sign-extended to 64 bits.
pub const fn sext(v: u64, size: u8) -> u64 {
    let shift = 64 - 8 * size as u32;
    (((v << shift) as i64) >> shift) as u64
}

/// The low `size` bytes of `v`.
pub const fn trunc(v: u64, size: u8) -> u64 {
    if size >= 8 { v } else { v & ((1u64 << (8 * size as u32)) - 1) }
}

// ---- Executing what was decoded.

pub const FLAG_CF: u64 = 1 << 0;
pub const FLAG_PF: u64 = 1 << 2;
pub const FLAG_AF: u64 = 1 << 4;
pub const FLAG_ZF: u64 = 1 << 6;
pub const FLAG_SF: u64 = 1 << 7;
pub const FLAG_OF: u64 = 1 << 11;
const ARITH_FLAGS: u64 = FLAG_CF | FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF;

/// Read register `r` as an operand of `size` bytes.
pub fn read_reg(gp: &[u64; 16], r: Reg, size: u8) -> u64 {
    if r.high8 { (gp[r.num as usize] >> 8) & 0xff } else { trunc(gp[r.num as usize], size) }
}

/// Write `v` to register `r` as an operand of `size` bytes: a 32-bit write
/// zeroes bits 32-63, as the CPU's; 8- and 16-bit writes keep the rest.
pub fn write_reg(gp: &mut [u64; 16], r: Reg, size: u8, v: u64) {
    let old = &mut gp[r.num as usize];
    *old = match (size, r.high8) {
        (1, true) => (*old & !0xff00) | ((v & 0xff) << 8),
        (1, false) => (*old & !0xff) | (v & 0xff),
        (2, _) => (*old & !0xffff) | (v & 0xffff),
        (4, _) => v & 0xffff_ffff,
        _ => v,
    };
}

/// The flags of a logical result (OR, AND, TEST): CF and OF clear, AF
/// undefined (cleared, as the CPU does).
pub fn logic_flags(rflags: u64, result: u64, size: u8) -> u64 {
    (rflags & !ARITH_FLAGS) | szp(result, size)
}

/// The flags of `a - b` (CMP), operands of `size` bytes.
pub fn sub_flags(rflags: u64, a: u64, b: u64, size: u8) -> u64 {
    let (a, b) = (trunc(a, size), trunc(b, size));
    let r = trunc(a.wrapping_sub(b), size);
    let sign = 1u64 << (8 * size as u32 - 1);
    let mut f = szp(r, size);
    if a < b {
        f |= FLAG_CF;
    }
    if (a ^ b) & (a ^ r) & sign != 0 {
        f |= FLAG_OF;
    }
    if (a ^ b ^ r) & 0x10 != 0 {
        f |= FLAG_AF;
    }
    (rflags & !ARITH_FLAGS) | f
}

fn szp(r: u64, size: u8) -> u64 {
    let r = trunc(r, size);
    let mut f = 0;
    if r == 0 {
        f |= FLAG_ZF;
    }
    if r & (1u64 << (8 * size as u32 - 1)) != 0 {
        f |= FLAG_SF;
    }
    if (r as u8).count_ones().is_multiple_of(2) {
        f |= FLAG_PF;
    }
    f
}

/// What executing an instruction with one memory operand does to the
/// registers, given what the memory read gives (`mem`, for kinds that
/// read it): the value written to memory, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effect {
    pub mem_write: Option<u64>,
}

/// Whether `kind` reads its memory operand.
pub fn reads_mem(kind: &Kind) -> bool {
    match kind {
        Kind::Load { .. } | Kind::Alu { .. } | Kind::Xchg { .. } => true,
        Kind::Store { .. } => false,
        _ => false,
    }
}

/// Execute `insn` (one with a ModRM or moffs memory operand) on the
/// registers `gp` and `rflags`, with `mem` the value its memory operand
/// holds if it reads it.
pub fn execute(insn: &Insn, gp: &mut [u64; 16], rflags: &mut u64, mem: u64) -> Effect {
    let size = insn.size;
    let operand = |gp: &[u64; 16], o: Operand| match o {
        Operand::Reg(r) => read_reg(gp, r, size),
        Operand::Imm(v) => trunc(v, size),
    };
    match insn.kind {
        Kind::Load { reg, dst, ext } => {
            let v = trunc(mem, size);
            let v = match ext {
                Ext::Sign => sext(v, size),
                _ => v,
            };
            write_reg(gp, reg, dst, v);
            Effect { mem_write: None }
        }
        Kind::Store { src } => Effect { mem_write: Some(operand(gp, src)) },
        Kind::Xchg { reg } => {
            let old = read_reg(gp, reg, size);
            write_reg(gp, reg, size, trunc(mem, size));
            Effect { mem_write: Some(old) }
        }
        Kind::Alu { op, mem_first, other } => {
            let m = trunc(mem, size);
            let o = operand(gp, other);
            let (a, b) = if mem_first { (m, o) } else { (o, m) };
            match op {
                AluOp::Cmp => {
                    *rflags = sub_flags(*rflags, a, b, size);
                    Effect { mem_write: None }
                }
                AluOp::Test => {
                    *rflags = logic_flags(*rflags, a & b, size);
                    Effect { mem_write: None }
                }
                AluOp::Or | AluOp::And => {
                    let r = if op == AluOp::Or { a | b } else { a & b };
                    *rflags = logic_flags(*rflags, r, size);
                    if mem_first {
                        Effect { mem_write: Some(r) }
                    } else {
                        if let Operand::Reg(reg) = other {
                            write_reg(gp, reg, size, r);
                        }
                        Effect { mem_write: None }
                    }
                }
            }
        }
        _ => Effect { mem_write: None },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d64(b: &[u8]) -> Insn {
        decode(b, Mode::Bits64).unwrap()
    }

    #[test]
    fn mov_forms() {
        // mov %eax, 0x300(%rbx)
        let i = d64(&[0x89, 0x83, 0x00, 0x03, 0x00, 0x00]);
        assert_eq!(i.len, 6);
        assert_eq!(i.size, 4);
        assert_eq!(i.kind, Kind::Store { src: Operand::Reg(Reg::new(0)) });
        // mov 0xb0(%rdx), %ecx
        let i = d64(&[0x8b, 0x8a, 0xb0, 0, 0, 0]);
        assert_eq!((i.len, i.size), (6, 4));
        assert_eq!(i.kind, Kind::Load { reg: Reg::new(1), dst: 4, ext: Ext::None });
        // mov %r9, (%rax) with REX.W.R
        let i = d64(&[0x4c, 0x89, 0x08]);
        assert_eq!((i.len, i.size), (3, 8));
        assert_eq!(i.kind, Kind::Store { src: Operand::Reg(Reg::new(9)) });
        // movb $0x5a, -8(%rbp)
        let i = d64(&[0xc6, 0x45, 0xf8, 0x5a]);
        assert_eq!((i.len, i.size), (4, 1));
        assert_eq!(i.kind, Kind::Store { src: Operand::Imm(0x5a) });
        // movq $-1, 8(%rax): a sign-extended imm32
        let i = d64(&[0x48, 0xc7, 0x40, 0x08, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!((i.len, i.size), (8, 8));
        assert_eq!(i.kind, Kind::Store { src: Operand::Imm(u64::MAX) });
        // movw $0x1234, (%rdi)
        let i = d64(&[0x66, 0xc7, 0x07, 0x34, 0x12]);
        assert_eq!((i.len, i.size), (5, 2));
        assert_eq!(i.kind, Kind::Store { src: Operand::Imm(0x1234) });
        // mov %ah, (%rax) without REX is AH; with REX it is SPL
        assert_eq!(d64(&[0x88, 0x20]).kind, Kind::Store { src: Operand::Reg(Reg { num: 0, high8: true }) });
        assert_eq!(d64(&[0x40, 0x88, 0x20]).kind, Kind::Store { src: Operand::Reg(Reg::new(4)) });
        // mov %eax, 0x12345678(%rip)
        let i = d64(&[0x89, 0x05, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!(i.len, 6);
        // SIB with no base: mov (,%rcx,4), %edx
        let i = d64(&[0x8b, 0x14, 0x8d, 0, 0, 0, 0]);
        assert_eq!(i.len, 7);
        // moffs: mov 0xfee000b0, %eax with a 64-bit address
        let i = d64(&[0xa1, 0xb0, 0, 0xe0, 0xfe, 0, 0, 0, 0]);
        assert_eq!((i.len, i.size), (9, 4));
        assert!(matches!(i.kind, Kind::Load { .. }));
        // A segment override and LOCK.
        let i = d64(&[0x65, 0xf0, 0x89, 0x01]);
        assert_eq!((i.len, i.seg), (4, Some(Seg::Gs)));
    }

    #[test]
    fn extensions_and_alu() {
        // movzbl (%rdi), %eax and movswq (%rsi), %rax
        assert_eq!(d64(&[0x0f, 0xb6, 0x07]).kind, Kind::Load { reg: Reg::new(0), dst: 4, ext: Ext::Zero });
        let i = d64(&[0x48, 0x0f, 0xbf, 0x06]);
        assert_eq!((i.size, i.kind), (2, Kind::Load { reg: Reg::new(0), dst: 8, ext: Ext::Sign }));
        // cmpl $0, 0x10(%rax); orl $4, (%rdx); andb $0xfe, (%rcx)
        let i = d64(&[0x83, 0x78, 0x10, 0x00]);
        assert_eq!(i.kind, Kind::Alu { op: AluOp::Cmp, mem_first: true, other: Operand::Imm(0) });
        let i = d64(&[0x83, 0x0a, 0x04]);
        assert_eq!(i.kind, Kind::Alu { op: AluOp::Or, mem_first: true, other: Operand::Imm(4) });
        let i = d64(&[0x80, 0x21, 0xfe]);
        assert_eq!((i.size, i.kind), (1, Kind::Alu { op: AluOp::And, mem_first: true, other: Operand::Imm(0xfe) }));
        // testl $0x1000, 0x300(%rax): F7 /0 with imm32
        let i = d64(&[0xf7, 0x80, 0, 3, 0, 0, 0, 0x10, 0, 0]);
        assert_eq!(i.len, 10);
        // cmp (%rax), %ecx (3B): the register first
        let i = d64(&[0x3b, 0x08]);
        assert_eq!(i.kind, Kind::Alu { op: AluOp::Cmp, mem_first: false, other: Operand::Reg(Reg::new(1)) });
        // xchg %eax, (%rdx)
        assert_eq!(d64(&[0x87, 0x02]).kind, Kind::Xchg { reg: Reg::new(0) });
    }

    #[test]
    fn strings_cr_and_modes() {
        let i = d64(&[0xf3, 0x48, 0xa5]);
        assert_eq!((i.kind, i.size, i.rep, i.addr), (Kind::Movs, 8, Rep::Repe, 8));
        let i = d64(&[0x67, 0xaa]);
        assert_eq!((i.kind, i.size, i.addr), (Kind::Stos, 1, 4));
        // mov %rax, %cr4; mov %cr8, %rcx (REX.R); mov %r9, %db7
        assert_eq!(d64(&[0x0f, 0x22, 0xe0]).kind, Kind::MovCr { write: true, cr: 4, reg: 0 });
        assert_eq!(d64(&[0x44, 0x0f, 0x20, 0xc1]).kind, Kind::MovCr { write: false, cr: 8, reg: 1 });
        assert_eq!(d64(&[0x41, 0x0f, 0x23, 0xf9]).kind, Kind::MovDr { write: true, dr: 7, reg: 9 });
        assert_eq!(d64(&[0x0f, 0x06]).kind, Kind::Clts);
        assert_eq!(d64(&[0x0f, 0x01, 0xf0]).kind, Kind::Lmsw { src: Some(0) });
        // Real mode: 16-bit operands by default, 32 with 66; 16-bit
        // addressing with its displacements.
        let i = decode(&[0x89, 0x46, 0x02], Mode::Bits16).unwrap();
        assert_eq!((i.len, i.size, i.addr), (3, 2, 2));
        let i = decode(&[0x66, 0x89, 0x06, 0x34, 0x12], Mode::Bits16).unwrap();
        assert_eq!((i.len, i.size), (5, 4));
        // 32-bit: no REX (0x48 is DEC there), so it is refused.
        assert_eq!(decode(&[0x48, 0x89, 0x08], Mode::Bits32), Err(Error::Unsupported));
        let i = decode(&[0x66, 0x89, 0x08], Mode::Bits32).unwrap();
        assert_eq!(i.size, 2);
    }

    #[test]
    fn refusals() {
        // Truncated, too long (15 prefixes), unknown, register operands.
        assert_eq!(decode(&[0x89], Mode::Bits64), Err(Error::Truncated));
        assert_eq!(decode(&[0x89, 0x83, 0x00], Mode::Bits64), Err(Error::Truncated));
        assert_eq!(decode(&[0x66; 16], Mode::Bits64), Err(Error::TooLong));
        let mut long = [0x66u8; 15];
        long[14] = 0x89;
        assert_eq!(decode(&long, Mode::Bits64), Err(Error::TooLong));
        assert_eq!(decode(&[0x01, 0x08], Mode::Bits64), Err(Error::Unsupported));
        assert_eq!(decode(&[0x89, 0xc0], Mode::Bits64), Err(Error::Unsupported));
        assert_eq!(decode(&[0x83, 0x00, 0x01], Mode::Bits64), Err(Error::Unsupported));
        assert_eq!(decode(&[0xc7, 0x08, 0, 0, 0, 0], Mode::Bits64), Err(Error::Unsupported));
        assert_eq!(decode(&[0x0f, 0x0b], Mode::Bits64), Err(Error::Unsupported));
        assert_eq!(decode(&[0x48, 0x66, 0x89, 0x08], Mode::Bits64), Err(Error::Unsupported));
        assert_eq!(decode(&[], Mode::Bits64), Err(Error::Truncated));
    }

    #[test]
    fn execution() {
        let mut gp = [0u64; 16];
        let mut fl = 0x2;
        gp[0] = 0xffff_ffff_0000_0000;
        // A 32-bit load zeroes the upper half; an 8-bit one keeps it.
        let i = d64(&[0x8b, 0x00]);
        execute(&i, &mut gp, &mut fl, 0x1234_5678_9abc_def0);
        assert_eq!(gp[0], 0x9abc_def0);
        gp[3] = 0x1111;
        execute(&d64(&[0x8a, 0x3b]), &mut gp, &mut fl, 0xaa);
        assert_eq!(gp[3], 0xaa11, "BH");
        // movsbq: sign-extension
        execute(&d64(&[0x48, 0x0f, 0xbe, 0x00]), &mut gp, &mut fl, 0x80);
        assert_eq!(gp[0], 0xffff_ffff_ffff_ff80);
        // Store of a register and of an immediate.
        gp[1] = 0xdead_beef;
        assert_eq!(execute(&d64(&[0x89, 0x08]), &mut gp, &mut fl, 0).mem_write, Some(0xdead_beef));
        // cmp: equal, below, signed overflow
        let cmp = d64(&[0x83, 0x38, 0x05]);
        execute(&cmp, &mut gp, &mut fl, 5);
        assert!(fl & FLAG_ZF != 0 && fl & FLAG_CF == 0);
        execute(&cmp, &mut gp, &mut fl, 4);
        assert!(fl & FLAG_CF != 0 && fl & FLAG_SF != 0 && fl & FLAG_ZF == 0);
        let cmpb = d64(&[0x80, 0x38, 0x01]);
        execute(&cmpb, &mut gp, &mut fl, 0x80);
        assert!(fl & FLAG_OF != 0, "0x80 - 1 overflows a signed byte");
        // or to memory, and to a register
        assert_eq!(execute(&d64(&[0x83, 0x08, 0x04]), &mut gp, &mut fl, 1).mem_write, Some(5));
        assert!(fl & (FLAG_CF | FLAG_OF | FLAG_ZF) == 0);
        gp[1] = 0x10;
        assert_eq!(execute(&d64(&[0x0b, 0x08]), &mut gp, &mut fl, 1).mem_write, None);
        assert_eq!(gp[1], 0x11);
        // test leaves memory alone
        assert_eq!(execute(&d64(&[0xf6, 0x00, 0x01]), &mut gp, &mut fl, 2).mem_write, None);
        assert!(fl & FLAG_ZF != 0);
        // xchg
        gp[0] = 7;
        assert_eq!(execute(&d64(&[0x87, 0x00]), &mut gp, &mut fl, 9).mem_write, Some(7));
        assert_eq!(gp[0], 9);
        // parity: 0x03 has two bits set
        assert!(logic_flags(0, 3, 4) & FLAG_PF != 0);
        assert!(logic_flags(0, 1, 4) & FLAG_PF == 0);
    }
}
