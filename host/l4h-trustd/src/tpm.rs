//! TPM 2.0 transports at locality 0: the FIFO (TIS) and CRB interfaces of
//! the TCG PC Client Platform TPM Profile, CRB with each start method
//! Linux's tpm_crb has on x86: the start register, the ACPI start method
//! (AMD fTPM) and Pluton's doorbells.  Commands are polled: trustd takes no
//! interrupt.

use l4h_virtio::Mmio;

use l4h_rt::host;
use l4h_rt::host::trust::{START_ACPI, START_PLUTON, TPM_TIS, TrustdConfig};

use crate::{aml, time};

/// The longest a command may take: key generation on a slow TPM.
const TIMEOUT_SECS: u64 = 120;
/// Largest response we accept.
const MAX_RESPONSE: usize = 4096;
/// Largest command we send: ActivateCredential with a guest's credential
/// blob and secret, at most a request page's data, and about 100 bytes of
/// handles and sessions around them.
pub const CMD_MAX: usize = l4h_abi::ATTEST_PAGE_DATA + 256;
/// Warnings that ask for the command again.
const RC_YIELDED: u32 = 0x908;
const RC_TESTING: u32 = 0x90a;
const RC_RETRY: u32 = 0x922;

pub enum Error {
    /// The TPM did not answer in time (what it was waiting for).
    Timeout(&'static str),
    /// A malformed response or an unusable interface.
    Bad(&'static str),
    /// A TPM response code.
    Rc(u32),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Timeout(what) => write!(f, "timeout waiting for {}", what),
            Error::Bad(why) => f.write_str(why),
            Error::Rc(rc) => write!(f, "TPM error {:#x}", rc),
        }
    }
}

pub struct Tpm {
    iface: u32,
    start: u32,
    /// FIFO: the registers; CRB: the locality registers, if any.
    loc: usize,
    ctrl: usize,
    cmd: (usize, usize),
    rsp: (usize, usize),
    /// Pluton's doorbells.
    bells: (usize, usize),
    acpi: Option<aml::Start>,
    hz: u64,
    /// The command being sent and the response last received.
    cbuf: [u8; CMD_MAX],
    rbuf: [u8; MAX_RESPONSE],
}

// FIFO (TIS) registers.
const TIS_ACCESS: usize = 0x00;
const TIS_STS: usize = 0x18;
const TIS_FIFO: usize = 0x24;
const ACCESS_VALID: u8 = 0x80;
const ACCESS_ACTIVE: u8 = 0x20;
const ACCESS_REQUEST: u8 = 0x02;
const STS_VALID: u32 = 0x80;
const STS_READY: u32 = 0x40;
const STS_GO: u32 = 0x20;
const STS_DATA: u32 = 0x10;
const STS_EXPECT: u32 = 0x08;

// CRB locality registers.
const CRB_LOC_STATE: usize = 0x00;
const CRB_LOC_CTRL: usize = 0x08;
const LOC_ASSIGNED: u32 = 0x02;
const LOC_VALID: u32 = 0x80;
// CRB control area.
const CRB_CTRL_REQ: usize = 0x00;
const CRB_CTRL_STS: usize = 0x04;
const CRB_CTRL_CANCEL: usize = 0x08;
const CRB_CTRL_START: usize = 0x0c;
const REQ_READY: u32 = 0x01;
const REQ_IDLE: u32 = 0x02;
const STS_FATAL: u32 = 0x01;

fn r8(a: usize) -> u8 {
    Mmio(a).r8(0)
}

fn w8(a: usize, v: u8) {
    Mmio(a).w8(0, v)
}

fn r32(a: usize) -> u32 {
    Mmio(a).r32(0)
}

fn w32(a: usize, v: u32) {
    Mmio(a).w32(0, v)
}

impl Tpm {
    pub fn new(cfg: &TrustdConfig, hz: u64) -> Result<Self, Error> {
        let acpi = match cfg.start {
            START_ACPI => Some(aml::Start::new(cfg, hz).map_err(Error::Bad)?),
            _ => None,
        };
        Ok(Tpm {
            iface: cfg.iface,
            start: cfg.start,
            loc: cfg.loc_va as usize,
            ctrl: cfg.ctrl_va as usize,
            cmd: (cfg.cmd_va as usize, cfg.cmd_size as usize),
            rsp: (cfg.rsp_va as usize, cfg.rsp_size as usize),
            bells: (cfg.start_va as usize, cfg.reply_va as usize),
            acpi,
            hz,
            cbuf: [0; CMD_MAX],
            rbuf: [0; MAX_RESPONSE],
        })
    }

    /// Poll until `done` holds, for at most `ms` (TIMEOUT_SECS if 0),
    /// sleeping on the timer in between: from 20 us, doubling up to 2 ms,
    /// so that quick operations finish quickly and slow ones (key
    /// generation, seconds) cost next to no CPU.
    fn wait_ms(&self, what: &'static str, ms: u64, mut done: impl FnMut(&Self) -> bool) -> Result<(), Error> {
        let ticks = if ms == 0 { self.hz * TIMEOUT_SECS } else { self.hz * ms / 1000 };
        let deadline = host::ticks::now() + ticks;
        let mut pause = self.hz / 50_000;
        while !done(self) {
            let now = host::ticks::now();
            if now > deadline {
                return Err(Error::Timeout(what));
            }
            time::sleep_until((now + pause).min(deadline + 1));
            pause = (pause * 2).min(self.hz / 500);
        }
        Ok(())
    }

    fn wait(&self, what: &'static str, done: impl FnMut(&Self) -> bool) -> Result<(), Error> {
        self.wait_ms(what, 0, done)
    }

    /// Send the command `build` writes (returning its length) and return
    /// the response, whose code is checked.  The TPM may ask for a command
    /// again (busy, self-testing): we do, for a while.
    pub fn exec(&mut self, build: impl FnOnce(&mut [u8]) -> Result<usize, Error>) -> Result<&[u8], Error> {
        let cmd = build(&mut self.cbuf)?;
        let deadline = host::ticks::now() + self.hz * TIMEOUT_SECS;
        loop {
            let n = match self.iface {
                TPM_TIS => self.exec_tis(cmd),
                _ => self.exec_crb(cmd),
            }?;
            if n < 10 {
                return Err(Error::Bad("short response"));
            }
            match u32::from_be_bytes(self.rbuf[6..10].try_into().unwrap()) {
                0 => return Ok(&self.rbuf[..n]),
                RC_YIELDED | RC_TESTING | RC_RETRY if host::ticks::now() < deadline => {
                    time::sleep_ns(self.hz, 1_000_000);
                }
                rc => return Err(Error::Rc(rc)),
            }
        }
    }

    /// The first `cmd` bytes of the command buffer, through the FIFO: the
    /// response's length.
    fn exec_tis(&mut self, cmd: usize) -> Result<usize, Error> {
        let regs = self.loc;
        w8(regs + TIS_ACCESS, ACCESS_REQUEST);
        self.wait("locality", |_| r8(regs + TIS_ACCESS) & (ACCESS_VALID | ACCESS_ACTIVE) == ACCESS_VALID | ACCESS_ACTIVE)?;
        let r = self.tis_command(cmd);
        // Back to idle, whatever happened, and give up the locality.
        w8(regs + TIS_STS, STS_READY as u8);
        w8(regs + TIS_ACCESS, ACCESS_ACTIVE);
        r
    }

    fn tis_command(&mut self, cmd: usize) -> Result<usize, Error> {
        let regs = self.loc;
        let burst = || ((r32(regs + TIS_STS) >> 8) & 0xffff) as usize;
        w8(regs + TIS_STS, STS_READY as u8);
        self.wait("command ready", |_| r32(regs + TIS_STS) & STS_READY != 0)?;
        let mut sent = 0;
        while sent < cmd {
            self.wait("burst count", |_| burst() != 0)?;
            let n = burst().min(cmd - sent);
            for &b in &self.cbuf[sent..sent + n] {
                w8(regs + TIS_FIFO, b);
            }
            sent += n;
        }
        self.wait("status", |_| r32(regs + TIS_STS) & STS_VALID != 0)?;
        if r32(regs + TIS_STS) & STS_EXPECT != 0 {
            return Err(Error::Bad("TPM expects more command bytes"));
        }
        w8(regs + TIS_STS, STS_GO as u8);
        self.wait("response", |_| r32(regs + TIS_STS) & (STS_VALID | STS_DATA) == STS_VALID | STS_DATA)?;
        let mut got = 0;
        let mut want = 10;
        while got < want {
            self.wait("response data", |_| burst() != 0)?;
            let n = burst().min(want - got);
            for b in &mut self.rbuf[got..got + n] {
                *b = r8(regs + TIS_FIFO);
            }
            got += n;
            if want == 10 && got >= 10 {
                want = u32::from_be_bytes(self.rbuf[2..6].try_into().unwrap()) as usize;
                if !(10..=MAX_RESPONSE).contains(&want) {
                    return Err(Error::Bad("response size"));
                }
            }
        }
        Ok(got)
    }

    /// The ACPI start method has no idle state (as Linux tpm_crb).
    fn has_idle(&self) -> bool {
        self.start != START_ACPI
    }

    /// Pluton: ring the start doorbell once the reply doorbell is 1, and
    /// with `wait`, until the TPM takes the request.
    fn doorbell(&self, wait: bool) -> Result<(), Error> {
        if self.start != START_PLUTON {
            return Ok(());
        }
        let (start, reply) = self.bells;
        self.wait("Pluton reply doorbell", |_| r32(reply) == 1)?;
        w32(start, 1);
        if wait {
            self.wait_ms("Pluton start doorbell", 200, |_| r32(start) == 0)?;
        }
        Ok(())
    }

    /// Write `bit` to CTRL_REQ and wait until the TPM clears it.
    fn request(&self, bit: u32, what: &'static str) -> Result<(), Error> {
        if !self.has_idle() {
            return Ok(());
        }
        w32(self.ctrl + CRB_CTRL_REQ, bit);
        self.doorbell(true)?;
        let ctrl = self.ctrl;
        self.wait(what, |_| r32(ctrl + CRB_CTRL_REQ) & bit == 0)
    }

    /// The first `cmd` bytes of the command buffer, through the CRB: the
    /// response's length.
    fn exec_crb(&mut self, cmd: usize) -> Result<usize, Error> {
        if cmd > self.cmd.1 {
            return Err(Error::Bad("command larger than the CRB buffer"));
        }
        let loc = self.loc;
        if loc != 0 {
            w32(loc + CRB_LOC_CTRL, 1);
            self.wait("locality", |_| r32(loc + CRB_LOC_STATE) & (LOC_VALID | LOC_ASSIGNED) == LOC_VALID | LOC_ASSIGNED)?;
        }
        let r = self.crb_command(cmd);
        let idle = self.request(REQ_IDLE, "go idle");
        if loc != 0 {
            w32(loc + CRB_LOC_CTRL, 2);
        }
        let r = r?;
        idle.map(|()| r)
    }

    fn crb_command(&mut self, cmd: usize) -> Result<usize, Error> {
        let ctrl = self.ctrl;
        self.request(REQ_READY, "command ready")?;
        if r32(ctrl + CRB_CTRL_STS) & STS_FATAL != 0 {
            return Err(Error::Bad("TPM in failure mode"));
        }
        w32(ctrl + CRB_CTRL_CANCEL, 0);
        for (i, &b) in self.cbuf[..cmd].iter().enumerate() {
            w8(self.cmd.0 + i, b);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // The start register, also with the other start methods (the
        // device is an MSFT0101: Linux does the same).
        w32(ctrl + CRB_CTRL_START, 1);
        if let Some(a) = &self.acpi {
            a.start().map_err(Error::Bad)?;
        }
        self.doorbell(false)?;
        self.wait("response", |_| r32(ctrl + CRB_CTRL_START) & 1 == 0)?;
        let base = self.rsp.0;
        let byte = |i: usize| r8(base + i);
        for (i, b) in self.rbuf[..10].iter_mut().enumerate() {
            *b = byte(i);
        }
        let n = u32::from_be_bytes(self.rbuf[2..6].try_into().unwrap()) as usize;
        if !(10..=MAX_RESPONSE.min(self.rsp.1)).contains(&n) {
            return Err(Error::Bad("response size"));
        }
        for (i, b) in self.rbuf[..n].iter_mut().enumerate().skip(10) {
            *b = byte(i);
        }
        Ok(n)
    }
}
