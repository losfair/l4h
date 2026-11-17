//! The TPM 2.0 commands trustd uses (TPM 2.0 Library, Part 3), marshalled
//! by hand: big-endian integers and TPM2B (u16 length, bytes) buffers.

use l4h_rt::host::fixed::ArrayVec;

use crate::tpm::{Error, Tpm};

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;

const CC_ACTIVATE_CREDENTIAL: u32 = 0x147;
const CC_CREATE_PRIMARY: u32 = 0x131;
const CC_FLUSH_CONTEXT: u32 = 0x165;
const CC_GET_CAPABILITY: u32 = 0x17a;
const CC_GET_RANDOM: u32 = 0x17b;
const CC_NV_READ: u32 = 0x14e;
const CC_NV_READ_PUBLIC: u32 = 0x169;
const CC_PCR_EXTEND: u32 = 0x182;
const CC_PCR_READ: u32 = 0x17e;
const CC_POLICY_SECRET: u32 = 0x151;
const CC_QUOTE: u32 = 0x158;
const CC_START_AUTH_SESSION: u32 = 0x176;
const CC_STARTUP: u32 = 0x144;

const RC_INITIALIZE: u32 = 0x100;

const CAP_TPM_PROPERTIES: u32 = 6;
const PT_MANUFACTURER: u32 = 0x105;

pub const RH_OWNER: u32 = 0x4000_0001;
pub const RH_NULL: u32 = 0x4000_0007;
const RS_PW: u32 = 0x4000_0009;
pub const RH_ENDORSEMENT: u32 = 0x4000_000b;

const ALG_RSA: u16 = 0x0001;
const ALG_SHA256: u16 = 0x000b;
const ALG_AES: u16 = 0x0006;
const ALG_NULL: u16 = 0x0010;
const ALG_ECDSA: u16 = 0x0018;
const ALG_ECC: u16 = 0x0023;
const ALG_CFB: u16 = 0x0043;
const ECC_NIST_P256: u16 = 0x0003;
const SE_POLICY: u8 = 0x01;

/// Object attributes.
const FIXED_TPM: u32 = 1 << 1;
const FIXED_PARENT: u32 = 1 << 4;
const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
const USER_WITH_AUTH: u32 = 1 << 6;
const ADMIN_WITH_POLICY: u32 = 1 << 7;
const NO_DA: u32 = 1 << 10;
const RESTRICTED: u32 = 1 << 16;
const DECRYPT: u32 = 1 << 17;
const SIGN: u32 = 1 << 18;

/// NV attributes: who may read.
const NV_OWNERREAD: u32 = 1 << 17;
const NV_AUTHREAD: u32 = 1 << 18;

/// EK certificates (TCG EK Credential Profile): RSA 2048 and ECC P-256,
/// for the EKs of the default ("low range") templates.
pub const NV_EK_CERT_RSA: u32 = 0x01c0_0002;
pub const NV_EK_CERT_ECC: u32 = 0x01c0_000a;

/// The policy of the default EK templates: PolicySecret(TPM_RH_ENDORSEMENT).
const EK_POLICY: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e,
    0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];

/// A command being built, in the TPM's command buffer: what does not fit
/// is not written, and `finish` fails.
struct Cmd<'a> {
    b: &'a mut [u8],
    n: usize,
    overflow: bool,
}

impl<'a> Cmd<'a> {
    fn new(b: &'a mut [u8], tag: u16, cc: u32) -> Self {
        let mut c = Cmd { b, n: 0, overflow: false };
        c.u16(tag).u32(0).u32(cc);
        c
    }

    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        match self.b.get_mut(self.n..self.n + b.len()) {
            Some(dst) if !self.overflow => {
                dst.copy_from_slice(b);
                self.n += b.len();
            }
            _ => self.overflow = true,
        }
        self
    }

    fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes(&[v])
    }

    fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    fn tpm2b(&mut self, b: &[u8]) -> &mut Self {
        self.u16(b.len() as u16).bytes(b)
    }

    /// A TPM2B of what `f` writes.
    fn tpm2b_with(&mut self, f: impl FnOnce(&mut Self)) -> &mut Self {
        let at = self.n;
        self.u16(0);
        f(self);
        if !self.overflow {
            let n = (self.n - at - 2) as u16;
            self.b[at..at + 2].copy_from_slice(&n.to_be_bytes());
        }
        self
    }

    /// The authorization area: `sessions` are (handle, nonce, attributes);
    /// all have an empty HMAC (password sessions with an empty password,
    /// and policy sessions that need none).
    fn auth(&mut self, sessions: &[(u32, &[u8], u8)]) -> &mut Self {
        let size: usize = sessions.iter().map(|(_, n, _)| 4 + 2 + n.len() + 1 + 2).sum();
        self.u32(size as u32);
        for &(h, nonce, attrs) in sessions {
            self.u32(h).tpm2b(nonce).u8(attrs).u16(0);
        }
        self
    }

    fn pw(&mut self) -> &mut Self {
        self.auth(&[(RS_PW, &[], 0)])
    }

    /// The command's length, written in its header.
    fn finish(self) -> Result<usize, Error> {
        if self.overflow {
            return Err(Error::Bad("command too large"));
        }
        self.b[2..6].copy_from_slice(&(self.n as u32).to_be_bytes());
        Ok(self.n)
    }
}

/// Run the command `tag`, `cc` with what `args` writes after its header:
/// the response.
fn run<'t>(tpm: &'t mut Tpm, tag: u16, cc: u32, args: impl FnOnce(&mut Cmd)) -> Result<&'t [u8], Error> {
    tpm.exec(|b| {
        let mut c = Cmd::new(b, tag, cc);
        args(&mut c);
        c.finish()
    })
}

/// A response being parsed.
pub struct Rsp<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Rsp<'a> {
    /// Past the header and `handles` handles; with sessions, past the
    /// parameter size too.
    fn new(b: &'a [u8], handles: usize, sessions: bool) -> Self {
        Rsp { b, at: 10 + 4 * handles + if sessions { 4 } else { 0 } }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let s = self.b.get(self.at..self.at + n).ok_or(Error::Bad("truncated response"))?;
        self.at += n;
        Ok(s)
    }

    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn tpm2b(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    fn handle(b: &[u8], i: usize) -> Result<u32, Error> {
        let h = b.get(10 + 4 * i..14 + 4 * i).ok_or(Error::Bad("truncated response"))?;
        Ok(u32::from_be_bytes(h.try_into().unwrap()))
    }
}

/// The public template of a primary key.
pub enum Template {
    Ak,
    Ek { ecc: bool },
}

/// TPMT_PUBLIC of the attestation key: a restricted ECDSA P-256 signing
/// key, a primary key of the endorsement hierarchy.  The same template
/// gives the same key on every boot (until the endorsement seed changes),
/// so a verifier enrolls it once.  Its password is empty, so it is out of
/// dictionary-attack protection (noDA): we never shut the TPM down
/// orderly, and each such boot counts as a failed authorization, which
/// would lock a protected key out after a few.
fn ak_template(t: &mut Cmd) {
    t.u16(ALG_ECC)
        .u16(ALG_SHA256)
        .u32(FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH | NO_DA | RESTRICTED | SIGN)
        .tpm2b(&[])
        .u16(ALG_NULL) // symmetric
        .u16(ALG_ECDSA)
        .u16(ALG_SHA256)
        .u16(ECC_NIST_P256)
        .u16(ALG_NULL) // kdf
        .tpm2b(&[])
        .tpm2b(&[]);
}

/// TPMT_PUBLIC of the default EK (TCG EK Credential Profile, templates
/// L-1 and L-2), which its certificate in NV certifies.
fn ek_template(t: &mut Cmd, ecc: bool) {
    t.u16(if ecc { ALG_ECC } else { ALG_RSA })
        .u16(ALG_SHA256)
        .u32(FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | ADMIN_WITH_POLICY | RESTRICTED | DECRYPT)
        .tpm2b(&EK_POLICY)
        .u16(ALG_AES)
        .u16(128)
        .u16(ALG_CFB)
        .u16(ALG_NULL); // scheme
    if ecc {
        t.u16(ECC_NIST_P256).u16(ALG_NULL).tpm2b(&[0; 32]).tpm2b(&[0; 32]);
    } else {
        t.u16(2048).u32(0).tpm2b(&[0; 256]);
    }
}

/// The sha256 PCR bank selection of `pcrs` (a bitmap of PCRs 0-23).
fn pcr_selection(c: &mut Cmd, pcrs: u32) {
    c.u32(1).u16(ALG_SHA256).u8(3).bytes(&pcrs.to_le_bytes()[..3]);
}

pub fn startup(tpm: &mut Tpm) -> Result<(), Error> {
    // TPM_SU_CLEAR.
    match run(tpm, ST_NO_SESSIONS, CC_STARTUP, |c| {
        c.u16(0);
    }) {
        Ok(_) | Err(Error::Rc(RC_INITIALIZE)) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn get_random(tpm: &mut Tpm, out: &mut [u8]) -> Result<(), Error> {
    let mut at = 0;
    while at < out.len() {
        let want = (out.len() - at).min(32) as u16;
        let r = run(tpm, ST_NO_SESSIONS, CC_GET_RANDOM, |c| {
            c.u16(want);
        })?;
        let got = Rsp::new(r, 0, false).tpm2b()?;
        if got.is_empty() {
            return Err(Error::Bad("no random bytes"));
        }
        let n = got.len().min(out.len() - at);
        out[at..at + n].copy_from_slice(&got[..n]);
        at += n;
    }
    Ok(())
}

/// The TPM's manufacturer (TPM_PT_MANUFACTURER): its TCG vendor ID, up to
/// four ASCII characters, big-endian and NUL-padded (0x414d4400 is "AMD").
pub fn manufacturer(tpm: &mut Tpm) -> Result<u32, Error> {
    let r = run(tpm, ST_NO_SESSIONS, CC_GET_CAPABILITY, |c| {
        c.u32(CAP_TPM_PROPERTIES).u32(PT_MANUFACTURER).u32(1);
    })?;
    let mut p = Rsp::new(r, 0, false);
    p.take(1)?; // moreData
    if p.u32()? != CAP_TPM_PROPERTIES || p.u32()? == 0 || p.u32()? != PT_MANUFACTURER {
        return Err(Error::Bad("no TPM_PT_MANUFACTURER"));
    }
    p.u32()
}

/// TPM2_CreatePrimary: the loaded key's handle, and its TPMT_PUBLIC as
/// the TPM returned it.
pub fn create_primary(tpm: &mut Tpm, hierarchy: u32, template: Template) -> Result<(u32, &[u8]), Error> {
    let r = run(tpm, ST_SESSIONS, CC_CREATE_PRIMARY, |c| {
        c.u32(hierarchy).pw();
        c.u16(4).tpm2b(&[]).tpm2b(&[]); // inSensitive: no auth, no data
        c.tpm2b_with(|t| match template {
            Template::Ak => ak_template(t),
            Template::Ek { ecc } => ek_template(t, ecc),
        });
        c.tpm2b(&[]).u32(0);
    })?;
    let handle = Rsp::handle(r, 0)?;
    Ok((handle, Rsp::new(r, 1, true).tpm2b()?))
}

pub fn flush(tpm: &mut Tpm, handle: u32) {
    let _ = run(tpm, ST_NO_SESSIONS, CC_FLUSH_CONTEXT, |c| {
        c.u32(handle);
    });
}

/// All the PCRs of a bank.
pub const PCRS: usize = 24;

/// The sha256 values of the PCRs in `pcrs` (a bitmap), in order.
pub fn pcr_read(tpm: &mut Tpm, pcrs: u32) -> Result<ArrayVec<(u32, [u8; 32]), PCRS>, Error> {
    let mut out = ArrayVec::new();
    let mut left = pcrs;
    while left != 0 {
        let r = run(tpm, ST_NO_SESSIONS, CC_PCR_READ, |c| pcr_selection(c, left))?;
        let mut p = Rsp::new(r, 0, false);
        p.u32()?; // update counter
        // The selection the values are for: the TPM returns at most 8.
        let mut got = 0u32;
        for _ in 0..p.u32()? {
            let alg = p.u16()?;
            let n = p.take(1)?[0] as usize;
            let bits = p.take(n)?;
            if alg == ALG_SHA256 {
                for (i, &b) in bits.iter().enumerate().take(3) {
                    got |= (b as u32) << (8 * i);
                }
            }
        }
        if got & left == 0 {
            return Err(Error::Bad("no sha256 PCR bank"));
        }
        let count = p.u32()?;
        let mut idx = (0..PCRS as u32).filter(|i| got & left & (1 << i) != 0);
        for _ in 0..count {
            let d = p.tpm2b()?;
            let i = idx.next().ok_or(Error::Bad("PCR values"))?;
            // Each index comes once (`left` loses those read), so all fit.
            out.push((i, d.try_into().map_err(|_| Error::Bad("PCR value size"))?)).map_err(|_| Error::Bad("PCR values"))?;
        }
        left &= !got;
    }
    out.sort_unstable_by_key(|&(i, _)| i);
    Ok(out)
}

pub fn pcr_extend(tpm: &mut Tpm, pcr: u32, digest: &[u8; 32]) -> Result<(), Error> {
    run(tpm, ST_SESSIONS, CC_PCR_EXTEND, |c| {
        c.u32(pcr).pw();
        c.u32(1).u16(ALG_SHA256).bytes(digest);
    })
    .map(|_| ())
}

/// TPM2_Quote of the sha256 PCRs `pcrs` with `key`: the TPMS_ATTEST and
/// its TPMT_SIGNATURE.
pub fn quote<'t>(tpm: &'t mut Tpm, key: u32, extra: &[u8], pcrs: u32) -> Result<(&'t [u8], &'t [u8]), Error> {
    let r = run(tpm, ST_SESSIONS, CC_QUOTE, |c| {
        c.u32(key).pw();
        c.tpm2b(extra).u16(ALG_NULL);
        pcr_selection(c, pcrs);
    })?;
    let mut p = Rsp::new(r, 0, true);
    let attest = p.tpm2b()?;
    // TPMT_SIGNATURE (ECDSA): alg, hash, r and s.
    let start = p.at;
    p.u16()?;
    p.u16()?;
    p.tpm2b()?;
    p.tpm2b()?;
    Ok((attest, &r[start..p.at]))
}

/// The size of NV index `index`, if it exists, with its contents in
/// `out` if they fit (else they are not read).
pub fn nv_read(tpm: &mut Tpm, index: u32, out: &mut [u8]) -> Result<Option<usize>, Error> {
    let r = match run(tpm, ST_NO_SESSIONS, CC_NV_READ_PUBLIC, |c| {
        c.u32(index);
    }) {
        Ok(r) => r,
        // TPM_RC_HANDLE for the first handle: no such index.
        Err(Error::Rc(0x18b)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut p = Rsp::new(r, 0, false);
    let mut public = Rsp { b: p.tpm2b()?, at: 0 };
    public.u32()?;
    public.u16()?;
    let attrs = public.u32()?;
    public.tpm2b()?;
    let size = public.u16()? as usize;
    let auth = if attrs & NV_AUTHREAD != 0 {
        index
    } else if attrs & NV_OWNERREAD != 0 {
        RH_OWNER
    } else {
        // Platform-readable only (PPREAD): firmware's.
        return Err(Error::Bad("NV index not readable"));
    };
    if size > out.len() {
        return Ok(Some(size));
    }
    let mut at = 0;
    while at < size {
        let n = (size - at).min(512);
        let r = run(tpm, ST_SESSIONS, CC_NV_READ, |c| {
            c.u32(auth).u32(index).pw();
            c.u16(n as u16).u16(at as u16);
        })?;
        let d = Rsp::new(r, 0, true).tpm2b()?;
        if d.is_empty() || d.len() > n {
            return Err(Error::Bad("NV_Read size"));
        }
        out[at..at + d.len()].copy_from_slice(d);
        at += d.len();
    }
    Ok(Some(size))
}

/// TPM2_ActivateCredential for `ak` with the EK `ek`, whose policy is
/// PolicySecret(TPM_RH_ENDORSEMENT): the credential, in `out`; its length.
pub fn activate_credential(tpm: &mut Tpm, ak: u32, ek: u32, blob: &[u8], secret: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let nonce = [0x4c; 32];
    let r = run(tpm, ST_NO_SESSIONS, CC_START_AUTH_SESSION, |c| {
        c.u32(RH_NULL).u32(RH_NULL).tpm2b(&nonce).tpm2b(&[]).u8(SE_POLICY).u16(ALG_NULL).u16(ALG_SHA256);
    })?;
    let session = Rsp::handle(r, 0)?;
    let result = (|| {
        run(tpm, ST_SESSIONS, CC_POLICY_SECRET, |c| {
            c.u32(RH_ENDORSEMENT).u32(session).pw();
            c.tpm2b(&[]).tpm2b(&[]).tpm2b(&[]).u32(0);
        })?;
        let r = run(tpm, ST_SESSIONS, CC_ACTIVATE_CREDENTIAL, |c| {
            c.u32(ak).u32(ek);
            // The AK by password, the EK by the policy session (which ends
            // with the command: continueSession clear).
            c.auth(&[(RS_PW, &[], 0), (session, &nonce, 0)]);
            c.tpm2b(blob).tpm2b(secret);
        })?;
        let cred = Rsp::new(r, 0, true).tpm2b()?;
        out.get_mut(..cred.len()).ok_or(Error::Bad("credential too large"))?.copy_from_slice(cred);
        Ok(cred.len())
    })();
    if result.is_err() {
        flush(tpm, session);
    }
    result
}
