//! The kexec event log passed to the next host as `kexec-log`. Each event's
//! final word records its control block so the next handoff can unreserve it;
//! that operational address is not part of the measured event digest.

use l4h_host::fixed::ArrayVec;

pub use l4h_host::trust::{KEXEC_LOG_EVENT as EVENT_SIZE, KEXEC_LOG_HEADER as HEADER_SIZE, KEXEC_LOG_MAGIC as MAGIC, KEXEC_LOG_VERSION as VERSION};
pub const MAX_LOG: usize = l4h_host::trust::KEXEC_LOG_MAX;
pub const MAX_EVENTS: usize = MAX_LOG / EVENT_SIZE;
pub const FLAG_INITRD: u32 = 1;
pub const FLAG_CONFIG: u32 = 2;

#[derive(Clone, Copy)]
pub struct Event {
    pub previous_key: [u8; 32],
    pub authenticode: [u8; 32],
    pub initrd: [u8; 32],
    pub config: [u8; 32],
    pub boot_strings: [u8; 32],
    pub flags: u32,
    /// Physical address of this handoff's control block (below 4 GiB).
    pub control: u32,
}

impl Event {
    pub fn encode(&self) -> [u8; EVENT_SIZE] {
        let mut out = [0; EVENT_SIZE];
        for (i, part) in [&self.previous_key, &self.authenticode, &self.initrd, &self.config, &self.boot_strings].iter().enumerate() {
            out[i * 32..i * 32 + 32].copy_from_slice(*part);
        }
        out[160..164].copy_from_slice(&self.flags.to_le_bytes());
        out[164..168].copy_from_slice(&self.control.to_le_bytes());
        out
    }

    /// The digest trustd extends into PCR 14: the event without the
    /// previous key and the control block.
    pub fn digest(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut event = sha2::Sha256::new();
        event.update(b"l4h-kexec-v1");
        event.update(&self.encode()[32..164]);
        event.finalize().into()
    }
}

/// The control block reserved by the previous handoff, if the log records it.
pub fn previous_control(previous: &[u8]) -> Option<u64> {
    let count = l4h_host::trust::kexec_log_count(previous).ok()?;
    if count == 0 {
        return None;
    }
    let at = HEADER_SIZE + (count as usize - 1) * EVENT_SIZE + 164;
    let control = u32::from_le_bytes(previous[at..at + 4].try_into().unwrap()) as u64;
    (control != 0).then_some(control)
}

pub fn build(previous: &[u8], event: &Event) -> Result<ArrayVec<u8, MAX_LOG>, &'static str> {
    let count = l4h_host::trust::kexec_log_count(previous)?;
    let next = count.checked_add(1).ok_or("kexec log count overflow")?;
    let size = HEADER_SIZE + next as usize * EVENT_SIZE;
    if size > MAX_LOG {
        log!("l4h-root: kexec chain reached {} events; cold boot required", MAX_EVENTS);
        return Err("kexec chain log is full; cold boot required");
    }
    let mut out = ArrayVec::new();
    out.extend_from_slice(&MAGIC).map_err(|_| "kexec log capacity")?;
    out.extend_from_slice(&VERSION.to_le_bytes()).map_err(|_| "kexec log capacity")?;
    out.extend_from_slice(&next.to_le_bytes()).map_err(|_| "kexec log capacity")?;
    if !previous.is_empty() {
        out.extend_from_slice(&previous[HEADER_SIZE..]).map_err(|_| "kexec log capacity")?;
    }
    out.extend_from_slice(&event.encode()).map_err(|_| "kexec log capacity")?;
    Ok(out)
}
