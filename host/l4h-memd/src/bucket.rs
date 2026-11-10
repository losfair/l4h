//! The token bucket that bounds the time one guest's hotplug calls take
//! from memd (DESIGN.md §8.5).  It holds microseconds of memd's time, and
//! each call is charged what it took: a guest that makes its unplugs slow
//! to revoke (many capabilities to the blocks) pays for them with later
//! calls, not other callers.

use l4h_rt::host::memd::{HP_BURST_US, HP_CALL_US, HP_SHARE};

#[derive(Clone, Copy)]
pub struct Bucket {
    /// Microseconds the guest may still take; below 0 after a call that
    /// took more than there was.
    tokens: i64,
    /// Refilled up to here, in microseconds: the time since, less than
    /// HP_SHARE of it, refills at the next call.
    last_us: u64,
}

impl Bucket {
    pub const fn full(now_us: u64) -> Self {
        Bucket { tokens: HP_BURST_US as i64, last_us: now_us }
    }

    /// Refill at `now_us`: the microseconds a call may take now, if the
    /// guest may make one.
    pub fn admit(&mut self, now_us: u64) -> Option<u64> {
        let refill = now_us.saturating_sub(self.last_us) / HP_SHARE;
        // At most now_us - last_us: neither wraps.
        self.last_us += refill * HP_SHARE;
        self.tokens = self.tokens.saturating_add(refill.min(i64::MAX as u64) as i64).min(HP_BURST_US as i64);
        (self.tokens >= HP_CALL_US as i64).then_some(self.tokens as u64)
    }

    /// A call admitted took `spent_us`.
    pub fn charge(&mut self, spent_us: u64) {
        self.tokens = self.tokens.saturating_sub(spent_us.clamp(HP_CALL_US, i64::MAX as u64) as i64);
    }
}
