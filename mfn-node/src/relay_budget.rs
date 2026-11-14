//! Process-wide cap on gossip transaction admission.
//!
//! One peer can otherwise force ring verification on every handler thread.
//! The bucket refills over time and drops the surplus before mempool admit.

use std::time::{Duration, Instant};

/// Sustained transaction admissions per second.
pub const RELAY_TX_PER_SEC: u32 = 64;
/// Largest burst the bucket will store.
pub const RELAY_TX_BURST: u32 = 128;

/// Token bucket for inbound transaction gossip.
#[derive(Debug)]
pub struct RelayBudget {
    tokens: u32,
    burst: u32,
    per_sec: u32,
    updated: Instant,
}

impl RelayBudget {
    /// Full bucket. `per_sec` and `burst` are raised to at least 1.
    #[must_use]
    pub fn new(per_sec: u32, burst: u32) -> Self {
        let burst = burst.max(1);
        Self {
            tokens: burst,
            burst,
            per_sec: per_sec.max(1),
            updated: Instant::now(),
        }
    }

    /// Production defaults ([`RELAY_TX_PER_SEC`], [`RELAY_TX_BURST`]).
    #[must_use]
    pub fn production() -> Self {
        Self::new(RELAY_TX_PER_SEC, RELAY_TX_BURST)
    }

    /// Take one token at `now`. False means the caller should not admit the tx.
    pub fn allow(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now
            .checked_duration_since(self.updated)
            .unwrap_or(Duration::ZERO);
        let millis = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX);
        if millis == 0 {
            return;
        }
        let add = millis.saturating_mul(self.per_sec) / 1_000;
        if add == 0 {
            return;
        }
        self.tokens = self.tokens.saturating_add(add).min(self.burst);
        self.updated = now;
    }
}

impl Default for RelayBudget {
    fn default() -> Self {
        Self::production()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refuse() {
        let mut budget = RelayBudget::new(1, 2);
        let t0 = Instant::now();
        assert!(budget.allow(t0));
        assert!(budget.allow(t0));
        assert!(!budget.allow(t0));
    }

    #[test]
    fn refill_restores_a_token() {
        let mut budget = RelayBudget::new(10, 1);
        let t0 = Instant::now();
        assert!(budget.allow(t0));
        assert!(!budget.allow(t0));
        assert!(budget.allow(t0 + Duration::from_millis(100)));
    }

    #[test]
    fn refill_does_not_exceed_burst() {
        let mut budget = RelayBudget::new(1_000, 3);
        let t0 = Instant::now();
        assert!(budget.allow(t0));
        let _ = budget.allow(t0 + Duration::from_secs(10));
        let mut granted = 0;
        let later = t0 + Duration::from_secs(10);
        while budget.allow(later) {
            granted += 1;
            if granted > 10 {
                break;
            }
        }
        assert!(granted <= 3);
    }
}
