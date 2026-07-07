//! Dandelion++-style transaction relay (**F5-P3** / B7).
//!
//! When enabled, freshly admitted txs propagate through a **stem** phase
//! (single-peer forward) before transitioning to **fluff** (parallel fan-out).
//! Default remains legacy parallel fan-out so existing mesh CI is unchanged
//! until operators opt in with `--dandelion`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mfn_crypto::dhash;
use mfn_crypto::Writer;

/// Per-node Dandelion++ relay parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DandelionConfig {
    /// When false, every relay decision is [`RelayAction::Fluff`].
    pub enabled: bool,
    /// Per-hop probability (0..=10_000 bps) to transition to fluff.
    pub fluff_probability_bps: u16,
    /// Stem epoch length in seconds (stem peer mapping rotates).
    pub epoch_secs: u64,
    /// Max time a tx may stay in stem before forced fluff.
    pub stem_timeout: Duration,
}

impl Default for DandelionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fluff_probability_bps: 900,
            epoch_secs: 600,
            stem_timeout: Duration::from_secs(30),
        }
    }
}

impl DandelionConfig {
    /// Opt-in production profile (`--dandelion`).
    #[must_use]
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }
}

/// How a fresh tx should leave this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAction {
    /// Forward to exactly one peer (stem phase).
    Stem {
        /// Dialable peer address.
        peer: String,
    },
    /// Parallel fan-out to all peers (fluff / legacy).
    Fluff,
}

struct PendingStem {
    first_seen: Instant,
}

/// In-memory stem-phase tracker for one `mfnd` process.
pub struct DandelionRelay {
    config: DandelionConfig,
    node_salt: [u8; 32],
    pending: HashMap<[u8; 32], PendingStem>,
    started: Instant,
}

impl DandelionRelay {
    /// Build relay state; `node_salt` should be stable per process (e.g. genesis id).
    #[must_use]
    pub fn new(config: DandelionConfig, node_salt: [u8; 32]) -> Self {
        Self {
            config,
            node_salt,
            pending: HashMap::new(),
            started: Instant::now(),
        }
    }

    /// Whether stem/fluff routing is active (vs legacy parallel fan-out).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Decide stem vs fluff for a freshly admitted tx.
    pub fn decide(&mut self, tx_id: [u8; 32], peers: &[String], now: Instant) -> RelayAction {
        if !self.config.enabled || peers.is_empty() {
            return RelayAction::Fluff;
        }
        if peers.len() == 1 {
            return RelayAction::Stem {
                peer: peers[0].clone(),
            };
        }
        if self.should_fluff(&tx_id, now) {
            self.pending.remove(&tx_id);
            return RelayAction::Fluff;
        }
        self.pending
            .entry(tx_id)
            .or_insert(PendingStem { first_seen: now });
        let epoch = self.current_epoch(now);
        let idx = stem_peer_index(&self.node_salt, epoch, &tx_id, peers.len());
        RelayAction::Stem {
            peer: peers[idx].clone(),
        }
    }

    fn should_fluff(&self, tx_id: &[u8; 32], now: Instant) -> bool {
        if let Some(entry) = self.pending.get(tx_id) {
            if now.duration_since(entry.first_seen) >= self.config.stem_timeout {
                return true;
            }
        }
        fluff_roll_bps(tx_id, self.current_epoch(now)) <= self.config.fluff_probability_bps
    }

    fn current_epoch(&self, now: Instant) -> u64 {
        let secs = now.duration_since(self.started).as_secs();
        if self.config.epoch_secs == 0 {
            return secs;
        }
        secs / self.config.epoch_secs
    }
}

fn stem_peer_index(node_salt: &[u8; 32], epoch: u64, tx_id: &[u8; 32], peer_count: usize) -> usize {
    let mut w = Writer::new();
    w.push(node_salt);
    w.u64(epoch);
    w.push(tx_id);
    let h = dhash(b"MFBN-1/dandelion-stem-v1", &[w.bytes()]);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&h[0..8]);
    let n = u64::from_be_bytes(buf);
    (n as usize) % peer_count
}

fn fluff_roll_bps(tx_id: &[u8; 32], epoch: u64) -> u16 {
    let mut w = Writer::new();
    w.push(tx_id);
    w.u64(epoch);
    let h = dhash(b"MFBN-1/dandelion-fluff-v1", &[w.bytes()]);
    u16::from_be_bytes([h[0], h[1]]) % 10_001
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peers(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("127.0.0.1:{}", 19000 + i)).collect()
    }

    #[test]
    fn disabled_always_fluffs() {
        let mut relay = DandelionRelay::new(DandelionConfig::default(), [1u8; 32]);
        let action = relay.decide([9u8; 32], &peers(3), Instant::now());
        assert_eq!(action, RelayAction::Fluff);
    }

    #[test]
    fn enabled_zero_fluff_probability_stems() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 0;
        let mut relay = DandelionRelay::new(cfg, [2u8; 32]);
        match relay.decide([1u8; 32], &peers(3), Instant::now()) {
            RelayAction::Stem { peer } => assert!(peer.starts_with("127.0.0.1:")),
            RelayAction::Fluff => panic!("expected stem"),
        }
    }

    #[test]
    fn enabled_full_fluff_probability_diffuses() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 10_000;
        let mut relay = DandelionRelay::new(cfg, [3u8; 32]);
        assert_eq!(
            relay.decide([4u8; 32], &peers(3), Instant::now()),
            RelayAction::Fluff
        );
    }

    #[test]
    fn stem_timeout_forces_fluff() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 0;
        cfg.stem_timeout = Duration::from_millis(1);
        let mut relay = DandelionRelay::new(cfg, [5u8; 32]);
        let t0 = Instant::now();
        assert!(matches!(
            relay.decide([6u8; 32], &peers(3), t0),
            RelayAction::Stem { .. }
        ));
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            relay.decide([6u8; 32], &peers(3), Instant::now()),
            RelayAction::Fluff
        );
    }

    #[test]
    fn single_peer_stems_to_only_candidate() {
        let mut relay = DandelionRelay::new(DandelionConfig::enabled(), [7u8; 32]);
        let ps = peers(1);
        assert_eq!(
            relay.decide([8u8; 32], &ps, Instant::now()),
            RelayAction::Stem {
                peer: ps[0].clone()
            }
        );
    }
}
