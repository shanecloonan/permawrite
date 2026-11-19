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
    /// Upper bound on the delay before a stem send. Zero disables jitter.
    pub stem_jitter: Duration,
}

impl Default for DandelionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fluff_probability_bps: 900,
            epoch_secs: 600,
            stem_timeout: Duration::from_secs(30),
            stem_jitter: Duration::ZERO,
        }
    }
}

impl DandelionConfig {
    /// Opt-in production profile (`--dandelion`).
    #[must_use]
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            stem_jitter: Duration::from_millis(250),
            ..Self::default()
        }
    }
}

/// Whether this node created the transaction or is relaying a stem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopKind {
    /// Created here. Always enters the epoch stem. Never diffuses immediately.
    Origin,
    /// Received from one peer. May extend the stem or fail safe into fluff.
    Relay,
    /// Received already diffused. It stays diffused.
    Fluff,
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
    /// No reachable stem peer yet. The body is remembered for the embargo.
    Hold,
}

struct PendingStem {
    first_seen: Instant,
    tx_wire: Vec<u8>,
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
        self.pending.entry(tx_id).or_insert(PendingStem {
            first_seen: now,
            tx_wire: Vec::new(),
        });
        let epoch = self.current_epoch(now);
        let idx = stem_peer_index(&self.node_salt, epoch, &tx_id, peers.len());
        RelayAction::Stem {
            peer: peers[idx].clone(),
        }
    }

    /// Epoch stem: one successor for the whole epoch, per-hop fluff, embargo.
    ///
    /// `peers` must already exclude the inbound peer. Origin hops do not fluff.
    pub fn forward(
        &mut self,
        tx_id: [u8; 32],
        tx_wire: &[u8],
        peers: &[String],
        now: Instant,
        hop: HopKind,
    ) -> RelayAction {
        if hop == HopKind::Fluff || !self.config.enabled {
            return RelayAction::Fluff;
        }
        if peers.is_empty() {
            self.pending.entry(tx_id).or_insert(PendingStem {
                first_seen: now,
                tx_wire: tx_wire.to_vec(),
            });
            return RelayAction::Hold;
        }
        if hop == HopKind::Relay {
            if let Some(entry) = self.pending.get(&tx_id) {
                if now.saturating_duration_since(entry.first_seen) >= self.config.stem_timeout {
                    self.pending.remove(&tx_id);
                    return RelayAction::Fluff;
                }
            } else if self.hop_fluffs(&tx_id, now) {
                return RelayAction::Fluff;
            }
        }
        self.pending.entry(tx_id).or_insert(PendingStem {
            first_seen: now,
            tx_wire: tx_wire.to_vec(),
        });
        let epoch = self.current_epoch(now);
        let idx = epoch_successor(&self.node_salt, epoch, peers.len());
        RelayAction::Stem {
            peer: peers[idx].clone(),
        }
    }

    /// Bodies whose stem embargo has elapsed. The peer exclusion is unknown here.
    pub fn take_expired(&mut self, now: Instant) -> Vec<(Vec<u8>, Option<String>)> {
        if !self.config.enabled {
            return Vec::new();
        }
        let timeout = self.config.stem_timeout;
        let expired: Vec<[u8; 32]> = self
            .pending
            .iter()
            .filter(|(_, entry)| now.saturating_duration_since(entry.first_seen) >= timeout)
            .map(|(id, _)| *id)
            .collect();
        let mut out = Vec::with_capacity(expired.len());
        for id in expired {
            if let Some(entry) = self.pending.remove(&id) {
                if !entry.tx_wire.is_empty() {
                    out.push((entry.tx_wire, None));
                }
            }
        }
        out
    }

    /// Delay before a stem send. Stable for one `(node, tx)` inside an epoch.
    #[must_use]
    pub fn stem_send_delay(&self, tx_id: &[u8; 32], now: Instant) -> Duration {
        if !self.config.enabled || self.config.stem_jitter.is_zero() {
            return Duration::ZERO;
        }
        let roll = u64::from(fluff_roll_bps_for_node(
            &self.node_salt,
            tx_id,
            self.current_epoch(now),
        ));
        let cap = self.config.stem_jitter.as_millis() as u64;
        Duration::from_millis(roll * cap / 10_000)
    }

    fn hop_fluffs(&self, tx_id: &[u8; 32], now: Instant) -> bool {
        fluff_roll_bps_for_node(&self.node_salt, tx_id, self.current_epoch(now))
            <= self.config.fluff_probability_bps
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

/// One stem neighbor for `(node, epoch)`. The transaction id is not an input,
/// so the anonymity graph is stable until the epoch rotates.
pub fn epoch_successor(node_salt: &[u8; 32], epoch: u64, peer_count: usize) -> usize {
    let mut w = Writer::new();
    w.push(node_salt);
    w.u64(epoch);
    let h = dhash(b"MFBN-1/dandelion-epoch-v1", &[w.bytes()]);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&h[0..8]);
    (u64::from_be_bytes(buf) as usize) % peer_count.max(1)
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

fn fluff_roll_bps_for_node(node_salt: &[u8; 32], tx_id: &[u8; 32], epoch: u64) -> u16 {
    let mut w = Writer::new();
    w.push(node_salt);
    w.push(tx_id);
    w.u64(epoch);
    let h = dhash(b"MFBN-1/dandelion-hop-v1", &[w.bytes()]);
    u16::from_be_bytes([h[0], h[1]]) % 10_001
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
            RelayAction::Fluff | RelayAction::Hold => panic!("expected stem"),
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

    #[test]
    fn three_node_epoch_stem_hides_the_origin_from_a_neighbor() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 0;
        cfg.epoch_secs = 600;
        cfg.stem_timeout = Duration::from_secs(30);
        let mut alice = DandelionRelay::new(cfg.clone(), [1u8; 32]);
        let mut bob = DandelionRelay::new(cfg.clone(), [2u8; 32]);
        let mut carol = DandelionRelay::new(cfg, [3u8; 32]);
        let now = Instant::now();
        let peers = vec!["bob".to_string(), "carol".to_string()];
        let tx = [9u8; 32];
        let RelayAction::Stem { peer: first } =
            alice.forward(tx, b"tx", &peers, now, HopKind::Origin)
        else {
            panic!("origin stems");
        };
        let RelayAction::Stem { peer: second_tx } =
            alice.forward([8u8; 32], b"tx", &peers, now, HopKind::Origin)
        else {
            panic!("same epoch stems");
        };
        assert_eq!(first, second_tx, "the epoch has one stem successor");
        let idle = if first == "bob" { "carol" } else { "bob" };
        let relay = if first == "bob" { &mut bob } else { &mut carol };
        let next_peers = vec!["alice".to_string(), idle.to_string()];
        let RelayAction::Stem { peer: next } =
            relay.forward(tx, b"tx", &next_peers, now, HopKind::Relay)
        else {
            panic!("relay keeps the stem when fluff probability is zero");
        };
        assert!(next == "alice" || next == idle);
        assert_eq!(
            alice.forward(
                tx,
                b"tx",
                &peers,
                now + Duration::from_secs(30),
                HopKind::Relay
            ),
            RelayAction::Fluff,
            "the embargo fluffs instead of dropping the transaction"
        );
    }
}
