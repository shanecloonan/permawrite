//! Dandelion++-style transaction relay (**F5-P3** / B7).
//!
//! When enabled, a transaction leaves its origin down a single **stem** and
//! each relay independently either extends that stem or switches to **fluff**
//! (parallel fan-out). An inbound fluff stays fluff. A stem that cannot be
//! forwarded is held until [`DandelionRelay::take_expired`] so the embargo
//! timer can diffuse it.
//!
//! Default remains legacy parallel fan-out so existing mesh CI is unchanged
//! until operators opt in with `--dandelion`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mfn_crypto::dhash;
use mfn_crypto::Writer;

/// Cap on remembered stem bodies so a peer cannot grow this map without bound.
const MAX_PENDING_STEMS: usize = 64;
/// Largest transaction body kept for the embargo. Larger bodies diffuse immediately.
const MAX_STEM_WIRE_BYTES: usize = 256 * 1024;

/// Per-node Dandelion++ relay parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DandelionConfig {
    /// When false, every relay decision is [`RelayAction::Fluff`].
    pub enabled: bool,
    /// Per-hop probability (0..=10_000 bps) that a stem relay switches to fluff.
    pub fluff_probability_bps: u16,
    /// Stem epoch length in seconds (stem peer mapping rotates).
    pub epoch_secs: u64,
    /// Max time a tx may stay in stem before the embargo forces fluff.
    pub stem_timeout: Duration,
    /// Upper bound on the per-stem send delay. Zero disables jitter.
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

/// How this node learned the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRole {
    /// Created on this node. The origin always stems and never diffuses itself.
    Origin,
    /// Received on the stem wire. This hop may stem again or fluff.
    StemRelay,
    /// Received on the fluff wire. Diffusion stays diffusion.
    FluffRelay,
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
    except_peer: Option<String>,
}

/// In-memory stem-phase tracker for one `mfnd` process.
pub struct DandelionRelay {
    config: DandelionConfig,
    node_salt: [u8; 32],
    pending: HashMap<[u8; 32], PendingStem>,
    started: Instant,
}

impl DandelionRelay {
    /// Build relay state. `node_salt` must differ per process so hop decisions do too.
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

    /// Delay before a stem send. Stable for one `(node, tx)` inside an epoch.
    #[must_use]
    pub fn stem_send_delay(&self, tx_id: &[u8; 32], now: Instant) -> Duration {
        if !self.config.enabled || self.config.stem_jitter.is_zero() {
            return Duration::ZERO;
        }
        let max_ms = u64::try_from(self.config.stem_jitter.as_millis()).unwrap_or(u64::MAX);
        if max_ms == 0 {
            return Duration::ZERO;
        }
        let mut w = Writer::new();
        w.push(&self.node_salt);
        w.push(tx_id);
        w.u64(self.current_epoch(now));
        let h = dhash(b"MFBN-1/dandelion-jitter-v1", &[w.bytes()]);
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&h[0..8]);
        let n = u64::from_be_bytes(buf);
        Duration::from_millis((n % max_ms).saturating_add(1)).min(self.config.stem_jitter)
    }

    /// Decide stem vs fluff for one transaction.
    ///
    /// `peers` must already exclude the inbound peer. `except_peer` is stored
    /// so an embargo fluff does not immediately bounce the body back.
    pub fn decide(
        &mut self,
        tx_id: [u8; 32],
        tx_wire: &[u8],
        peers: &[String],
        except_peer: Option<&str>,
        now: Instant,
        role: RelayRole,
    ) -> RelayAction {
        if !self.config.enabled {
            self.pending.remove(&tx_id);
            return RelayAction::Fluff;
        }
        if role == RelayRole::FluffRelay {
            self.pending.remove(&tx_id);
            return RelayAction::Fluff;
        }
        if let Some(entry) = self.pending.get(&tx_id) {
            if elapsed(now, entry.first_seen) >= self.config.stem_timeout {
                self.pending.remove(&tx_id);
                return RelayAction::Fluff;
            }
        } else if role == RelayRole::StemRelay && self.hop_fluffs(&tx_id, now) {
            return RelayAction::Fluff;
        }
        if tx_wire.len() > MAX_STEM_WIRE_BYTES {
            if peers.is_empty() {
                return RelayAction::Fluff;
            }
            let epoch = self.current_epoch(now);
            let idx = stem_peer_index(&self.node_salt, epoch, &tx_id, peers.len());
            return RelayAction::Stem {
                peer: peers[idx].clone(),
            };
        }
        if !self.pending.contains_key(&tx_id) && self.pending.len() >= MAX_PENDING_STEMS {
            return RelayAction::Fluff;
        }
        self.pending.entry(tx_id).or_insert(PendingStem {
            first_seen: now,
            tx_wire: tx_wire.to_vec(),
            except_peer: except_peer.map(str::to_string),
        });
        if peers.is_empty() {
            return RelayAction::Hold;
        }
        let epoch = self.current_epoch(now);
        let idx = stem_peer_index(&self.node_salt, epoch, &tx_id, peers.len());
        RelayAction::Stem {
            peer: peers[idx].clone(),
        }
    }

    /// Bodies whose stem embargo has elapsed. Each item is `(tx_wire, except_peer)`.
    pub fn take_expired(&mut self, now: Instant) -> Vec<(Vec<u8>, Option<String>)> {
        if !self.config.enabled {
            return Vec::new();
        }
        let timeout = self.config.stem_timeout;
        let expired: Vec<[u8; 32]> = self
            .pending
            .iter()
            .filter(|(_, entry)| elapsed(now, entry.first_seen) >= timeout)
            .map(|(id, _)| *id)
            .collect();
        let mut out = Vec::with_capacity(expired.len());
        for id in expired {
            if let Some(entry) = self.pending.remove(&id) {
                out.push((entry.tx_wire, entry.except_peer));
            }
        }
        out
    }

    fn hop_fluffs(&self, tx_id: &[u8; 32], now: Instant) -> bool {
        fluff_roll_bps(&self.node_salt, tx_id, self.current_epoch(now))
            <= self.config.fluff_probability_bps
    }

    fn current_epoch(&self, now: Instant) -> u64 {
        let secs = elapsed(now, self.started).as_secs();
        if self.config.epoch_secs == 0 {
            return secs;
        }
        secs / self.config.epoch_secs
    }
}

fn elapsed(now: Instant, then: Instant) -> Duration {
    now.checked_duration_since(then).unwrap_or(Duration::ZERO)
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

/// Per-hop fluff coin. `node_salt` is part of the preimage so two relays do not
/// share one network-wide decision for the same transaction.
fn fluff_roll_bps(node_salt: &[u8; 32], tx_id: &[u8; 32], epoch: u64) -> u16 {
    let mut w = Writer::new();
    w.push(node_salt);
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

    fn decide(
        relay: &mut DandelionRelay,
        tx_id: [u8; 32],
        peer_list: &[String],
        now: Instant,
        role: RelayRole,
    ) -> RelayAction {
        relay.decide(tx_id, b"tx-wire", peer_list, None, now, role)
    }

    #[test]
    fn disabled_always_fluffs() {
        let mut relay = DandelionRelay::new(DandelionConfig::default(), [1u8; 32]);
        let action = decide(
            &mut relay,
            [9u8; 32],
            &peers(3),
            Instant::now(),
            RelayRole::Origin,
        );
        assert_eq!(action, RelayAction::Fluff);
    }

    #[test]
    fn origin_never_fluffs_itself() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 10_000;
        let mut relay = DandelionRelay::new(cfg, [3u8; 32]);
        let now = Instant::now();
        assert!(matches!(
            decide(&mut relay, [4u8; 32], &peers(3), now, RelayRole::Origin),
            RelayAction::Stem { .. }
        ));
        assert_eq!(
            decide(&mut relay, [5u8; 32], &peers(3), now, RelayRole::StemRelay),
            RelayAction::Fluff
        );
    }

    #[test]
    fn enabled_zero_fluff_probability_stems() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 0;
        let mut relay = DandelionRelay::new(cfg, [2u8; 32]);
        match decide(
            &mut relay,
            [1u8; 32],
            &peers(3),
            Instant::now(),
            RelayRole::StemRelay,
        ) {
            RelayAction::Stem { peer } => assert!(peer.starts_with("127.0.0.1:")),
            other => panic!("expected stem, got {other:?}"),
        }
    }

    #[test]
    fn inbound_fluff_stays_fluff() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 0;
        let mut relay = DandelionRelay::new(cfg, [4u8; 32]);
        assert_eq!(
            decide(
                &mut relay,
                [8u8; 32],
                &peers(3),
                Instant::now(),
                RelayRole::FluffRelay
            ),
            RelayAction::Fluff
        );
    }

    #[test]
    fn hop_fluff_depends_on_node_salt() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 5_000;
        let peer_list = peers(4);
        let now = Instant::now();
        let mut diverged = false;
        for n in 0u32..400 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&n.to_le_bytes());
            let mut a = DandelionRelay::new(cfg.clone(), [1u8; 32]);
            let mut b = DandelionRelay::new(cfg.clone(), [2u8; 32]);
            let a_fluff = matches!(
                decide(&mut a, id, &peer_list, now, RelayRole::StemRelay),
                RelayAction::Fluff
            );
            let b_fluff = matches!(
                decide(&mut b, id, &peer_list, now, RelayRole::StemRelay),
                RelayAction::Fluff
            );
            if a_fluff != b_fluff {
                diverged = true;
                break;
            }
        }
        assert!(
            diverged,
            "stem relays must not share one fluff coin for the same tx"
        );
    }

    #[test]
    fn stem_timeout_forces_fluff_without_a_second_arrival() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 0;
        cfg.stem_timeout = Duration::from_secs(30);
        let mut relay = DandelionRelay::new(cfg, [5u8; 32]);
        let t0 = Instant::now();
        assert!(matches!(
            decide(&mut relay, [6u8; 32], &peers(3), t0, RelayRole::Origin),
            RelayAction::Stem { .. }
        ));
        let expired = relay.take_expired(t0 + Duration::from_secs(30));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, b"tx-wire");
        assert!(relay.take_expired(t0 + Duration::from_secs(31)).is_empty());
    }

    #[test]
    fn second_sight_after_timeout_fluffs() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 0;
        cfg.stem_timeout = Duration::from_secs(10);
        let mut relay = DandelionRelay::new(cfg, [5u8; 32]);
        let t0 = Instant::now();
        assert!(matches!(
            decide(&mut relay, [6u8; 32], &peers(3), t0, RelayRole::StemRelay),
            RelayAction::Stem { .. }
        ));
        assert_eq!(
            decide(
                &mut relay,
                [6u8; 32],
                &peers(3),
                t0 + Duration::from_secs(10),
                RelayRole::StemRelay
            ),
            RelayAction::Fluff
        );
    }

    #[test]
    fn empty_peer_set_holds_for_embargo() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 0;
        cfg.stem_timeout = Duration::from_secs(5);
        let mut relay = DandelionRelay::new(cfg, [9u8; 32]);
        let t0 = Instant::now();
        assert_eq!(
            decide(&mut relay, [1u8; 32], &[], t0, RelayRole::Origin),
            RelayAction::Hold
        );
        let expired = relay.take_expired(t0 + Duration::from_secs(5));
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn single_peer_stems_to_only_candidate() {
        let mut relay = DandelionRelay::new(DandelionConfig::enabled(), [7u8; 32]);
        let ps = peers(1);
        assert_eq!(
            decide(
                &mut relay,
                [8u8; 32],
                &ps,
                Instant::now(),
                RelayRole::Origin
            ),
            RelayAction::Stem {
                peer: ps[0].clone()
            }
        );
    }

    #[test]
    fn pending_cap_fluffs_instead_of_growing() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 0;
        let mut relay = DandelionRelay::new(cfg, [11u8; 32]);
        let now = Instant::now();
        let peer_list = peers(2);
        for n in 0..MAX_PENDING_STEMS {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&(n as u32).to_le_bytes());
            assert!(matches!(
                decide(&mut relay, id, &peer_list, now, RelayRole::Origin),
                RelayAction::Stem { .. }
            ));
        }
        let mut overflow = [0u8; 32];
        overflow[31] = 0xff;
        assert_eq!(
            decide(&mut relay, overflow, &peer_list, now, RelayRole::Origin),
            RelayAction::Fluff
        );
    }

    #[test]
    fn oversized_stem_body_fluffs() {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 0;
        let mut relay = DandelionRelay::new(cfg, [12u8; 32]);
        let big = vec![0u8; MAX_STEM_WIRE_BYTES + 1];
        assert!(matches!(
            relay.decide(
                [1u8; 32],
                &big,
                &peers(2),
                None,
                Instant::now(),
                RelayRole::Origin
            ),
            RelayAction::Stem { .. }
        ));
        assert_eq!(
            relay.decide(
                [2u8; 32],
                &big,
                &[],
                None,
                Instant::now(),
                RelayRole::Origin
            ),
            RelayAction::Fluff
        );
    }

    #[test]
    fn stem_jitter_is_bounded_and_stable() {
        let relay = DandelionRelay::new(DandelionConfig::enabled(), [13u8; 32]);
        let now = Instant::now();
        let d1 = relay.stem_send_delay(&[4u8; 32], now);
        let d2 = relay.stem_send_delay(&[4u8; 32], now);
        assert_eq!(d1, d2);
        assert!(!d1.is_zero());
        assert!(d1 <= Duration::from_millis(250));
        let off = DandelionRelay::new(DandelionConfig::default(), [13u8; 32]);
        assert!(off.stem_send_delay(&[4u8; 32], now).is_zero());
    }
}
