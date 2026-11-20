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

/// Default cap on stem bodies held under embargo at once (**G-11**).
pub const DEFAULT_MAX_PENDING_STEMS: usize = 1024;
/// Default cap on the total bytes of stem bodies held under embargo (**G-11**).
pub const DEFAULT_MAX_PENDING_STEM_BYTES: usize = 8 * 1024 * 1024;

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
    /// Most stem entries held at once. When full, the oldest relayed stem is
    /// force-fluffed early; the arriving tx still gets its stem. `0` acts as `1`.
    pub max_pending_stems: usize,
    /// Most bytes of stem bodies held at once. One body larger than the whole
    /// budget is held alone and leaves on the next arrival.
    pub max_pending_stem_bytes: usize,
}

impl Default for DandelionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fluff_probability_bps: 900,
            epoch_secs: 600,
            stem_timeout: Duration::from_secs(30),
            stem_jitter: Duration::ZERO,
            max_pending_stems: DEFAULT_MAX_PENDING_STEMS,
            max_pending_stem_bytes: DEFAULT_MAX_PENDING_STEM_BYTES,
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
    /// Created by this node. Evicted only when no relayed stem is left.
    origin: bool,
}

/// In-memory stem-phase tracker for one `mfnd` process.
///
/// The pending set is bounded by [`DandelionConfig::max_pending_stems`] and
/// [`DandelionConfig::max_pending_stem_bytes`]. A peer that floods stem
/// transactions cannot grow this node's memory past those caps: the oldest
/// relayed stem leaves early through [`DandelionRelay::take_expired`] and is
/// fluffed, which is the same fail-safe the embargo timer applies. Bodies this
/// node created are evicted last, so a flood never turns an origin stem into
/// an immediate fluff.
pub struct DandelionRelay {
    config: DandelionConfig,
    node_salt: [u8; 32],
    pending: HashMap<[u8; 32], PendingStem>,
    pending_bytes: usize,
    /// Bodies forced out of the stem set before their embargo elapsed.
    evicted: Vec<Vec<u8>>,
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
            pending_bytes: 0,
            evicted: Vec::new(),
            started: Instant::now(),
        }
    }

    /// Whether stem/fluff routing is active (vs legacy parallel fan-out).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Stem entries currently under embargo.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Bytes of stem bodies currently under embargo.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// Track `tx_id` under embargo. An id already tracked keeps its first entry.
    fn track(&mut self, tx_id: [u8; 32], tx_wire: &[u8], now: Instant, origin: bool) {
        if self.pending.contains_key(&tx_id) {
            return;
        }
        self.make_room(tx_wire.len());
        self.pending_bytes = self.pending_bytes.saturating_add(tx_wire.len());
        self.pending.insert(
            tx_id,
            PendingStem {
                first_seen: now,
                tx_wire: tx_wire.to_vec(),
                origin,
            },
        );
    }

    fn untrack(&mut self, tx_id: &[u8; 32]) -> Option<PendingStem> {
        let entry = self.pending.remove(tx_id)?;
        self.pending_bytes = self.pending_bytes.saturating_sub(entry.tx_wire.len());
        Some(entry)
    }

    /// Evict until one more entry of `incoming` bytes fits. Relayed stems go
    /// first, oldest first; origin stems only when nothing else is left.
    fn make_room(&mut self, incoming: usize) {
        let max_entries = self.config.max_pending_stems.max(1);
        let max_bytes = self.config.max_pending_stem_bytes;
        while !self.pending.is_empty()
            && (self.pending.len() >= max_entries
                || self.pending_bytes.saturating_add(incoming) > max_bytes)
        {
            let Some(victim) = self.eviction_candidate() else {
                break;
            };
            if let Some(entry) = self.untrack(&victim) {
                if !entry.tx_wire.is_empty() {
                    self.evicted.push(entry.tx_wire);
                }
            }
        }
    }

    fn eviction_candidate(&self) -> Option<[u8; 32]> {
        let oldest = |origin: bool| {
            self.pending
                .iter()
                .filter(|(_, e)| e.origin == origin)
                .min_by_key(|(id, e)| (e.first_seen, **id))
                .map(|(id, _)| *id)
        };
        oldest(false).or_else(|| oldest(true))
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
            self.untrack(&tx_id);
            return RelayAction::Fluff;
        }
        self.track(tx_id, &[], now, false);
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
        let origin = hop == HopKind::Origin;
        if peers.is_empty() {
            self.track(tx_id, tx_wire, now, origin);
            return RelayAction::Hold;
        }
        if hop == HopKind::Relay {
            if let Some(entry) = self.pending.get(&tx_id) {
                if now.saturating_duration_since(entry.first_seen) >= self.config.stem_timeout {
                    self.untrack(&tx_id);
                    return RelayAction::Fluff;
                }
            } else if self.hop_fluffs(&tx_id, now) {
                return RelayAction::Fluff;
            }
        }
        self.track(tx_id, tx_wire, now, origin);
        let epoch = self.current_epoch(now);
        let idx = epoch_successor(&self.node_salt, epoch, peers.len());
        RelayAction::Stem {
            peer: peers[idx].clone(),
        }
    }

    /// Bodies whose stem embargo has elapsed, plus bodies the stem-set cap
    /// forced out early. The peer exclusion is unknown here.
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
        let mut out: Vec<(Vec<u8>, Option<String>)> = std::mem::take(&mut self.evicted)
            .into_iter()
            .map(|wire| (wire, None))
            .collect();
        out.reserve(expired.len());
        for id in expired {
            if let Some(entry) = self.untrack(&id) {
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

    fn bounded_cfg(max_entries: usize, max_bytes: usize) -> DandelionConfig {
        let mut cfg = DandelionConfig::enabled();
        cfg.fluff_probability_bps = 0;
        cfg.stem_timeout = Duration::from_secs(30);
        cfg.max_pending_stems = max_entries;
        cfg.max_pending_stem_bytes = max_bytes;
        cfg
    }

    fn id(n: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = n;
        out[31] = 0xA5;
        out
    }

    #[test]
    fn g11_defaults_bound_the_stem_set() {
        let cfg = DandelionConfig::default();
        assert_eq!(cfg.max_pending_stems, DEFAULT_MAX_PENDING_STEMS);
        assert_eq!(cfg.max_pending_stem_bytes, DEFAULT_MAX_PENDING_STEM_BYTES);
        let enabled = DandelionConfig::enabled();
        assert_eq!(enabled.max_pending_stems, DEFAULT_MAX_PENDING_STEMS);
        assert_eq!(
            enabled.max_pending_stem_bytes,
            DEFAULT_MAX_PENDING_STEM_BYTES
        );
        // One 4 MiB frame (the P2P payload cap) always fits the byte budget.
        assert!(cfg.max_pending_stem_bytes >= 4 * 1024 * 1024);
        assert!(cfg.max_pending_stems >= 64);
    }

    #[test]
    fn g11_relay_flood_cannot_exceed_the_entry_cap() {
        let mut relay = DandelionRelay::new(bounded_cfg(8, usize::MAX), [11u8; 32]);
        let ps = peers(3);
        let t0 = Instant::now();
        for i in 0..200u8 {
            let action = relay.forward(
                id(i),
                &[i; 64],
                &ps,
                t0 + Duration::from_millis(i.into()),
                HopKind::Relay,
            );
            assert!(
                matches!(action, RelayAction::Stem { .. }),
                "the arriving stem still stems under a flood (i={i})"
            );
            assert!(
                relay.pending_len() <= 8,
                "entries {} > cap at i={i}",
                relay.pending_len()
            );
        }
        assert_eq!(relay.pending_len(), 8);
        assert_eq!(relay.pending_bytes(), 8 * 64);
        let forced = relay.take_expired(t0 + Duration::from_secs(1));
        assert_eq!(
            forced.len(),
            192,
            "every evicted body is fluffed, not dropped"
        );
        assert_eq!(
            forced[0].0,
            vec![0u8; 64],
            "oldest relayed stem leaves first"
        );
        assert_eq!(forced[191].0, vec![191u8; 64]);
        assert!(relay.take_expired(t0 + Duration::from_secs(1)).is_empty());
        assert_eq!(
            relay.pending_len(),
            8,
            "the last eight wait for their embargo"
        );
    }

    #[test]
    fn g11_relay_flood_cannot_exceed_the_byte_cap() {
        let mut relay = DandelionRelay::new(bounded_cfg(usize::MAX, 1000), [12u8; 32]);
        let ps = peers(2);
        let t0 = Instant::now();
        for i in 0..50u8 {
            relay.forward(
                id(i),
                &[i; 300],
                &ps,
                t0 + Duration::from_millis(i.into()),
                HopKind::Relay,
            );
            assert!(
                relay.pending_bytes() <= 1000,
                "bytes {} > cap at i={i}",
                relay.pending_bytes()
            );
        }
        assert_eq!(relay.pending_len(), 3);
        assert_eq!(relay.pending_bytes(), 900);
        assert_eq!(relay.take_expired(t0).len(), 47);
    }

    #[test]
    fn g11_one_body_over_the_whole_budget_is_held_alone() {
        let mut relay = DandelionRelay::new(bounded_cfg(usize::MAX, 100), [13u8; 32]);
        let ps = peers(2);
        let t0 = Instant::now();
        relay.forward(id(1), &[1u8; 40], &ps, t0, HopKind::Relay);
        relay.forward(
            id(2),
            &[2u8; 500],
            &ps,
            t0 + Duration::from_millis(1),
            HopKind::Relay,
        );
        assert_eq!(
            relay.pending_len(),
            1,
            "the small body made room; the big one is held"
        );
        assert_eq!(relay.pending_bytes(), 500);
        relay.forward(
            id(3),
            &[3u8; 40],
            &ps,
            t0 + Duration::from_millis(2),
            HopKind::Relay,
        );
        assert_eq!(relay.pending_len(), 1);
        assert_eq!(
            relay.pending_bytes(),
            40,
            "the oversize body leaves on the next arrival"
        );
        let forced = relay.take_expired(t0);
        assert_eq!(forced.len(), 2);
        assert_eq!(forced[1].0.len(), 500);
    }

    #[test]
    fn g11_flood_evicts_relayed_stems_before_an_origin_stem() {
        let mut relay = DandelionRelay::new(bounded_cfg(4, usize::MAX), [14u8; 32]);
        let ps = peers(3);
        let t0 = Instant::now();
        let mine = id(0xEE);
        assert!(matches!(
            relay.forward(mine, b"mine", &ps, t0, HopKind::Origin),
            RelayAction::Stem { .. }
        ));
        for i in 1..=40u8 {
            relay.forward(
                id(i),
                &[i; 16],
                &ps,
                t0 + Duration::from_millis(i.into()),
                HopKind::Relay,
            );
        }
        assert_eq!(relay.pending_len(), 4);
        let forced = relay.take_expired(t0 + Duration::from_secs(1));
        assert_eq!(forced.len(), 37);
        assert!(
            forced.iter().all(|(wire, _)| wire.as_slice() != b"mine"),
            "the origin body is never force-fluffed while relayed stems remain"
        );
        let own_embargo = relay.take_expired(t0 + Duration::from_secs(30));
        assert!(
            own_embargo
                .iter()
                .any(|(wire, _)| wire.as_slice() == b"mine"),
            "the origin body still fluffs at its own embargo"
        );
    }

    #[test]
    fn g11_hold_without_peers_is_bounded_too() {
        let mut relay = DandelionRelay::new(bounded_cfg(2, usize::MAX), [15u8; 32]);
        let t0 = Instant::now();
        for i in 0..10u8 {
            assert_eq!(
                relay.forward(
                    id(i),
                    &[i; 8],
                    &[],
                    t0 + Duration::from_millis(i.into()),
                    HopKind::Relay
                ),
                RelayAction::Hold
            );
        }
        assert_eq!(relay.pending_len(), 2);
        assert_eq!(relay.take_expired(t0).len(), 8);
    }

    #[test]
    fn g11_decide_tracks_without_bodies_and_stays_bounded() {
        let mut relay = DandelionRelay::new(bounded_cfg(3, usize::MAX), [16u8; 32]);
        let ps = peers(3);
        let t0 = Instant::now();
        for i in 0..30u8 {
            relay.decide(id(i), &ps, t0 + Duration::from_millis(i.into()));
        }
        assert_eq!(relay.pending_len(), 3);
        assert_eq!(relay.pending_bytes(), 0);
        assert!(
            relay.take_expired(t0).is_empty(),
            "entries without a body have nothing to fluff"
        );
    }

    #[test]
    fn g11_repeat_of_a_tracked_id_keeps_its_first_entry() {
        let mut relay = DandelionRelay::new(bounded_cfg(4, usize::MAX), [17u8; 32]);
        let ps = peers(2);
        let t0 = Instant::now();
        relay.forward(id(1), &[1u8; 10], &ps, t0, HopKind::Relay);
        relay.forward(
            id(1),
            &[1u8; 10],
            &ps,
            t0 + Duration::from_secs(1),
            HopKind::Relay,
        );
        assert_eq!(relay.pending_len(), 1);
        assert_eq!(relay.pending_bytes(), 10);
        assert_eq!(
            relay.take_expired(t0 + Duration::from_secs(30)).len(),
            1,
            "the embargo is measured from the first sighting"
        );
        assert_eq!(relay.pending_bytes(), 0);
    }

    #[test]
    fn g11_disabled_relay_tracks_nothing() {
        let mut relay = DandelionRelay::new(DandelionConfig::default(), [18u8; 32]);
        let ps = peers(2);
        for i in 0..5u8 {
            relay.forward(id(i), &[i; 8], &ps, Instant::now(), HopKind::Relay);
        }
        assert_eq!(relay.pending_len(), 0);
        assert_eq!(relay.pending_bytes(), 0);
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
