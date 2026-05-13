//! In-memory chain driver.
//!
//! The `Chain` struct owns a [`ChainState`] and applies blocks
//! sequentially. It's the smallest possible "running chain in a process"
//! artifact — no IO, no clock, no async runtime. Higher layers (mempool,
//! producer loop, RPC, P2P) will eventually attach *around* this driver.
//!
//! ## Lifecycle
//!
//! ```text
//!   Chain::from_genesis(cfg)          ──► tip_height = Some(0)
//!     │
//!     ├── chain.apply(block_1)?       ──► tip_height = Some(1)
//!     ├── chain.apply(block_2)?       ──► tip_height = Some(2)
//!     └── …
//! ```
//!
//! ## Invariants enforced by this driver
//!
//! - The chain starts at the genesis block produced by
//!   [`mfn_consensus::build_genesis`] using a caller-supplied
//!   [`GenesisConfig`]. `tip_height` is `Some(0)` after construction.
//! - Every block applied through [`Chain::apply`] is validated by
//!   [`mfn_consensus::apply_block`]; failure leaves the chain state
//!   *unchanged* (the underlying STF is pure — we never partially commit
//!   an invalid block).
//! - On success the chain moves to the new tip and remembers its
//!   `block_id` (already tracked inside `ChainState.block_ids`).
//!
//! ## What this driver does *not* do
//!
//! - **No block production.** Building a candidate block from txs + a
//!   slot context + producer keys is a separate concern; the harness in
//!   `tests/single_validator_flow.rs` shows the wiring, and a dedicated
//!   `producer` module will land in a later M2.x milestone.
//! - **No re-org / fork choice.** Single canonical chain only. Re-orgs
//!   become relevant once the P2P layer feeds the node forks from peers.
//! - **No persistent IO.** The deterministic byte codec for full chain
//!   state lives at [`mfn_consensus::chain_checkpoint`] (M2.0.15); this
//!   driver only exposes the in-memory [`Chain::checkpoint`] and
//!   [`Chain::from_checkpoint`] adaptors over it. The actual on-disk
//!   layout (file path, RocksDB column families, …) is the daemon's
//!   responsibility and intentionally not encoded here.
//! - **No clock.** The producer is the source of truth for
//!   `header.timestamp`; the chain just enforces strict monotonicity.

use mfn_consensus::{
    apply_block, apply_genesis, build_genesis, decode_chain_checkpoint, encode_chain_checkpoint,
    ApplyOutcome, Block, BlockError, ChainCheckpoint, ChainCheckpointError, ChainState,
    GenesisConfig, Validator,
};

/// Configuration for constructing a [`Chain`] from genesis.
///
/// A thin wrapper around [`GenesisConfig`]. We keep it as a distinct type
/// so future fields (data-directory path, log-file path, peer seeds, …)
/// can attach without re-shuffling the consensus-spec type.
#[derive(Clone, Debug)]
pub struct ChainConfig {
    /// The genesis configuration to bootstrap from. Consumed once on
    /// construction.
    pub genesis: GenesisConfig,
}

impl ChainConfig {
    /// Build a config from a bare [`GenesisConfig`].
    #[must_use]
    pub fn new(genesis: GenesisConfig) -> Self {
        Self { genesis }
    }
}

/// Lightweight snapshot of the chain's vital statistics.
///
/// Cheap to compute on every call — no allocation, no clones of the
/// underlying state. Intended for diagnostic logging, RPC `chain/info`
/// endpoints, and assertion-style tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainStats {
    /// Current tip height (`None` only if construction failed — see
    /// [`ChainError::PreGenesis`]). For a successfully-constructed
    /// [`Chain`] this is always `Some`.
    pub height: Option<u32>,
    /// Current tip's `block_id` (`None` before any block — never the
    /// case for a successfully-constructed [`Chain`]).
    pub tip_id: Option<[u8; 32]>,
    /// Number of active validators (post-rotation).
    pub validator_count: usize,
    /// Sum of all active validator stakes.
    pub total_stake: u64,
    /// Permanence treasury balance, in base units.
    pub treasury: u128,
}

/// Errors produced by the [`Chain`] driver.
///
/// Wraps [`BlockError`] from the consensus layer in a single variant and
/// adds chain-driver-level errors (operations that aren't even
/// applicable until the chain has reached genesis).
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The chain hasn't reached the genesis block yet. This is
    /// vestigial for the current driver (we always genesis-ize on
    /// construction) but exists so future "delayed-genesis" flows can
    /// surface a typed error rather than panicking.
    #[error("chain has not reached genesis yet")]
    PreGenesis,

    /// The genesis block returned by [`mfn_consensus::build_genesis`]
    /// failed to apply (almost always a malformed [`GenesisConfig`]).
    #[error("genesis application failed: {0}")]
    Genesis(BlockError),

    /// One or more consensus checks failed when applying a block.
    /// Carries the proposed block's id (so callers can log it) plus
    /// the full structured error list from `apply_block`.
    #[error("apply_block rejected block {hex}: {errors:?}", hex = hex_id(block_id))]
    Reject {
        /// `block_id` of the rejected proposal (header bytes hash).
        block_id: [u8; 32],
        /// Structured rejection reasons.
        errors: Vec<BlockError>,
    },

    /// The chain checkpoint passed to [`Chain::from_checkpoint`] failed
    /// to decode (bad magic, integrity tag mismatch, truncated payload,
    /// duplicate validator index, …). Wraps the underlying
    /// [`ChainCheckpointError`].
    #[error("chain checkpoint decode failed: {0}")]
    CheckpointDecode(#[from] ChainCheckpointError),

    /// The caller's [`ChainConfig::genesis`] does not match the
    /// `genesis_id` embedded in the checkpoint. A restored chain must
    /// be re-attached to its **own** genesis to preserve replay
    /// determinism — restoring against the wrong genesis would silently
    /// hand the daemon a chain that disagrees with the rest of the
    /// network on `chain_id`.
    #[error(
        "checkpoint genesis_id {hex_checkpoint} does not match local genesis {hex_local}",
        hex_checkpoint = hex_id(expected),
        hex_local = hex_id(got)
    )]
    GenesisMismatch {
        /// The `genesis_id` encoded inside the checkpoint payload.
        expected: [u8; 32],
        /// The `genesis_id` derived from the caller-supplied
        /// [`ChainConfig::genesis`].
        got: [u8; 32],
    },
}

fn hex_id(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// In-memory chain driver.
///
/// Owns a [`ChainState`]; every successful [`Chain::apply`] swaps the
/// state for the next tip. The driver is intentionally minimal — it
/// hands out read-only views of the underlying state via accessor
/// methods rather than exposing `&mut ChainState`, so callers can't
/// sidestep `apply_block` and mutate the chain.
///
/// `Chain` is `!Sync` by composition (the inner state contains
/// `HashMap`s and `Vec`s) — wrap it in a `Mutex` if you need shared
/// access across threads. The intended usage pattern is single-owner /
/// single-task; the producer / RPC handlers (future) will channel
/// requests *to* the chain rather than locking it.
#[derive(Debug)]
pub struct Chain {
    state: ChainState,
    /// Cached genesis block id, so we can answer "what's our chain id"
    /// queries without re-hashing every time.
    genesis_id: [u8; 32],
}

impl Chain {
    /// Build a chain from genesis.
    ///
    /// Runs [`build_genesis`] → [`apply_genesis`] and stores the result.
    /// `tip_height` is `Some(0)` after this returns successfully.
    ///
    /// # Errors
    ///
    /// [`ChainError::Genesis`] if the genesis block fails to apply
    /// (e.g. invalid endowment / emission / bonding params in the
    /// [`GenesisConfig`]).
    pub fn from_genesis(cfg: ChainConfig) -> Result<Self, ChainError> {
        let genesis = build_genesis(&cfg.genesis);
        let genesis_id = mfn_consensus::block_id(&genesis.header);
        let state = apply_genesis(&genesis, &cfg.genesis).map_err(ChainError::Genesis)?;
        Ok(Self { state, genesis_id })
    }

    /// Apply a candidate block to the chain.
    ///
    /// On success the chain moves to the new tip and the new
    /// [`ChainState`] is held internally. On failure the chain is
    /// untouched (apply_block is pure; we never partially commit).
    ///
    /// # Errors
    ///
    /// [`ChainError::Reject`] with the proposed `block_id` and the
    /// structured rejection list from [`apply_block`].
    pub fn apply(&mut self, block: &Block) -> Result<[u8; 32], ChainError> {
        match apply_block(&self.state, block) {
            ApplyOutcome::Ok { state, block_id } => {
                self.state = state;
                Ok(block_id)
            }
            ApplyOutcome::Err { errors, block_id } => Err(ChainError::Reject { block_id, errors }),
        }
    }

    /// Genesis block id — fixed for the lifetime of the chain.
    #[must_use]
    pub fn genesis_id(&self) -> &[u8; 32] {
        &self.genesis_id
    }

    /// Read-only view of the current chain state.
    ///
    /// Intended for RPC handlers, diagnostics, and tests. Mutating the
    /// chain is only possible via [`Chain::apply`].
    #[must_use]
    pub fn state(&self) -> &ChainState {
        &self.state
    }

    /// Current tip height (`Some(0)` immediately after construction).
    #[must_use]
    pub fn tip_height(&self) -> Option<u32> {
        self.state.height
    }

    /// Current tip's `block_id`. For a successfully-constructed chain
    /// this is always `Some`.
    #[must_use]
    pub fn tip_id(&self) -> Option<&[u8; 32]> {
        self.state.tip_id()
    }

    /// Active validator set (post-rotation).
    #[must_use]
    pub fn validators(&self) -> &[Validator] {
        &self.state.validators
    }

    /// Permanence-treasury balance, in base units.
    #[must_use]
    pub fn treasury(&self) -> u128 {
        self.state.treasury
    }

    /// Sum of all active validator stakes.
    #[must_use]
    pub fn total_stake(&self) -> u64 {
        self.state.validators.iter().map(|v| v.stake).sum()
    }

    /// Cheap snapshot of vital chain stats. See [`ChainStats`].
    #[must_use]
    pub fn stats(&self) -> ChainStats {
        ChainStats {
            height: self.state.height,
            tip_id: self.state.tip_id().copied(),
            validator_count: self.state.validators.len(),
            total_stake: self.total_stake(),
            treasury: self.state.treasury,
        }
    }

    /* ------------------------------------------------------------- *
     *  Persistence (M2.0.15)                                          *
     * ------------------------------------------------------------- */

    /// Bundle the chain's current [`ChainState`] and `genesis_id` into
    /// an owned [`ChainCheckpoint`] suitable for serialisation via
    /// [`Chain::encode_checkpoint`] or any other byte codec. Cheap —
    /// the only cost is cloning the underlying state.
    #[must_use]
    pub fn checkpoint(&self) -> ChainCheckpoint {
        ChainCheckpoint {
            genesis_id: self.genesis_id,
            state: self.state.clone(),
        }
    }

    /// Encode the chain's current state to the canonical byte form
    /// (magic + version + payload + integrity tag) so it can be
    /// persisted to disk, streamed to a snapshot service, or shipped
    /// to a peer. See [`mfn_consensus::chain_checkpoint`] for the wire
    /// layout and on-disk guarantees.
    ///
    /// Bytes produced here always round-trip through
    /// [`Chain::from_checkpoint_bytes`] — calling
    /// `Chain::encode_checkpoint` twice on a chain with the same state
    /// yields byte-identical output.
    #[must_use]
    pub fn encode_checkpoint(&self) -> Vec<u8> {
        encode_chain_checkpoint(&self.checkpoint())
    }

    /// Restore a [`Chain`] from a decoded [`ChainCheckpoint`].
    ///
    /// Verifies the checkpoint's `genesis_id` matches the
    /// `ChainConfig`-derived genesis — restoring with a foreign
    /// genesis would silently fork the daemon off the rest of the
    /// network on `chain_id`.
    ///
    /// # Errors
    ///
    /// - [`ChainError::GenesisMismatch`] when the checkpoint's
    ///   `genesis_id` differs from the local one.
    pub fn from_checkpoint(
        cfg: ChainConfig,
        checkpoint: ChainCheckpoint,
    ) -> Result<Self, ChainError> {
        let genesis = build_genesis(&cfg.genesis);
        let local_genesis_id = mfn_consensus::block_id(&genesis.header);
        if local_genesis_id != checkpoint.genesis_id {
            return Err(ChainError::GenesisMismatch {
                expected: checkpoint.genesis_id,
                got: local_genesis_id,
            });
        }
        Ok(Self {
            state: checkpoint.state,
            genesis_id: checkpoint.genesis_id,
        })
    }

    /// Decode + restore a [`Chain`] from canonical checkpoint bytes
    /// produced by [`Chain::encode_checkpoint`].
    ///
    /// # Errors
    ///
    /// - [`ChainError::CheckpointDecode`] when the byte payload is
    ///   malformed (bad magic, integrity tag mismatch, truncation, …).
    /// - [`ChainError::GenesisMismatch`] when the checkpoint's
    ///   `genesis_id` differs from the caller-supplied
    ///   [`ChainConfig`]'s genesis.
    pub fn from_checkpoint_bytes(cfg: ChainConfig, bytes: &[u8]) -> Result<Self, ChainError> {
        let checkpoint = decode_chain_checkpoint(bytes).map_err(ChainError::CheckpointDecode)?;
        Self::from_checkpoint(cfg, checkpoint)
    }
}

/* ----------------------------------------------------------------------- *
 *  Unit tests                                                              *
 * ----------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_consensus::{
        build_unsealed_header, seal_block, ConsensusParams, GenesisConfig, DEFAULT_EMISSION_PARAMS,
    };
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    fn empty_genesis_cfg() -> GenesisConfig {
        GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: ConsensusParams {
                expected_proposers_per_slot: 1.0,
                quorum_stake_bps: 6667,
                ..ConsensusParams::default()
            },
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        }
    }

    /// Smoke test: `Chain::from_genesis` lands at height 0 and the
    /// genesis_id matches the tip_id.
    #[test]
    fn from_genesis_lands_at_height_zero() {
        let chain = Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis");
        assert_eq!(chain.tip_height(), Some(0));
        assert_eq!(chain.tip_id(), Some(chain.genesis_id()));
        assert_eq!(chain.validators().len(), 0);
        assert_eq!(chain.treasury(), 0);
    }

    /// Apply two empty (no-validator, no-tx) blocks back-to-back and
    /// verify the chain advances height + tip_id each time.
    #[test]
    fn apply_two_empty_blocks_in_sequence() {
        let mut chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis");
        let g_id = *chain.genesis_id();

        let unsealed_b1 = build_unsealed_header(chain.state(), &[], &[], &[], &[], 1, 100);
        assert_eq!(unsealed_b1.prev_hash, g_id);
        let b1 = seal_block(
            unsealed_b1,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let id_b1 = chain.apply(&b1).expect("apply b1");
        assert_eq!(chain.tip_height(), Some(1));
        assert_eq!(chain.tip_id(), Some(&id_b1));

        let unsealed_b2 = build_unsealed_header(chain.state(), &[], &[], &[], &[], 2, 200);
        assert_eq!(unsealed_b2.prev_hash, id_b1);
        let b2 = seal_block(
            unsealed_b2,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let id_b2 = chain.apply(&b2).expect("apply b2");
        assert_eq!(chain.tip_height(), Some(2));
        assert_eq!(chain.tip_id(), Some(&id_b2));
        assert_ne!(id_b1, id_b2);
    }

    /// A block with the wrong `prev_hash` is rejected and the chain
    /// state is left untouched (no partial mutation).
    #[test]
    fn block_with_wrong_prev_hash_is_rejected_state_untouched() {
        let mut chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis");
        let snapshot = chain.stats();

        // Build a valid header, then flip prev_hash.
        let mut unsealed = build_unsealed_header(chain.state(), &[], &[], &[], &[], 1, 100);
        unsealed.prev_hash[0] ^= 0xff;
        let bad = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let err = chain.apply(&bad).expect_err("must reject");
        match err {
            ChainError::Reject { errors, .. } => {
                assert!(
                    errors
                        .iter()
                        .any(|e| matches!(e, BlockError::PrevHashMismatch)),
                    "expected PrevHashMismatch in {errors:?}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // State must be completely unchanged.
        assert_eq!(chain.stats(), snapshot);
    }

    /// A block with the wrong height is rejected; state untouched.
    #[test]
    fn block_with_wrong_height_is_rejected() {
        let mut chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis");
        let snapshot = chain.stats();

        let mut unsealed = build_unsealed_header(chain.state(), &[], &[], &[], &[], 1, 100);
        unsealed.height = 42; // not next-up
        let bad = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let err = chain.apply(&bad).expect_err("must reject");
        match err {
            ChainError::Reject { errors, .. } => {
                assert!(
                    errors
                        .iter()
                        .any(|e| matches!(e, BlockError::BadHeight { .. })),
                    "expected BadHeight in {errors:?}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(chain.stats(), snapshot);
    }

    /// `ChainStats` accurately reflects post-block state across
    /// multiple blocks.
    #[test]
    fn stats_track_block_application() {
        let mut chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis");
        let s0 = chain.stats();
        assert_eq!(s0.height, Some(0));
        assert_eq!(s0.validator_count, 0);
        assert_eq!(s0.total_stake, 0);
        assert_eq!(s0.treasury, 0);

        let unsealed = build_unsealed_header(chain.state(), &[], &[], &[], &[], 1, 100);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        chain.apply(&blk).expect("apply");
        let s1 = chain.stats();
        assert_eq!(s1.height, Some(1));
        assert_ne!(s1.tip_id, s0.tip_id);
    }

    /// Two chains constructed from the same `GenesisConfig` must
    /// produce byte-identical genesis ids — determinism is what makes
    /// every other property (block ids, light-client verification,
    /// chain-replay correctness) possible.
    #[test]
    fn genesis_is_deterministic_across_constructions() {
        let cfg_a = ChainConfig::new(empty_genesis_cfg());
        let cfg_b = ChainConfig::new(empty_genesis_cfg());
        let a = Chain::from_genesis(cfg_a).expect("a");
        let b = Chain::from_genesis(cfg_b).expect("b");
        assert_eq!(
            a.genesis_id(),
            b.genesis_id(),
            "same config must yield same genesis id"
        );
        // And both chains agree on every field at height 0.
        assert_eq!(a.tip_height(), b.tip_height());
        assert_eq!(a.stats(), b.stats());
    }

    /// The genesis block's tip_id is recorded as the chain's
    /// genesis_id — they must always be equal at height 0.
    #[test]
    fn tip_id_equals_genesis_id_at_construction() {
        let chain = Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis");
        assert_eq!(chain.tip_id(), Some(chain.genesis_id()));
    }

    /* --------------------------------------------------------------- *
     *  Persistence (M2.0.15)                                            *
     * --------------------------------------------------------------- */

    fn apply_one_empty_block(chain: &mut Chain, slot: u32, ts: u64) {
        let unsealed = build_unsealed_header(chain.state(), &[], &[], &[], &[], slot, ts);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        chain.apply(&blk).expect("apply");
    }

    /// `Chain::checkpoint` returns a bundle that round-trips through
    /// the codec, and the restored chain has byte-identical encoded
    /// state.
    #[test]
    fn checkpoint_round_trip_at_genesis() {
        let chain = Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis");
        let bytes = chain.encode_checkpoint();
        let restored = Chain::from_checkpoint_bytes(ChainConfig::new(empty_genesis_cfg()), &bytes)
            .expect("restore");
        assert_eq!(restored.genesis_id(), chain.genesis_id());
        assert_eq!(restored.tip_id(), chain.tip_id());
        assert_eq!(restored.tip_height(), chain.tip_height());
        assert_eq!(restored.stats(), chain.stats());
        // Re-encoding the restored chain must produce identical bytes.
        let bytes2 = restored.encode_checkpoint();
        assert_eq!(bytes, bytes2);
    }

    /// After applying three blocks, encode + decode and verify the
    /// resulting chain agrees with the original on every diagnostic
    /// (tip_id, tip_height, stats) and on the canonical re-encoded
    /// bytes.
    #[test]
    fn checkpoint_after_three_blocks_round_trips() {
        let mut chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis");
        apply_one_empty_block(&mut chain, 1, 100);
        apply_one_empty_block(&mut chain, 2, 200);
        apply_one_empty_block(&mut chain, 3, 300);

        let bytes = chain.encode_checkpoint();
        let restored = Chain::from_checkpoint_bytes(ChainConfig::new(empty_genesis_cfg()), &bytes)
            .expect("restore");
        assert_eq!(restored.tip_height(), chain.tip_height());
        assert_eq!(restored.tip_id(), chain.tip_id());
        assert_eq!(restored.genesis_id(), chain.genesis_id());
        assert_eq!(restored.stats(), chain.stats());
        assert_eq!(restored.encode_checkpoint(), bytes);

        // And the restored chain can keep advancing in lockstep with
        // the original from the same next block.
        let unsealed = build_unsealed_header(chain.state(), &[], &[], &[], &[], 4, 400);
        let blk = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut restored = restored;
        let id_orig = chain.apply(&blk).expect("orig advance");
        let id_rest = restored.apply(&blk).expect("restored advance");
        assert_eq!(id_orig, id_rest);
        assert_eq!(chain.tip_id(), restored.tip_id());
        assert_eq!(chain.encode_checkpoint(), restored.encode_checkpoint());
    }

    /// Restoring with the wrong genesis config produces
    /// `GenesisMismatch`, never silently rewires the chain.
    #[test]
    fn from_checkpoint_rejects_foreign_genesis() {
        let chain = Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis");
        let bytes = chain.encode_checkpoint();

        // The genesis timestamp is hashed into the genesis header
        // (and therefore the genesis_id); flipping it gives us a
        // distinct local-genesis to test the mismatch path.
        let mut foreign = empty_genesis_cfg();
        foreign.timestamp = 1_000_000;
        let err = Chain::from_checkpoint_bytes(ChainConfig::new(foreign), &bytes)
            .expect_err("must reject");
        match err {
            ChainError::GenesisMismatch { expected, got } => {
                assert_eq!(&expected, chain.genesis_id());
                assert_ne!(&got, chain.genesis_id());
            }
            other => panic!("expected GenesisMismatch, got {other:?}"),
        }
    }

    /// Tampered checkpoint bytes surface as a typed
    /// `CheckpointDecode` error rather than corrupting the new chain.
    #[test]
    fn from_checkpoint_bytes_rejects_tamper() {
        let chain = Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis");
        let mut bytes = chain.encode_checkpoint();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        let err = Chain::from_checkpoint_bytes(ChainConfig::new(empty_genesis_cfg()), &bytes)
            .expect_err("must reject");
        match err {
            ChainError::CheckpointDecode(ChainCheckpointError::IntegrityCheckFailed) => {}
            other => panic!("expected IntegrityCheckFailed, got {other:?}"),
        }
    }
}
