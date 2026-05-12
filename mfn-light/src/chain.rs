//! Light-client chain follower.
//!
//! The [`LightChain`] struct owns:
//!
//! - The *trusted* validator set, evolved deterministically across
//!   rotations via [`LightChain::apply_block`] (M2.0.8). The next
//!   block's `validator_root` is the cryptographic audit of the
//!   previous block's evolution — if the light client gets it wrong,
//!   `verify_header` fails with `ValidatorRootMismatch` on the very
//!   next block.
//! - The chain's [`ConsensusParams`] (for quorum threshold + slot-eligibility math).
//! - The chain's [`BondingParams`] (for entry/exit churn + unbond delay).
//! - The current tip's `block_id` and height.
//! - The fixed genesis `block_id` (for "what chain am I on?" queries).
//! - Shadow state required to derive the next validator set from the
//!   current one: `validator_stats` (per-validator liveness counters),
//!   `pending_unbonds` (in-flight exit queue), and the four bond-epoch
//!   counters (`bond_epoch_id`, `bond_epoch_entry_count`,
//!   `bond_epoch_exit_count`, `next_validator_index`).
//!
//! Every successful [`LightChain::apply_block`] swaps the tip pointer
//! for the next header AND evolves the trusted validator set so the
//! *next* block's header is verified against the right committee.
//!
//! ## What this driver does
//!
//! - [`LightChain::apply_header`] — header-only application (M2.0.6).
//!   Strict height/`prev_hash` linkage + [`verify_header`] cryptographic
//!   check + tip advance. Useful when the body isn't available yet
//!   (e.g. lightweight sync of *just* the header chain for inclusion
//!   proofs against a trusted checkpoint). **Does not** evolve the
//!   validator set — header-only callers that need to follow across a
//!   rotation must either re-bootstrap or use `apply_block`.
//! - [`LightChain::apply_block`] — full block application (M2.0.7 + M2.0.8).
//!   Same linkage + header verification, plus stateless body
//!   verification via [`mfn_consensus::verify_block_body`] of the four
//!   header-bound body roots (`tx_root`, `bond_root`, `slashing_root`,
//!   `storage_proof_root`), plus byte-for-byte mirror of
//!   `mfn-consensus`'s validator-set evolution (equivocation slashing,
//!   liveness slashing, bond ops, unbond settlements). After a
//!   successful `apply_block`, the light client has cryptographic
//!   confidence that the delivered body is byte-for-byte the body the
//!   producer signed over AND its trusted validator set is the same
//!   set the next block's header will commit to.
//!
//! ## What this driver does NOT do (yet)
//!
//! - **No state-dependent body roots.** `storage_root` and `utxo_root`
//!   are functions of accumulated chain state, not pure functions of
//!   the block body. A stateless light client can't independently
//!   recompute them; they're already cryptographically covered by the
//!   BLS aggregate signing `header_signing_hash`.
//! - **No re-org / fork choice.** Single canonical header chain only.
//!   Future P2P / sync layers would attach re-org logic on top.
//! - **No persistence.** Tip pointer + trusted validators live in
//!   memory. Trivial to add via a separate `mfn-light::store` module.

use std::collections::BTreeMap;

use mfn_consensus::{
    apply_bond_ops_evolution, apply_equivocation_slashings, apply_liveness_evolution,
    apply_unbond_settlements, block_id, build_genesis, finality_bitmap_from_header,
    verify_block_body, verify_header, Block, BlockHeader, BodyVerifyError, BondEpochCounters,
    BondOpError, BondingParams, ConsensusParams, GenesisConfig, HeaderCheck, HeaderVerifyError,
    PendingUnbond, Validator, ValidatorStats, DEFAULT_BONDING_PARAMS,
};

/* ----------------------------------------------------------------------- *
 *  Config                                                                  *
 * ----------------------------------------------------------------------- */

/// Configuration for constructing a [`LightChain`] from genesis.
///
/// Thin wrapper around [`GenesisConfig`]. A distinct type so future
/// fields (trusted-checkpoint overrides, sync mode, peer seeds, …)
/// can attach without re-shuffling the consensus-spec type.
#[derive(Clone, Debug)]
pub struct LightChainConfig {
    /// The genesis configuration to bootstrap from.
    pub genesis: GenesisConfig,
}

impl LightChainConfig {
    /// Build a config from a bare [`GenesisConfig`].
    #[must_use]
    pub fn new(genesis: GenesisConfig) -> Self {
        Self { genesis }
    }
}

/* ----------------------------------------------------------------------- *
 *  Stats / outcome                                                         *
 * ----------------------------------------------------------------------- */

/// Cheap snapshot of the light-chain's vital statistics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LightChainStats {
    /// Current tip height (`0` immediately after construction).
    pub height: u32,
    /// Current tip's `block_id`.
    pub tip_id: [u8; 32],
    /// Genesis `block_id` (constant for the chain's lifetime).
    pub genesis_id: [u8; 32],
    /// Number of trusted validators.
    pub validator_count: usize,
    /// Sum of stake of all trusted validators.
    pub total_stake: u64,
}

/// Returned by [`LightChain::apply_header`] on success — carries the
/// new tip's `block_id` and the [`HeaderCheck`] from the underlying
/// `verify_header` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedHeader {
    /// `block_id` of the just-applied header (now the chain's tip).
    pub block_id: [u8; 32],
    /// Verification stats from [`verify_header`] — producer index,
    /// signing stake, quorum check, etc.
    pub check: HeaderCheck,
}

/// Returned by [`LightChain::apply_block`] on success — carries the
/// new tip's `block_id`, the [`HeaderCheck`] from the underlying
/// `verify_header` call, and summary counts of the validator-set
/// evolution that took place.
///
/// `validators_added`, `validators_slashed_equiv`, `validators_slashed_liveness`,
/// and `validators_unbond_settled` together describe everything that
/// changed in the trusted validator set as a result of applying this
/// block. Together with the new tip's `block_id`, the next block's
/// header (whose `validator_root` commits to the post-this-block
/// validator set) implicitly audits this evolution: if any count is
/// wrong, the next `apply_block` will fail with `HeaderVerify`
/// wrapping `ValidatorRootMismatch`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedBlock {
    /// `block_id` of the just-applied block (now the chain's tip).
    pub block_id: [u8; 32],
    /// Verification stats from [`verify_header`].
    pub check: HeaderCheck,
    /// Validators added to the trusted set this block (successful
    /// `BondOp::Register` ops).
    pub validators_added: u32,
    /// Validators whose stake was zeroed by equivocation slashing
    /// (canonical `SlashEvidence` entries that passed verification).
    pub validators_slashed_equivocation: u32,
    /// Validators whose stake was multiplicatively reduced by
    /// liveness auto-slashing on this block.
    pub validators_slashed_liveness: u32,
    /// Pending unbonds that settled (stake zeroed) this block.
    pub validators_unbond_settled: u32,
}

/* ----------------------------------------------------------------------- *
 *  Errors                                                                  *
 * ----------------------------------------------------------------------- */

/// Errors produced by [`LightChain`].
#[derive(Debug, thiserror::Error)]
pub enum LightChainError {
    /// `header.prev_hash` does not equal the current `tip_id`. Either
    /// the header is for a different chain, or there's a gap (the
    /// caller skipped a header).
    #[error(
        "prev_hash mismatch at height {height}: expected tip {expected_hex}, header committed {got_hex}",
        expected_hex = hex_id(expected),
        got_hex = hex_id(got),
    )]
    PrevHashMismatch {
        /// Height the offending header claims.
        height: u32,
        /// `block_id` the light chain expected for `prev_hash`.
        expected: [u8; 32],
        /// `prev_hash` the offending header actually carries.
        got: [u8; 32],
    },

    /// `header.height` is not exactly `tip_height + 1`. Light clients
    /// don't reorder or batch headers — they expect strict
    /// monotonicity.
    #[error("height mismatch: expected {expected}, header committed {got}")]
    HeightMismatch {
        /// Height the light chain expects next.
        expected: u32,
        /// Height the offending header actually claims.
        got: u32,
    },

    /// Cryptographic / structural verification of the header failed.
    /// See [`HeaderVerifyError`] for the specific reason.
    #[error("header verification failed at height {height}: {source}")]
    HeaderVerify {
        /// Height the offending header claims.
        height: u32,
        /// Specific cryptographic failure.
        source: HeaderVerifyError,
    },

    /// Body-root verification of the delivered block failed: at least
    /// one of `tx_root` / `bond_root` / `slashing_root` /
    /// `storage_proof_root` recomputed from `block.<field>` doesn't
    /// match the value the header claims. See [`BodyVerifyError`] for
    /// the specific root.
    ///
    /// **State invariant**: when this is returned by
    /// [`LightChain::apply_block`], the chain's tip and trusted
    /// validator set are unchanged.
    #[error("body verification failed at height {height}: {source}")]
    BodyMismatch {
        /// Height the offending block claims.
        height: u32,
        /// Specific body-root failure.
        source: BodyVerifyError,
    },

    /// Validator-set evolution failed: a bond op in `block.bond_ops`
    /// did not pass the same checks that
    /// [`mfn_consensus::apply_block`] applies (bad register signature,
    /// duplicate vrf_pk, churn budget exhausted, unknown validator
    /// for unbond, …).
    ///
    /// In an honest chain this should never happen: if 2/3-stake
    /// quorum signs a header committing to a bad bond-op list, that
    /// quorum is Byzantine. The light client still re-runs the same
    /// validity checks the full node does, so this variant is
    /// defense-in-depth.
    ///
    /// **State invariant**: when this is returned by
    /// [`LightChain::apply_block`], the chain's tip and trusted
    /// validator set are unchanged — `apply_block` is atomic.
    #[error("validator-set evolution failed at height {height}: bond op #{index}: {message}")]
    EvolutionFailed {
        /// Height the offending block claims.
        height: u32,
        /// 0-indexed position of the offending op in
        /// `block.bond_ops`.
        index: usize,
        /// Human-readable reason.
        message: String,
    },
}

fn hex_id(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        use core::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/* ----------------------------------------------------------------------- *
 *  LightChain                                                              *
 * ----------------------------------------------------------------------- */

/// Light-client chain follower.
///
/// Tracks the current tip, the genesis id, a trusted validator set,
/// and the shadow state required to evolve the trusted set across
/// rotations (per-validator liveness stats, pending-unbond queue,
/// bond-epoch counters). `apply_block` mirrors `mfn-consensus`'s
/// validator-set evolution byte-for-byte by calling the same pure
/// helper functions, so the light client cannot drift from the full
/// node's view of `trusted_validators_n` for any honest chain.
///
/// `LightChain` is `Send` (every field is `Send`) but `!Sync` by
/// default — wrap in a `Mutex` if shared across threads is needed.
/// The intended usage pattern is single-owner.
#[derive(Clone, Debug)]
pub struct LightChain {
    // ---- Identity + tip ----
    genesis_id: [u8; 32],
    tip_height: u32,
    tip_id: [u8; 32],
    // ---- Consensus / bonding params (frozen at genesis) ----
    params: ConsensusParams,
    bonding_params: BondingParams,
    // ---- Trusted validator set + shadow state for evolution (M2.0.8) ----
    trusted_validators: Vec<Validator>,
    validator_stats: Vec<ValidatorStats>,
    pending_unbonds: BTreeMap<u32, PendingUnbond>,
    bond_counters: BondEpochCounters,
}

impl LightChain {
    /// Build a light chain from genesis.
    ///
    /// Runs [`build_genesis`] to derive the genesis block, computes
    /// the genesis `block_id`, and seeds the trusted validator set
    /// plus shadow evolution state from `cfg.genesis`. After this
    /// returns successfully:
    ///
    /// - `tip_height() == 0`
    /// - `tip_id() == genesis_id()`
    /// - `trusted_validators()` matches `cfg.genesis.validators`
    /// - `validator_stats()` matches the full-node post-genesis
    ///   `validator_stats` (defaulted, one per genesis validator).
    /// - `pending_unbonds()` is empty.
    /// - `next_validator_index()` is `max(v.index for v in
    ///   genesis.validators) + 1` (or 0 if empty), matching the
    ///   full-node `apply_genesis` convention.
    /// - `bonding_params()` is `cfg.genesis.bonding_params` if
    ///   provided, else [`DEFAULT_BONDING_PARAMS`].
    ///
    /// No fallible work happens in genesis bootstrapping for the
    /// light-client path — the only thing we compute is the block id
    /// (an infallible hash) and copy a `Vec<Validator>` out. The
    /// return type is `Self` rather than `Result<Self, _>` to make
    /// that contract explicit.
    #[must_use]
    pub fn from_genesis(cfg: LightChainConfig) -> Self {
        let LightChainConfig { genesis: cfg } = cfg;
        let genesis_block = build_genesis(&cfg);
        let genesis_id = block_id(&genesis_block.header);

        // Mirror `apply_genesis` exactly so the light client's shadow
        // state starts byte-for-byte equal to the full node's.
        let bonding_params = cfg.bonding_params.unwrap_or(DEFAULT_BONDING_PARAMS);
        let validator_stats = vec![ValidatorStats::default(); cfg.validators.len()];
        let next_validator_index = cfg
            .validators
            .iter()
            .map(|v| v.index)
            .max()
            .map(|m| m.saturating_add(1))
            .unwrap_or(0);
        let bond_counters = BondEpochCounters {
            bond_epoch_id: 0,
            bond_epoch_entry_count: 0,
            bond_epoch_exit_count: 0,
            next_validator_index,
        };

        Self {
            genesis_id,
            tip_height: 0,
            tip_id: genesis_id,
            params: cfg.params,
            bonding_params,
            trusted_validators: cfg.validators,
            validator_stats,
            pending_unbonds: BTreeMap::new(),
            bond_counters,
        }
    }

    /// Apply a candidate header.
    ///
    /// In order:
    ///
    /// 1. Check `header.height == tip_height + 1`.
    /// 2. Check `header.prev_hash == tip_id`.
    /// 3. Run [`verify_header`] against the trusted validator set.
    /// 4. Compute the new tip `block_id` and advance.
    ///
    /// On failure, the light chain is **unchanged** — `tip_height`,
    /// `tip_id`, and the trusted validators are all untouched.
    ///
    /// # Errors
    ///
    /// - [`LightChainError::HeightMismatch`] — height not the expected
    ///   successor.
    /// - [`LightChainError::PrevHashMismatch`] — header doesn't link
    ///   to the current tip.
    /// - [`LightChainError::HeaderVerify`] — cryptographic / structural
    ///   verification failure (see [`HeaderVerifyError`] for the
    ///   specific reason).
    pub fn apply_header(&mut self, header: &BlockHeader) -> Result<AppliedHeader, LightChainError> {
        // (1) Height must be the strict successor.
        let expected_height = self.tip_height.saturating_add(1);
        if header.height != expected_height {
            return Err(LightChainError::HeightMismatch {
                expected: expected_height,
                got: header.height,
            });
        }

        // (2) prev_hash must point at our current tip.
        if header.prev_hash != self.tip_id {
            return Err(LightChainError::PrevHashMismatch {
                height: header.height,
                expected: self.tip_id,
                got: header.prev_hash,
            });
        }

        // (3) Cryptographic verification — validator_root + producer
        //     proof + BLS finality aggregate.
        let check =
            verify_header(header, &self.trusted_validators, &self.params).map_err(|source| {
                LightChainError::HeaderVerify {
                    height: header.height,
                    source,
                }
            })?;

        // (4) Advance tip. Note: nothing past this point can fail —
        //     we never partially commit.
        let new_tip = block_id(header);
        self.tip_height = header.height;
        self.tip_id = new_tip;

        Ok(AppliedHeader {
            block_id: new_tip,
            check,
        })
    }

    /// Apply a full candidate block (header + body).
    ///
    /// In order:
    ///
    /// 1. Linkage: `header.height == tip_height + 1`.
    /// 2. Linkage: `header.prev_hash == tip_id`.
    /// 3. Cryptographic header verification via [`verify_header`]
    ///    against the trusted validator set (validator-set commitment
    ///    + producer proof + BLS finality aggregate).
    /// 4. Body verification via [`verify_block_body`] — re-derives
    ///    `tx_root`, `bond_root`, `slashing_root`, `storage_proof_root`
    ///    from `block.<field>` and matches each against the (now
    ///    authenticated) header.
    /// 5. Advance tip.
    ///
    /// On failure, the light chain is **unchanged** — no partial
    /// commits, no side effects.
    ///
    /// ## Why body verification runs *after* header verification
    ///
    /// We check the header's BLS-signed authenticity *first*, then
    /// check the body matches what the (now-trusted) header signed
    /// over. This ordering produces the cleanest error semantics:
    ///
    /// - [`LightChainError::HeaderVerify`] means "this header isn't
    ///   genuine" — produced by a forger or tampered with.
    /// - [`LightChainError::BodyMismatch`] means "this header *is*
    ///   genuine, but the delivered body doesn't match what it
    ///   committed to" — the body was tampered with after signing,
    ///   or the peer delivered the wrong body for this header.
    ///
    /// Either is a hard reject; the diagnostic distinction is useful
    /// for caller logging / peer scoring.
    ///
    /// # Errors
    ///
    /// - [`LightChainError::HeightMismatch`] — block isn't the strict
    ///   successor of the current tip.
    /// - [`LightChainError::PrevHashMismatch`] — block doesn't link
    ///   to the current tip.
    /// - [`LightChainError::HeaderVerify`] — cryptographic header
    ///   failure.
    /// - [`LightChainError::BodyMismatch`] — header is authentic but
    ///   the body doesn't match one of the four header-bound body
    ///   roots.
    pub fn apply_block(&mut self, block: &Block) -> Result<AppliedBlock, LightChainError> {
        // (1) Height must be the strict successor.
        let expected_height = self.tip_height.saturating_add(1);
        if block.header.height != expected_height {
            return Err(LightChainError::HeightMismatch {
                expected: expected_height,
                got: block.header.height,
            });
        }

        // (2) prev_hash must point at our current tip.
        if block.header.prev_hash != self.tip_id {
            return Err(LightChainError::PrevHashMismatch {
                height: block.header.height,
                expected: self.tip_id,
                got: block.header.prev_hash,
            });
        }

        // (3) Cryptographic header verification.
        let check = verify_header(&block.header, &self.trusted_validators, &self.params).map_err(
            |source| LightChainError::HeaderVerify {
                height: block.header.height,
                source,
            },
        )?;

        // (4) Body verification — header is now authenticated, so a
        //     body-root mismatch unambiguously means "wrong body for
        //     this authentic header".
        verify_block_body(block).map_err(|source| LightChainError::BodyMismatch {
            height: block.header.height,
            source,
        })?;

        // (5) Validator-set evolution (M2.0.8).
        //
        //     Mirror `mfn-consensus::apply_block`'s evolution phases
        //     byte-for-byte by calling the same pure helpers. Work
        //     against staging copies so the light chain stays atomic:
        //     if any phase rejects, we return without committing any
        //     mutation.
        let mut staged_validators = self.trusted_validators.clone();
        let mut staged_stats = self.validator_stats.clone();
        let mut staged_pending = self.pending_unbonds.clone();
        let mut staged_counters = self.bond_counters;

        // Phase A: equivocation slashings.
        let eq = apply_equivocation_slashings(&mut staged_validators, &block.slashings);
        // We don't surface Equivocation errors as LightChainError —
        // `mfn-consensus::apply_block` allows the block to advance with
        // *valid* slashings even if some entries in the slashing list
        // are individually invalid (the full node surfaces them as
        // BlockError but still applies the valid ones). To stay
        // byte-for-byte compatible we do the same here.
        let validators_slashed_equivocation = (block.slashings.len() - eq.errors.len()) as u32;

        // Phase B: liveness slashing — needs the finality bitmap from
        // `producer_proof`. `verify_header` already validated that the
        // proof decodes and that the bitmap is internally consistent,
        // so this `Option` is `Some` for every non-bootstrap block.
        let bitmap = finality_bitmap_from_header(&block.header);
        let pre_liveness_slashes: u32 = staged_stats.iter().map(|s| s.liveness_slashes).sum();
        if let Some(b) = &bitmap {
            apply_liveness_evolution(&mut staged_validators, &mut staged_stats, b, &self.params);
        }
        let post_liveness_slashes: u32 = staged_stats.iter().map(|s| s.liveness_slashes).sum();
        let validators_slashed_liveness =
            post_liveness_slashes.saturating_sub(pre_liveness_slashes);

        // Phase C: bond ops (Register / Unbond).
        let pre_bond_validators = staged_validators.len();
        apply_bond_ops_evolution(
            block.header.height,
            &mut staged_counters,
            &mut staged_validators,
            &mut staged_stats,
            &mut staged_pending,
            &self.bonding_params,
            &block.bond_ops,
        )
        .map_err(
            |BondOpError { index, message }| LightChainError::EvolutionFailed {
                height: block.header.height,
                index,
                message,
            },
        )?;
        let validators_added = (staged_validators.len() - pre_bond_validators) as u32;

        // Phase D: unbond settlements.
        let pre_pending = staged_pending.len();
        apply_unbond_settlements(
            block.header.height,
            &mut staged_counters,
            &self.bonding_params,
            &mut staged_validators,
            &mut staged_pending,
        );
        let validators_unbond_settled = pre_pending.saturating_sub(staged_pending.len()) as u32;

        // (6) Atomic commit. Nothing past this point can fail.
        let new_tip = block_id(&block.header);
        self.trusted_validators = staged_validators;
        self.validator_stats = staged_stats;
        self.pending_unbonds = staged_pending;
        self.bond_counters = staged_counters;
        self.tip_height = block.header.height;
        self.tip_id = new_tip;

        Ok(AppliedBlock {
            block_id: new_tip,
            check,
            validators_added,
            validators_slashed_equivocation,
            validators_slashed_liveness,
            validators_unbond_settled,
        })
    }

    /// Current tip height. `0` immediately after construction.
    #[must_use]
    pub fn tip_height(&self) -> u32 {
        self.tip_height
    }

    /// Current tip's `block_id`. Equal to `genesis_id()` immediately
    /// after construction.
    #[must_use]
    pub fn tip_id(&self) -> &[u8; 32] {
        &self.tip_id
    }

    /// Genesis `block_id`. Constant for the lifetime of the chain.
    #[must_use]
    pub fn genesis_id(&self) -> &[u8; 32] {
        &self.genesis_id
    }

    /// Trusted validator set the next header will be verified against.
    /// Evolved across rotations via [`LightChain::apply_block`] — see
    /// the M2.0.8 design note for the four-phase evolution algorithm.
    #[must_use]
    pub fn trusted_validators(&self) -> &[Validator] {
        &self.trusted_validators
    }

    /// Per-validator participation stats (aligned with
    /// [`Self::trusted_validators`] by index). Mirrors the full
    /// node's `ChainState.validator_stats`.
    #[must_use]
    pub fn validator_stats(&self) -> &[ValidatorStats] {
        &self.validator_stats
    }

    /// In-flight unbond requests indexed by `Validator::index`.
    /// Settled when this validator's `unlock_height` is reached AND
    /// exit-churn budget permits.
    #[must_use]
    pub fn pending_unbonds(&self) -> &BTreeMap<u32, PendingUnbond> {
        &self.pending_unbonds
    }

    /// Bond-epoch counters mirroring `mfn-consensus::ChainState` —
    /// `bond_epoch_id`, `bond_epoch_entry_count`,
    /// `bond_epoch_exit_count`, `next_validator_index`.
    #[must_use]
    pub fn bond_counters(&self) -> &BondEpochCounters {
        &self.bond_counters
    }

    /// Next `Validator::index` the chain will assign to a freshly-bonded
    /// validator. Monotonically increasing across the chain's lifetime.
    #[must_use]
    pub fn next_validator_index(&self) -> u32 {
        self.bond_counters.next_validator_index
    }

    /// Consensus parameters (frozen at genesis).
    #[must_use]
    pub fn params(&self) -> &ConsensusParams {
        &self.params
    }

    /// Bonding parameters (frozen at genesis).
    #[must_use]
    pub fn bonding_params(&self) -> &BondingParams {
        &self.bonding_params
    }

    /// Sum of stake of all trusted validators.
    #[must_use]
    pub fn total_stake(&self) -> u64 {
        self.trusted_validators.iter().map(|v| v.stake).sum()
    }

    /// Cheap snapshot of vital statistics.
    #[must_use]
    pub fn stats(&self) -> LightChainStats {
        LightChainStats {
            height: self.tip_height,
            tip_id: self.tip_id,
            genesis_id: self.genesis_id,
            validator_count: self.trusted_validators.len(),
            total_stake: self.total_stake(),
        }
    }
}

/* ----------------------------------------------------------------------- *
 *  Unit tests                                                              *
 * ----------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_bls::bls_keygen_from_seed;
    use mfn_consensus::{
        apply_genesis, build_coinbase, build_unsealed_header, cast_vote, emission_at_height,
        encode_finality_proof, finalize, header_signing_hash, seal_block, try_produce_slot,
        FinalityProof, PayoutAddress, SlotContext, Validator, ValidatorPayout, ValidatorSecrets,
        DEFAULT_EMISSION_PARAMS,
    };
    use mfn_crypto::stealth::stealth_gen;
    use mfn_crypto::vrf::vrf_keygen_from_seed;
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    fn mk_validator(i: u32, stake: u64) -> (Validator, ValidatorSecrets) {
        let vrf = vrf_keygen_from_seed(&[i as u8 + 1; 32]).unwrap();
        let bls = bls_keygen_from_seed(&[i as u8 + 101; 32]);
        let payout_wallet = stealth_gen();
        let payout = ValidatorPayout {
            view_pub: payout_wallet.view_pub,
            spend_pub: payout_wallet.spend_pub,
        };
        let val = Validator {
            index: i,
            vrf_pk: vrf.pk,
            bls_pk: bls.pk,
            stake,
            payout: Some(payout),
        };
        let secrets = ValidatorSecrets {
            index: i,
            vrf,
            bls: bls.clone(),
        };
        (val, secrets)
    }

    fn single_validator_cfg() -> (GenesisConfig, ValidatorSecrets, ConsensusParams, Validator) {
        let (v0, s0) = mk_validator(0, 1_000_000);
        let params = ConsensusParams {
            expected_proposers_per_slot: 10.0,
            quorum_stake_bps: 6666,
            liveness_max_consecutive_missed: 64,
            liveness_slash_bps: 0,
        };
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: vec![v0.clone()],
            params,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        (cfg, s0, params, v0)
    }

    /// Build a signed block 1 against the given genesis config + validator.
    /// Returns the block and the post-block state (so we can chain).
    fn produce_block(
        prev_state: &mfn_consensus::ChainState,
        v0: &Validator,
        s0: &ValidatorSecrets,
        params: ConsensusParams,
        height: u32,
    ) -> mfn_consensus::Block {
        let payout = v0.payout.unwrap();
        let cb_payout = PayoutAddress {
            view_pub: payout.view_pub,
            spend_pub: payout.spend_pub,
        };
        let emission = emission_at_height(u64::from(height), &DEFAULT_EMISSION_PARAMS);
        let cb = build_coinbase(u64::from(height), emission, &cb_payout).expect("cb");
        let txs = vec![cb];

        let unsealed = build_unsealed_header(
            prev_state,
            &txs,
            &[],
            &[],
            &[],
            height,
            u64::from(height) * 100,
        );
        let header_hash = header_signing_hash(&unsealed);
        let ctx = SlotContext {
            height,
            slot: height,
            prev_hash: unsealed.prev_hash,
        };
        let total_stake = v0.stake;
        let producer_proof = try_produce_slot(
            &ctx,
            s0,
            v0,
            total_stake,
            params.expected_proposers_per_slot,
            &header_hash,
        )
        .expect("produce")
        .expect("eligible");
        let vote = cast_vote(
            &header_hash,
            s0,
            &ctx,
            &producer_proof,
            v0,
            total_stake,
            params.expected_proposers_per_slot,
        )
        .expect("vote");
        let agg = finalize(&header_hash, &[vote], 1).expect("agg");
        let fin = FinalityProof {
            producer: producer_proof,
            finality: agg,
            signing_stake: v0.stake,
        };
        seal_block(
            unsealed,
            txs,
            Vec::new(),
            encode_finality_proof(&fin),
            Vec::new(),
            Vec::new(),
        )
    }

    /// `from_genesis` should land at height 0 with tip = genesis id.
    #[test]
    fn from_genesis_lands_at_height_zero() {
        let (cfg, _s0, _params, v0) = single_validator_cfg();
        let light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        assert_eq!(light.tip_height(), 0);
        assert_eq!(light.tip_id(), light.genesis_id());
        assert_eq!(light.trusted_validators().len(), 1);
        assert_eq!(light.trusted_validators()[0].index, v0.index);
        assert_eq!(light.total_stake(), 1_000_000);
    }

    /// Genesis is deterministic across constructions.
    #[test]
    fn from_genesis_is_deterministic_across_constructions() {
        let (cfg, _s0, _params, _v0) = single_validator_cfg();
        let a = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let b = LightChain::from_genesis(LightChainConfig::new(cfg));
        assert_eq!(a.genesis_id(), b.genesis_id());
        assert_eq!(a.tip_id(), b.tip_id());
    }

    /// Real signed block 1 must apply through the light chain.
    #[test]
    fn apply_header_accepts_real_signed_block() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));

        // Need a full ChainState to feed `build_unsealed_header`. The
        // light chain doesn't carry one — that's the whole point —
        // but the *producer* side does. Construct one here just to
        // make a real block.
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let block = produce_block(&state, &v0, &s0, params, 1);

        let applied = light.apply_header(&block.header).expect("must apply");
        assert_eq!(light.tip_height(), 1);
        assert_eq!(light.tip_id(), &applied.block_id);
        assert_eq!(applied.check.producer_index, 0);
        assert_eq!(applied.check.signing_stake, 1_000_000);
    }

    /// Wrong `prev_hash` → typed `PrevHashMismatch`, state preserved.
    #[test]
    fn apply_header_rejects_wrong_prev_hash() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let mut block = produce_block(&state, &v0, &s0, params, 1);
        // Flip the prev_hash. Note: this also breaks the BLS aggregate
        // signature (which signs over header_signing_hash including
        // prev_hash), but the linkage check happens *first*, so the
        // typed error must be `PrevHashMismatch`, not `HeaderVerify`.
        block.header.prev_hash[0] ^= 0xff;

        let pre = light.stats();
        let err = light.apply_header(&block.header).expect_err("reject");
        match err {
            LightChainError::PrevHashMismatch { height, .. } => assert_eq!(height, 1),
            other => panic!("expected PrevHashMismatch, got {other:?}"),
        }
        assert_eq!(light.stats(), pre, "state must be untouched on rejection");
    }

    /// Wrong height → typed `HeightMismatch`, state preserved.
    #[test]
    fn apply_header_rejects_wrong_height() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let mut block = produce_block(&state, &v0, &s0, params, 1);
        block.header.height = 42;

        let pre = light.stats();
        let err = light.apply_header(&block.header).expect_err("reject");
        match err {
            LightChainError::HeightMismatch { expected, got } => {
                assert_eq!(expected, 1);
                assert_eq!(got, 42);
            }
            other => panic!("expected HeightMismatch, got {other:?}"),
        }
        assert_eq!(light.stats(), pre);
    }

    /// Cryptographic tamper (validator_root flip) → `HeaderVerify`
    /// wrapping `ValidatorRootMismatch`. State preserved.
    #[test]
    fn apply_header_rejects_tampered_validator_root() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let mut block = produce_block(&state, &v0, &s0, params, 1);
        block.header.validator_root[0] ^= 0xff;

        let pre = light.stats();
        let err = light.apply_header(&block.header).expect_err("reject");
        match err {
            LightChainError::HeaderVerify {
                height,
                source: HeaderVerifyError::ValidatorRootMismatch,
            } => assert_eq!(height, 1),
            other => panic!("expected HeaderVerify/ValidatorRootMismatch, got {other:?}"),
        }
        assert_eq!(light.stats(), pre);
    }

    /// stats accessors must agree with the individual ones.
    #[test]
    fn stats_agree_with_individual_accessors() {
        let (cfg, _s0, _params, _v0) = single_validator_cfg();
        let light = LightChain::from_genesis(LightChainConfig::new(cfg));
        let s = light.stats();
        assert_eq!(s.height, light.tip_height());
        assert_eq!(s.tip_id, *light.tip_id());
        assert_eq!(s.genesis_id, *light.genesis_id());
        assert_eq!(s.validator_count, light.trusted_validators().len());
        assert_eq!(s.total_stake, light.total_stake());
    }

    /* ----------------------------------------------------------------- *
     *  M2.0.7 — apply_block                                              *
     * ----------------------------------------------------------------- */

    /// Real signed block 1 must apply through the light chain via
    /// `apply_block`. After: tip = block 1's id, height = 1.
    #[test]
    fn apply_block_accepts_real_signed_block() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let block = produce_block(&state, &v0, &s0, params, 1);

        let applied = light.apply_block(&block).expect("must apply");
        assert_eq!(light.tip_height(), 1);
        assert_eq!(light.tip_id(), &applied.block_id);
        assert_eq!(applied.check.producer_index, 0);
        assert_eq!(applied.check.signing_stake, 1_000_000);
    }

    /// Tampered `tx_root` in the *header* (body still original) →
    /// the header now claims a tx_root that doesn't match the body.
    /// But since header BLS-signs over its own tx_root, the header
    /// is no longer authentic → `HeaderVerify`. State preserved.
    #[test]
    fn apply_block_rejects_tampered_tx_root_in_header() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let mut block = produce_block(&state, &v0, &s0, params, 1);
        block.header.tx_root[0] ^= 0xff;

        let pre = light.stats();
        let err = light.apply_block(&block).expect_err("reject");
        assert!(
            matches!(err, LightChainError::HeaderVerify { .. }),
            "tampering header fields breaks the BLS signature → HeaderVerify, got {err:?}"
        );
        assert_eq!(light.stats(), pre, "state must be untouched on rejection");
    }

    /// Tampered body (push a duplicate tx) → the recomputed `tx_root`
    /// no longer matches the (authentic) header → `BodyMismatch`.
    /// State preserved.
    #[test]
    fn apply_block_rejects_tampered_tx_body() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let mut block = produce_block(&state, &v0, &s0, params, 1);
        // Tamper the body without touching the header — this leaves
        // the header BLS-signed and authentic, but its tx_root no
        // longer matches the body.
        let cb = block.txs[0].clone();
        block.txs.push(cb);

        let pre = light.stats();
        let err = light.apply_block(&block).expect_err("reject");
        match err {
            LightChainError::BodyMismatch {
                height,
                source: BodyVerifyError::TxRootMismatch { .. },
            } => assert_eq!(height, 1),
            other => panic!("expected BodyMismatch/TxRootMismatch, got {other:?}"),
        }
        assert_eq!(light.stats(), pre, "state must be untouched on rejection");
    }

    /// Wrong `prev_hash` → typed `PrevHashMismatch`. The linkage
    /// check fires before body verification.
    #[test]
    fn apply_block_rejects_wrong_prev_hash() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let mut block = produce_block(&state, &v0, &s0, params, 1);
        block.header.prev_hash[0] ^= 0xff;

        let pre = light.stats();
        let err = light.apply_block(&block).expect_err("reject");
        match err {
            LightChainError::PrevHashMismatch { height, .. } => assert_eq!(height, 1),
            other => panic!("expected PrevHashMismatch, got {other:?}"),
        }
        assert_eq!(light.stats(), pre);
    }

    /// Wrong height → typed `HeightMismatch`. Linkage fires first.
    #[test]
    fn apply_block_rejects_wrong_height() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let mut block = produce_block(&state, &v0, &s0, params, 1);
        block.header.height = 42;

        let pre = light.stats();
        let err = light.apply_block(&block).expect_err("reject");
        match err {
            LightChainError::HeightMismatch { expected, got } => {
                assert_eq!(expected, 1);
                assert_eq!(got, 42);
            }
            other => panic!("expected HeightMismatch, got {other:?}"),
        }
        assert_eq!(light.stats(), pre);
    }

    /// After a successful `apply_block`, `apply_block` again with a
    /// fresh block 2 must continue cleanly.
    #[test]
    fn apply_block_chains_across_two_blocks() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let mut state = apply_genesis(&g, &cfg).unwrap();

        let block1 = produce_block(&state, &v0, &s0, params, 1);
        light.apply_block(&block1).expect("block 1");
        state = match mfn_consensus::apply_block(&state, &block1) {
            mfn_consensus::ApplyOutcome::Ok { state, .. } => state,
            other => panic!("apply_block(block 1) failed: {other:?}"),
        };

        let block2 = produce_block(&state, &v0, &s0, params, 2);
        let applied2 = light.apply_block(&block2).expect("block 2");
        assert_eq!(light.tip_height(), 2);
        assert_eq!(light.tip_id(), &applied2.block_id);
    }

    /// Determinism: same chain → same final stats irrespective of
    /// whether each block is fed through `apply_header` (header only)
    /// or `apply_block` (full block). The header-only path skips body
    /// verification but produces the same tip / height.
    #[test]
    fn apply_header_and_apply_block_agree_on_tip() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let block = produce_block(&state, &v0, &s0, params, 1);

        let mut a = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let mut b = LightChain::from_genesis(LightChainConfig::new(cfg));
        a.apply_header(&block.header).expect("a");
        b.apply_block(&block).expect("b");
        assert_eq!(a.stats(), b.stats());
    }

    /* ----------------------------------------------------------------- *
     *  M2.0.8 — Validator-set evolution                                  *
     * ----------------------------------------------------------------- */

    /// `from_genesis` initialises shadow state correctly:
    ///   - `validator_stats` aligned with `trusted_validators`.
    ///   - `pending_unbonds` empty.
    ///   - `bond_counters.next_validator_index` = max(index) + 1.
    ///   - `bonding_params` = `DEFAULT_BONDING_PARAMS` when genesis
    ///     supplies `None`.
    #[test]
    fn from_genesis_initializes_shadow_state() {
        let (cfg, _s0, _params, _v0) = single_validator_cfg();
        let light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        assert_eq!(light.validator_stats().len(), 1);
        assert_eq!(light.validator_stats()[0], ValidatorStats::default());
        assert!(light.pending_unbonds().is_empty());
        let bc = light.bond_counters();
        assert_eq!(bc.bond_epoch_id, 0);
        assert_eq!(bc.bond_epoch_entry_count, 0);
        assert_eq!(bc.bond_epoch_exit_count, 0);
        assert_eq!(bc.next_validator_index, 1, "max(0) + 1");
        // Default bonding params (genesis didn't override).
        assert_eq!(
            light.bonding_params().min_validator_stake,
            mfn_consensus::DEFAULT_BONDING_PARAMS.min_validator_stake
        );
    }

    /// `from_genesis` with an empty validator set seeds
    /// `next_validator_index = 0`.
    #[test]
    fn from_genesis_empty_validators_indexes_at_zero() {
        let mut cfg = single_validator_cfg().0;
        cfg.validators = Vec::new();
        let light = LightChain::from_genesis(LightChainConfig::new(cfg));
        assert_eq!(light.bond_counters().next_validator_index, 0);
        assert!(light.validator_stats().is_empty());
    }

    /// `apply_block` on a clean 1-validator chain increments
    /// `validator_stats[0].total_signed` (the validator voted).
    /// Liveness shouldn't slash because `liveness_slash_bps = 0`
    /// in the test config.
    #[test]
    fn apply_block_increments_total_signed_for_voting_validator() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let block = produce_block(&state, &v0, &s0, params, 1);
        let applied = light.apply_block(&block).expect("apply");
        assert_eq!(light.validator_stats()[0].total_signed, 1);
        assert_eq!(light.validator_stats()[0].consecutive_missed, 0);
        assert_eq!(light.validator_stats()[0].liveness_slashes, 0);
        // No bond ops, no slashings, no unbonds.
        assert_eq!(applied.validators_added, 0);
        assert_eq!(applied.validators_slashed_equivocation, 0);
        assert_eq!(applied.validators_slashed_liveness, 0);
        assert_eq!(applied.validators_unbond_settled, 0);
    }

    /// Multi-block: total_signed advances per block.
    #[test]
    fn apply_block_total_signed_advances_across_blocks() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let mut state = apply_genesis(&g, &cfg).unwrap();
        for h in 1..=3 {
            let block = produce_block(&state, &v0, &s0, params, h);
            state = match mfn_consensus::apply_block(&state, &block) {
                mfn_consensus::ApplyOutcome::Ok { state, .. } => state,
                other => panic!("apply_block(block {h}) failed: {other:?}"),
            };
            light.apply_block(&block).expect("light apply");
        }
        assert_eq!(light.validator_stats()[0].total_signed, 3);
        assert_eq!(light.tip_height(), 3);
    }

    /// Tampered body → state preserved. Specifically, validator_stats
    /// must not have advanced.
    #[test]
    fn apply_block_body_tamper_preserves_validator_stats() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let mut block = produce_block(&state, &v0, &s0, params, 1);
        // Body tamper without touching header → BodyMismatch (header is
        // still authentic, but body root mismatches).
        let cb = block.txs[0].clone();
        block.txs.push(cb);

        let pre_stats = light.validator_stats().to_vec();
        let pre_tip = light.tip_id;
        let _ = light.apply_block(&block).expect_err("reject");
        assert_eq!(light.validator_stats(), &pre_stats[..]);
        assert_eq!(light.tip_id, pre_tip);
    }

    /// Header verification's `validator_root` check is the
    /// cross-block audit of the previous block's evolution. We
    /// simulate "wrong evolution" by hand-mutating the trusted set
    /// and confirm the next `apply_block` fails with
    /// `ValidatorRootMismatch` — exactly the failure mode that catches
    /// a drift between full-node and light-client evolution.
    #[test]
    fn evolution_drift_caught_by_next_block_validator_root_check() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let state = apply_genesis(&g, &cfg).unwrap();
        let block1 = produce_block(&state, &v0, &s0, params, 1);
        light.apply_block(&block1).expect("block 1");
        let state1 = match mfn_consensus::apply_block(&state, &block1) {
            mfn_consensus::ApplyOutcome::Ok { state, .. } => state,
            other => panic!("block 1 should apply: {other:?}"),
        };
        let block2 = produce_block(&state1, &v0, &s0, params, 2);

        // Simulate drift: zero the trusted validator's stake without
        // any corresponding chain event. This is what a bug in
        // `apply_block` evolution would look like.
        light.trusted_validators[0].stake = 0;

        let err = light.apply_block(&block2).expect_err("must reject");
        match err {
            LightChainError::HeaderVerify {
                source: HeaderVerifyError::ValidatorRootMismatch,
                ..
            } => (),
            other => panic!("expected ValidatorRootMismatch, got {other:?}"),
        }
    }

    /// `applied.validators_added` / `_slashed_*` / `_unbond_settled`
    /// all start at zero for a no-bond-no-slash chain.
    #[test]
    fn applied_block_counts_are_zero_for_no_event_chain() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let mut state = apply_genesis(&g, &cfg).unwrap();
        for h in 1..=3 {
            let block = produce_block(&state, &v0, &s0, params, h);
            state = match mfn_consensus::apply_block(&state, &block) {
                mfn_consensus::ApplyOutcome::Ok { state, .. } => state,
                other => panic!("apply_block(block {h}) failed: {other:?}"),
            };
            let applied = light.apply_block(&block).expect("light apply");
            assert_eq!(applied.validators_added, 0);
            assert_eq!(applied.validators_slashed_equivocation, 0);
            assert_eq!(applied.validators_slashed_liveness, 0);
            assert_eq!(applied.validators_unbond_settled, 0);
        }
    }

    /// `validator_set_root(light.trusted_validators())` must equal
    /// the next block's `header.validator_root` after every applied
    /// block. This is the core invariant of M2.0.8 — the next block's
    /// header implicitly audits the previous block's evolution.
    #[test]
    fn validator_set_root_matches_next_block_header_after_apply() {
        let (cfg, s0, params, v0) = single_validator_cfg();
        let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));
        let g = build_genesis(&cfg);
        let mut state = apply_genesis(&g, &cfg).unwrap();
        for h in 1..=3 {
            let block = produce_block(&state, &v0, &s0, params, h);
            state = match mfn_consensus::apply_block(&state, &block) {
                mfn_consensus::ApplyOutcome::Ok { state, .. } => state,
                other => panic!("block {h}: {other:?}"),
            };
            light.apply_block(&block).expect("light apply");
            // Next block's header will commit to this set.
            let expected = mfn_consensus::validator_set_root(light.trusted_validators());
            let actual = mfn_consensus::validator_set_root(&state.validators);
            assert_eq!(
                expected, actual,
                "block {h}: light + full validator sets must agree byte-for-byte"
            );
        }
    }
}
