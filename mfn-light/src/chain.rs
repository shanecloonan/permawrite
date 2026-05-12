//! Header-only light-client chain follower.
//!
//! The [`LightChain`] struct owns:
//!
//! - The *trusted* validator set (set at construction time from a
//!   [`GenesisConfig`]; not yet evolved across rotations — see M2.0.8).
//! - The chain's [`ConsensusParams`] (for quorum threshold + slot-eligibility math).
//! - The current tip's `block_id` and height.
//! - The fixed genesis `block_id` (for "what chain am I on?" queries).
//!
//! Every successful [`LightChain::apply_header`] swaps the tip pointer
//! for the next header. The trusted-validators set is *not* mutated
//! in this slice — callers following a chain across a rotation should
//! re-bootstrap from a freshly-trusted checkpoint until M2.0.8 lands
//! body-aware validator-set evolution.
//!
//! ## What this driver does NOT do (yet)
//!
//! - **No body verification.** Reconstructing `tx_root` / `bond_root` /
//!   `slashing_root` / `storage_proof_root` / `storage_root` from a
//!   delivered body and comparing against the header is M2.0.7 work.
//! - **No validator-set evolution.** Processing `BondOp`s, slashings,
//!   liveness slashes, and pending-unbond settlements to derive
//!   `trusted_validators_{n+1}` from `trusted_validators_n` is M2.0.8.
//! - **No re-org / fork choice.** Single canonical header chain only.
//!   Future P2P / sync layers would attach re-org logic on top.
//! - **No persistence.** Tip pointer + trusted validators live in
//!   memory. Trivial to add via a separate `mfn-light::store` module.

use mfn_consensus::{
    block_id, build_genesis, verify_header, BlockHeader, ConsensusParams, GenesisConfig,
    HeaderCheck, HeaderVerifyError, Validator,
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

/// Header-only light-client chain follower.
///
/// Tracks the current tip, the genesis id, and a trusted validator
/// set. The trusted set is *not* yet rotated across `BondOp`s /
/// slashings / unbond settlements — that's M2.0.8 work. For this
/// slice, the chain follower works for stable-validator windows
/// (which covers the vast majority of bulk-sync time).
///
/// `LightChain` is `Send` (every field is `Send`) but `!Sync` by
/// default — wrap in a `Mutex` if shared across threads is needed.
/// The intended usage pattern is single-owner.
#[derive(Clone, Debug)]
pub struct LightChain {
    trusted_validators: Vec<Validator>,
    params: ConsensusParams,
    tip_height: u32,
    tip_id: [u8; 32],
    genesis_id: [u8; 32],
}

impl LightChain {
    /// Build a light chain from genesis.
    ///
    /// Runs [`build_genesis`] to derive the genesis block, computes
    /// the genesis `block_id`, and seeds the trusted validator set
    /// from `cfg.genesis.validators`. After this returns successfully:
    ///
    /// - `tip_height() == 0`
    /// - `tip_id() == genesis_id()`
    /// - `trusted_validators()` matches `cfg.genesis.validators`
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
        Self {
            trusted_validators: cfg.validators,
            params: cfg.params,
            tip_height: 0,
            tip_id: genesis_id,
            genesis_id,
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
    /// Not yet evolved across rotations — see crate-level docs.
    #[must_use]
    pub fn trusted_validators(&self) -> &[Validator] {
        &self.trusted_validators
    }

    /// Consensus parameters (frozen at genesis).
    #[must_use]
    pub fn params(&self) -> &ConsensusParams {
        &self.params
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
}
