//! Block production helpers.
//!
//! Wraps the consensus-layer building blocks
//! ([`build_unsealed_header`], [`try_produce_slot`], [`cast_vote`],
//! [`finalize`], [`seal_block`]) into a single reusable API. This is
//! the surface every higher-level orchestration layer will consume:
//!
//! - The future single-node demo (M2.1) drives a chain by calling
//!   [`produce_solo_block`] in a slot-timer loop.
//! - The future P2P producer / voter loops (M2.2) will split the
//!   workflow into the 3-stage form documented below
//!   ([`build_proposal`] → distributed `cast_vote` → [`seal_proposal`]).
//! - Multi-validator tests already collect votes by hand today; the
//!   helpers here let those tests shrink to a few lines.
//!
//! ## Three-stage producer protocol
//!
//! 1. **Build proposal.** The slot-eligible producer builds an
//!    unsealed header committing every body element (txs, bond ops,
//!    slashings, storage proofs), runs the VRF + ed25519 producer
//!    proof, and packages everything as a [`BlockProposal`]. This is
//!    the byte string that goes out on the P2P wire for voters to
//!    sign over.
//! 2. **Collect votes.** Each active (`stake > 0`) committee member
//!    BLS-signs the proposal's `header_hash` via
//!    [`mfn_consensus::cast_vote`]. In the solo case the producer is
//!    the only voter; in the multi-validator case the producer
//!    gathers votes off the wire.
//! 3. **Seal.** Once a quorum has voted, the producer aggregates the
//!    votes with [`mfn_consensus::finalize`] and seals the block via
//!    [`mfn_consensus::seal_block`]. The resulting `Block` is ready
//!    to broadcast and apply.
//!
//! For the simplest case (solo producer = solo voter) the convenience
//! function [`produce_solo_block`] runs all three stages in one call.
//! Multi-validator and split producer/voter flows use the staged API
//! directly.

use mfn_consensus::{
    build_unsealed_header, cast_vote, encode_finality_proof, finalize, header_signing_hash,
    seal_block, try_produce_slot, Block, BlockHeader, BondOp, ConsensusError, ConsensusParams,
    FinalityProof, ProducerProof, SlashEvidence, SlotContext, TransactionWire, Validator,
    ValidatorSecrets,
};
use mfn_storage::StorageProof;

use crate::Chain;

/* ----------------------------------------------------------------------- *
 *  Inputs                                                                  *
 * ----------------------------------------------------------------------- */

/// Everything a producer needs to *consider including* in a block,
/// alongside the slot timing it's targeting.
///
/// The body lists are passed verbatim to [`build_unsealed_header`]; the
/// producer is responsible for upstream validity (mempool-side fee
/// validation, dedup, etc.). For an empty / "tick" block, all four
/// lists are empty and the helper still produces a valid block.
#[derive(Clone, Debug, Default)]
pub struct BlockInputs {
    /// Block height being targeted. Must equal `chain.tip_height() + 1`.
    pub height: u32,
    /// Slot timer value. For simple deployments use `slot = height`.
    pub slot: u32,
    /// Wall-clock timestamp (must be strictly greater than the parent
    /// block's timestamp, per the consensus rules).
    pub timestamp: u64,
    /// Transactions to include. If the producer has a `ValidatorPayout`,
    /// element `0` must be a valid coinbase paying the producer's
    /// emission + fee share — the helper does not synthesize the
    /// coinbase for you, callers do.
    pub txs: Vec<TransactionWire>,
    /// Bond operations to apply this block.
    pub bond_ops: Vec<BondOp>,
    /// Slashing evidence to record this block.
    pub slashings: Vec<SlashEvidence>,
    /// Storage proofs (SPoRA) to include this block.
    pub storage_proofs: Vec<StorageProof>,
}

/* ----------------------------------------------------------------------- *
 *  Proposal                                                                *
 * ----------------------------------------------------------------------- */

/// A block proposal — everything except the committee aggregate.
///
/// Produced by [`build_proposal`]. Validators that receive this off
/// the P2P wire BLS-sign `header_hash` via [`mfn_consensus::cast_vote`]
/// and return their [`mfn_consensus::CommitteeVote`] to the producer.
/// Once the producer has a quorum of votes, [`seal_proposal`] aggregates
/// them and produces the final [`Block`].
#[derive(Clone, Debug)]
pub struct BlockProposal {
    /// Unsealed header (no `producer_proof` field set yet).
    pub unsealed_header: BlockHeader,
    /// Cached `header_signing_hash(&unsealed_header)`. Voters BLS-sign
    /// over this; the producer's own ed25519 + VRF producer-proof
    /// also signs over this.
    pub header_hash: [u8; 32],
    /// Slot context used to derive the producer proof. Voters need
    /// this to re-derive eligibility for the producer.
    pub ctx: SlotContext,
    /// The producer's own VRF + ed25519 proof of slot eligibility.
    pub producer_proof: ProducerProof,
    /// Body — txs, bond ops, slashings, storage proofs — in the
    /// exact form committed to by the header roots.
    pub txs: Vec<TransactionWire>,
    /// See `txs`.
    pub bond_ops: Vec<BondOp>,
    /// See `txs`.
    pub slashings: Vec<SlashEvidence>,
    /// See `txs`.
    pub storage_proofs: Vec<StorageProof>,
}

/* ----------------------------------------------------------------------- *
 *  Errors                                                                  *
 * ----------------------------------------------------------------------- */

/// Errors produced by the producer helpers.
///
/// Distinct from [`crate::ChainError`] — `ChainError` is what comes
/// out of *applying* a block; `ProducerError` is what comes out of
/// *building* one.
#[derive(Debug, thiserror::Error)]
pub enum ProducerError {
    /// `try_produce_slot` failed for non-eligibility reasons (e.g. the
    /// validator's VRF key is malformed). Genuine non-eligibility is
    /// returned as `ProducerError::NotSlotEligible` so callers can
    /// distinguish "skip this slot" from "something is broken".
    #[error("producer-proof generation failed: {0}")]
    ProducerProof(#[from] ConsensusError),

    /// The producer's VRF output for this slot is above the
    /// eligibility threshold — i.e. they're not allowed to propose
    /// this slot. The caller should try a different validator or wait
    /// for the next slot.
    #[error("validator not slot-eligible for slot {slot} at height {height}")]
    NotSlotEligible {
        /// Block height the producer was trying to propose.
        height: u32,
        /// Slot number that the producer was found ineligible for.
        slot: u32,
    },

    /// BLS aggregation across the collected committee votes failed.
    /// This is the only failure path of [`mfn_consensus::finalize`]
    /// — typically caused by a malformed vote or an empty vote list.
    #[error("BLS aggregation failed: {0}")]
    Aggregation(String),
}

/* ----------------------------------------------------------------------- *
 *  Stage 1 — build_proposal                                                *
 * ----------------------------------------------------------------------- */

/// Build a block proposal: stage 1 of the 3-stage producer protocol.
///
/// Computes the unsealed header (committing every body element),
/// derives the producer's VRF eligibility proof, and packages
/// everything into a [`BlockProposal`].
///
/// # Slot eligibility
///
/// If the producer's VRF output for this slot is above the threshold,
/// returns [`ProducerError::NotSlotEligible`] — the caller should
/// either retry with a different validator (for committees where
/// multiple producers may be eligible) or skip the slot.
///
/// # Errors
///
/// - [`ProducerError::ProducerProof`] for cryptographic / decoding
///   failures.
/// - [`ProducerError::NotSlotEligible`] when the producer is not
///   slot-eligible.
pub fn build_proposal(
    state: &mfn_consensus::ChainState,
    producer: &Validator,
    secrets: &ValidatorSecrets,
    params: ConsensusParams,
    inputs: BlockInputs,
) -> Result<BlockProposal, ProducerError> {
    let unsealed = build_unsealed_header(
        state,
        &inputs.txs,
        &inputs.bond_ops,
        &inputs.slashings,
        &inputs.storage_proofs,
        inputs.height,
        inputs.timestamp,
    );
    let header_hash = header_signing_hash(&unsealed);
    let ctx = SlotContext {
        height: inputs.height,
        slot: inputs.slot,
        prev_hash: unsealed.prev_hash,
    };

    let total_stake: u64 = state.validators.iter().map(|v| v.stake).sum();
    let producer_proof = try_produce_slot(
        &ctx,
        secrets,
        producer,
        total_stake,
        params.expected_proposers_per_slot,
        &header_hash,
    )?
    .ok_or(ProducerError::NotSlotEligible {
        height: inputs.height,
        slot: inputs.slot,
    })?;

    Ok(BlockProposal {
        unsealed_header: unsealed,
        header_hash,
        ctx,
        producer_proof,
        txs: inputs.txs,
        bond_ops: inputs.bond_ops,
        slashings: inputs.slashings,
        storage_proofs: inputs.storage_proofs,
    })
}

/* ----------------------------------------------------------------------- *
 *  Stage 2 — vote_on_proposal                                              *
 * ----------------------------------------------------------------------- */

/// Cast a committee vote on a [`BlockProposal`]: stage 2 of the
/// 3-stage producer protocol.
///
/// A thin wrapper over [`mfn_consensus::cast_vote`] that re-derives
/// the slot eligibility context for the voter. Returns a
/// [`mfn_consensus::CommitteeVote`] which the producer collects.
///
/// # Errors
///
/// Surface for any [`ConsensusError`] from `cast_vote` — typically
/// only fires for malformed inputs (the consensus layer doesn't
/// distinguish "you didn't sign" from "the signature is bad").
pub fn vote_on_proposal(
    proposal: &BlockProposal,
    state: &mfn_consensus::ChainState,
    voter: &Validator,
    voter_secrets: &ValidatorSecrets,
    producer: &Validator,
    params: ConsensusParams,
) -> Result<mfn_bls::CommitteeVote, ProducerError> {
    let _ = voter; // signature ergonomics — see note below
    let total_stake: u64 = state.validators.iter().map(|v| v.stake).sum();
    cast_vote(
        &proposal.header_hash,
        voter_secrets,
        &proposal.ctx,
        &proposal.producer_proof,
        producer,
        total_stake,
        params.expected_proposers_per_slot,
    )
    .map_err(ProducerError::ProducerProof)
}

/* ----------------------------------------------------------------------- *
 *  Stage 3 — seal_proposal                                                 *
 * ----------------------------------------------------------------------- */

/// Seal a [`BlockProposal`] with a set of committee votes into a
/// final [`Block`]: stage 3 of the 3-stage producer protocol.
///
/// `signing_stake` must equal the sum of stakes of the validators
/// whose votes are in `votes`. The producer is responsible for
/// computing it.
///
/// # Errors
///
/// [`ProducerError::Aggregation`] when [`mfn_consensus::finalize`]
/// can't aggregate the votes (empty vote list, malformed signatures,
/// etc.).
pub fn seal_proposal(
    proposal: BlockProposal,
    votes: &[mfn_bls::CommitteeVote],
    validators_len: usize,
    signing_stake: u64,
) -> Result<Block, ProducerError> {
    let agg = finalize(&proposal.header_hash, votes, validators_len)
        .map_err(|e| ProducerError::Aggregation(format!("{e:?}")))?;
    let fin = FinalityProof {
        producer: proposal.producer_proof,
        finality: agg,
        signing_stake,
    };
    Ok(seal_block(
        proposal.unsealed_header,
        proposal.txs,
        proposal.bond_ops,
        encode_finality_proof(&fin),
        proposal.slashings,
        proposal.storage_proofs,
    ))
}

/* ----------------------------------------------------------------------- *
 *  Convenience — produce_solo_block                                        *
 * ----------------------------------------------------------------------- */

/// All-in-one helper for the **solo-validator** case: producer is
/// also the only voter.
///
/// Runs all three stages in one call. Equivalent to:
///
/// ```ignore
/// let prop = build_proposal(state, producer, secrets, params, inputs)?;
/// let vote = vote_on_proposal(&prop, state, producer, secrets, producer, params)?;
/// seal_proposal(prop, &[vote], 1, producer.stake)
/// ```
///
/// Intended for tests and single-node demos. Multi-validator
/// production code should use the staged API directly so votes can
/// flow over the P2P layer.
///
/// # Errors
///
/// Forwards any [`ProducerError`] from the three stages.
pub fn produce_solo_block(
    chain: &Chain,
    producer: &Validator,
    secrets: &ValidatorSecrets,
    params: ConsensusParams,
    inputs: BlockInputs,
) -> Result<Block, ProducerError> {
    let state = chain.state();
    let proposal = build_proposal(state, producer, secrets, params, inputs)?;
    let vote = vote_on_proposal(&proposal, state, producer, secrets, producer, params)?;
    let signing_stake = producer.stake;
    let validators_len = state.validators.len();
    seal_proposal(proposal, &[vote], validators_len, signing_stake)
}

/* ----------------------------------------------------------------------- *
 *  Unit tests                                                              *
 * ----------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Chain, ChainConfig};
    use mfn_bls::bls_keygen_from_seed;
    use mfn_consensus::{
        build_coinbase, emission_at_height, ConsensusParams, GenesisConfig, PayoutAddress,
        Validator, ValidatorPayout, ValidatorSecrets, DEFAULT_EMISSION_PARAMS,
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

    fn single_validator_chain() -> (Chain, Validator, ValidatorSecrets, ConsensusParams) {
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
        let chain = Chain::from_genesis(ChainConfig::new(cfg)).expect("genesis");
        (chain, v0, s0, params)
    }

    fn coinbase_inputs(producer: &Validator, height: u32) -> BlockInputs {
        let p = producer.payout.unwrap();
        let cb_payout = PayoutAddress {
            view_pub: p.view_pub,
            spend_pub: p.spend_pub,
        };
        let emission = emission_at_height(u64::from(height), &DEFAULT_EMISSION_PARAMS);
        let cb = build_coinbase(u64::from(height), emission, &cb_payout).expect("cb");
        BlockInputs {
            height,
            slot: height,
            timestamp: u64::from(height) * 100,
            txs: vec![cb],
            bond_ops: Vec::new(),
            slashings: Vec::new(),
            storage_proofs: Vec::new(),
        }
    }

    /// `produce_solo_block` produces a block that the chain accepts.
    /// This is the headline contract — the helper has to compose
    /// with `Chain::apply` without any extra glue.
    #[test]
    fn produce_solo_block_yields_an_applyable_block() {
        let (mut chain, producer, secrets, params) = single_validator_chain();
        let inputs = coinbase_inputs(&producer, 1);
        let block =
            produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("produce solo");
        let id = chain.apply(&block).expect("apply");
        assert_eq!(chain.tip_height(), Some(1));
        assert_eq!(chain.tip_id(), Some(&id));
    }

    /// Running solo production five blocks in a row drives the chain
    /// forward each time. This proves the helper composes
    /// idempotently with the chain driver.
    #[test]
    fn produce_solo_block_five_in_a_row() {
        let (mut chain, producer, secrets, params) = single_validator_chain();
        let mut last_id = *chain.genesis_id();
        for height in 1..=5u32 {
            let inputs = coinbase_inputs(&producer, height);
            let block = produce_solo_block(&chain, &producer, &secrets, params, inputs)
                .expect("produce solo");
            let id = chain.apply(&block).expect("apply");
            assert_eq!(chain.tip_height(), Some(height));
            assert_ne!(id, last_id, "block ids must change between heights");
            last_id = id;
        }
    }

    /// `build_proposal` returns `NotSlotEligible` for a validator
    /// with zero stake.
    ///
    /// We construct an active genesis (so the chain bootstraps) but
    /// then ask for a proposal from a *different* validator whose
    /// stake is zero. The VRF eligibility check should refuse.
    #[test]
    fn build_proposal_refuses_ineligible_producer() {
        let (chain, _producer, _secrets, params) = single_validator_chain();
        // Construct a fresh stake-zero "validator" with valid keys.
        let (mut v_bad, s_bad) = mk_validator(99, 0);
        // v_bad isn't in state.validators, but try_produce_slot only
        // cares about (vrf_pk, stake, total_stake, params). Stake 0
        // → eligibility threshold 0 → never eligible.
        v_bad.stake = 0;
        let inputs = coinbase_inputs(&v_bad, 1);
        let err =
            build_proposal(chain.state(), &v_bad, &s_bad, params, inputs).expect_err("must refuse");
        assert!(
            matches!(err, ProducerError::NotSlotEligible { .. }),
            "expected NotSlotEligible, got {err:?}"
        );
    }

    /// The staged API (`build_proposal` → `vote_on_proposal` →
    /// `seal_proposal`) is equivalent to `produce_solo_block` for a
    /// solo validator. Same chain → same block-id by construction
    /// (every step is deterministic).
    #[test]
    fn staged_api_equivalent_to_solo_helper() {
        let (chain, producer, secrets, params) = single_validator_chain();
        let inputs = coinbase_inputs(&producer, 1);

        // Solo path.
        let solo_block =
            produce_solo_block(&chain, &producer, &secrets, params, inputs.clone()).expect("solo");

        // Staged path.
        let prop =
            build_proposal(chain.state(), &producer, &secrets, params, inputs).expect("propose");
        let vote = vote_on_proposal(&prop, chain.state(), &producer, &secrets, &producer, params)
            .expect("vote");
        let staged_block = seal_proposal(prop, &[vote], 1, producer.stake).expect("seal");

        assert_eq!(
            mfn_consensus::block_id(&solo_block.header),
            mfn_consensus::block_id(&staged_block.header),
            "staged and solo paths must produce the same block id"
        );
    }
}
