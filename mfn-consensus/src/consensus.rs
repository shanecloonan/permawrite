//! Slot-based PoS consensus.
//!
//! Port of `cloonan-group/lib/network/consensus.ts`. Combines the
//! privacy-friendly primitives we already have:
//!
//! - **VRF (ed25519)** — per-slot randomness from each validator's secret
//!   key. Determines who's "lucky" enough to propose this slot.
//! - **BLS (BLS12-381) committee** — N-of-K aggregate signatures over the
//!   proposed block header (the finality vote).
//! - **Stake-weighted thresholds** — a validator's VRF output must fall
//!   below `THRESHOLD · stake / Σ stake`. More stake → more lucky-slot
//!   mass. Sybil resistance is economic.
//! - **Slashable equivocation** — see [`crate::slashing`] for the on-chain
//!   evidence and verifier.
//!
//! ## Protocol per slot `s`
//!
//! 1. `slot_seed = dhash(CONSENSUS_SLOT, prev_hash || height || slot)`.
//! 2. Each validator `v` with stake `w_v` computes
//!    `y_v = VRF.output(sk_v_vrf, slot_seed)`; eligible iff
//!    `y_v < threshold · w_v / W`, where `W = Σ w_v`.
//! 3. The **producer** is the eligible validator with the smallest `y_v`
//!    (deterministic tiebreak; the proof carries both `y_v` and the VRF
//!    proof `π`).
//! 4. Producer assembles the block and BLS-signs the header.
//! 5. Each committee member verifies the producer's eligibility, then
//!    BLS-signs the header themselves.
//! 6. Producer aggregates the BLS votes (bitmap + Σ sig). If `≥ quorum` by
//!    stake-weight signed, the aggregate becomes the header's
//!    `producer_proof`.
//!
//! Close in spirit to Ouroboros Praos / Algorand BA, stripped to the
//! minimum cryptographic core. Network layer, view-change, long-range fork
//! choice, validator-set reconfiguration: out of scope here.

use curve25519_dalek::edwards::EdwardsPoint;

use mfn_bls::encode_public_key;
use mfn_bls::{
    aggregate_committee_votes, bls_sign, bls_verify, decode_signature, encode_signature,
    verify_committee_aggregate, BlsKeypair, BlsPublicKey, BlsResult, BlsSignature,
    CommitteeAggregate, CommitteeVote,
};
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::domain::{CONSENSUS_SLOT, VALIDATOR_LEAF};
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::merkle_root_or_zero;
use mfn_crypto::vrf::{
    decode_vrf_proof, encode_vrf_proof, vrf_output_as_u64, vrf_prove, vrf_verify, VrfKeypair,
    VrfProof,
};

/// Public payout destination of a validator (used by the chain's coinbase
/// routing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatorPayout {
    /// Public view key.
    pub view_pub: EdwardsPoint,
    /// Public spend key.
    pub spend_pub: EdwardsPoint,
}

/// A validator's on-chain record.
#[derive(Clone, Debug)]
pub struct Validator {
    /// Index into the canonical validator list (frozen at genesis in v0.1).
    pub index: u32,
    /// ed25519 VRF public key (for the leader lottery).
    pub vrf_pk: EdwardsPoint,
    /// BLS12-381 voting public key (for finality aggregation).
    pub bls_pk: BlsPublicKey,
    /// Effective stake weight.
    pub stake: u64,
    /// Optional stealth payout destination. When `Some`, the producer's
    /// block-reward coinbase pays to this address; when `None`, the block
    /// burns the coinbase (no UTXO created) — used for backward compat
    /// with pre-tokenomics validator records.
    pub payout: Option<ValidatorPayout>,
}

/* ----------------------------------------------------------------------- *
 *  Validator-set commitment (M2.0)                                         *
 * ----------------------------------------------------------------------- */

/// Canonical bytes for a single [`Validator`] when committed under the
/// block header's `validator_root`.
///
/// Layout (no domain prefix): `index(u32, BE) ‖ stake(u64, BE) ‖
/// vrf_pk(32) ‖ bls_pk(48) ‖ payout_flag(u8) ‖ [view_pub(32) ‖ spend_pub(32)]?`.
///
/// Deterministic; mirrors the on-wire encoding of these fields elsewhere.
/// Does **not** include [`crate::block::ValidatorStats`] — stats churn
/// every block via liveness tracking and would otherwise re-hash every
/// leaf needlessly. Light clients verifying a finality bitmap need
/// `(index, stake, bls_pk)` and nothing else.
#[must_use]
pub fn validator_leaf_bytes(v: &Validator) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(v.index);
    w.u64(v.stake);
    w.push(&v.vrf_pk.compress().to_bytes());
    w.push(&encode_public_key(&v.bls_pk));
    match &v.payout {
        None => {
            w.u8(0);
        }
        Some(p) => {
            w.u8(1);
            w.push(&p.view_pub.compress().to_bytes());
            w.push(&p.spend_pub.compress().to_bytes());
        }
    }
    w.into_bytes()
}

/// 32-byte Merkle leaf hash for one validator (domain-separated under
/// [`VALIDATOR_LEAF`]).
#[must_use]
pub fn validator_leaf_hash(v: &Validator) -> [u8; 32] {
    dhash(VALIDATOR_LEAF, &[&validator_leaf_bytes(v)])
}

/// Merkle root over the active validator set in canonical index order.
///
/// Empty validator set → all-zero sentinel (matches the other consensus
/// root commitments). This root is what every block header commits to,
/// reflecting the validator set the block is being validated against —
/// i.e., the *pre-block* validator set so the producer-proof + finality
/// bitmap are immediately verifiable from the header alone.
///
/// Bond ops, equivocation slashing, and liveness slashing all change
/// the next block's `validator_root`; the current block's root reflects
/// what *was*, not what *will be*.
#[must_use]
pub fn validator_set_root(validators: &[Validator]) -> [u8; 32] {
    if validators.is_empty() {
        return [0u8; 32];
    }
    let leaves: Vec<[u8; 32]> = validators.iter().map(validator_leaf_hash).collect();
    merkle_root_or_zero(&leaves)
}

/// Per-validator secret material (held only by the validator's process,
/// never persisted on-chain).
#[derive(Clone, Debug)]
pub struct ValidatorSecrets {
    /// Index in the canonical validator list.
    pub index: u32,
    /// VRF keypair.
    pub vrf: VrfKeypair,
    /// BLS keypair.
    pub bls: BlsKeypair,
}

/// Context for a single slot — what every validator needs to decide
/// eligibility and to verify a producer's proof.
#[derive(Clone, Debug)]
pub struct SlotContext {
    /// Block height being produced.
    pub height: u32,
    /// Slot number within the epoch (or globally — caller's choice).
    pub slot: u32,
    /// Hash of the previous block's signing header.
    pub prev_hash: [u8; 32],
}

/* ----------------------------------------------------------------------- *
 *  Slot seed                                                               *
 * ----------------------------------------------------------------------- */

/// Deterministic per-slot seed used as the VRF input.
///
/// Includes `prev_hash` so seeds are unique per fork, and the `(height,
/// slot)` pair so distinct attempts within a fork don't collide.
pub fn slot_seed(ctx: &SlotContext) -> [u8; 32] {
    let mut w = Writer::new();
    w.push(&ctx.prev_hash);
    w.u32(ctx.height);
    w.u32(ctx.slot);
    dhash(CONSENSUS_SLOT, &[w.bytes()])
}

/* ----------------------------------------------------------------------- *
 *  Eligibility                                                             *
 * ----------------------------------------------------------------------- */

/// Compute the producer-eligibility threshold for a validator with stake
/// `stake` out of total stake `total_stake`.
///
/// ```text
///     threshold = floor(2^64 · F · stake / total_stake)
/// ```
///
/// where `F = expected_proposers_per_slot` is a global parameter. Setting
/// `F = 1` makes the expected number of eligible validators per slot
/// exactly one (Algorand-style); typical config uses `F = 1.5` to keep
/// liveness against minority-stake offline validators.
///
/// **Encoding:** `F` is rounded to a `factor / 2^30` fixed-point value to
/// keep arithmetic deterministic. The computation
/// `(factor · stake · 2^34) / total_stake` fits in `u128` for any
/// realistic stake (stake ≤ 2^57 is more than enough for any chain that
/// also fits in `u64` base units).
pub fn eligibility_threshold(
    stake: u64,
    total_stake: u64,
    expected_proposers_per_slot: f64,
) -> u64 {
    if total_stake == 0 {
        return 0;
    }
    let factor: u64 = (expected_proposers_per_slot * f64::from(1u32 << 30)).round() as u64;
    // (factor * stake * 2^34) / total_stake — saturates to u64::MAX when
    // factor * stake / total_stake > 2^30 (i.e. the validator owns more
    // than 100% / F of the stake, which makes them deterministically
    // eligible every slot).
    let num: u128 = (factor as u128) * (stake as u128);
    let scaled: u128 = num << 34;
    let result: u128 = scaled / (total_stake as u128);
    result.min(u64::MAX as u128) as u64
}

/// Check eligibility from a 32-byte VRF output.
#[inline]
pub fn is_eligible(beta: &[u8; 32], threshold: u64) -> bool {
    vrf_output_as_u64(beta) < threshold
}

/* ----------------------------------------------------------------------- *
 *  Producer proof                                                          *
 * ----------------------------------------------------------------------- */

/// What a candidate producer broadcasts. The protocol picks the smallest
/// `beta` among all eligible candidates as the legitimate proposer for the
/// slot.
#[derive(Clone, Debug)]
pub struct ProducerProof {
    /// Index of the producing validator.
    pub validator_index: u32,
    /// VRF output `β` (raw 32 bytes).
    pub beta: [u8; 32],
    /// VRF proof `π` over the slot seed.
    pub vrf_proof: VrfProof,
    /// Producer's BLS signature over the block-header signing hash.
    pub producer_sig: BlsSignature,
}

/// Outcome of a verification check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusCheck {
    /// All checks passed.
    Ok,
    /// Validator index mismatch.
    IndexMismatch,
    /// VRF proof failed verification.
    VrfInvalid,
    /// VRF output did not match the proof's stated `beta`.
    VrfOutputMismatch,
    /// VRF output was at or above the eligibility threshold.
    NotEligible,
    /// Producer's BLS signature didn't verify.
    ProducerSigInvalid,
    /// Aggregate finality message ≠ expected header hash.
    FinalityMsgMismatch,
    /// Aggregate signature failed pairing check.
    AggregateInvalid,
    /// `signing_stake` claim didn't match the bitmap's stake sum.
    SigningStakeMismatch,
    /// Aggregate covered less than the configured quorum threshold.
    QuorumNotMet,
    /// Producer's `validator_index` not present in the validator set.
    ProducerNotInSet,
}

impl ConsensusCheck {
    /// `true` iff the check passed.
    #[inline]
    pub fn is_ok(&self) -> bool {
        matches!(self, ConsensusCheck::Ok)
    }
}

/// Run a validator's slot-eligibility check; if eligible, build their
/// candidate [`ProducerProof`].
///
/// `block_header_hash` is the [`crate::block::header_signing_hash`] of the
/// proposed header — what the producer signs and what every committee
/// member will later sign too.
///
/// Returns `Ok(None)` when the validator is NOT eligible this slot (the
/// common case for `F ≤ 1` and many validators).
pub fn try_produce_slot(
    ctx: &SlotContext,
    secrets: &ValidatorSecrets,
    validator: &Validator,
    total_stake: u64,
    expected_proposers_per_slot: f64,
    block_header_hash: &[u8; 32],
) -> Result<Option<ProducerProof>, ConsensusError> {
    if secrets.index != validator.index {
        return Err(ConsensusError::SecretsIndexMismatch);
    }
    let seed = slot_seed(ctx);
    let res = vrf_prove(&secrets.vrf, &seed).map_err(ConsensusError::Crypto)?;
    let threshold =
        eligibility_threshold(validator.stake, total_stake, expected_proposers_per_slot);
    if !is_eligible(&res.output, threshold) {
        return Ok(None);
    }
    let producer_sig = bls_sign(block_header_hash, &secrets.bls.sk);
    Ok(Some(ProducerProof {
        validator_index: validator.index,
        beta: res.output,
        vrf_proof: res.proof,
        producer_sig,
    }))
}

/// Verify a candidate [`ProducerProof`]. This is what every other
/// validator runs before BLS-signing the block in finality voting.
pub fn verify_producer_proof(
    ctx: &SlotContext,
    proof: &ProducerProof,
    validator: &Validator,
    total_stake: u64,
    expected_proposers_per_slot: f64,
    block_header_hash: &[u8; 32],
) -> ConsensusCheck {
    if proof.validator_index != validator.index {
        return ConsensusCheck::IndexMismatch;
    }
    let seed = slot_seed(ctx);
    let v = vrf_verify(&validator.vrf_pk, &seed, &proof.vrf_proof);
    if !v.ok {
        return ConsensusCheck::VrfInvalid;
    }
    if v.output != proof.beta {
        return ConsensusCheck::VrfOutputMismatch;
    }
    let threshold =
        eligibility_threshold(validator.stake, total_stake, expected_proposers_per_slot);
    if !is_eligible(&proof.beta, threshold) {
        return ConsensusCheck::NotEligible;
    }
    if !bls_verify(&proof.producer_sig, block_header_hash, &validator.bls_pk) {
        return ConsensusCheck::ProducerSigInvalid;
    }
    ConsensusCheck::Ok
}

/// Tiebreak among multiple eligible candidates: pick the smallest `beta`
/// (lexicographic byte order).
pub fn pick_winner(candidates: &[ProducerProof]) -> Option<&ProducerProof> {
    candidates.iter().min_by(|a, b| a.beta.cmp(&b.beta))
}

/* ----------------------------------------------------------------------- *
 *  Committee finality                                                      *
 * ----------------------------------------------------------------------- */

/// A committee member's vote on a producer's block.
pub fn cast_vote(
    block_header_hash: &[u8; 32],
    voter: &ValidatorSecrets,
    ctx: &SlotContext,
    producer: &ProducerProof,
    producer_validator: &Validator,
    total_stake: u64,
    expected_proposers_per_slot: f64,
) -> Result<CommitteeVote, ConsensusError> {
    let r = verify_producer_proof(
        ctx,
        producer,
        producer_validator,
        total_stake,
        expected_proposers_per_slot,
        block_header_hash,
    );
    if !r.is_ok() {
        return Err(ConsensusError::RefusingToVote(r));
    }
    Ok(CommitteeVote {
        index: voter.index as usize,
        sig: bls_sign(block_header_hash, &voter.bls.sk),
    })
}

/// Aggregate committee votes into a single [`CommitteeAggregate`].
pub fn finalize(
    block_header_hash: &[u8; 32],
    votes: &[CommitteeVote],
    total_validators: usize,
) -> BlsResult<CommitteeAggregate> {
    aggregate_committee_votes(block_header_hash, votes, total_validators)
}

/// A finality bundle — what goes into the block header's `producer_proof`.
#[derive(Clone, Debug)]
pub struct FinalityProof {
    /// VRF-eligible producer's proof.
    pub producer: ProducerProof,
    /// BLS-aggregated committee signatures.
    pub finality: CommitteeAggregate,
    /// Total stake-weight that signed (cached for fast verification).
    pub signing_stake: u64,
}

/// Verify a complete [`FinalityProof`] against the validator set.
pub fn verify_finality_proof(
    ctx: &SlotContext,
    proof: &FinalityProof,
    validators: &[Validator],
    expected_proposers_per_slot: f64,
    quorum_stake_bps: u32,
    block_header_hash: &[u8; 32],
) -> ConsensusCheck {
    let total_stake: u128 = validators.iter().map(|v| u128::from(v.stake)).sum();

    // 1. Producer exists in the validator set.
    let producer_validator = match validators
        .iter()
        .find(|v| v.index == proof.producer.validator_index)
    {
        Some(v) => v,
        None => return ConsensusCheck::ProducerNotInSet,
    };

    let pr = verify_producer_proof(
        ctx,
        &proof.producer,
        producer_validator,
        total_stake as u64,
        expected_proposers_per_slot,
        block_header_hash,
    );
    if !pr.is_ok() {
        return pr;
    }

    // 2. Aggregate covers the right message + verifies under the canonical
    //    validator pubkey set.
    if proof.finality.msg.as_slice() != block_header_hash.as_slice() {
        return ConsensusCheck::FinalityMsgMismatch;
    }
    let validator_pks: Vec<BlsPublicKey> = validators.iter().map(|v| v.bls_pk).collect();
    if !verify_committee_aggregate(&proof.finality, &validator_pks) {
        return ConsensusCheck::AggregateInvalid;
    }

    // 3. Sum stake of bitmap-marked validators.
    let mut signed: u128 = 0;
    for (i, v) in validators.iter().enumerate() {
        let byte = i >> 3;
        let bit = i & 7;
        if byte < proof.finality.bitmap.len() && (proof.finality.bitmap[byte] & (1u8 << bit)) != 0 {
            signed += u128::from(v.stake);
        }
    }
    if signed != u128::from(proof.signing_stake) {
        return ConsensusCheck::SigningStakeMismatch;
    }

    // quorum_stake_bps is in basis points (10000 = 100%). 6667 = 2/3 + 1bp.
    let required: u128 = (total_stake * u128::from(quorum_stake_bps)).div_ceil(10_000u128);
    if signed < required {
        return ConsensusCheck::QuorumNotMet;
    }

    ConsensusCheck::Ok
}

/* ----------------------------------------------------------------------- *
 *  Encoding                                                                *
 * ----------------------------------------------------------------------- */

/// Encode a [`ProducerProof`] to its consensus-critical bytes.
pub fn encode_producer_proof(p: &ProducerProof) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(p.validator_index);
    w.push(&p.beta);
    w.push(&encode_vrf_proof(&p.vrf_proof));
    w.push(&encode_signature(&p.producer_sig));
    w.into_bytes()
}

/// Decode bytes produced by [`encode_producer_proof`].
pub fn decode_producer_proof(bytes: &[u8]) -> Result<ProducerProof, ConsensusDecodeError> {
    let mut r = Reader::new(bytes);
    let validator_index = r.u32()?;
    let beta_raw = r.bytes(32)?;
    let mut beta = [0u8; 32];
    beta.copy_from_slice(beta_raw);
    let vrf_proof = decode_vrf_proof(r.bytes(mfn_crypto::vrf::VRF_PROOF_BYTES)?)?;
    let producer_sig = decode_signature(r.bytes(mfn_bls::BLS_SIGNATURE_BYTES)?)?;
    Ok(ProducerProof {
        validator_index,
        beta,
        vrf_proof,
        producer_sig,
    })
}

/// Encode a [`CommitteeAggregate`] to its consensus-critical bytes.
pub fn encode_committee_aggregate(c: &CommitteeAggregate) -> Vec<u8> {
    let mut w = Writer::new();
    w.blob(&c.msg);
    w.blob(&c.bitmap);
    w.push(&encode_signature(&c.agg_sig));
    w.into_bytes()
}

/// Decode a [`CommitteeAggregate`] from its bytes.
pub fn decode_committee_aggregate(
    bytes: &[u8],
) -> Result<CommitteeAggregate, ConsensusDecodeError> {
    let mut r = Reader::new(bytes);
    let msg = r.blob()?.to_vec();
    let bitmap = r.blob()?.to_vec();
    let agg_sig = decode_signature(r.bytes(mfn_bls::BLS_SIGNATURE_BYTES)?)?;
    Ok(CommitteeAggregate {
        msg,
        bitmap,
        agg_sig,
    })
}

/// Encode a full [`FinalityProof`].
pub fn encode_finality_proof(p: &FinalityProof) -> Vec<u8> {
    let mut w = Writer::new();
    w.blob(&encode_producer_proof(&p.producer));
    w.blob(&encode_committee_aggregate(&p.finality));
    w.u64(p.signing_stake);
    w.into_bytes()
}

/// Decode a [`FinalityProof`].
pub fn decode_finality_proof(bytes: &[u8]) -> Result<FinalityProof, ConsensusDecodeError> {
    let mut r = Reader::new(bytes);
    let producer_bytes = r.blob()?.to_vec();
    let producer = decode_producer_proof(&producer_bytes)?;
    let agg_bytes = r.blob()?.to_vec();
    let finality = decode_committee_aggregate(&agg_bytes)?;
    let signing_stake = r.u64()?;
    Ok(FinalityProof {
        producer,
        finality,
        signing_stake,
    })
}

/* ----------------------------------------------------------------------- *
 *  Errors                                                                  *
 * ----------------------------------------------------------------------- */

/// Errors from consensus-side helpers.
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    /// Caller passed `ValidatorSecrets` whose index disagrees with the
    /// associated `Validator`.
    #[error("validator/secrets index mismatch")]
    SecretsIndexMismatch,
    /// A committee member refused to vote on the producer's block (e.g.
    /// because the producer's proof didn't verify).
    #[error("refusing to vote: {0:?}")]
    RefusingToVote(ConsensusCheck),
    /// Underlying cryptographic operation failed (VRF, BLS).
    #[error(transparent)]
    Crypto(#[from] mfn_crypto::CryptoError),
}

/// Errors from decoding consensus-side wire formats.
#[derive(Debug, thiserror::Error)]
pub enum ConsensusDecodeError {
    /// Underlying buffer too short or malformed.
    #[error(transparent)]
    Codec(#[from] mfn_crypto::CryptoError),
    /// BLS signature decode failure.
    #[error(transparent)]
    Bls(#[from] mfn_bls::BlsError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_bls::bls_keygen_from_seed;
    use mfn_crypto::vrf::vrf_keygen_from_seed;

    fn fresh_validator(index: u32, stake: u64) -> (Validator, ValidatorSecrets) {
        let vrf = vrf_keygen_from_seed(&[index as u8 + 1; 32]).expect("vrf");
        let bls = bls_keygen_from_seed(&[index as u8 + 101; 32]);
        let val = Validator {
            index,
            vrf_pk: vrf.pk,
            bls_pk: bls.pk,
            stake,
            payout: None,
        };
        let secrets = ValidatorSecrets {
            index,
            vrf,
            bls: bls.clone(),
        };
        (val, secrets)
    }

    #[test]
    fn slot_seed_is_deterministic() {
        let ctx = SlotContext {
            height: 5,
            slot: 9,
            prev_hash: [7u8; 32],
        };
        assert_eq!(slot_seed(&ctx), slot_seed(&ctx));
    }

    #[test]
    fn slot_seed_changes_with_inputs() {
        let a = slot_seed(&SlotContext {
            height: 1,
            slot: 1,
            prev_hash: [0u8; 32],
        });
        let b = slot_seed(&SlotContext {
            height: 1,
            slot: 2,
            prev_hash: [0u8; 32],
        });
        assert_ne!(a, b);
    }

    #[test]
    fn full_stake_validator_is_eligible_at_f_eq_1() {
        // stake == total_stake and F == 1 ⇒ threshold == 2^64 (saturates),
        // so any VRF output is below threshold.
        let t = eligibility_threshold(100, 100, 1.0);
        assert_eq!(t, u64::MAX);
    }

    #[test]
    fn zero_total_stake_yields_zero_threshold() {
        assert_eq!(eligibility_threshold(0, 0, 1.0), 0);
    }

    #[test]
    fn threshold_scales_with_stake_fraction() {
        let half = eligibility_threshold(50, 100, 1.0);
        let quarter = eligibility_threshold(25, 100, 1.0);
        assert!(half > quarter);
        // Half-stake threshold ≈ 2 × quarter-stake (within rounding).
        let ratio = (half as u128) * 1000 / (quarter as u128);
        assert!((1990..=2010).contains(&ratio), "ratio={ratio}");
    }

    #[test]
    fn producer_round_trip_verifies() {
        let (val_a, sec_a) = fresh_validator(0, 1_000);
        let (val_b, _sec_b) = fresh_validator(1, 1_000);
        let validators = vec![val_a.clone(), val_b];
        let total_stake = 2_000u64;

        let ctx = SlotContext {
            height: 1,
            slot: 0,
            prev_hash: [42u8; 32],
        };
        let header_hash = [11u8; 32];

        // F=10 (way overshooting) so the validator is always eligible.
        let prop = try_produce_slot(&ctx, &sec_a, &val_a, total_stake, 10.0, &header_hash)
            .expect("propose")
            .expect("eligible at F=10");

        let chk = verify_producer_proof(&ctx, &prop, &val_a, total_stake, 10.0, &header_hash);
        assert_eq!(chk, ConsensusCheck::Ok);

        let _ = validators;
    }

    #[test]
    fn producer_proof_encode_decode_round_trip() {
        let (val, sec) = fresh_validator(0, 1_000);
        let ctx = SlotContext {
            height: 1,
            slot: 0,
            prev_hash: [42u8; 32],
        };
        let header_hash = [11u8; 32];
        let prop = try_produce_slot(&ctx, &sec, &val, 1_000, 10.0, &header_hash)
            .expect("propose")
            .expect("eligible");
        let bytes = encode_producer_proof(&prop);
        let dec = decode_producer_proof(&bytes).expect("decode");
        assert_eq!(dec.validator_index, prop.validator_index);
        assert_eq!(dec.beta, prop.beta);
        // Verifying again confirms VRF + BLS sigs survived the round-trip.
        assert_eq!(
            verify_producer_proof(&ctx, &dec, &val, 1_000, 10.0, &header_hash),
            ConsensusCheck::Ok
        );
    }

    #[test]
    fn committee_finality_quorum_succeeds() {
        // 3 validators, equal stake; quorum = 2/3 + 1 bp = 6667 bps.
        // All 3 sign → trivial quorum.
        let (v0, s0) = fresh_validator(0, 100);
        let (v1, s1) = fresh_validator(1, 100);
        let (v2, s2) = fresh_validator(2, 100);
        let validators = vec![v0.clone(), v1.clone(), v2.clone()];
        let total_stake = 300u64;
        let ctx = SlotContext {
            height: 1,
            slot: 0,
            prev_hash: [0u8; 32],
        };
        let header_hash = [99u8; 32];

        let prop = try_produce_slot(&ctx, &s0, &v0, total_stake, 10.0, &header_hash)
            .expect("propose")
            .expect("eligible");
        let vote_1 =
            cast_vote(&header_hash, &s1, &ctx, &prop, &v0, total_stake, 10.0).expect("vote 1");
        let vote_2 =
            cast_vote(&header_hash, &s2, &ctx, &prop, &v0, total_stake, 10.0).expect("vote 2");
        let vote_p =
            cast_vote(&header_hash, &s0, &ctx, &prop, &v0, total_stake, 10.0).expect("vote p");

        let agg = finalize(&header_hash, &[vote_p, vote_1, vote_2], validators.len()).expect("agg");

        let fin = FinalityProof {
            producer: prop,
            finality: agg,
            signing_stake: 300,
        };
        let chk = verify_finality_proof(&ctx, &fin, &validators, 10.0, 6667, &header_hash);
        assert_eq!(chk, ConsensusCheck::Ok);
    }

    #[test]
    fn committee_finality_quorum_fails_below_threshold() {
        let (v0, s0) = fresh_validator(0, 100);
        let (v1, s1) = fresh_validator(1, 100);
        let (v2, _s2) = fresh_validator(2, 100);
        let validators = vec![v0.clone(), v1.clone(), v2.clone()];
        let total_stake = 300u64;
        let ctx = SlotContext {
            height: 1,
            slot: 0,
            prev_hash: [0u8; 32],
        };
        let header_hash = [99u8; 32];

        let prop = try_produce_slot(&ctx, &s0, &v0, total_stake, 10.0, &header_hash)
            .expect("propose")
            .expect("eligible");
        // Only producer + one other vote (200/300 = 66.67%, BELOW 6667 bps
        // quorum which is 66.67% strict).
        let vote_1 =
            cast_vote(&header_hash, &s1, &ctx, &prop, &v0, total_stake, 10.0).expect("vote 1");
        let vote_p =
            cast_vote(&header_hash, &s0, &ctx, &prop, &v0, total_stake, 10.0).expect("vote p");

        let agg = finalize(&header_hash, &[vote_p, vote_1], validators.len()).expect("agg");

        let fin = FinalityProof {
            producer: prop,
            finality: agg,
            signing_stake: 200,
        };
        let chk = verify_finality_proof(&ctx, &fin, &validators, 10.0, 6667, &header_hash);
        assert_eq!(chk, ConsensusCheck::QuorumNotMet);
    }

    #[test]
    fn finality_proof_encode_decode_round_trip() {
        let (v0, s0) = fresh_validator(0, 100);
        let (v1, s1) = fresh_validator(1, 100);
        let (v2, s2) = fresh_validator(2, 100);
        let validators = vec![v0.clone(), v1, v2.clone()];
        let total_stake = 300u64;
        let ctx = SlotContext {
            height: 1,
            slot: 0,
            prev_hash: [0u8; 32],
        };
        let header_hash = [99u8; 32];

        let prop = try_produce_slot(&ctx, &s0, &v0, total_stake, 10.0, &header_hash)
            .expect("propose")
            .expect("eligible");
        let votes = vec![
            cast_vote(&header_hash, &s0, &ctx, &prop, &v0, total_stake, 10.0).unwrap(),
            cast_vote(&header_hash, &s1, &ctx, &prop, &v0, total_stake, 10.0).unwrap(),
            cast_vote(&header_hash, &s2, &ctx, &prop, &v0, total_stake, 10.0).unwrap(),
        ];
        let agg = finalize(&header_hash, &votes, validators.len()).expect("agg");
        let fin = FinalityProof {
            producer: prop,
            finality: agg,
            signing_stake: 300,
        };

        let bytes = encode_finality_proof(&fin);
        let dec = decode_finality_proof(&bytes).expect("decode");
        let chk = verify_finality_proof(&ctx, &dec, &validators, 10.0, 6667, &header_hash);
        assert_eq!(chk, ConsensusCheck::Ok);
    }

    #[test]
    fn pick_winner_picks_smallest_beta() {
        // Construct three fake ProducerProofs with hand-picked betas.
        let mk_dummy = |i: u32, beta_byte: u8| -> ProducerProof {
            let (_v, s) = fresh_validator(i, 100);
            let mut beta = [255u8; 32];
            beta[0] = beta_byte;
            let res = vrf_prove(&s.vrf, b"placeholder").unwrap();
            ProducerProof {
                validator_index: i,
                beta,
                vrf_proof: res.proof,
                producer_sig: bls_sign(&beta, &s.bls.sk),
            }
        };
        let candidates = vec![mk_dummy(0, 50), mk_dummy(1, 10), mk_dummy(2, 30)];
        let w = pick_winner(&candidates).expect("winner");
        assert_eq!(w.validator_index, 1);
    }

    /* ----------------------------------------------------------------- *
     *  Validator-set commitment (M2.0)                                   *
     * ----------------------------------------------------------------- */

    #[test]
    fn validator_leaf_bytes_depend_on_every_field() {
        let (mut v, _) = fresh_validator(0, 1_000);

        let base = validator_leaf_bytes(&v);

        v.index = 1;
        let by_index = validator_leaf_bytes(&v);
        assert_ne!(base, by_index, "index must influence leaf");

        v.index = 0;
        v.stake = 999;
        let by_stake = validator_leaf_bytes(&v);
        assert_ne!(base, by_stake, "stake must influence leaf");

        v.stake = 1_000;
        v.vrf_pk = fresh_validator(7, 1_000).0.vrf_pk;
        let by_vrf = validator_leaf_bytes(&v);
        assert_ne!(base, by_vrf, "vrf_pk must influence leaf");

        let (mut v2, _) = fresh_validator(0, 1_000);
        v2.bls_pk = fresh_validator(7, 1_000).0.bls_pk;
        assert_ne!(
            validator_leaf_bytes(&v2),
            base,
            "bls_pk must influence leaf"
        );

        // Payout presence flips a discriminator byte.
        let (mut vp, _) = fresh_validator(0, 1_000);
        vp.payout = Some(ValidatorPayout {
            view_pub: curve25519_dalek::edwards::EdwardsPoint::default(),
            spend_pub: curve25519_dalek::edwards::EdwardsPoint::default(),
        });
        assert_ne!(validator_leaf_bytes(&vp), base, "payout flag changes leaf");
    }

    #[test]
    fn validator_leaf_hash_is_domain_separated() {
        // Two distinct ways of arriving at "equal bytes" must not produce
        // a collision because of [`VALIDATOR_LEAF`] domain separation.
        let (v, _) = fresh_validator(0, 1_000);
        let h = validator_leaf_hash(&v);
        // Direct dhash with a different domain should differ.
        let other = mfn_crypto::hash::dhash(b"MFBN-1/not-a-leaf", &[&validator_leaf_bytes(&v)]);
        assert_ne!(h, other);
    }

    #[test]
    fn validator_set_root_empty_is_zero_sentinel() {
        assert_eq!(validator_set_root(&[]), [0u8; 32]);
    }

    #[test]
    fn validator_set_root_changes_when_stake_changes() {
        let (mut v0, _) = fresh_validator(0, 1_000);
        let (v1, _) = fresh_validator(1, 1_000);
        let r0 = validator_set_root(&[v0.clone(), v1.clone()]);
        v0.stake = 999_999;
        let r1 = validator_set_root(&[v0, v1]);
        assert_ne!(r0, r1, "slashing/rotation must move the root");
    }

    #[test]
    fn validator_set_root_changes_with_order() {
        // The set is committed in *canonical (chain-stored) order* — not
        // a sorted multiset. Tests must defend against accidental
        // commutative collapse.
        let (v0, _) = fresh_validator(0, 1_000);
        let (v1, _) = fresh_validator(1, 1_000);
        let a = validator_set_root(&[v0.clone(), v1.clone()]);
        let b = validator_set_root(&[v1, v0]);
        assert_ne!(a, b);
    }

    #[test]
    fn validator_set_root_changes_when_validator_added() {
        let (v0, _) = fresh_validator(0, 1_000);
        let (v1, _) = fresh_validator(1, 1_000);
        let r_one = validator_set_root(std::slice::from_ref(&v0));
        let r_two = validator_set_root(&[v0, v1]);
        assert_ne!(r_one, r_two, "registering a validator must move the root");
    }

    /// TS-parity golden vector for the M2.0 validator-set commitment.
    ///
    /// Pinned to deterministic seed inputs so the `cloonan-group`
    /// reference can mirror byte-for-byte. The vector covers all three
    /// public helpers: `validator_leaf_bytes`, `validator_leaf_hash`,
    /// and `validator_set_root` over a non-trivial set (one validator
    /// with payout, one without — exercises both branches of the
    /// canonical encoding).
    ///
    /// **Reference inputs:**
    /// - `v0`: index=0, stake=1_000_000,
    ///   `vrf_pk = vrf_keygen_from_seed([1; 32]).pk`,
    ///   `bls_pk = bls_keygen_from_seed([101; 32]).pk`, payout=None
    /// - `v1`: index=1, stake=2_000_000,
    ///   `vrf_pk = vrf_keygen_from_seed([2; 32]).pk`,
    ///   `bls_pk = bls_keygen_from_seed([102; 32]).pk`,
    ///   `payout.view_pub = 3 · G`, `payout.spend_pub = 5 · G`
    #[test]
    fn validator_root_wire_matches_cloonan_ts_smoke_reference() {
        use curve25519_dalek::scalar::Scalar;
        use mfn_crypto::point::generator_g;

        let vrf0 = vrf_keygen_from_seed(&[1u8; 32]).expect("vrf0");
        let bls0 = bls_keygen_from_seed(&[101u8; 32]);
        let v0 = Validator {
            index: 0,
            vrf_pk: vrf0.pk,
            bls_pk: bls0.pk,
            stake: 1_000_000,
            payout: None,
        };

        let vrf1 = vrf_keygen_from_seed(&[2u8; 32]).expect("vrf1");
        let bls1 = bls_keygen_from_seed(&[102u8; 32]);
        let v1 = Validator {
            index: 1,
            vrf_pk: vrf1.pk,
            bls_pk: bls1.pk,
            stake: 2_000_000,
            payout: Some(ValidatorPayout {
                view_pub: generator_g() * Scalar::from(3u64),
                spend_pub: generator_g() * Scalar::from(5u64),
            }),
        };

        // ----- v0 (no payout) -----
        // 4 (index) + 8 (stake) + 32 (vrf_pk) + 48 (bls_pk) + 1 (payout_flag) = 93 bytes
        let v0_bytes = validator_leaf_bytes(&v0);
        assert_eq!(
            v0_bytes.len(),
            93,
            "v0 canonical leaf must be 93 bytes (no payout branch)"
        );
        assert_eq!(
            hex::encode(&v0_bytes),
            "0000000000000000000f42408a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5cb5a05f6d4ac7b5906f838f775da2c17d3b1f77aead8860b10922e816fb7419541642a9f70f2c101600554d315a8f6c5900",
            "v0 canonical bytes drifted"
        );
        let v0_leaf = validator_leaf_hash(&v0);
        assert_eq!(
            hex::encode(v0_leaf),
            "00c034ee4366815b9dc13f4769e47090a86a5ab7f355477e67135fa7f958b605",
            "v0 (no payout) leaf hash drifted"
        );

        // ----- v1 (with payout) -----
        // 93 + 32 (view_pub) + 32 (spend_pub) = 157 bytes
        let v1_bytes = validator_leaf_bytes(&v1);
        assert_eq!(
            v1_bytes.len(),
            157,
            "v1 canonical leaf must be 157 bytes (with-payout branch)"
        );
        assert_eq!(
            hex::encode(&v1_bytes),
            "0000000100000000001e84808139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394ae5765f8aa19f64c622783fe27b225cb75d79b03c69178cc73e8f72ada2814436f9161cba5489be72448779e9786325001d4b4f5784868c3020403246717ec169ff79e26608ea126a1ab69ee77d1b16712edc876d6831fd2105d0b4389ca2e283166469289146e2ce06faefe98b22548df",
            "v1 canonical bytes drifted"
        );
        let v1_leaf = validator_leaf_hash(&v1);
        assert_eq!(
            hex::encode(v1_leaf),
            "ee082d7d2df87805f7bc2058d87de8f149832bfedb8df11f3b66752d6af674c0",
            "v1 (with payout) leaf hash drifted"
        );

        // ----- root over [v0, v1] -----
        let root = validator_set_root(&[v0, v1]);
        assert_eq!(
            hex::encode(root),
            "dad4793fd4c01fc2710792e5fe4afb5391b701f6ad3f884d7515c7f04d1445a7",
            "validator_set_root over [v0, v1] drifted"
        );
    }
}
