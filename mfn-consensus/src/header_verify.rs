//! Light-client verification primitives.
//!
//! This module hosts the **pure, state-free** verification functions
//! a light client uses to follow the chain without holding a full
//! [`crate::block::ChainState`]:
//!
//! - [`verify_header`] (M2.0.5) — given a trusted pre-block validator
//!   set and a [`BlockHeader`], verify the header's consensus-critical
//!   commitments (validator-set commitment + producer proof + BLS
//!   finality aggregate).
//! - [`verify_block_body`] (M2.0.7) — given a [`crate::block::Block`],
//!   re-derive the five body-bound Merkle roots that are pure
//!   functions of the block body (`tx_root`, `bond_root`,
//!   `slashing_root`, `storage_proof_root`, `claims_root`) and verify they match
//!   the header. The other two header-bound roots (`storage_root`,
//!   `utxo_root`) are state-dependent and out-of-scope for stateless
//!   verification — they're already cryptographically bound through
//!   the BLS aggregate verified by [`verify_header`].
//!
//! ## Why this primitive exists
//!
//! After milestones M2.0 / M2.0.1 / M2.0.2 the [`BlockHeader`] binds
//! every block-body element (txs, bond ops, slashings, the pre-block
//! validator set, and storage proofs) under the producer's BLS
//! aggregate. That means a verifier holding *only* the header chain
//! can structurally re-derive every body root from a body delivered
//! out-of-band, *and* — crucially — verify that the header itself was
//! BLS-signed by a quorum of the validator set it claims to commit
//! to. This module is the verification half of that contract.
//!
//! `apply_block` already does all the same cryptographic checks
//! internally as part of Phase 0 + Phase 1 of the state-transition
//! function (see [`crate::block::apply_block`]). But `apply_block`
//! requires a full [`crate::block::ChainState`] — it needs to
//! actually mutate state, run the storage-proof phase, settle
//! unbonds, etc. A light client doesn't have a `ChainState`. It has
//! a header chain plus a *trusted starting validator set* (typically
//! the genesis config). [`verify_header`] is the part of `apply_block`
//! that's safe to run with only that.
//!
//! ## Chain of trust
//!
//! The light-client model is:
//!
//! ```text
//!  trusted starting validators (e.g. genesis cfg.validators)
//!         │
//!         ▼
//!  verify_header(header_1, trusted_validators_0, params)  ──► OK
//!         │
//!         │  (caller replays block_1.bond_ops / slashings / unbonds
//!         │   against trusted_validators_0 to derive
//!         │   trusted_validators_1 — body needed for this step)
//!         ▼
//!  verify_header(header_2, trusted_validators_1, params)  ──► OK
//!         │
//!         ▼
//!         …
//! ```
//!
//! [`verify_header`] alone only handles a single hop. Walking the
//! whole chain (and tracking the trusted validator-set evolution as
//! it rotates through `BondOp`s and slashings) is the job of the
//! future `mfn-light` crate. Splitting the concerns this way keeps
//! the *cryptographic* primitive pure: same inputs, same outputs,
//! no IO, no async, no clock.
//!
//! ## Not in scope
//!
//! - **Header chain linkage.** Confirming `header.prev_hash ==
//!   block_id(prev_header)` and `header.height == prev_height + 1`
//!   is the caller's responsibility — chained headers are verified
//!   by whoever decides which chain to follow (in practice the
//!   `mfn-light::LightChain` driver).
//! - **State-dependent body roots.** `storage_root` and `utxo_root`
//!   are functions of accumulated chain state, not pure functions of
//!   the block body. A stateless verifier can't independently
//!   recompute them; they're already covered by the BLS aggregate
//!   (which signs over `header_signing_hash`, including those roots).

use crate::block::{header_signing_hash, tx_merkle_root, Block, BlockHeader, ConsensusParams};
use crate::bond_wire::bond_merkle_root;
use crate::claims::{claims_merkle_root, collect_claim_merkle_leaves_for_txs};
use crate::consensus::{
    decode_finality_proof, validator_set_root, verify_finality_proof, ConsensusCheck,
    ConsensusDecodeError, SlotContext, Validator,
};
use crate::slashing::slashing_merkle_root;
use mfn_storage::storage_proof_merkle_root;

/* ----------------------------------------------------------------------- *
 *  Result                                                                  *
 * ----------------------------------------------------------------------- */

/// Successful verification of a header. Carries enough info for a
/// light client to (a) confirm which validator produced the block,
/// and (b) understand how much stake voted.
///
/// `quorum_reached` is always `true` for a successful verification —
/// it's exposed as a field so callers writing their own
/// quorum-stricter policies (e.g. "I require 90% stake even though
/// the chain only requires 2/3") can compare `signing_stake` to
/// `total_stake` directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderCheck {
    /// Validator index of the block producer (as recorded in the
    /// `producer_proof`'s VRF half).
    pub producer_index: u32,
    /// Sum of stake of validators whose bit is set in the
    /// finality bitmap.
    pub signing_stake: u64,
    /// Sum of stake of *all* validators in the trusted set.
    pub total_stake: u64,
    /// Minimum signing stake required to clear quorum at
    /// `params.quorum_stake_bps`. Always `signing_stake >= quorum_required`
    /// for a successful verification (this is *what* was verified).
    pub quorum_required: u64,
    /// Number of validators in the trusted set.
    pub validator_count: usize,
    /// Always `true` for a successful verification; exposed so
    /// stricter callers can pattern-match without redoing the math.
    pub quorum_reached: bool,
}

/* ----------------------------------------------------------------------- *
 *  Errors                                                                  *
 * ----------------------------------------------------------------------- */

/// Failure modes of [`verify_header`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HeaderVerifyError {
    /// `header.validator_root` does not equal
    /// `validator_set_root(trusted_validators)`. The trust anchor
    /// the caller provided doesn't match the set the producer
    /// claimed to commit to — either the caller's set is wrong, or
    /// the header is for a different chain.
    #[error("validator_root mismatch: header committed a different validator set than the caller's trusted set")]
    ValidatorRootMismatch,

    /// Header has an empty `producer_proof`, but the trusted set is
    /// non-empty. This only happens for the genesis block (which is
    /// the trust anchor, not light-verifiable in the normal sense).
    /// Light clients should bootstrap from a `GenesisConfig`, not
    /// try to "verify" the genesis header.
    #[error("genesis-style header (empty producer_proof) cannot be light-verified")]
    GenesisHeader,

    /// `header.producer_proof` failed to decode. The header is
    /// malformed.
    #[error("producer_proof decode failed: {0}")]
    ProducerProofDecode(String),

    /// One of the cryptographic / structural finality checks failed.
    /// See [`ConsensusCheck`] for the specific reason.
    #[error("finality proof rejected: {0:?}")]
    FinalityRejected(ConsensusCheck),

    /// `trusted_validators` was empty. A light client *must* be
    /// bootstrapped with a non-empty trusted set; verifying a header
    /// against an empty set is structurally meaningless.
    #[error(
        "trusted validator set is empty — light client must be bootstrapped with a non-empty set"
    )]
    EmptyTrustedSet,
}

impl From<ConsensusDecodeError> for HeaderVerifyError {
    fn from(e: ConsensusDecodeError) -> Self {
        HeaderVerifyError::ProducerProofDecode(format!("{e}"))
    }
}

/* ----------------------------------------------------------------------- *
 *  Verify                                                                  *
 * ----------------------------------------------------------------------- */

/// Verify a [`BlockHeader`] against a trusted *pre-block* validator
/// set.
///
/// "Pre-block" is the same convention `apply_block` uses for
/// `validator_root`: the set that was in force at the moment the
/// producer signed the header. Any rotation / slashing / unbond
/// settlement applied *by* this block moves the *next* header's
/// `validator_root`, and is the caller's responsibility to apply
/// before verifying the next header (typically by replaying
/// `block.bond_ops`, `block.slashings`, and any pending-unbond
/// settlements against their own trusted-validators bookkeeping).
///
/// # Checks performed (in order)
///
/// 1. **Trusted set non-empty.** Empty set → [`HeaderVerifyError::EmptyTrustedSet`].
/// 2. **Validator-root match.** `validator_set_root(trusted) ==
///    header.validator_root` (the trust anchor). Mismatch →
///    [`HeaderVerifyError::ValidatorRootMismatch`].
/// 3. **Producer-proof present.** Genesis-style headers (empty
///    `producer_proof`) → [`HeaderVerifyError::GenesisHeader`].
/// 4. **Producer-proof decode.** Malformed bytes →
///    [`HeaderVerifyError::ProducerProofDecode`].
/// 5. **Full [`verify_finality_proof`].** This covers producer VRF +
///    ed25519 + slot eligibility, BLS aggregate over the header
///    signing hash, signing-stake-bitmap consistency, and quorum
///    threshold. Any failure → [`HeaderVerifyError::FinalityRejected`].
///
/// # Determinism
///
/// Pure function. No IO, no allocation beyond what `verify_finality_proof`
/// requires, no clock. Calling this with the same `(header,
/// trusted_validators, params)` returns byte-for-byte the same
/// result.
///
/// # Errors
///
/// See variants of [`HeaderVerifyError`].
pub fn verify_header(
    header: &BlockHeader,
    trusted_validators: &[Validator],
    params: &ConsensusParams,
) -> Result<HeaderCheck, HeaderVerifyError> {
    // (1) Trusted-set non-empty.
    if trusted_validators.is_empty() {
        return Err(HeaderVerifyError::EmptyTrustedSet);
    }

    // (2) Validator-root match.
    let computed_root = validator_set_root(trusted_validators);
    if computed_root != header.validator_root {
        return Err(HeaderVerifyError::ValidatorRootMismatch);
    }

    // (3) Producer-proof present.
    if header.producer_proof.is_empty() {
        return Err(HeaderVerifyError::GenesisHeader);
    }

    // (4) Producer-proof decode.
    let fin = decode_finality_proof(&header.producer_proof)?;

    // (5) Full finality verification.
    let ctx = SlotContext {
        height: header.height,
        slot: header.slot,
        prev_hash: header.prev_hash,
    };
    let header_hash = header_signing_hash(header);
    let check = verify_finality_proof(
        &ctx,
        &fin,
        trusted_validators,
        params.expected_proposers_per_slot,
        params.quorum_stake_bps,
        &header_hash,
    );
    if !check.is_ok() {
        return Err(HeaderVerifyError::FinalityRejected(check));
    }

    // Compute quorum stats for the caller.
    let total_stake: u64 = trusted_validators.iter().map(|v| v.stake).sum();
    let quorum_required =
        (u128::from(total_stake) * u128::from(params.quorum_stake_bps)).div_ceil(10_000u128) as u64;

    Ok(HeaderCheck {
        producer_index: fin.producer.validator_index,
        signing_stake: fin.signing_stake,
        total_stake,
        quorum_required,
        validator_count: trusted_validators.len(),
        quorum_reached: true,
    })
}

/* ----------------------------------------------------------------------- *
 *  Body verification (M2.0.7)                                              *
 * ----------------------------------------------------------------------- */

/// Failure modes of [`verify_block_body`]. Each variant carries the
/// header's claimed root (`expected`) and the root the verifier
/// computed from the delivered body (`got`) so callers can log a
/// useful diagnostic.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BodyVerifyError {
    /// `header.tx_root` doesn't equal `tx_merkle_root(&block.txs)`.
    /// The delivered txs are not the txs the header was signed over.
    #[error("tx_root mismatch")]
    TxRootMismatch {
        /// Root the header claims (the value the producer BLS-signed
        /// over via `header_signing_hash`).
        expected: [u8; 32],
        /// Root the verifier computed from `block.txs`.
        got: [u8; 32],
    },

    /// `header.bond_root` doesn't equal `bond_merkle_root(&block.bond_ops)`.
    #[error("bond_root mismatch")]
    BondRootMismatch {
        /// Root the header claims.
        expected: [u8; 32],
        /// Root the verifier computed from `block.bond_ops`.
        got: [u8; 32],
    },

    /// `header.slashing_root` doesn't equal `slashing_merkle_root(&block.slashings)`.
    /// (Leaves are canonicalized per M2.0.1, so pair-swap inside an
    /// evidence pair is a no-op — but a different set of evidences,
    /// or a different number, moves the root.)
    #[error("slashing_root mismatch")]
    SlashingRootMismatch {
        /// Root the header claims.
        expected: [u8; 32],
        /// Root the verifier computed from `block.slashings`.
        got: [u8; 32],
    },

    /// `header.storage_proof_root` doesn't equal
    /// `storage_proof_merkle_root(&block.storage_proofs)`.
    /// (Order is producer-emit; see M2.0.2.)
    #[error("storage_proof_root mismatch")]
    StorageProofRootMismatch {
        /// Root the header claims.
        expected: [u8; 32],
        /// Root the verifier computed from `block.storage_proofs`.
        got: [u8; 32],
    },

    /// `header.claims_root` didn't match the Merkle root over verified
    /// authorship claim leaves (M2.2.x).
    #[error("claims_root mismatch")]
    ClaimsRootMismatch {
        /// Root the header claims.
        expected: [u8; 32],
        /// Root the verifier computed from `block.txs` extras.
        got: [u8; 32],
    },

    /// Malformed `MFEX` / `MFCL` or an invalid claim signature in some tx.
    #[error("authorship claims body invalid: {0}")]
    AuthorshipClaimsBody(String),
}

/// Verify that a delivered [`Block`] body matches the five
/// header-bound body roots that are pure functions of the block body
/// alone:
///
/// - [`BlockHeader::tx_root`] == `tx_merkle_root(&block.txs)`
/// - [`BlockHeader::bond_root`] == `bond_merkle_root(&block.bond_ops)`
/// - [`BlockHeader::slashing_root`] == `slashing_merkle_root(&block.slashings)`
/// - [`BlockHeader::storage_proof_root`] == `storage_proof_merkle_root(&block.storage_proofs)`
/// - [`BlockHeader::claims_root`] == Merkle root over verified authorship
///   claim leaves in block order (non-coinbase txs; see M2.2.x)
///
/// Combined with [`verify_header`] — which verifies that
/// `header_signing_hash` was BLS-signed by a quorum of the trusted
/// validator set, and `header_signing_hash` binds all five of these
/// roots — this gives a light client cryptographic confidence that
/// the delivered body is **the** body the producer signed over. A
/// malicious peer cannot deliver a tampered body without one of
/// these checks rejecting.
///
/// ## What this function does *not* verify
///
/// - [`BlockHeader::storage_root`] — depends on cross-block dedup
///   against the chain's `storage` map. Stateless verification of
///   this root has a false-positive rate when blocks contain
///   re-anchoring txs (which `apply_block` silently filters out).
///   A future light-client slice that maintains a `storage` shadow
///   set could add this check.
/// - [`BlockHeader::utxo_root`] — depends on the cumulative UTXO
///   accumulator. Same reasoning: requires state.
/// - [`BlockHeader::validator_root`] — already verified via the
///   trust anchor in [`verify_header`].
///
/// Both state-dependent roots are *already cryptographically bound*
/// through the BLS aggregate signing `header_signing_hash` (which
/// includes them). So even though a stateless verifier can't
/// independently recompute them, a forged block can't smuggle them
/// past [`verify_header`].
///
/// ## Determinism
///
/// Pure function. No IO, no allocation beyond what the underlying
/// `*_merkle_root` helpers require. Calling this with the same
/// `&Block` returns byte-for-byte the same result.
///
/// # Errors
///
/// See variants of [`BodyVerifyError`].
pub fn verify_block_body(block: &Block) -> Result<(), BodyVerifyError> {
    let tx_root = tx_merkle_root(&block.txs);
    if tx_root != block.header.tx_root {
        return Err(BodyVerifyError::TxRootMismatch {
            expected: block.header.tx_root,
            got: tx_root,
        });
    }

    let bond_root = bond_merkle_root(&block.bond_ops);
    if bond_root != block.header.bond_root {
        return Err(BodyVerifyError::BondRootMismatch {
            expected: block.header.bond_root,
            got: bond_root,
        });
    }

    let slashing_root = slashing_merkle_root(&block.slashings);
    if slashing_root != block.header.slashing_root {
        return Err(BodyVerifyError::SlashingRootMismatch {
            expected: block.header.slashing_root,
            got: slashing_root,
        });
    }

    let storage_proof_root = storage_proof_merkle_root(&block.storage_proofs);
    if storage_proof_root != block.header.storage_proof_root {
        return Err(BodyVerifyError::StorageProofRootMismatch {
            expected: block.header.storage_proof_root,
            got: storage_proof_root,
        });
    }

    let claim_leaves = collect_claim_merkle_leaves_for_txs(&block.txs, block.header.height)
        .map_err(|e| BodyVerifyError::AuthorshipClaimsBody(e.to_string()))?;
    let claims_root = claims_merkle_root(&claim_leaves);
    if claims_root != block.header.claims_root {
        return Err(BodyVerifyError::ClaimsRootMismatch {
            expected: block.header.claims_root,
            got: claims_root,
        });
    }

    Ok(())
}

/* ----------------------------------------------------------------------- *
 *  Unit tests                                                              *
 * ----------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{apply_genesis, build_genesis, build_unsealed_header, seal_block};
    use crate::coinbase::{build_coinbase, PayoutAddress};
    use crate::consensus::{
        cast_vote, encode_finality_proof, finalize, try_produce_slot, FinalityProof, Validator,
        ValidatorPayout, ValidatorSecrets,
    };
    use crate::emission::{emission_at_height, DEFAULT_EMISSION_PARAMS};
    use crate::{ConsensusParams, GenesisConfig};
    use mfn_bls::bls_keygen_from_seed;
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

    /// Build a real, fully signed block at height 1 against a
    /// single-validator chain. Returns the header + the validator
    /// set the header was signed against (i.e. the pre-block set).
    fn build_signed_block_1() -> (
        crate::block::Block,
        Vec<Validator>,
        ConsensusParams,
        ValidatorSecrets,
    ) {
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
        let genesis = build_genesis(&cfg);
        let state = apply_genesis(&genesis, &cfg).expect("apply genesis");

        // Build block 1.
        let payout = v0.payout.unwrap();
        let cb_payout = PayoutAddress {
            view_pub: payout.view_pub,
            spend_pub: payout.spend_pub,
        };
        let emission = emission_at_height(1, &DEFAULT_EMISSION_PARAMS);
        let cb = build_coinbase(1, emission, &cb_payout).expect("cb");
        let txs = vec![cb];

        let unsealed = build_unsealed_header(&state, &txs, &[], &[], &[], 1, 100);
        let header_hash = header_signing_hash(&unsealed);
        let ctx = SlotContext {
            height: 1,
            slot: 1,
            prev_hash: unsealed.prev_hash,
        };
        let total_stake = v0.stake;
        let producer_proof = try_produce_slot(
            &ctx,
            &s0,
            &v0,
            total_stake,
            params.expected_proposers_per_slot,
            &header_hash,
        )
        .expect("produce")
        .expect("eligible");
        let vote = cast_vote(
            &header_hash,
            &s0,
            &ctx,
            &producer_proof,
            &v0,
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
        let block = seal_block(
            unsealed,
            txs,
            Vec::new(),
            encode_finality_proof(&fin),
            Vec::new(),
            Vec::new(),
        );
        (block, vec![v0], params, s0)
    }

    /// Headline case: a real signed block 1 verifies under its
    /// pre-block validator set.
    #[test]
    fn verify_header_accepts_real_signed_block() {
        let (block, validators, params, _s0) = build_signed_block_1();
        let check = verify_header(&block.header, &validators, &params).expect("must verify");
        assert_eq!(check.producer_index, 0);
        assert_eq!(check.signing_stake, 1_000_000);
        assert_eq!(check.total_stake, 1_000_000);
        assert!(check.quorum_reached);
        assert_eq!(check.validator_count, 1);
        // 1_000_000 * 6666 / 10_000 = 666_600 (ceil-div, exact)
        assert_eq!(check.quorum_required, 666_600);
    }

    /// Tampered `validator_root`: caller's trusted set no longer
    /// matches what the header committed to.
    #[test]
    fn verify_header_rejects_tampered_validator_root() {
        let (mut block, validators, params, _s0) = build_signed_block_1();
        block.header.validator_root[0] ^= 0xff;
        let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
        assert_eq!(err, HeaderVerifyError::ValidatorRootMismatch);
    }

    /// Caller's trusted set is the WRONG set — different stake, same
    /// vrf/bls keys. The computed `validator_root` won't match.
    #[test]
    fn verify_header_rejects_wrong_trusted_set() {
        let (block, mut validators, params, _s0) = build_signed_block_1();
        // Bump stake — root must change.
        validators[0].stake += 1;
        let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
        assert_eq!(err, HeaderVerifyError::ValidatorRootMismatch);
    }

    /// Tampered finality bitmap → BLS aggregate disagrees.
    #[test]
    fn verify_header_rejects_tampered_producer_proof() {
        let (mut block, validators, params, _s0) = build_signed_block_1();
        // Flip a byte of the producer_proof. Since this contains
        // the BLS aggregate, signature verification must fail.
        let mid = block.header.producer_proof.len() / 2;
        block.header.producer_proof[mid] ^= 0xff;
        let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
        // Could be a decode failure or a finality failure — both
        // are acceptable rejections.
        match err {
            HeaderVerifyError::FinalityRejected(_) | HeaderVerifyError::ProducerProofDecode(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// Empty trusted set → typed error, not panic.
    #[test]
    fn verify_header_rejects_empty_trusted_set() {
        let (block, _validators, params, _s0) = build_signed_block_1();
        let err = verify_header(&block.header, &[], &params).expect_err("must reject");
        assert_eq!(err, HeaderVerifyError::EmptyTrustedSet);
    }

    /// A header with an empty `producer_proof` (the genesis-style
    /// case) is rejected with a specific error so a light client can
    /// surface a helpful message rather than a cryptic decode
    /// failure.
    #[test]
    fn verify_header_rejects_empty_producer_proof() {
        let (mut block, validators, params, _s0) = build_signed_block_1();
        block.header.producer_proof = Vec::new();
        let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
        assert_eq!(err, HeaderVerifyError::GenesisHeader);
    }

    /// Truncated `producer_proof` bytes → decode error path.
    #[test]
    fn verify_header_rejects_truncated_producer_proof() {
        let (mut block, validators, params, _s0) = build_signed_block_1();
        // Keep just a few bytes — not enough to decode.
        block.header.producer_proof.truncate(8);
        let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
        assert!(
            matches!(err, HeaderVerifyError::ProducerProofDecode(_)),
            "expected ProducerProofDecode, got {err:?}"
        );
    }

    /// Tampered `header.height` → `header_signing_hash` differs from
    /// what the producer / committee signed → finality verification
    /// fails.
    #[test]
    fn verify_header_rejects_tampered_height() {
        let (mut block, validators, params, _s0) = build_signed_block_1();
        block.header.height = 42;
        let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
        match err {
            HeaderVerifyError::FinalityRejected(_) => {}
            other => panic!("expected FinalityRejected, got {other:?}"),
        }
    }

    /// Tampered `header.slot` → producer-proof's slot context
    /// differs → VRF / producer signature fails.
    #[test]
    fn verify_header_rejects_tampered_slot() {
        let (mut block, validators, params, _s0) = build_signed_block_1();
        block.header.slot = block.header.slot.wrapping_add(1);
        let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
        match err {
            HeaderVerifyError::FinalityRejected(_) => {}
            other => panic!("expected FinalityRejected, got {other:?}"),
        }
    }

    /// Determinism: repeat verification of the same valid header
    /// must produce byte-for-byte the same `HeaderCheck`.
    #[test]
    fn verify_header_is_deterministic() {
        let (block, validators, params, _s0) = build_signed_block_1();
        let a = verify_header(&block.header, &validators, &params).expect("a");
        let b = verify_header(&block.header, &validators, &params).expect("b");
        assert_eq!(a, b);
    }

    /* ----------------------------------------------------------------- *
     *  M2.0.7 — verify_block_body                                        *
     * ----------------------------------------------------------------- */

    /// Headline: a real signed block 1 — built by `build_unsealed_header`
    /// which sets every root consistently — must body-verify cleanly.
    #[test]
    fn verify_block_body_accepts_consistent_block() {
        let (block, _validators, _params, _s0) = build_signed_block_1();
        verify_block_body(&block).expect("must verify");
    }

    /// Tampered `tx_root` → typed `TxRootMismatch` with the actual
    /// re-derived root in `got`.
    #[test]
    fn verify_block_body_rejects_tampered_tx_root() {
        let (mut block, _validators, _params, _s0) = build_signed_block_1();
        let original = block.header.tx_root;
        block.header.tx_root[0] ^= 0xff;
        let err = verify_block_body(&block).expect_err("must reject");
        match err {
            BodyVerifyError::TxRootMismatch { expected, got } => {
                assert_ne!(expected, original, "header field was tampered");
                assert_eq!(
                    got, original,
                    "re-derived root equals the un-tampered original"
                );
            }
            other => panic!("expected TxRootMismatch, got {other:?}"),
        }
    }

    /// Tampered `bond_root` → typed `BondRootMismatch`.
    #[test]
    fn verify_block_body_rejects_tampered_bond_root() {
        let (mut block, _validators, _params, _s0) = build_signed_block_1();
        block.header.bond_root[0] ^= 0xff;
        let err = verify_block_body(&block).expect_err("must reject");
        assert!(matches!(err, BodyVerifyError::BondRootMismatch { .. }));
    }

    /// Tampered `slashing_root` → typed `SlashingRootMismatch`.
    #[test]
    fn verify_block_body_rejects_tampered_slashing_root() {
        let (mut block, _validators, _params, _s0) = build_signed_block_1();
        block.header.slashing_root[0] ^= 0xff;
        let err = verify_block_body(&block).expect_err("must reject");
        assert!(matches!(err, BodyVerifyError::SlashingRootMismatch { .. }));
    }

    /// Tampered `storage_proof_root` → typed `StorageProofRootMismatch`.
    #[test]
    fn verify_block_body_rejects_tampered_storage_proof_root() {
        let (mut block, _validators, _params, _s0) = build_signed_block_1();
        block.header.storage_proof_root[0] ^= 0xff;
        let err = verify_block_body(&block).expect_err("must reject");
        assert!(matches!(
            err,
            BodyVerifyError::StorageProofRootMismatch { .. }
        ));
    }

    /// Tampered `claims_root` → typed `ClaimsRootMismatch`.
    #[test]
    fn verify_block_body_rejects_tampered_claims_root() {
        let (mut block, _validators, _params, _s0) = build_signed_block_1();
        block.header.claims_root[0] ^= 0xff;
        let err = verify_block_body(&block).expect_err("must reject");
        assert!(matches!(err, BodyVerifyError::ClaimsRootMismatch { .. }));
    }

    /// Re-ordering txs (swap two equivalent-but-distinct txs)
    /// must move `tx_root` → body verification rejects.
    ///
    /// We use the coinbase tx as the sole tx in our test setup, so
    /// here we instead simulate body-side tampering by pushing a
    /// duplicate of the coinbase tx into `block.txs` — the producer
    /// committed to one tx; an added tx changes the recomputed root.
    #[test]
    fn verify_block_body_rejects_tampered_tx_body() {
        let (mut block, _validators, _params, _s0) = build_signed_block_1();
        // Duplicate the existing coinbase. Note: this is purely a
        // body-side tamper test — apply_block would reject the
        // duplicate-coinbase block for other reasons; here we're
        // verifying that the *body root check itself* catches the
        // mismatch.
        let cb = block.txs[0].clone();
        block.txs.push(cb);
        let err = verify_block_body(&block).expect_err("must reject");
        assert!(matches!(err, BodyVerifyError::TxRootMismatch { .. }));
    }

    /// Determinism: repeat verification of the same valid block
    /// must produce byte-for-byte the same `Ok(())`.
    #[test]
    fn verify_block_body_is_deterministic() {
        let (block, _validators, _params, _s0) = build_signed_block_1();
        let a = verify_block_body(&block);
        let b = verify_block_body(&block);
        assert_eq!(a, b);
    }

    /// Genesis block is body-consistent (all empty bodies → all-zero
    /// sentinel roots in the genesis header, which `build_genesis`
    /// computes the same way).
    #[test]
    fn verify_block_body_accepts_genesis() {
        let (v0, _s0) = mk_validator(0, 1_000_000);
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: vec![v0],
            params: ConsensusParams {
                expected_proposers_per_slot: 10.0,
                quorum_stake_bps: 6666,
                liveness_max_consecutive_missed: 64,
                liveness_slash_bps: 0,
            },
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let genesis = build_genesis(&cfg);
        verify_block_body(&genesis).expect("genesis body must verify");
    }
}
