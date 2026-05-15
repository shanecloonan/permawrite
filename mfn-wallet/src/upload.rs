//! Storage-upload construction.
//!
//! Build a signed [`mfn_consensus::TransactionWire`] that:
//!
//! 1. Spends one or more of the wallet's owned outputs (full RingCT ring
//!    + CLSAG + range proofs — identical to [`crate::build_transfer`]).
//! 2. Anchors a [`mfn_storage::StorageCommitment`] in its first output,
//!    so the chain registers the upload in `ChainState.storage` and
//!    SPoRA proofs become claimable.
//! 3. Pays the chain-public `fee` whose treasury-bound slice (`fee ·
//!    fee_to_treasury_bps / 10000`) covers the protocol-required
//!    upfront endowment.
//!
//! ## Why this lives in its own module
//!
//! `spend.rs` deliberately hard-codes `storage: None` on every output —
//! it is the privacy-only path and its API surface is small for that
//! reason. Uploads need extra inputs (`data`, `replication`, chunk
//! size, endowment params, fee-to-treasury bps), extra outputs ([
//! `BuiltCommitment`] returned to the caller so they can serve chunks
//! to storage operators later), and extra error variants. Mixing those
//! into [`crate::TransferPlan`] would muddy the simpler path; splitting
//! them keeps each call site obvious.
//!
//! ## Symmetry with the consensus / mempool gates
//!
//! Every check the mempool's storage-anchoring gate enforces
//! (`mfn_node::Mempool::admit` step 6, byte-equivalent to
//! `mfn_consensus::apply_block`'s per-tx storage loop) is replicated
//! here as a *typed wallet error* raised **before** signing:
//!
//! - `replication ∉ [min, max]` → [`WalletError::UploadReplicationOutOfRange`]
//! - `required_endowment` errors → [`WalletError::Endowment`]
//! - `treasury_share < required_endowment` →
//!   [`WalletError::UploadUnderfunded`] (callers get the *minimum
//!   acceptable fee* in the error so retry is trivial)
//! - `fee_to_treasury_bps == 0` (would never satisfy any non-zero
//!   burden) → [`WalletError::UploadTreasuryRouteDisabled`]
//! - `required_endowment > u64::MAX` (can't be Pedersen-committed in
//!   `StorageCommitment.endowment`) →
//!   [`WalletError::UploadEndowmentExceedsU64`]
//!
//! This means the wallet **never signs a tx the mempool would reject
//! for storage reasons** — saving CLSAG work and avoiding the privacy
//! leak of broadcasting a tx whose key images become public for nothing
//! in return.
//!
//! ## What the wallet does NOT do
//!
//! Out of scope for M2.0.14 (kept simple to avoid creep):
//!
//! - **Persist `data`**: callers retain the raw bytes (the wallet only
//!   needs them in memory to chunk + hash). Serving those chunks to
//!   storage operators when challenged is the operator's / uploader's
//!   responsibility, downstream of this milestone.
//! - **Build storage proofs**: the SPoRA prover side lives behind
//!   [`mfn_storage::build_storage_proof`] and is invoked by the block
//!   producer / storage operator, not the uploader.
//! - **Auto-detect dedup**: if the wallet uploads the same `data` at
//!   the same `replication` twice, the mempool/chain *silently skip*
//!   the second anchor (zero burden, no error). We do not pre-check
//!   `state.storage.contains_key(...)` because the caller may
//!   legitimately want to anchor the same bytes again at a different
//!   replication factor (yielding a different `StorageCommitment`
//!   hash).
//!
//! The returned [`UploadArtifacts`] carries the [`BuiltCommitment`]
//! (Merkle tree + endowment blinding scalar) so any of the above can
//! be wired up at a higher layer without re-running the chunking step.

use curve25519_dalek::scalar::Scalar;
use mfn_consensus::{build_mfex_extra, sign_transaction, InputSpec, OutputSpec, SignedTransaction};
use mfn_crypto::clsag::ClsagRing;
use mfn_crypto::{select_gamma_decoys, DecoyCandidate, DEFAULT_GAMMA_PARAMS};
use mfn_storage::{build_storage_commitment, required_endowment, BuiltCommitment, EndowmentParams};

use crate::decoy::RingMember;
use crate::error::WalletError;
use crate::owned::OwnedOutput;
use crate::spend::TransferRecipient;

/// Output of [`build_storage_upload`].
///
/// Carries:
///
/// - the wire-ready [`SignedTransaction`] for submission to the mempool;
/// - the [`BuiltCommitment`] (Merkle tree, endowment Pedersen blinding)
///   that the uploader keeps so they can later answer SPoRA challenges
///   via [`mfn_storage::build_storage_proof`] and / or open the
///   endowment with [`mfn_storage::verify_endowment_opening`];
/// - the computed `burden` (chain-required endowment in MFN base units)
///   and the `min_fee` that satisfies the treasury-share gate, for
///   wallet UX (showing the user *why* the fee is what it is).
#[derive(Debug)]
pub struct UploadArtifacts {
    /// Signed, sealed, ready-for-mempool transaction. Its first output
    /// carries the storage commitment; remaining outputs are change.
    pub signed: SignedTransaction,
    /// Built commitment + Merkle tree + endowment blinding. Caller must
    /// retain `built.tree` (locally) to serve chunks for SPoRA audits,
    /// and `built.blinding` to ever prove an endowment opening.
    pub built: BuiltCommitment,
    /// Protocol-required upfront endowment burden in MFN base units
    /// (`Σ required_endowment` over every newly-anchored commitment —
    /// always one for now, since each tx anchors at most one upload).
    pub burden: u128,
    /// Smallest `fee` value that satisfies the chain's UploadUnderfunded
    /// gate for this `burden`. Always ≤ caller's `fee` on success.
    pub min_fee: u64,
}

/// All inputs to [`build_storage_upload`].
///
/// The wallet's higher-level `Wallet::build_storage_upload` wires these
/// for the common path (anchor-to-self with greedy coin selection); use
/// this directly when you need to anchor to an arbitrary recipient,
/// supply a non-default chunk size, or pin the Pedersen blinding (e.g.
/// for deterministic tests that want to call `verify_endowment_opening`
/// later).
pub struct StorageUploadPlan<'a, R: FnMut() -> f64> {
    /// Owned outputs being spent. The wallet picks them via
    /// coin-selection upstream; this layer simply consumes the choice.
    pub inputs: &'a [&'a OwnedOutput],
    /// Recipient + MFN value that receives the storage-anchoring
    /// output. The output is a *real* RingCT UTXO — the recipient (often
    /// the uploader themselves) can later spend it like any other.
    /// Setting `anchor.value == 0` is permitted by consensus (range
    /// proofs allow zero) but the resulting output cannot be spent.
    pub anchor: TransferRecipient,
    /// Raw bytes to anchor. Hashed + chunked by
    /// [`mfn_storage::build_storage_commitment`]. May be empty (results
    /// in a well-defined single-empty-chunk commitment with zero
    /// burden).
    pub data: &'a [u8],
    /// Number of independent replicas the chain must keep. Must satisfy
    /// `[endowment_params.min_replication, endowment_params.max_replication]`.
    pub replication: u8,
    /// Override the chunking granularity (must be a power of two).
    /// `None` ⇒ [`mfn_storage::DEFAULT_CHUNK_SIZE`] (256 KiB), which is
    /// the byte-for-byte-canonical value with the TS reference and
    /// what every storage operator expects by default.
    pub chunk_size: Option<usize>,
    /// Explicit Pedersen blinding for the commitment's `endowment`
    /// field. `None` ⇒ fresh random scalar from the OS CSPRNG. Test
    /// callers pin this for determinism; production callers should
    /// leave it `None`.
    pub endowment_blinding: Option<Scalar>,
    /// Endowment params — typically `&chain_state.endowment_params`.
    /// Drives both `required_endowment` and the replication range.
    pub endowment_params: &'a EndowmentParams,
    /// `chain_state.emission_params.fee_to_treasury_bps`. Drives the
    /// underfunded gate: `fee · bps / 10000 ≥ burden`. Default chain
    /// param is `9000` (90% of every fee flows to the storage
    /// treasury).
    pub fee_to_treasury_bps: u16,
    /// Additional non-storage outputs. Typically one entry: the change
    /// output back to the uploader's own keys. Empty if `Σ inputs =
    /// anchor.value + fee` exactly.
    pub change_recipients: &'a [TransferRecipient],
    /// Public fee claimed by the producer. Must be ≥ `min_fee` derived
    /// from `required_endowment(data.len(), replication, params)` and
    /// `fee_to_treasury_bps`; the wallet rejects underfunded fees up
    /// front via [`WalletError::UploadUnderfunded`].
    pub fee: u64,
    /// Opaque memo committed to by the tx preimage. Pass `&[]` for none.
    /// When [`Self::authorship_claims`] is non-empty, this must be empty
    /// — the wire `extra` is exactly [`build_mfex_extra`]`(authorship_claims)`.
    pub extra: &'a [u8],
    /// Optional signed authorship claims (MFEX/MFCL) in `tx.extra`. When
    /// non-empty, [`Self::extra`] must be `&[]`, and every claim's
    /// `data_root` must match the upload's [`mfn_storage::StorageCommitment::data_root`]
    /// (enforced in [`build_storage_upload`]).
    pub authorship_claims: &'a [mfn_crypto::authorship::AuthorshipClaim],
    /// Anonymity-set size **including** the real input. ≥ 2.
    pub ring_size: usize,
    /// Decoy candidate pool. Must be sorted by height ascending — use
    /// [`crate::DecoyPoolBuilder`] to construct.
    pub decoy_pool: &'a [DecoyCandidate<RingMember>],
    /// Chain height the wallet is spending from (drives the gamma age
    /// distribution).
    pub current_height: u64,
    /// `FnMut() -> f64` returning uniform `[0, 1)`. Used for both
    /// decoy sampling and `signer_idx` selection.
    pub rng: &'a mut R,
}

/// Compute the minimum `fee` that satisfies the chain's
/// `UploadUnderfunded` gate for an upload of `data_len` bytes at the
/// given replication factor.
///
/// Formula: the chain requires
///
/// ```text
///     fee · fee_to_treasury_bps / 10_000  ≥  required_endowment(data_len, replication, params)
/// ```
///
/// so the smallest acceptable fee is
///
/// ```text
///     min_fee  =  ceil(required_endowment · 10_000 / fee_to_treasury_bps)
/// ```
///
/// Returns `0` when `data_len == 0` (zero burden) or when
/// `required_endowment` returns `0` for any other reason.
///
/// # Errors
///
/// - [`WalletError::UploadReplicationOutOfRange`] when `replication` is
///   outside `[min_replication, max_replication]`.
/// - [`WalletError::UploadTreasuryRouteDisabled`] when
///   `fee_to_treasury_bps == 0` and the burden is non-zero (no positive
///   fee can ever satisfy the gate).
/// - [`WalletError::UploadEndowmentExceedsU64`] when the implied min_fee
///   exceeds `u64::MAX` (pathological size × replication).
/// - [`WalletError::Endowment`] for upstream endowment-math errors.
pub fn estimate_minimum_fee_for_upload(
    data_len: u64,
    replication: u8,
    endowment_params: &EndowmentParams,
    fee_to_treasury_bps: u16,
) -> Result<u64, WalletError> {
    if replication < endowment_params.min_replication
        || replication > endowment_params.max_replication
    {
        return Err(WalletError::UploadReplicationOutOfRange {
            got: replication,
            min: endowment_params.min_replication,
            max: endowment_params.max_replication,
        });
    }
    let burden = required_endowment(data_len, replication, endowment_params)?;
    if burden == 0 {
        return Ok(0);
    }
    if fee_to_treasury_bps == 0 {
        return Err(WalletError::UploadTreasuryRouteDisabled);
    }
    let bps = u128::from(fee_to_treasury_bps);
    // ceil(burden · 10000 / bps), saturating against overflow.
    let scaled = burden
        .checked_mul(10_000u128)
        .ok_or(WalletError::UploadEndowmentExceedsU64 { burden })?;
    let min_fee_u128 = scaled.div_ceil(bps);
    if min_fee_u128 > u128::from(u64::MAX) {
        return Err(WalletError::UploadEndowmentExceedsU64 { burden });
    }
    Ok(min_fee_u128 as u64)
}

/// Build, sign, and seal a storage-upload transaction.
///
/// On success the returned [`UploadArtifacts`] contains the
/// [`SignedTransaction`] that can be submitted to a mempool; on failure
/// every distinguishable reason is a typed [`WalletError`] variant. No
/// `expect` / panic / silent-degrade paths.
///
/// # Errors
///
/// All variants of [`WalletError`] that apply to spending +
/// [`WalletError::UploadReplicationOutOfRange`],
/// [`WalletError::UploadUnderfunded`],
/// [`WalletError::UploadTreasuryRouteDisabled`],
/// [`WalletError::UploadEndowmentExceedsU64`],
/// [`WalletError::Endowment`], [`WalletError::Spora`].
pub fn build_storage_upload<R>(
    plan: StorageUploadPlan<'_, R>,
) -> Result<UploadArtifacts, WalletError>
where
    R: FnMut() -> f64,
{
    if plan.ring_size < 2 {
        return Err(WalletError::DecoyPoolTooSmall {
            ring_size: plan.ring_size,
            pool_size: plan.decoy_pool.len(),
        });
    }
    if plan.decoy_pool.len() + 1 < plan.ring_size {
        return Err(WalletError::DecoyPoolTooSmall {
            ring_size: plan.ring_size,
            pool_size: plan.decoy_pool.len(),
        });
    }

    // (1) Replication range — surface early so the caller never wastes
    //     CLSAG work on a tx the chain would reject.
    if plan.replication < plan.endowment_params.min_replication
        || plan.replication > plan.endowment_params.max_replication
    {
        return Err(WalletError::UploadReplicationOutOfRange {
            got: plan.replication,
            min: plan.endowment_params.min_replication,
            max: plan.endowment_params.max_replication,
        });
    }

    // (2) Compute burden (Σ required_endowment for this upload's
    //     newly-anchored commitments — always one, since we anchor
    //     exactly one commitment per upload tx).
    let burden = required_endowment(
        plan.data.len() as u64,
        plan.replication,
        plan.endowment_params,
    )?;

    // (3) Endowment must fit in u64 to be Pedersen-committable in
    //     `StorageCommitment.endowment`.
    if burden > u128::from(u64::MAX) {
        return Err(WalletError::UploadEndowmentExceedsU64 { burden });
    }
    let endowment_amount: u64 = burden as u64;

    // (4) UploadUnderfunded gate — mirror the mempool / chain check
    //     exactly. When burden == 0 (empty data), this short-circuits
    //     to "any fee, including 0, is acceptable on this axis".
    let bps = u128::from(plan.fee_to_treasury_bps);
    let treasury_share: u128 = u128::from(plan.fee) * bps / 10_000;
    let min_fee = if burden == 0 {
        0u64
    } else {
        if plan.fee_to_treasury_bps == 0 {
            return Err(WalletError::UploadTreasuryRouteDisabled);
        }
        // ceil(burden · 10000 / bps)
        let scaled = burden
            .checked_mul(10_000u128)
            .ok_or(WalletError::UploadEndowmentExceedsU64 { burden })?;
        let mf = scaled.div_ceil(bps);
        if mf > u128::from(u64::MAX) {
            return Err(WalletError::UploadEndowmentExceedsU64 { burden });
        }
        mf as u64
    };
    if treasury_share < burden {
        return Err(WalletError::UploadUnderfunded {
            fee: plan.fee,
            treasury_share,
            burden,
            min_fee,
        });
    }

    // (5) Balance check: Σ inputs == anchor.value + Σ change + fee.
    let input_total: u64 = plan
        .inputs
        .iter()
        .map(|o| o.value)
        .fold(0u64, u64::saturating_add);
    let change_total: u64 = plan
        .change_recipients
        .iter()
        .map(|r| r.value)
        .fold(0u64, u64::saturating_add);
    let needed = plan
        .anchor
        .value
        .saturating_add(change_total)
        .saturating_add(plan.fee);
    if input_total != needed {
        return Err(WalletError::InsufficientFunds {
            requested: needed,
            available: input_total,
        });
    }

    // (6) Build the storage commitment + ring CT inputs.
    let built = build_storage_commitment(
        plan.data,
        endowment_amount,
        plan.chunk_size,
        plan.replication,
        plan.endowment_blinding,
    )?;

    if !plan.authorship_claims.is_empty() {
        if !plan.extra.is_empty() {
            return Err(WalletError::UploadExtraConflictsWithAuthorshipClaims);
        }
        for c in plan.authorship_claims {
            if c.data_root != built.commit.data_root {
                return Err(WalletError::AuthorshipClaimDataRootMismatch);
            }
        }
    }

    let mut input_specs: Vec<InputSpec> = Vec::with_capacity(plan.inputs.len());
    let decoys_per_input = plan.ring_size - 1;

    for real in plan.inputs.iter().copied() {
        let decoys = select_gamma_decoys(
            plan.decoy_pool,
            decoys_per_input,
            plan.current_height,
            plan.rng,
            &DEFAULT_GAMMA_PARAMS,
        )?;
        if decoys.len() < decoys_per_input {
            return Err(WalletError::DecoyPoolTooSmall {
                ring_size: plan.ring_size,
                pool_size: plan.decoy_pool.len(),
            });
        }

        let r = (plan.rng)();
        let signer_idx = {
            let raw = (r * plan.ring_size as f64) as usize;
            raw.min(plan.ring_size - 1)
        };

        let mut p_col: Vec<curve25519_dalek::edwards::EdwardsPoint> =
            Vec::with_capacity(plan.ring_size);
        let mut c_col: Vec<curve25519_dalek::edwards::EdwardsPoint> =
            Vec::with_capacity(plan.ring_size);
        let mut decoy_iter = decoys.into_iter();
        for slot in 0..plan.ring_size {
            if slot == signer_idx {
                p_col.push(real.one_time_addr);
                c_col.push(real.commit);
            } else {
                let next = decoy_iter
                    .next()
                    .expect("decoy_iter must have ring_size-1 items");
                p_col.push(next.data.0);
                c_col.push(next.data.1);
            }
        }
        input_specs.push(InputSpec {
            ring: ClsagRing { p: p_col, c: c_col },
            signer_idx,
            spend_priv: real.one_time_spend,
            value: real.value,
            blinding: real.blinding,
        });
    }

    // (7) Outputs: anchor first (with `storage: Some(commit)`), change
    //     after (all `storage: None`). Order matters only as far as the
    //     caller's mental model — consensus does not care.
    let mut output_specs: Vec<OutputSpec> = Vec::with_capacity(1 + plan.change_recipients.len());
    output_specs.push(OutputSpec::ToRecipient {
        recipient: plan.anchor.recipient,
        value: plan.anchor.value,
        storage: Some(built.commit.clone()),
    });
    for c in plan.change_recipients {
        output_specs.push(OutputSpec::ToRecipient {
            recipient: c.recipient,
            value: c.value,
            storage: None,
        });
    }

    // (8) RingCT ceremony.
    let extra_wire: Vec<u8> = if plan.authorship_claims.is_empty() {
        plan.extra.to_vec()
    } else {
        build_mfex_extra(plan.authorship_claims)?
    };
    let signed = sign_transaction(input_specs, output_specs, plan.fee, extra_wire)?;

    Ok(UploadArtifacts {
        signed,
        built,
        burden,
        min_fee,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{wallet_from_seed, OwnedOutput};
    use curve25519_dalek::scalar::Scalar;
    use mfn_consensus::Recipient;
    use mfn_crypto::point::{generator_g, generator_h};
    use mfn_crypto::scalar::random_scalar;
    use mfn_storage::{storage_commitment_hash, DEFAULT_ENDOWMENT_PARAMS};

    fn one_real_owned_output(value: u64) -> OwnedOutput {
        let one_time_spend = random_scalar();
        let blinding = random_scalar();
        let one_time_addr = generator_g() * one_time_spend;
        let commit = (generator_g() * blinding) + (generator_h() * Scalar::from(value));
        let key_image =
            crate::owned::key_image_for_owned(&one_time_addr, one_time_spend).expect("key image");
        OwnedOutput {
            one_time_addr,
            commit,
            value,
            blinding,
            one_time_spend,
            key_image,
            tx_id: [0u8; 32],
            output_idx: 0,
            height: 1,
        }
    }

    fn decoy_pool(n: usize) -> Vec<DecoyCandidate<RingMember>> {
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let sp = random_scalar();
            let bp = random_scalar();
            let p = generator_g() * sp;
            let c = (generator_g() * bp) + (generator_h() * Scalar::from((i as u64) + 1));
            out.push(DecoyCandidate {
                data: (p, c),
                height: 1,
            });
        }
        out
    }

    fn rng() -> impl FnMut() -> f64 {
        mfn_crypto::seeded_rng(0xfeed_cafe)
    }

    fn alice_recipient() -> (mfn_consensus::Recipient, crate::WalletKeys) {
        let keys = wallet_from_seed(&[0xa1u8; 32]);
        let r = Recipient {
            view_pub: keys.view_pub(),
            spend_pub: keys.spend_pub(),
        };
        (r, keys)
    }

    #[test]
    fn happy_path_anchors_data_and_returns_artifacts() {
        let (anchor_recipient, _keys) = alice_recipient();
        let input_value = 50_000_000_000u64;
        let owned = one_real_owned_output(input_value);
        let inputs = [&owned];
        let pool = decoy_pool(10);
        let mut r = rng();

        let data = b"the cypherpunks write code";
        let replication: u8 = 3;
        let params = DEFAULT_ENDOWMENT_PARAMS;
        let fee_to_treasury_bps = 9000u16;
        let burden = required_endowment(data.len() as u64, replication, &params).expect("burden");
        let min_fee = estimate_minimum_fee_for_upload(
            data.len() as u64,
            replication,
            &params,
            fee_to_treasury_bps,
        )
        .expect("min_fee");
        let fee = min_fee.max(1);
        // burden is small enough we can self-pay the anchor with most
        // of the input and route the rest to change.
        let anchor_value = 100_000u64;
        let change_value = input_value - anchor_value - fee;
        let change = [TransferRecipient {
            recipient: anchor_recipient,
            value: change_value,
        }];

        let plan = StorageUploadPlan {
            inputs: &inputs,
            anchor: TransferRecipient {
                recipient: anchor_recipient,
                value: anchor_value,
            },
            data,
            replication,
            chunk_size: None,
            endowment_blinding: None,
            endowment_params: &params,
            fee_to_treasury_bps,
            change_recipients: &change,
            fee,
            extra: b"upload-1",
            authorship_claims: &[],
            ring_size: 4,
            decoy_pool: &pool,
            current_height: 1,
            rng: &mut r,
        };
        let art = build_storage_upload(plan).expect("build_storage_upload happy path");

        // Tx shape: one storage-bearing output + one change output.
        assert_eq!(art.signed.tx.outputs.len(), 2);
        assert!(
            art.signed.tx.outputs[0].storage.is_some(),
            "first output carries the storage commitment"
        );
        assert!(
            art.signed.tx.outputs[1].storage.is_none(),
            "change output has no storage"
        );

        // Burden + min_fee match what we computed locally.
        assert_eq!(art.burden, burden);
        assert_eq!(art.min_fee, min_fee);

        // The on-chain storage hash matches the BuiltCommitment we
        // returned to the caller (so the caller can correlate the tx
        // with `state.storage[hash]` after it mines).
        let sc_on_tx = art.signed.tx.outputs[0]
            .storage
            .as_ref()
            .expect("storage present");
        assert_eq!(
            storage_commitment_hash(sc_on_tx),
            storage_commitment_hash(&art.built.commit),
            "wire commitment and artifact commitment are identical"
        );

        // Endowment opening: the blinding scalar we returned must open
        // the on-wire Pedersen commitment to the chain-required burden.
        assert!(
            mfn_storage::verify_endowment_opening(
                sc_on_tx,
                u64::try_from(burden).expect("burden fits"),
                &art.built.blinding,
            ),
            "BuiltCommitment.blinding must open the on-wire endowment to `burden`"
        );

        // Fee floor satisfied by construction.
        let treasury_share: u128 = u128::from(fee) * u128::from(fee_to_treasury_bps) / 10_000;
        assert!(treasury_share >= burden);
    }

    #[test]
    fn replication_below_min_rejected_with_typed_error() {
        let (anchor_recipient, _keys) = alice_recipient();
        let owned = one_real_owned_output(1_000_000);
        let inputs = [&owned];
        let pool = decoy_pool(10);
        let mut r = rng();
        let params = DEFAULT_ENDOWMENT_PARAMS;

        let plan = StorageUploadPlan {
            inputs: &inputs,
            anchor: TransferRecipient {
                recipient: anchor_recipient,
                value: 1_000,
            },
            data: b"data",
            replication: 1, // below default min of 3
            chunk_size: None,
            endowment_blinding: None,
            endowment_params: &params,
            fee_to_treasury_bps: 9000,
            change_recipients: &[],
            fee: 999_000,
            extra: b"",
            authorship_claims: &[],
            ring_size: 4,
            decoy_pool: &pool,
            current_height: 1,
            rng: &mut r,
        };
        let err = build_storage_upload(plan).expect_err("must reject replication=1");
        match err {
            WalletError::UploadReplicationOutOfRange { got, min, max } => {
                assert_eq!(got, 1);
                assert_eq!(min, params.min_replication);
                assert_eq!(max, params.max_replication);
            }
            other => panic!("expected UploadReplicationOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn replication_above_max_rejected_with_typed_error() {
        let (anchor_recipient, _keys) = alice_recipient();
        let owned = one_real_owned_output(1_000_000);
        let inputs = [&owned];
        let pool = decoy_pool(10);
        let mut r = rng();
        let params = DEFAULT_ENDOWMENT_PARAMS;

        let plan = StorageUploadPlan {
            inputs: &inputs,
            anchor: TransferRecipient {
                recipient: anchor_recipient,
                value: 1_000,
            },
            data: b"data",
            replication: 99, // above default max of 32
            chunk_size: None,
            endowment_blinding: None,
            endowment_params: &params,
            fee_to_treasury_bps: 9000,
            change_recipients: &[],
            fee: 999_000,
            extra: b"",
            authorship_claims: &[],
            ring_size: 4,
            decoy_pool: &pool,
            current_height: 1,
            rng: &mut r,
        };
        let err = build_storage_upload(plan).expect_err("must reject replication=99");
        assert!(
            matches!(
                err,
                WalletError::UploadReplicationOutOfRange { got: 99, .. }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn fee_below_minimum_rejected_with_actionable_min_fee() {
        let (anchor_recipient, _keys) = alice_recipient();
        let owned = one_real_owned_output(50_000_000_000);
        let inputs = [&owned];
        let pool = decoy_pool(10);
        let mut r = rng();
        let params = DEFAULT_ENDOWMENT_PARAMS;

        // 100 KiB at replication 3 → non-trivial burden → fee=1 is way below.
        let data = vec![0x42u8; 100 * 1024];
        let plan = StorageUploadPlan {
            inputs: &inputs,
            anchor: TransferRecipient {
                recipient: anchor_recipient,
                value: 100,
            },
            data: &data,
            replication: 3,
            chunk_size: None,
            endowment_blinding: None,
            endowment_params: &params,
            fee_to_treasury_bps: 9000,
            change_recipients: &[],
            fee: 1, // grossly insufficient
            extra: b"",
            authorship_claims: &[],
            ring_size: 4,
            decoy_pool: &pool,
            current_height: 1,
            rng: &mut r,
        };
        let err = build_storage_upload(plan).expect_err("must reject fee=1");
        match err {
            WalletError::UploadUnderfunded {
                fee,
                treasury_share,
                burden,
                min_fee,
            } => {
                assert_eq!(fee, 1);
                assert!(burden > 0);
                assert!(treasury_share < burden);
                assert!(min_fee > 1, "min_fee={min_fee} should be > 1 for 100 KiB");
                // Sanity: paying `min_fee` would clear the gate.
                let cleared = u128::from(min_fee) * 9000 / 10_000;
                assert!(cleared >= burden, "min_fee must clear the burden");
            }
            other => panic!("expected UploadUnderfunded, got {other:?}"),
        }
    }

    #[test]
    fn fee_to_treasury_bps_zero_yields_typed_error_when_burden_positive() {
        let (anchor_recipient, _keys) = alice_recipient();
        let owned = one_real_owned_output(50_000_000_000);
        let inputs = [&owned];
        let pool = decoy_pool(10);
        let mut r = rng();
        let params = DEFAULT_ENDOWMENT_PARAMS;

        let plan = StorageUploadPlan {
            inputs: &inputs,
            anchor: TransferRecipient {
                recipient: anchor_recipient,
                value: 100,
            },
            data: b"non-empty",
            replication: 3,
            chunk_size: None,
            endowment_blinding: None,
            endowment_params: &params,
            fee_to_treasury_bps: 0, // routing disabled
            change_recipients: &[],
            fee: 1_000_000,
            extra: b"",
            authorship_claims: &[],
            ring_size: 4,
            decoy_pool: &pool,
            current_height: 1,
            rng: &mut r,
        };
        let err = build_storage_upload(plan).expect_err("must reject bps=0 + non-zero burden");
        assert!(
            matches!(err, WalletError::UploadTreasuryRouteDisabled),
            "got {err:?}"
        );
    }

    #[test]
    fn empty_data_zero_burden_zero_min_fee_is_fine() {
        let (anchor_recipient, _keys) = alice_recipient();
        let input_value = 10_000u64;
        let owned = one_real_owned_output(input_value);
        let inputs = [&owned];
        let pool = decoy_pool(10);
        let mut r = rng();
        let params = DEFAULT_ENDOWMENT_PARAMS;

        let fee = 0u64;
        let anchor_value = 10_000u64;

        let plan = StorageUploadPlan {
            inputs: &inputs,
            anchor: TransferRecipient {
                recipient: anchor_recipient,
                value: anchor_value,
            },
            data: &[],
            replication: 3,
            chunk_size: None,
            endowment_blinding: None,
            endowment_params: &params,
            fee_to_treasury_bps: 0, // even bps=0 is fine when burden=0
            change_recipients: &[],
            fee,
            extra: b"",
            authorship_claims: &[],
            ring_size: 4,
            decoy_pool: &pool,
            current_height: 1,
            rng: &mut r,
        };
        let art = build_storage_upload(plan).expect("empty data must be accepted");
        assert_eq!(art.burden, 0);
        assert_eq!(art.min_fee, 0);
        assert_eq!(art.signed.tx.outputs.len(), 1);
        assert_eq!(
            art.signed.tx.outputs[0]
                .storage
                .as_ref()
                .unwrap()
                .size_bytes,
            0
        );
    }

    #[test]
    fn estimate_minimum_fee_is_monotonic_in_size_at_fixed_replication() {
        let params = DEFAULT_ENDOWMENT_PARAMS;
        let small = estimate_minimum_fee_for_upload(1_000, 3, &params, 9000).expect("small");
        let big = estimate_minimum_fee_for_upload(1_000_000, 3, &params, 9000).expect("big");
        assert!(big > small, "min fee should grow with size");
    }

    #[test]
    fn estimate_minimum_fee_satisfies_gate_exactly() {
        // For any (size, repl), the returned min_fee must clear
        // `fee * bps / 10000 >= required_endowment` and min_fee - 1
        // (when positive) must not.
        let params = DEFAULT_ENDOWMENT_PARAMS;
        let bps = 9000u16;
        for size in [10u64, 1_000, 100_000, 10_000_000] {
            for repl in [3u8, 5, 10, 32] {
                let burden = required_endowment(size, repl, &params).unwrap();
                let mf = estimate_minimum_fee_for_upload(size, repl, &params, bps).expect("mf");
                let cleared = u128::from(mf) * u128::from(bps) / 10_000;
                assert!(
                    cleared >= burden,
                    "min_fee {mf} should clear burden {burden} for size {size}, repl {repl}"
                );
                if mf > 0 {
                    let cleared_minus = u128::from(mf - 1) * u128::from(bps) / 10_000;
                    assert!(
                        cleared_minus < burden,
                        "min_fee - 1 = {} should NOT clear burden {burden}",
                        mf - 1
                    );
                }
            }
        }
    }

    #[test]
    fn estimate_minimum_fee_rejects_replication_out_of_range() {
        let params = DEFAULT_ENDOWMENT_PARAMS;
        let err = estimate_minimum_fee_for_upload(1_000, 1, &params, 9000).expect_err("repl=1");
        assert!(matches!(
            err,
            WalletError::UploadReplicationOutOfRange { got: 1, .. }
        ));
    }

    #[test]
    fn insufficient_funds_on_unbalanced_inputs() {
        let (anchor_recipient, _keys) = alice_recipient();
        let owned = one_real_owned_output(100);
        let inputs = [&owned];
        let pool = decoy_pool(10);
        let mut r = rng();
        let params = DEFAULT_ENDOWMENT_PARAMS;

        let plan = StorageUploadPlan {
            inputs: &inputs,
            anchor: TransferRecipient {
                recipient: anchor_recipient,
                value: 1_000, // more than input_total = 100
            },
            data: &[],
            replication: 3,
            chunk_size: None,
            endowment_blinding: None,
            endowment_params: &params,
            fee_to_treasury_bps: 9000,
            change_recipients: &[],
            fee: 0,
            extra: b"",
            authorship_claims: &[],
            ring_size: 4,
            decoy_pool: &pool,
            current_height: 1,
            rng: &mut r,
        };
        let err = build_storage_upload(plan).expect_err("must reject unbalanced");
        assert!(matches!(err, WalletError::InsufficientFunds { .. }));
    }

    #[test]
    fn pinned_blinding_is_returned_for_later_endowment_opening() {
        // When the caller pins the Pedersen blinding, the returned
        // BuiltCommitment.blinding must equal the pinned scalar so the
        // caller can later open the endowment.
        let (anchor_recipient, _keys) = alice_recipient();
        let input_value = 50_000_000u64;
        let owned = one_real_owned_output(input_value);
        let inputs = [&owned];
        let pool = decoy_pool(10);
        let mut r = rng();
        let params = DEFAULT_ENDOWMENT_PARAMS;

        let pinned: Scalar = Scalar::from(0xC0FFEEu64);
        let data = b"deterministic blinding";
        let replication: u8 = 3;
        let min_fee =
            estimate_minimum_fee_for_upload(data.len() as u64, replication, &params, 9000).unwrap();
        let fee = min_fee.max(1);
        let anchor_value = 1_000u64;
        let change_value = input_value - anchor_value - fee;
        let change = [TransferRecipient {
            recipient: anchor_recipient,
            value: change_value,
        }];

        let plan = StorageUploadPlan {
            inputs: &inputs,
            anchor: TransferRecipient {
                recipient: anchor_recipient,
                value: anchor_value,
            },
            data,
            replication,
            chunk_size: None,
            endowment_blinding: Some(pinned),
            endowment_params: &params,
            fee_to_treasury_bps: 9000,
            change_recipients: &change,
            fee,
            extra: b"",
            authorship_claims: &[],
            ring_size: 4,
            decoy_pool: &pool,
            current_height: 1,
            rng: &mut r,
        };
        let art = build_storage_upload(plan).expect("happy");
        assert_eq!(art.built.blinding, pinned, "blinding must round-trip");
        // And it opens the on-wire endowment to `burden`.
        let sc = art.signed.tx.outputs[0].storage.as_ref().unwrap();
        assert!(mfn_storage::verify_endowment_opening(
            sc,
            u64::try_from(art.burden).unwrap(),
            &pinned,
        ));
    }
}
