//! pply_block deterministic state transition.

use super::internal::*;

use super::error::BlockError;
use super::header::{block_id, header_signing_hash, Block};
use super::state::{ChainState, StorageEntry, UtxoEntry};
use super::wire::{storage_merkle_root, tx_merkle_root};

/* ----------------------------------------------------------------------- *
 *  Block application                                                      *
 * ----------------------------------------------------------------------- */

/// Either the new state (on success) or a structured list of errors.
///
/// Boxed-state variants would obscure the natural shape; the `Ok` arm
/// carries a `ChainState` directly. The size disparity between the
/// variants is fine because successful application is overwhelmingly the
/// common path and the `Err` variant is small anyway.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ApplyOutcome {
    /// All checks passed; `state` is the new tip state.
    Ok {
        /// New state.
        state: ChainState,
        /// Id of the applied block.
        block_id: [u8; 32],
    },
    /// One or more checks failed; the input state is unchanged.
    Err {
        /// Structured error list (one per failed check).
        errors: Vec<BlockError>,
        /// Id of the proposed block (so callers can log it).
        block_id: [u8; 32],
    },
}

impl ApplyOutcome {
    /// `true` iff application succeeded.
    pub fn is_ok(&self) -> bool {
        matches!(self, ApplyOutcome::Ok { .. })
    }

    /// Block id of the applied/proposed block.
    pub fn block_id(&self) -> &[u8; 32] {
        match self {
            ApplyOutcome::Ok { block_id, .. } | ApplyOutcome::Err { block_id, .. } => block_id,
        }
    }

    /// Move out the new state, if successful.
    pub fn into_state(self) -> Option<ChainState> {
        match self {
            ApplyOutcome::Ok { state, .. } => Some(state),
            ApplyOutcome::Err { .. } => None,
        }
    }
}

/// Apply a candidate block to a chain state.
///
/// Performs every consensus check, in order:
///
/// 1. Header sanity: height = `state.height + 1`, `prev_hash` = current
///    tip id (none ⇒ genesis-only chain).
/// 2. Tx Merkle root matches the recomputed root; bond Merkle root
///    matches [`Block::bond_ops`].
/// 3. (If validators present) the [`crate::consensus::FinalityProof`]
///    verifies — producer was eligible at this slot, committee quorum
///    signed the header.
/// 4. Each tx verifies; cross-tx and cross-chain key images do not
///    collide; outputs are added to the UTXO set + accumulator.
/// 5. Storage commitments newly introduced by tx outputs are registered.
/// 6. Slashing evidence verifies; offending validators have their stake
///    zeroed in the new state.
/// 7. SPoRA storage proofs accrue rewards and update per-commitment state.
/// 8. Liveness stats from the finality bitmap; auto-slash chronic misses.
/// 9. [`BondOp`]s are validated and applied atomically (new validators are
///    not subject to this block's finality bitmap).
/// 10. When a producer has a [`crate::consensus::ValidatorPayout`], the
///     block must include a coinbase (in `tx[0]`) paying
///     `emission(height) + producer_fee` (+ storage rewards).
/// 11. Storage Merkle root matches tx-anchored new commitments.
/// 12. UTXO accumulator root matches.
///
/// Returns [`ApplyOutcome::Ok`] with the new state, or
/// [`ApplyOutcome::Err`] with a list of [`BlockError`]s and the original
/// state untouched.
pub fn apply_block(state: &ChainState, block: &Block) -> ApplyOutcome {
    let proposed_id = block_id(&block.header);
    let mut errors: Vec<BlockError> = Vec::new();

    // ---- Header sanity ----
    let expected_height = state.height.map(|h| h + 1).unwrap_or(0);
    if block.header.height != expected_height {
        errors.push(BlockError::BadHeight {
            expected: expected_height,
            got: block.header.height,
        });
    }
    if let Some(tip) = state.tip_id() {
        if &block.header.prev_hash != tip {
            errors.push(BlockError::PrevHashMismatch);
        }
    } else if block.header.prev_hash != [0u8; 32] {
        errors.push(BlockError::PrevHashMismatch);
    }

    // ---- Tx merkle root ----
    let expected_tx_root = tx_merkle_root(&block.txs);
    if expected_tx_root != block.header.tx_root {
        errors.push(BlockError::TxRootMismatch);
    }

    let expected_bond_root = bond_merkle_root(&block.bond_ops);
    if expected_bond_root != block.header.bond_root {
        errors.push(BlockError::BondRootMismatch);
    }

    // ---- Slashing evidence merkle root (M2.0.1) ----
    //
    // Each piece of evidence is canonicalized in `slashing_leaf_hash`,
    // so swapping the (hash_a, sig_a) / (hash_b, sig_b) pair cannot
    // forge a different leaf. The root commits the slashing list under
    // the header so a light client can verify it without the rest of
    // the block body.
    let expected_slashing_root = crate::slashing::slashing_merkle_root(&block.slashings);
    if expected_slashing_root != block.header.slashing_root {
        errors.push(BlockError::SlashingRootMismatch);
    }

    // ---- Storage-proof merkle root (M2.0.2) ----
    //
    // Closes the last body-rooting gap: now every part of the block
    // body except the producer-proof itself is header-rooted.
    let expected_storage_proof_root = mfn_storage::storage_proof_merkle_root(&block.storage_proofs);
    if expected_storage_proof_root != block.header.storage_proof_root {
        errors.push(BlockError::StorageProofRootMismatch);
    }

    // ---- Validator-set merkle root (pre-block commitment, M2.0) ----
    //
    // Committing to the validator set **as it stood when this block was
    // produced** lets a light client verify the producer eligibility and
    // BLS quorum bitmap from the header alone, without holding the live
    // validator list. Validators introduced or evicted by this block
    // (bond ops, equivocation slashing, liveness slashing, unbond
    // settlement) move the *next* header's root, not this one's.
    let expected_validator_root = crate::consensus::validator_set_root(&state.validators);
    if expected_validator_root != block.header.validator_root {
        errors.push(BlockError::ValidatorRootMismatch);
    }

    // ---- Authorship claims Merkle root (M2.2.x) ----
    //
    // Header `claims_root` binds every verified claim leaf in block order
    // (non-coinbase txs only). Parse+verify once here; the tx walk reuses
    // the results when mutating [`ChainState::claims`].
    let per_tx_claims: Vec<VerifiedClaimsForTxResult> = block
        .txs
        .iter()
        .enumerate()
        .map(|(ti, tx)| {
            if ti == 0 && is_coinbase_shaped(tx) {
                Ok((Vec::new(), Vec::new()))
            } else {
                verified_claims_for_tx(tx, ti as u32, block.header.height)
            }
        })
        .collect();

    let mut header_claim_leaves: Vec<[u8; 32]> = Vec::new();
    for (ti, res) in per_tx_claims.iter().enumerate() {
        match res {
            Ok((_, leaves)) => {
                if !(ti == 0 && is_coinbase_shaped(&block.txs[ti])) {
                    header_claim_leaves.extend_from_slice(leaves);
                }
            }
            Err(e) => errors.push(BlockError::AuthorshipClaims(e.to_string())),
        }
    }
    let expected_claims_root = claims_merkle_root(&header_claim_leaves);
    if expected_claims_root != block.header.claims_root {
        errors.push(BlockError::ClaimsRootMismatch);
    }

    // ---- Producer/finality proof ----
    let mut producer_idx: Option<u32> = None;
    let mut finality_bitmap: Option<Vec<u8>> = None;
    if !state.validators.is_empty() {
        if block.header.producer_proof.is_empty() {
            errors.push(BlockError::MissingProducerProof);
        } else {
            match decode_finality_proof(&block.header.producer_proof) {
                Ok(fin) => {
                    let ctx = SlotContext {
                        height: block.header.height,
                        slot: block.header.slot,
                        prev_hash: block.header.prev_hash,
                    };
                    let header_hash = header_signing_hash(&block.header);
                    let chk = verify_finality_proof(
                        &ctx,
                        &fin,
                        &state.validators,
                        state.params.expected_proposers_per_slot,
                        state.params.quorum_stake_bps,
                        &header_hash,
                    );
                    if !chk.is_ok() {
                        errors.push(BlockError::FinalityInvalid(chk));
                    } else {
                        producer_idx = Some(fin.producer.validator_index);
                        finality_bitmap = Some(fin.finality.bitmap.clone());
                    }
                }
                Err(e) => errors.push(BlockError::FinalityDecode(format!("{e}"))),
            }
        }
    }

    // ---- Tentative state copy (only kept on success). ----
    let mut next = state.clone();
    next.height = Some(block.header.height);

    // Storage commitments newly anchored this block (in declaration order),
    // for the post-block storage-root check.
    let mut new_storages: Vec<StorageCommitment> = Vec::new();

    // Producer + coinbase policy.
    let producer =
        producer_idx.and_then(|idx| state.validators.iter().find(|v| v.index == idx).cloned());
    let require_coinbase = producer
        .as_ref()
        .map(|p| p.payout.is_some())
        .unwrap_or(false);

    // ---- Walk txs ----
    // A coinbase-shaped tx anywhere past position 0 is a protocol
    // violation. Catch up front.
    for (i, tx) in block.txs.iter().enumerate().skip(1) {
        if is_coinbase_shaped(tx) {
            errors.push(BlockError::CoinbaseOutOfPosition(i));
        }
    }

    let mut coinbase_tx: Option<&TransactionWire> = None;
    let mut fee_sum: u128 = 0;

    for (ti, tx) in block.txs.iter().enumerate() {
        let is_coinbase_pos = ti == 0 && is_coinbase_shaped(tx);

        if is_coinbase_pos {
            coinbase_tx = Some(tx);
            // Coinbase output goes into UTXO + accumulator. The actual
            // amount/balance check happens below after fee_sum is known.
            for out in &tx.outputs {
                let key = out.one_time_addr.compress().to_bytes();
                next.utxo.insert(
                    key,
                    UtxoEntry {
                        commit: out.amount,
                        height: block.header.height,
                    },
                );
                let leaf = utxo_leaf_hash(&out.one_time_addr, &out.amount, block.header.height);
                match append_utxo(&next.utxo_tree, leaf) {
                    Ok(t) => next.utxo_tree = t,
                    Err(e) => errors.push(BlockError::AccumulatorFull(format!("{e}"))),
                }
                // Coinbase outputs cannot anchor storage; verify_coinbase
                // enforces this, so we skip storage handling here.
            }
            continue;
        }

        if ti == 0 && require_coinbase {
            errors.push(BlockError::MissingCoinbase {
                got_inputs: tx.inputs.len(),
            });
        }

        // Regular tx path.
        let v = verify_transaction(tx, &next.params.ring_policy());
        if !v.ok {
            errors.push(BlockError::TxInvalid {
                index: ti,
                errors: v.errors,
            });
            continue;
        }

        // ---- Ring-membership check (consensus-critical, see SECURITY note) ----
        //
        // `verify_transaction` is stateless: it proves the CLSAG signer
        // controlled the spend key of *some* ring member, but a CLSAG
        // ring whose members are fabricated (P, C) pairs would still
        // verify because the math doesn't care whether the points are
        // on-chain. Combined with the balance equation
        //
        //     Σ pseudo − Σ amount − fee·H == 0
        //
        // a malicious spender who invents a ring member with commitment
        // C_fake = G·r + H·v_fake can pseudo-output the fake value into
        // their own outputs — i.e. mint MFN out of thin air. The
        // CHAIN-LEVEL check that every ring member is a real UTXO is the
        // only thing that closes this attack.
        //
        // Genesis UTXOs are included in `state.utxo`, so genesis-anchored
        // outputs are valid ring members from height 0 onwards.
        let mut ring_ok = true;
        for (ii, inp) in tx.inputs.iter().enumerate() {
            if inp.ring.p.len() != inp.ring.c.len() {
                errors.push(BlockError::TxInvalid {
                    index: ti,
                    errors: vec![format!(
                        "input {ii}: ring P-column length {} != C-column length {}",
                        inp.ring.p.len(),
                        inp.ring.c.len()
                    )],
                });
                ring_ok = false;
                break;
            }
            for (ri, (p, c)) in inp.ring.p.iter().zip(inp.ring.c.iter()).enumerate() {
                let key = p.compress().to_bytes();
                match next.utxo.get(&key) {
                    Some(entry) if entry.commit == *c => {}
                    Some(_) => {
                        errors.push(BlockError::RingMemberCommitMismatch {
                            tx: ti,
                            input: ii,
                            ring_index: ri,
                            one_time_addr: hex_short(&key),
                        });
                        ring_ok = false;
                    }
                    None => {
                        errors.push(BlockError::RingMemberNotInUtxoSet {
                            tx: ti,
                            input: ii,
                            ring_index: ri,
                            one_time_addr: hex_short(&key),
                        });
                        ring_ok = false;
                    }
                }
            }
        }
        if !ring_ok {
            continue;
        }

        // Fees accrue to the producer via the coinbase.
        fee_sum += u128::from(tx.fee);

        // Cross-tx + cross-chain key image gate.
        for ki in &v.key_images {
            let ki_bytes = ki.compress().to_bytes();
            if next.spent_key_images.contains(&ki_bytes) {
                errors.push(BlockError::DoubleSpend {
                    index: ti,
                    key_image: hex_short(&ki_bytes),
                });
            } else {
                next.spent_key_images.insert(ki_bytes);
            }
        }

        // New outputs → UTXO map + accumulator + storage registry.
        for out in &tx.outputs {
            let key = out.one_time_addr.compress().to_bytes();
            next.utxo.insert(
                key,
                UtxoEntry {
                    commit: out.amount,
                    height: block.header.height,
                },
            );
            let leaf = utxo_leaf_hash(&out.one_time_addr, &out.amount, block.header.height);
            match append_utxo(&next.utxo_tree, leaf) {
                Ok(t) => next.utxo_tree = t,
                Err(e) => errors.push(BlockError::AccumulatorFull(format!("{e}"))),
            }

            if let Some(sc) = &out.storage {
                let h = storage_commitment_hash(sc);
                if let std::collections::hash_map::Entry::Vacant(e) = next.storage.entry(h) {
                    e.insert(StorageEntry {
                        commit: sc.clone(),
                        last_proven_height: block.header.height,
                        last_proven_slot: u64::from(block.header.slot),
                        pending_yield_ppb: 0,
                    });
                    new_storages.push(sc.clone());
                }
            }
        }

        // ---- Storage upload endowment enforcement ----
        //
        // For every NEW storage commitment in this tx's outputs, sum the
        // protocol-required endowment burden. The tx's treasury-bound
        // share of fees must cover the burden, otherwise the upload is
        // under-funded and the permanence guarantee breaks. Replication
        // bounds (min/max) are also enforced here.
        let mut tx_burden: u128 = 0;
        let mut tx_storage_ok = true;
        let mut seen_in_tx: HashSet<[u8; 32]> = HashSet::new();
        for (oi, out) in tx.outputs.iter().enumerate() {
            let sc = match &out.storage {
                Some(s) => s,
                None => continue,
            };
            let h = storage_commitment_hash(sc);
            // Only NEW anchors incur burden — duplicates are inert.
            if state.storage.contains_key(&h) || !seen_in_tx.insert(h) {
                continue;
            }
            let repl = sc.replication;
            if repl < next.endowment_params.min_replication {
                errors.push(BlockError::StorageReplicationTooLow {
                    tx: ti,
                    output: oi,
                    got: repl,
                    min: next.endowment_params.min_replication,
                });
                tx_storage_ok = false;
                break;
            }
            if repl > next.endowment_params.max_replication {
                errors.push(BlockError::StorageReplicationTooHigh {
                    tx: ti,
                    output: oi,
                    got: repl,
                    max: next.endowment_params.max_replication,
                });
                tx_storage_ok = false;
                break;
            }
            match required_endowment(sc.size_bytes, repl, &next.endowment_params) {
                Ok(b) => tx_burden = tx_burden.saturating_add(b),
                Err(e) => {
                    errors.push(BlockError::EndowmentMathFailed {
                        tx: ti,
                        output: oi,
                        reason: format!("{e}"),
                    });
                    tx_storage_ok = false;
                    break;
                }
            }
        }
        if tx_storage_ok && tx_burden > 0 {
            let tx_treasury_share: u128 =
                u128::from(tx.fee) * u128::from(next.emission_params.fee_to_treasury_bps) / 10_000;
            if tx_treasury_share < tx_burden {
                errors.push(BlockError::UploadUnderfunded {
                    tx: ti,
                    burden: tx_burden,
                    treasury_share: tx_treasury_share,
                    fee: tx.fee,
                    fee_to_treasury_bps: next.emission_params.fee_to_treasury_bps,
                });
            }
        }

        if !(ti == 0 && is_coinbase_shaped(tx)) {
            if let Ok((clist, _leaves)) = &per_tx_claims[ti] {
                let tid = tx_id(tx);
                for (ci, c) in clist.iter().enumerate() {
                    let ci_u32 = ci as u32;
                    if !check_claim_storage_binding(c, &next.storage) {
                        errors.push(BlockError::AuthorshipClaims(
                            AuthorshipClaimVerifyError::CommitHashNotAnchored {
                                tx_index: ti as u32,
                                claim_index: ci_u32,
                            }
                            .to_string(),
                        ));
                        continue;
                    }
                    if !check_claim_key_unique(c, &next.claims) {
                        errors.push(BlockError::AuthorshipClaims(
                            AuthorshipClaimVerifyError::DuplicateClaimKey {
                                tx_index: ti as u32,
                                claim_index: ci_u32,
                            }
                            .to_string(),
                        ));
                        continue;
                    }
                    let rec = claim_to_record(c, tid, block.header.height, ti as u32, ci_u32);
                    next.claims.insert(authorship_claim_key(c), rec);
                }
            }
        }
    }

    // ---- Slashing evidence (equivocation → stake zeroed, credit to treasury) ----
    //
    // Per the M1 economic model (see `docs/M1_VALIDATOR_ROTATION.md`), a
    // slashed validator's forfeited stake flows into the permanence
    // treasury rather than vanishing. This keeps the books balanced
    // against `BondOp::Register`'s burn-to-treasury credit: every base
    // unit a validator commits is permanently anchored in the chain's
    // permanence-funding pool, whether it's later returned via unbond,
    // forfeited via slash, or paid out as block reward.
    //
    // Validator-set mutation is delegated to
    // [`crate::validator_evolution::apply_equivocation_slashings`] —
    // the same pure function the light client uses.
    {
        let eq = crate::validator_evolution::apply_equivocation_slashings(
            &mut next.validators,
            &block.slashings,
        );
        next.treasury = next.treasury.saturating_add(eq.forfeited_total);
        for err in eq.errors {
            errors.push(match err {
                crate::validator_evolution::EquivocationError::Duplicate { index, voter_index } => {
                    BlockError::DuplicateSlash { index, voter_index }
                }
                crate::validator_evolution::EquivocationError::Invalid { index, reason } => {
                    BlockError::SlashInvalid { index, reason }
                }
            });
        }
    }

    // ---- Storage proofs: per-block SPoRA audit + endowment-proportional
    //      reward accrual via the PPB accumulator ----
    let mut seen_proofs: HashSet<[u8; 32]> = HashSet::new();
    let mut accepted_storage_proofs: u128 = 0;
    let mut storage_bonus_total: u128 = 0;
    let mut accepted_proof_settlements: Vec<(mfn_storage::StorageProof, u128)> = Vec::new();
    let current_slot = u64::from(block.header.slot);
    for (pi, proof) in block.storage_proofs.iter().enumerate() {
        if !seen_proofs.insert(proof.commit_hash) {
            errors.push(BlockError::DuplicateStorageProof {
                index: pi,
                commit_hash: hex_short(&proof.commit_hash),
            });
            continue;
        }
        let entry = match next.storage.get(&proof.commit_hash).cloned() {
            Some(e) => e,
            None => {
                errors.push(BlockError::StorageProofUnknownCommit {
                    index: pi,
                    commit_hash: hex_short(&proof.commit_hash),
                });
                continue;
            }
        };
        let verdict = verify_storage_proof(
            &entry.commit,
            &block.header.prev_hash,
            block.header.slot,
            proof,
        );
        if !verdict.is_valid() {
            errors.push(BlockError::StorageProofInvalid {
                index: pi,
                reason: verdict,
            });
            continue;
        }
        match accrue_proof_reward(AccrueArgs {
            size_bytes: entry.commit.size_bytes,
            replication: entry.commit.replication,
            pending_ppb: entry.pending_yield_ppb,
            last_proven_slot: entry.last_proven_slot,
            current_slot,
            params: &next.endowment_params,
        }) {
            Ok(accrual) => {
                next.storage.insert(
                    proof.commit_hash,
                    StorageEntry {
                        commit: entry.commit,
                        last_proven_height: block.header.height,
                        last_proven_slot: current_slot,
                        pending_yield_ppb: accrual.new_pending_ppb,
                    },
                );
                accepted_storage_proofs += 1;
                storage_bonus_total = storage_bonus_total.saturating_add(accrual.payout);
                accepted_proof_settlements.push((proof.clone(), accrual.payout));
            }
            Err(e) => errors.push(BlockError::EndowmentMathFailed {
                tx: 0,
                output: pi,
                reason: format!("accrue: {e}"),
            }),
        }
    }

    // ---- Liveness participation tracking + auto-slashing ----
    //
    // Walk this block's verified finality bitmap. For each non-zero-stake
    // validator: a set bit credits a successful vote, a clear bit
    // increments consecutive_missed. When consecutive_missed crosses
    // `liveness_max_consecutive_missed`, the validator's stake is
    // multiplicatively reduced by `liveness_slash_bps` and the counter
    // resets — repeated trip-ups compound. Equivocation slashing
    // (the `SlashEvidence` path above) zeros stake outright; this layer
    // catches chronic absenteeism that equivocation evidence can't
    // attribute.
    //
    // The slashed-away delta is credited to the permanence treasury —
    // same sink as equivocation slashing and bond burns, so chronic
    // absenteeism funds storage operators rather than vanishing.
    //
    // Mutation is delegated to
    // [`crate::validator_evolution::apply_liveness_evolution`].
    if let Some(ref bitmap) = finality_bitmap {
        let out = crate::validator_evolution::apply_liveness_evolution(
            &mut next.validators,
            &mut next.validator_stats,
            bitmap,
            &next.params,
        );
        if out.liveness_burn_total > 0 {
            next.treasury = next.treasury.saturating_add(out.liveness_burn_total);
        }
    }

    // ---- Bond ops (M1): new validators appended; not subject to this
    //      block's finality bitmap (they were not yet in the committee).
    //
    // Every successful `BondOp::Register` burns its declared `stake` to
    // the permanence treasury. Bonded MFN is therefore *immediately*
    // working for storage operators the moment a validator joins.
    //
    // `BondOp::Unbond` enqueues an exit; the validator stays in the
    // active set (still slashable!) until the unbond delay elapses,
    // at which point the settlement phase below zeros their stake.
    //
    // Mutation is delegated to
    // [`crate::validator_evolution::apply_bond_ops_evolution`] and
    // [`crate::validator_evolution::apply_unbond_settlements`] — the
    // same pure functions the light client uses to evolve its trusted
    // validator set across rotations.
    let mut counters = crate::validator_evolution::BondEpochCounters {
        bond_epoch_id: next.bond_epoch_id,
        bond_epoch_entry_count: next.bond_epoch_entry_count,
        bond_epoch_exit_count: next.bond_epoch_exit_count,
        next_validator_index: next.next_validator_index,
    };
    match crate::validator_evolution::apply_bond_ops_evolution(
        block.header.height,
        &mut counters,
        &mut next.validators,
        &mut next.validator_stats,
        &mut next.pending_unbonds,
        &next.bonding_params,
        &block.bond_ops,
    ) {
        Ok(burn_total) => {
            next.treasury = next.treasury.saturating_add(burn_total);
        }
        Err(crate::validator_evolution::BondOpError { index, message }) => {
            errors.push(BlockError::BondOpRejected { index, message });
        }
    }

    // ---- Unbond settlements (M1): scan pending_unbonds in deterministic
    //      sorted-by-index order; for each entry whose unlock_height has
    //      arrived AND exit-churn budget remains, zero the validator's
    //      stake. Bonded MFN stays in treasury -- for M1, bonding is a
    //      one-way contribution to permanence; an honorable exit only
    //      frees the operator from future slashing exposure.
    crate::validator_evolution::apply_unbond_settlements(
        block.header.height,
        &mut counters,
        &next.bonding_params,
        &mut next.validators,
        &mut next.pending_unbonds,
    );

    // Commit the counter mutations back to chain state.
    next.bond_epoch_id = counters.bond_epoch_id;
    next.bond_epoch_entry_count = counters.bond_epoch_entry_count;
    next.bond_epoch_exit_count = counters.bond_epoch_exit_count;
    next.next_validator_index = counters.next_validator_index;

    // ---- Two-sided economic settlement ----
    //
    //   1. treasury_fee = fee_sum · fee_to_treasury_bps / 10000
    //      producer_fee = fee_sum − treasury_fee
    //   2. Treasury gains treasury_fee.
    //   3. Storage rewards = storage_proof_reward · N_accepted + Σ bonus.
    //      Treasury drains first; any shortfall is minted via emission
    //      as a backstop. Treasury balance never goes negative.
    //   4. Coinbase output 0 = producer (subsidy + producer_fee);
    //      outputs 1..N = per-operator storage rewards.
    let emission_params = next.emission_params;
    let treasury_fee: u128 = fee_sum * u128::from(emission_params.fee_to_treasury_bps) / 10_000;
    let producer_fee_u128 = fee_sum - treasury_fee;
    let producer_fee: u64 = u64::try_from(producer_fee_u128).unwrap_or(u64::MAX);

    let storage_reward_total: u128 = u128::from(emission_params.storage_proof_reward)
        .saturating_mul(accepted_storage_proofs)
        .saturating_add(storage_bonus_total);

    let mut pending_treasury = next.treasury.saturating_add(treasury_fee);
    let storage_from_treasury = pending_treasury.min(storage_reward_total);
    pending_treasury -= storage_from_treasury;
    next.treasury = pending_treasury;
    // The remaining `storage_reward_total - storage_from_treasury` is the
    // emission backstop; it's part of operator coinbase outputs but
    // not subtracted from the treasury.

    if require_coinbase {
        let producer = producer
            .as_ref()
            .expect("require_coinbase implies producer present");
        let payout = producer
            .payout
            .as_ref()
            .expect("require_coinbase implies payout present");
        let producer_payout = crate::coinbase::PayoutAddress {
            view_pub: payout.view_pub,
            spend_pub: payout.spend_pub,
        };
        let specs = block_coinbase_specs(
            u64::from(block.header.height),
            &emission_params,
            fee_sum,
            producer_payout,
            &accepted_proof_settlements,
        );
        match coinbase_tx {
            None => errors.push(BlockError::CoinbaseRequiredButAbsent),
            Some(cb) => {
                let cv = verify_coinbase_outputs(
                    cb,
                    u64::from(block.header.height),
                    &payout.spend_pub,
                    &specs,
                );
                if !cv.ok {
                    errors.push(BlockError::CoinbaseInvalid(cv.errors));
                }
            }
        }
    } else if coinbase_tx.is_some() {
        errors.push(BlockError::UnexpectedCoinbase);
    }

    // ---- Storage root ----
    let expected_storage_root = storage_merkle_root(&new_storages);
    if expected_storage_root != block.header.storage_root {
        errors.push(BlockError::StorageRootMismatch);
    }

    // ---- UTXO accumulator root ----
    let computed_root = utxo_tree_root(&next.utxo_tree);
    if computed_root != block.header.utxo_root {
        errors.push(BlockError::UtxoRootMismatch);
    }

    if !errors.is_empty() {
        return ApplyOutcome::Err {
            errors,
            block_id: proposed_id,
        };
    }

    next.block_ids.push(proposed_id);
    ApplyOutcome::Ok {
        state: next,
        block_id: proposed_id,
    }
}

fn hex_short(b: &[u8]) -> String {
    let mut s = String::with_capacity(13);
    for byte in b.iter().take(6) {
        s.push_str(&format!("{byte:02x}"));
    }
    s.push('…');
    s
}
