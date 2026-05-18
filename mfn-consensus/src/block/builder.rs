//! Block + chain-state machine.
//!
//! Port of `cloonan-group/lib/network/block.ts`. This module turns the
//! crate's other primitives — transactions, coinbase, emission, slashing,
//! consensus finality — into an **actual chain** with a deterministic
//! state-transition function.
//!
//! Three concepts:
//!
//! - [`BlockHeader`] / [`Block`] — header + body, deterministically hashed.
//! - [`ChainState`] — known UTXOs, spent key images, storage registry,
//!   validator set, treasury, accumulator root, and the block-id chain.
//! - [`apply_block`] — pure function that validates a candidate block
//!   against the current state and returns either a new state or a list
//!   of errors. Same inputs always produce the same outputs (modulo
//!   hashing the same bytes).
//!
//! ## v0.1 scope
//!
//! This is the consensus-critical subset. The rest of the TS reference
//! (storage proof verification, endowment-based per-tx burden, treasury
//! drain → storage reward routing, storage proof reward bonuses) lives
//! gated behind the future [`mfn-storage`](https://github.com/...)
//! crate. Block application here:
//!
//! - verifies header sanity (height, prev hash);
//! - checks the tx Merkle root;
//! - verifies the producer's [`crate::consensus::FinalityProof`] when
//!   the chain has a validator set;
//! - walks the tx list: position 0 may be a coinbase, all others go
//!   through [`crate::transaction::verify_transaction`];
//! - rejects cross-tx and cross-chain double-spends;
//! - inserts new UTXOs into both the map and the cryptographic
//!   accumulator;
//! - registers new storage commitments (without enforcing endowment);
//! - applies slashing evidence (stake zeroed);
//! - verifies the coinbase against `emission(height) + producer_fee` when
//!   the producer has a payout address;
//! - checks the storage Merkle root + the UTXO accumulator root.
//!
//! When the storage layer lands, the per-block apply function will gain
//! storage-proof verification, endowment-burden enforcement, and the
//! two-sided treasury/emission settlement. The wire format is forward-
//! compatible: blocks produced today will still validate then.

#![allow(unused_imports)]

use std::collections::{BTreeMap, HashMap, HashSet};

use curve25519_dalek::edwards::EdwardsPoint;

use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::domain::{BLOCK_HEADER, BLOCK_ID};
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::merkle_root_or_zero;
use mfn_crypto::utxo_tree::{
    append_utxo, empty_utxo_tree, utxo_leaf_hash, utxo_tree_root, UtxoTreeState,
};
use mfn_storage::{
    accrue_proof_reward, decode_storage_proof, encode_storage_proof, required_endowment,
    storage_commitment_hash, verify_storage_proof, AccrueArgs, EndowmentParams, StorageCommitment,
    StorageProof, StorageProofCheck, DEFAULT_ENDOWMENT_PARAMS,
};

use crate::bond_wire::{bond_merkle_root, decode_bond_op, encode_bond_op, BondOp, BondWireError};
use crate::bonding::{BondingParams, DEFAULT_BONDING_PARAMS};
use crate::claims::{
    authorship_claim_key, check_claim_key_unique, check_claim_storage_binding, claim_to_record,
    claims_merkle_root, collect_claim_merkle_leaves_for_txs, verified_claims_for_tx,
    AuthorshipClaimVerifyError, VerifiedClaimsForTxResult,
};
use crate::coinbase::{is_coinbase_shaped, verify_coinbase};
use crate::consensus::{decode_finality_proof, verify_finality_proof, SlotContext, Validator};
use crate::emission::{emission_at_height, EmissionParams, DEFAULT_EMISSION_PARAMS};
use crate::slashing::{
    decode_evidence, encode_evidence, EvidenceCheck, SlashDecodeError, SlashEvidence,
};
use crate::transaction::{
    encode_transaction, read_transaction, tx_id, verify_transaction, TransactionWire, TxDecodeError,
};

use super::header::{Block, BlockHeader, HEADER_VERSION};
use super::state::ChainState;
use super::wire::{storage_merkle_root, tx_merkle_root};

/* ----------------------------------------------------------------------- *
 *  Block builder (producer-side)                                           *
 * ----------------------------------------------------------------------- */

/// Build an unsealed (no `producer_proof`) header for the next block.
/// Producers compute the [`header_signing_hash`] over this header to know
/// what to BLS-sign; once they have a [`crate::consensus::FinalityProof`],
/// they call [`seal_block`] to produce the final `Block`.
///
/// `slot` is the explicit slot timer value; tests can default it to
/// `height`.
pub fn build_unsealed_header(
    state: &ChainState,
    txs: &[TransactionWire],
    bond_ops: &[BondOp],
    slashings: &[SlashEvidence],
    storage_proofs: &[StorageProof],
    slot: u32,
    timestamp: u64,
) -> BlockHeader {
    let next_height = state.height.map(|h| h + 1).unwrap_or(0);

    // Storage commitments newly introduced this block (in tx-output
    // declaration order). Duplicates of already-anchored commitments do
    // NOT contribute (they were paid for by the original anchor).
    let mut new_storages: Vec<StorageCommitment> = Vec::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for tx in txs {
        for out in &tx.outputs {
            if let Some(sc) = &out.storage {
                let h = storage_commitment_hash(sc);
                if state.storage.contains_key(&h) || !seen.insert(h) {
                    continue;
                }
                new_storages.push(sc.clone());
            }
        }
    }

    // Project the post-block accumulator: every tx output appended in
    // tx-by-tx, output-by-output order.
    let mut projected_tree = state.utxo_tree.clone();
    for tx in txs {
        for out in &tx.outputs {
            let leaf = utxo_leaf_hash(&out.one_time_addr, &out.amount, next_height);
            projected_tree =
                append_utxo(&projected_tree, leaf).expect("realistic block fits in accumulator");
        }
    }

    let prev_hash = state.tip_id().copied().unwrap_or([0u8; 32]);

    let claim_leaves = collect_claim_merkle_leaves_for_txs(txs, next_height).unwrap_or_else(|e| {
        panic!("build_unsealed_header: invalid authorship MFEX/MFCL in tx list: {e}")
    });
    let claims_root = claims_merkle_root(&claim_leaves);

    BlockHeader {
        version: HEADER_VERSION,
        prev_hash,
        height: next_height,
        slot,
        timestamp,
        tx_root: tx_merkle_root(txs),
        storage_root: storage_merkle_root(&new_storages),
        bond_root: bond_merkle_root(bond_ops),
        slashing_root: crate::slashing::slashing_merkle_root(slashings),
        storage_proof_root: mfn_storage::storage_proof_merkle_root(storage_proofs),
        // Commit to the validator set the block was produced against —
        // i.e., the *pre-block* set held by `state`. Any rotation /
        // slashing applied in this block moves the *next* header's
        // validator_root, not this one's.
        validator_root: crate::consensus::validator_set_root(&state.validators),
        claims_root,
        producer_proof: Vec::new(),
        utxo_root: utxo_tree_root(&projected_tree),
    }
}

/// Attach an encoded finality proof to a header.
pub fn seal_block(
    mut header: BlockHeader,
    txs: Vec<TransactionWire>,
    bond_ops: Vec<BondOp>,
    producer_proof: Vec<u8>,
    slashings: Vec<SlashEvidence>,
    storage_proofs: Vec<StorageProof>,
) -> Block {
    header.producer_proof = producer_proof;
    Block {
        header,
        txs,
        slashings,
        storage_proofs,
        bond_ops,
    }
}
