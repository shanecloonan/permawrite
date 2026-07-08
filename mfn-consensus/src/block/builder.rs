//! Producer-side block header builder.

use super::internal::*;

use super::header::{Block, BlockHeader, HEADER_VERSION};
use super::state::ChainState;
use super::wire::{storage_merkle_root, tx_merkle_root};

/* ----------------------------------------------------------------------- *
 *  Block builder (producer-side)                                           *
 * ----------------------------------------------------------------------- */

/// Build an unsealed (no `producer_proof`) header for the next block.
pub fn build_unsealed_header(
    state: &ChainState,
    txs: &[TransactionWire],
    bond_ops: &[BondOp],
    slashings: &[SlashEvidence],
    storage_proofs: &[StorageProof],
    slot: u32,
    timestamp: u64,
) -> BlockHeader {
    build_unsealed_header_storage_ops(
        state,
        txs,
        bond_ops,
        slashings,
        storage_proofs,
        &[],
        slot,
        timestamp,
    )
}

/// Like [`build_unsealed_header`] but includes storage-operator registration ops
/// in the `bond_root` Merkle tree.
#[allow(clippy::too_many_arguments)]
pub fn build_unsealed_header_storage_ops(
    state: &ChainState,
    txs: &[TransactionWire],
    bond_ops: &[BondOp],
    slashings: &[SlashEvidence],
    storage_proofs: &[StorageProof],
    storage_operator_ops: &[StorageOperatorOp],
    slot: u32,
    timestamp: u64,
) -> BlockHeader {
    let next_height = state.height.map(|h| h + 1).unwrap_or(0);

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
        bond_root: bond_section_merkle_root(bond_ops, storage_operator_ops),
        slashing_root: crate::slashing::slashing_merkle_root(slashings),
        storage_proof_root: mfn_storage::storage_proof_merkle_root(storage_proofs),
        validator_root: crate::consensus::validator_set_root(&state.validators),
        claims_root,
        producer_proof: Vec::new(),
        utxo_root: utxo_tree_root(&projected_tree),
    }
}

/// Attach an encoded finality proof to a header.
pub fn seal_block(
    header: BlockHeader,
    txs: Vec<TransactionWire>,
    bond_ops: Vec<BondOp>,
    producer_proof: Vec<u8>,
    slashings: Vec<SlashEvidence>,
    storage_proofs: Vec<StorageProof>,
) -> Block {
    seal_block_storage_ops(
        header,
        txs,
        bond_ops,
        producer_proof,
        slashings,
        storage_proofs,
        Vec::new(),
    )
}

/// Like [`seal_block`] but carries storage-operator registration ops.
pub fn seal_block_storage_ops(
    mut header: BlockHeader,
    txs: Vec<TransactionWire>,
    bond_ops: Vec<BondOp>,
    producer_proof: Vec<u8>,
    slashings: Vec<SlashEvidence>,
    storage_proofs: Vec<StorageProof>,
    storage_operator_ops: Vec<StorageOperatorOp>,
) -> Block {
    header.producer_proof = producer_proof;
    Block {
        header,
        txs,
        slashings,
        storage_proofs,
        bond_ops,
        storage_operator_ops,
    }
}
