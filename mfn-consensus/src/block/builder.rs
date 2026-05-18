//! Producer-side block header builder.

use super::internal::*;

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
