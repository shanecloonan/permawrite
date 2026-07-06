//! Shared imports for block submodules (crate-private).

#![allow(unused_imports)]

pub(crate) use std::collections::{BTreeMap, HashMap, HashSet};

pub(crate) use curve25519_dalek::edwards::EdwardsPoint;

pub(crate) use mfn_crypto::codec::{Reader, Writer};
pub(crate) use mfn_crypto::domain::{BLOCK_HEADER, BLOCK_ID};
pub(crate) use mfn_crypto::hash::dhash;
pub(crate) use mfn_crypto::merkle::merkle_root_or_zero;
pub(crate) use mfn_crypto::utxo_tree::{
    append_utxo, empty_utxo_tree, utxo_leaf_hash, utxo_tree_root, UtxoTreeState,
};
pub(crate) use mfn_storage::{
    accrue_proof_reward, decode_storage_proof, encode_storage_proof, required_endowment,
    storage_commitment_hash, validate_storage_commitment_shape, verify_storage_proof, AccrueArgs,
    EndowmentParams, StorageCommitment, StorageProof, StorageProofCheck, DEFAULT_ENDOWMENT_PARAMS,
};

pub(crate) use crate::bond_wire::{
    bond_merkle_root, decode_bond_op, encode_bond_op, BondOp, BondWireError,
};
pub(crate) use crate::bonding::{BondingParams, DEFAULT_BONDING_PARAMS};
pub(crate) use crate::claims::{
    authorship_claim_key, check_claim_key_unique, check_claim_storage_binding, claim_to_record,
    claims_merkle_root, collect_claim_merkle_leaves_for_txs, verified_claims_for_tx,
    AuthorshipClaimVerifyError, VerifiedClaimsForTxResult,
};
pub(crate) use crate::coinbase::{is_coinbase_shaped, verify_coinbase_outputs};
pub(crate) use crate::consensus::Validator;
#[cfg(feature = "bls")]
pub(crate) use crate::consensus::{decode_finality_proof, verify_finality_proof, SlotContext};
pub(crate) use crate::emission::{
    block_coinbase_specs, emission_at_height, EmissionParams, DEFAULT_EMISSION_PARAMS,
};
pub(crate) use crate::slashing::{
    decode_evidence, encode_evidence, EvidenceCheck, SlashDecodeError, SlashEvidence,
};
pub(crate) use crate::transaction::{
    encode_transaction, read_transaction, tx_id, verify_transaction, TransactionWire, TxDecodeError,
};
