//! `wasm-bindgen` exports for browser hosts.

use wasm_bindgen::prelude::*;

use crate::core::{
    claim_pubkey_hex_from_seed, parse_seed_hex, storage_upload_preview_json,
    wallet_address_json_from_seed,
};

fn js_err(msg: impl AsRef<str>) -> JsValue {
    JsValue::from_str(msg.as_ref())
}

/// Derive stealth address public keys from a 64-hex-char wallet seed.
///
/// Returns a JSON string: `{"view_pub":"…","spend_pub":"…"}`.
#[wasm_bindgen(js_name = walletAddressFromSeedHex)]
pub fn wasm_wallet_address_from_seed_hex(seed_hex: &str) -> Result<String, JsValue> {
    let seed = parse_seed_hex(seed_hex).map_err(|e| js_err(e.to_string()))?;
    Ok(wallet_address_json_from_seed(&seed))
}

/// Derive the MFCL claiming public key from the same wallet seed.
#[wasm_bindgen(js_name = claimPubkeyFromSeedHex)]
pub fn wasm_claim_pubkey_from_seed_hex(seed_hex: &str) -> Result<String, JsValue> {
    let seed = parse_seed_hex(seed_hex).map_err(|e| js_err(e.to_string()))?;
    Ok(claim_pubkey_hex_from_seed(&seed))
}

/// Chunk payload bytes and return storage commitment preview JSON.
///
/// `replication` is the on-chain replication factor (≥ 1).
#[wasm_bindgen(js_name = storageUploadPreview)]
pub fn wasm_storage_upload_preview(data: &[u8], replication: u8) -> Result<String, JsValue> {
    storage_upload_preview_json(data, replication).map_err(|e| js_err(e.to_string()))
}

#[cfg(feature = "wasm-full")]
use crate::header_verify_core::{block_id_from_header_hex_json, verify_header_hex_json};
#[cfg(feature = "wasm-full")]
use crate::light_chain_core::{
    light_chain_apply_evolution_json, light_chain_bootstrap_checkpoint_hex,
    light_chain_verify_header_json,
};
#[cfg(feature = "wasm-full")]
use crate::light_quorum_core::{
    light_chain_checkpoint_summary_json, light_chain_weak_subjectivity_json,
    light_follow_quorum_json,
};
#[cfg(feature = "wasm-full")]
use crate::scan_core::{scan_block_hex_json, scan_block_txs_json, scan_transaction_hex_json};
#[cfg(feature = "wasm-full")]
use crate::transfer_core::{build_transfer_json, decoy_pool_preview_json};
#[cfg(feature = "wasm-full")]
use crate::upload_core::{
    build_storage_proof_json, build_storage_upload_json, storage_chunk_hex_json,
    upload_min_fee_json, verify_storage_proof_json,
};

/// Scan a wire-encoded transaction (hex) for outputs owned by the wallet seed.
///
/// `owned_key_images_hex` is a JS array of 64-hex-char key images for outputs
/// already known to be unspent (empty array if none).
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = scanTransactionHex)]
pub fn wasm_scan_transaction_hex(
    seed_hex: &str,
    tx_hex: &str,
    height: u32,
    owned_key_images_hex: Vec<String>,
) -> Result<String, JsValue> {
    let seed = parse_seed_hex(seed_hex).map_err(|e| js_err(e.to_string()))?;
    scan_transaction_hex_json(&seed, tx_hex, height, &owned_key_images_hex)
        .map_err(|e| js_err(e.to_string()))
}

/// Scan a wire-encoded block (hex) for outputs owned by the wallet seed.
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = scanBlockHex)]
pub fn wasm_scan_block_hex(
    seed_hex: &str,
    block_hex: &str,
    owned_key_images_hex: Vec<String>,
) -> Result<String, JsValue> {
    let seed = parse_seed_hex(seed_hex).map_err(|e| js_err(e.to_string()))?;
    scan_block_hex_json(&seed, block_hex, &owned_key_images_hex).map_err(|e| js_err(e.to_string()))
}

/// Recompute `block_id` from header wire hex (does not trust RPC-supplied ids).
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = blockIdFromHeaderHex)]
pub fn wasm_block_id_from_header_hex(header_hex: &str) -> Result<String, JsValue> {
    block_id_from_header_hex_json(header_hex).map_err(|e| js_err(e.to_string()))
}

/// Build a genesis light-follower checkpoint from `get_chain_params` JSON.
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = lightChainBootstrapCheckpoint)]
pub fn wasm_light_chain_bootstrap_checkpoint(trust_json: &str) -> Result<String, JsValue> {
    light_chain_bootstrap_checkpoint_hex(trust_json).map_err(|e| js_err(e.to_string()))
}

/// Verify a header against a light-follower checkpoint (evolving trusted set).
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = lightChainVerifyHeader)]
pub fn wasm_light_chain_verify_header(
    checkpoint_hex: &str,
    header_hex: &str,
) -> Result<String, JsValue> {
    light_chain_verify_header_json(checkpoint_hex, header_hex).map_err(|e| js_err(e.to_string()))
}

/// Apply validator-set evolution after header verify; returns updated checkpoint hex.
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = lightChainApplyEvolution)]
pub fn wasm_light_chain_apply_evolution(
    checkpoint_hex: &str,
    header_hex: &str,
    evolution_json: &str,
) -> Result<String, JsValue> {
    light_chain_apply_evolution_json(checkpoint_hex, header_hex, evolution_json)
        .map_err(|e| js_err(e.to_string()))
}

/// Weak-subjectivity digest of a light-follower checkpoint (**M4.14**).
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = lightChainCheckpointSummary)]
pub fn wasm_light_chain_checkpoint_summary(checkpoint_hex: &str) -> Result<String, JsValue> {
    light_chain_checkpoint_summary_json(checkpoint_hex).map_err(|e| js_err(e.to_string()))
}

/// Compare a trusted summary JSON against a checkpoint (**M4.14**).
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = lightChainWeakSubjectivity)]
pub fn wasm_light_chain_weak_subjectivity(
    trusted_summary_json: &str,
    checkpoint_hex: &str,
) -> Result<String, JsValue> {
    light_chain_weak_subjectivity_json(trusted_summary_json, checkpoint_hex)
        .map_err(|e| js_err(e.to_string()))
}

/// Require multiple `get_light_follow` batches to agree row-for-row (**M4.14**).
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = lightFollowQuorum)]
pub fn wasm_light_follow_quorum(batches_json: &str) -> Result<String, JsValue> {
    light_follow_quorum_json(batches_json).map_err(|e| js_err(e.to_string()))
}

/// Verify BLS finality + validator-root binding on a header wire hex.
///
/// `validators_json` / `consensus_json` match [`get_chain_params`] RPC fields.
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = verifyHeaderHex)]
pub fn wasm_verify_header_hex(
    header_hex: &str,
    validators_json: &str,
    consensus_json: &str,
) -> Result<String, JsValue> {
    verify_header_hex_json(header_hex, validators_json, consensus_json)
        .map_err(|e| js_err(e.to_string()))
}

/// Scan wire-encoded transactions at `height` without downloading the full block body.
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = scanBlockTxsHex)]
pub fn wasm_scan_block_txs_hex(
    seed_hex: &str,
    height: u32,
    tx_hexes: Vec<String>,
    owned_key_images_hex: Vec<String>,
) -> Result<String, JsValue> {
    let seed = parse_seed_hex(seed_hex).map_err(|e| js_err(e.to_string()))?;
    scan_block_txs_json(&seed, height, &tx_hexes, &owned_key_images_hex)
        .map_err(|e| js_err(e.to_string()))
}

/// Preview a decoy pool from a JSON array of `{height, one_time_addr_hex, commit_hex}`.
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = decoyPoolPreviewJson)]
pub fn wasm_decoy_pool_preview_json(
    decoy_utxos_json: &str,
    exclude_one_time_addrs_hex: Vec<String>,
) -> Result<String, JsValue> {
    decoy_pool_preview_json(decoy_utxos_json, &exclude_one_time_addrs_hex)
        .map_err(|e| js_err(e.to_string()))
}

/// Build and sign a CLSAG transfer; `plan_json` matches the Rust [`TransferPlanJson`] shape.
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = buildTransferJson)]
pub fn wasm_build_transfer_json(plan_json: &str) -> Result<String, JsValue> {
    build_transfer_json(plan_json).map_err(|e| js_err(e.to_string()))
}

/// Minimum mempool fee for a storage upload (returns JSON number).
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = uploadMinFee)]
pub fn wasm_upload_min_fee(
    data_len: u32,
    replication: u8,
    fee_to_treasury_bps: u16,
) -> Result<String, JsValue> {
    upload_min_fee_json(u64::from(data_len), replication, fee_to_treasury_bps)
        .map_err(|e| js_err(e.to_string()))
}

/// Build and sign a storage upload tx; `plan_json` describes inputs, anchor, decoys, fee.
#[cfg(feature = "wasm-full")]
#[wasm_bindgen(js_name = buildStorageUpload)]
pub fn wasm_build_storage_upload(
    seed_hex: &str,
    data: &[u8],
    plan_json: &str,
) -> Result<String, JsValue> {
    let seed = parse_seed_hex(seed_hex).map_err(|e| js_err(e.to_string()))?;
    build_storage_upload_json(&seed, data, plan_json).map_err(|e| js_err(e.to_string()))
}

#[cfg(feature = "wasm-full")]
/// Build a SPoRA storage proof from seed, payload bytes, and commitment wire hex.
#[wasm_bindgen(js_name = buildStorageProof)]
pub fn wasm_build_storage_proof(
    seed_hex: &str,
    data: &[u8],
    prev_block_id_hex: &str,
    slot: u32,
    commitment_wire_hex: &str,
) -> Result<String, JsValue> {
    build_storage_proof_json(seed_hex, data, prev_block_id_hex, slot, commitment_wire_hex)
        .map_err(|e| js_err(e.to_string()))
}
#[cfg(feature = "wasm-full")]
/// Verify a SPoRA storage proof; returns JSON `{ valid, check }`.
#[wasm_bindgen(js_name = verifyStorageProof)]
pub fn wasm_verify_storage_proof(
    commitment_wire_hex: &str,
    prev_block_id_hex: &str,
    slot: u32,
    proof_wire_hex: &str,
) -> Result<String, JsValue> {
    verify_storage_proof_json(commitment_wire_hex, prev_block_id_hex, slot, proof_wire_hex)
        .map_err(|e| js_err(e.to_string()))
}
#[cfg(feature = "wasm-full")]
/// Extract one chunk of payload data as hex for HTTP replication.
#[wasm_bindgen(js_name = storageChunkHex)]
pub fn wasm_storage_chunk_hex(data: &[u8], chunk_size: u32, index: u32) -> Result<String, JsValue> {
    storage_chunk_hex_json(data, chunk_size, index).map_err(|e| js_err(e.to_string()))
}
