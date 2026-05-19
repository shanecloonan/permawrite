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
use crate::scan_core::{scan_block_hex_json, scan_transaction_hex_json};
#[cfg(feature = "wasm-full")]
use crate::transfer_core::{build_transfer_json, decoy_pool_preview_json};
#[cfg(feature = "wasm-full")]
use crate::upload_core::{build_storage_upload_json, upload_min_fee_json};

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
