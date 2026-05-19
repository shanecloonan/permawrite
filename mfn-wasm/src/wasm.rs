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
