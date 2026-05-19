//! Target-agnostic helpers (unit-tested on native; re-exported to WASM).

use mfn_storage::{
    build_storage_commitment, required_endowment, storage_commitment_hash, DEFAULT_ENDOWMENT_PARAMS,
};
use mfn_wallet::{wallet_from_seed, ClaimingIdentity};
use serde::Serialize;

/// Errors from seed parsing or storage construction.
#[derive(Debug, thiserror::Error)]
pub enum WasmCoreError {
    /// Hex seed / argument decode failure.
    #[error("{0}")]
    InvalidHex(String),
    /// Storage commitment could not be built.
    #[error("{0}")]
    Storage(String),
}

/// Parse a 32-byte wallet seed from 64 hex digits (optional `0x` prefix).
pub fn parse_seed_hex(seed_hex: &str) -> Result<[u8; 32], WasmCoreError> {
    let t = seed_hex
        .trim()
        .strip_prefix("0x")
        .or_else(|| seed_hex.trim().strip_prefix("0X"))
        .unwrap_or(seed_hex.trim());
    if t.len() != 64 {
        return Err(WasmCoreError::InvalidHex(format!(
            "seed must be 64 hex characters (got {})",
            t.len()
        )));
    }
    let mut seed = [0u8; 32];
    hex::decode_to_slice(t, &mut seed).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    Ok(seed)
}

/// Stealth address public keys for a deterministic wallet seed (JSON object).
pub fn wallet_address_json_from_seed(seed: &[u8; 32]) -> String {
    #[derive(Serialize)]
    struct Addr {
        view_pub: String,
        spend_pub: String,
    }
    let keys = wallet_from_seed(seed);
    let json = Addr {
        view_pub: hex::encode(keys.view_pub().compress().to_bytes()),
        spend_pub: hex::encode(keys.spend_pub().compress().to_bytes()),
    };
    serde_json::to_string(&json).expect("address json")
}

/// MFCL `claim_pubkey` for the same seed used by `mfn-cli wallet claim`.
pub fn claim_pubkey_hex_from_seed(seed: &[u8; 32]) -> String {
    hex::encode(
        ClaimingIdentity::from_seed(seed)
            .claim_pubkey()
            .compress()
            .to_bytes(),
    )
}

/// Preview a storage upload: chunking, `data_root`, commitment hash, required endowment.
pub fn storage_upload_preview_json(data: &[u8], replication: u8) -> Result<String, WasmCoreError> {
    if replication == 0 {
        return Err(WasmCoreError::Storage(
            "replication must be at least 1".into(),
        ));
    }
    let params = DEFAULT_ENDOWMENT_PARAMS;
    let endowment = required_endowment(data.len() as u64, replication, &params)
        .map_err(|e| WasmCoreError::Storage(e.to_string()))?;
    let endowment_u64 = u64::try_from(endowment).map_err(|_| {
        WasmCoreError::Storage(format!("required_endowment {endowment} exceeds u64::MAX"))
    })?;
    let built = build_storage_commitment(data, endowment_u64, None, replication, None)
        .map_err(|e| WasmCoreError::Storage(e.to_string()))?;
    let commitment_hash = storage_commitment_hash(&built.commit);
    #[derive(Serialize)]
    struct Preview {
        data_root: String,
        commitment_hash: String,
        size_bytes: u64,
        chunk_size: u32,
        num_chunks: u32,
        replication: u8,
        required_endowment: u128,
        endowment_hex: String,
    }
    let json = Preview {
        data_root: hex::encode(built.commit.data_root),
        commitment_hash: hex::encode(commitment_hash),
        size_bytes: built.commit.size_bytes,
        chunk_size: built.commit.chunk_size,
        num_chunks: built.commit.num_chunks,
        replication: built.commit.replication,
        required_endowment: endowment,
        endowment_hex: hex::encode(built.commit.endowment.compress().to_bytes()),
    };
    serde_json::to_string(&json).map_err(|e| WasmCoreError::Storage(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x42u8; 32];

    #[test]
    fn wallet_address_json_is_stable() {
        let j1 = wallet_address_json_from_seed(&SEED);
        let j2 = wallet_address_json_from_seed(&SEED);
        assert_eq!(j1, j2);
        assert!(j1.contains("view_pub"));
        assert!(j1.contains("spend_pub"));
    }

    #[test]
    fn claim_pubkey_matches_wallet_crate() {
        let pk = claim_pubkey_hex_from_seed(&SEED);
        assert_eq!(pk.len(), 64);
    }

    #[test]
    fn storage_preview_nonempty_payload() {
        let j = storage_upload_preview_json(b"permawrite wasm", 3).expect("preview");
        assert!(j.contains("data_root"));
        assert!(j.contains("required_endowment"));
    }

    #[test]
    fn parse_seed_hex_accepts_0x_prefix() {
        let seed = parse_seed_hex(&format!("0x{}", hex::encode(SEED))).expect("parse");
        assert_eq!(seed, SEED);
    }

    #[test]
    fn parse_seed_hex_rejects_short_input() {
        assert!(parse_seed_hex("abcd").is_err());
    }
}
