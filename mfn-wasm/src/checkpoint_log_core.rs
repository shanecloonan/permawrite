//! Signed checkpoint log verify/cross-check for browser light wallets (**F12** phase 3).

use mfn_checkpoint_log::{
    checkpoint_log_verify_jsonl, cross_check_summary_against_checkpoint_log_jsonl,
    LightCheckpointSummary,
};
use serde::Serialize;

use crate::core::WasmCoreError;

#[derive(Serialize)]
struct VerifyOk {
    ok: bool,
    valid_entries: usize,
    max_tip_height: u32,
    signer_ids: Vec<String>,
}

#[derive(Serialize)]
struct CrossCheckOk {
    ok: bool,
    matched: bool,
    matching_signer_ids: Vec<String>,
    entries_at_height: usize,
}

#[derive(Serialize)]
struct StepErr {
    ok: bool,
    error: String,
}

/// Verify every JSONL line in a signed checkpoint log (in-memory string).
pub fn checkpoint_log_verify_json(log_jsonl: &str) -> Result<String, WasmCoreError> {
    match checkpoint_log_verify_jsonl(log_jsonl) {
        Ok(report) => {
            let body = VerifyOk {
                ok: true,
                valid_entries: report.valid_entries,
                max_tip_height: report.max_tip_height,
                signer_ids: report.signer_ids,
            };
            serde_json::to_string(&body).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
        }
        Err(e) => {
            let body = StepErr {
                ok: false,
                error: e.to_string(),
            };
            serde_json::to_string(&body).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
        }
    }
}

/// Cross-check a trusted summary JSON against a signed checkpoint log JSONL.
pub fn checkpoint_log_cross_check_json(
    summary_json: &str,
    log_jsonl: &str,
) -> Result<String, WasmCoreError> {
    let summary: LightCheckpointSummary = serde_json::from_str(summary_json)
        .map_err(|e| WasmCoreError::InvalidHex(format!("summary json: {e}")))?;
    match cross_check_summary_against_checkpoint_log_jsonl(&summary, log_jsonl) {
        Ok(report) => {
            let body = CrossCheckOk {
                ok: true,
                matched: true,
                matching_signer_ids: report.matching_signer_ids,
                entries_at_height: report.entries_at_height,
            };
            serde_json::to_string(&body).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
        }
        Err(e) => {
            let body = StepErr {
                ok: false,
                error: e.to_string(),
            };
            serde_json::to_string(&body).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_checkpoint_log::{
        checkpoint_log_sign, encode_checkpoint_log_entry, CheckpointLogSignParams,
    };

    fn sample_summary() -> LightCheckpointSummary {
        LightCheckpointSummary {
            genesis_id: "aa".repeat(32),
            tip_height: 42,
            tip_block_id: "bb".repeat(32),
            validator_count: 3,
            validator_set_root: "cc".repeat(32),
            checkpoint_digest: "dd".repeat(32),
            anchor_peers: Vec::new(),
        }
    }

    #[test]
    fn wasm_cross_check_json_matches_cli_crate() {
        let summary = sample_summary();
        let entry = checkpoint_log_sign(&CheckpointLogSignParams {
            summary: summary.clone(),
            signer_id: "wasm-test".into(),
            signer_seed_hex: hex::encode([11u8; 32]),
            checkpoint_hex: None,
        })
        .expect("sign");
        let jsonl = encode_checkpoint_log_entry(&entry).expect("encode");
        let summary_json = serde_json::to_string(&summary).expect("summary json");
        let out = checkpoint_log_cross_check_json(&summary_json, &jsonl).expect("cross-check");
        assert!(out.contains("\"matched\":true"));
        assert!(out.contains("wasm-test"));
    }
}
