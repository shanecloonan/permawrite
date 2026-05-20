//! Weak-subjectivity checkpoint summaries for CLI light wallets (**M3.13**).

use std::fs;
use std::path::Path;

use crate::rpc::LightCheckpointSummary;
use crate::wallet_cmd::WalletCmdError;
use mfn_consensus::validator_set_root;
use mfn_crypto::dhash;
use mfn_crypto::domain::LIGHT_CHECKPOINT;
use mfn_light::LightChain;

/// Build the same summary object as `get_light_snapshot.summary` / browser pins.
pub fn summary_from_checkpoint_hex(checkpoint_hex: &str) -> Result<LightCheckpointSummary, String> {
    let bytes = decode_hex(checkpoint_hex, "checkpoint_hex")?;
    let chain = LightChain::decode_checkpoint(&bytes).map_err(|e| format!("decode: {e}"))?;
    let checkpoint_bytes = chain.encode_checkpoint();
    let digest = dhash(LIGHT_CHECKPOINT, &[&checkpoint_bytes]);
    Ok(LightCheckpointSummary {
        genesis_id: hex::encode(chain.genesis_id()),
        tip_height: chain.tip_height(),
        tip_block_id: hex::encode(chain.tip_id()),
        validator_count: u64::try_from(chain.trusted_validators().len())
            .map_err(|_| "validator_count overflow".to_string())?,
        validator_set_root: hex::encode(validator_set_root(chain.trusted_validators())),
        checkpoint_digest: hex::encode(digest),
    })
}

/// Compare pinned weak-subjectivity fields against a checkpoint (M4.14 parity).
pub fn weak_subjectivity_agrees(
    trusted: &LightCheckpointSummary,
    checkpoint_hex: &str,
) -> Result<(), String> {
    let remote = summary_from_checkpoint_hex(checkpoint_hex)?;
    if norm_hex32(&trusted.genesis_id) != norm_hex32(&remote.genesis_id) {
        return Err("genesis_id mismatch (trusted vs checkpoint)".into());
    }
    if trusted.tip_height != remote.tip_height {
        return Err(format!(
            "tip_height mismatch (trusted {} vs checkpoint {})",
            trusted.tip_height, remote.tip_height
        ));
    }
    if norm_hex32(&trusted.tip_block_id) != norm_hex32(&remote.tip_block_id) {
        return Err("tip_block_id mismatch (trusted vs checkpoint)".into());
    }
    if norm_hex32(&trusted.validator_set_root) != norm_hex32(&remote.validator_set_root) {
        return Err("validator_set_root mismatch (trusted vs checkpoint)".into());
    }
    Ok(())
}

/// Load a trusted summary JSON file (`get_light_snapshot.summary` shape).
pub fn load_trusted_summary_file(path: &Path) -> Result<LightCheckpointSummary, WalletCmdError> {
    let raw = fs::read_to_string(path)
        .map_err(|e| WalletCmdError::Usage(format!("read {}: {e}", path.display())))?;
    serde_json::from_str(&raw).map_err(|e| {
        WalletCmdError::Usage(format!("parse trusted summary {}: {e}", path.display()))
    })
}

/// Write a trusted summary for out-of-band distribution.
pub fn save_trusted_summary_file(
    path: &Path,
    summary: &LightCheckpointSummary,
) -> Result<(), WalletCmdError> {
    let raw = serde_json::to_string_pretty(summary)
        .map_err(|e| WalletCmdError::Usage(format!("encode trusted summary: {e}")))?;
    fs::write(path, raw)
        .map_err(|e| WalletCmdError::Usage(format!("write {}: {e}", path.display())))
}

fn norm_hex32(s: &str) -> String {
    let t = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    t.to_ascii_lowercase()
}

fn decode_hex(s: &str, label: &str) -> Result<Vec<u8>, String> {
    let t = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    hex::decode(t).map_err(|e| format!("{label}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_consensus::{BondingParams, ConsensusParams, GenesisConfig};
    use mfn_light::LightChainConfig;

    fn sample_chain() -> LightChain {
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: ConsensusParams {
                expected_proposers_per_slot: 1.0,
                quorum_stake_bps: 6670,
                liveness_max_consecutive_missed: 3,
                liveness_slash_bps: 100,
            },
            emission_params: mfn_consensus::DEFAULT_EMISSION_PARAMS,
            endowment_params: mfn_storage::DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: Some(BondingParams {
                min_validator_stake: 1,
                unbond_delay_heights: 1,
                max_entry_churn_per_epoch: 1,
                max_exit_churn_per_epoch: 1,
                slots_per_epoch: 1,
            }),
        };
        LightChain::from_genesis(LightChainConfig::new(cfg))
    }

    #[test]
    fn weak_subjectivity_round_trip() {
        let chain = sample_chain();
        let hex = hex::encode(chain.encode_checkpoint());
        let summary = summary_from_checkpoint_hex(&hex).expect("summary");
        weak_subjectivity_agrees(&summary, &hex).expect("agrees");
    }

    #[test]
    fn weak_subjectivity_rejects_wrong_height() {
        let chain = sample_chain();
        let hex = hex::encode(chain.encode_checkpoint());
        let mut summary = summary_from_checkpoint_hex(&hex).expect("summary");
        summary.tip_height = 99;
        assert!(weak_subjectivity_agrees(&summary, &hex).is_err());
    }
}
