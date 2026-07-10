//! Weak-subjectivity summary helpers shared by CLI and WASM light clients.

use mfn_consensus::validator_set_root;
use mfn_crypto::dhash;
use mfn_crypto::domain::LIGHT_CHECKPOINT;
use mfn_light::LightChain;
use serde::{Deserialize, Serialize};

/// Weak-subjectivity summary embedded in `get_light_snapshot`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightCheckpointSummary {
    /// Genesis block id (64-char hex).
    pub genesis_id: String,
    /// Checkpoint tip height.
    pub tip_height: u32,
    /// Checkpoint tip block id (64-char hex).
    pub tip_block_id: String,
    /// Trusted validator count.
    pub validator_count: u64,
    /// Validator set Merkle root (64-char hex).
    pub validator_set_root: String,
    /// Checkpoint integrity digest (64-char hex).
    pub checkpoint_digest: String,
    /// Optional diverse boot peers bundled with the checkpoint (**F12** phase 0).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchor_peers: Vec<String>,
}

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
        anchor_peers: Vec::new(),
    })
}

/// Field-by-field equality of two summary objects (all weak-subjectivity fields).
#[must_use]
pub fn summaries_equal(a: &LightCheckpointSummary, b: &LightCheckpointSummary) -> bool {
    norm_hex32(&a.genesis_id) == norm_hex32(&b.genesis_id)
        && a.tip_height == b.tip_height
        && norm_hex32(&a.tip_block_id) == norm_hex32(&b.tip_block_id)
        && a.validator_count == b.validator_count
        && norm_hex32(&a.validator_set_root) == norm_hex32(&b.validator_set_root)
        && norm_hex32(&a.checkpoint_digest) == norm_hex32(&b.checkpoint_digest)
}

/// Human-readable diff when [`summaries_equal`] is false.
#[must_use]
pub fn format_summary_diff(
    left_label: &str,
    left: &LightCheckpointSummary,
    right_label: &str,
    right: &LightCheckpointSummary,
) -> String {
    let mut lines = vec![format!(
        "trusted summary mismatch: {left_label} vs {right_label}"
    )];
    if norm_hex32(&left.genesis_id) != norm_hex32(&right.genesis_id) {
        lines.push(format!(
            "  genesis_id: {} vs {}",
            left.genesis_id, right.genesis_id
        ));
    }
    if left.tip_height != right.tip_height {
        lines.push(format!(
            "  tip_height: {} vs {}",
            left.tip_height, right.tip_height
        ));
    }
    if norm_hex32(&left.tip_block_id) != norm_hex32(&right.tip_block_id) {
        lines.push(format!(
            "  tip_block_id: {} vs {}",
            left.tip_block_id, right.tip_block_id
        ));
    }
    if left.validator_count != right.validator_count {
        lines.push(format!(
            "  validator_count: {} vs {}",
            left.validator_count, right.validator_count
        ));
    }
    if norm_hex32(&left.validator_set_root) != norm_hex32(&right.validator_set_root) {
        lines.push(format!(
            "  validator_set_root: {} vs {}",
            left.validator_set_root, right.validator_set_root
        ));
    }
    if norm_hex32(&left.checkpoint_digest) != norm_hex32(&right.checkpoint_digest) {
        lines.push(format!(
            "  checkpoint_digest: {} vs {}",
            left.checkpoint_digest, right.checkpoint_digest
        ));
    }
    lines.join("\n")
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

/// Normalize a 32-byte hex field (strip `0x`, lowercase).
/// Normalize a hex string to lowercase without `0x` prefix.
pub fn norm_hex32(s: &str) -> String {
    let t = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    t.to_ascii_lowercase()
}

pub(crate) fn decode_hex(s: &str, label: &str) -> Result<Vec<u8>, String> {
    let t = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    hex::decode(t).map_err(|e| format!("{label}: {e}"))
}

pub(crate) fn decode_hex_fixed32(hex_str: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(hex_str, label)?;
    if bytes.len() != 32 {
        return Err(format!("{label}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn decode_hex_fixed64(hex_str: &str, label: &str) -> Result<[u8; 64], String> {
    let bytes = decode_hex(hex_str, label)?;
    if bytes.len() != 64 {
        return Err(format!("{label}: expected 64 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_consensus::{BondingParams, ConsensusParams, GenesisConfig, TEST_CONSENSUS_PARAMS};
    use mfn_light::LightChainConfig;

    fn sample_chain() -> LightChain {
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: ConsensusParams {
                expected_proposers_per_slot: 1.0,
                quorum_stake_bps: 6670,
                liveness_max_consecutive_missed: 3,
                liveness_slash_bps: 100,
                ..TEST_CONSENSUS_PARAMS
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
    fn summaries_equal_detects_digest_mismatch() {
        let chain = sample_chain();
        let hex = hex::encode(chain.encode_checkpoint());
        let a = summary_from_checkpoint_hex(&hex).expect("summary");
        let mut b = a.clone();
        b.checkpoint_digest = "00".repeat(32);
        assert!(!summaries_equal(&a, &b));
        assert!(format_summary_diff("a", &a, "b", &b).contains("checkpoint_digest"));
    }
}
