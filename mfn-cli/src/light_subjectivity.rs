//! Weak-subjectivity checkpoint summaries for CLI light wallets (**M3.13**–**M3.15**).

use std::fs;
use std::path::{Path, PathBuf};

use crate::rpc::LightCheckpointSummary;
use crate::rpc::RpcClient;
use crate::wallet_cmd::WalletCmdError;
use crate::wallet_store::WalletFile;
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

/// Options for `wallet export-trusted-summary` (**M3.14**).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportTrustedSummaryParams {
    /// Write JSON here; stdout when `None`.
    pub output_path: Option<PathBuf>,
    /// Snapshot height; chain tip when `None` (ignored with [`Self::from_wallet_checkpoint`]).
    pub height: Option<u32>,
    /// Persist summary into `wallet.json` (`trusted_light_summary`).
    pub pin_wallet: bool,
    /// Derive summary from persisted `light_checkpoint_hex` instead of RPC.
    pub from_wallet_checkpoint: bool,
}

/// Fetch or derive a trusted summary and optionally write / pin it.
pub fn wallet_export_trusted_summary(
    wallet_path: &Path,
    client: &mut RpcClient,
    params: &ExportTrustedSummaryParams,
) -> Result<(), WalletCmdError> {
    let summary = if params.from_wallet_checkpoint {
        let file = WalletFile::load(wallet_path)?;
        let cp_hex = file.light_checkpoint_hex.as_ref().ok_or_else(|| {
            WalletCmdError::Usage(
                "wallet has no light_checkpoint_hex; run wallet light-scan first".into(),
            )
        })?;
        summary_from_checkpoint_hex(cp_hex)
            .map_err(|e| WalletCmdError::Usage(format!("summary from checkpoint: {e}")))?
    } else {
        let height = match params.height {
            Some(h) => h,
            None => {
                let tip = client.get_tip()?;
                u32::try_from(tip.tip_height.unwrap_or(0))
                    .map_err(|_| WalletCmdError::Usage("tip_height exceeds u32::MAX".into()))?
            }
        };
        let snap = client.get_light_snapshot(Some(height))?;
        if snap.tip_height != height {
            return Err(WalletCmdError::Usage(format!(
                "get_light_snapshot at {height} returned tip_height {}",
                snap.tip_height
            )));
        }
        let derived = summary_from_checkpoint_hex(&snap.checkpoint_hex)
            .map_err(|e| WalletCmdError::Usage(format!("derive summary: {e}")))?;
        if norm_hex32(&snap.summary.genesis_id) != norm_hex32(&derived.genesis_id)
            || snap.summary.tip_height != derived.tip_height
            || norm_hex32(&snap.summary.tip_block_id) != norm_hex32(&derived.tip_block_id)
            || norm_hex32(&snap.summary.validator_set_root)
                != norm_hex32(&derived.validator_set_root)
        {
            return Err(WalletCmdError::Usage(
                "RPC embedded summary disagrees with checkpoint-derived summary".into(),
            ));
        }
        snap.summary
    };

    if let Some(out) = &params.output_path {
        save_trusted_summary_file(out, &summary)?;
        println!("wrote {}", out.display());
    } else {
        let raw = serde_json::to_string_pretty(&summary)
            .map_err(|e| WalletCmdError::Usage(format!("encode summary: {e}")))?;
        println!("{raw}");
    }

    println!("tip_height={}", summary.tip_height);
    println!("checkpoint_digest={}", summary.checkpoint_digest);
    println!("validator_set_root={}", summary.validator_set_root);

    if params.pin_wallet {
        let mut file = WalletFile::load(wallet_path)?;
        file.trusted_light_summary = Some(summary);
        file.save(wallet_path)?;
        println!("pinned trusted_light_summary in {}", wallet_path.display());
    }

    Ok(())
}

/// Options for `wallet import-trusted-summary` (**M3.15**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportTrustedSummaryParams {
    /// JSON file produced by export or `get_light_snapshot.summary`.
    pub summary_path: PathBuf,
    /// When the wallet has `light_checkpoint_hex`, require agreement before pin.
    pub verify_wallet_checkpoint: bool,
}

/// Load a trusted summary file and pin it into `wallet.json` (offline).
pub fn wallet_import_trusted_summary(
    wallet_path: &Path,
    params: &ImportTrustedSummaryParams,
) -> Result<(), WalletCmdError> {
    let summary = load_trusted_summary_file(&params.summary_path)?;
    validate_trusted_summary(&summary)?;

    if params.verify_wallet_checkpoint {
        let file = WalletFile::load(wallet_path)?;
        if let Some(cp_hex) = file.light_checkpoint_hex.as_ref() {
            weak_subjectivity_agrees(&summary, cp_hex).map_err(|e| {
                WalletCmdError::Usage(format!(
                    "trusted summary disagrees with wallet light_checkpoint_hex: {e}"
                ))
            })?;
            println!("verified trusted summary against wallet light checkpoint");
        } else {
            println!("wallet has no light_checkpoint_hex; skipped checkpoint verify");
        }
    }

    let mut file = WalletFile::load(wallet_path)?;
    file.trusted_light_summary = Some(summary.clone());
    file.save(wallet_path)?;

    println!(
        "imported trusted_light_summary from {}",
        params.summary_path.display()
    );
    println!("tip_height={}", summary.tip_height);
    println!("checkpoint_digest={}", summary.checkpoint_digest);
    println!("validator_set_root={}", summary.validator_set_root);
    println!("pinned in {}", wallet_path.display());
    Ok(())
}

fn validate_trusted_summary(summary: &LightCheckpointSummary) -> Result<(), WalletCmdError> {
    for (label, hex) in [
        ("genesis_id", summary.genesis_id.as_str()),
        ("tip_block_id", summary.tip_block_id.as_str()),
        ("validator_set_root", summary.validator_set_root.as_str()),
        ("checkpoint_digest", summary.checkpoint_digest.as_str()),
    ] {
        let t = hex
            .trim()
            .strip_prefix("0x")
            .or_else(|| hex.trim().strip_prefix("0X"))
            .unwrap_or(hex.trim());
        if t.is_empty() || !t.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(WalletCmdError::Usage(format!(
                "trusted summary field {label} is not hex"
            )));
        }
    }
    Ok(())
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

    #[test]
    fn validate_trusted_summary_rejects_bad_digest() {
        let chain = sample_chain();
        let hex = hex::encode(chain.encode_checkpoint());
        let mut summary = summary_from_checkpoint_hex(&hex).expect("summary");
        summary.checkpoint_digest = "not-hex".into();
        assert!(validate_trusted_summary(&summary).is_err());
    }
}
