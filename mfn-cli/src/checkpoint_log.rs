//! Signed append-only checkpoint log (**F12**) — CLI file IO wrapper.

use std::path::Path;

pub use mfn_checkpoint_log::{
    append_checkpoint_log_entry, encode_checkpoint_log_entry, signer_keypair_from_seed,
    CheckpointLogCrossCheckReport, CheckpointLogEntry, CheckpointLogVerifyReport,
    CHECKPOINT_LOG_ENTRY_DOMAIN, CHECKPOINT_LOG_SIGNER_DOMAIN, CHECKPOINT_LOG_VERSION,
    MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX_ENV,
};

use mfn_checkpoint_log::{
    checkpoint_log_sign as core_checkpoint_log_sign, checkpoint_log_verify_path,
    cross_check_summary_against_checkpoint_log_path, CheckpointLogError, LightCheckpointSummary,
};

use crate::light_subjectivity::load_trusted_summary_file;
use crate::wallet_cmd::WalletCmdError;

/// Parameters for `checkpoint-log sign`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointLogSignParams {
    /// Trusted summary JSON file (`export-trusted-summary` shape).
    pub summary_path: std::path::PathBuf,
    /// Signer label embedded in the log.
    pub signer_id: String,
    /// 32-byte hex seed for maintainer Schnorr key (not a wallet spend seed).
    pub signer_seed_hex: String,
    /// Optional checkpoint hex copied into the entry.
    pub checkpoint_hex: Option<String>,
    /// Append signed entry to this JSONL file when set.
    pub append_log: Option<std::path::PathBuf>,
}

/// Build and optionally append a signed checkpoint log entry.
pub fn checkpoint_log_sign(
    params: &CheckpointLogSignParams,
) -> Result<CheckpointLogEntry, WalletCmdError> {
    let summary = load_trusted_summary_file(&params.summary_path)?;
    let core_params = mfn_checkpoint_log::CheckpointLogSignParams {
        summary,
        signer_id: params.signer_id.clone(),
        signer_seed_hex: params.signer_seed_hex.clone(),
        checkpoint_hex: params.checkpoint_hex.clone(),
    };
    let entry = core_checkpoint_log_sign(&core_params).map_err(map_log_err)?;
    if let Some(log_path) = &params.append_log {
        append_checkpoint_log_entry(log_path, &entry).map_err(map_log_err)?;
        println!("appended checkpoint log entry to {}", log_path.display());
    }
    Ok(entry)
}

/// Verify every JSONL line in `path`.
pub fn checkpoint_log_verify(path: &Path) -> Result<CheckpointLogVerifyReport, WalletCmdError> {
    checkpoint_log_verify_path(path).map_err(map_log_err)
}

/// Cross-check a live weak-subjectivity summary against a signed checkpoint log.
pub fn cross_check_summary_against_checkpoint_log(
    summary: &LightCheckpointSummary,
    path: &Path,
) -> Result<CheckpointLogCrossCheckReport, WalletCmdError> {
    cross_check_summary_against_checkpoint_log_path(summary, path).map_err(map_log_err)
}

fn map_log_err(err: CheckpointLogError) -> WalletCmdError {
    WalletCmdError::Usage(err.to_string())
}
