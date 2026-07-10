//! Signed checkpoint log for light-client weak subjectivity (**F12**).
//!
//! Shared by `mfn-cli`, `mfn-wasm`, and future light-client hosts so browser
//! wallets cross-check the same Schnorr-signed JSONL as the CLI.

#![warn(missing_docs)]

mod log;
mod summary;

pub use log::{
    checkpoint_log_sign, checkpoint_log_verify_jsonl,
    cross_check_summary_against_checkpoint_log_jsonl, encode_checkpoint_log_entry,
    signer_keypair_from_seed, CheckpointLogCrossCheckReport, CheckpointLogEntry,
    CheckpointLogError, CheckpointLogSignParams, CheckpointLogVerifyReport,
    CHECKPOINT_LOG_ENTRY_DOMAIN, CHECKPOINT_LOG_SIGNER_DOMAIN, CHECKPOINT_LOG_VERSION,
    MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX_ENV,
};
pub use summary::{
    format_summary_diff, norm_hex32, summaries_equal, summary_from_checkpoint_hex,
    weak_subjectivity_agrees, LightCheckpointSummary,
};

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Write};
use std::path::Path;

/// Verify every JSONL line in `path`.
pub fn checkpoint_log_verify_path(
    path: &Path,
) -> Result<CheckpointLogVerifyReport, CheckpointLogError> {
    let file = File::open(path)
        .map_err(|e| CheckpointLogError::Usage(format!("read {}: {e}", path.display())))?;
    let reader = BufReader::new(file);
    log::verify_reader(reader, &path.display().to_string())
}

/// Cross-check a live weak-subjectivity summary against a signed checkpoint log file.
pub fn cross_check_summary_against_checkpoint_log_path(
    summary: &LightCheckpointSummary,
    path: &Path,
) -> Result<CheckpointLogCrossCheckReport, CheckpointLogError> {
    let file = File::open(path)
        .map_err(|e| CheckpointLogError::Usage(format!("read {}: {e}", path.display())))?;
    let reader = BufReader::new(file);
    log::cross_check_reader(summary, reader, &path.display().to_string())
}

/// Append a verified entry to a JSONL log (creates file if missing).
pub fn append_checkpoint_log_entry(
    path: &Path,
    entry: &CheckpointLogEntry,
) -> Result<(), CheckpointLogError> {
    entry.verify().map_err(CheckpointLogError::Usage)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| CheckpointLogError::Usage(format!("open {}: {e}", path.display())))?;
    let line = serde_json::to_string(entry)
        .map_err(|e| CheckpointLogError::Usage(format!("encode entry: {e}")))?;
    writeln!(file, "{line}")
        .map_err(|e| CheckpointLogError::Usage(format!("write {}: {e}", path.display())))?;
    Ok(())
}
