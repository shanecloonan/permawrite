//! Signed append-only checkpoint log (**F12** phase 1).
//!
//! Maintainers and community witnesses publish Schnorr-signed trusted-summary
//! entries so light clients can cross-check P2P tips without trusting one RPC.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use mfn_crypto::hash::hash_to_scalar;
use mfn_crypto::point::{generator_g, point_from_bytes};
use mfn_crypto::schnorr::{
    decode_schnorr_signature, encode_schnorr_signature, schnorr_sign_with, schnorr_verify,
    SchnorrKeypair,
};
use serde::{Deserialize, Serialize};

use crate::light_subjectivity::{
    format_summary_diff, load_trusted_summary_file, summaries_equal, summary_from_checkpoint_hex,
};
use crate::rpc::LightCheckpointSummary;
use crate::wallet_cmd::WalletCmdError;

/// Wire format version for checkpoint log entries.
pub const CHECKPOINT_LOG_VERSION: u32 = 1;

/// Domain separation for checkpoint-log maintainer signing keys.
pub const CHECKPOINT_LOG_SIGNER_DOMAIN: &[u8] = b"MFN:checkpoint-log-signer:v1";

/// Domain separation for signed entry payloads.
pub const CHECKPOINT_LOG_ENTRY_DOMAIN: &[u8] = b"MFN:checkpoint-log-entry:v1";

/// Environment variable for default maintainer signing seed (32-byte hex).
pub const MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX_ENV: &str = "MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX";

/// One signed line in a checkpoint log (JSONL).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointLogEntry {
    /// Format version (must be [`CHECKPOINT_LOG_VERSION`]).
    pub version: u32,
    /// Human-readable signer label (e.g. `permawrite-maintainer-1`).
    pub signer_id: String,
    /// RFC3339 UTC timestamp when the entry was published.
    pub published_at: String,
    /// Weak-subjectivity summary being attested.
    pub summary: LightCheckpointSummary,
    /// Optional full checkpoint bytes for offline verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_hex: Option<String>,
    /// Signer public key (64-char hex, compressed Edwards point).
    pub signer_pk_hex: String,
    /// Schnorr signature over [`signing_bytes`](Self::signing_bytes) (128-char hex).
    pub signature_hex: String,
}

/// Payload signed for each log entry (excludes `signature_hex`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CheckpointLogSigningBody<'a> {
    version: u32,
    signer_id: &'a str,
    published_at: &'a str,
    summary: &'a LightCheckpointSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint_hex: Option<&'a str>,
    signer_pk_hex: String,
}

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

/// Result of verifying a checkpoint log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointLogVerifyReport {
    /// Lines successfully verified.
    pub valid_entries: usize,
    /// Highest `tip_height` among valid entries.
    pub max_tip_height: u32,
    /// Distinct signer ids observed.
    pub signer_ids: Vec<String>,
}

/// Result of cross-checking a live summary against a signed checkpoint log (**F12** phase 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointLogCrossCheckReport {
    /// Signer labels whose entries match the live summary at `tip_height`.
    pub matching_signer_ids: Vec<String>,
    /// Valid log entries at the live summary's `tip_height`.
    pub entries_at_height: usize,
}

/// Derive a deterministic maintainer signing key from a 32-byte seed.
#[must_use]
pub fn signer_keypair_from_seed(seed: &[u8; 32]) -> SchnorrKeypair {
    let priv_key = hash_to_scalar(&[CHECKPOINT_LOG_SIGNER_DOMAIN, seed]);
    let pub_key = generator_g() * priv_key;
    SchnorrKeypair { priv_key, pub_key }
}

impl CheckpointLogEntry {
    /// Canonical signing bytes for this entry (domain-separated JSON body).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let body = CheckpointLogSigningBody {
            version: self.version,
            signer_id: &self.signer_id,
            published_at: &self.published_at,
            summary: &self.summary,
            checkpoint_hex: self.checkpoint_hex.as_deref(),
            signer_pk_hex: self.signer_pk_hex.clone(),
        };
        let json = serde_json::to_vec(&body).map_err(|e| format!("encode signing body: {e}"))?;
        let mut out = CHECKPOINT_LOG_ENTRY_DOMAIN.to_vec();
        out.push(0);
        out.extend_from_slice(&json);
        Ok(out)
    }

    /// Verify Schnorr signature and optional checkpoint agreement.
    pub fn verify(&self) -> Result<(), String> {
        if self.version != CHECKPOINT_LOG_VERSION {
            return Err(format!(
                "unsupported checkpoint log version {} (expected {CHECKPOINT_LOG_VERSION})",
                self.version
            ));
        }
        if self.signer_id.trim().is_empty() {
            return Err("signer_id must not be empty".into());
        }
        let pk_bytes = decode_hex_fixed32(&self.signer_pk_hex, "signer_pk_hex")?;
        let sig_bytes = decode_hex_fixed64(&self.signature_hex, "signature_hex")?;
        let pk = point_from_bytes(&pk_bytes).map_err(|e| format!("signer_pk_hex: {e}"))?;
        let sig =
            decode_schnorr_signature(&sig_bytes).map_err(|e| format!("signature_hex: {e}"))?;
        let msg = self.signing_bytes()?;
        if !schnorr_verify(&msg, &sig, &pk) {
            return Err("checkpoint log signature invalid".into());
        }
        if let Some(cp_hex) = self.checkpoint_hex.as_ref() {
            summary_from_checkpoint_hex(cp_hex).map_err(|e| format!("checkpoint_hex: {e}"))?;
            crate::light_subjectivity::weak_subjectivity_agrees(&self.summary, cp_hex)
                .map_err(|e| format!("summary vs checkpoint_hex: {e}"))?;
        }
        Ok(())
    }
}

/// Build and optionally append a signed checkpoint log entry.
pub fn checkpoint_log_sign(
    params: &CheckpointLogSignParams,
) -> Result<CheckpointLogEntry, WalletCmdError> {
    let summary = load_trusted_summary_file(&params.summary_path)?;
    let seed = decode_seed_hex(&params.signer_seed_hex)?;
    let kp = signer_keypair_from_seed(&seed);
    let signer_pk_hex = hex::encode(kp.pub_key.compress().to_bytes());
    let published_at = chrono_lite_rfc3339_now();
    let mut entry = CheckpointLogEntry {
        version: CHECKPOINT_LOG_VERSION,
        signer_id: params.signer_id.clone(),
        published_at,
        summary,
        checkpoint_hex: params.checkpoint_hex.clone(),
        signer_pk_hex,
        signature_hex: String::new(),
    };
    let msg = entry.signing_bytes().map_err(WalletCmdError::Usage)?;
    let sig = schnorr_sign_with(&msg, &kp, &mut rand_core::OsRng);
    entry.signature_hex = hex::encode(encode_schnorr_signature(&sig));
    if let Some(log_path) = &params.append_log {
        append_checkpoint_log_entry(log_path, &entry).map_err(WalletCmdError::Usage)?;
        println!("appended checkpoint log entry to {}", log_path.display());
    }
    Ok(entry)
}

/// Verify every JSONL line in `path`.
pub fn checkpoint_log_verify(path: &Path) -> Result<CheckpointLogVerifyReport, WalletCmdError> {
    let file = File::open(path)
        .map_err(|e| WalletCmdError::Usage(format!("read {}: {e}", path.display())))?;
    let reader = BufReader::new(file);
    let mut valid_entries = 0usize;
    let mut max_tip_height = 0u32;
    let mut signer_ids = Vec::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| {
            WalletCmdError::Usage(format!("read {} line {}: {e}", path.display(), line_no + 1))
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: CheckpointLogEntry = serde_json::from_str(trimmed).map_err(|e| {
            WalletCmdError::Usage(format!(
                "parse {} line {}: {e}",
                path.display(),
                line_no + 1
            ))
        })?;
        entry.verify().map_err(|e| {
            WalletCmdError::Usage(format!("{} line {}: {e}", path.display(), line_no + 1))
        })?;
        valid_entries = valid_entries.saturating_add(1);
        max_tip_height = max_tip_height.max(entry.summary.tip_height);
        if !signer_ids.iter().any(|s| s == &entry.signer_id) {
            signer_ids.push(entry.signer_id.clone());
        }
    }
    if valid_entries == 0 {
        return Err(WalletCmdError::Usage(format!(
            "checkpoint log {} has no entries",
            path.display()
        )));
    }
    Ok(CheckpointLogVerifyReport {
        valid_entries,
        max_tip_height,
        signer_ids,
    })
}

/// Cross-check a live weak-subjectivity summary against a signed checkpoint log.
///
/// Requires at least one cryptographically valid entry whose weak-subjectivity
/// fields match `summary`. Rejects when entries exist at the same `tip_height`
/// but none agree (social consensus disagreement).
pub fn cross_check_summary_against_checkpoint_log(
    summary: &LightCheckpointSummary,
    path: &Path,
) -> Result<CheckpointLogCrossCheckReport, WalletCmdError> {
    let file = File::open(path)
        .map_err(|e| WalletCmdError::Usage(format!("read {}: {e}", path.display())))?;
    let reader = BufReader::new(file);
    let mut matching_signer_ids = Vec::new();
    let mut entries_at_height = 0usize;
    let mut first_disagreement: Option<(String, LightCheckpointSummary)> = None;
    let mut valid_entries = 0usize;

    for (line_no, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| {
            WalletCmdError::Usage(format!("read {} line {}: {e}", path.display(), line_no + 1))
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: CheckpointLogEntry = serde_json::from_str(trimmed).map_err(|e| {
            WalletCmdError::Usage(format!(
                "parse {} line {}: {e}",
                path.display(),
                line_no + 1
            ))
        })?;
        entry.verify().map_err(|e| {
            WalletCmdError::Usage(format!("{} line {}: {e}", path.display(), line_no + 1))
        })?;
        valid_entries = valid_entries.saturating_add(1);

        if entry.summary.tip_height != summary.tip_height {
            continue;
        }
        entries_at_height = entries_at_height.saturating_add(1);
        if summaries_equal(&entry.summary, summary) {
            if !matching_signer_ids.iter().any(|s| s == &entry.signer_id) {
                matching_signer_ids.push(entry.signer_id.clone());
            }
        } else if first_disagreement.is_none() {
            first_disagreement = Some((entry.signer_id.clone(), entry.summary));
        }
    }

    if valid_entries == 0 {
        return Err(WalletCmdError::Usage(format!(
            "checkpoint log {} has no entries",
            path.display()
        )));
    }
    if !matching_signer_ids.is_empty() {
        return Ok(CheckpointLogCrossCheckReport {
            matching_signer_ids,
            entries_at_height,
        });
    }
    if entries_at_height > 0 {
        let (signer_id, disagreeing) = first_disagreement.expect("entries_at_height > 0");
        let diff = format_summary_diff("live sync", summary, &signer_id, &disagreeing);
        return Err(WalletCmdError::Usage(format!(
            "checkpoint log disagrees with live sync at tip_height {}:\n{diff}",
            summary.tip_height
        )));
    }
    Err(WalletCmdError::Usage(format!(
        "checkpoint log {} has no attestation at tip_height {}",
        path.display(),
        summary.tip_height
    )))
}

/// Append a verified entry to a JSONL log (creates file if missing).
pub fn append_checkpoint_log_entry(path: &Path, entry: &CheckpointLogEntry) -> Result<(), String> {
    entry.verify()?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let line = serde_json::to_string(entry).map_err(|e| format!("encode entry: {e}"))?;
    writeln!(file, "{line}").map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

fn decode_seed_hex(hex_str: &str) -> Result<[u8; 32], WalletCmdError> {
    decode_hex_fixed32(hex_str, "signer seed").map_err(WalletCmdError::Usage)
}

fn decode_hex_fixed32(hex_str: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex_vec(hex_str, label)?;
    if bytes.len() != 32 {
        return Err(format!("{label}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_fixed64(hex_str: &str, label: &str) -> Result<[u8; 64], String> {
    let bytes = decode_hex_vec(hex_str, label)?;
    if bytes.len() != 64 {
        return Err(format!("{label}: expected 64 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_vec(hex_str: &str, label: &str) -> Result<Vec<u8>, String> {
    let t = hex_str
        .trim()
        .strip_prefix("0x")
        .or_else(|| hex_str.trim().strip_prefix("0X"))
        .unwrap_or(hex_str.trim());
    hex::decode(t).map_err(|e| format!("{label}: {e}"))
}

fn chrono_lite_rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn sign_and_verify_round_trip() {
        let seed = [7u8; 32];
        let kp = signer_keypair_from_seed(&seed);
        let mut entry = CheckpointLogEntry {
            version: CHECKPOINT_LOG_VERSION,
            signer_id: "test-maintainer".into(),
            published_at: "0Z".into(),
            summary: sample_summary(),
            checkpoint_hex: None,
            signer_pk_hex: hex::encode(kp.pub_key.compress().to_bytes()),
            signature_hex: String::new(),
        };
        let msg = entry.signing_bytes().expect("signing bytes");
        let sig = schnorr_sign_with(&msg, &kp, &mut rand_core::OsRng);
        entry.signature_hex = hex::encode(encode_schnorr_signature(&sig));
        entry.verify().expect("verify");
    }

    fn signed_entry(
        seed: [u8; 32],
        signer_id: &str,
        summary: LightCheckpointSummary,
    ) -> CheckpointLogEntry {
        let kp = signer_keypair_from_seed(&seed);
        let mut entry = CheckpointLogEntry {
            version: CHECKPOINT_LOG_VERSION,
            signer_id: signer_id.into(),
            published_at: "0Z".into(),
            summary,
            checkpoint_hex: None,
            signer_pk_hex: hex::encode(kp.pub_key.compress().to_bytes()),
            signature_hex: String::new(),
        };
        let msg = entry.signing_bytes().expect("signing bytes");
        let sig = schnorr_sign_with(&msg, &kp, &mut rand_core::OsRng);
        entry.signature_hex = hex::encode(encode_schnorr_signature(&sig));
        entry
    }

    #[test]
    fn cross_check_accepts_matching_entry() {
        let summary = sample_summary();
        let entry = signed_entry([9u8; 32], "maintainer-a", summary.clone());
        let dir =
            std::env::temp_dir().join(format!("mfn-checkpoint-log-cross-{}", std::process::id()));
        let log_path = dir.join("checkpoints.jsonl");
        std::fs::create_dir_all(&dir).expect("tmpdir");
        append_checkpoint_log_entry(&log_path, &entry).expect("append");
        let report =
            cross_check_summary_against_checkpoint_log(&summary, &log_path).expect("cross-check");
        assert_eq!(report.matching_signer_ids, vec!["maintainer-a".to_string()]);
        assert_eq!(report.entries_at_height, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_check_rejects_disagreement_at_height() {
        let summary = sample_summary();
        let mut disagree = summary.clone();
        disagree.tip_block_id = "ee".repeat(32);
        let entry = signed_entry([10u8; 32], "maintainer-b", disagree);
        let dir = std::env::temp_dir().join(format!(
            "mfn-checkpoint-log-disagree-{}",
            std::process::id()
        ));
        let log_path = dir.join("checkpoints.jsonl");
        std::fs::create_dir_all(&dir).expect("tmpdir");
        append_checkpoint_log_entry(&log_path, &entry).expect("append");
        let err = cross_check_summary_against_checkpoint_log(&summary, &log_path)
            .expect_err("disagreement");
        assert!(err.to_string().contains("disagrees with live sync"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_signature_rejected() {
        let seed = [8u8; 32];
        let kp = signer_keypair_from_seed(&seed);
        let entry = CheckpointLogEntry {
            version: CHECKPOINT_LOG_VERSION,
            signer_id: "test".into(),
            published_at: "0Z".into(),
            summary: sample_summary(),
            checkpoint_hex: None,
            signer_pk_hex: hex::encode(kp.pub_key.compress().to_bytes()),
            signature_hex: "00".repeat(64),
        };
        assert!(entry.verify().is_err());
    }
}
