//! Light-follow quorum and weak-subjectivity checkpoint helpers (**M4.14**).

use mfn_consensus::validator_set_root;
use mfn_light::LightChain;
use serde::{Deserialize, Serialize};

use crate::core::WasmCoreError;
use crate::light_chain_core::light_chain_from_checkpoint_hex;

#[derive(Serialize)]
struct CheckpointSummary {
    genesis_id: String,
    tip_height: u32,
    tip_block_id: String,
    validator_count: usize,
    validator_set_root: String,
    checkpoint_digest: String,
}

#[derive(Serialize)]
struct WeakSubjectivityOk {
    ok: bool,
    agrees: bool,
    local: CheckpointSummary,
    remote: CheckpointSummary,
}

#[derive(Serialize)]
struct QuorumOk {
    ok: bool,
    row_count: usize,
    peer_count: usize,
}

#[derive(Serialize)]
struct StepErr {
    ok: bool,
    error: String,
}

#[derive(Deserialize)]
struct FollowRowJson {
    height: u32,
    block_id: String,
    header_hex: String,
    slashings: Option<Vec<FollowBlobJson>>,
    bond_ops: Option<Vec<FollowBlobJson>>,
}

#[derive(Deserialize)]
struct FollowBlobJson {
    evidence_hex: Option<String>,
    op_hex: Option<String>,
}

#[derive(Deserialize)]
struct FollowBatchJson {
    rows: Vec<FollowRowJson>,
}

#[derive(Deserialize)]
struct FollowQuorumBody {
    batches: Vec<FollowBatchJson>,
}

#[derive(Deserialize)]
struct TrustedSummaryJson {
    genesis_id: String,
    tip_height: u32,
    tip_block_id: String,
    validator_set_root: String,
}

fn decode_hex_payload(hex_str: &str) -> Result<Vec<u8>, WasmCoreError> {
    let t = hex_str
        .trim()
        .strip_prefix("0x")
        .or_else(|| hex_str.trim().strip_prefix("0X"))
        .unwrap_or(hex_str.trim());
    hex::decode(t).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
}

fn normalize_hex32(s: &str) -> String {
    let t = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    t.to_ascii_lowercase()
}

fn checkpoint_summary(chain: &LightChain) -> CheckpointSummary {
    let bytes = chain.encode_checkpoint();
    let digest = mfn_crypto::dhash(mfn_crypto::domain::LIGHT_CHECKPOINT, &[&bytes]);
    CheckpointSummary {
        genesis_id: hex::encode(chain.genesis_id()),
        tip_height: chain.tip_height(),
        tip_block_id: hex::encode(chain.tip_id()),
        validator_count: chain.trusted_validators().len(),
        validator_set_root: hex::encode(validator_set_root(chain.trusted_validators())),
        checkpoint_digest: hex::encode(digest),
    }
}

/// Weak-subjectivity digest for a light-follower checkpoint (browser compare).
pub fn light_chain_checkpoint_summary_json(checkpoint_hex: &str) -> Result<String, WasmCoreError> {
    let chain = light_chain_from_checkpoint_hex(checkpoint_hex)?;
    let body = checkpoint_summary(&chain);
    serde_json::to_string(&body).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
}

/// Compare a locally stored trusted summary against a checkpoint (e.g. RPC snapshot).
pub fn light_chain_weak_subjectivity_json(
    trusted_summary_json: &str,
    checkpoint_hex: &str,
) -> Result<String, WasmCoreError> {
    let trusted: TrustedSummaryJson = serde_json::from_str(trusted_summary_json)
        .map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    let chain = light_chain_from_checkpoint_hex(checkpoint_hex)?;
    let remote = checkpoint_summary(&chain);
    let agrees = normalize_hex32(&trusted.genesis_id) == remote.genesis_id
        && trusted.tip_height == remote.tip_height
        && normalize_hex32(&trusted.tip_block_id) == remote.tip_block_id
        && normalize_hex32(&trusted.validator_set_root) == remote.validator_set_root;
    let local = CheckpointSummary {
        genesis_id: normalize_hex32(&trusted.genesis_id),
        tip_height: trusted.tip_height,
        tip_block_id: normalize_hex32(&trusted.tip_block_id),
        validator_count: remote.validator_count,
        validator_set_root: normalize_hex32(&trusted.validator_set_root),
        checkpoint_digest: String::new(),
    };
    let body = WeakSubjectivityOk {
        ok: true,
        agrees,
        local,
        remote,
    };
    serde_json::to_string(&body).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
}

fn row_blob_hex_list(
    rows: &[FollowRowJson],
    field_slashings: bool,
) -> Result<Vec<Vec<String>>, WasmCoreError> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let blobs = if field_slashings {
            row.slashings.as_deref().unwrap_or(&[])
        } else {
            row.bond_ops.as_deref().unwrap_or(&[])
        };
        let mut hexes = Vec::with_capacity(blobs.len());
        for b in blobs {
            let h = if field_slashings {
                b.evidence_hex.as_deref()
            } else {
                b.op_hex.as_deref()
            };
            let Some(raw) = h else {
                return Err(WasmCoreError::InvalidHex(
                    "follow row missing evidence_hex/op_hex".into(),
                ));
            };
            hexes.push(normalize_hex32(raw));
        }
        out.push(hexes);
    }
    Ok(out)
}

/// Require every `get_light_follow`-shaped batch in `batches` to agree row-for-row.
pub fn light_follow_quorum_json(batches_json: &str) -> Result<String, WasmCoreError> {
    let body: FollowQuorumBody =
        serde_json::from_str(batches_json).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    if body.batches.is_empty() {
        let err = StepErr {
            ok: false,
            error: "quorum requires at least one batch".into(),
        };
        return serde_json::to_string(&err).map_err(|e| WasmCoreError::InvalidHex(e.to_string()));
    }
    let reference = &body.batches[0].rows;
    for (peer_index, batch) in body.batches.iter().enumerate().skip(1) {
        if batch.rows.len() != reference.len() {
            let err = StepErr {
                ok: false,
                error: format!(
                    "peer {peer_index} row count {} != reference {}",
                    batch.rows.len(),
                    reference.len()
                ),
            };
            return serde_json::to_string(&err)
                .map_err(|e| WasmCoreError::InvalidHex(e.to_string()));
        }
        for (row_a, row_b) in reference.iter().zip(&batch.rows) {
            if row_a.height != row_b.height {
                let err = StepErr {
                    ok: false,
                    error: format!("peer {peer_index} height mismatch at {}", row_a.height),
                };
                return serde_json::to_string(&err)
                    .map_err(|e| WasmCoreError::InvalidHex(e.to_string()));
            }
            if normalize_hex32(&row_a.block_id) != normalize_hex32(&row_b.block_id) {
                let err = StepErr {
                    ok: false,
                    error: format!(
                        "peer {peer_index} block_id mismatch at height {}",
                        row_a.height
                    ),
                };
                return serde_json::to_string(&err)
                    .map_err(|e| WasmCoreError::InvalidHex(e.to_string()));
            }
            let ha = decode_hex_payload(&row_a.header_hex)?;
            let hb = decode_hex_payload(&row_b.header_hex)?;
            if ha != hb {
                let err = StepErr {
                    ok: false,
                    error: format!(
                        "peer {peer_index} header_hex mismatch at height {}",
                        row_a.height
                    ),
                };
                return serde_json::to_string(&err)
                    .map_err(|e| WasmCoreError::InvalidHex(e.to_string()));
            }
        }
        let slash_a = row_blob_hex_list(reference, true)?;
        let slash_b = row_blob_hex_list(&batch.rows, true)?;
        if slash_a != slash_b {
            let err = StepErr {
                ok: false,
                error: format!("peer {peer_index} slashings mismatch"),
            };
            return serde_json::to_string(&err)
                .map_err(|e| WasmCoreError::InvalidHex(e.to_string()));
        }
        let bond_a = row_blob_hex_list(reference, false)?;
        let bond_b = row_blob_hex_list(&batch.rows, false)?;
        if bond_a != bond_b {
            let err = StepErr {
                ok: false,
                error: format!("peer {peer_index} bond_ops mismatch"),
            };
            return serde_json::to_string(&err)
                .map_err(|e| WasmCoreError::InvalidHex(e.to_string()));
        }
    }
    let ok = QuorumOk {
        ok: true,
        row_count: reference.len(),
        peer_count: body.batches.len(),
    };
    serde_json::to_string(&ok).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
}
