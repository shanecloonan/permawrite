//! `mfn-cli uploads` — query on-chain storage index via `mfnd serve` (**M3.9**),
//! list wallet-local SPoRA artifacts (**M3.25**), reconcile both (**M3.26**),
//! and retrieve payload bytes from local artifacts (**M3.27**).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::rpc::{RpcClient, StorageChallenge};
use mfn_storage_operator::backfill_upload_artifact_from_challenge;
use mfn_storage_operator::upload_artifact_store::{
    list_upload_artifacts, load_upload_artifact, upload_artifacts_root,
};

/// Pagination and optional claims join for `uploads list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadsListParams {
    /// Max rows (node clamps to RPC maximum).
    pub limit: Option<u64>,
    /// Skip first N rows.
    pub offset: Option<u64>,
    /// When true, each row may include a `claims` array for its `data_root`.
    pub include_claims: bool,
}

/// Output options for local upload inventory and reconciliation commands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UploadsInventoryParams {
    /// Print a single JSON object instead of key=value lines.
    pub json: bool,
}

/// Output and overwrite options for `uploads fetch-http`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UploadsFetchHttpParams {
    /// Overwrite an existing artifact/output.
    pub force: bool,
    /// Print a single JSON object instead of key=value lines.
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RetrieveOutput {
    data_root_hex: String,
    payload_bytes: usize,
    output_path: String,
    artifact_source_path: Option<String>,
    tx_id: Option<String>,
}

/// Node page size for [`uploads_status`] (matches `MAX_RECENT_UPLOADS_LIMIT` in `mfn-rpc`).
const CHAIN_UPLOADS_PAGE_LIMIT: u64 = 200;

/// On-chain row used for reconciliation (**M3.26**).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainUploadRow {
    /// Storage commitment hash (hex).
    pub commitment_hash: String,
    /// Merkle data root (hex).
    pub data_root: String,
    /// Last height a valid SPoRA proof was applied for this commitment.
    pub last_proven_height: u64,
}

/// Reconciliation outcome for one commitment hash (**M3.26**).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UploadReconcileStatus {
    /// Anchored on-chain and `payload.bin` exists locally.
    Matched,
    /// Artifact on disk but not in the node's recent upload index.
    LocalOnly,
    /// Indexed on-chain but no local artifact directory for `--wallet`.
    ChainOnly,
}

/// Per-commitment reconciliation row (**M3.26**).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadReconcileRow {
    /// `matched`, `local_only`, or `chain_only`.
    pub status: UploadReconcileStatus,
    /// Storage commitment hash (hex).
    pub commitment_hash: String,
    /// Merkle data root when known from local and/or chain row.
    pub data_root: Option<String>,
    /// From chain index when present.
    pub last_proven_height: Option<u64>,
    /// Local `payload.bin` size when an artifact exists.
    pub payload_bytes: Option<u64>,
    /// Local artifact directory when present.
    pub artifact_dir: Option<String>,
}

/// Summary counts from [`reconcile_uploads`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UploadReconcileSummary {
    /// Commitments with both chain index row and local artifact.
    pub matched: usize,
    /// Local artifacts with no matching chain index row.
    pub local_only: usize,
    /// Chain index rows with no local artifact for this wallet.
    pub chain_only: usize,
}

/// Join local artifact summaries with on-chain upload rows by commitment hash.
#[must_use]
pub fn reconcile_uploads(
    local: &[mfn_storage_operator::UploadArtifactSummary],
    chain: &[ChainUploadRow],
) -> (Vec<UploadReconcileRow>, UploadReconcileSummary) {
    let mut local_map: BTreeMap<&str, &mfn_storage_operator::UploadArtifactSummary> =
        BTreeMap::new();
    for e in local {
        local_map.insert(e.commitment_hash_hex.as_str(), e);
    }
    let mut chain_map: BTreeMap<&str, &ChainUploadRow> = BTreeMap::new();
    for row in chain {
        chain_map.insert(row.commitment_hash.as_str(), row);
    }

    let mut hashes: BTreeSet<&str> = BTreeSet::new();
    hashes.extend(local_map.keys().copied());
    hashes.extend(chain_map.keys().copied());

    let mut rows = Vec::with_capacity(hashes.len());
    let mut summary = UploadReconcileSummary::default();
    for hash in hashes {
        let (local_e, chain_e) = (local_map.get(hash), chain_map.get(hash));
        let status = match (local_e, chain_e) {
            (Some(_), Some(_)) => {
                summary.matched += 1;
                UploadReconcileStatus::Matched
            }
            (Some(_), None) => {
                summary.local_only += 1;
                UploadReconcileStatus::LocalOnly
            }
            (None, Some(_)) => {
                summary.chain_only += 1;
                UploadReconcileStatus::ChainOnly
            }
            (None, None) => unreachable!("hash came from maps"),
        };
        rows.push(UploadReconcileRow {
            status,
            commitment_hash: hash.to_string(),
            data_root: local_e
                .map(|e| e.data_root_hex.clone())
                .or_else(|| chain_e.map(|c| c.data_root.clone())),
            last_proven_height: chain_e.map(|c| c.last_proven_height),
            payload_bytes: local_e.map(|e| e.payload_bytes),
            artifact_dir: local_e.map(|e| e.artifact_dir.display().to_string()),
        });
    }
    (rows, summary)
}

fn status_label(status: &UploadReconcileStatus) -> &'static str {
    match status {
        UploadReconcileStatus::Matched => "matched",
        UploadReconcileStatus::LocalOnly => "local_only",
        UploadReconcileStatus::ChainOnly => "chain_only",
    }
}

fn print_reconcile_rows(rows: &[UploadReconcileRow], summary: &UploadReconcileSummary) {
    println!("reconcile_matched={}", summary.matched);
    println!("reconcile_local_only={}", summary.local_only);
    println!("reconcile_chain_only={}", summary.chain_only);
    println!("reconcile_rows={}", rows.len());
    for (i, row) in rows.iter().enumerate() {
        println!(
            "row[{i}] status={} commitment_hash={}",
            status_label(&row.status),
            row.commitment_hash
        );
        if let Some(dr) = &row.data_root {
            println!("row[{i}] data_root={dr}");
        }
        if let Some(h) = row.last_proven_height {
            println!("row[{i}] last_proven_height={h}");
        }
        if let Some(pb) = row.payload_bytes {
            println!("row[{i}] payload_bytes={pb}");
            println!("row[{i}] local_artifact=yes");
        } else {
            println!("row[{i}] local_artifact=no");
        }
        if let Some(dir) = &row.artifact_dir {
            println!("row[{i}] artifact_dir={dir}");
        }
    }
}

fn total_artifact_payload_bytes(local: &[mfn_storage_operator::UploadArtifactSummary]) -> u64 {
    local.iter().map(|e| e.payload_bytes).sum()
}

fn local_artifact_json(e: &mfn_storage_operator::UploadArtifactSummary) -> Value {
    let mut value = serde_json::json!({
        "commitment_hash": e.commitment_hash_hex,
        "data_root": e.data_root_hex,
        "size_bytes": e.size_bytes,
        "payload_bytes": e.payload_bytes,
        "num_chunks": e.num_chunks,
        "replication": e.replication,
        "artifact_dir": e.artifact_dir.display().to_string(),
    });
    let obj = value
        .as_object_mut()
        .expect("local artifact json object literal");
    if !e.source_path.is_empty() {
        obj.insert("source_path".into(), serde_json::json!(e.source_path));
    }
    if let Some(tx_id) = &e.tx_id {
        obj.insert("tx_id".into(), serde_json::json!(tx_id));
    }
    value
}

fn uploads_local_json(root: &Path, local: &[mfn_storage_operator::UploadArtifactSummary]) -> Value {
    serde_json::json!({
        "artifacts_root": root.display().to_string(),
        "artifacts_count": local.len(),
        "artifacts_payload_bytes": total_artifact_payload_bytes(local),
        "artifacts": local.iter().map(local_artifact_json).collect::<Vec<_>>(),
    })
}

fn reconcile_row_json(row: &UploadReconcileRow) -> Value {
    let mut value = serde_json::json!({
        "status": status_label(&row.status),
        "commitment_hash": row.commitment_hash,
        "local_artifact": row.payload_bytes.is_some(),
    });
    let obj = value
        .as_object_mut()
        .expect("reconcile row json object literal");
    if let Some(data_root) = &row.data_root {
        obj.insert("data_root".into(), serde_json::json!(data_root));
    }
    if let Some(last_proven_height) = row.last_proven_height {
        obj.insert(
            "last_proven_height".into(),
            serde_json::json!(last_proven_height),
        );
    }
    if let Some(payload_bytes) = row.payload_bytes {
        obj.insert("payload_bytes".into(), serde_json::json!(payload_bytes));
    }
    if let Some(artifact_dir) = &row.artifact_dir {
        obj.insert("artifact_dir".into(), serde_json::json!(artifact_dir));
    }
    value
}

fn uploads_status_json(
    root: &Path,
    local: &[mfn_storage_operator::UploadArtifactSummary],
    chain: &[ChainUploadRow],
    rows: &[UploadReconcileRow],
    summary: &UploadReconcileSummary,
) -> Value {
    serde_json::json!({
        "artifacts_root": root.display().to_string(),
        "local_artifacts": local.len(),
        "local_artifacts_payload_bytes": total_artifact_payload_bytes(local),
        "chain_uploads_indexed": chain.len(),
        "reconcile": {
            "matched": summary.matched,
            "local_only": summary.local_only,
            "chain_only": summary.chain_only,
            "rows": rows.len(),
        },
        "rows": rows.iter().map(reconcile_row_json).collect::<Vec<_>>(),
    })
}

fn parse_chain_upload_row(i: usize, u: &Value) -> Result<ChainUploadRow, String> {
    let obj = u
        .as_object()
        .ok_or_else(|| format!("uploads[{i}] must be an object"))?;
    let commitment_hash = obj
        .get("commitment_hash")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("uploads[{i}].commitment_hash missing"))?
        .to_string();
    let data_root = obj
        .get("data_root")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("uploads[{i}].data_root missing"))?
        .to_string();
    let last_proven_height = obj
        .get("last_proven_height")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("uploads[{i}].last_proven_height missing"))?;
    Ok(ChainUploadRow {
        commitment_hash,
        data_root,
        last_proven_height,
    })
}

fn fetch_chain_uploads(client: &mut RpcClient) -> Result<Vec<ChainUploadRow>, String> {
    let mut out = Vec::new();
    let mut offset = 0u64;
    loop {
        let v = client
            .call(
                "list_recent_uploads",
                serde_json::json!({
                    "limit": CHAIN_UPLOADS_PAGE_LIMIT,
                    "offset": offset,
                }),
            )
            .map_err(|e| e.to_string())?;
        let total = field_u64(&v, "total")?;
        let page = field_array(&v, "uploads")?;
        let n = page.len();
        for (i, u) in page.iter().enumerate() {
            out.push(parse_chain_upload_row(i, u)?);
        }
        offset = offset.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if n == 0 || offset >= total {
            break;
        }
    }
    Ok(out)
}

/// `uploads status` — reconcile `--wallet` artifacts with `list_recent_uploads` (**M3.26**).
pub fn uploads_status(
    wallet_path: &Path,
    client: &mut RpcClient,
    params: UploadsInventoryParams,
) -> Result<(), String> {
    let local = list_upload_artifacts(wallet_path).map_err(|e| e.to_string())?;
    let chain = fetch_chain_uploads(client)?;
    let root = upload_artifacts_root(wallet_path);
    let (rows, summary) = reconcile_uploads(&local, &chain);
    if params.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&uploads_status_json(
                &root, &local, &chain, &rows, &summary
            ))
            .map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    println!("artifacts_root={}", root.display());
    println!("local_artifacts={}", local.len());
    println!(
        "local_artifacts_payload_bytes={}",
        total_artifact_payload_bytes(&local)
    );
    println!("chain_uploads_indexed={}", chain.len());
    print_reconcile_rows(&rows, &summary);
    Ok(())
}

/// `uploads fetch-http` — backfill from HTTP chunk peers and export payload bytes (**M3.28**).
pub fn uploads_fetch_http(
    wallet_path: &Path,
    client: &mut RpcClient,
    commitment_hash_hex: &str,
    peers: &[String],
    output_path: &Path,
    params: UploadsFetchHttpParams,
) -> Result<(), String> {
    if peers.is_empty() {
        return Err("uploads fetch-http requires at least one PEER".into());
    }
    validate_retrieve_output(output_path, params.force)?;

    let ch = client
        .get_storage_challenge(commitment_hash_hex)
        .map_err(|e| e.to_string())?;
    let op_ch = storage_challenge_for_operator(&ch);
    let backfill = backfill_upload_artifact_from_challenge(
        wallet_path,
        commitment_hash_hex,
        peers,
        &op_ch,
        params.force,
    )
    .map_err(|e| e.to_string())?;

    let retrieve =
        retrieve_artifact_to_output(wallet_path, commitment_hash_hex, output_path, params.force)?;
    if params.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&fetch_http_json(peers, &backfill, &retrieve))
                .map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    println!("commitment_hash={}", backfill.commitment_hash_hex);
    println!("peers={}", peers.join(","));
    println!("quorum={}", peers.len());
    println!("chunks_fetched={}", backfill.chunks_fetched);
    println!("artifact_dir={}", backfill.artifact_dir.display());
    print_retrieve_output(commitment_hash_hex, &retrieve);
    println!("fetch_http=ok");
    Ok(())
}

fn fetch_http_json(
    peers: &[String],
    backfill: &mfn_storage_operator::BackfillResult,
    retrieve: &RetrieveOutput,
) -> Value {
    let mut value = serde_json::json!({
        "commitment_hash": backfill.commitment_hash_hex,
        "data_root": retrieve.data_root_hex,
        "peers": peers,
        "quorum": peers.len(),
        "chunks_fetched": backfill.chunks_fetched,
        "payload_bytes": retrieve.payload_bytes,
        "artifact_dir": backfill.artifact_dir.display().to_string(),
        "output_path": retrieve.output_path,
        "fetch_http": "ok",
    });
    let obj = value
        .as_object_mut()
        .expect("fetch-http json object literal");
    if let Some(source) = &retrieve.artifact_source_path {
        obj.insert("artifact_source_path".into(), serde_json::json!(source));
    }
    if let Some(tx_id) = &retrieve.tx_id {
        obj.insert("tx_id".into(), serde_json::json!(tx_id));
    }
    value
}

fn storage_challenge_for_operator(
    ch: &StorageChallenge,
) -> mfn_storage_operator::rpc::StorageChallenge {
    mfn_storage_operator::rpc::StorageChallenge {
        commitment_hash: ch.commitment_hash.clone(),
        commitment_wire_hex: ch.commitment_wire_hex.clone(),
        data_root: ch.data_root.clone(),
        size_bytes: ch.size_bytes,
        replication: ch.replication,
        num_chunks: ch.num_chunks,
        chunk_size: ch.chunk_size,
        next_height: ch.next_height,
        next_slot: ch.next_slot,
        prev_block_id: ch.prev_block_id.clone(),
        chunk_index: ch.chunk_index,
    }
}

/// `uploads retrieve` — export payload bytes from a wallet-local upload artifact (**M3.27**).
pub fn uploads_retrieve(
    wallet_path: &Path,
    commitment_hash_hex: &str,
    output_path: &Path,
    force: bool,
) -> Result<(), String> {
    let output = retrieve_artifact_to_output(wallet_path, commitment_hash_hex, output_path, force)?;
    print_retrieve_output(commitment_hash_hex, &output);
    println!("retrieve=ok");
    Ok(())
}

fn retrieve_artifact_to_output(
    wallet_path: &Path,
    commitment_hash_hex: &str,
    output_path: &Path,
    force: bool,
) -> Result<RetrieveOutput, String> {
    validate_retrieve_output(output_path, force)?;

    let loaded =
        load_upload_artifact(wallet_path, commitment_hash_hex).map_err(|e| e.to_string())?;
    let temp_path = retrieve_temp_path(output_path)?;
    if temp_path.exists() {
        std::fs::remove_file(&temp_path)
            .map_err(|e| format!("remove stale temp {}: {e}", temp_path.display()))?;
    }
    std::fs::write(&temp_path, &loaded.payload)
        .map_err(|e| format!("write {}: {e}", temp_path.display()))?;
    if output_path.exists() {
        std::fs::remove_file(output_path)
            .map_err(|e| format!("replace {}: {e}", output_path.display()))?;
    }
    std::fs::rename(&temp_path, output_path).map_err(|e| {
        let _ = std::fs::remove_file(&temp_path);
        format!(
            "rename {} to {}: {e}",
            temp_path.display(),
            output_path.display()
        )
    })?;

    Ok(RetrieveOutput {
        data_root_hex: hex::encode(loaded.built.commit.data_root),
        payload_bytes: loaded.payload.len(),
        output_path: output_path.display().to_string(),
        artifact_source_path: (!loaded.source_path.is_empty()).then_some(loaded.source_path),
        tx_id: loaded.tx_id,
    })
}

fn print_retrieve_output(commitment_hash_hex: &str, output: &RetrieveOutput) {
    println!("commitment_hash={commitment_hash_hex}");
    println!("data_root={}", output.data_root_hex);
    println!("payload_bytes={}", output.payload_bytes);
    println!("output_path={}", output.output_path);
    if let Some(source) = &output.artifact_source_path {
        println!("artifact_source_path={source}");
    }
    if let Some(tx_id) = &output.tx_id {
        println!("tx_id={tx_id}");
    }
}

fn validate_retrieve_output(output_path: &Path, force: bool) -> Result<(), String> {
    if output_path.exists() && !force {
        return Err(format!(
            "output file already exists at {}; add `replace` to overwrite",
            output_path.display()
        ));
    }
    if output_path.exists() && !output_path.is_file() {
        return Err(format!(
            "output path exists and is not a file: {}",
            output_path.display()
        ));
    }
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(format!(
                "output parent directory does not exist: {}",
                parent.display()
            ));
        }
    }
    Ok(())
}

fn retrieve_temp_path(output_path: &Path) -> Result<PathBuf, String> {
    let name = output_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("output path has no file name: {}", output_path.display()))?;
    let temp_name = format!(".{name}.tmp");
    Ok(output_path.with_file_name(temp_name))
}

/// `uploads local` — list persisted upload artifacts for `--wallet` (**M3.25**).
pub fn uploads_local(wallet_path: &Path, params: UploadsInventoryParams) -> Result<(), String> {
    let entries = list_upload_artifacts(wallet_path).map_err(|e| e.to_string())?;
    let root = upload_artifacts_root(wallet_path);
    if params.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&uploads_local_json(&root, &entries))
                .map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    println!("artifacts_root={}", root.display());
    println!("artifacts_count={}", entries.len());
    println!(
        "artifacts_payload_bytes={}",
        total_artifact_payload_bytes(&entries)
    );
    for (i, e) in entries.iter().enumerate() {
        println!("artifact[{i}] commitment_hash={}", e.commitment_hash_hex);
        println!("artifact[{i}] data_root={}", e.data_root_hex);
        println!("artifact[{i}] size_bytes={}", e.size_bytes);
        println!("artifact[{i}] payload_bytes={}", e.payload_bytes);
        println!("artifact[{i}] num_chunks={}", e.num_chunks);
        println!("artifact[{i}] replication={}", e.replication);
        if !e.source_path.is_empty() {
            println!("artifact[{i}] source_path={}", e.source_path);
        }
        if let Some(tx_id) = &e.tx_id {
            println!("artifact[{i}] tx_id={tx_id}");
        }
        println!("artifact[{i}] dir={}", e.artifact_dir.display());
    }
    Ok(())
}

/// `uploads list` — storage commitments by `last_proven_height` descending.
pub fn uploads_list(client: &mut RpcClient, params: &UploadsListParams) -> Result<(), String> {
    let v = client
        .call("list_recent_uploads", list_params_json(params))
        .map_err(|e| e.to_string())?;
    print_upload_list_page(&v)
}

fn list_params_json(params: &UploadsListParams) -> Value {
    let mut m = serde_json::Map::new();
    if let Some(limit) = params.limit {
        m.insert("limit".into(), serde_json::json!(limit));
    }
    if let Some(offset) = params.offset {
        m.insert("offset".into(), serde_json::json!(offset));
    }
    if params.include_claims {
        m.insert("include_claims".into(), serde_json::json!(true));
    }
    Value::Object(m)
}

fn print_upload_list_page(v: &Value) -> Result<(), String> {
    let total = field_u64(v, "total")?;
    let offset = field_u64(v, "offset")?;
    let limit = field_u64(v, "limit")?;
    let include_claims = v
        .get("include_claims")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let uploads = field_array(v, "uploads")?;
    println!("total={total}");
    println!("offset={offset}");
    println!("limit={limit}");
    println!("include_claims={include_claims}");
    println!("uploads_returned={}", uploads.len());
    for (i, u) in uploads.iter().enumerate() {
        print_upload_line(i, u, include_claims)?;
    }
    Ok(())
}

fn print_upload_line(i: usize, u: &Value, include_claims: bool) -> Result<(), String> {
    let obj = u
        .as_object()
        .ok_or_else(|| format!("uploads[{i}] must be an object"))?;
    let commitment_hash = obj
        .get("commitment_hash")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("uploads[{i}].commitment_hash missing"))?;
    let data_root = obj
        .get("data_root")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("uploads[{i}].data_root missing"))?;
    let size_bytes = obj
        .get("size_bytes")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("uploads[{i}].size_bytes missing"))?;
    let num_chunks = obj
        .get("num_chunks")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("uploads[{i}].num_chunks missing"))?;
    let replication = obj
        .get("replication")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("uploads[{i}].replication missing"))?;
    let last_proven_height = obj
        .get("last_proven_height")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("uploads[{i}].last_proven_height missing"))?;
    println!(
        "upload[{i}] commitment_hash={commitment_hash} data_root={data_root} size_bytes={size_bytes} num_chunks={num_chunks} replication={replication} last_proven_height={last_proven_height}"
    );
    if include_claims {
        let claims = obj
            .get("claims")
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("uploads[{i}].claims missing (include_claims=true)"))?;
        println!("  claims_count={}", claims.len());
    }
    Ok(())
}

fn field_u64(v: &Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("response missing {key}"))
}

fn field_array<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .ok_or_else(|| format!("response missing {key} array"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_storage::{
        build_storage_commitment, storage_commitment_hash, DEFAULT_ENDOWMENT_PARAMS,
    };
    use mfn_storage_operator::upload_artifact_store::{
        save_upload_artifact, upload_artifacts_root,
    };
    use mfn_storage_operator::UploadArtifactSummary;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_local(hash: &str) -> UploadArtifactSummary {
        UploadArtifactSummary {
            commitment_hash_hex: hash.to_string(),
            data_root_hex: "aa".repeat(32),
            size_bytes: 10,
            num_chunks: 1,
            replication: 1,
            payload_bytes: 10,
            source_path: String::new(),
            tx_id: None,
            artifact_dir: PathBuf::from("artifacts/x"),
        }
    }

    fn temp_wallet(test: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "permawrite-cli-uploads-{test}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    #[test]
    fn reconcile_uploads_matched_local_only_and_chain_only() {
        let local = vec![
            sample_local(&"11".repeat(32)),
            sample_local(&"22".repeat(32)),
        ];
        let chain = vec![
            ChainUploadRow {
                commitment_hash: "11".repeat(32),
                data_root: "bb".repeat(32),
                last_proven_height: 3,
            },
            ChainUploadRow {
                commitment_hash: "33".repeat(32),
                data_root: "cc".repeat(32),
                last_proven_height: 9,
            },
        ];
        let (rows, summary) = reconcile_uploads(&local, &chain);
        assert_eq!(summary.matched, 1);
        assert_eq!(summary.local_only, 1);
        assert_eq!(summary.chain_only, 1);
        assert_eq!(rows.len(), 3);
        let matched = rows
            .iter()
            .find(|r| r.status == UploadReconcileStatus::Matched)
            .expect("matched");
        assert_eq!(matched.last_proven_height, Some(3));
        assert_eq!(matched.payload_bytes, Some(10));
    }

    #[test]
    fn total_artifact_payload_bytes_sums_local_payloads() {
        let mut a = sample_local(&"11".repeat(32));
        a.payload_bytes = 7;
        let mut b = sample_local(&"22".repeat(32));
        b.payload_bytes = 13;
        assert_eq!(total_artifact_payload_bytes(&[a, b]), 20);
    }

    #[test]
    fn uploads_local_json_includes_backup_sizing() {
        let mut artifact = sample_local(&"11".repeat(32));
        artifact.payload_bytes = 42;
        artifact.source_path = "source.bin".into();
        artifact.tx_id = Some("tx1".into());
        let value = uploads_local_json(Path::new("wallet.upload-artifacts"), &[artifact]);
        assert_eq!(value["artifacts_count"], 1);
        assert_eq!(value["artifacts_payload_bytes"], 42);
        assert_eq!(value["artifacts"][0]["source_path"], "source.bin");
        assert_eq!(value["artifacts"][0]["tx_id"], "tx1");
    }

    #[test]
    fn uploads_status_json_includes_reconcile_summary() {
        let local = vec![sample_local(&"11".repeat(32))];
        let chain = vec![ChainUploadRow {
            commitment_hash: "22".repeat(32),
            data_root: "bb".repeat(32),
            last_proven_height: 9,
        }];
        let (rows, summary) = reconcile_uploads(&local, &chain);
        let value = uploads_status_json(
            Path::new("wallet.upload-artifacts"),
            &local,
            &chain,
            &rows,
            &summary,
        );
        assert_eq!(value["local_artifacts"], 1);
        assert_eq!(value["chain_uploads_indexed"], 1);
        assert_eq!(value["reconcile"]["local_only"], 1);
        assert_eq!(value["reconcile"]["chain_only"], 1);
        assert_eq!(value["rows"].as_array().expect("rows").len(), 2);
    }

    #[test]
    fn fetch_http_json_includes_restore_output() {
        let peers = vec!["127.0.0.1:18780".to_string()];
        let backfill = mfn_storage_operator::BackfillResult {
            commitment_hash_hex: "33".repeat(32),
            chunks_fetched: 2,
            payload_bytes: 512,
            artifact_dir: PathBuf::from("wallet.upload-artifacts/33"),
        };
        let retrieve = RetrieveOutput {
            data_root_hex: "aa".repeat(32),
            payload_bytes: 512,
            output_path: "restored.bin".into(),
            artifact_source_path: Some("source.bin".into()),
            tx_id: Some("tx1".into()),
        };
        let value = fetch_http_json(&peers, &backfill, &retrieve);
        assert_eq!(value["commitment_hash"], "33".repeat(32));
        assert_eq!(value["data_root"], "aa".repeat(32));
        assert_eq!(value["peers"][0], "127.0.0.1:18780");
        assert_eq!(value["quorum"], 1);
        assert_eq!(value["chunks_fetched"], 2);
        assert_eq!(value["payload_bytes"], 512);
        assert_eq!(value["artifact_dir"], "wallet.upload-artifacts/33");
        assert_eq!(value["output_path"], "restored.bin");
        assert_eq!(value["artifact_source_path"], "source.bin");
        assert_eq!(value["tx_id"], "tx1");
        assert_eq!(value["fetch_http"], "ok");
    }

    #[test]
    fn uploads_retrieve_writes_payload_and_requires_replace() {
        let wallet = temp_wallet("retrieve");
        let output = wallet.with_file_name("retrieved.bin");
        let payload: Vec<u8> = (0u32..2048).map(|i| (i % 251) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(512),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let hash_hex = hex::encode(storage_commitment_hash(&built.commit));
        save_upload_artifact(
            &wallet,
            &built,
            &payload,
            Path::new("source.bin"),
            Some("tx1"),
        )
        .expect("save artifact");

        uploads_retrieve(&wallet, &hash_hex, &output, false).expect("retrieve");
        assert_eq!(std::fs::read(&output).expect("output"), payload);

        let err = uploads_retrieve(&wallet, &hash_hex, &output, false).expect_err("no replace");
        assert!(err.contains("already exists"), "{err}");
        uploads_retrieve(&wallet, &hash_hex, &output, true).expect("replace retrieve");

        std::fs::remove_file(&output).ok();
        std::fs::remove_dir_all(upload_artifacts_root(&wallet)).ok();
        std::fs::remove_file(&wallet).ok();
    }
}
