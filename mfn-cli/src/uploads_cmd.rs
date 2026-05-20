//! `mfn-cli uploads` — query on-chain storage index via `mfnd serve` (**M3.9**),
//! list wallet-local SPoRA artifacts (**M3.25**), and reconcile both (**M3.26**).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::Value;

use crate::rpc::RpcClient;
use mfn_storage_operator::upload_artifact_store::{list_upload_artifacts, upload_artifacts_root};

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
pub fn uploads_status(wallet_path: &Path, client: &mut RpcClient) -> Result<(), String> {
    let local = list_upload_artifacts(wallet_path).map_err(|e| e.to_string())?;
    let chain = fetch_chain_uploads(client)?;
    let root = upload_artifacts_root(wallet_path);
    let (rows, summary) = reconcile_uploads(&local, &chain);
    println!("artifacts_root={}", root.display());
    println!("local_artifacts={}", local.len());
    println!("chain_uploads_indexed={}", chain.len());
    print_reconcile_rows(&rows, &summary);
    Ok(())
}

/// `uploads local` — list persisted upload artifacts for `--wallet` (**M3.25**).
pub fn uploads_local(wallet_path: &Path) -> Result<(), String> {
    let entries = list_upload_artifacts(wallet_path).map_err(|e| e.to_string())?;
    let root = upload_artifacts_root(wallet_path);
    println!("artifacts_root={}", root.display());
    println!("artifacts_count={}", entries.len());
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
    use mfn_storage_operator::UploadArtifactSummary;
    use std::path::PathBuf;

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
}
