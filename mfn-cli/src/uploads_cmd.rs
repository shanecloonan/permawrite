//! `mfn-cli uploads` — query on-chain storage index via `mfnd serve` (**M3.9**)
//! and list wallet-local SPoRA artifacts (**M3.25**).

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
