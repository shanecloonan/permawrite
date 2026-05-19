//! `mfn-cli claims` — query on-chain MFCL authorship index via `mfnd serve` (**M3.8**).

use serde_json::Value;

use crate::rpc::RpcClient;

/// List pagination for `claims recent` / `claims roots`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimsListParams {
    /// Max rows (node clamps to RPC maximum).
    pub limit: Option<u64>,
    /// Skip first N rows.
    pub offset: Option<u64>,
}

/// `claims for DATA_ROOT_HEX` — all claims bound to a content `data_root`.
pub fn claims_for(client: &mut RpcClient, data_root_hex: &str) -> Result<(), String> {
    let root = normalize_hash32(data_root_hex, "data_root")?;
    let v = client
        .call("get_claims_for", serde_json::json!({ "data_root": root }))
        .map_err(|e| e.to_string())?;
    let data_root = field_str(&v, "data_root")?;
    let claims = field_array(&v, "claims")?;
    println!("data_root={data_root}");
    println!("claim_count={}", claims.len());
    for (i, c) in claims.iter().enumerate() {
        print_claim_line(i, c)?;
    }
    Ok(())
}

/// `claims recent` — newest claims chain-wide (paginated).
pub fn claims_recent(client: &mut RpcClient, params: &ClaimsListParams) -> Result<(), String> {
    let v = client
        .call("list_recent_claims", list_params_json(params))
        .map_err(|e| e.to_string())?;
    print_claim_list_page(&v)
}

/// `claims by-pubkey HEX` — claims signed by one `claim_pubkey`.
pub fn claims_by_pubkey(
    client: &mut RpcClient,
    claim_pubkey_hex: &str,
    limit: Option<u64>,
) -> Result<(), String> {
    let pk = normalize_hash32(claim_pubkey_hex, "claim_pubkey")?;
    let mut params = serde_json::json!({ "claim_pubkey": pk });
    if let Some(lim) = limit {
        params["limit"] = serde_json::json!(lim);
    }
    let v = client
        .call("get_claims_by_pubkey", params)
        .map_err(|e| e.to_string())?;
    let claim_pubkey = field_str(&v, "claim_pubkey")?;
    let limit = field_u64(&v, "limit")?;
    let claims = field_array(&v, "claims")?;
    println!("claim_pubkey={claim_pubkey}");
    println!("limit={limit}");
    println!("claims_returned={}", claims.len());
    for (i, c) in claims.iter().enumerate() {
        print_claim_line(i, c)?;
    }
    Ok(())
}

/// `claims roots` — distinct `data_root` values that have at least one claim.
pub fn claims_roots(client: &mut RpcClient, params: &ClaimsListParams) -> Result<(), String> {
    let v = client
        .call("list_data_roots_with_claims", list_params_json(params))
        .map_err(|e| e.to_string())?;
    let total = field_u64(&v, "total")?;
    let offset = field_u64(&v, "offset")?;
    let limit = field_u64(&v, "limit")?;
    let roots = field_array(&v, "roots")?;
    println!("total={total}");
    println!("offset={offset}");
    println!("limit={limit}");
    println!("roots_returned={}", roots.len());
    for r in roots {
        let obj = r
            .as_object()
            .ok_or_else(|| "roots[] entry must be an object".to_string())?;
        let data_root = obj
            .get("data_root")
            .and_then(|x| x.as_str())
            .ok_or_else(|| "roots[].data_root missing".to_string())?;
        let claim_count = obj
            .get("claim_count")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| "roots[].claim_count missing".to_string())?;
        let max_h = obj
            .get("max_claim_height")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| "roots[].max_claim_height missing".to_string())?;
        println!("data_root={data_root} claim_count={claim_count} max_claim_height={max_h}");
    }
    Ok(())
}

fn list_params_json(params: &ClaimsListParams) -> Value {
    let mut m = serde_json::Map::new();
    if let Some(limit) = params.limit {
        m.insert("limit".into(), serde_json::json!(limit));
    }
    if let Some(offset) = params.offset {
        m.insert("offset".into(), serde_json::json!(offset));
    }
    Value::Object(m)
}

fn print_claim_list_page(v: &Value) -> Result<(), String> {
    let total = field_u64(v, "total")?;
    let offset = field_u64(v, "offset")?;
    let limit = field_u64(v, "limit")?;
    let claims = field_array(v, "claims")?;
    println!("total={total}");
    println!("offset={offset}");
    println!("limit={limit}");
    println!("claims_returned={}", claims.len());
    for (i, c) in claims.iter().enumerate() {
        print_claim_line(i, c)?;
    }
    Ok(())
}

fn print_claim_line(i: usize, c: &Value) -> Result<(), String> {
    let obj = c
        .as_object()
        .ok_or_else(|| format!("claims[{i}] must be an object"))?;
    let height = obj
        .get("height")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("claims[{i}].height missing"))?;
    let data_root = obj
        .get("data_root")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("claims[{i}].data_root missing"))?;
    let claim_pubkey = obj
        .get("claim_pubkey")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("claims[{i}].claim_pubkey missing"))?;
    let commit_hash = obj
        .get("commit_hash")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("claims[{i}].commit_hash missing"))?;
    let tx_id = obj
        .get("tx_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("claims[{i}].tx_id missing"))?;
    let message_hex = obj
        .get("message_hex")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    println!(
        "claim[{i}] height={height} data_root={data_root} claim_pubkey={claim_pubkey} commit_hash={commit_hash} tx_id={tx_id} message_hex={message_hex}"
    );
    Ok(())
}

fn normalize_hash32(hex_str: &str, field: &str) -> Result<String, String> {
    let t = hex_str.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.len() != 64 {
        return Err(format!(
            "{field} must be 64 hex characters (got {})",
            t.len()
        ));
    }
    if hex::decode(t).is_err() {
        return Err(format!("{field} hex decode failed"));
    }
    Ok(t.to_ascii_lowercase())
}

fn field_str(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("response missing {key}"))
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
