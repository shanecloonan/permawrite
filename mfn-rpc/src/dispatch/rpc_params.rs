//! JSON-RPC `params` parsing for `mfnd serve` dispatch.

use serde_json::{Map, Value};

/// `submit_storage_proof` accepts `params` as `{"proof_hex": "…"}` or `["…"]`.
pub(super) fn extract_submit_proof_hex(params: Option<&Value>) -> Result<&str, String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    match p {
        Value::Object(obj) => match obj.get("proof_hex") {
            Some(Value::String(s)) => Ok(s.as_str()),
            Some(_) => Err("params.proof_hex must be a JSON string".to_string()),
            None => {
                Err("missing params.proof_hex (hex-encoded encode_storage_proof bytes)".to_string())
            }
        },
        Value::Array(arr) => {
            let first = arr
                .first()
                .ok_or_else(|| "params array is empty (expected one hex string)".to_string())?;
            match first {
                Value::String(s) => Ok(s.as_str()),
                _ => Err(
                    "params[0] must be a JSON string (hex-encoded encode_storage_proof bytes)"
                        .to_string(),
                ),
            }
        }
        _ => Err("params must be a JSON object or a JSON array".to_string()),
    }
}

/// Parsed `get_storage_challenge` params (**B-45**: optional operator payout pubs).
pub(super) struct StorageChallengeParams {
    pub commit_hash: [u8; 32],
    pub operator_view_pub: Option<curve25519_dalek::edwards::EdwardsPoint>,
    pub operator_spend_pub: Option<curve25519_dalek::edwards::EdwardsPoint>,
}

/// `get_storage_challenge` accepts commitment hash plus optional compressed
/// operator payout points (`view_pub_hex` / `spend_pub_hex`) for B3 salted challenges.
pub(super) fn extract_storage_challenge_params(
    params: Option<&Value>,
) -> Result<StorageChallengeParams, String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    let (hex_s, view_hex, spend_hex) = match p {
        Value::Object(obj) => {
            let hex_s = obj
                .get("commitment_hash")
                .or_else(|| obj.get("commit_hash"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    "missing params.commitment_hash (64-char hex storage commitment hash)"
                        .to_string()
                })?;
            let view_hex = obj.get("view_pub_hex").and_then(|v| v.as_str());
            let spend_hex = obj.get("spend_pub_hex").and_then(|v| v.as_str());
            (hex_s, view_hex, spend_hex)
        }
        Value::Array(arr) => {
            let hex_s = arr.first().and_then(|v| v.as_str()).ok_or_else(|| {
                "params array is empty (expected commitment_hash hex)".to_string()
            })?;
            (hex_s, None, None)
        }
        _ => return Err("params must be a JSON object or a JSON array".to_string()),
    };
    let commit_hash = parse_tx_id_hex32(hex_s)?;
    let (operator_view_pub, operator_spend_pub) = match (view_hex, spend_hex) {
        (None, None) => (None, None),
        (Some(vh), Some(sh)) => (
            Some(parse_compressed_edwards_hex(vh, "view_pub_hex")?),
            Some(parse_compressed_edwards_hex(sh, "spend_pub_hex")?),
        ),
        _ => {
            return Err(
                "params.view_pub_hex and params.spend_pub_hex must both be set or both omitted"
                    .to_string(),
            );
        }
    };
    Ok(StorageChallengeParams {
        commit_hash,
        operator_view_pub,
        operator_spend_pub,
    })
}

fn parse_compressed_edwards_hex(
    hex_s: &str,
    field: &str,
) -> Result<curve25519_dalek::edwards::EdwardsPoint, String> {
    let hex_s = hex_s
        .strip_prefix("0x")
        .or_else(|| hex_s.strip_prefix("0X"))
        .unwrap_or(hex_s);
    let bytes = hex::decode(hex_s).map_err(|e| format!("{field}: hex decode: {e}"))?;
    mfn_crypto::point::point_from_bytes(&bytes).map_err(|e| format!("{field}: {e}"))
}

/// `submit_tx` accepts `params` as `{"tx_hex": "…"}` or `["…"]` (hex only).
pub(super) fn extract_submit_tx_hex(params: Option<&Value>) -> Result<&str, String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    match p {
        Value::Object(obj) => match obj.get("tx_hex") {
            Some(Value::String(s)) => Ok(s.as_str()),
            Some(_) => Err("params.tx_hex must be a JSON string".to_string()),
            None => Err("missing params.tx_hex (hex-encoded encode_transaction bytes)".to_string()),
        },
        Value::Array(arr) => {
            let first = arr
                .first()
                .ok_or_else(|| "params array is empty (expected one hex string)".to_string())?;
            match first {
                Value::String(s) => Ok(s.as_str()),
                _ => Err(
                    "params[0] must be a JSON string (hex-encoded encode_transaction bytes)"
                        .to_string(),
                ),
            }
        }
        _ => Err("params must be a JSON object or a JSON array".to_string()),
    }
}

pub(super) fn parse_height_u32(n: u64) -> Result<u32, String> {
    u32::try_from(n).map_err(|_| format!("height {n} is out of u32 range"))
}

/// `get_block` / `get_block_header` accept `params` as `{"height": N}` or `[N]`
/// (block heights ≥ 1).
pub(super) fn extract_height_param(params: Option<&Value>) -> Result<u32, String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    let n = match p {
        Value::Object(obj) => match obj.get("height") {
            Some(Value::Number(num)) => num
                .as_u64()
                .ok_or_else(|| "params.height must be a non-negative JSON number".to_string())?,
            Some(_) => return Err("params.height must be a JSON number".to_string()),
            None => return Err("missing params.height".to_string()),
        },
        Value::Array(arr) => {
            let first = arr
                .first()
                .ok_or_else(|| "params array is empty (expected one height)".to_string())?;
            match first {
                Value::Number(num) => num.as_u64().ok_or_else(|| {
                    "params[0] height must be a non-negative JSON number".to_string()
                })?,
                _ => return Err("params[0] must be a JSON number (block height)".to_string()),
            }
        }
        _ => return Err("params must be a JSON object or a JSON array".to_string()),
    };
    parse_height_u32(n)
}

/// Max inclusive span for [`get_block_headers`] (`to_height - from_height + 1`).
pub(super) const MAX_BLOCK_HEADERS_SPAN: u32 = 4096;

/// `get_block_headers` accepts `{"from_height": N, "to_height": M}` with `1 ≤ N ≤ M` and
/// `M - N + 1 ≤ MAX_BLOCK_HEADERS_SPAN`.
pub(super) fn extract_height_range_param(params: Option<&Value>) -> Result<(u32, u32), String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    let obj = match p {
        Value::Object(o) => o,
        _ => {
            return Err("params must be a JSON object with from_height and to_height".to_string());
        }
    };
    let from = match obj.get("from_height") {
        Some(Value::Number(num)) => num
            .as_u64()
            .ok_or_else(|| "params.from_height must be a non-negative JSON number".to_string())?,
        Some(_) => return Err("params.from_height must be a JSON number".to_string()),
        None => return Err("missing params.from_height".to_string()),
    };
    let to = match obj.get("to_height") {
        Some(Value::Number(num)) => num
            .as_u64()
            .ok_or_else(|| "params.to_height must be a non-negative JSON number".to_string())?,
        Some(_) => return Err("params.to_height must be a JSON number".to_string()),
        None => return Err("missing params.to_height".to_string()),
    };
    let from_h = parse_height_u32(from)?;
    let to_h = parse_height_u32(to)?;
    if to_h < from_h {
        return Err(format!("to_height {to_h} must be ≥ from_height {from_h}"));
    }
    let span = to_h - from_h + 1;
    if span > MAX_BLOCK_HEADERS_SPAN {
        return Err(format!(
            "header range span {span} exceeds max {MAX_BLOCK_HEADERS_SPAN} (narrow from_height..to_height)"
        ));
    }
    Ok((from_h, to_h))
}

/// `get_light_follow_p2p` — `peer` plus the same height range as [`get_light_follow`].
pub(super) fn extract_peer_light_follow_params(
    params: Option<&Value>,
) -> Result<(String, u32, u32), String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    let obj = match p {
        Value::Object(o) => o,
        _ => {
            return Err(
                "params must be a JSON object with peer, from_height, and to_height".to_string(),
            );
        }
    };
    let peer = match obj.get("peer") {
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        Some(_) => return Err("params.peer must be a non-empty string (HOST:PORT)".to_string()),
        None => return Err("missing params.peer (HOST:PORT)".to_string()),
    };
    let (from_h, to_h) = extract_height_range_param(Some(p))?;
    Ok((peer, from_h, to_h))
}

/// `get_light_follow_quorum_p2p` — `peers` array plus height range (**M4.16**).
pub(super) fn extract_peers_light_follow_params(
    params: Option<&Value>,
) -> Result<(Vec<String>, u32, u32), String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    let obj = match p {
        Value::Object(o) => o,
        _ => {
            return Err(
                "params must be a JSON object with peers, from_height, and to_height".to_string(),
            );
        }
    };
    let peers_val = obj
        .get("peers")
        .ok_or_else(|| "missing params.peers (array of HOST:PORT)".to_string())?;
    let peers: Vec<String> = match peers_val {
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for (i, item) in arr.iter().enumerate() {
                let s = item
                    .as_str()
                    .ok_or_else(|| format!("params.peers[{i}] must be a string"))?;
                let t = s.trim();
                if t.is_empty() {
                    return Err(format!("params.peers[{i}] must be non-empty"));
                }
                out.push(t.to_string());
            }
            out
        }
        _ => return Err("params.peers must be a JSON array of HOST:PORT strings".to_string()),
    };
    if peers.len() < 2 {
        return Err("quorum requires at least 2 peers in params.peers".to_string());
    }
    if peers.len() > 8 {
        return Err("at most 8 peers per quorum fetch".to_string());
    }
    let (from_h, to_h) = extract_height_range_param(Some(p))?;
    Ok((peers, from_h, to_h))
}

/// `get_mempool_tx` reads a 32-byte transaction id from hex (same shapes as height params).
pub(super) fn extract_tx_id_param(params: Option<&Value>) -> Result<&str, String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    match p {
        Value::Object(obj) => match obj.get("tx_id") {
            Some(Value::String(s)) => Ok(s.as_str()),
            Some(_) => Err("params.tx_id must be a JSON string".to_string()),
            None => Err("missing params.tx_id (64 hex digits, 32-byte tx id)".to_string()),
        },
        Value::Array(arr) => {
            let first = arr.first().ok_or_else(|| {
                "params array is empty (expected one tx_id hex string)".to_string()
            })?;
            match first {
                Value::String(s) => Ok(s.as_str()),
                _ => Err(
                    "params[0] must be a JSON string (64 hex digits, 32-byte tx id)".to_string(),
                ),
            }
        }
        _ => Err("params must be a JSON object or a JSON array".to_string()),
    }
}

pub(super) fn parse_tx_id_hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.len() != 64 {
        return Err(format!(
            "tx_id hex must be exactly 64 hex digits (32 bytes), got {} characters",
            s.len()
        ));
    }
    let bytes = hex::decode(s).map_err(|e| format!("tx_id hex decode: {e}"))?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

pub(super) const DEFAULT_CLAIMS_BY_PUBKEY_LIMIT: u64 = 50;
pub(super) const MAX_CLAIMS_BY_PUBKEY_LIMIT: u64 = 500;
pub(super) const DEFAULT_RECENT_UPLOADS_LIMIT: u64 = 20;
pub(super) const MAX_RECENT_UPLOADS_LIMIT: u64 = 200;
/// Default page size for [`list_utxos`] (browser decoy pools).
pub(super) const DEFAULT_LIST_UTXOS_LIMIT: u64 = 500;
pub(super) const MAX_LIST_UTXOS_LIMIT: u64 = 10_000;

pub(super) fn extract_data_root_param(params: Option<&Value>) -> Result<&str, String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    match p {
        Value::Object(obj) => match obj.get("data_root") {
            Some(Value::String(s)) => Ok(s.as_str()),
            Some(_) => Err("params.data_root must be a JSON string".to_string()),
            None => Err("missing params.data_root (64 hex digits, 32-byte data root)".to_string()),
        },
        Value::Array(arr) => {
            let first = arr.first().ok_or_else(|| {
                "params array is empty (expected one data_root hex string)".to_string()
            })?;
            match first {
                Value::String(s) => Ok(s.as_str()),
                _ => Err(
                    "params[0] must be a JSON string (64 hex digits, 32-byte data root)"
                        .to_string(),
                ),
            }
        }
        _ => Err("params must be a JSON object or a JSON array".to_string()),
    }
}

pub(super) fn extract_claim_pubkey_and_limit(
    params: Option<&Value>,
) -> Result<([u8; 32], usize), String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    let (pk_str, lim_u64) = match p {
        Value::Object(obj) => {
            let pk = match obj.get("claim_pubkey") {
                Some(Value::String(s)) => s.as_str(),
                Some(_) => return Err("params.claim_pubkey must be a JSON string".to_string()),
                None => return Err("missing params.claim_pubkey (64 hex digits)".to_string()),
            };
            let lim = match obj.get("limit") {
                None => DEFAULT_CLAIMS_BY_PUBKEY_LIMIT,
                Some(Value::Number(n)) => n
                    .as_u64()
                    .ok_or_else(|| "params.limit must be a non-negative JSON number".to_string())?,
                Some(_) => return Err("params.limit must be a JSON number".to_string()),
            };
            (pk, lim)
        }
        Value::Array(arr) => {
            let first = arr
                .first()
                .ok_or_else(|| "params array is empty (expected claim_pubkey hex)".to_string())?;
            let pk = match first {
                Value::String(s) => s.as_str(),
                _ => return Err("params[0] must be a JSON string (claim_pubkey hex)".to_string()),
            };
            let lim = match arr.get(1) {
                None => DEFAULT_CLAIMS_BY_PUBKEY_LIMIT,
                Some(Value::Number(n)) => n.as_u64().ok_or_else(|| {
                    "params[1] limit must be a non-negative JSON number".to_string()
                })?,
                Some(_) => return Err("params[1] must be a JSON number (limit)".to_string()),
            };
            (pk, lim)
        }
        _ => return Err("params must be a JSON object or a JSON array".to_string()),
    };
    let root = parse_tx_id_hex32(pk_str)?;
    let lim = lim_u64.clamp(1, MAX_CLAIMS_BY_PUBKEY_LIMIT);
    let lim_usize = usize::try_from(lim).map_err(|_| "limit out of usize range".to_string())?;
    Ok((root, lim_usize))
}

/// Shared **`limit`** / **`offset`** parsing for paged discovery RPCs.
pub(super) fn extract_list_limit_offset_from_object_with_caps(
    obj: &Map<String, Value>,
    default_limit: u64,
    max_limit: u64,
) -> Result<(usize, usize), String> {
    let limit_u = match obj.get("limit") {
        None => default_limit,
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| "params.limit must be a non-negative JSON number".to_string())?,
        Some(_) => return Err("params.limit must be a JSON number".to_string()),
    };
    let offset_u = match obj.get("offset") {
        None => 0u64,
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| "params.offset must be a non-negative JSON number".to_string())?,
        Some(_) => return Err("params.offset must be a JSON number".to_string()),
    };
    let limit_u = limit_u.clamp(1, max_limit);
    let limit = usize::try_from(limit_u).map_err(|_| "limit out of usize range".to_string())?;
    let offset = usize::try_from(offset_u).map_err(|_| "offset out of usize range".to_string())?;
    Ok((limit, offset))
}

/// Shared **`limit`** / **`offset`** parsing for paged discovery RPCs (`list_recent_uploads`, M2.2.10).
pub(super) fn extract_list_limit_offset_from_object(
    obj: &Map<String, Value>,
) -> Result<(usize, usize), String> {
    extract_list_limit_offset_from_object_with_caps(
        obj,
        DEFAULT_RECENT_UPLOADS_LIMIT,
        MAX_RECENT_UPLOADS_LIMIT,
    )
}

pub(super) fn extract_list_utxos_params(params: Option<&Value>) -> Result<(usize, usize), String> {
    match params {
        None | Some(Value::Null) => Ok((
            usize::try_from(DEFAULT_LIST_UTXOS_LIMIT).expect("DEFAULT_LIST_UTXOS_LIMIT fits usize"),
            0,
        )),
        Some(Value::Object(obj)) if obj.is_empty() => Ok((
            usize::try_from(DEFAULT_LIST_UTXOS_LIMIT).expect("DEFAULT_LIST_UTXOS_LIMIT fits usize"),
            0,
        )),
        Some(Value::Object(obj)) => extract_list_limit_offset_from_object_with_caps(
            obj,
            DEFAULT_LIST_UTXOS_LIMIT,
            MAX_LIST_UTXOS_LIMIT,
        ),
        Some(Value::Array(_)) => Err("params must be a JSON object (not an array)".to_string()),
        Some(_) => Err("params must be a JSON object".to_string()),
    }
}

pub(super) fn extract_list_limit_offset_params(
    params: Option<&Value>,
) -> Result<(usize, usize), String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    let Value::Object(obj) = p else {
        return Err("params must be a JSON object".to_string());
    };
    extract_list_limit_offset_from_object(obj)
}

pub(super) fn extract_list_recent_uploads_params(
    params: Option<&Value>,
) -> Result<(usize, usize, bool), String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    let Value::Object(obj) = p else {
        return Err("params must be a JSON object".to_string());
    };
    let (limit, offset) = extract_list_limit_offset_from_object(obj)?;
    let include_claims = match obj.get("include_claims") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("params.include_claims must be a JSON boolean".to_string()),
    };
    Ok((limit, offset, include_claims))
}

/// `get_light_snapshot` accepts absent / `null` / `{}` / `[]` (tip) or `{"height": N}` / `[N]`.
pub(super) fn extract_optional_height_param(params: Option<&Value>) -> Result<Option<u32>, String> {
    match params {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(o)) if o.is_empty() => Ok(None),
        Some(Value::Array(a)) if a.is_empty() => Ok(None),
        Some(v) => extract_height_param(Some(v)).map(Some),
    }
}

/// `get_mempool`, `clear_mempool`, `get_checkpoint`, `get_chain_params`, `save_checkpoint`, `list_methods`, etc. accept only absent / `null` / `{}` / `[]` `params`.
pub(super) fn reject_nonempty_empty_params(
    params: Option<&Value>,
    method: &str,
) -> Result<(), String> {
    match params {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Object(o)) if o.is_empty() => Ok(()),
        Some(Value::Array(a)) if a.is_empty() => Ok(()),
        Some(_) => Err(format!(
            "{method} does not accept non-empty params (omit `params` or use null, {{}}, or [])"
        )),
    }
}

pub(super) fn extract_checkpoint_hex_param(params: Option<&Value>) -> Result<String, String> {
    let v = params.ok_or_else(|| "missing params".to_string())?;
    match v {
        Value::Object(o) => o
            .get("checkpoint_hex")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "checkpoint_hex required".to_string()),
        Value::Array(a) if a.len() == 1 => a[0]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "checkpoint_hex must be a string".to_string()),
        _ => Err(
            "get_light_checkpoint_summary expects {\"checkpoint_hex\":\"…\"} or [\"…\"]"
                .to_string(),
        ),
    }
}
