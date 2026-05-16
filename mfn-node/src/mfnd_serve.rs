//! TCP control plane for `mfnd serve` (M2.1.6 + M2.1.6.1 + **M2.1.8** + **M2.1.10** + **M2.1.11** + **M2.1.12** + **M2.1.13** + **M2.1.14** + **M2.1.15** + **M2.1.16** + **M2.1.17** + **M2.1.18** + **M2.2.8** + **M2.2.10** + **M2.3.3** optional `--p2p-listen` + **M2.3.5** P2P ping/pong after hello + **M2.3.6** optional `--p2p-dial` + **M2.3.7** shared P2P socket I/O timeouts + **M2.3.8** [`ChainTipV1`] exchange on P2P streams + **M2.3.9** `mfnd_p2p_peer_tip` stdout + **M2.3.10** [`GoodbyeV1`] after tip on the full peer path + **M2.3.11** `mfnd_p2p_height_cmp` stdout + **M2.3.12** `mfnd_p2p_handshake_ms` stdout + **M2.3.13** `hid=` per successful P2P session on those stdout lines).
//!
//! One request per accepted connection: a single UTF-8 line of JSON, then
//! one JSON response line and the connection closes. Responses follow
//! [JSON-RPC 2.0](https://www.jsonrpc.org/specification): `jsonrpc`, `id`, and
//! either `result` or `error` (`code` + `message`). Requests may omit
//! `jsonrpc` (legacy tooling); when `jsonrpc` is present it must be `"2.0"`.
//! Omitted `id` is treated as `null` and echoed back (the TCP server always
//! emits one response line per connection, including for JSON-RPC
//! notifications).
//!
//! **`submit_tx` params** may be either a JSON object `{"tx_hex":"…"}` or a
//! one-element JSON array `["…"]` whose first entry is the same hex string
//! (JSON-RPC positional style).
//!
//! **`get_block`** (M2.1.10) returns canonical block bytes for heights `1..=tip_height`
//! from the on-disk `chain.blocks` log after [`crate::ChainStore::read_block_log_validated`];
//! params are `{"height": <n>}` or `[<n>]`.
//!
//! **`get_block_header`** (M2.1.11) returns the same height slice with
//! [`mfn_consensus::block_header_bytes`] as `header_hex` plus lowercase
//! [`mfn_consensus::block_id`] hex (no tx body).
//!
//! **`get_mempool`** (M2.1.12) returns `mempool_len` and every pending tx id
//! as lowercase hex in **`tx_ids`**, sorted lexicographically for a stable wire shape.
//!
//! **`get_mempool_tx`** (M2.1.13) returns `tx_id` + `tx_hex` (`encode_transaction`) for one
//! pending entry; `params` are `{"tx_id": "<64 hex>"}` or `["<64 hex>"]` (optional `0x` prefix).
//!
//! **`remove_mempool_tx`** (M2.1.14) drops a pending entry by id if present (`Mempool::evict`);
//! same `params` shapes as **`get_mempool_tx`**. Result is always success on valid params:
//! `removed` (whether an entry was evicted) and `pool_len`.
//!
//! **`clear_mempool`** (M2.1.15) empties the entire pool (`Mempool::clear`); `params` must be
//! omitted, `null`, `{}`, or `[]` (same rule as **`get_mempool`**). Success returns **`cleared_count`**
//! (how many txs were removed) and **`pool_len`** (always `0`).
//!
//! **`get_checkpoint`** (M2.1.16) returns canonical [`crate::Chain::encode_checkpoint`] bytes as
//! lowercase hex plus **`byte_len`**; same empty-only `params` rule as **`get_mempool`**. This is
//! the in-memory snapshot (what `mfnd save` would persist), not a separate disk read.
//!
//! **`save_checkpoint`** (M2.1.17) persists the live chain via [`crate::ChainStore::save`] (same
//! rotation semantics as `mfnd save`); same empty-only `params` as **`get_mempool`**. Success returns
//! **`bytes_written`**, **`checkpoint_path`**, and **`backup_path`** strings. IO failures map to **`-32004`**
//! (`CHECKPOINT_SAVE`).
//!
//! **`list_methods`** (M2.1.18) returns **`methods`**: every implemented JSON-RPC method name as a JSON
//! string, sorted lexicographically (includes **`list_methods`**); same empty-only `params` as **`get_mempool`**.
//!
//! **Authorship discovery (M2.2.8)** — read [`mfn_consensus::ChainState::claims`] / [`mfn_consensus::ChainState::storage`]:
//! **`get_claims_for`** (`params`: `{"data_root":"…"}` or `[hex]` — 64 hex digits, 32-byte root) returns **`claims`**
//! (array of records: `height`, `tx_id`, indices, `wire_version`, `data_root`, `claim_pubkey`, `message_hex`, `sig_hex`).
//! **`get_claims_by_pubkey`** (`params`: `{"claim_pubkey":"…","limit":N}` or `[hex]` / `[hex, N]`) scans the index and returns up to **`limit`**
//! matches (**`limit`** defaults to **50**, max **500**), newest by **`height`** first. **`list_recent_uploads`** (`params` object only: optional
//! **`limit`** default **20** max **200**, **`offset`** default **0**, **`include_claims`** boolean default **false**) pages **`ChainState.storage`**
//! by **`last_proven_height`** descending; when **`include_claims`** is true, each row may include a **`claims`** array for that row’s **`data_root`**.
//!
//! **Derived indexer views (M2.2.10)** — same object-only **`limit`** / **`offset`** bounds as **`list_recent_uploads`**:
//! **`list_recent_claims`** flattens every indexed claim, sorted newest-first by **`(height, tx_id, tx_index, claim_index)`**, then pages.
//! **`list_data_roots_with_claims`** lists each **`data_root`** that has at least one claim, sorted by **`max_claim_height`** descending (tie-break: lexicographic **`data_root`**), with **`claim_count`** and **`max_claim_height`** per row.

use std::cmp::Ordering;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use mfn_consensus::block::StorageEntry;
use mfn_consensus::{
    block_header_bytes, block_id, decode_transaction, encode_block, encode_transaction, tx_id,
    AuthorshipClaimRecord, Block,
};
use mfn_crypto::schnorr::encode_schnorr_signature;
use serde_json::{json, Map, Value};

use crate::{AdmitOutcome, Chain, ChainConfig, ChainStore, Mempool, MempoolConfig};

/// Shared `(tip_height, tip_id)` snapshot for P2P [`crate::network::ChainTipV1`] exchange (M2.3.8).
type P2pTipShared = Arc<Mutex<(u32, [u8; 32])>>;

/// Monotonic handshake id counter for P2P stdout correlation (**M2.3.13** `hid=`).
type P2pHidCounter = Arc<AtomicU64>;

const JSONRPC_VERSION: &str = "2.0";

mod rpc_codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
    /// Mempool [`crate::Mempool::admit`] rejected the decoded transaction.
    pub const MEMPOOL_REJECT: i64 = -32001;
    /// [`crate::ChainStore`] / `chain.blocks` read or validation failed.
    pub const BLOCK_LOG_STORE: i64 = -32002;
    /// No mempool entry for the requested [`TransactionWire`](mfn_consensus::TransactionWire) id.
    pub const MEMPOOL_TX_NOT_FOUND: i64 = -32003;
    /// [`crate::ChainStore::save`] failed (IO or other store error).
    pub const CHECKPOINT_SAVE: i64 = -32004;
}

fn hex32(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn admit_outcome_json(o: &AdmitOutcome) -> Value {
    match o {
        AdmitOutcome::Fresh { tx_id } => json!({"kind": "Fresh", "tx_id": hex32(tx_id)}),
        AdmitOutcome::ReplacedByFee { tx_id, displaced } => json!({
            "kind": "ReplacedByFee",
            "tx_id": hex32(tx_id),
            "displaced": displaced.iter().map(hex32).collect::<Vec<_>>(),
        }),
        AdmitOutcome::EvictedLowest { tx_id, evicted } => json!({
            "kind": "EvictedLowest",
            "tx_id": hex32(tx_id),
            "evicted": hex32(evicted),
        }),
    }
}

fn rpc_success(id: &Value, result: Value) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "result": result,
        "id": id,
    })
}

fn rpc_error(id: &Value, code: i64, message: impl AsRef<str>) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "error": {"code": code, "message": message.as_ref()},
        "id": id,
    })
}

fn request_id(req: &Value) -> Value {
    match req.get("id") {
        None => Value::Null,
        Some(v) => v.clone(),
    }
}

/// `submit_tx` accepts `params` as `{"tx_hex": "…"}` or `["…"]` (hex only).
fn extract_submit_tx_hex(params: Option<&Value>) -> Result<&str, String> {
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

fn parse_height_u32(n: u64) -> Result<u32, String> {
    u32::try_from(n).map_err(|_| format!("height {n} is out of u32 range"))
}

/// `get_block` / `get_block_header` accept `params` as `{"height": N}` or `[N]`
/// (block heights ≥ 1).
fn extract_height_param(params: Option<&Value>) -> Result<u32, String> {
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

/// `get_mempool_tx` reads a 32-byte transaction id from hex (same shapes as height params).
fn extract_tx_id_param(params: Option<&Value>) -> Result<&str, String> {
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

fn parse_tx_id_hex32(s: &str) -> Result<[u8; 32], String> {
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

const DEFAULT_CLAIMS_BY_PUBKEY_LIMIT: u64 = 50;
const MAX_CLAIMS_BY_PUBKEY_LIMIT: u64 = 500;
const DEFAULT_RECENT_UPLOADS_LIMIT: u64 = 20;
const MAX_RECENT_UPLOADS_LIMIT: u64 = 200;

fn extract_data_root_param(params: Option<&Value>) -> Result<&str, String> {
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

fn extract_claim_pubkey_and_limit(params: Option<&Value>) -> Result<([u8; 32], usize), String> {
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

/// Shared **`limit`** / **`offset`** parsing for paged discovery RPCs (`list_recent_uploads`, M2.2.10).
fn extract_list_limit_offset_from_object(
    obj: &Map<String, Value>,
) -> Result<(usize, usize), String> {
    let limit_u = match obj.get("limit") {
        None => DEFAULT_RECENT_UPLOADS_LIMIT,
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
    let limit_u = limit_u.clamp(1, MAX_RECENT_UPLOADS_LIMIT);
    let limit = usize::try_from(limit_u).map_err(|_| "limit out of usize range".to_string())?;
    let offset = usize::try_from(offset_u).map_err(|_| "offset out of usize range".to_string())?;
    Ok((limit, offset))
}

fn extract_list_limit_offset_params(params: Option<&Value>) -> Result<(usize, usize), String> {
    let p = match params {
        None | Some(Value::Null) => return Err("missing `params`".to_string()),
        Some(v) => v,
    };
    let Value::Object(obj) = p else {
        return Err("params must be a JSON object".to_string());
    };
    extract_list_limit_offset_from_object(obj)
}

fn extract_list_recent_uploads_params(
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

fn authorship_claim_record_json(rec: &AuthorshipClaimRecord) -> Value {
    let c = &rec.claim;
    json!({
        "height": rec.height,
        "tx_id": hex32(&rec.tx_id),
        "tx_index": rec.tx_index,
        "claim_index": rec.claim_index,
        "wire_version": c.wire_version,
        "data_root": hex32(&c.data_root),
        "claim_pubkey": hex32(c.claim_pubkey.compress().as_bytes()),
        "message_hex": hex::encode(&c.message),
        "sig_hex": hex::encode(encode_schnorr_signature(&c.sig)),
    })
}

fn json_storage_upload_row(
    commitment_hash: &[u8; 32],
    entry: &StorageEntry,
    chain: &Chain,
    include_claims: bool,
) -> Value {
    let c = &entry.commit;
    let mut m = Map::new();
    m.insert("commitment_hash".into(), json!(hex32(commitment_hash)));
    m.insert("data_root".into(), json!(hex32(&c.data_root)));
    m.insert("size_bytes".into(), json!(c.size_bytes));
    m.insert("chunk_size".into(), json!(c.chunk_size));
    m.insert("num_chunks".into(), json!(c.num_chunks));
    m.insert("replication".into(), json!(c.replication));
    m.insert(
        "endowment_hex".into(),
        json!(hex32(c.endowment.compress().as_bytes())),
    );
    m.insert("last_proven_height".into(), json!(entry.last_proven_height));
    m.insert("last_proven_slot".into(), json!(entry.last_proven_slot));
    if include_claims {
        let claims_json: Vec<Value> = chain
            .state()
            .claims
            .get(&c.data_root)
            .map(|v| v.iter().map(authorship_claim_record_json).collect())
            .unwrap_or_default();
        m.insert("claims".into(), Value::Array(claims_json));
    }
    Value::Object(m)
}

fn collect_claims_for_pubkey<'a>(
    chain: &'a Chain,
    pk: &[u8; 32],
    limit: usize,
) -> Vec<&'a AuthorshipClaimRecord> {
    let mut out: Vec<&AuthorshipClaimRecord> = Vec::new();
    for v in chain.state().claims.values() {
        for rec in v {
            if rec.claim.claim_pubkey.compress().as_bytes().as_slice() == pk.as_slice() {
                out.push(rec);
            }
        }
    }
    out.sort_by(|a, b| {
        b.height
            .cmp(&a.height)
            .then_with(|| a.tx_id.cmp(&b.tx_id))
            .then_with(|| a.tx_index.cmp(&b.tx_index))
            .then_with(|| a.claim_index.cmp(&b.claim_index))
    });
    out.truncate(limit);
    out
}

fn collect_all_claims_sorted_recent_first(chain: &Chain) -> Vec<&AuthorshipClaimRecord> {
    let mut out: Vec<&AuthorshipClaimRecord> = Vec::new();
    for v in chain.state().claims.values() {
        for rec in v {
            out.push(rec);
        }
    }
    out.sort_by(|a, b| {
        b.height
            .cmp(&a.height)
            .then_with(|| a.tx_id.cmp(&b.tx_id))
            .then_with(|| a.tx_index.cmp(&b.tx_index))
            .then_with(|| a.claim_index.cmp(&b.claim_index))
    });
    out
}

fn collect_data_roots_with_claims_sorted(chain: &Chain) -> Vec<([u8; 32], u32, usize)> {
    let mut rows: Vec<([u8; 32], u32, usize)> = Vec::new();
    for (root, v) in chain.state().claims.iter() {
        if v.is_empty() {
            continue;
        }
        let max_h = v
            .iter()
            .map(|r| r.height)
            .max()
            .expect("non-empty claim vec");
        rows.push((*root, max_h, v.len()));
    }
    rows.sort_by(|(ra, ha, _), (rb, hb, _)| {
        hb.cmp(ha).then_with(|| ra.as_slice().cmp(rb.as_slice()))
    });
    rows
}

/// `get_mempool`, `clear_mempool`, `get_checkpoint`, `save_checkpoint`, `list_methods`, etc. accept only absent / `null` / `{}` / `[]` `params`.
fn reject_nonempty_empty_params(params: Option<&Value>, method: &str) -> Result<(), String> {
    match params {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Object(o)) if o.is_empty() => Ok(()),
        Some(Value::Array(a)) if a.is_empty() => Ok(()),
        Some(_) => Err(format!(
            "{method} does not accept non-empty params (omit `params` or use null, {{}}, or [])"
        )),
    }
}

/// Method names implemented by [`dispatch_serve_methods`], sorted for a stable wire shape.
///
/// **Keep in sync** when adding a new `match` arm (include the new name here).
fn serve_rpc_methods_json_result() -> Value {
    let mut methods: Vec<&'static str> = vec![
        "clear_mempool",
        "get_block",
        "get_block_header",
        "get_claims_by_pubkey",
        "get_claims_for",
        "get_checkpoint",
        "get_mempool",
        "get_mempool_tx",
        "get_tip",
        "list_data_roots_with_claims",
        "list_methods",
        "list_recent_claims",
        "list_recent_uploads",
        "remove_mempool_tx",
        "save_checkpoint",
        "submit_tx",
    ];
    methods.sort_unstable();
    json!({ "methods": methods })
}

/// Load `chain.blocks` validated against `chain` after height / tip checks.
/// `height` must be parsed from params (caller maps `extract_height_param` errors).
fn read_validated_blocks_for_height(
    store: &ChainStore,
    chain: &Chain,
    height: u32,
    id: &Value,
) -> Result<Vec<Block>, Value> {
    if height == 0 {
        return Err(rpc_error(
            id,
            rpc_codes::INVALID_PARAMS,
            "height must be at least 1 (genesis is not stored in chain.blocks)",
        ));
    }
    let tip_h = match chain.tip_height() {
        Some(h) => h,
        None => {
            return Err(rpc_error(
                id,
                rpc_codes::BLOCK_LOG_STORE,
                "chain tip_height is None (unexpected)",
            ));
        }
    };
    if height > tip_h {
        return Err(rpc_error(
            id,
            rpc_codes::INVALID_PARAMS,
            format!("height {height} exceeds chain tip_height {tip_h}"),
        ));
    }
    match store.read_block_log_validated(chain) {
        Ok(b) => Ok(b),
        Err(e) => Err(rpc_error(
            id,
            rpc_codes::BLOCK_LOG_STORE,
            format!("read_block_log_validated: {e}"),
        )),
    }
}

/// Parse one request line and return a single JSON-RPC 2.0 response value.
pub(crate) fn parse_and_dispatch_serve(
    store: &ChainStore,
    chain: &mut Chain,
    pool: &mut Mempool,
    line: &str,
) -> Value {
    let line = line.trim();
    if line.is_empty() {
        return rpc_error(
            &Value::Null,
            rpc_codes::INVALID_REQUEST,
            "empty request line",
        );
    }
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return rpc_error(
                &Value::Null,
                rpc_codes::PARSE_ERROR,
                format!("Parse error: {e}"),
            );
        }
    };
    let id = request_id(&req);
    if let Some(v) = req.get("jsonrpc") {
        if v.as_str() != Some(JSONRPC_VERSION) {
            return rpc_error(
                &id,
                rpc_codes::INVALID_REQUEST,
                r#"when present, jsonrpc must be "2.0""#,
            );
        }
    }
    dispatch_serve_methods(store, chain, pool, &req, &id)
}

fn dispatch_serve_methods(
    store: &ChainStore,
    chain: &mut Chain,
    pool: &mut Mempool,
    req: &Value,
    id: &Value,
) -> Value {
    let method = match req.get("method") {
        Some(Value::String(s)) => s.as_str(),
        Some(_) => {
            return rpc_error(
                id,
                rpc_codes::INVALID_REQUEST,
                "method must be a JSON string",
            );
        }
        None => return rpc_error(id, rpc_codes::INVALID_REQUEST, "missing field `method`"),
    };

    match method {
        "get_tip" => {
            let tip_h = chain.tip_height().map(|h| json!(h)).unwrap_or(Value::Null);
            let tip_id = chain.tip_id().map(hex32).unwrap_or_else(|| "none".into());
            let genesis_id = hex32(chain.genesis_id());
            let body = json!({
                "tip_height": tip_h,
                "tip_id": tip_id,
                "genesis_id": genesis_id,
                "validator_count": chain.validators().len(),
                "mempool_len": pool.len(),
            });
            rpc_success(id, body)
        }
        "list_methods" => {
            if let Err(msg) = reject_nonempty_empty_params(req.get("params"), "list_methods") {
                return rpc_error(id, rpc_codes::INVALID_PARAMS, msg);
            }
            rpc_success(id, serve_rpc_methods_json_result())
        }
        "get_checkpoint" => {
            if let Err(msg) = reject_nonempty_empty_params(req.get("params"), "get_checkpoint") {
                return rpc_error(id, rpc_codes::INVALID_PARAMS, msg);
            }
            let bytes = chain.encode_checkpoint();
            rpc_success(
                id,
                json!({
                    "checkpoint_hex": hex::encode(&bytes),
                    "byte_len": bytes.len(),
                }),
            )
        }
        "save_checkpoint" => {
            if let Err(msg) = reject_nonempty_empty_params(req.get("params"), "save_checkpoint") {
                return rpc_error(id, rpc_codes::INVALID_PARAMS, msg);
            }
            match store.save(chain) {
                Ok(meta) => rpc_success(
                    id,
                    json!({
                        "bytes_written": meta.bytes_written,
                        "checkpoint_path": meta.checkpoint_path.display().to_string(),
                        "backup_path": meta.backup_path.display().to_string(),
                    }),
                ),
                Err(e) => rpc_error(
                    id,
                    rpc_codes::CHECKPOINT_SAVE,
                    format!("checkpoint save: {e}"),
                ),
            }
        }
        "get_mempool" => {
            if let Err(msg) = reject_nonempty_empty_params(req.get("params"), "get_mempool") {
                return rpc_error(id, rpc_codes::INVALID_PARAMS, msg);
            }
            let mut ids: Vec<String> = pool.iter().map(|e| hex32(&e.tx_id)).collect();
            ids.sort_unstable();
            let body = json!({
                "mempool_len": pool.len(),
                "tx_ids": ids,
            });
            rpc_success(id, body)
        }
        "clear_mempool" => {
            if let Err(msg) = reject_nonempty_empty_params(req.get("params"), "clear_mempool") {
                return rpc_error(id, rpc_codes::INVALID_PARAMS, msg);
            }
            let cleared_count = pool.len();
            pool.clear();
            rpc_success(
                id,
                json!({
                    "cleared_count": cleared_count,
                    "pool_len": pool.len(),
                }),
            )
        }
        "get_mempool_tx" => {
            let hex_s = match extract_tx_id_param(req.get("params")) {
                Ok(s) => s,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let tid = match parse_tx_id_hex32(hex_s) {
                Ok(id) => id,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            match pool.get(&tid) {
                None => rpc_error(
                    id,
                    rpc_codes::MEMPOOL_TX_NOT_FOUND,
                    "mempool has no transaction with that tx_id",
                ),
                Some(ent) => {
                    let wire = encode_transaction(&ent.tx);
                    let body = json!({
                        "tx_id": hex32(&tid),
                        "tx_hex": hex::encode(wire),
                    });
                    rpc_success(id, body)
                }
            }
        }
        "remove_mempool_tx" => {
            let hex_s = match extract_tx_id_param(req.get("params")) {
                Ok(s) => s,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let tid = match parse_tx_id_hex32(hex_s) {
                Ok(b) => b,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let removed = pool.evict(&tid);
            rpc_success(
                id,
                json!({
                    "removed": removed,
                    "pool_len": pool.len(),
                }),
            )
        }
        "submit_tx" => {
            let hex_s = match extract_submit_tx_hex(req.get("params")) {
                Ok(s) => s,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let hex_s = hex_s.trim();
            let hex_s = hex_s
                .strip_prefix("0x")
                .or_else(|| hex_s.strip_prefix("0X"))
                .unwrap_or(hex_s);
            let bytes = match hex::decode(hex_s) {
                Ok(b) => b,
                Err(e) => {
                    return rpc_error(id, rpc_codes::INVALID_PARAMS, format!("hex decode: {e}"));
                }
            };
            let tx = match decode_transaction(&bytes) {
                Ok(t) => t,
                Err(e) => {
                    return rpc_error(
                        id,
                        rpc_codes::INVALID_PARAMS,
                        format!("decode_transaction: {e}"),
                    );
                }
            };
            let tid = tx_id(&tx);
            match pool.admit(tx, chain.state()) {
                Ok(outcome) => {
                    let body = json!({
                        "tx_id": hex32(&tid),
                        "pool_len": pool.len(),
                        "outcome": admit_outcome_json(&outcome),
                    });
                    rpc_success(id, body)
                }
                Err(e) => rpc_error(id, rpc_codes::MEMPOOL_REJECT, format!("mempool admit: {e}")),
            }
        }
        "get_block" => {
            let height = match extract_height_param(req.get("params")) {
                Ok(h) => h,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let blocks = match read_validated_blocks_for_height(store, chain, height, id) {
                Ok(b) => b,
                Err(resp) => return resp,
            };
            let idx = (height - 1) as usize;
            let block = &blocks[idx];
            let bytes = encode_block(block);
            let body = json!({
                "height": height,
                "block_hex": hex::encode(&bytes),
            });
            rpc_success(id, body)
        }
        "get_block_header" => {
            let height = match extract_height_param(req.get("params")) {
                Ok(h) => h,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let blocks = match read_validated_blocks_for_height(store, chain, height, id) {
                Ok(b) => b,
                Err(resp) => return resp,
            };
            let idx = (height - 1) as usize;
            let block = &blocks[idx];
            let hbytes = block_header_bytes(&block.header);
            let bid = block_id(&block.header);
            let body = json!({
                "height": height,
                "block_id": hex32(&bid),
                "header_hex": hex::encode(hbytes),
            });
            rpc_success(id, body)
        }
        "get_claims_for" => {
            let hex_s = match extract_data_root_param(req.get("params")) {
                Ok(s) => s,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let root = match parse_tx_id_hex32(hex_s) {
                Ok(r) => r,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let claims: Vec<Value> = chain
                .state()
                .claims
                .get(&root)
                .map(|v| {
                    let mut rows: Vec<_> = v.iter().collect();
                    rows.sort_by(|a, b| {
                        a.height
                            .cmp(&b.height)
                            .then_with(|| a.tx_id.cmp(&b.tx_id))
                            .then_with(|| a.tx_index.cmp(&b.tx_index))
                            .then_with(|| a.claim_index.cmp(&b.claim_index))
                    });
                    rows.into_iter().map(authorship_claim_record_json).collect()
                })
                .unwrap_or_default();
            rpc_success(
                id,
                json!({
                    "data_root": hex32(&root),
                    "claims": claims,
                }),
            )
        }
        "get_claims_by_pubkey" => {
            let (pk, limit) = match extract_claim_pubkey_and_limit(req.get("params")) {
                Ok(x) => x,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let rows = collect_claims_for_pubkey(chain, &pk, limit);
            let claims: Vec<Value> = rows.into_iter().map(authorship_claim_record_json).collect();
            rpc_success(
                id,
                json!({
                    "claim_pubkey": hex32(&pk),
                    "limit": limit,
                    "claims": claims,
                }),
            )
        }
        "list_data_roots_with_claims" => {
            let (limit, offset) = match extract_list_limit_offset_params(req.get("params")) {
                Ok(x) => x,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let rows = collect_data_roots_with_claims_sorted(chain);
            let total = rows.len();
            let roots: Vec<Value> = rows
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|(root, max_h, n)| {
                    json!({
                        "data_root": hex32(&root),
                        "claim_count": n,
                        "max_claim_height": max_h,
                    })
                })
                .collect();
            rpc_success(
                id,
                json!({
                    "roots": roots,
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                }),
            )
        }
        "list_recent_claims" => {
            let (limit, offset) = match extract_list_limit_offset_params(req.get("params")) {
                Ok(x) => x,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let flat = collect_all_claims_sorted_recent_first(chain);
            let total = flat.len();
            let claims: Vec<Value> = flat
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(authorship_claim_record_json)
                .collect();
            rpc_success(
                id,
                json!({
                    "claims": claims,
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                }),
            )
        }
        "list_recent_uploads" => {
            let (limit, offset, include_claims) =
                match extract_list_recent_uploads_params(req.get("params")) {
                    Ok(x) => x,
                    Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
                };
            let st = chain.state();
            let total = st.storage.len();
            let mut rows: Vec<(&[u8; 32], &StorageEntry)> = st.storage.iter().collect();
            rows.sort_by(|(ha, ea), (hb, eb)| {
                eb.last_proven_height
                    .cmp(&ea.last_proven_height)
                    .then_with(|| ha.cmp(hb))
            });
            let uploads: Vec<Value> = rows
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|(h, e)| json_storage_upload_row(h, e, chain, include_claims))
                .collect();
            rpc_success(
                id,
                json!({
                    "uploads": uploads,
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                    "include_claims": include_claims,
                }),
            )
        }
        other => rpc_error(
            id,
            rpc_codes::METHOD_NOT_FOUND,
            format!("unknown method `{other}`"),
        ),
    }
}

fn write_line(stream: &mut TcpStream, v: &Value) -> Result<(), String> {
    let s = v.to_string();
    writeln!(stream, "{s}").map_err(|e| format!("mfnd serve: write response: {e}"))
}

fn handle_client(
    stream: &mut TcpStream,
    store: &ChainStore,
    chain: &mut Chain,
    pool: &mut Mempool,
) -> Result<(), String> {
    let peer = stream
        .peer_addr()
        .map_err(|e| format!("mfnd serve: peer_addr: {e}"))?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| format!("{e}"))?);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("mfnd serve: read request from {peer}: {e}"))?;
    let resp = parse_and_dispatch_serve(store, chain, pool, &line);
    write_line(stream, &resp)
}

fn snapshot_chain_tip_for_p2p(chain: &Chain) -> (u32, [u8; 32]) {
    let height = chain.tip_height().unwrap_or(0);
    let tip_id = chain
        .tip_id()
        .copied()
        .unwrap_or_else(|| *chain.genesis_id());
    (height, tip_id)
}

fn p2p_log_peer_tip(hid: u64, peer: &str, remote: &crate::network::ChainTipV1) {
    println!(
        "mfnd_p2p_peer_tip hid={hid} peer={peer} height={} tip_id={}",
        remote.height,
        hex32(&remote.tip_id)
    );
    let _ = std::io::stdout().flush();
}

fn p2p_height_cmp_label(local_height: u32, remote_height: u32) -> &'static str {
    match remote_height.cmp(&local_height) {
        Ordering::Less => "behind",
        Ordering::Equal => "equal",
        Ordering::Greater => "ahead",
    }
}

fn p2p_log_height_cmp(
    hid: u64,
    peer: &str,
    local_height: u32,
    remote: &crate::network::ChainTipV1,
) {
    let cmp = p2p_height_cmp_label(local_height, remote.height);
    println!(
        "mfnd_p2p_height_cmp hid={hid} peer={peer} local_height={local_height} remote_height={} cmp={cmp}",
        remote.height
    );
    let _ = std::io::stdout().flush();
}

fn p2p_log_handshake_ms(hid: u64, peer: &str, elapsed: std::time::Duration) {
    println!(
        "mfnd_p2p_handshake_ms hid={hid} peer={peer} ms={}",
        elapsed.as_millis()
    );
    let _ = std::io::stdout().flush();
}

fn spawn_p2p_handshake_loop(
    listener: TcpListener,
    genesis_id: [u8; 32],
    tip_cell: P2pTipShared,
    hid_counter: P2pHidCounter,
) -> Result<(), String> {
    thread::Builder::new()
        .name("mfnd-p2p".into())
        .spawn(move || loop {
            let (mut sock, peer) = match listener.accept() {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("mfnd p2p: accept: {e}");
                    continue;
                }
            };
            let t0 = Instant::now();
            let _ =
                sock.set_read_timeout(Some(crate::network::handshake::P2P_HANDSHAKE_IO_TIMEOUT));
            let _ =
                sock.set_write_timeout(Some(crate::network::handshake::P2P_HANDSHAKE_IO_TIMEOUT));
            if let Err(e) = crate::network::hello_v1_handshake(&mut sock, &genesis_id) {
                eprintln!("mfnd p2p: handshake from {peer}: {e}");
                continue;
            }
            if let Err(e) = crate::network::recv_ping_send_pong(&mut sock) {
                eprintln!("mfnd p2p: ping/pong from {peer}: {e}");
                continue;
            }
            let local = {
                let g = tip_cell.lock().unwrap_or_else(|e| e.into_inner());
                crate::network::ChainTipV1 {
                    height: g.0,
                    tip_id: g.1,
                }
            };
            match crate::network::exchange_chain_tip_v1_as_listener(&mut sock, &local) {
                Ok(remote) => match crate::network::exchange_goodbye_v1_as_listener(&mut sock) {
                    Ok(()) => {
                        let hid = hid_counter.fetch_add(1, AtomicOrdering::Relaxed);
                        p2p_log_peer_tip(hid, &peer.to_string(), &remote);
                        p2p_log_height_cmp(hid, &peer.to_string(), local.height, &remote);
                        p2p_log_handshake_ms(hid, &peer.to_string(), t0.elapsed());
                    }
                    Err(e) => eprintln!("mfnd p2p: goodbye from {peer}: {e}"),
                },
                Err(e) => eprintln!("mfnd p2p: chain tip exchange from {peer}: {e}"),
            }
        })
        .map_err(|e| format!("mfnd serve: spawn p2p thread: {e}"))?;
    Ok(())
}

fn spawn_p2p_outbound_dial(
    addr: String,
    genesis_id: [u8; 32],
    tip_cell: P2pTipShared,
    hid_counter: P2pHidCounter,
) -> Result<(), String> {
    thread::Builder::new()
        .name("mfnd-p2p-dial".into())
        .spawn(move || {
            let local = {
                let g = tip_cell.lock().unwrap_or_else(|e| e.into_inner());
                crate::network::ChainTipV1 {
                    height: g.0,
                    tip_id: g.1,
                }
            };
            let t0 = Instant::now();
            match crate::network::tcp_connect_peer_v1_handshake_with_tip_exchange(
                addr.as_str(),
                &genesis_id,
                &local,
            ) {
                Ok((_sock, remote)) => {
                    let hid = hid_counter.fetch_add(1, AtomicOrdering::Relaxed);
                    println!("mfnd_p2p_dial_ok={addr}");
                    let _ = std::io::stdout().flush();
                    p2p_log_peer_tip(hid, addr.as_str(), &remote);
                    p2p_log_height_cmp(hid, addr.as_str(), local.height, &remote);
                    p2p_log_handshake_ms(hid, addr.as_str(), t0.elapsed());
                }
                Err(e) => eprintln!("mfnd p2p dial `{addr}`: {e}"),
            }
        })
        .map_err(|e| format!("mfnd serve: spawn p2p dial thread: {e}"))?;
    Ok(())
}

/// Run a blocking TCP loop: load chain + empty mempool, print bound address, then
/// serve one JSON line per connection until the process exits.
///
/// When `p2p_listen` is `Some`, binds a second listener, prints `mfnd_p2p_listening=…`, and
/// spawns a background thread that accepts peers, runs [`crate::network::hello_v1_handshake`]
/// then [`crate::network::recv_ping_send_pong`] then [`crate::network::exchange_chain_tip_v1_as_listener`]
/// then [`crate::network::exchange_goodbye_v1_as_listener`]
/// (same genesis id as the loaded chain; tip snapshot from the live chain after each successful RPC),
/// then prints **`mfnd_p2p_peer_tip`** (with monotonic per-process **`hid=`**), remote height + tip id, then **`mfnd_p2p_height_cmp`** / **`mfnd_p2p_handshake_ms`** with the same **`hid`**, then closes each connection.
///
/// When `p2p_dial` is `Some`, spawns a background thread that runs [`crate::network::tcp_connect_peer_v1_handshake_with_tip_exchange`]
/// against that address and prints `mfnd_p2p_dial_ok=…` then **`mfnd_p2p_peer_tip`** / **`mfnd_p2p_height_cmp`** / **`mfnd_p2p_handshake_ms`** sharing one **`hid`** on success (stderr on failure).
pub(crate) fn run_serve(
    store: &ChainStore,
    cfg: ChainConfig,
    rpc_listen: &str,
    p2p_listen: Option<&str>,
    p2p_dial: Option<&str>,
) -> Result<(), String> {
    let mut chain = store.load_or_genesis(cfg).map_err(|e| format!("{e}"))?;
    let mut pool = Mempool::new(MempoolConfig::default());
    let genesis_id = *chain.genesis_id();

    let (p2p_tip_cell, p2p_hid_counter): (Option<P2pTipShared>, Option<P2pHidCounter>) =
        if p2p_listen.is_some() || p2p_dial.is_some() {
            (
                Some(Arc::new(Mutex::new(snapshot_chain_tip_for_p2p(&chain)))),
                Some(Arc::new(AtomicU64::new(0))),
            )
        } else {
            (None, None)
        };

    let p2p_listener = if let Some(addr) = p2p_listen {
        Some(TcpListener::bind(addr).map_err(|e| format!("mfnd serve: bind P2P `{addr}`: {e}"))?)
    } else {
        None
    };

    let listener = TcpListener::bind(rpc_listen)
        .map_err(|e| format!("mfnd serve: bind `{rpc_listen}`: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("mfnd serve: local_addr: {e}"))?;
    println!("mfnd_serve_listening={addr}");
    std::io::stdout()
        .flush()
        .map_err(|e| format!("mfnd serve: stdout flush: {e}"))?;

    if let Some(pl) = p2p_listener {
        let p2p_addr = pl
            .local_addr()
            .map_err(|e| format!("mfnd serve: p2p local_addr: {e}"))?;
        println!("mfnd_p2p_listening={p2p_addr}");
        std::io::stdout()
            .flush()
            .map_err(|e| format!("mfnd serve: stdout flush (p2p): {e}"))?;
        spawn_p2p_handshake_loop(
            pl,
            genesis_id,
            p2p_tip_cell
                .as_ref()
                .expect("p2p tip cell when p2p listen")
                .clone(),
            p2p_hid_counter
                .as_ref()
                .expect("p2p hid counter when p2p listen")
                .clone(),
        )?;
    }

    if let Some(dial) = p2p_dial {
        spawn_p2p_outbound_dial(
            dial.to_string(),
            genesis_id,
            p2p_tip_cell
                .as_ref()
                .expect("p2p tip cell when p2p dial")
                .clone(),
            p2p_hid_counter
                .as_ref()
                .expect("p2p hid counter when p2p dial")
                .clone(),
        )?;
    }

    #[cfg(unix)]
    {
        let _ = ctrlc::set_handler(|| std::process::exit(0));
    }

    loop {
        let (mut stream, _) = match listener.accept() {
            Ok(x) => x,
            Err(e) => {
                eprintln!("mfnd serve: accept: {e}");
                continue;
            }
        };
        match handle_client(&mut stream, store, &mut chain, &mut pool) {
            Ok(()) => {
                if let Some(tc) = &p2p_tip_cell {
                    if let Ok(mut g) = tc.lock() {
                        *g = snapshot_chain_tip_for_p2p(&chain);
                    }
                }
            }
            Err(e) => {
                let fallback = rpc_error(
                    &Value::Null,
                    rpc_codes::INTERNAL_ERROR,
                    format!("mfnd serve: {e}"),
                );
                let _ = write_line(&mut stream, &fallback);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use mfn_bls::bls_keygen_from_seed;
    use mfn_consensus::{
        block_header_bytes, build_coinbase, decode_block, decode_block_header, emission_at_height,
        ConsensusParams, GenesisConfig, PayoutAddress, Validator, ValidatorPayout,
        ValidatorSecrets, DEFAULT_EMISSION_PARAMS,
    };
    use mfn_crypto::stealth::stealth_gen;
    use mfn_crypto::vrf::vrf_keygen_from_seed;
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    use crate::{demo_genesis, produce_solo_block, BlockInputs, Chain, ChainConfig};

    fn mk_validator(i: u32, stake: u64) -> (Validator, ValidatorSecrets) {
        let vrf = vrf_keygen_from_seed(&[i as u8 + 1; 32]).unwrap();
        let bls = bls_keygen_from_seed(&[i as u8 + 101; 32]);
        let payout_wallet = stealth_gen();
        let payout = ValidatorPayout {
            view_pub: payout_wallet.view_pub,
            spend_pub: payout_wallet.spend_pub,
        };
        let val = Validator {
            index: i,
            vrf_pk: vrf.pk,
            bls_pk: bls.pk,
            stake,
            payout: Some(payout),
        };
        let secrets = ValidatorSecrets {
            index: i,
            vrf,
            bls: bls.clone(),
        };
        (val, secrets)
    }

    fn solo_chain_fixture() -> (
        Chain,
        Validator,
        ValidatorSecrets,
        ConsensusParams,
        ChainConfig,
    ) {
        let (v0, s0) = mk_validator(0, 1_000_000);
        let params = ConsensusParams {
            expected_proposers_per_slot: 10.0,
            quorum_stake_bps: 6666,
            liveness_max_consecutive_missed: 64,
            liveness_slash_bps: 0,
        };
        let gc = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: vec![v0.clone()],
            params,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let cfg = ChainConfig::new(gc);
        let chain = Chain::from_genesis(cfg.clone()).expect("genesis");
        (chain, v0, s0, params, cfg)
    }

    fn coinbase_inputs(producer: &Validator, height: u32) -> BlockInputs {
        let p = producer.payout.unwrap();
        let cb_payout = PayoutAddress {
            view_pub: p.view_pub,
            spend_pub: p.spend_pub,
        };
        let emission = emission_at_height(u64::from(height), &DEFAULT_EMISSION_PARAMS);
        let cb = build_coinbase(u64::from(height), emission, &cb_payout).expect("cb");
        BlockInputs {
            height,
            slot: height,
            timestamp: u64::from(height) * 100,
            txs: vec![cb],
            bond_ops: Vec::new(),
            slashings: Vec::new(),
            storage_proofs: Vec::new(),
        }
    }

    fn test_store_chain_pool(test_name: &str) -> (ChainStore, Chain, Mempool, PathBuf) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mfn-serve-test-{test_name}-{}-{nanos}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let store = ChainStore::new(&root);
        let cfg = ChainConfig::new(demo_genesis::empty_local_dev_genesis());
        let chain = store.load_or_genesis(cfg).expect("load_or_genesis");
        let pool = Mempool::new(MempoolConfig::default());
        (store, chain, pool, root)
    }

    #[test]
    fn p2p_height_cmp_label_orders_remote_vs_local() {
        assert_eq!(p2p_height_cmp_label(0, 0), "equal");
        assert_eq!(p2p_height_cmp_label(0, 1), "ahead");
        assert_eq!(p2p_height_cmp_label(2, 1), "behind");
    }

    #[test]
    fn rpc_empty_line_is_invalid_request() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_empty_line");
        let v = parse_and_dispatch_serve(&store, &mut c, &mut p, "   \n");
        assert_eq!(v["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_REQUEST);
        assert!(v["result"].is_null());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_invalid_json_is_parse_error_with_null_id() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_invalid_json");
        let v = parse_and_dispatch_serve(&store, &mut c, &mut p, "{not json");
        assert_eq!(v["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(v["error"]["code"], rpc_codes::PARSE_ERROR);
        assert_eq!(v["id"], Value::Null);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_rejects_wrong_jsonrpc_version() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_wrong_jsonrpc");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"1.0","method":"get_tip","id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_REQUEST);
        assert_eq!(v["id"], json!(1));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_unknown_method() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_unknown_method");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"nope","id":"abc"}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::METHOD_NOT_FOUND);
        assert_eq!(v["id"], json!("abc"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_tip_legacy_no_jsonrpc_echoes_null_id() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_get_tip_legacy");
        let v = parse_and_dispatch_serve(&store, &mut c, &mut p, r#"{"method":"get_tip"}"#);
        assert_eq!(v["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(v["id"], Value::Null);
        assert_eq!(v["error"], Value::Null);
        let tip = &v["result"]["tip_height"];
        assert!(tip.is_number() || tip.is_null());
        assert!(v["result"]["genesis_id"].as_str().unwrap().len() == 64);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_tip_echoes_numeric_id() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_get_tip_id");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_tip","id":42}"#,
        );
        assert_eq!(v["id"], json!(42));
        assert!(v["result"]["mempool_len"].as_u64() == Some(0));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_submit_tx_missing_tx_hex() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_submit_missing_hex");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"submit_tx","params":{},"id":0}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"].as_str().unwrap().contains("tx_hex"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_submit_tx_array_params_truncated_wire() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_submit_trunc");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"submit_tx","params":["00"],"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        let m = v["error"]["message"].as_str().unwrap();
        assert!(
            m.contains("decode_transaction") || m.contains("decode"),
            "m={m}"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_submit_tx_array_params_empty_array() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_submit_empty_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"submit_tx","params":[],"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"].as_str().unwrap().contains("array"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_submit_tx_array_params_first_not_string() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_submit_arr_not_str");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"submit_tx","params":[1],"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("params[0]"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_submit_tx_params_must_be_object_or_array() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_submit_params_type");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"submit_tx","params":"00","id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("object or a JSON array"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_submit_tx_missing_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_submit_no_params");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"submit_tx","id":0}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"].as_str().unwrap().contains("params"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_method_must_be_string() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_method_not_str");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":7,"id":null}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_REQUEST);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_block_height_zero_is_invalid_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gb_h0");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_block","params":{"height":0},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("at least 1"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_block_height_exceeds_tip_at_genesis() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gb_exceeds");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_block","params":{"height":1},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        let m = v["error"]["message"].as_str().unwrap();
        assert!(m.contains("exceeds"), "m={m}");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_block_array_positional_height() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gb_array");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_block","params":[1],"id":9}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_block_missing_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gb_no_params");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_block","id":0}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_block_read_validated_failure_maps_to_block_log_store() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mfn-serve-test-rpc_gb_bad_log-{}-{nanos}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let store = ChainStore::new(&root);

        let (mut chain, producer, secrets, params, cfg) = solo_chain_fixture();
        let inputs = coinbase_inputs(&producer, 1);
        let block = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("solo");
        chain.apply(&block).expect("apply");
        assert_eq!(chain.tip_height(), Some(1));
        store
            .save(&chain)
            .expect("checkpoint tip 1 without block log sidecar");

        let mut chain_loaded = store.load_or_genesis(cfg).expect("reload");
        let mut pool = Mempool::new(MempoolConfig::default());
        let v = parse_and_dispatch_serve(
            &store,
            &mut chain_loaded,
            &mut pool,
            r#"{"jsonrpc":"2.0","method":"get_block","params":{"height":1},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::BLOCK_LOG_STORE);
        let v2 = parse_and_dispatch_serve(
            &store,
            &mut chain_loaded,
            &mut pool,
            r#"{"jsonrpc":"2.0","method":"get_block_header","params":{"height":1},"id":2}"#,
        );
        assert_eq!(v2["error"]["code"], rpc_codes::BLOCK_LOG_STORE);
        let m = v["error"]["message"].as_str().unwrap();
        assert!(
            m.contains("read_block_log_validated") || m.contains("block log"),
            "m={m}"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_block_header_height_zero_is_invalid_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gbh_h0");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_block_header","params":{"height":0},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("at least 1"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_block_header_missing_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gbh_no_params");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_block_header","id":0}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_block_header_matches_full_block_at_height_1() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mfn-serve-test-rpc_gbh_ok-{}-{nanos}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let store = ChainStore::new(&root);

        let (mut chain, producer, secrets, params, cfg) = solo_chain_fixture();
        let inputs = coinbase_inputs(&producer, 1);
        let block = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("solo");
        chain.apply(&block).expect("apply");
        store.append_block(&block).expect("append_block");
        store.save(&chain).expect("save");

        let mut chain_loaded = store.load_or_genesis(cfg).expect("reload");
        let mut pool = Mempool::new(MempoolConfig::default());
        let vh = parse_and_dispatch_serve(
            &store,
            &mut chain_loaded,
            &mut pool,
            r#"{"jsonrpc":"2.0","method":"get_block_header","params":{"height":1},"id":1}"#,
        );
        assert_eq!(vh["error"], Value::Null);
        let vb = parse_and_dispatch_serve(
            &store,
            &mut chain_loaded,
            &mut pool,
            r#"{"jsonrpc":"2.0","method":"get_block","params":{"height":1},"id":2}"#,
        );
        assert_eq!(vb["error"], Value::Null);

        let hdr_hex = vh["result"]["header_hex"].as_str().expect("header_hex");
        let hdr_bytes = hex::decode(hdr_hex).expect("header hex");
        let dec_hdr = decode_block_header(&hdr_bytes).expect("decode_block_header");
        let bid_exp = super::block_id(&dec_hdr);
        assert_eq!(
            vh["result"]["block_id"].as_str().expect("block_id"),
            hex32(&bid_exp)
        );

        let full_hex = vb["result"]["block_hex"].as_str().expect("block_hex");
        let full = hex::decode(full_hex).expect("block hex");
        let dec_block = decode_block(&full).expect("decode_block");
        assert_eq!(
            block_header_bytes(&dec_block.header),
            hdr_bytes,
            "decoded header bytes must match header-only response"
        );
        assert_eq!(
            super::block_id(&dec_block.header),
            bid_exp,
            "header-only id must match full block"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_mempool_empty_pool_no_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gp_empty");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_mempool","id":0}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["mempool_len"], json!(0));
        assert_eq!(v["result"]["tx_ids"], json!([]));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_mempool_accepts_explicit_empty_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gp_empty_obj");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_mempool","params":{},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["mempool_len"], json!(0));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_mempool_accepts_empty_array_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gp_empty_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_mempool","params":[],"id":3}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["mempool_len"], json!(0));
        assert_eq!(v["result"]["tx_ids"], json!([]));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_mempool_rejects_nonempty_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gp_bad");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_mempool","params":{"foo":1},"id":2}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_mempool_tx_missing_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gmtx_no_params");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_mempool_tx","id":0}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"].as_str().unwrap().contains("params"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_mempool_tx_missing_tx_id_in_object() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gmtx_empty_obj");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_mempool_tx","params":{},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"].as_str().unwrap().contains("tx_id"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_mempool_tx_array_empty() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gmtx_empty_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_mempool_tx","params":[],"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_mempool_tx_rejects_bad_hex() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gmtx_bad_hex");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_mempool_tx","params":{"tx_id":"zz00000000000000000000000000000000000000000000000000000000000000"},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"].as_str().unwrap().contains("hex"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_mempool_tx_rejects_wrong_hex_len() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gmtx_bad_len");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_mempool_tx","params":{"tx_id":"abcd"},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"].as_str().unwrap().contains("64"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_mempool_tx_not_found_object_param() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gmtx_nf_obj");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_mempool_tx","params":{"tx_id":"0000000000000000000000000000000000000000000000000000000000000000"},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::MEMPOOL_TX_NOT_FOUND);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_mempool_tx_not_found_array_param() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gmtx_nf_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_mempool_tx","params":["0000000000000000000000000000000000000000000000000000000000000000"],"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::MEMPOOL_TX_NOT_FOUND);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_mempool_tx_params_must_be_object_or_array() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gmtx_params_type");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_mempool_tx","params":"00","id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("object or a JSON array"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_remove_mempool_tx_missing_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_rmtx_no_params");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"remove_mempool_tx","id":0}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"].as_str().unwrap().contains("params"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_remove_mempool_tx_missing_tx_id_in_object() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_rmtx_empty_obj");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"remove_mempool_tx","params":{},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"].as_str().unwrap().contains("tx_id"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_remove_mempool_tx_array_empty() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_rmtx_empty_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"remove_mempool_tx","params":[],"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_remove_mempool_tx_rejects_bad_hex() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_rmtx_bad_hex");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"remove_mempool_tx","params":{"tx_id":"zz00000000000000000000000000000000000000000000000000000000000000"},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"].as_str().unwrap().contains("hex"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_remove_mempool_tx_rejects_wrong_hex_len() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_rmtx_bad_len");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"remove_mempool_tx","params":{"tx_id":"abcd"},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"].as_str().unwrap().contains("64"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_remove_mempool_tx_absent_object_param() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_rmtx_absent_obj");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"remove_mempool_tx","params":{"tx_id":"0000000000000000000000000000000000000000000000000000000000000000"},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["removed"], json!(false));
        assert_eq!(v["result"]["pool_len"], json!(0));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_remove_mempool_tx_absent_array_param() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_rmtx_absent_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"remove_mempool_tx","params":["0000000000000000000000000000000000000000000000000000000000000000"],"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["removed"], json!(false));
        assert_eq!(v["result"]["pool_len"], json!(0));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_remove_mempool_tx_params_must_be_object_or_array() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_rmtx_params_type");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"remove_mempool_tx","params":"00","id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("object or a JSON array"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_checkpoint_no_params_matches_chain_encode() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gcp_ok");
        let expect = c.encode_checkpoint();
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_checkpoint","id":0}"#,
        );
        assert_eq!(v["error"], Value::Null);
        let hx = v["result"]["checkpoint_hex"]
            .as_str()
            .expect("checkpoint_hex");
        let got = hex::decode(hx).expect("hex decode");
        assert_eq!(v["result"]["byte_len"], json!(got.len()));
        assert_eq!(got, expect);
        let cfg = ChainConfig::new(demo_genesis::empty_local_dev_genesis());
        let restored = Chain::from_checkpoint_bytes(cfg, &got).expect("from_checkpoint_bytes");
        assert_eq!(restored.encode_checkpoint(), expect);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_checkpoint_accepts_explicit_empty_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gcp_empty_obj");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_checkpoint","params":{},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert!(v["result"]["checkpoint_hex"].as_str().unwrap().len() >= 64);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_checkpoint_accepts_empty_array_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gcp_empty_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_checkpoint","params":[],"id":3}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(
            v["result"]["byte_len"].as_u64().unwrap() as usize * 2,
            v["result"]["checkpoint_hex"].as_str().unwrap().len()
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_checkpoint_rejects_nonempty_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gcp_bad");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_checkpoint","params":{"x":1},"id":2}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("get_checkpoint"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_save_checkpoint_writes_primary_and_returns_meta() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_save_cp_ok");
        assert!(!store.checkpoint_path().exists());
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"save_checkpoint","id":7}"#,
        );
        assert_eq!(v["error"], Value::Null);
        let bw = v["result"]["bytes_written"]
            .as_u64()
            .expect("bytes_written");
        assert!(bw > 0);
        let cp = v["result"]["checkpoint_path"]
            .as_str()
            .expect("checkpoint_path");
        assert!(
            cp.contains("chain.checkpoint") && !cp.contains("chain.checkpoint.bak"),
            "cp={cp}"
        );
        assert!(store.checkpoint_path().exists());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_save_checkpoint_accepts_explicit_empty_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_save_cp_empty_obj");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"save_checkpoint","params":{},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert!(v["result"]["bytes_written"].as_u64().unwrap() > 0);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_save_checkpoint_accepts_empty_array_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_save_cp_empty_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"save_checkpoint","params":[],"id":3}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert!(v["result"]["backup_path"].as_str().unwrap().contains("bak"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_save_checkpoint_rejects_nonempty_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_save_cp_bad");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"save_checkpoint","params":{"n":1},"id":2}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("save_checkpoint"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_methods_sorted_includes_dispatch_names() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_lm_ok");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_methods","id":0}"#,
        );
        assert_eq!(v["error"], Value::Null);
        let arr = v["result"]["methods"].as_array().expect("methods array");
        let names: Vec<&str> = arr
            .iter()
            .map(|x| x.as_str().expect("method name str"))
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "methods must be lexicographically sorted");
        for expected in [
            "clear_mempool",
            "get_block",
            "get_block_header",
            "get_claims_by_pubkey",
            "get_claims_for",
            "get_checkpoint",
            "get_mempool",
            "get_mempool_tx",
            "get_tip",
            "list_data_roots_with_claims",
            "list_methods",
            "list_recent_claims",
            "list_recent_uploads",
            "remove_mempool_tx",
            "save_checkpoint",
            "submit_tx",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
        assert_eq!(names.len(), 16);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_methods_accepts_explicit_empty_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_lm_empty_obj");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_methods","params":{},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["methods"].as_array().unwrap().len(), 16);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_methods_accepts_empty_array_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_lm_empty_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_methods","params":[],"id":3}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert!(v["result"]["methods"]
            .as_array()
            .unwrap()
            .contains(&json!("list_methods")));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_methods_rejects_nonempty_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_lm_bad");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_methods","params":{"x":1},"id":2}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("list_methods"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_claims_for_missing_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gcf_miss");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_claims_for","id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_claims_for_bad_hex_len() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gcf_bad");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_claims_for","params":{"data_root":"00"},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_claims_for_empty_when_unknown_root() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gcf_empty");
        let z = "0000000000000000000000000000000000000000000000000000000000000000";
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            &format!(
                r#"{{"jsonrpc":"2.0","method":"get_claims_for","params":{{"data_root":"{z}"}},"id":1}}"#
            ),
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["data_root"], json!(z));
        assert_eq!(v["result"]["claims"], json!([]));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_claims_by_pubkey_object_default_limit() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gcbp_obj");
        let z = "0101010101010101010101010101010101010101010101010101010101010101";
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            &format!(
                r#"{{"jsonrpc":"2.0","method":"get_claims_by_pubkey","params":{{"claim_pubkey":"{z}"}},"id":1}}"#
            ),
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["claim_pubkey"], json!(z));
        assert_eq!(v["result"]["limit"], json!(50));
        assert_eq!(v["result"]["claims"], json!([]));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_claims_by_pubkey_array_positional_limit() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gcbp_arr");
        let z = "0202020202020202020202020202020202020202020202020202020202020202";
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            &format!(
                r#"{{"jsonrpc":"2.0","method":"get_claims_by_pubkey","params":["{z}",3],"id":1}}"#
            ),
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["limit"], json!(3));
        assert_eq!(v["result"]["claims"], json!([]));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_claims_by_pubkey_rejects_bad_hex() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_gcbp_bad");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_claims_by_pubkey","params":{"claim_pubkey":"gg"},"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_recent_uploads_defaults_on_empty_chain() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_lru_def");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_recent_uploads","params":{},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["uploads"], json!([]));
        assert_eq!(v["result"]["total"], json!(0));
        assert_eq!(v["result"]["offset"], json!(0));
        assert_eq!(v["result"]["limit"], json!(20));
        assert_eq!(v["result"]["include_claims"], json!(false));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_recent_uploads_rejects_array_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_lru_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_recent_uploads","params":[],"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_recent_uploads_include_claims_adds_key_on_row() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_lru_claims");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_recent_uploads","params":{"limit":5,"offset":0,"include_claims":true},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["uploads"], json!([]));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_recent_claims_defaults_on_empty_chain() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_lrc_def");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_recent_claims","params":{},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["claims"], json!([]));
        assert_eq!(v["result"]["total"], json!(0));
        assert_eq!(v["result"]["offset"], json!(0));
        assert_eq!(v["result"]["limit"], json!(20));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_recent_claims_rejects_array_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_lrc_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_recent_claims","params":[],"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_data_roots_with_claims_defaults_on_empty_chain() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_ldr_def");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_data_roots_with_claims","params":{},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["roots"], json!([]));
        assert_eq!(v["result"]["total"], json!(0));
        assert_eq!(v["result"]["offset"], json!(0));
        assert_eq!(v["result"]["limit"], json!(20));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_data_roots_with_claims_rejects_array_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_ldr_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_data_roots_with_claims","params":[],"id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_clear_mempool_empty_pool_no_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_clr_empty");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"clear_mempool","id":0}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["cleared_count"], json!(0));
        assert_eq!(v["result"]["pool_len"], json!(0));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_clear_mempool_accepts_explicit_empty_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_clr_empty_obj");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"clear_mempool","params":{},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["cleared_count"], json!(0));
        assert_eq!(v["result"]["pool_len"], json!(0));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_clear_mempool_accepts_empty_array_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_clr_empty_arr");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"clear_mempool","params":[],"id":3}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["cleared_count"], json!(0));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_clear_mempool_rejects_nonempty_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_clr_bad");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"clear_mempool","params":{"foo":1},"id":2}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("clear_mempool"));
        fs::remove_dir_all(&root).ok();
    }
}
