//! TCP control plane for `mfnd serve` (M2.1.6 + M2.1.6.1 + **M2.1.8** + **M2.1.10** + **M2.1.11**).
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

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

use mfn_consensus::{block_header_bytes, block_id, decode_transaction, encode_block, tx_id, Block};
use serde_json::{json, Value};

use crate::{AdmitOutcome, Chain, ChainConfig, ChainStore, Mempool, MempoolConfig};

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

/// Run a blocking TCP loop: load chain + empty mempool, print bound address, then
/// serve one JSON line per connection until the process exits.
pub(crate) fn run_serve(store: &ChainStore, cfg: ChainConfig, listen: &str) -> Result<(), String> {
    let mut chain = store.load_or_genesis(cfg).map_err(|e| format!("{e}"))?;
    let mut pool = Mempool::new(MempoolConfig::default());

    let listener =
        TcpListener::bind(listen).map_err(|e| format!("mfnd serve: bind `{listen}`: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("mfnd serve: local_addr: {e}"))?;
    println!("mfnd_serve_listening={addr}");
    std::io::stdout()
        .flush()
        .map_err(|e| format!("mfnd serve: stdout flush: {e}"))?;

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
        if let Err(e) = handle_client(&mut stream, store, &mut chain, &mut pool) {
            let fallback = rpc_error(
                &Value::Null,
                rpc_codes::INTERNAL_ERROR,
                format!("mfnd serve: {e}"),
            );
            let _ = write_line(&mut stream, &fallback);
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

    use crate::{demo_genesis, produce_solo_block, BlockInputs};

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
}
