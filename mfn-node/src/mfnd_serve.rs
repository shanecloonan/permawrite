//! TCP control plane for `mfnd serve` (M2.1.6 + M2.1.6.1 + **M2.1.8**).
//!
//! One request per accepted connection: a single UTF-8 line of JSON, then
//! one JSON response line and the connection closes. Responses follow
//! [JSON-RPC 2.0](https://www.jsonrpc.org/specification): `jsonrpc`, `id`, and
//! either `result` or `error` (`code` + `message`). Requests may omit
//! `jsonrpc` (legacy tooling); when `jsonrpc` is present it must be `"2.0"`.
//! Omitted `id` is treated as `null` and echoed back (the TCP server always
//! emits one response line per connection, including for JSON-RPC
//! notifications).

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

use mfn_consensus::{decode_transaction, tx_id};
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

/// Parse one request line and return a single JSON-RPC 2.0 response value.
pub(crate) fn parse_and_dispatch_serve(chain: &mut Chain, pool: &mut Mempool, line: &str) -> Value {
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
    dispatch_serve_methods(chain, pool, &req, &id)
}

fn dispatch_serve_methods(chain: &mut Chain, pool: &mut Mempool, req: &Value, id: &Value) -> Value {
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
            let hex_s = match req.get("params").and_then(|p| p.get("tx_hex")) {
                Some(Value::String(s)) => s.as_str(),
                Some(_) => {
                    return rpc_error(
                        id,
                        rpc_codes::INVALID_PARAMS,
                        "params.tx_hex must be a JSON string",
                    );
                }
                None => {
                    return rpc_error(
                        id,
                        rpc_codes::INVALID_PARAMS,
                        "missing params.tx_hex (hex-encoded encode_transaction bytes)",
                    );
                }
            };
            let hex_s = hex_s.trim();
            let hex_s = hex_s
                .strip_prefix("0x")
                .or_else(|| hex_s.strip_prefix("0X"))
                .unwrap_or(hex_s);
            let bytes = match hex::decode(hex_s) {
                Ok(b) => b,
                Err(e) => {
                    return rpc_error(
                        id,
                        rpc_codes::INVALID_PARAMS,
                        format!("params.tx_hex hex decode: {e}"),
                    );
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
    let resp = parse_and_dispatch_serve(chain, pool, &line);
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
        if let Err(e) = handle_client(&mut stream, &mut chain, &mut pool) {
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
    use crate::{demo_genesis, Chain, ChainConfig, Mempool, MempoolConfig};

    fn test_chain_and_pool() -> (Chain, Mempool) {
        let chain = Chain::from_genesis(ChainConfig::new(demo_genesis::empty_local_dev_genesis()))
            .expect("genesis");
        let pool = Mempool::new(MempoolConfig::default());
        (chain, pool)
    }

    #[test]
    fn rpc_empty_line_is_invalid_request() {
        let (mut c, mut p) = test_chain_and_pool();
        let v = parse_and_dispatch_serve(&mut c, &mut p, "   \n");
        assert_eq!(v["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_REQUEST);
        assert!(v["result"].is_null());
    }

    #[test]
    fn rpc_invalid_json_is_parse_error_with_null_id() {
        let (mut c, mut p) = test_chain_and_pool();
        let v = parse_and_dispatch_serve(&mut c, &mut p, "{not json");
        assert_eq!(v["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(v["error"]["code"], rpc_codes::PARSE_ERROR);
        assert_eq!(v["id"], Value::Null);
    }

    #[test]
    fn rpc_rejects_wrong_jsonrpc_version() {
        let (mut c, mut p) = test_chain_and_pool();
        let v = parse_and_dispatch_serve(
            &mut c,
            &mut p,
            r#"{"jsonrpc":"1.0","method":"get_tip","id":1}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_REQUEST);
        assert_eq!(v["id"], json!(1));
    }

    #[test]
    fn rpc_unknown_method() {
        let (mut c, mut p) = test_chain_and_pool();
        let v = parse_and_dispatch_serve(
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"nope","id":"abc"}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::METHOD_NOT_FOUND);
        assert_eq!(v["id"], json!("abc"));
    }

    #[test]
    fn rpc_get_tip_legacy_no_jsonrpc_echoes_null_id() {
        let (mut c, mut p) = test_chain_and_pool();
        let v = parse_and_dispatch_serve(&mut c, &mut p, r#"{"method":"get_tip"}"#);
        assert_eq!(v["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(v["id"], Value::Null);
        assert_eq!(v["error"], Value::Null);
        let tip = &v["result"]["tip_height"];
        assert!(tip.is_number() || tip.is_null());
        assert!(v["result"]["genesis_id"].as_str().unwrap().len() == 64);
    }

    #[test]
    fn rpc_get_tip_echoes_numeric_id() {
        let (mut c, mut p) = test_chain_and_pool();
        let v = parse_and_dispatch_serve(
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_tip","id":42}"#,
        );
        assert_eq!(v["id"], json!(42));
        assert!(v["result"]["mempool_len"].as_u64() == Some(0));
    }

    #[test]
    fn rpc_submit_tx_missing_tx_hex() {
        let (mut c, mut p) = test_chain_and_pool();
        let v = parse_and_dispatch_serve(
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"submit_tx","params":{},"id":0}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"].as_str().unwrap().contains("tx_hex"));
    }

    #[test]
    fn rpc_method_must_be_string() {
        let (mut c, mut p) = test_chain_and_pool();
        let v =
            parse_and_dispatch_serve(&mut c, &mut p, r#"{"jsonrpc":"2.0","method":7,"id":null}"#);
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_REQUEST);
    }
}
