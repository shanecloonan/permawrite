//! Minimal TCP control plane for `mfnd serve` (M2.1.6; subprocess `submit_tx`
//! negative-path coverage in `tests/mfnd_smoke.rs` — M2.1.6.1).
//!
//! One request per accepted connection: a single UTF-8 line of JSON, then
//! one JSON response line and the connection closes. Intended for localhost
//! tooling and integration tests; not a full JSON-RPC 2.0 server yet.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

use mfn_consensus::{decode_transaction, tx_id};
use serde_json::{json, Value};

use crate::{AdmitOutcome, Chain, ChainConfig, ChainStore, Mempool, MempoolConfig};

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
    let line = line.trim();
    if line.is_empty() {
        return Err("empty request line".into());
    }
    let req: Value = serde_json::from_str(line).map_err(|e| format!("invalid json: {e}"))?;
    let method = req
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing string field `method`".to_string())?;

    match method {
        "get_tip" => {
            let tip_h = chain.tip_height().map(|h| json!(h)).unwrap_or(Value::Null);
            let tip_id = chain.tip_id().map(hex32).unwrap_or_else(|| "none".into());
            let genesis_id = hex32(chain.genesis_id());
            let resp = json!({
                "ok": true,
                "result": {
                    "tip_height": tip_h,
                    "tip_id": tip_id,
                    "genesis_id": genesis_id,
                    "validator_count": chain.validators().len(),
                    "mempool_len": pool.len(),
                }
            });
            write_line(stream, &resp)
        }
        "submit_tx" => {
            let hex_s = req
                .get("params")
                .and_then(|p| p.get("tx_hex"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    "missing params.tx_hex (hex-encoded encode_transaction bytes)".to_string()
                })?;
            let hex_s = hex_s.trim();
            let hex_s = hex_s
                .strip_prefix("0x")
                .or_else(|| hex_s.strip_prefix("0X"))
                .unwrap_or(hex_s);
            let bytes = hex::decode(hex_s).map_err(|e| format!("params.tx_hex hex decode: {e}"))?;
            let tx = decode_transaction(&bytes).map_err(|e| format!("decode_transaction: {e}"))?;
            let id = tx_id(&tx);
            match pool.admit(tx, chain.state()) {
                Ok(outcome) => {
                    let resp = json!({
                        "ok": true,
                        "result": {
                            "tx_id": hex32(&id),
                            "pool_len": pool.len(),
                            "outcome": admit_outcome_json(&outcome),
                        }
                    });
                    write_line(stream, &resp)
                }
                Err(e) => write_line(
                    stream,
                    &json!({"ok": false, "error": format!("admit: {e}")}),
                ),
            }
        }
        other => write_line(
            stream,
            &json!({"ok": false, "error": format!("unknown method `{other}`")}),
        ),
    }
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
            let _ = write_line(&mut stream, &json!({"ok": false, "error": e}));
        }
    }
}
