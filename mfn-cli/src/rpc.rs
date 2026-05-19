//! JSON-RPC 2.0 client for `mfnd serve` (one request line per TCP connection).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

/// Default `mfnd serve --rpc-listen` when not overridden.
pub const DEFAULT_RPC_ADDR: &str = "127.0.0.1:18731";

/// Chain tip snapshot from `get_tip`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ChainTip {
    /// Canonical tip height (`null` at empty genesis-only view).
    pub tip_height: Option<u64>,
    /// 64-char hex block id at tip, or `"none"`.
    pub tip_id: String,
    /// Genesis block id (64-char hex).
    pub genesis_id: String,
    /// Active validator count from genesis state.
    pub validator_count: u64,
    /// Mempool transaction count.
    pub mempool_len: u64,
    /// Merkle root of mempool tx ids (64-char hex).
    pub mempool_root: String,
}

/// Block header summary from `get_block_header`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlockHeaderInfo {
    /// Block height (≥ 1).
    pub height: u64,
    /// Canonical block id (64-char hex).
    pub block_id: String,
    /// `block_header_bytes` hex.
    pub header_hex: String,
}

/// `submit_tx` admission summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitTxResult {
    /// Canonical tx id (64-char hex).
    pub tx_id: String,
    /// Mempool length after admission.
    pub pool_len: u64,
    /// `outcome.kind` from JSON-RPC (`Fresh`, `Duplicate`, …).
    pub outcome_kind: String,
}

/// Mempool listing from `get_mempool`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MempoolSummary {
    /// Number of txs in the mempool.
    pub mempool_len: u64,
    /// Sorted tx id hex strings.
    pub tx_ids: Vec<String>,
}

/// JSON-RPC client error.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// TCP or framing I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parse failure.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Server returned a JSON-RPC error object.
    #[error("rpc error {code}: {message}")]
    Server {
        /// JSON-RPC error code.
        code: i64,
        /// Error message string.
        message: String,
    },
    /// Unexpected response shape or client-side validation.
    #[error("{0}")]
    Protocol(String),
}

/// Talks to a running `mfnd serve` JSON-RPC listener.
#[derive(Debug, Clone)]
pub struct RpcClient {
    addr: String,
    next_id: u64,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl RpcClient {
    /// Connect to `addr` (`HOST:PORT`, e.g. [`DEFAULT_RPC_ADDR`]).
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            next_id: 1,
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
        }
    }

    /// Override TCP connect timeout (primarily for tests).
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Override per-request read/write timeout.
    pub fn with_io_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = timeout;
        self
    }

    /// Peer `HOST:PORT`.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Issue a JSON-RPC 2.0 call and return the `result` value.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let req = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id,
        });
        let line = serde_json::to_string(&req)?;
        let resp_line = self.request_line(&line)?;
        let v: Value = serde_json::from_str(resp_line.trim())?;
        if let Some(err) = v.get("error") {
            if !err.is_null() {
                let code = err
                    .get("code")
                    .and_then(|c| c.as_i64())
                    .unwrap_or(-1);
                let message = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error")
                    .to_string();
                return Err(RpcError::Server { code, message });
            }
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| RpcError::Protocol("response missing result".into()))
    }

    /// `get_tip` — chain tip, genesis id, mempool summary fields.
    pub fn get_tip(&mut self) -> Result<ChainTip, RpcError> {
        let v = self.call("get_tip", Value::Null)?;
        serde_json::from_value(v).map_err(|e| RpcError::Protocol(format!("get_tip decode: {e}")))
    }

    /// `list_methods` — sorted method names exposed by the node.
    pub fn list_methods(&mut self) -> Result<Vec<String>, RpcError> {
        let v = self.call("list_methods", json!({}))?;
        let methods = v
            .get("methods")
            .and_then(|m| m.as_array())
            .ok_or_else(|| RpcError::Protocol("list_methods: missing methods array".into()))?;
        let mut names: Vec<String> = methods
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect();
        names.sort_unstable();
        Ok(names)
    }

    /// `get_block_header` for `height` (≥ 1).
    pub fn get_block_header(&mut self, height: u32) -> Result<BlockHeaderInfo, RpcError> {
        let v = self.call("get_block_header", json!({ "height": height }))?;
        serde_json::from_value(v)
            .map_err(|e| RpcError::Protocol(format!("get_block_header decode: {e}")))
    }

    /// `get_mempool` — tx id list.
    pub fn get_mempool(&mut self) -> Result<MempoolSummary, RpcError> {
        let v = self.call("get_mempool", Value::Null)?;
        serde_json::from_value(v).map_err(|e| RpcError::Protocol(format!("get_mempool decode: {e}")))
    }

    /// `get_checkpoint` — returns `Chain::encode_checkpoint` bytes.
    pub fn get_checkpoint(&mut self) -> Result<Vec<u8>, RpcError> {
        let v = self.call("get_checkpoint", Value::Null)?;
        let hex_str = v
            .get("checkpoint_hex")
            .and_then(|x| x.as_str())
            .ok_or_else(|| RpcError::Protocol("get_checkpoint: missing checkpoint_hex".into()))?;
        hex::decode(hex_str).map_err(|e| RpcError::Protocol(format!("get_checkpoint hex: {e}")))
    }

    /// `submit_tx` — broadcast hex-encoded `encode_transaction` bytes.
    pub fn submit_tx(&mut self, tx_bytes: &[u8]) -> Result<SubmitTxResult, RpcError> {
        let v = self.call(
            "submit_tx",
            json!({ "tx_hex": hex::encode(tx_bytes) }),
        )?;
        let tx_id = v
            .get("tx_id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| RpcError::Protocol("submit_tx: missing tx_id".into()))?
            .to_string();
        let pool_len = v
            .get("pool_len")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| RpcError::Protocol("submit_tx: missing pool_len".into()))?;
        let outcome_kind = v
            .get("outcome")
            .and_then(|o| o.get("kind"))
            .and_then(|k| k.as_str())
            .unwrap_or("unknown")
            .to_string();
        Ok(SubmitTxResult {
            tx_id,
            pool_len,
            outcome_kind,
        })
    }

    /// `get_block` for `height` (≥ 1) — returns canonical encoded block bytes.
    pub fn get_block(&mut self, height: u32) -> Result<Vec<u8>, RpcError> {
        let v = self.call("get_block", json!({ "height": height }))?;
        let h = v
            .get("height")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| RpcError::Protocol("get_block: missing height".into()))?;
        if h != u64::from(height) {
            return Err(RpcError::Protocol(format!(
                "get_block: height mismatch (asked {height}, got {h})"
            )));
        }
        let hex_str = v
            .get("block_hex")
            .and_then(|x| x.as_str())
            .ok_or_else(|| RpcError::Protocol("get_block: missing block_hex".into()))?;
        hex::decode(hex_str).map_err(|e| RpcError::Protocol(format!("get_block hex: {e}")))
    }

    fn request_line(&self, request_line: &str) -> Result<String, RpcError> {
        let mut stream = TcpStream::connect_timeout(
            &self
                .addr
                .parse()
                .map_err(|e| RpcError::Protocol(format!("invalid rpc addr: {e}")))?,
            self.connect_timeout,
        )?;
        stream.set_read_timeout(Some(self.io_timeout))?;
        stream.set_write_timeout(Some(self.io_timeout))?;
        let mut req = request_line.to_string();
        if !req.ends_with('\n') {
            req.push('\n');
        }
        stream.write_all(req.as_bytes())?;
        stream.flush()?;
        let mut resp = String::new();
        BufReader::new(&stream)
            .read_line(&mut resp)
            .map_err(RpcError::Io)?;
        if resp.trim().is_empty() {
            return Err(RpcError::Protocol("empty response from node".into()));
        }
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_tip_deserializes_null_height() {
        let v = json!({
            "tip_height": null,
            "tip_id": "none",
            "genesis_id": "aa".repeat(32),
            "validator_count": 1,
            "mempool_len": 0,
            "mempool_root": "bb".repeat(32),
        });
        let tip: ChainTip = serde_json::from_value(v).unwrap();
        assert_eq!(tip.tip_height, None);
        assert_eq!(tip.tip_id, "none");
    }
}
