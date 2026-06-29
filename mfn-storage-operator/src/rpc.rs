//! Minimal JSON-RPC client for storage-operator methods on `mfnd serve`.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use mfn_storage::{encode_storage_proof, StorageProof};
use serde::Deserialize;
use serde_json::{json, Value};

/// Default `mfnd serve --rpc-listen`.
pub const DEFAULT_RPC_ADDR: &str = "127.0.0.1:18731";

/// `get_storage_challenge` response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StorageChallenge {
    /// Storage commitment hash (64-char hex).
    pub commitment_hash: String,
    /// Canonical `encode_storage_commitment` bytes (hex).
    pub commitment_wire_hex: String,
    /// Merkle root (64-char hex).
    pub data_root: String,
    /// Payload size in bytes.
    pub size_bytes: u64,
    /// On-chain replication factor.
    pub replication: u8,
    /// Chunk count.
    pub num_chunks: u32,
    /// Chunk size.
    pub chunk_size: u32,
    /// Height the proof must target.
    pub next_height: u32,
    /// Slot for challenge derivation.
    pub next_slot: u32,
    /// Parent block id (64-char hex).
    pub prev_block_id: String,
    /// Challenged chunk index.
    pub chunk_index: u32,
}

/// `submit_storage_proof` admission summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitStorageProofResult {
    /// Commitment hash (64-char hex).
    pub commit_hash: String,
    /// Pool length after admit.
    pub pool_len: u64,
    /// `outcome.kind` (`Fresh` / `Replaced`).
    pub outcome_kind: String,
    /// Expected inclusion height.
    pub next_height: u32,
}

/// Tip snapshot for daemon health lines.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ChainTip {
    /// Canonical tip height (`null` when empty).
    pub tip_height: Option<u64>,
    /// Tip block id hex or `none`.
    pub tip_id: String,
    /// Chain genesis id (64-char hex).
    pub genesis_id: String,
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
    /// Unexpected response shape.
    #[error("{0}")]
    Protocol(String),
}

/// Talks to a running `mfnd serve` JSON-RPC listener.
#[derive(Debug, Clone)]
pub struct RpcClient {
    addr: String,
    api_key: Option<String>,
    next_id: u64,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl RpcClient {
    /// Connect to `HOST:PORT` (default [`DEFAULT_RPC_ADDR`]).
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            api_key: None,
            next_id: 1,
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
        }
    }

    /// Attach an RPC API key to every request.
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
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
        let mut req = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id,
        });
        if let (Some(api_key), Value::Object(obj)) = (&self.api_key, &mut req) {
            obj.insert("api_key".to_string(), Value::String(api_key.clone()));
        }
        let line = serde_json::to_string(&req)?;
        let resp_line = self.request_line(&line)?;
        let v: Value = serde_json::from_str(resp_line.trim())?;
        if let Some(err) = v.get("error") {
            if !err.is_null() {
                let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
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

    /// `get_tip` for cycle metadata.
    pub fn get_tip(&mut self) -> Result<ChainTip, RpcError> {
        let v = self.call("get_tip", Value::Null)?;
        serde_json::from_value(v).map_err(|e| RpcError::Protocol(format!("get_tip decode: {e}")))
    }

    /// `get_storage_challenge` for the next block.
    pub fn get_storage_challenge(
        &mut self,
        commitment_hash_hex: &str,
    ) -> Result<StorageChallenge, RpcError> {
        let v = self.call(
            "get_storage_challenge",
            json!({ "commitment_hash": commitment_hash_hex }),
        )?;
        serde_json::from_value(v)
            .map_err(|e| RpcError::Protocol(format!("get_storage_challenge decode: {e}")))
    }

    /// `submit_storage_proof` — queue a SPoRA proof for the next block.
    pub fn submit_storage_proof(
        &mut self,
        proof: &StorageProof,
    ) -> Result<SubmitStorageProofResult, RpcError> {
        let wire = encode_storage_proof(proof);
        let v = self.call(
            "submit_storage_proof",
            json!({ "proof_hex": hex::encode(wire) }),
        )?;
        let commit_hash = v
            .get("commit_hash")
            .and_then(|x| x.as_str())
            .ok_or_else(|| RpcError::Protocol("submit_storage_proof: missing commit_hash".into()))?
            .to_string();
        let pool_len = v
            .get("pool_len")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| RpcError::Protocol("submit_storage_proof: missing pool_len".into()))?;
        let outcome_kind = v
            .get("outcome")
            .and_then(|o| o.get("kind"))
            .and_then(|k| k.as_str())
            .ok_or_else(|| RpcError::Protocol("submit_storage_proof: missing outcome.kind".into()))?
            .to_string();
        let next_height = v
            .get("next_height")
            .and_then(|x| x.as_u64())
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| {
                RpcError::Protocol("submit_storage_proof: missing next_height".into())
            })?;
        Ok(SubmitStorageProofResult {
            commit_hash,
            pool_len,
            outcome_kind,
            next_height,
        })
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
