//! JSON-RPC 2.0 client for `mfnd serve` (one request line per TCP connection).
//!
//! **B8.3:** optional Tor-routed RPC dials (`--tor` / `MFN_CLI_RPC_TOR`) route through
//! SOCKS5 so `--rpc HOST.onion:PORT` works for remote `submit_tx` without exposing
//! the caller's IP to the seed node.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use mfn_net::{
    is_onion_host, parse_peer_host_port, P2pTransportConfig, P2pTransportKind, DEFAULT_TOR_SOCKS5,
};
use mfn_storage::{encode_storage_proof, StorageProof};
use serde::Deserialize;
use serde_json::{json, Value};

/// Default `mfnd serve --rpc-listen` when not overridden.
pub const DEFAULT_RPC_ADDR: &str = "127.0.0.1:18731";

/// Environment variable: set to `1` / `true` to route RPC over Tor (same as `--tor`).
pub const MFN_CLI_RPC_TOR_ENV: &str = "MFN_CLI_RPC_TOR";

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

/// `get_storage_challenge` response (**M3.22**).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StorageChallenge {
    /// Storage commitment hash (64-char hex).
    pub commitment_hash: String,
    /// Canonical `encode_storage_commitment` bytes (hex).
    pub commitment_wire_hex: String,
    /// Merkle root over chunk hashes (64-char hex).
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

/// `get_proof_pool` snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProofPoolSnapshot {
    /// Pending proof count.
    pub pool_len: u64,
    /// Commitment hashes (hex).
    pub commit_hashes: Vec<String>,
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

/// Compact header row from `get_block_headers`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlockHeaderRow {
    /// Block height (≥ 1).
    pub height: u32,
    /// Canonical block id (64-char hex).
    pub block_id: String,
    /// Previous block id (64-char hex).
    pub prev_block_id: String,
    /// `block_header_bytes` hex.
    pub header_hex: String,
}

/// `get_block_headers` page.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlockHeadersPage {
    /// Genesis block id (64-char hex).
    pub genesis_id: String,
    /// Header rows in ascending height order.
    pub headers: Vec<BlockHeaderRow>,
}

/// Evolution row from `get_light_follow`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LightFollowRow {
    /// Block height.
    pub height: u32,
    /// Canonical block id (64-char hex).
    pub block_id: String,
    /// `block_header_bytes` hex.
    pub header_hex: String,
    /// Equivocation evidence wire hex entries.
    pub slashings: Vec<LightFollowSlashing>,
    /// Bond op wire hex entries.
    pub bond_ops: Vec<LightFollowBondOp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
/// Slashing wire hex wrapper.
pub struct LightFollowSlashing {
    /// `encode_evidence` hex.
    pub evidence_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
/// Bond op wire hex wrapper.
pub struct LightFollowBondOp {
    /// `encode_bond_op` hex.
    pub op_hex: String,
}

/// `get_light_follow` page.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LightFollowPage {
    /// Inclusive range start.
    pub from_height: u32,
    /// Inclusive range end.
    pub to_height: u32,
    /// Evolution rows.
    pub rows: Vec<LightFollowRow>,
}

/// Weak-subjectivity summary embedded in `get_light_snapshot`.
pub use mfn_checkpoint_log::LightCheckpointSummary;

/// `get_light_snapshot` result.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LightSnapshot {
    /// Snapshot height (same as checkpoint tip).
    pub tip_height: u32,
    /// `LightChain::encode_checkpoint` hex.
    pub checkpoint_hex: String,
    /// Weak-subjectivity fields for the checkpoint.
    pub summary: LightCheckpointSummary,
}

/// One transaction from `get_block_txs`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlockTxRow {
    /// Index in block body.
    pub tx_index: u64,
    /// `encode_transaction` hex.
    pub tx_hex: String,
    /// Canonical tx id (64-char hex).
    pub tx_id: String,
}

/// `get_block_txs` result.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlockTxsPage {
    /// Block height.
    pub height: u32,
    /// Block id at height.
    pub block_id: String,
    /// Transactions in block order.
    pub txs: Vec<BlockTxRow>,
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

/// Outbound RPC dial mode (**B8.3**).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RpcConnectConfig {
    /// When set, dials route through this SOCKS5 proxy (Tor).
    pub tor_socks5: Option<String>,
}

impl RpcConnectConfig {
    /// Cleartext TCP (default).
    pub fn tcp() -> Self {
        Self::default()
    }

    /// Tor-routed dials via SOCKS5 at `proxy` (`HOST:PORT`, default Tor daemon).
    pub fn tor(proxy: impl Into<String>) -> Self {
        Self {
            tor_socks5: Some(proxy.into()),
        }
    }

    /// Read [`MFN_CLI_RPC_TOR_ENV`] and [`mfn_net::MFND_TOR_SOCKS5_ENV`].
    pub fn from_env() -> Result<Self, String> {
        let enabled = match std::env::var(MFN_CLI_RPC_TOR_ENV) {
            Ok(raw) => parse_env_bool(&raw)?,
            Err(std::env::VarError::NotPresent) => false,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!("{MFN_CLI_RPC_TOR_ENV} must be valid UTF-8"));
            }
        };
        if !enabled {
            return Ok(Self::tcp());
        }
        let tor_socks5 = match std::env::var(mfn_net::MFND_TOR_SOCKS5_ENV) {
            Ok(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(format!(
                        "{} must not be empty",
                        mfn_net::MFND_TOR_SOCKS5_ENV
                    ));
                }
                trimmed.to_string()
            }
            Err(std::env::VarError::NotPresent) => DEFAULT_TOR_SOCKS5.into(),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!(
                    "{} must be valid UTF-8",
                    mfn_net::MFND_TOR_SOCKS5_ENV
                ));
            }
        };
        Ok(Self::tor(tor_socks5))
    }
}

fn parse_env_bool(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => Ok(false),
        "1" | "true" | "yes" | "on" => Ok(true),
        other => Err(format!(
            "{MFN_CLI_RPC_TOR_ENV}={other:?} must be 0/1 or true/false"
        )),
    }
}

/// Talks to a running `mfnd serve` JSON-RPC listener.
#[derive(Debug, Clone)]
pub struct RpcClient {
    addr: String,
    api_key: Option<String>,
    connect: RpcConnectConfig,
    next_id: u64,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl RpcClient {
    /// Connect to `addr` (`HOST:PORT`, e.g. [`DEFAULT_RPC_ADDR`]).
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            api_key: None,
            connect: RpcConnectConfig::tcp(),
            next_id: 1,
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
        }
    }

    /// Route RPC dials through SOCKS5 (Tor). Reuses the same proxy knob as `mfnd serve`.
    pub fn with_tor(mut self, socks5: impl Into<String>) -> Self {
        self.connect = RpcConnectConfig::tor(socks5);
        self
    }

    /// Install an explicit connect config (cleartext or Tor).
    pub fn with_connect_config(mut self, connect: RpcConnectConfig) -> Self {
        self.connect = connect;
        self
    }

    /// Attach an RPC API key to every request.
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
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

    /// Peer `HOST:PORT` (or `.onion:PORT` when Tor mode is enabled).
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Active RPC connect config (for quorum peer clients that should mirror Tor mode).
    pub fn connect_config(&self) -> &RpcConnectConfig {
        &self.connect
    }

    /// Spawn a client to `addr` with the same Tor/cleartext settings as `self`.
    pub fn peer_client(&self, addr: impl Into<String>) -> Self {
        Self::new(addr).with_connect_config(self.connect.clone())
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

    /// `get_tip` — chain tip, genesis id, mempool summary fields.
    pub fn get_tip(&mut self) -> Result<ChainTip, RpcError> {
        let v = self.call("get_tip", Value::Null)?;
        serde_json::from_value(v).map_err(|e| RpcError::Protocol(format!("get_tip decode: {e}")))
    }

    /// `get_status` — machine-readable node health/status snapshot.
    pub fn get_status(&mut self) -> Result<Value, RpcError> {
        self.call("get_status", Value::Null)
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
        serde_json::from_value(v)
            .map_err(|e| RpcError::Protocol(format!("get_mempool decode: {e}")))
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
        let v = self.call("submit_tx", json!({ "tx_hex": hex::encode(tx_bytes) }))?;
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

    /// `get_chain_params` — genesis id, validators, consensus, bonding, emission.
    pub fn get_chain_params(&mut self) -> Result<Value, RpcError> {
        self.call("get_chain_params", json!({}))
    }

    /// `get_block_headers` for an inclusive height range.
    pub fn get_block_headers(
        &mut self,
        from_height: u32,
        to_height: u32,
    ) -> Result<BlockHeadersPage, RpcError> {
        let v = self.call(
            "get_block_headers",
            json!({ "from_height": from_height, "to_height": to_height }),
        )?;
        serde_json::from_value(v)
            .map_err(|e| RpcError::Protocol(format!("get_block_headers decode: {e}")))
    }

    /// `get_light_follow_p2p` — dial `peer` (`HOST:PORT`) and return the same batch shape as local.
    pub fn get_light_follow_p2p(
        &mut self,
        peer: &str,
        from_height: u32,
        to_height: u32,
    ) -> Result<LightFollowPage, RpcError> {
        let v = self.call(
            "get_light_follow_p2p",
            json!({
                "peer": peer,
                "from_height": from_height,
                "to_height": to_height,
            }),
        )?;
        serde_json::from_value(v)
            .map_err(|e| RpcError::Protocol(format!("get_light_follow_p2p decode: {e}")))
    }

    /// `get_light_follow` evolution rows for an inclusive height range.
    pub fn get_light_follow(
        &mut self,
        from_height: u32,
        to_height: u32,
    ) -> Result<LightFollowPage, RpcError> {
        let v = self.call(
            "get_light_follow",
            json!({ "from_height": from_height, "to_height": to_height }),
        )?;
        serde_json::from_value(v)
            .map_err(|e| RpcError::Protocol(format!("get_light_follow decode: {e}")))
    }

    /// `get_light_snapshot` at `height` (or chain tip when `None`).
    pub fn get_light_snapshot(&mut self, height: Option<u32>) -> Result<LightSnapshot, RpcError> {
        let params = match height {
            Some(h) => json!({ "height": h }),
            None => json!(null),
        };
        let v = self.call("get_light_snapshot", params)?;
        serde_json::from_value(v)
            .map_err(|e| RpcError::Protocol(format!("get_light_snapshot decode: {e}")))
    }

    /// `get_block_txs` — wire-encoded transactions at `height`.
    pub fn get_block_txs(&mut self, height: u32) -> Result<BlockTxsPage, RpcError> {
        let v = self.call("get_block_txs", json!({ "height": height }))?;
        serde_json::from_value(v)
            .map_err(|e| RpcError::Protocol(format!("get_block_txs decode: {e}")))
    }

    /// `get_storage_challenge` for the next block (**M3.22**).
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

    /// `get_proof_pool` — pending operator proofs.
    pub fn get_proof_pool(&mut self) -> Result<ProofPoolSnapshot, RpcError> {
        let v = self.call("get_proof_pool", json!(null))?;
        serde_json::from_value(v)
            .map_err(|e| RpcError::Protocol(format!("get_proof_pool decode: {e}")))
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
        let mut stream = self.connect_stream()?;
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

    fn connect_stream(&self) -> Result<TcpStream, RpcError> {
        if let Some(ref proxy) = self.connect.tor_socks5 {
            let cfg = P2pTransportConfig {
                kind: P2pTransportKind::Tor,
                tor_socks5: proxy.clone(),
            };
            return cfg.connect_peer(&self.addr).map_err(RpcError::Io);
        }
        let (host, _) = parse_peer_host_port(&self.addr)
            .map_err(|e| RpcError::Protocol(format!("invalid rpc addr: {e}")))?;
        if is_onion_host(&host) {
            return Err(RpcError::Protocol(format!(
                "rpc addr {:?} is a .onion hidden service; pass --tor (or set {MFN_CLI_RPC_TOR_ENV}=1)",
                self.addr
            )));
        }
        let addr = self
            .addr
            .parse()
            .map_err(|e| RpcError::Protocol(format!("invalid rpc addr: {e}")))?;
        TcpStream::connect_timeout(&addr, self.connect_timeout).map_err(RpcError::Io)
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

    #[test]
    fn cleartext_rpc_rejects_onion_without_tor() {
        let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:18731";
        let client = RpcClient::new(onion);
        let err = client.connect_stream().unwrap_err();
        match err {
            RpcError::Protocol(msg) => {
                assert!(msg.contains(".onion"));
                assert!(msg.contains("--tor"));
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn tor_rpc_without_reachable_proxy_fails() {
        let client = RpcClient::new("example.onion:8333").with_tor("127.0.0.1:1");
        assert!(client.connect_stream().is_err());
    }

    #[test]
    fn rpc_connect_config_from_env_defaults_off() {
        std::env::remove_var(MFN_CLI_RPC_TOR_ENV);
        std::env::remove_var(mfn_net::MFND_TOR_SOCKS5_ENV);
        let cfg = RpcConnectConfig::from_env().unwrap();
        assert_eq!(cfg, RpcConnectConfig::tcp());
    }
}
