//! JSON-RPC 2.0 dispatch for `mfnd serve` (methods, params, error codes).

use std::collections::BTreeMap;
use std::sync::Arc;

use mfn_bls::encode_public_key;
use mfn_consensus::block::{StorageEntry, UtxoEntry};
use mfn_consensus::{
    block_header_bytes, block_id, decode_block_header, decode_transaction, encode_block,
    encode_bond_op, encode_slash_evidence, encode_transaction, tx_id, validator_set_root,
    AuthorshipClaimRecord, Block, BondEpochCounters, ConsensusParams, GenesisConfig, Validator,
};
use mfn_crypto::dhash;
use mfn_crypto::domain::LIGHT_CHECKPOINT;
use mfn_crypto::schnorr::encode_schnorr_signature;
use mfn_light::checkpoint::{encode_checkpoint_bytes, CheckpointParts};
use mfn_light::light_checkpoint_after_blocks;
use mfn_light::LightChain;
use mfn_net::LightFollowV1;
use serde_json::{json, Map, Value};

use mfn_runtime::{mempool_root, AdmitOutcome, Chain, Mempool, ProofAdmitOutcome, ProofPool};
use mfn_storage::{
    chunk_index_for_challenge, chunk_index_for_operator_challenge, decode_storage_proof,
    encode_storage_commitment, operator_identity_from_payout, operator_payout_is_valid,
};
use mfn_store::ChainPersistence;

const JSONRPC_VERSION: &str = "2.0";
/// JSON-RPC 2.0 standard codes and Permawrite application error codes.
#[allow(missing_docs)]
pub mod rpc_codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
    /// Mempool [`mfn_runtime::Mempool::admit`] rejected the decoded transaction.
    pub const MEMPOOL_REJECT: i64 = -32001;
    /// [`mfn_store::ChainStore`] / `chain.blocks` read or validation failed.
    pub const BLOCK_LOG_STORE: i64 = -32002;
    /// No mempool entry for the requested [`TransactionWire`](mfn_consensus::TransactionWire) id.
    pub const MEMPOOL_TX_NOT_FOUND: i64 = -32003;
    /// [`mfn_store::ChainStore::save`] failed (IO or other store error).
    pub const CHECKPOINT_SAVE: i64 = -32004;
    /// [`mfn_runtime::ProofPool::admit`] rejected the decoded proof.
    pub const PROOF_POOL_REJECT: i64 = -32005;
    /// RPC method requires an API key configured by the node operator.
    pub const AUTH_REQUIRED: i64 = -32006;
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

/// Build a JSON-RPC 2.0 success response with the given `id` and `result`.
pub fn rpc_success(id: &Value, result: Value) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "result": result,
        "id": id,
    })
}

/// Build a JSON-RPC 2.0 error response with the given `id`, `code`, and message.
pub fn rpc_error(id: &Value, code: i64, message: impl AsRef<str>) -> Value {
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

#[path = "dispatch/rpc_method_meta.rs"]
mod rpc_method_meta;
#[path = "dispatch/rpc_params.rs"]
mod rpc_params;

use rpc_method_meta::{
    authorize_rpc_method, serve_rpc_method_names, serve_rpc_methods_json_result,
};
use rpc_params::*;

fn next_block_context(chain: &Chain) -> ([u8; 32], u32) {
    let prev = chain
        .tip_id()
        .copied()
        .unwrap_or_else(|| *chain.genesis_id());
    let next_height = chain.tip_height().map(|h| h.saturating_add(1)).unwrap_or(1);
    (prev, next_height)
}

fn proof_admit_outcome_json(o: &ProofAdmitOutcome) -> Value {
    match o {
        ProofAdmitOutcome::Fresh => json!({"kind": "Fresh"}),
        ProofAdmitOutcome::Replaced => json!({"kind": "Replaced"}),
    }
}
fn json_utxo_row(one_time_addr_key: &[u8; 32], entry: &UtxoEntry) -> Value {
    json!({
        "height": entry.height,
        "one_time_addr_hex": hex32(one_time_addr_key),
        "commit_hex": hex32(&entry.commit.compress().to_bytes()),
    })
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
        "commit_hash": hex32(&c.commit_hash),
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
        let mut claims_json: Vec<Value> = chain
            .state()
            .claims
            .iter()
            .filter(|((root, _), _)| *root == c.data_root)
            .map(|(_, rec)| authorship_claim_record_json(rec))
            .collect();
        claims_json.sort_by(|a, b| {
            let ha = a.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
            let hb = b.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
            ha.cmp(&hb)
        });
        m.insert("claims".into(), Value::Array(claims_json));
    }
    Value::Object(m)
}

fn collect_claims_for_pubkey<'a>(
    chain: &'a Chain,
    pk: &[u8; 32],
    limit: usize,
) -> Vec<&'a AuthorshipClaimRecord> {
    let mut out: Vec<&AuthorshipClaimRecord> = chain
        .state()
        .claims
        .iter()
        .filter(|((_, claim_pk), rec)| {
            *claim_pk == *pk
                && rec.claim.claim_pubkey.compress().as_bytes().as_slice() == pk.as_slice()
        })
        .map(|(_, rec)| rec)
        .collect();
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
    let mut out: Vec<&AuthorshipClaimRecord> = chain.state().claims.values().collect();
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
    let mut counts: BTreeMap<[u8; 32], (u32, usize)> = BTreeMap::new();
    for ((root, _), rec) in chain.state().claims.iter() {
        counts
            .entry(*root)
            .and_modify(|(max_h, n)| {
                *max_h = (*max_h).max(rec.height);
                *n += 1;
            })
            .or_insert((rec.height, 1));
    }
    for (root, (max_h, n)) in counts {
        rows.push((root, max_h, n));
    }
    rows.sort_by(|(ra, ha, _), (rb, hb, _)| {
        hb.cmp(ha).then_with(|| ra.as_slice().cmp(rb.as_slice()))
    });
    rows
}

fn validator_row_json(v: &Validator) -> Value {
    let payout = match &v.payout {
        None => Value::Null,
        Some(p) => json!({
            "view_pub_hex": hex::encode(p.view_pub.compress().to_bytes()),
            "spend_pub_hex": hex::encode(p.spend_pub.compress().to_bytes()),
        }),
    };
    json!({
        "index": v.index,
        "stake": v.stake,
        "vrf_pk_hex": hex::encode(v.vrf_pk.compress().to_bytes()),
        "bls_pk_hex": hex::encode(encode_public_key(&v.bls_pk)),
        "payout": payout,
    })
}

fn light_snapshot_hex(chain: &Chain) -> String {
    let s = chain.state();
    let tip_height = chain.tip_height().unwrap_or(0);
    let tip_id = chain.tip_id().copied().unwrap_or(*chain.genesis_id());
    let parts = CheckpointParts {
        tip_height,
        tip_id,
        genesis_id: *chain.genesis_id(),
        params: s.params,
        bonding_params: s.bonding_params,
        validators: s.validators.clone(),
        validator_stats: s.validator_stats.clone(),
        pending_unbonds: s.pending_unbonds.clone(),
        bond_counters: BondEpochCounters {
            bond_epoch_id: s.bond_epoch_id,
            bond_epoch_entry_count: s.bond_epoch_entry_count,
            bond_epoch_exit_count: s.bond_epoch_exit_count,
            next_validator_index: s.next_validator_index,
        },
    };
    hex::encode(encode_checkpoint_bytes(&parts))
}

/// Weak-subjectivity fields for a light-follower checkpoint (**M4.14**).
fn light_checkpoint_summary_json(checkpoint_hex: &str) -> Result<Value, String> {
    let t = checkpoint_hex
        .trim()
        .strip_prefix("0x")
        .or_else(|| checkpoint_hex.trim().strip_prefix("0X"))
        .unwrap_or(checkpoint_hex.trim());
    let bytes = hex::decode(t).map_err(|e| format!("checkpoint_hex: {e}"))?;
    let chain =
        LightChain::decode_checkpoint(&bytes).map_err(|e| format!("decode_checkpoint: {e}"))?;
    let checkpoint_bytes = chain.encode_checkpoint();
    let digest = dhash(LIGHT_CHECKPOINT, &[&checkpoint_bytes]);
    Ok(json!({
        "genesis_id": hex32(chain.genesis_id()),
        "tip_height": chain.tip_height(),
        "tip_block_id": hex32(chain.tip_id()),
        "validator_count": chain.trusted_validators().len(),
        "validator_set_root": hex32(&validator_set_root(chain.trusted_validators())),
        "checkpoint_digest": hex32(&digest),
    }))
}

fn light_snapshot_replay_at_height(
    store: &dyn ChainPersistence,
    chain: &Chain,
    genesis: &GenesisConfig,
    height: u32,
) -> Result<String, String> {
    let tip_h = chain
        .tip_height()
        .ok_or("chain tip_height is None (unexpected)")?;
    if height > tip_h {
        return Err(format!("height {height} exceeds chain tip_height {tip_h}"));
    }
    let blocks = store
        .read_block_log_validated(chain)
        .map_err(|e| format!("read_block_log_validated: {e}"))?;
    let bytes = light_checkpoint_after_blocks(genesis.clone(), &blocks, height)
        .map_err(|e| format!("light_checkpoint_after_blocks: {e}"))?;
    Ok(hex::encode(bytes))
}

fn consensus_params_json(p: &ConsensusParams) -> Value {
    json!({
        "expected_proposers_per_slot": p.expected_proposers_per_slot,
        "quorum_stake_bps": p.quorum_stake_bps,
        "liveness_max_consecutive_missed": p.liveness_max_consecutive_missed,
        "liveness_slash_bps": p.liveness_slash_bps,
    })
}

/// Monetary / permanence parameters from the live chain state (genesis-frozen in v0.1).
fn chain_params_json(chain: &Chain) -> Value {
    let s = chain.state();
    let e = &s.emission_params;
    let end = &s.endowment_params;
    let bond = &s.bonding_params;
    let validators: Vec<Value> = s.validators.iter().map(validator_row_json).collect();
    json!({
        "tip_height": s.height.map(|h| json!(h)).unwrap_or(Value::Null),
        "genesis_id": hex32(chain.genesis_id()),
        "treasury_base_units": s.treasury.to_string(),
        "mfn_decimals": mfn_consensus::emission::MFN_DECIMALS,
        "mfn_base": mfn_consensus::emission::MFN_BASE,
        "emission": {
            "initial_reward": e.initial_reward,
            "halving_period": e.halving_period,
            "halving_count": e.halving_count,
            "tail_emission": e.tail_emission,
            "storage_proof_reward": e.storage_proof_reward,
            "fee_to_treasury_bps": e.fee_to_treasury_bps,
            "subsidy_to_treasury_bps": e.subsidy_to_treasury_bps,
        },
        "endowment": {
            "cost_per_byte_year_ppb": end.cost_per_byte_year_ppb,
            "inflation_ppb": end.inflation_ppb,
            "real_yield_ppb": end.real_yield_ppb,
            "min_replication": end.min_replication,
            "max_replication": end.max_replication,
            "slots_per_year": end.slots_per_year,
            "proof_reward_window_slots": end.proof_reward_window_slots,
            "require_endowment_opening": end.require_endowment_opening,
            "require_endowment_range_proof": end.require_endowment_range_proof,
            "operator_salted_challenges": end.operator_salted_challenges,
            "require_registered_operators": end.require_registered_operators,
        },
        "bonding": {
            "min_validator_stake": bond.min_validator_stake,
            "unbond_delay_heights": bond.unbond_delay_heights,
            "max_entry_churn_per_epoch": bond.max_entry_churn_per_epoch,
            "max_exit_churn_per_epoch": bond.max_exit_churn_per_epoch,
            "slots_per_epoch": bond.slots_per_epoch,
        },
        "consensus": consensus_params_json(&s.params),
        "validators": validators,
    })
}

/// Load `chain.blocks` validated against `chain` after height / tip checks.
/// `height` must be parsed from params (caller maps `extract_height_param` errors).
fn read_validated_blocks_for_height(
    store: &dyn ChainPersistence,
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

fn header_row_json(block: &Block, height: u32) -> Value {
    let bid = block_id(&block.header);
    json!({
        "height": height,
        "block_id": hex32(&bid),
        "prev_block_id": hex32(&block.header.prev_hash),
        "header_hex": hex::encode(block_header_bytes(&block.header)),
    })
}

/// JSON-RPC page for a P2P or local [`LightFollowV1`] payload (**M4.15**).
pub fn light_follow_v1_to_json(follow: &LightFollowV1, from_height: u32, to_height: u32) -> Value {
    let rows: Vec<Value> = follow
        .rows
        .iter()
        .map(|row| {
            let slashings: Vec<Value> = row
                .slashings
                .iter()
                .map(|s| json!({ "evidence_hex": hex::encode(s) }))
                .collect();
            let bond_ops: Vec<Value> = row
                .bond_ops
                .iter()
                .map(|b| json!({ "op_hex": hex::encode(b) }))
                .collect();
            let mut obj = json!({
                "height": row.height,
                "block_id": hex32(&row.block_id),
                "header_hex": hex::encode(&row.header_wire),
                "slashings": slashings,
                "bond_ops": bond_ops,
            });
            if let Ok(header) = decode_block_header(&row.header_wire) {
                if let Some(o) = obj.as_object_mut() {
                    o.insert("prev_block_id".into(), json!(hex32(&header.prev_hash)));
                }
            }
            obj
        })
        .collect();
    json!({
        "from_height": from_height,
        "to_height": to_height,
        "genesis_id": hex32(&follow.genesis_id),
        "rows": rows,
    })
}

fn light_follow_row_json(block: &Block, height: u32) -> Value {
    let slashings: Vec<Value> = block
        .slashings
        .iter()
        .map(|ev| json!({ "evidence_hex": hex::encode(encode_slash_evidence(ev, block.header.version)) }))
        .collect();
    let bond_ops: Vec<Value> = block
        .bond_ops
        .iter()
        .map(|op| json!({ "op_hex": hex::encode(encode_bond_op(op)) }))
        .collect();
    let mut row = header_row_json(block, height);
    if let Some(obj) = row.as_object_mut() {
        obj.insert("slashings".into(), Value::Array(slashings));
        obj.insert("bond_ops".into(), Value::Array(bond_ops));
    }
    row
}

/// Called with canonical tx wire bytes when [`Mempool::admit`] returns fresh.
pub type FreshTxHook = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Called with the live mempool immediately after a Fresh admit (before the RPC response is sent).
pub type FreshAdmitHook = Arc<dyn Fn(&Mempool) + Send + Sync>;

/// Called after the proof pool changes (**M3.23** durable snapshot).
pub type ProofPoolPersistHook = Arc<dyn Fn(&ProofPool) + Send + Sync>;

/// Fetch a light-follow batch from a remote P2P peer (`HOST:PORT`) (**M4.15**).
pub type P2pLightFollowHook = Arc<dyn Fn(&str, u32, u32) -> Result<Value, String> + Send + Sync>;

/// Fetch from multiple P2P peers and require agreeing rows (**M4.16**).
pub type P2pLightFollowQuorumHook =
    Arc<dyn Fn(&[String], u32, u32) -> Result<Value, String> + Send + Sync>;
/// Public-safe P2P status snapshot injected by `mfnd serve`.
pub type P2pStatusHook = Arc<dyn Fn() -> Value + Send + Sync>;
/// Diverse boot peers for checkpoint summaries (**F12** phase 0).
pub type P2pAnchorPeersHook = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Contested blocks from verified P2P fraud proofs (**F5** phase 1b).
pub type FraudContestsHook = Arc<dyn Fn() -> Value + Send + Sync>;

/// Optional hooks for `mfnd serve` dispatch (**M2.3.20** mempool fan-out).
#[derive(Clone, Default)]
pub struct ServeDispatchOpts {
    /// Genesis spec for replaying light checkpoints at historical heights (M4.12).
    pub genesis: Option<Arc<GenesisConfig>>,
    /// Optional API key required for `wallet-write` and `operator-admin` methods.
    pub rpc_api_key: Option<String>,
    /// Configured maximum in-flight JSON-RPC connections, when dispatch runs behind `mfnd serve`.
    pub rpc_max_in_flight: Option<usize>,
    /// Live in-flight JSON-RPC connection counter, when dispatch runs behind `mfnd serve`.
    pub rpc_current_in_flight: Option<Arc<dyn Fn() -> usize + Send + Sync>>,
    /// Maximum newline-delimited JSON-RPC request line bytes, when enforced by `mfnd serve`.
    pub rpc_max_request_line_bytes: Option<u64>,
    /// Per-connection JSON-RPC read/write timeout in milliseconds, when enforced by `mfnd serve`.
    pub rpc_io_timeout_ms: Option<u64>,
    /// Configured JSON-RPC listen address, when dispatch runs behind `mfnd serve`.
    pub rpc_listen_addr: Option<String>,
    /// Whether the configured JSON-RPC bind is non-loopback, when known.
    pub rpc_public_bind: Option<bool>,
    /// Post-admit fan-out for accepted txs.
    pub on_fresh_tx: Option<FreshTxHook>,
    /// Durable mempool snapshot while `pool` is still exclusively borrowed by dispatch.
    pub on_fresh_admit: Option<FreshAdmitHook>,
    /// Outbound P2P light-follow fetch for [`get_light_follow_p2p`].
    pub p2p_light_follow: Option<P2pLightFollowHook>,
    /// Multi-peer P2P quorum for [`get_light_follow_quorum_p2p`].
    pub p2p_light_follow_quorum: Option<P2pLightFollowQuorumHook>,
    /// Public-safe P2P health fields for [`get_status`].
    pub p2p_status: Option<P2pStatusHook>,
    /// Diverse session/durable peers for [`get_light_snapshot`] anchor list (**F12**).
    pub p2p_anchor_peers: Option<P2pAnchorPeersHook>,
    /// P2P-verified fraud contests for [`list_fraud_contests`] (**F5** phase 1b).
    pub fraud_contests: Option<FraudContestsHook>,
    /// Persist `proof_pool.bytes` after admit/clear (**M3.23**).
    pub on_proof_pool_change: Option<ProofPoolPersistHook>,
}

/// Parse one request line and return a single JSON-RPC 2.0 response value.
pub fn parse_and_dispatch_serve(
    store: &dyn ChainPersistence,
    chain: &mut Chain,
    pool: &mut Mempool,
    line: &str,
) -> Value {
    parse_and_dispatch_serve_opts(store, chain, pool, None, line, ServeDispatchOpts::default())
}

/// Like [`parse_and_dispatch_serve`] with optional post-admit hooks.
pub fn parse_and_dispatch_serve_opts(
    store: &dyn ChainPersistence,
    chain: &mut Chain,
    pool: &mut Mempool,
    proof_pool: Option<&mut ProofPool>,
    line: &str,
    opts: ServeDispatchOpts,
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
    if !req.is_object() {
        return rpc_error(
            &Value::Null,
            rpc_codes::INVALID_REQUEST,
            "request must be a JSON object",
        );
    }
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
    dispatch_serve_methods(store, chain, pool, proof_pool, &req, &id, &opts)
}

fn dispatch_serve_methods(
    store: &dyn ChainPersistence,
    chain: &mut Chain,
    pool: &mut Mempool,
    proof_pool: Option<&mut ProofPool>,
    req: &Value,
    id: &Value,
    opts: &ServeDispatchOpts,
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

    if let Some(resp) = authorize_rpc_method(method, req, id, opts) {
        return resp;
    }

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
                "mempool_root": hex32(&mempool_root(pool)),
            });
            rpc_success(id, body)
        }
        "list_methods" => {
            if let Err(msg) = reject_nonempty_empty_params(req.get("params"), "list_methods") {
                return rpc_error(id, rpc_codes::INVALID_PARAMS, msg);
            }
            rpc_success(id, serve_rpc_methods_json_result())
        }
        "list_fraud_contests" => {
            if let Err(msg) = reject_nonempty_empty_params(req.get("params"), "list_fraud_contests")
            {
                return rpc_error(id, rpc_codes::INVALID_PARAMS, msg);
            }
            let body = match opts.fraud_contests.as_ref() {
                Some(hook) => hook(),
                None => json!({
                    "configured": false,
                    "contest_count": 0,
                    "contests": [],
                }),
            };
            rpc_success(id, body)
        }
        "get_status" => {
            if let Err(msg) = reject_nonempty_empty_params(req.get("params"), "get_status") {
                return rpc_error(id, rpc_codes::INVALID_PARAMS, msg);
            }
            let tip_height = chain.tip_height().map(|h| json!(h)).unwrap_or(Value::Null);
            let tip_id = chain.tip_id().map(hex32).unwrap_or_else(|| "none".into());
            let proof_pool_json = match proof_pool.as_ref() {
                Some(pool) => json!({
                    "configured": true,
                    "pool_len": pool.len(),
                }),
                None => json!({
                    "configured": false,
                    "pool_len": Value::Null,
                }),
            };
            let rpc_current_in_flight = opts
                .rpc_current_in_flight
                .as_ref()
                .map(|current| json!(current()))
                .unwrap_or(Value::Null);
            let rpc_max_in_flight = opts
                .rpc_max_in_flight
                .map(|max| json!(max))
                .unwrap_or(Value::Null);
            let rpc_max_request_line_bytes = opts
                .rpc_max_request_line_bytes
                .map(|max| json!(max))
                .unwrap_or(Value::Null);
            let rpc_io_timeout_ms = opts
                .rpc_io_timeout_ms
                .map(|timeout| json!(timeout))
                .unwrap_or(Value::Null);
            let rpc_listen_addr = opts
                .rpc_listen_addr
                .as_ref()
                .map(|addr| json!(addr))
                .unwrap_or(Value::Null);
            let rpc_public_bind = opts
                .rpc_public_bind
                .map(|public| json!(public))
                .unwrap_or(Value::Null);
            let p2p_status = opts
                .p2p_status
                .as_ref()
                .map(|status| status())
                .unwrap_or_else(|| {
                    json!({
                        "configured": false,
                        "listen_addr": Value::Null,
                        "peer_count": Value::Null,
                        "session_count": Value::Null,
                        "max_outbound_peers": Value::Null,
                    })
                });
            rpc_success(
                id,
                json!({
                    "service": "mfnd",
                    "status": "ok",
                    "chain": {
                        "genesis_id": hex32(chain.genesis_id()),
                        "tip_height": tip_height,
                        "tip_id": tip_id,
                        "validator_count": chain.validators().len(),
                    },
                    "mempool": {
                        "pool_len": pool.len(),
                        "root": hex32(&mempool_root(pool)),
                    },
                    "proof_pool": proof_pool_json,
                    "rpc": {
                        "auth_enabled": opts.rpc_api_key.is_some(),
                        "protected_method_classes": ["wallet-write", "operator-admin"],
                        "method_count": serve_rpc_method_names().len(),
                        "max_in_flight": rpc_max_in_flight,
                        "current_in_flight": rpc_current_in_flight,
                        "max_request_line_bytes": rpc_max_request_line_bytes,
                        "io_timeout_ms": rpc_io_timeout_ms,
                        "listen_addr": rpc_listen_addr,
                        "public_bind": rpc_public_bind,
                    },
                    "p2p": p2p_status,
                }),
            )
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
                    if matches!(outcome, AdmitOutcome::Fresh { .. }) {
                        if let Some(cb) = &opts.on_fresh_admit {
                            cb(pool);
                        }
                        if let Some(cb) = &opts.on_fresh_tx {
                            cb(&bytes);
                        }
                    }
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
        "submit_storage_proof" => {
            let Some(proof_pool) = proof_pool else {
                return rpc_error(
                    id,
                    rpc_codes::INTERNAL_ERROR,
                    "proof pool not configured on this node",
                );
            };
            let hex_s = match extract_submit_proof_hex(req.get("params")) {
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
            let proof = match decode_storage_proof(&bytes) {
                Ok(p) => p,
                Err(e) => {
                    return rpc_error(
                        id,
                        rpc_codes::INVALID_PARAMS,
                        format!("decode_storage_proof: {e}"),
                    );
                }
            };
            let commit_hash = proof.commit_hash;
            let (prev, next_h) = next_block_context(chain);
            match proof_pool.admit(proof, chain.state(), &prev, next_h) {
                Ok(outcome) => {
                    if let Some(cb) = &opts.on_proof_pool_change {
                        cb(proof_pool);
                    }
                    let body = json!({
                        "commit_hash": hex32(&commit_hash),
                        "pool_len": proof_pool.len(),
                        "outcome": proof_admit_outcome_json(&outcome),
                        "next_height": next_h,
                        "prev_block_id": hex32(&prev),
                    });
                    rpc_success(id, body)
                }
                Err(e) => rpc_error(
                    id,
                    rpc_codes::PROOF_POOL_REJECT,
                    format!("proof pool admit: {e}"),
                ),
            }
        }
        "get_proof_pool" => {
            let Some(proof_pool) = proof_pool else {
                return rpc_error(
                    id,
                    rpc_codes::INTERNAL_ERROR,
                    "proof pool not configured on this node",
                );
            };
            let ids: Vec<String> = proof_pool
                .commit_hashes()
                .into_iter()
                .map(|id| hex32(&id))
                .collect();
            let entries: Vec<Value> = proof_pool
                .entry_keys()
                .into_iter()
                .map(|(commit, op)| {
                    json!({
                        "commit_hash": hex32(&commit),
                        "operator_id": hex32(&op),
                    })
                })
                .collect();
            rpc_success(
                id,
                json!({
                    "pool_len": proof_pool.len(),
                    "commit_hashes": ids,
                    "entries": entries,
                }),
            )
        }
        "clear_proof_pool" => {
            let Some(proof_pool) = proof_pool else {
                return rpc_error(
                    id,
                    rpc_codes::INTERNAL_ERROR,
                    "proof pool not configured on this node",
                );
            };
            let cleared = proof_pool.len();
            proof_pool.clear();
            if let Some(cb) = &opts.on_proof_pool_change {
                cb(proof_pool);
            }
            rpc_success(
                id,
                json!({
                    "cleared": cleared,
                    "pool_len": proof_pool.len(),
                }),
            )
        }
        "get_storage_challenge" => {
            let ch_params = match extract_storage_challenge_params(req.get("params")) {
                Ok(p) => p,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let commit_hash = ch_params.commit_hash;
            let entry = match chain.state().storage.get(&commit_hash) {
                Some(e) => e,
                None => {
                    return rpc_error(
                        id,
                        rpc_codes::INVALID_PARAMS,
                        format!("unknown storage commitment {}", hex32(&commit_hash)),
                    );
                }
            };
            let (prev, next_h) = next_block_context(chain);
            let salted = chain.state().endowment_params.operator_salted_challenges != 0;
            // B-45: with payout pubs → operator-salted index (required for prove).
            // Without pubs on a salted chain → return commitment metadata + unsalted
            // index and `operator_keys_required=true` so backfill/inbox keep working.
            let (idx, operator_identity, operator_keys_required) = if salted {
                match (ch_params.operator_view_pub, ch_params.operator_spend_pub) {
                    (Some(view), Some(spend)) => {
                        if !operator_payout_is_valid(&view, &spend) {
                            return rpc_error(
                                id,
                                rpc_codes::INVALID_PARAMS,
                                "invalid operator payout keys",
                            );
                        }
                        let op_id = operator_identity_from_payout(&view, &spend);
                        let idx = chunk_index_for_operator_challenge(
                            &prev,
                            next_h,
                            &commit_hash,
                            &op_id,
                            entry.commit.num_chunks,
                        );
                        (idx, Some(op_id), false)
                    }
                    (None, None) => {
                        let idx = chunk_index_for_challenge(
                            &prev,
                            next_h,
                            &commit_hash,
                            entry.commit.num_chunks,
                        );
                        (idx, None, true)
                    }
                    _ => {
                        return rpc_error(
                            id,
                            rpc_codes::INVALID_PARAMS,
                            "params.view_pub_hex and params.spend_pub_hex must both be set or both omitted",
                        );
                    }
                }
            } else {
                let idx =
                    chunk_index_for_challenge(&prev, next_h, &commit_hash, entry.commit.num_chunks);
                (idx, None, false)
            };
            let mut body = json!({
                "commitment_hash": hex32(&commit_hash),
                "commitment_wire_hex": hex::encode(encode_storage_commitment(&entry.commit)),
                "data_root": hex32(&entry.commit.data_root),
                "size_bytes": entry.commit.size_bytes,
                "replication": entry.commit.replication,
                "num_chunks": entry.commit.num_chunks,
                "chunk_size": entry.commit.chunk_size,
                "next_height": next_h,
                "next_slot": next_h,
                "prev_block_id": hex32(&prev),
                "chunk_index": idx,
                "operator_salted": salted,
                "operator_keys_required": operator_keys_required,
            });
            if let Some(op_id) = operator_identity {
                if let Some(obj) = body.as_object_mut() {
                    obj.insert("operator_identity".into(), json!(hex32(&op_id)));
                }
            }
            rpc_success(id, body)
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
            rpc_success(id, header_row_json(block, height))
        }
        "get_block_headers" => {
            let (from_h, to_h) = match extract_height_range_param(req.get("params")) {
                Ok(r) => r,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let blocks = match read_validated_blocks_for_height(store, chain, to_h, id) {
                Ok(b) => b,
                Err(resp) => return resp,
            };
            let mut headers = Vec::with_capacity((to_h - from_h + 1) as usize);
            for h in from_h..=to_h {
                let block = &blocks[(h - 1) as usize];
                headers.push(header_row_json(block, h));
            }
            rpc_success(
                id,
                json!({
                    "from_height": from_h,
                    "to_height": to_h,
                    "genesis_id": hex32(chain.genesis_id()),
                    "headers": headers,
                }),
            )
        }
        "get_block_txs" => {
            let height = match extract_height_param(req.get("params")) {
                Ok(h) => h,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let blocks = match read_validated_blocks_for_height(store, chain, height, id) {
                Ok(b) => b,
                Err(resp) => return resp,
            };
            let block = &blocks[(height - 1) as usize];
            let txs: Vec<Value> = block
                .txs
                .iter()
                .enumerate()
                .map(|(i, tx)| {
                    let wire = encode_transaction(tx);
                    let tid = tx_id(tx);
                    json!({
                        "tx_index": i,
                        "tx_hex": hex::encode(&wire),
                        "tx_id": hex32(&tid),
                    })
                })
                .collect();
            rpc_success(
                id,
                json!({
                    "height": height,
                    "block_id": hex32(&block_id(&block.header)),
                    "txs": txs,
                }),
            )
        }
        "get_chain_params" => {
            if let Err(msg) = reject_nonempty_empty_params(req.get("params"), "get_chain_params") {
                return rpc_error(id, rpc_codes::INVALID_PARAMS, msg);
            }
            rpc_success(id, chain_params_json(chain))
        }
        "get_light_snapshot" => {
            let height = match extract_optional_height_param(req.get("params")) {
                Ok(h) => h,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let tip_h = chain.tip_height().unwrap_or(0);
            let snapshot_height = height.unwrap_or(tip_h);
            let checkpoint_hex = match height {
                None => light_snapshot_hex(chain),
                Some(h) if h == tip_h => light_snapshot_hex(chain),
                Some(h) => {
                    let genesis = match opts.genesis.as_deref() {
                        Some(g) => g,
                        None => {
                            return rpc_error(
                                id,
                                rpc_codes::INVALID_PARAMS,
                                "get_light_snapshot at height requires node genesis (internal)",
                            );
                        }
                    };
                    match light_snapshot_replay_at_height(store, chain, genesis, h) {
                        Ok(hex) => hex,
                        Err(msg) => {
                            if msg.contains("exceeds chain tip_height") {
                                return rpc_error(id, rpc_codes::INVALID_PARAMS, msg);
                            }
                            return rpc_error(id, rpc_codes::BLOCK_LOG_STORE, msg);
                        }
                    }
                }
            };
            let summary = match light_checkpoint_summary_json(&checkpoint_hex) {
                Ok(s) => s,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let summary = match &opts.p2p_anchor_peers {
                Some(hook) => {
                    let peers = hook();
                    if peers.is_empty() {
                        summary
                    } else if let Some(obj) = summary.as_object().cloned() {
                        let mut merged = obj;
                        merged.insert("anchor_peers".into(), json!(peers));
                        Value::Object(merged)
                    } else {
                        summary
                    }
                }
                None => summary,
            };
            rpc_success(
                id,
                json!({
                    "tip_height": snapshot_height,
                    "checkpoint_hex": checkpoint_hex,
                    "summary": summary,
                }),
            )
        }
        "get_light_checkpoint_summary" => {
            let checkpoint_hex = match extract_checkpoint_hex_param(req.get("params")) {
                Ok(h) => h,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            match light_checkpoint_summary_json(&checkpoint_hex) {
                Ok(summary) => rpc_success(id, summary),
                Err(msg) => rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            }
        }
        "get_light_follow" => {
            let (from_h, to_h) = match extract_height_range_param(req.get("params")) {
                Ok(r) => r,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let blocks = match read_validated_blocks_for_height(store, chain, to_h, id) {
                Ok(b) => b,
                Err(resp) => return resp,
            };
            let mut rows = Vec::with_capacity((to_h - from_h + 1) as usize);
            for h in from_h..=to_h {
                let block = &blocks[(h - 1) as usize];
                rows.push(light_follow_row_json(block, h));
            }
            rpc_success(
                id,
                json!({
                    "from_height": from_h,
                    "to_height": to_h,
                    "genesis_id": hex32(chain.genesis_id()),
                    "rows": rows,
                    "source": "local",
                }),
            )
        }
        "get_light_follow_p2p" => {
            let (peer, from_h, to_h) = match extract_peer_light_follow_params(req.get("params")) {
                Ok(r) => r,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let fetch = match opts.p2p_light_follow.as_ref() {
                Some(f) => f,
                None => {
                    return rpc_error(
                        id,
                        rpc_codes::INVALID_PARAMS,
                        "get_light_follow_p2p requires mfnd serve P2P fetch (internal)",
                    );
                }
            };
            match fetch(peer.as_str(), from_h, to_h) {
                Ok(page) => rpc_success(id, page),
                Err(msg) => rpc_error(id, rpc_codes::BLOCK_LOG_STORE, msg),
            }
        }
        "get_light_follow_quorum_p2p" => {
            let (peers, from_h, to_h) = match extract_peers_light_follow_params(req.get("params")) {
                Ok(r) => r,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let fetch = match opts.p2p_light_follow_quorum.as_ref() {
                Some(f) => f,
                None => {
                    return rpc_error(
                        id,
                        rpc_codes::INVALID_PARAMS,
                        "get_light_follow_quorum_p2p requires mfnd serve P2P quorum (internal)",
                    );
                }
            };
            match fetch(peers.as_slice(), from_h, to_h) {
                Ok(page) => rpc_success(id, page),
                Err(msg) => rpc_error(id, rpc_codes::BLOCK_LOG_STORE, msg),
            }
        }
        "get_block_evolution" => {
            let height = match extract_height_param(req.get("params")) {
                Ok(h) => h,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let blocks = match read_validated_blocks_for_height(store, chain, height, id) {
                Ok(b) => b,
                Err(resp) => return resp,
            };
            let block = &blocks[(height - 1) as usize];
            let slashings: Vec<Value> = block
                .slashings
                .iter()
                .map(|ev| json!({ "evidence_hex": hex::encode(encode_slash_evidence(ev, block.header.version)) }))
                .collect();
            let bond_ops: Vec<Value> = block
                .bond_ops
                .iter()
                .map(|op| json!({ "op_hex": hex::encode(encode_bond_op(op)) }))
                .collect();
            rpc_success(
                id,
                json!({
                    "height": height,
                    "slashings": slashings,
                    "bond_ops": bond_ops,
                }),
            )
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
            let mut rows: Vec<&AuthorshipClaimRecord> = chain
                .state()
                .claims
                .iter()
                .filter(|((data_root, _), _)| *data_root == root)
                .map(|(_, rec)| rec)
                .collect();
            rows.sort_by(|a, b| {
                a.height
                    .cmp(&b.height)
                    .then_with(|| a.tx_id.cmp(&b.tx_id))
                    .then_with(|| a.tx_index.cmp(&b.tx_index))
                    .then_with(|| a.claim_index.cmp(&b.claim_index))
            });
            let claims: Vec<Value> = rows.into_iter().map(authorship_claim_record_json).collect();
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
        "list_utxos" => {
            let (limit, offset) = match extract_list_utxos_params(req.get("params")) {
                Ok(x) => x,
                Err(msg) => return rpc_error(id, rpc_codes::INVALID_PARAMS, msg),
            };
            let st = chain.state();
            let total = st.utxo.len();
            let mut rows: Vec<(&[u8; 32], &UtxoEntry)> = st.utxo.iter().collect();
            rows.sort_by(|(ka, ea), (kb, eb)| ea.height.cmp(&eb.height).then_with(|| ka.cmp(kb)));
            let utxos: Vec<Value> = rows
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|(k, e)| json_utxo_row(k, e))
                .collect();
            rpc_success(
                id,
                json!({
                    "utxos": utxos,
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

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_store::ChainStore;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use mfn_bls::bls_keygen_from_seed;
    use mfn_consensus::{
        block_header_bytes, build_coinbase, decode_block, decode_block_header, emission_at_height,
        ConsensusParams, GenesisConfig, PayoutAddress, Validator, ValidatorPayout,
        ValidatorSecrets, DEFAULT_EMISSION_PARAMS, TEST_CONSENSUS_PARAMS,
    };
    use mfn_crypto::stealth::stealth_gen;
    use mfn_crypto::vrf::vrf_keygen_from_seed;
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    use mfn_runtime::{
        demo_genesis, produce_solo_block, BlockInputs, Chain, ChainConfig, MempoolConfig,
    };

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
            ..TEST_CONSENSUS_PARAMS
        };
        let gc = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            initial_storage_operators: Vec::new(),
            validators: vec![v0.clone()],
            params,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
            header_version: 1,
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
            storage_operator_ops: Vec::new(),
        }
    }

    fn test_store_chain_pool(test_name: &str) -> (ChainStore, Chain, Mempool, PathBuf) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mfn-rpc-test-{test_name}-{}-{nanos}",
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
    fn rpc_non_object_request_is_invalid_request() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_non_object");
        let v = parse_and_dispatch_serve(&store, &mut c, &mut p, r#"["get_tip"]"#);
        assert_eq!(v["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_REQUEST);
        assert_eq!(
            v["error"]["message"],
            json!("request must be a JSON object")
        );
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
    fn rpc_get_chain_params_genesis_defaults() {
        use mfn_consensus::{
            emission::{DEFAULT_EMISSION_PARAMS, MFN_BASE, MFN_DECIMALS},
            DEFAULT_BONDING_PARAMS, DEFAULT_CONSENSUS_PARAMS,
        };
        use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_chain_params");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_chain_params","id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["tip_height"], json!(0));
        assert_eq!(
            v["result"]["emission"]["fee_to_treasury_bps"],
            json!(DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps)
        );
        assert_eq!(
            v["result"]["emission"]["subsidy_to_treasury_bps"],
            json!(DEFAULT_EMISSION_PARAMS.subsidy_to_treasury_bps)
        );
        assert_eq!(
            v["result"]["endowment"]["min_replication"],
            json!(DEFAULT_ENDOWMENT_PARAMS.min_replication)
        );
        assert_eq!(
            v["result"]["endowment"]["require_endowment_range_proof"],
            json!(DEFAULT_ENDOWMENT_PARAMS.require_endowment_range_proof)
        );
        assert_eq!(v["result"]["mfn_decimals"], json!(MFN_DECIMALS));
        assert_eq!(v["result"]["mfn_base"], json!(MFN_BASE));
        assert_eq!(
            v["result"]["bonding"]["unbond_delay_heights"],
            json!(DEFAULT_BONDING_PARAMS.unbond_delay_heights)
        );
        assert!(v["result"]["validators"].is_array());
        assert_eq!(
            v["result"]["consensus"]["quorum_stake_bps"],
            json!(DEFAULT_CONSENSUS_PARAMS.quorum_stake_bps)
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_chain_params_rejects_nonempty_params() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_chain_params_bad");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_chain_params","params":{"x":1},"id":2}"#,
        );
        assert_eq!(v["error"]["code"], rpc_codes::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("get_chain_params"));
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
            "mfn-rpc-test-rpc_gb_bad_log-{}-{nanos}",
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
            "mfn-rpc-test-rpc_gbh_ok-{}-{nanos}",
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
        assert_eq!(
            vh["result"]["prev_block_id"]
                .as_str()
                .expect("prev_block_id"),
            hex32(&dec_hdr.prev_hash)
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
    fn rpc_get_block_headers_linkage_and_batch() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mfn-rpc-test-rpc_gbh_batch-{}-{nanos}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let store = ChainStore::new(&root);

        let (mut chain, producer, secrets, params, cfg) = solo_chain_fixture();
        for h in 1..=3u32 {
            let inputs = coinbase_inputs(&producer, h);
            let block =
                produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("solo");
            chain.apply(&block).expect("apply");
            store.append_block(&block).expect("append");
        }
        store.save(&chain).expect("save");

        let mut chain_loaded = store.load_or_genesis(cfg).expect("reload");
        let mut pool = Mempool::new(MempoolConfig::default());
        let v = parse_and_dispatch_serve(
            &store,
            &mut chain_loaded,
            &mut pool,
            r#"{"jsonrpc":"2.0","method":"get_block_headers","params":{"from_height":1,"to_height":3},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        let headers = v["result"]["headers"].as_array().expect("headers");
        assert_eq!(headers.len(), 3);
        assert_eq!(
            v["result"]["genesis_id"].as_str().expect("genesis_id"),
            hex32(chain_loaded.genesis_id())
        );
        assert_eq!(
            headers[1]["prev_block_id"].as_str().unwrap(),
            headers[0]["block_id"].as_str().unwrap()
        );
        assert_eq!(
            headers[2]["prev_block_id"].as_str().unwrap(),
            headers[1]["block_id"].as_str().unwrap()
        );
        assert_eq!(
            headers[0]["prev_block_id"].as_str().unwrap(),
            hex32(chain_loaded.genesis_id())
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_block_txs_matches_block_tx_count() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mfn-rpc-test-rpc_gbtx-{}-{nanos}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let store = ChainStore::new(&root);

        let (mut chain, producer, secrets, params, cfg) = solo_chain_fixture();
        let inputs = coinbase_inputs(&producer, 1);
        let block = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("solo");
        let tx_count = block.txs.len();
        chain.apply(&block).expect("apply");
        store.append_block(&block).expect("append");
        store.save(&chain).expect("save");

        let mut chain_loaded = store.load_or_genesis(cfg).expect("reload");
        let mut pool = Mempool::new(MempoolConfig::default());
        let v = parse_and_dispatch_serve(
            &store,
            &mut chain_loaded,
            &mut pool,
            r#"{"jsonrpc":"2.0","method":"get_block_txs","params":{"height":1},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["txs"].as_array().unwrap().len(), tx_count);
        assert!(v["result"]["txs"][0]["tx_hex"].as_str().unwrap().len() > 2);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_light_snapshot_matches_checkpoint_encoder() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_light_snap");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_light_snapshot","id":0}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["tip_height"], json!(0));
        assert_eq!(
            v["result"]["checkpoint_hex"].as_str().unwrap(),
            light_snapshot_hex(&c)
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_light_snapshot_includes_anchor_peers_when_hook_set() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_light_snap_anchor");
        let hook: P2pAnchorPeersHook =
            Arc::new(|| vec!["203.0.113.10:8333".into(), "203.0.113.11:8334".into()]);
        let v = parse_and_dispatch_serve_opts(
            &store,
            &mut c,
            &mut p,
            None,
            r#"{"jsonrpc":"2.0","method":"get_light_snapshot","id":0}"#,
            ServeDispatchOpts {
                p2p_anchor_peers: Some(hook),
                ..ServeDispatchOpts::default()
            },
        );
        assert_eq!(v["error"], Value::Null);
        let anchors = v["result"]["summary"]["anchor_peers"]
            .as_array()
            .expect("anchor_peers");
        assert_eq!(anchors.len(), 2);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_light_checkpoint_summary_matches_snapshot_embedded_summary() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_light_sum");
        let snap = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_light_snapshot","id":0}"#,
        );
        assert_eq!(snap["error"], Value::Null);
        let checkpoint_hex = snap["result"]["checkpoint_hex"].as_str().unwrap();
        let embedded = &snap["result"]["summary"];
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            &format!(
                r#"{{"jsonrpc":"2.0","method":"get_light_checkpoint_summary","params":{{"checkpoint_hex":"{checkpoint_hex}"}},"id":1}}"#
            ),
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(&v["result"], embedded);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_light_snapshot_rejects_unknown_param_key() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_light_snap_rej");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"get_light_snapshot","params":{"x":1},"id":1}"#,
        );
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("params.height"));
        fs::remove_dir_all(&root).ok();
    }

    fn dispatch_with_genesis(
        store: &ChainStore,
        chain: &mut Chain,
        pool: &mut Mempool,
        line: &str,
        genesis: Arc<GenesisConfig>,
    ) -> Value {
        parse_and_dispatch_serve_opts(
            store,
            chain,
            pool,
            None,
            line,
            ServeDispatchOpts {
                genesis: Some(genesis),
                ..ServeDispatchOpts::default()
            },
        )
    }

    #[test]
    fn rpc_get_light_snapshot_at_height_replay_matches_tip_snapshot() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mfn-rpc-test-rpc_lsnap_h-{}-{nanos}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let store = ChainStore::new(&root);

        let (mut chain, producer, secrets, params, cfg) = solo_chain_fixture();
        let genesis = Arc::new(cfg.genesis.clone());
        let inputs = coinbase_inputs(&producer, 1);
        let block = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("solo");
        chain.apply(&block).expect("apply");
        store.append_block(&block).expect("append");
        store.save(&chain).expect("save");

        let mut chain_loaded = store.load_or_genesis(cfg).expect("reload");
        let mut pool = Mempool::new(MempoolConfig::default());
        let v = dispatch_with_genesis(
            &store,
            &mut chain_loaded,
            &mut pool,
            r#"{"jsonrpc":"2.0","method":"get_light_snapshot","params":{"height":1},"id":1}"#,
            Arc::clone(&genesis),
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["tip_height"], json!(1));
        assert_eq!(
            v["result"]["checkpoint_hex"].as_str().unwrap(),
            light_snapshot_hex(&chain_loaded)
        );
        let v0 = dispatch_with_genesis(
            &store,
            &mut chain_loaded,
            &mut pool,
            r#"{"jsonrpc":"2.0","method":"get_light_snapshot","params":{"height":0},"id":2}"#,
            genesis,
        );
        assert_eq!(v0["error"], Value::Null);
        assert_eq!(v0["result"]["tip_height"], json!(0));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_light_follow_batch_matches_per_block_evolution() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mfn-rpc-test-rpc_lfol-{}-{nanos}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let store = ChainStore::new(&root);

        let (mut chain, producer, secrets, params, cfg) = solo_chain_fixture();
        let inputs = coinbase_inputs(&producer, 1);
        let block = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("solo");
        chain.apply(&block).expect("apply");
        store.append_block(&block).expect("append");
        store.save(&chain).expect("save");

        let mut chain_loaded = store.load_or_genesis(cfg).expect("reload");
        let mut pool = Mempool::new(MempoolConfig::default());
        let v = parse_and_dispatch_serve(
            &store,
            &mut chain_loaded,
            &mut pool,
            r#"{"jsonrpc":"2.0","method":"get_light_follow","params":{"from_height":1,"to_height":1},"id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["rows"].as_array().unwrap().len(), 1);
        assert_eq!(v["result"]["rows"][0]["slashings"], json!([]));
        assert_eq!(v["result"]["rows"][0]["bond_ops"], json!([]));
        assert!(v["result"]["rows"][0]["header_hex"].as_str().unwrap().len() > 2);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_block_evolution_solo_block_empty_events() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mfn-rpc-test-rpc_evo-{}-{nanos}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let store = ChainStore::new(&root);

        let (mut chain, producer, secrets, params, cfg) = solo_chain_fixture();
        let inputs = coinbase_inputs(&producer, 1);
        let block = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("solo");
        chain.apply(&block).expect("apply");
        store.append_block(&block).expect("append");
        store.save(&chain).expect("save");

        let mut chain_loaded = store.load_or_genesis(cfg).expect("reload");
        let mut pool = Mempool::new(MempoolConfig::default());
        let v = parse_and_dispatch_serve(
            &store,
            &mut chain_loaded,
            &mut pool,
            r#"{"jsonrpc":"2.0","method":"get_block_evolution","params":{"height":1},"id":2}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["height"], json!(1));
        assert_eq!(v["result"]["slashings"], json!([]));
        assert_eq!(v["result"]["bond_ops"], json!([]));
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
        let classes = v["result"]["method_classes"]
            .as_object()
            .expect("method_classes object");
        assert_eq!(classes["get_tip"], json!("public-safe"));
        assert_eq!(classes["get_status"], json!("public-safe"));
        assert_eq!(classes["submit_tx"], json!("wallet-write"));
        assert_eq!(classes["save_checkpoint"], json!("operator-admin"));
        for expected in [
            "clear_mempool",
            "clear_proof_pool",
            "get_block",
            "get_block_header",
            "get_block_evolution",
            "get_block_headers",
            "get_block_txs",
            "get_chain_params",
            "get_light_snapshot",
            "get_light_checkpoint_summary",
            "get_light_follow",
            "get_light_follow_p2p",
            "get_claims_by_pubkey",
            "get_claims_for",
            "get_checkpoint",
            "get_mempool",
            "get_mempool_tx",
            "get_proof_pool",
            "get_storage_challenge",
            "get_status",
            "get_tip",
            "list_data_roots_with_claims",
            "list_fraud_contests",
            "list_methods",
            "list_recent_claims",
            "list_recent_uploads",
            "list_utxos",
            "remove_mempool_tx",
            "save_checkpoint",
            "submit_storage_proof",
            "submit_tx",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
        assert_eq!(names.len(), 32);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_status_returns_machine_readable_snapshot() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_status");
        let v = parse_and_dispatch_serve_opts(
            &store,
            &mut c,
            &mut p,
            None,
            r#"{"jsonrpc":"2.0","method":"get_status","id":"s"}"#,
            ServeDispatchOpts {
                rpc_api_key: Some("secret".into()),
                ..ServeDispatchOpts::default()
            },
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["id"], json!("s"));
        assert_eq!(v["result"]["service"], json!("mfnd"));
        assert_eq!(v["result"]["status"], json!("ok"));
        assert_eq!(v["result"]["chain"]["tip_height"], json!(0));
        assert_eq!(v["result"]["mempool"]["pool_len"], json!(0));
        assert_eq!(v["result"]["proof_pool"]["configured"], json!(false));
        assert_eq!(v["result"]["rpc"]["auth_enabled"], json!(true));
        assert_eq!(v["result"]["rpc"]["method_count"], json!(32));
        assert_eq!(v["result"]["rpc"]["max_in_flight"], Value::Null);
        assert_eq!(v["result"]["rpc"]["current_in_flight"], Value::Null);
        assert_eq!(v["result"]["rpc"]["max_request_line_bytes"], Value::Null);
        assert_eq!(v["result"]["rpc"]["io_timeout_ms"], Value::Null);
        assert_eq!(v["result"]["rpc"]["listen_addr"], Value::Null);
        assert_eq!(v["result"]["rpc"]["public_bind"], Value::Null);
        assert_eq!(v["result"]["p2p"]["configured"], json!(false));
        assert_eq!(v["result"]["p2p"]["listen_addr"], Value::Null);
        assert_eq!(v["result"]["p2p"]["peer_count"], Value::Null);
        assert_eq!(v["result"]["p2p"]["session_count"], Value::Null);
        assert_eq!(v["result"]["p2p"]["max_outbound_peers"], Value::Null);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_status_reports_runtime_rpc_connection_limits() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_status_limits");
        let current = Arc::new(|| 3usize);
        let v = parse_and_dispatch_serve_opts(
            &store,
            &mut c,
            &mut p,
            None,
            r#"{"jsonrpc":"2.0","method":"get_status","id":"s"}"#,
            ServeDispatchOpts {
                rpc_max_in_flight: Some(9),
                rpc_current_in_flight: Some(current),
                rpc_max_request_line_bytes: Some(1_048_576),
                rpc_io_timeout_ms: Some(30_000),
                rpc_listen_addr: Some("127.0.0.1:18731".into()),
                rpc_public_bind: Some(false),
                ..ServeDispatchOpts::default()
            },
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["rpc"]["max_in_flight"], json!(9));
        assert_eq!(v["result"]["rpc"]["current_in_flight"], json!(3));
        assert_eq!(
            v["result"]["rpc"]["max_request_line_bytes"],
            json!(1_048_576)
        );
        assert_eq!(v["result"]["rpc"]["io_timeout_ms"], json!(30_000));
        assert_eq!(v["result"]["rpc"]["listen_addr"], json!("127.0.0.1:18731"));
        assert_eq!(v["result"]["rpc"]["public_bind"], json!(false));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_get_status_reports_runtime_p2p_snapshot() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_status_p2p");
        let status = Arc::new(|| {
            json!({
                "configured": true,
                "listen_addr": "127.0.0.1:19000",
                "peer_count": 3,
                "session_count": 2,
                "max_outbound_peers": 8,
            })
        });
        let v = parse_and_dispatch_serve_opts(
            &store,
            &mut c,
            &mut p,
            None,
            r#"{"jsonrpc":"2.0","method":"get_status","id":"s"}"#,
            ServeDispatchOpts {
                p2p_status: Some(status),
                ..ServeDispatchOpts::default()
            },
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["p2p"]["configured"], json!(true));
        assert_eq!(v["result"]["p2p"]["listen_addr"], json!("127.0.0.1:19000"));
        assert_eq!(v["result"]["p2p"]["peer_count"], json!(3));
        assert_eq!(v["result"]["p2p"]["session_count"], json!(2));
        assert_eq!(v["result"]["p2p"]["max_outbound_peers"], json!(8));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_api_key_allows_public_methods_without_key() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_auth_public");
        let v = parse_and_dispatch_serve_opts(
            &store,
            &mut c,
            &mut p,
            None,
            r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#,
            ServeDispatchOpts {
                rpc_api_key: Some("secret".into()),
                ..ServeDispatchOpts::default()
            },
        );
        assert_eq!(v["error"], Value::Null);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_api_key_rejects_wallet_write_without_key() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_auth_wallet");
        let v = parse_and_dispatch_serve_opts(
            &store,
            &mut c,
            &mut p,
            None,
            r#"{"jsonrpc":"2.0","method":"submit_tx","params":["00"],"id":1}"#,
            ServeDispatchOpts {
                rpc_api_key: Some("secret".into()),
                ..ServeDispatchOpts::default()
            },
        );
        assert_eq!(v["error"]["code"], rpc_codes::AUTH_REQUIRED);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("wallet-write"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_api_key_rejects_operator_admin_with_wrong_key() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_auth_admin_bad");
        let v = parse_and_dispatch_serve_opts(
            &store,
            &mut c,
            &mut p,
            None,
            r#"{"jsonrpc":"2.0","method":"clear_mempool","api_key":"wrong","id":1}"#,
            ServeDispatchOpts {
                rpc_api_key: Some("secret".into()),
                ..ServeDispatchOpts::default()
            },
        );
        assert_eq!(v["error"]["code"], rpc_codes::AUTH_REQUIRED);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("operator-admin"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_api_key_allows_operator_admin_with_auth_object_key() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_auth_admin_ok");
        let v = parse_and_dispatch_serve_opts(
            &store,
            &mut c,
            &mut p,
            None,
            r#"{"jsonrpc":"2.0","method":"clear_mempool","auth":{"api_key":"secret"},"id":1}"#,
            ServeDispatchOpts {
                rpc_api_key: Some("secret".into()),
                ..ServeDispatchOpts::default()
            },
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["pool_len"], json!(0));
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
        assert_eq!(v["result"]["methods"].as_array().unwrap().len(), 32);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_fraud_contests_unconfigured_when_hook_absent() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_fraud_contests_off");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_fraud_contests","id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["configured"], json!(false));
        assert_eq!(v["result"]["contest_count"], json!(0));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_fraud_contests_returns_hook_snapshot() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_fraud_contests_on");
        let hook: FraudContestsHook = Arc::new(|| {
            json!({
                "configured": true,
                "contest_count": 1,
                "contests": [{
                    "block_id": "aa".repeat(32),
                    "height": 7,
                    "producer_index": 2,
                    "label": "valid_fraud:TxRoot:height=7",
                }],
            })
        });
        let v = parse_and_dispatch_serve_opts(
            &store,
            &mut c,
            &mut p,
            None,
            r#"{"jsonrpc":"2.0","method":"list_fraud_contests","id":1}"#,
            ServeDispatchOpts {
                fraud_contests: Some(hook),
                ..ServeDispatchOpts::default()
            },
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["contest_count"], json!(1));
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
    fn rpc_list_utxos_empty_genesis() {
        let (store, mut c, mut p, root) = test_store_chain_pool("rpc_lutxo_empty");
        let v = parse_and_dispatch_serve(
            &store,
            &mut c,
            &mut p,
            r#"{"jsonrpc":"2.0","method":"list_utxos","id":1}"#,
        );
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["result"]["utxos"], json!([]));
        assert_eq!(v["result"]["total"], json!(0));
        assert_eq!(v["result"]["offset"], json!(0));
        assert_eq!(v["result"]["limit"], json!(500));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rpc_list_utxos_after_solo_coinbase() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mfn-rpc-test-rpc_lutxo_cb-{}-{nanos}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let store = ChainStore::new(&root);
        let (mut chain, producer, secrets, params, _cfg) = solo_chain_fixture();
        let inputs = coinbase_inputs(&producer, 1);
        let block = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("solo");
        chain.apply(&block).expect("apply");
        let mut pool = Mempool::new(MempoolConfig::default());
        let v = parse_and_dispatch_serve(
            &store,
            &mut chain,
            &mut pool,
            r#"{"jsonrpc":"2.0","method":"list_utxos","params":{},"id":2}"#,
        );
        assert_eq!(v["error"], Value::Null);
        let utxos = v["result"]["utxos"].as_array().expect("utxos");
        assert!(
            !utxos.is_empty(),
            "coinbase should create at least one UTXO"
        );
        assert_eq!(v["result"]["total"].as_u64().unwrap(), utxos.len() as u64);
        let row = &utxos[0];
        assert_eq!(row["height"], json!(1));
        assert_eq!(row["one_time_addr_hex"].as_str().unwrap().len(), 64);
        assert_eq!(row["commit_hex"].as_str().unwrap().len(), 64);
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
