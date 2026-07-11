//! Blocking TCP `mfnd serve`: one UTF-8 JSON line per connection, optional P2P listeners.
//!
//! JSON-RPC parsing and method dispatch are in [`mfn_rpc`]. P2P framing and handshake
//! threads are in [`mfn_net::serve`].

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use mfn_consensus::GenesisConfig;
use mfn_net::serve::{
    spawn_inbound_handshake_loop, spawn_outbound_dial, BlockSyncApplierHook, BlockSyncHook,
    FanoutPeerSetHook, HidCounter, InboundP2pLoop, LightFollowHook, OutboundP2pDial,
    P2pSessionHooks, TipSnapshot,
};
use mfn_net::FanoutPeerSet;
use mfn_rpc::{parse_and_dispatch_serve_opts, ServeDispatchOpts};
use mfn_runtime::{
    mempool_root, Chain, ChainConfig, Mempool, MempoolConfig, ProofPool, ProofPoolConfig,
};
use mfn_store::{
    load_mempool, load_or_genesis_replaying_block_log, load_proof_pool, save_mempool,
    save_proof_pool, ChainPersistence,
};
use serde_json::{json, Value};

use crate::p2p_block_sync::P2pBlockSyncHandler;
use crate::p2p_fanout::{
    spawn_committee_catch_up_loop, spawn_peer_diversity_redial_loop, spawn_reconnect_saved_peers,
    CommitteeCatchUpLoop, P2pPeerSet, PeerDiversityRedialLoop, ReconnectPeersBoot,
};
use crate::p2p_gossip::P2pGossipHandler;
use crate::p2p_reconnect_plan::is_self_peer_addr;
use crate::p2p_repair_sweep::{
    repair_interval_ms_from_env, repair_threshold_slots_from_env, spawn_repair_sweep_loop,
    RepairSweepLoop, DEFAULT_REPAIR_INTERVAL_MS,
};
use crate::role_topology::{
    chain_validator_is_storage_operator, observer_loopback_rpc_hint_warning,
    pm23_hard_fail_enabled, pm23_operator_manifest_env_warnings, role_topology_colocation_warning,
    validator_index_from_env,
};
use crate::runner::{
    produce_config_from_env, spawn_slot_producer_loop, ProductionEngine, ProductionEngineDeps,
};

type P2pServeHooks = (
    Option<TipSnapshot>,
    Option<HidCounter>,
    Option<mfn_net::GossipHook>,
    Option<BlockSyncHook>,
    Option<LightFollowHook>,
    Option<BlockSyncApplierHook>,
    Option<Arc<P2pPeerSet>>,
    Option<mfn_net::ProductionHook>,
);

/// Maximum accepted newline-delimited JSON-RPC request line.
///
/// `mfnd serve` intentionally handles one request per TCP connection. Cap the line before
/// dispatch so malformed clients cannot force unbounded memory growth before JSON parsing.
pub(crate) const MFND_RPC_MAX_REQUEST_LINE_BYTES: u64 = 1_048_576;

/// Per-connection JSON-RPC read/write timeout.
pub(crate) const MFND_RPC_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum accepted JSON-RPC connections being handled at once.
pub(crate) const MFND_RPC_MAX_IN_FLIGHT_CONNECTIONS: usize = 64;

const MFND_RPC_MAX_IN_FLIGHT_ENV: &str = "MFND_RPC_MAX_IN_FLIGHT";

fn rpc_max_in_flight_from_env() -> Result<usize, String> {
    match std::env::var(MFND_RPC_MAX_IN_FLIGHT_ENV) {
        Ok(raw) => {
            let n: usize = raw
                .trim()
                .parse()
                .map_err(|_| format!("{MFND_RPC_MAX_IN_FLIGHT_ENV} must be a positive integer"))?;
            if n == 0 {
                return Err(format!("{MFND_RPC_MAX_IN_FLIGHT_ENV} must be at least 1"));
            }
            Ok(n)
        }
        Err(std::env::VarError::NotPresent) => Ok(MFND_RPC_MAX_IN_FLIGHT_CONNECTIONS),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{MFND_RPC_MAX_IN_FLIGHT_ENV} must be valid UTF-8"))
        }
    }
}

fn configure_rpc_stream(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(MFND_RPC_IO_TIMEOUT))
        .map_err(|e| format!("mfnd serve: set RPC read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(MFND_RPC_IO_TIMEOUT))
        .map_err(|e| format!("mfnd serve: set RPC write timeout: {e}"))
}

fn write_line(stream: &mut TcpStream, v: &Value) -> Result<(), String> {
    let s = v.to_string();
    writeln!(stream, "{s}").map_err(|e| format!("mfnd serve: write response: {e}"))
}

fn write_rpc_busy_response(stream: &mut TcpStream, rpc_max_in_flight: usize) -> Result<(), String> {
    configure_rpc_stream(stream)?;
    let resp = mfn_rpc::rpc_error(
        &Value::Null,
        mfn_rpc::rpc_codes::INTERNAL_ERROR,
        format!("RPC server busy: maximum in-flight connections is {rpc_max_in_flight}"),
    );
    log_rpc_request_outcome("unknown", &resp, Duration::ZERO);
    write_line(stream, &resp)
}

struct RpcInFlightPermit {
    counter: Arc<AtomicUsize>,
}

impl Drop for RpcInFlightPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_rpc_permit(counter: &Arc<AtomicUsize>, max: usize) -> Option<RpcInFlightPermit> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= max {
            return None;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Some(RpcInFlightPermit {
                    counter: Arc::clone(counter),
                });
            }
            Err(next) => current = next,
        }
    }
}

fn rpc_log_token(s: &str) -> String {
    let token: String = s
        .chars()
        .take(64)
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '.' | ':' => c,
            _ => '_',
        })
        .collect();
    if token.is_empty() {
        "unknown".to_string()
    } else {
        token
    }
}

fn rpc_method_for_log(line: &str) -> String {
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(rpc_log_token))
        .unwrap_or_else(|| "unknown".to_string())
}

fn log_rpc_request_outcome(method: &str, resp: &Value, elapsed: Duration) {
    let error_code = resp
        .get("error")
        .filter(|e| !e.is_null())
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_i64());
    let result = if error_code.is_some() { "error" } else { "ok" };
    let code = error_code
        .map(|c| c.to_string())
        .unwrap_or_else(|| "none".to_string());
    println!(
        "mfnd_rpc_request method={} result={} error_code={} elapsed_ms={}",
        method,
        result,
        code,
        elapsed.as_millis()
    );
    let _ = std::io::stdout().flush();
}

enum RpcRequestLine {
    Dispatch(String),
    Respond(Value),
}

fn read_rpc_request_line(stream: &mut TcpStream) -> Result<RpcRequestLine, String> {
    let peer = stream
        .peer_addr()
        .map_err(|e| format!("mfnd serve: peer_addr: {e}"))?;
    configure_rpc_stream(stream)?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| format!("{e}"))?);
    let mut line = String::new();
    reader
        .by_ref()
        .take(MFND_RPC_MAX_REQUEST_LINE_BYTES.saturating_add(1))
        .read_line(&mut line)
        .map_err(|e| format!("mfnd serve: read request from {peer}: {e}"))?;
    if (line.len() as u64) > MFND_RPC_MAX_REQUEST_LINE_BYTES {
        return Ok(RpcRequestLine::Respond(mfn_rpc::rpc_error(
            &Value::Null,
            mfn_rpc::rpc_codes::INVALID_REQUEST,
            format!("request line exceeds maximum of {MFND_RPC_MAX_REQUEST_LINE_BYTES} bytes"),
        )));
    }
    Ok(RpcRequestLine::Dispatch(line))
}

fn dispatch_client_request(
    stream: &mut TcpStream,
    store: &dyn ChainPersistence,
    chain: &mut Chain,
    pool: &mut Mempool,
    proof_pool: &mut ProofPool,
    line: &str,
    dispatch_opts: ServeDispatchOpts,
) -> Result<(), String> {
    let method = rpc_method_for_log(line);
    let started = Instant::now();
    let resp =
        parse_and_dispatch_serve_opts(store, chain, pool, Some(proof_pool), line, dispatch_opts);
    log_rpc_request_outcome(&method, &resp, started.elapsed());
    write_line(stream, &resp)
}

struct RpcServeState {
    store: Arc<dyn ChainPersistence + Send + Sync>,
    chain: Arc<Mutex<Chain>>,
    pool: Arc<Mutex<Mempool>>,
    proof_pool: Arc<Mutex<ProofPool>>,
    serve_tip: TipSnapshot,
    dispatch_opts: ServeDispatchOpts,
}

fn handle_accepted_rpc_stream(
    mut stream: TcpStream,
    state: RpcServeState,
    _permit: RpcInFlightPermit,
) {
    let read_started = Instant::now();
    let line = match read_rpc_request_line(&mut stream) {
        Ok(RpcRequestLine::Dispatch(line)) => line,
        Ok(RpcRequestLine::Respond(resp)) => {
            log_rpc_request_outcome("unknown", &resp, read_started.elapsed());
            let _ = write_line(&mut stream, &resp);
            return;
        }
        Err(e) => {
            let resp = mfn_rpc::rpc_error(
                &Value::Null,
                mfn_rpc::rpc_codes::INTERNAL_ERROR,
                format!("mfnd serve: {e}"),
            );
            log_rpc_request_outcome("unknown", &resp, read_started.elapsed());
            let _ = write_line(&mut stream, &resp);
            return;
        }
    };
    let Ok(mut chain_guard) = state.chain.lock() else {
        eprintln!("mfnd serve: chain mutex poisoned");
        return;
    };
    let Ok(mut pool_guard) = state.pool.lock() else {
        eprintln!("mfnd serve: pool mutex poisoned");
        return;
    };
    let Ok(mut proof_guard) = state.proof_pool.lock() else {
        eprintln!("mfnd serve: proof_pool mutex poisoned");
        return;
    };
    let len_before = pool_guard.len();
    let root_before = mempool_root(&pool_guard);
    match dispatch_client_request(
        &mut stream,
        state.store.as_ref(),
        &mut chain_guard,
        &mut pool_guard,
        &mut proof_guard,
        &line,
        state.dispatch_opts,
    ) {
        Ok(()) => {
            if pool_guard.len() != len_before || mempool_root(&pool_guard) != root_before {
                persist_mempool(state.store.as_ref(), &pool_guard);
            }
            if let Ok(mut g) = state.serve_tip.lock() {
                *g = snapshot_chain_tip_for_p2p(&chain_guard);
            }
        }
        Err(e) => {
            let resp = mfn_rpc::rpc_error(
                &Value::Null,
                mfn_rpc::rpc_codes::INTERNAL_ERROR,
                format!("mfnd serve: {e}"),
            );
            let _ = write_line(&mut stream, &resp);
        }
    }
}

fn snapshot_chain_tip_for_p2p(chain: &Chain) -> (u32, [u8; 32]) {
    let height = chain.tip_height().unwrap_or(0);
    let tip_id = chain
        .tip_id()
        .copied()
        .unwrap_or_else(|| *chain.genesis_id());
    (height, tip_id)
}

fn log_chain_identity(genesis_id: &[u8; 32], network_label: Option<&str>) {
    if let Some(name) = network_label {
        println!("mfnd_chain_network={name}");
    }
    let mut hex = String::with_capacity(64);
    for b in genesis_id {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    println!("mfnd_chain_genesis_id={hex}");
    let _ = std::io::stdout().flush();
}

fn log_mempool_save(meta: &mfn_store::MempoolSaveMeta) {
    println!(
        "mfnd_mempool_save_ok bytes={} tx_count={}",
        meta.bytes_written, meta.tx_count
    );
    let _ = std::io::stdout().flush();
}

fn log_mempool_load(stats: &mfn_runtime::MempoolRestoreStats) {
    if stats.loaded > 0 {
        println!(
            "mfnd_mempool_load_ok loaded={} admitted={} skipped={}",
            stats.loaded, stats.admitted, stats.skipped
        );
        let _ = std::io::stdout().flush();
    }
}

fn persist_mempool(store: &dyn ChainPersistence, pool: &Mempool) {
    match save_mempool(store, pool) {
        Ok(m) => log_mempool_save(&m),
        Err(e) => eprintln!("mfnd_mempool_save_abort {e}"),
    }
}

fn log_proof_pool_save(meta: &mfn_store::ProofPoolSaveMeta) {
    println!(
        "mfnd_proof_pool_save_ok bytes={} proof_count={}",
        meta.bytes_written, meta.proof_count
    );
    let _ = std::io::stdout().flush();
}

fn log_proof_pool_load(stats: &mfn_runtime::ProofPoolRestoreStats) {
    if stats.loaded > 0 {
        println!(
            "mfnd_proof_pool_load_ok loaded={} admitted={} skipped={}",
            stats.loaded, stats.admitted, stats.skipped
        );
        let _ = std::io::stdout().flush();
    }
}

fn persist_proof_pool(store: &dyn ChainPersistence, pool: &ProofPool) {
    match save_proof_pool(store, pool) {
        Ok(m) => log_proof_pool_save(&m),
        Err(e) => eprintln!("mfnd_proof_pool_save_abort {e}"),
    }
}

fn next_block_context(chain: &Chain) -> ([u8; 32], u32) {
    let prev = chain
        .tip_id()
        .copied()
        .unwrap_or_else(|| *chain.genesis_id());
    let next_height = chain.tip_height().map(|h| h.saturating_add(1)).unwrap_or(1);
    (prev, next_height)
}

struct ServeDispatchState<'a> {
    store: &'a Arc<dyn ChainPersistence + Send + Sync>,
    fanout_peers: Option<&'a Arc<P2pPeerSet>>,
    genesis: Arc<GenesisConfig>,
    genesis_id: [u8; 32],
    serve_tip: TipSnapshot,
    rpc_api_key: Option<String>,
    rpc_max_in_flight: usize,
    rpc_in_flight: Arc<AtomicUsize>,
    rpc_listen: &'a str,
    local_p2p_listen: Option<std::net::SocketAddr>,
}

fn serve_dispatch_opts(state: ServeDispatchState<'_>) -> ServeDispatchOpts {
    let ServeDispatchState {
        store,
        fanout_peers,
        genesis,
        genesis_id,
        serve_tip,
        rpc_api_key,
        rpc_max_in_flight,
        rpc_in_flight,
        rpc_listen,
        local_p2p_listen,
    } = state;
    let store_persist = Arc::clone(store);
    let store_proof = Arc::clone(store);
    let on_fresh_admit =
        Arc::new(move |pool: &Mempool| persist_mempool(store_persist.as_ref(), pool));
    let on_proof_pool_change =
        Arc::new(move |pool: &ProofPool| persist_proof_pool(store_proof.as_ref(), pool));
    let on_fresh_tx = fanout_peers.map(|ps| {
        let ps = Arc::clone(ps);
        Arc::new(move |bytes: &[u8]| {
            FanoutPeerSet::fanout_fresh_tx(ps.as_ref(), bytes, None);
        }) as Arc<dyn Fn(&[u8]) + Send + Sync>
    });
    let tip_for_fetch = serve_tip.clone();
    let tip_for_quorum = serve_tip.clone();
    let rpc_in_flight_current = Arc::new(move || rpc_in_flight.load(Ordering::Acquire));
    let p2p_light_follow: mfn_rpc::P2pLightFollowHook = Arc::new(move |peer, from, to| {
        let tip_guard = tip_for_fetch
            .lock()
            .map_err(|_| "serve tip mutex poisoned".to_string())?;
        let (height, tip_id) = *tip_guard;
        let local_tip = mfn_net::ChainTipV1 { height, tip_id };
        crate::p2p_light_follow_fetch::fetch_light_follow_json(
            peer,
            &genesis_id,
            local_tip,
            from,
            to,
        )
    });
    let p2p_light_follow_quorum: mfn_rpc::P2pLightFollowQuorumHook =
        Arc::new(move |peers, from, to| {
            let tip_guard = tip_for_quorum
                .lock()
                .map_err(|_| "serve tip mutex poisoned".to_string())?;
            let (height, tip_id) = *tip_guard;
            let local_tip = mfn_net::ChainTipV1 { height, tip_id };
            crate::p2p_light_follow_fetch::fetch_light_follow_quorum_json(
                peers,
                &genesis_id,
                local_tip,
                from,
                to,
            )
        });
    let p2p_status = fanout_peers.map(|ps| {
        let ps = Arc::clone(ps);
        let listen_addr = local_p2p_listen.map(|addr| addr.to_string());
        Arc::new(move || {
            let diversity = ps.peer_diversity_snapshot();
            json!({
                "configured": true,
                "listen_addr": listen_addr.as_deref(),
                "peer_count": ps.snapshot_peers().len(),
                "session_count": diversity.session_count,
                "max_outbound_peers": ps.max_outbound_peers(),
                "distinct_ipv4_prefix16": diversity.distinct_ipv4_prefix16,
                "distinct_onion": diversity.distinct_onion,
                "distinct_other_hosts": diversity.distinct_other_hosts,
                "ipv4_session_count": diversity.ipv4_session_count,
            })
        }) as mfn_rpc::P2pStatusHook
    });
    let p2p_anchor_peers = fanout_peers.map(|ps| {
        let ps = Arc::clone(ps);
        Arc::new(move || {
            ps.snapshot_checkpoint_anchor_peers(mfn_net::DEFAULT_CHECKPOINT_ANCHOR_PEER_COUNT)
        }) as mfn_rpc::P2pAnchorPeersHook
    });
    ServeDispatchOpts {
        genesis: Some(genesis),
        rpc_api_key,
        rpc_max_in_flight: Some(rpc_max_in_flight),
        rpc_current_in_flight: Some(rpc_in_flight_current),
        rpc_max_request_line_bytes: Some(MFND_RPC_MAX_REQUEST_LINE_BYTES),
        rpc_io_timeout_ms: Some(MFND_RPC_IO_TIMEOUT.as_millis() as u64),
        rpc_listen_addr: Some(rpc_listen.to_string()),
        rpc_public_bind: Some(!rpc_listen_is_loopback(rpc_listen)),
        on_fresh_tx,
        on_fresh_admit: Some(on_fresh_admit),
        on_proof_pool_change: Some(on_proof_pool_change),
        p2p_light_follow: Some(p2p_light_follow),
        p2p_light_follow_quorum: Some(p2p_light_follow_quorum),
        p2p_status,
        p2p_anchor_peers,
    }
}

fn rpc_listen_is_loopback(addr: &str) -> bool {
    let host = addr
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']))
        .unwrap_or(addr);
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

fn rpc_public_bind_warning(rpc_listen: &str, auth_enabled: bool) -> Option<String> {
    if rpc_listen_is_loopback(rpc_listen) {
        return None;
    }
    let auth_note = if auth_enabled {
        "RPC API key is enabled for wallet-write/operator-admin methods, but public read methods remain unauthenticated"
    } else {
        "RPC API key is not enabled; wallet-write/operator-admin methods are unauthenticated"
    };
    Some(format!(
        "mfnd_rpc_public_bind_warning listen={rpc_listen} {auth_note}; use firewall/TLS/VPN/SSH tunnel and upstream rate limits before internet exposure"
    ))
}

/// True when `--dandelion` was passed or `MFND_DANDELION` is set to a truthy value.
fn dandelion_enabled(cli_flag: bool) -> bool {
    if cli_flag {
        return true;
    }
    matches!(
        std::env::var("MFND_DANDELION").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

/// Run a blocking TCP loop: load chain + mempool snapshot, print bound address, then
/// serve one JSON line per connection until the process exits.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_serve(
    store: Arc<dyn ChainPersistence + Send + Sync>,
    cfg: ChainConfig,
    rpc_listen: &str,
    rpc_api_key: Option<String>,
    p2p_listen: Option<&str>,
    p2p_dials: &[String],
    produce: bool,
    committee_vote: bool,
    slot_duration_ms: u64,
    network_label: Option<&str>,
    dandelion: bool,
) -> Result<(), String> {
    let dandelion = dandelion_enabled(dandelion);
    let genesis_timestamp = cfg.genesis.timestamp;
    let genesis_for_rpc = Arc::new(cfg.genesis.clone());
    let (loaded_chain, replay_stats) =
        load_or_genesis_replaying_block_log(store.as_ref(), cfg).map_err(|e| format!("{e}"))?;
    println!(
        "mfnd_block_log_replay blocks_read={} skipped={} applied={} final_height={}",
        replay_stats.blocks_read,
        replay_stats.blocks_skipped,
        replay_stats.blocks_applied,
        replay_stats.final_height
    );
    let chain = Arc::new(Mutex::new(loaded_chain));
    let pool = Arc::new(Mutex::new(Mempool::new(MempoolConfig::default())));
    let proof_pool = Arc::new(Mutex::new(ProofPool::new(ProofPoolConfig::default())));
    {
        let guard = chain
            .lock()
            .map_err(|_| "mfnd serve: chain mutex poisoned".to_string())?;
        let mut pool_guard = pool
            .lock()
            .map_err(|_| "mfnd serve: pool mutex poisoned".to_string())?;
        let stats = load_mempool(store.as_ref(), &mut pool_guard, guard.state())
            .map_err(|e| format!("mfnd serve: load mempool: {e}"))?;
        log_mempool_load(&stats);
    }
    {
        let guard = chain
            .lock()
            .map_err(|_| "mfnd serve: chain mutex poisoned".to_string())?;
        let mut proof_guard = proof_pool
            .lock()
            .map_err(|_| "mfnd serve: proof_pool mutex poisoned".to_string())?;
        let (prev, next_h) = next_block_context(&guard);
        let stats = load_proof_pool(
            store.as_ref(),
            &mut proof_guard,
            guard.state(),
            &prev,
            next_h,
        )
        .map_err(|e| format!("mfnd serve: load proof pool: {e}"))?;
        log_proof_pool_load(&stats);
    }
    let genesis_id = {
        let guard = chain
            .lock()
            .map_err(|_| "mfnd serve: chain mutex poisoned".to_string())?;
        *guard.genesis_id()
    };

    if (produce || committee_vote) && p2p_listen.is_none() && p2p_dials.is_empty() {
        return Err(
            "mfnd serve --produce / --committee-vote requires --p2p-listen and/or --p2p-dial"
                .into(),
        );
    }
    if produce && committee_vote {
        return Err("mfnd serve: --produce and --committee-vote are mutually exclusive".into());
    }
    if rpc_api_key.is_some() {
        println!("mfnd_rpc_auth=enabled protected_classes=wallet-write,operator-admin");
    }
    if let Some(warning) = rpc_public_bind_warning(rpc_listen, rpc_api_key.is_some()) {
        eprintln!("{warning}");
    }
    let is_storage_operator = if produce || committee_vote {
        validator_index_from_env().is_some_and(|idx| {
            chain
                .lock()
                .map(|guard| chain_validator_is_storage_operator(&guard, idx))
                .unwrap_or(false)
        })
    } else {
        false
    };
    if let Some(warning) = role_topology_colocation_warning(
        produce,
        committee_vote,
        rpc_listen,
        p2p_listen,
        is_storage_operator,
    ) {
        eprintln!("{warning}");
    }
    if let Some(hint) =
        observer_loopback_rpc_hint_warning(produce, committee_vote, rpc_listen, p2p_listen)
    {
        eprintln!("{hint}");
    }
    for warning in pm23_operator_manifest_env_warnings(produce, committee_vote) {
        eprintln!("{warning}");
        if pm23_hard_fail_enabled() {
            return Err(format!(
                "mfnd serve: PM23 hard fail enabled (MFND_PM23_HARD_FAIL=1): {warning}"
            ));
        }
    }
    let rpc_max_in_flight = rpc_max_in_flight_from_env()?;
    println!("mfnd_rpc_max_in_flight={rpc_max_in_flight}");

    let (p2p_listener, local_p2p_listen) = if let Some(addr) = p2p_listen {
        let listener =
            TcpListener::bind(addr).map_err(|e| format!("mfnd serve: bind P2P `{addr}`: {e}"))?;
        let listen_addr = listener
            .local_addr()
            .map_err(|e| format!("mfnd serve: p2p local_addr: {e}"))?;
        // Announce P2P listen before fan-out / production setup so devnet start-all polls
        // do not block on committee engine initialization (GHA Nightly ~900s voter poll).
        println!("mfnd_p2p_listening={listen_addr}");
        std::io::stdout()
            .flush()
            .map_err(|e| format!("mfnd serve: stdout flush (p2p early): {e}"))?;
        (Some(listener), Some(listen_addr))
    } else {
        (None, None)
    };

    let p2p_enabled = p2p_listen.is_some() || !p2p_dials.is_empty();
    if p2p_enabled {
        let transport = crate::network::init_active_p2p_transport_from_env()
            .map_err(|e| format!("mfnd serve: {e}"))?;
        println!(
            "mfnd_p2p_transport={} tor_socks5={}",
            transport.harness_label(),
            transport.tor_socks5
        );
        std::io::stdout()
            .flush()
            .map_err(|e| format!("mfnd serve: stdout flush (p2p transport): {e}"))?;
        if transport.kind == crate::network::P2pTransportKind::Tor {
            eprintln!(
                "mfnd_p2p_transport_warning tor outbound dials require reachable SOCKS5 at {}",
                transport.tor_socks5
            );
        }
        if let Some(onion) = crate::network::P2pTransportConfig::p2p_onion_from_env()
            .map_err(|e| format!("mfnd serve: {e}"))?
        {
            println!("mfnd_p2p_onion={onion}");
            std::io::stdout()
                .flush()
                .map_err(|e| format!("mfnd serve: stdout flush (p2p onion): {e}"))?;
        }
        let min_prefix16 = mfn_net::min_distinct_ipv4_prefix16_from_env()
            .map_err(|e| format!("mfnd serve: {e}"))?;
        println!("mfnd_p2p_diversity_policy=min_distinct_prefix16={min_prefix16}");
        if min_prefix16 > 0 {
            match mfn_net::peer_diversity_redial_enabled_from_env() {
                Ok(true) => println!("mfnd_p2p_diversity_redial_policy=enabled"),
                Ok(false) => println!("mfnd_p2p_diversity_redial_policy=disabled"),
                Err(e) => eprintln!("mfnd_p2p_diversity_config_error {e}"),
            }
        }
        std::io::stdout()
            .flush()
            .map_err(|e| format!("mfnd serve: stdout flush (p2p diversity): {e}"))?;
    }
    let (
        p2p_tip_cell,
        p2p_hid_counter,
        gossip_hook,
        block_sync_hook,
        light_follow_hook,
        block_applier_hook,
        fanout_peers,
        production_hook,
    ): P2pServeHooks = if p2p_enabled {
        let tip_cell = Arc::new(Mutex::new({
            let guard = chain
                .lock()
                .map_err(|_| "mfnd serve: chain mutex poisoned".to_string())?;
            snapshot_chain_tip_for_p2p(&guard)
        }));
        let dandelion_config = if dandelion {
            crate::dandelion::DandelionConfig::enabled()
        } else {
            crate::dandelion::DandelionConfig::default()
        };
        if dandelion {
            println!("mfnd_dandelion=enabled");
        }
        let fanout = P2pPeerSet::new(
            genesis_id,
            Arc::clone(&tip_cell),
            store.root().to_path_buf(),
            Arc::clone(&chain),
            dandelion_config,
        );
        let hook = P2pGossipHandler::new(
            Arc::clone(&chain),
            Arc::clone(&pool),
            Arc::clone(&proof_pool),
            Arc::clone(&store),
            Arc::clone(&tip_cell),
            Some(Arc::clone(&fanout)),
        );
        let (sync_hook, light_follow_hook) =
            P2pBlockSyncHandler::new_hooks(Arc::clone(&chain), Arc::clone(&store));
        let gossip_hook: mfn_net::GossipHook = hook.clone();
        let applier_hook: BlockSyncApplierHook = hook;
        let hid_counter = Arc::new(AtomicU64::new(0));
        let production_hook = if produce || committee_vote {
            let validators = {
                let guard = chain
                    .lock()
                    .map_err(|_| "mfnd serve: chain mutex poisoned".to_string())?;
                guard.validators().to_vec()
            };
            let local = produce_config_from_env(&validators, slot_duration_ms)?;
            if produce {
                println!(
                    "mfnd_producer_start validator_index={} slot_duration_ms={slot_duration_ms}",
                    local.validator.index
                );
            } else {
                println!(
                    "mfnd_committee_vote_start validator_index={}",
                    local.validator.index
                );
            }
            std::io::stdout()
                .flush()
                .map_err(|e| format!("mfnd serve: stdout flush (producer): {e}"))?;
            let engine = ProductionEngine::new(ProductionEngineDeps {
                chain: Arc::clone(&chain),
                pool: Arc::clone(&pool),
                proof_pool: Arc::clone(&proof_pool),
                store: Arc::clone(&store),
                tip_cell: Arc::clone(&tip_cell),
                genesis_timestamp,
                local,
                peers: Arc::clone(&fanout),
            });
            fanout.attach_production(Arc::clone(&engine) as mfn_net::ProductionHook);
            if produce {
                spawn_slot_producer_loop(Arc::clone(&engine));
            }
            if committee_vote {
                spawn_committee_catch_up_loop(CommitteeCatchUpLoop {
                    peer_set: Arc::clone(&fanout),
                    genesis_id,
                    tip_cell: Arc::clone(&tip_cell),
                    hid_counter: Arc::clone(&hid_counter),
                    block_sync: Arc::clone(&sync_hook),
                    block_applier: Arc::clone(&applier_hook),
                    local_p2p_listen,
                    interval_ms: slot_duration_ms.max(5_000),
                })?;
            }
            Some(engine as mfn_net::ProductionHook)
        } else {
            None
        };
        if !produce && !committee_vote && !p2p_dials.is_empty() {
            println!("mfnd_observer_catchup_start");
            std::io::stdout()
                .flush()
                .map_err(|e| format!("mfnd serve: stdout flush (observer catch-up): {e}"))?;
            let observer_catch_up_ms = slot_duration_ms.max(15_000);
            spawn_committee_catch_up_loop(CommitteeCatchUpLoop {
                peer_set: Arc::clone(&fanout),
                genesis_id,
                tip_cell: Arc::clone(&tip_cell),
                hid_counter: Arc::clone(&hid_counter),
                block_sync: Arc::clone(&sync_hook),
                block_applier: Arc::clone(&applier_hook),
                local_p2p_listen,
                interval_ms: observer_catch_up_ms,
            })?;
        }
        let repair_threshold = repair_threshold_slots_from_env()?;
        if repair_threshold > 0 {
            let repair_interval = repair_interval_ms_from_env(
                slot_duration_ms
                    .saturating_mul(10)
                    .max(DEFAULT_REPAIR_INTERVAL_MS),
            )?;
            println!(
                "mfnd_repair_sweep_start threshold_slots={repair_threshold} interval_ms={repair_interval}"
            );
            std::io::stdout()
                .flush()
                .map_err(|e| format!("mfnd serve: stdout flush (repair sweep): {e}"))?;
            spawn_repair_sweep_loop(RepairSweepLoop {
                peer_set: Arc::clone(&fanout),
                interval_ms: repair_interval,
                repair_threshold_slots: repair_threshold,
            })?;
        }
        let min_prefix16 = mfn_net::min_distinct_ipv4_prefix16_from_env()
            .map_err(|e| format!("mfnd serve: {e}"))?;
        if min_prefix16 > 0
            && mfn_net::peer_diversity_redial_enabled_from_env()
                .map_err(|e| format!("mfnd serve: {e}"))?
        {
            let diversity_interval = slot_duration_ms.saturating_mul(4).max(60_000);
            println!("mfnd_p2p_diversity_redial_start interval_ms={diversity_interval}");
            std::io::stdout()
                .flush()
                .map_err(|e| format!("mfnd serve: stdout flush (diversity redial): {e}"))?;
            spawn_peer_diversity_redial_loop(PeerDiversityRedialLoop {
                peer_set: Arc::clone(&fanout),
                genesis_id,
                tip_cell: Arc::clone(&tip_cell),
                hid_counter: Arc::clone(&hid_counter),
                block_sync: Arc::clone(&sync_hook),
                block_applier: Arc::clone(&applier_hook),
                local_p2p_listen,
                interval_ms: diversity_interval,
            })?;
        }
        (
            Some(tip_cell),
            Some(hid_counter),
            Some(gossip_hook),
            Some(sync_hook),
            Some(light_follow_hook),
            Some(applier_hook),
            Some(fanout),
            production_hook,
        )
    } else {
        (None, None, None, None, None, None, None, None)
    };

    log_chain_identity(&genesis_id, network_label);

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
        if local_p2p_listen.is_none() {
            return Err(
                "mfnd serve: internal error: P2P listener active without listen address".into(),
            );
        };
        let Some(tip_cell) = p2p_tip_cell.as_ref() else {
            return Err(
                "mfnd serve: internal error: P2P listener active without tip snapshot".into(),
            );
        };
        let Some(hid_counter) = p2p_hid_counter.as_ref() else {
            return Err(
                "mfnd serve: internal error: P2P listener active without HID counter".into(),
            );
        };
        spawn_inbound_handshake_loop(InboundP2pLoop {
            listener: pl,
            genesis_id,
            tip_cell: tip_cell.clone(),
            hid_counter: hid_counter.clone(),
            hooks: P2pSessionHooks {
                gossip: gossip_hook.clone(),
                block_sync: block_sync_hook.clone(),
                block_applier: block_applier_hook.clone(),
                light_follow: light_follow_hook.clone(),
                fanout_peers: fanout_peers
                    .as_ref()
                    .map(|p| Arc::clone(p) as FanoutPeerSetHook),
                production: production_hook.clone(),
            },
        })?;
    }

    for dial in p2p_dials {
        if is_self_peer_addr(dial, local_p2p_listen) {
            println!("mfnd_p2p_self_dial_skip peer={dial}");
            std::io::stdout()
                .flush()
                .map_err(|e| format!("mfnd serve: stdout flush (p2p self skip): {e}"))?;
            continue;
        }
        let (Some(tip_cell), Some(hid_counter)) = (p2p_tip_cell.as_ref(), p2p_hid_counter.as_ref())
        else {
            eprintln!("mfnd_p2p_dial_skip peer={dial} reason=missing_p2p_state");
            continue;
        };
        spawn_outbound_dial(OutboundP2pDial {
            addr: dial.clone(),
            genesis_id,
            tip_cell: tip_cell.clone(),
            hid_counter: hid_counter.clone(),
            hooks: P2pSessionHooks {
                gossip: gossip_hook.clone(),
                block_sync: block_sync_hook.clone(),
                block_applier: block_applier_hook.clone(),
                light_follow: light_follow_hook.clone(),
                fanout_peers: fanout_peers
                    .as_ref()
                    .map(|p| Arc::clone(p) as FanoutPeerSetHook),
                production: production_hook.clone(),
            },
            local_p2p_listen,
        })?;
    }

    if let (Some(ps), Some(tc), Some(hid)) = (
        fanout_peers.as_ref(),
        p2p_tip_cell.as_ref(),
        p2p_hid_counter.as_ref(),
    ) {
        spawn_reconnect_saved_peers(ReconnectPeersBoot {
            peer_set: ps,
            genesis_id,
            tip_cell: Arc::clone(tc),
            hid_counter: Arc::clone(hid),
            gossip: gossip_hook,
            block_sync: block_sync_hook.clone(),
            block_applier: block_applier_hook,
            fanout_hook: fanout_peers
                .as_ref()
                .map(|p| Arc::clone(p) as FanoutPeerSetHook),
            local_p2p_listen,
            skip_addrs: p2p_dials,
        })?;
    }

    let serve_tip: TipSnapshot = p2p_tip_cell.clone().unwrap_or_else(|| {
        Arc::new(Mutex::new(
            chain
                .lock()
                .map(|g| snapshot_chain_tip_for_p2p(&g))
                .unwrap_or((0, genesis_id)),
        ))
    });
    let rpc_in_flight = Arc::new(AtomicUsize::new(0));
    let dispatch_opts = serve_dispatch_opts(ServeDispatchState {
        store: &store,
        fanout_peers: fanout_peers.as_ref(),
        genesis: genesis_for_rpc,
        genesis_id,
        serve_tip: serve_tip.clone(),
        rpc_api_key,
        rpc_max_in_flight,
        rpc_in_flight: Arc::clone(&rpc_in_flight),
        rpc_listen,
        local_p2p_listen,
    });

    #[cfg(unix)]
    {
        let store_c = Arc::clone(&store);
        let pool_c = Arc::clone(&pool);
        let proof_pool_c = Arc::clone(&proof_pool);
        let peers_c = fanout_peers.clone();
        ctrlc::set_handler(move || {
            if let Ok(guard) = pool_c.lock() {
                persist_mempool(store_c.as_ref(), &guard);
            }
            if let Ok(guard) = proof_pool_c.lock() {
                persist_proof_pool(store_c.as_ref(), &guard);
            }
            if let Some(ps) = peers_c.as_ref() {
                ps.persist();
            }
            std::process::exit(0);
        })
        .map_err(|e| format!("mfnd serve: install Ctrl+C handler: {e}"))?;
    }

    loop {
        let (mut stream, _) = match listener.accept() {
            Ok(x) => x,
            Err(e) => {
                eprintln!("mfnd serve: accept: {e}");
                continue;
            }
        };
        let Some(permit) = try_acquire_rpc_permit(&rpc_in_flight, rpc_max_in_flight) else {
            let _ = write_rpc_busy_response(&mut stream, rpc_max_in_flight);
            continue;
        };
        let store_c = Arc::clone(&store);
        let chain_c = Arc::clone(&chain);
        let pool_c = Arc::clone(&pool);
        let proof_pool_c = Arc::clone(&proof_pool);
        let serve_tip_c = Arc::clone(&serve_tip);
        let dispatch_opts_c = dispatch_opts.clone();
        let rpc_state = RpcServeState {
            store: store_c,
            chain: chain_c,
            pool: pool_c,
            proof_pool: proof_pool_c,
            serve_tip: serve_tip_c,
            dispatch_opts: dispatch_opts_c,
        };
        if let Err(e) = thread::Builder::new()
            .name("mfnd-rpc".to_string())
            .spawn(move || {
                handle_accepted_rpc_stream(stream, rpc_state, permit);
            })
        {
            eprintln!("mfnd serve: spawn RPC worker: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn configure_rpc_stream_sets_read_and_write_timeouts() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = TcpStream::connect(addr).expect("connect client");
        let (server, _) = listener.accept().expect("accept server");

        configure_rpc_stream(&server).expect("configure server stream");

        assert_eq!(
            server.read_timeout().expect("server read timeout"),
            Some(MFND_RPC_IO_TIMEOUT)
        );
        assert_eq!(
            server.write_timeout().expect("server write timeout"),
            Some(MFND_RPC_IO_TIMEOUT)
        );

        drop(client);
    }

    #[test]
    fn write_rpc_busy_response_sets_timeouts_and_returns_json_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = TcpStream::connect(addr).expect("connect client");
        let (mut server, _) = listener.accept().expect("accept server");

        write_rpc_busy_response(&mut server, 7).expect("write busy response");

        assert_eq!(
            server.read_timeout().expect("server read timeout"),
            Some(MFND_RPC_IO_TIMEOUT)
        );
        assert_eq!(
            server.write_timeout().expect("server write timeout"),
            Some(MFND_RPC_IO_TIMEOUT)
        );

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read busy response");
        let resp: Value = serde_json::from_str(line.trim()).expect("json busy response");
        assert_eq!(resp["id"], Value::Null);
        assert_eq!(
            resp["error"]["code"],
            Value::from(mfn_rpc::rpc_codes::INTERNAL_ERROR)
        );
        assert!(resp["error"]["message"]
            .as_str()
            .expect("message")
            .contains("maximum in-flight connections is 7"));
    }

    #[test]
    fn rpc_in_flight_permit_caps_and_releases() {
        let counter = Arc::new(AtomicUsize::new(0));
        let first = try_acquire_rpc_permit(&counter, 2).expect("first permit");
        let second = try_acquire_rpc_permit(&counter, 2).expect("second permit");
        assert!(try_acquire_rpc_permit(&counter, 2).is_none());
        assert_eq!(counter.load(Ordering::Acquire), 2);

        drop(first);
        assert_eq!(counter.load(Ordering::Acquire), 1);
        let third = try_acquire_rpc_permit(&counter, 2).expect("third permit");
        assert_eq!(counter.load(Ordering::Acquire), 2);

        drop(second);
        drop(third);
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    #[test]
    fn rpc_max_in_flight_env_defaults_when_unset() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var(MFND_RPC_MAX_IN_FLIGHT_ENV);
        assert_eq!(
            rpc_max_in_flight_from_env().expect("default max"),
            MFND_RPC_MAX_IN_FLIGHT_CONNECTIONS
        );
    }

    #[test]
    fn rpc_max_in_flight_env_accepts_positive_integer() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var(MFND_RPC_MAX_IN_FLIGHT_ENV, "7");
        assert_eq!(rpc_max_in_flight_from_env().expect("custom max"), 7);
        std::env::remove_var(MFND_RPC_MAX_IN_FLIGHT_ENV);
    }

    #[test]
    fn rpc_max_in_flight_env_rejects_zero_and_malformed_values() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var(MFND_RPC_MAX_IN_FLIGHT_ENV, "0");
        assert!(rpc_max_in_flight_from_env()
            .expect_err("zero must fail")
            .contains("at least 1"));
        std::env::set_var(MFND_RPC_MAX_IN_FLIGHT_ENV, "not-a-number");
        assert!(rpc_max_in_flight_from_env()
            .expect_err("malformed must fail")
            .contains("positive integer"));
        std::env::remove_var(MFND_RPC_MAX_IN_FLIGHT_ENV);
    }

    #[test]
    fn rpc_public_bind_warning_skips_loopback() {
        assert!(rpc_public_bind_warning("127.0.0.1:18731", false).is_none());
        assert!(rpc_public_bind_warning("[::1]:18731", true).is_none());
        assert!(rpc_public_bind_warning("localhost:18731", true).is_none());
    }

    #[test]
    fn rpc_public_bind_warning_without_auth_mentions_unauthenticated_writes() {
        let warning = rpc_public_bind_warning("0.0.0.0:18731", false).expect("warning");
        assert!(warning.contains("mfnd_rpc_public_bind_warning"));
        assert!(warning.contains("listen=0.0.0.0:18731"));
        assert!(warning.contains("RPC API key is not enabled"));
        assert!(warning.contains("wallet-write/operator-admin methods are unauthenticated"));
    }

    #[test]
    fn rpc_public_bind_warning_with_auth_mentions_public_reads() {
        let warning = rpc_public_bind_warning("0.0.0.0:18731", true).expect("warning");
        assert!(warning.contains("RPC API key is enabled"));
        assert!(warning.contains("public read methods remain unauthenticated"));
        assert!(warning.contains("upstream rate limits"));
    }

    #[test]
    fn read_rpc_request_line_rejects_oversized_before_dispatch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = TcpStream::connect(addr).expect("connect client");
        let (mut server, _) = listener.accept().expect("accept server");

        let oversized = "x".repeat((MFND_RPC_MAX_REQUEST_LINE_BYTES as usize) + 1);
        let writer = std::thread::spawn(move || {
            let mut client = client;
            writeln!(client, "{oversized}").expect("write oversized request");
        });
        let line = read_rpc_request_line(&mut server).expect("read request line");
        match line {
            RpcRequestLine::Respond(resp) => {
                assert_eq!(resp["error"]["code"], mfn_rpc::rpc_codes::INVALID_REQUEST);
                assert!(resp["error"]["message"]
                    .as_str()
                    .expect("error message")
                    .contains("request line exceeds maximum"));
            }
            RpcRequestLine::Dispatch(_) => panic!("oversized request must not dispatch"),
        }
        writer.join().expect("writer thread");
    }

    #[test]
    fn rpc_method_for_log_sanitizes_without_params() {
        let method = rpc_method_for_log(
            r#"{"jsonrpc":"2.0","method":"submit_tx\napi_key=leak","params":{"api_key":"secret"},"id":1}"#,
        );
        assert_eq!(method, "submit_tx_api_key_leak");
        assert!(!method.contains("secret"));
    }

    #[test]
    fn rpc_method_for_log_uses_unknown_for_malformed_or_missing_method() {
        assert_eq!(rpc_method_for_log(r#"{"jsonrpc":"2.0""#), "unknown");
        assert_eq!(
            rpc_method_for_log(r#"{"jsonrpc":"2.0","params":{"api_key":"secret"}}"#),
            "unknown"
        );
    }

    #[test]
    fn rpc_log_token_limits_length_and_replaces_controls() {
        let token = rpc_log_token(&format!("{}{}", "a".repeat(80), "\n"));
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c == 'a'));
    }
}
