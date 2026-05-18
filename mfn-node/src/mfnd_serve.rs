//! Blocking TCP `mfnd serve`: one UTF-8 JSON line per connection, optional P2P listeners.
//!
//! JSON-RPC parsing and method dispatch are in [`mfn_rpc`]. P2P framing and handshake
//! threads are in [`mfn_net::serve`].

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use mfn_net::serve::{
    spawn_inbound_handshake_loop, spawn_outbound_dial, BlockSyncApplierHook, BlockSyncHook,
    FanoutPeerSetHook, HidCounter, InboundP2pLoop, OutboundP2pDial, P2pSessionHooks, TipSnapshot,
};
use mfn_net::FanoutPeerSet;
use mfn_rpc::{parse_and_dispatch_serve_opts, ServeDispatchOpts};
use mfn_runtime::{mempool_root, Chain, ChainConfig, Mempool, MempoolConfig};
use mfn_store::{load_mempool, save_mempool, ChainPersistence};
use serde_json::Value;

use crate::p2p_block_sync::P2pBlockSyncHandler;
use crate::p2p_fanout::{spawn_reconnect_saved_peers, P2pPeerSet, ReconnectPeersBoot};
use crate::p2p_gossip::P2pGossipHandler;
use crate::runner::{
    produce_config_from_env, spawn_slot_producer_loop, ProductionEngine, ProductionEngineDeps,
};

type P2pServeHooks = (
    Option<TipSnapshot>,
    Option<HidCounter>,
    Option<mfn_net::GossipHook>,
    Option<BlockSyncHook>,
    Option<BlockSyncApplierHook>,
    Option<Arc<P2pPeerSet>>,
    Option<mfn_net::ProductionHook>,
);

fn write_line(stream: &mut TcpStream, v: &Value) -> Result<(), String> {
    let s = v.to_string();
    writeln!(stream, "{s}").map_err(|e| format!("mfnd serve: write response: {e}"))
}

fn handle_client(
    stream: &mut TcpStream,
    store: &dyn ChainPersistence,
    chain: &mut Chain,
    pool: &mut Mempool,
    dispatch_opts: ServeDispatchOpts,
) -> Result<(), String> {
    let peer = stream
        .peer_addr()
        .map_err(|e| format!("mfnd serve: peer_addr: {e}"))?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| format!("{e}"))?);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("mfnd serve: read request from {peer}: {e}"))?;
    let resp = parse_and_dispatch_serve_opts(store, chain, pool, &line, dispatch_opts);
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

fn serve_dispatch_opts(fanout_peers: Option<&Arc<P2pPeerSet>>) -> ServeDispatchOpts {
    ServeDispatchOpts {
        on_fresh_tx: fanout_peers.map(|ps| {
            let ps = Arc::clone(ps);
            Arc::new(move |bytes: &[u8]| {
                FanoutPeerSet::fanout_fresh_tx(ps.as_ref(), bytes, None);
            }) as Arc<dyn Fn(&[u8]) + Send + Sync>
        }),
    }
}

/// Run a blocking TCP loop: load chain + mempool snapshot, print bound address, then
/// serve one JSON line per connection until the process exits.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_serve(
    store: Arc<dyn ChainPersistence + Send + Sync>,
    cfg: ChainConfig,
    rpc_listen: &str,
    p2p_listen: Option<&str>,
    p2p_dial: Option<&str>,
    produce: bool,
    committee_vote: bool,
    slot_duration_ms: u64,
) -> Result<(), String> {
    let genesis_timestamp = cfg.genesis.timestamp;
    let chain = Arc::new(Mutex::new(
        store.load_or_genesis(cfg).map_err(|e| format!("{e}"))?,
    ));
    let pool = Arc::new(Mutex::new(Mempool::new(MempoolConfig::default())));
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
    let genesis_id = {
        let guard = chain
            .lock()
            .map_err(|_| "mfnd serve: chain mutex poisoned".to_string())?;
        *guard.genesis_id()
    };

    if (produce || committee_vote) && p2p_listen.is_none() && p2p_dial.is_none() {
        return Err(
            "mfnd serve --produce / --committee-vote requires --p2p-listen and/or --p2p-dial"
                .into(),
        );
    }
    if produce && committee_vote {
        return Err("mfnd serve: --produce and --committee-vote are mutually exclusive".into());
    }

    let p2p_enabled = p2p_listen.is_some() || p2p_dial.is_some();
    let (
        p2p_tip_cell,
        p2p_hid_counter,
        gossip_hook,
        block_sync_hook,
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
        let fanout = P2pPeerSet::new(
            genesis_id,
            Arc::clone(&tip_cell),
            store.root().to_path_buf(),
        );
        let hook = P2pGossipHandler::new(
            Arc::clone(&chain),
            Arc::clone(&pool),
            Arc::clone(&store),
            Arc::clone(&tip_cell),
        );
        let sync_hook = P2pBlockSyncHandler::new(Arc::clone(&chain), Arc::clone(&store));
        let gossip_hook: mfn_net::GossipHook = hook.clone();
        let applier_hook: BlockSyncApplierHook = hook;
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
            Some(engine as mfn_net::ProductionHook)
        } else {
            None
        };
        (
            Some(tip_cell),
            Some(Arc::new(AtomicU64::new(0))),
            Some(gossip_hook),
            Some(sync_hook),
            Some(applier_hook),
            Some(fanout),
            production_hook,
        )
    } else {
        (None, None, None, None, None, None, None)
    };

    let (p2p_listener, local_p2p_listen) = if let Some(addr) = p2p_listen {
        let listener =
            TcpListener::bind(addr).map_err(|e| format!("mfnd serve: bind P2P `{addr}`: {e}"))?;
        let listen_addr = listener
            .local_addr()
            .map_err(|e| format!("mfnd serve: p2p local_addr: {e}"))?;
        (Some(listener), Some(listen_addr))
    } else {
        (None, None)
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
        let p2p_addr = local_p2p_listen.expect("p2p listen addr when listener bound");
        println!("mfnd_p2p_listening={p2p_addr}");
        std::io::stdout()
            .flush()
            .map_err(|e| format!("mfnd serve: stdout flush (p2p): {e}"))?;
        spawn_inbound_handshake_loop(InboundP2pLoop {
            listener: pl,
            genesis_id,
            tip_cell: p2p_tip_cell
                .as_ref()
                .expect("p2p tip cell when p2p listen")
                .clone(),
            hid_counter: p2p_hid_counter
                .as_ref()
                .expect("p2p hid counter when p2p listen")
                .clone(),
            hooks: P2pSessionHooks {
                gossip: gossip_hook.clone(),
                block_sync: block_sync_hook.clone(),
                block_applier: block_applier_hook.clone(),
                fanout_peers: fanout_peers
                    .as_ref()
                    .map(|p| Arc::clone(p) as FanoutPeerSetHook),
                production: production_hook.clone(),
            },
        })?;
    }

    if let Some(dial) = p2p_dial {
        spawn_outbound_dial(OutboundP2pDial {
            addr: dial.to_string(),
            genesis_id,
            tip_cell: p2p_tip_cell
                .as_ref()
                .expect("p2p tip cell when p2p dial")
                .clone(),
            hid_counter: p2p_hid_counter
                .as_ref()
                .expect("p2p hid counter when p2p dial")
                .clone(),
            hooks: P2pSessionHooks {
                gossip: gossip_hook.clone(),
                block_sync: block_sync_hook.clone(),
                block_applier: block_applier_hook.clone(),
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
            block_applier: block_applier_hook,
            fanout_hook: fanout_peers
                .as_ref()
                .map(|p| Arc::clone(p) as FanoutPeerSetHook),
            local_p2p_listen,
            skip_addr: p2p_dial,
        })?;
    }

    let dispatch_opts = serve_dispatch_opts(fanout_peers.as_ref());

    #[cfg(unix)]
    {
        let store_c = Arc::clone(&store);
        let pool_c = Arc::clone(&pool);
        let peers_c = fanout_peers.clone();
        ctrlc::set_handler(move || {
            if let Ok(guard) = pool_c.lock() {
                persist_mempool(store_c.as_ref(), &guard);
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
        let Ok(mut chain_guard) = chain.lock() else {
            eprintln!("mfnd serve: chain mutex poisoned");
            continue;
        };
        let Ok(mut pool_guard) = pool.lock() else {
            eprintln!("mfnd serve: pool mutex poisoned");
            continue;
        };
        let root_before = mempool_root(&pool_guard);
        match handle_client(
            &mut stream,
            store.as_ref(),
            &mut chain_guard,
            &mut pool_guard,
            dispatch_opts.clone(),
        ) {
            Ok(()) => {
                if mempool_root(&pool_guard) != root_before {
                    persist_mempool(store.as_ref(), &pool_guard);
                }
                if let Some(tc) = &p2p_tip_cell {
                    if let Ok(mut g) = tc.lock() {
                        *g = snapshot_chain_tip_for_p2p(&chain_guard);
                    }
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
}
