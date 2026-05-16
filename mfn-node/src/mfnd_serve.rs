//! Blocking TCP `mfnd serve`: one UTF-8 JSON line per connection, optional P2P listeners.
//!
//! JSON-RPC parsing and method dispatch are in [`mfn_rpc`]. P2P framing and handshake
//! threads are in [`mfn_net::serve`].

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use mfn_net::serve::{spawn_inbound_handshake_loop, spawn_outbound_dial, HidCounter, TipSnapshot};
use mfn_rpc::parse_and_dispatch_serve;
use mfn_runtime::{Chain, ChainConfig, Mempool, MempoolConfig};
use mfn_store::ChainStore;
use serde_json::Value;

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

/// Run a blocking TCP loop: load chain + empty mempool, print bound address, then
/// serve one JSON line per connection until the process exits.
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

    let (p2p_tip_cell, p2p_hid_counter): (Option<TipSnapshot>, Option<HidCounter>) =
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
        spawn_inbound_handshake_loop(
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
        spawn_outbound_dial(
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
