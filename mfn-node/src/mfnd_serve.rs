//! Blocking TCP `mfnd serve`: one UTF-8 JSON line per connection, optional P2P listeners.
//!
//! JSON-RPC parsing and method dispatch are implemented in [`mfn_rpc`]. This module
//! owns the accept loop, stdout harness lines (`mfnd_serve_listening=`, `mfnd_p2p_*`), and
//! optional peer handshakes when `--p2p-listen` / `--p2p-dial` are set.

use std::cmp::Ordering;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use mfn_rpc::parse_and_dispatch_serve;
use mfn_runtime::{Chain, ChainConfig, Mempool, MempoolConfig};
use mfn_store::ChainStore;
use serde_json::Value;

/// Shared `(tip_height, tip_id)` snapshot for P2P [`crate::network::ChainTipV1`] exchange.
type P2pTipShared = Arc<Mutex<(u32, [u8; 32])>>;

/// Monotonic handshake id counter for P2P stdout correlation (`hid=`).
type P2pHidCounter = Arc<AtomicU64>;

fn hex32(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
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

fn snapshot_chain_tip_for_p2p(chain: &Chain) -> (u32, [u8; 32]) {
    let height = chain.tip_height().unwrap_or(0);
    let tip_id = chain
        .tip_id()
        .copied()
        .unwrap_or_else(|| *chain.genesis_id());
    (height, tip_id)
}

fn p2p_log_peer_tip(hid: u64, peer: &str, remote: &crate::network::ChainTipV1) {
    println!(
        "mfnd_p2p_peer_tip hid={hid} peer={peer} height={} tip_id={}",
        remote.height,
        hex32(&remote.tip_id)
    );
    let _ = std::io::stdout().flush();
}

fn p2p_height_cmp_label(local_height: u32, remote_height: u32) -> &'static str {
    match remote_height.cmp(&local_height) {
        Ordering::Less => "behind",
        Ordering::Equal => "equal",
        Ordering::Greater => "ahead",
    }
}

fn p2p_log_height_cmp(
    hid: u64,
    peer: &str,
    local_height: u32,
    remote: &crate::network::ChainTipV1,
) {
    let cmp = p2p_height_cmp_label(local_height, remote.height);
    println!(
        "mfnd_p2p_height_cmp hid={hid} peer={peer} local_height={local_height} remote_height={} cmp={cmp}",
        remote.height
    );
    let _ = std::io::stdout().flush();
}

fn p2p_log_handshake_ms(hid: u64, peer: &str, elapsed: std::time::Duration) {
    println!(
        "mfnd_p2p_handshake_ms hid={hid} peer={peer} ms={}",
        elapsed.as_millis()
    );
    let _ = std::io::stdout().flush();
}

fn spawn_p2p_handshake_loop(
    listener: TcpListener,
    genesis_id: [u8; 32],
    tip_cell: P2pTipShared,
    hid_counter: P2pHidCounter,
) -> Result<(), String> {
    thread::Builder::new()
        .name("mfnd-p2p".into())
        .spawn(move || loop {
            let (mut sock, peer) = match listener.accept() {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("mfnd p2p: accept: {e}");
                    continue;
                }
            };
            let hid = hid_counter.fetch_add(1, AtomicOrdering::Relaxed);
            let t0 = Instant::now();
            let _ =
                sock.set_read_timeout(Some(crate::network::handshake::P2P_HANDSHAKE_IO_TIMEOUT));
            let _ =
                sock.set_write_timeout(Some(crate::network::handshake::P2P_HANDSHAKE_IO_TIMEOUT));
            if let Err(e) = crate::network::hello_v1_handshake(&mut sock, &genesis_id) {
                eprintln!("mfnd_p2p_handshake_abort hid={hid} peer={peer} stage=hello {e}");
                continue;
            }
            if let Err(e) = crate::network::recv_ping_send_pong(&mut sock) {
                eprintln!("mfnd_p2p_handshake_abort hid={hid} peer={peer} stage=ping_pong {e}");
                continue;
            }
            let local = {
                let g = tip_cell.lock().unwrap_or_else(|e| e.into_inner());
                crate::network::ChainTipV1 {
                    height: g.0,
                    tip_id: g.1,
                }
            };
            match crate::network::exchange_chain_tip_v1_as_listener(&mut sock, &local) {
                Ok(remote) => match crate::network::exchange_goodbye_v1_as_listener(&mut sock) {
                    Ok(()) => {
                        p2p_log_peer_tip(hid, &peer.to_string(), &remote);
                        p2p_log_height_cmp(hid, &peer.to_string(), local.height, &remote);
                        p2p_log_handshake_ms(hid, &peer.to_string(), t0.elapsed());
                    }
                    Err(e) => {
                        eprintln!(
                            "mfnd_p2p_handshake_abort hid={hid} peer={peer} stage=goodbye {e}"
                        );
                    }
                },
                Err(e) => eprintln!("mfnd_p2p_handshake_abort hid={hid} peer={peer} stage=tip {e}"),
            }
        })
        .map_err(|e| format!("mfnd serve: spawn p2p thread: {e}"))?;
    Ok(())
}

fn spawn_p2p_outbound_dial(
    addr: String,
    genesis_id: [u8; 32],
    tip_cell: P2pTipShared,
    hid_counter: P2pHidCounter,
) -> Result<(), String> {
    thread::Builder::new()
        .name("mfnd-p2p-dial".into())
        .spawn(move || {
            let local = {
                let g = tip_cell.lock().unwrap_or_else(|e| e.into_inner());
                crate::network::ChainTipV1 {
                    height: g.0,
                    tip_id: g.1,
                }
            };
            let t0 = Instant::now();
            match crate::network::tcp_connect_peer_v1_handshake_with_tip_exchange(
                addr.as_str(),
                &genesis_id,
                &local,
            ) {
                Ok((_sock, remote)) => {
                    let hid = hid_counter.fetch_add(1, AtomicOrdering::Relaxed);
                    println!("mfnd_p2p_dial_ok={addr}");
                    let _ = std::io::stdout().flush();
                    p2p_log_peer_tip(hid, addr.as_str(), &remote);
                    p2p_log_height_cmp(hid, addr.as_str(), local.height, &remote);
                    p2p_log_handshake_ms(hid, addr.as_str(), t0.elapsed());
                }
                Err(e) => eprintln!("mfnd p2p dial `{addr}`: {e}"),
            }
        })
        .map_err(|e| format!("mfnd serve: spawn p2p dial thread: {e}"))?;
    Ok(())
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

    let (p2p_tip_cell, p2p_hid_counter): (Option<P2pTipShared>, Option<P2pHidCounter>) =
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
        spawn_p2p_handshake_loop(
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
        spawn_p2p_outbound_dial(
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

#[cfg(test)]
mod tests {
    use super::p2p_height_cmp_label;

    #[test]
    fn p2p_height_cmp_label_orders_remote_vs_local() {
        assert_eq!(p2p_height_cmp_label(0, 0), "equal");
        assert_eq!(p2p_height_cmp_label(0, 1), "ahead");
        assert_eq!(p2p_height_cmp_label(2, 1), "behind");
    }
}
