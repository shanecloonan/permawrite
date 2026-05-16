//! `mfnd serve` P2P accept/dial threads and stdout harness lines (`mfnd_p2p_*`).

use std::cmp::Ordering;
use std::io::Write;
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crate::{
    exchange_chain_tip_v1_as_listener, exchange_goodbye_v1_as_listener, hello_v1_handshake,
    recv_ping_send_pong, tcp_connect_peer_v1_handshake_with_tip_exchange, ChainTipV1,
    P2P_HANDSHAKE_IO_TIMEOUT,
};

/// Shared `(tip_height, tip_id)` snapshot for [`ChainTipV1`] exchange during `mfnd serve`.
pub type TipSnapshot = Arc<Mutex<(u32, [u8; 32])>>;

/// Monotonic handshake id counter for P2P stdout correlation (`hid=`).
pub type HidCounter = Arc<AtomicU64>;

fn hex32(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Compare remote height to local for `mfnd_p2p_height_cmp` stdout (`ahead` / `equal` / `behind`).
pub fn height_cmp_label(local_height: u32, remote_height: u32) -> &'static str {
    match remote_height.cmp(&local_height) {
        Ordering::Less => "behind",
        Ordering::Equal => "equal",
        Ordering::Greater => "ahead",
    }
}

fn log_peer_tip(hid: u64, peer: &str, remote: &ChainTipV1) {
    println!(
        "mfnd_p2p_peer_tip hid={hid} peer={peer} height={} tip_id={}",
        remote.height,
        hex32(&remote.tip_id)
    );
    let _ = std::io::stdout().flush();
}

fn log_height_cmp(hid: u64, peer: &str, local_height: u32, remote: &ChainTipV1) {
    let cmp = height_cmp_label(local_height, remote.height);
    println!(
        "mfnd_p2p_height_cmp hid={hid} peer={peer} local_height={local_height} remote_height={} cmp={cmp}",
        remote.height
    );
    let _ = std::io::stdout().flush();
}

fn log_handshake_ms(hid: u64, peer: &str, elapsed: std::time::Duration) {
    println!(
        "mfnd_p2p_handshake_ms hid={hid} peer={peer} ms={}",
        elapsed.as_millis()
    );
    let _ = std::io::stdout().flush();
}

/// Spawn the inbound P2P accept loop used by `mfnd serve --p2p-listen`.
pub fn spawn_inbound_handshake_loop(
    listener: TcpListener,
    genesis_id: [u8; 32],
    tip_cell: TipSnapshot,
    hid_counter: HidCounter,
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
            let _ = sock.set_read_timeout(Some(P2P_HANDSHAKE_IO_TIMEOUT));
            let _ = sock.set_write_timeout(Some(P2P_HANDSHAKE_IO_TIMEOUT));
            if let Err(e) = hello_v1_handshake(&mut sock, &genesis_id) {
                eprintln!("mfnd_p2p_handshake_abort hid={hid} peer={peer} stage=hello {e}");
                continue;
            }
            if let Err(e) = recv_ping_send_pong(&mut sock) {
                eprintln!("mfnd_p2p_handshake_abort hid={hid} peer={peer} stage=ping_pong {e}");
                continue;
            }
            let local = {
                let g = tip_cell.lock().unwrap_or_else(|e| e.into_inner());
                ChainTipV1 {
                    height: g.0,
                    tip_id: g.1,
                }
            };
            match exchange_chain_tip_v1_as_listener(&mut sock, &local) {
                Ok(remote) => match exchange_goodbye_v1_as_listener(&mut sock) {
                    Ok(()) => {
                        let peer_s = peer.to_string();
                        log_peer_tip(hid, &peer_s, &remote);
                        log_height_cmp(hid, &peer_s, local.height, &remote);
                        log_handshake_ms(hid, &peer_s, t0.elapsed());
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

/// Spawn the outbound P2P dial thread used by `mfnd serve --p2p-dial`.
pub fn spawn_outbound_dial(
    addr: String,
    genesis_id: [u8; 32],
    tip_cell: TipSnapshot,
    hid_counter: HidCounter,
) -> Result<(), String> {
    thread::Builder::new()
        .name("mfnd-p2p-dial".into())
        .spawn(move || {
            let local = {
                let g = tip_cell.lock().unwrap_or_else(|e| e.into_inner());
                ChainTipV1 {
                    height: g.0,
                    tip_id: g.1,
                }
            };
            let t0 = Instant::now();
            match tcp_connect_peer_v1_handshake_with_tip_exchange(
                addr.as_str(),
                &genesis_id,
                &local,
            ) {
                Ok((_sock, remote)) => {
                    let hid = hid_counter.fetch_add(1, AtomicOrdering::Relaxed);
                    println!("mfnd_p2p_dial_ok={addr}");
                    let _ = std::io::stdout().flush();
                    log_peer_tip(hid, addr.as_str(), &remote);
                    log_height_cmp(hid, addr.as_str(), local.height, &remote);
                    log_handshake_ms(hid, addr.as_str(), t0.elapsed());
                }
                Err(e) => eprintln!("mfnd p2p dial `{addr}`: {e}"),
            }
        })
        .map_err(|e| format!("mfnd serve: spawn p2p dial thread: {e}"))?;
    Ok(())
}
