//! `mfnd serve` P2P accept/dial threads and stdout harness lines (`mfnd_p2p_*`).

use std::cmp::Ordering;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crate::{
    exchange_chain_tip_v1_as_listener, exchange_goodbye_v1_as_listener, hello_v1_handshake,
    pull_blocks_to_tip, recv_ping_send_pong, send_gossip_end_v1, serve_post_handshake_v1,
};
use crate::gossip::send_p2p_advertise_v1;
use crate::{
    tcp_connect_peer_v1_handshake_with_tip_exchange, BlockSyncApplier, BlockSyncProvider,
    ChainTipV1, GossipHandler, GossipRecvStats, PullBlocksStats, P2P_GOSSIP_IO_TIMEOUT,
    P2P_HANDSHAKE_IO_TIMEOUT,
};

/// Shared gossip admission hook for inbound P2P sessions (**M2.3.16**).
pub type GossipHook = Arc<dyn GossipHandler>;

/// Block-log query hook for inbound [`GetBlocksByHeightV1`] (**M2.3.18**).
pub type BlockSyncHook = Arc<dyn BlockSyncProvider>;

/// Apply hook for outbound/inbound catch-up pulls (**M2.3.19**).
pub type BlockSyncApplierHook = Arc<dyn BlockSyncApplier>;

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

fn log_gossip_tx(hid: u64, peer: &str, outcome: &str, tx_id_hex: &str) {
    println!("mfnd_p2p_tx_admit hid={hid} peer={peer} outcome={outcome} tx_id={tx_id_hex}");
    let _ = std::io::stdout().flush();
}

fn log_gossip_block(hid: u64, peer: &str, outcome: &str, height: Option<u32>) {
    match height {
        Some(h) => {
            println!("mfnd_p2p_block_apply hid={hid} peer={peer} outcome={outcome} height={h}")
        }
        None => println!("mfnd_p2p_block_apply hid={hid} peer={peer} outcome={outcome}"),
    }
    let _ = std::io::stdout().flush();
}

fn log_sync_start(hid: u64, peer: &str, local_height: u32, remote_height: u32) {
    println!(
        "mfnd_p2p_sync_start hid={hid} peer={peer} local_height={local_height} remote_height={remote_height}"
    );
    let _ = std::io::stdout().flush();
}

fn log_sync_end(hid: u64, peer: &str, stats: &PullBlocksStats) {
    println!(
        "mfnd_p2p_sync_end hid={hid} peer={peer} applied={} final_height={}",
        stats.blocks_applied, stats.local_height_after
    );
    let _ = std::io::stdout().flush();
}

fn log_sync_abort(hid: u64, peer: &str, err: &impl std::fmt::Display) {
    eprintln!("mfnd_p2p_sync_abort hid={hid} peer={peer} {err}");
}

fn maybe_pull_blocks_if_behind(
    sock: &mut TcpStream,
    hid: u64,
    peer: &str,
    local: &ChainTipV1,
    remote: &ChainTipV1,
    applier: &BlockSyncApplierHook,
) {
    if remote.height <= local.height {
        return;
    }
    log_sync_start(hid, peer, local.height, remote.height);
    let _ = sock.set_read_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    match pull_blocks_to_tip(sock, local.height, remote.height, applier.as_ref()) {
        Ok(stats) => log_sync_end(hid, peer, &stats),
        Err(e) => log_sync_abort(hid, peer, &e),
    }
}

fn log_gossip_end(hid: u64, peer: &str, stats: &GossipRecvStats) {
    println!(
        "mfnd_p2p_gossip_end hid={hid} peer={peer} tx_frames={} block_frames={}",
        stats.tx_frames, stats.block_frames
    );
    let _ = std::io::stdout().flush();
}

/// Registry of peers for mempool fan-out (**M2.3.20**).
pub type FanoutPeerSetHook = Arc<dyn crate::gossip::FanoutPeerSet>;

struct InboundGossip {
    inner: GossipHook,
    hid: u64,
    peer: String,
    fanout_peers: Option<FanoutPeerSetHook>,
}

impl GossipHandler for InboundGossip {
    fn on_tx_v1(&self, tx_wire: &[u8]) -> String {
        let label = self.inner.on_tx_v1(tx_wire);
        if let Some(tx_id) = label.strip_prefix("fresh:") {
            log_gossip_tx(self.hid, &self.peer, "accepted", tx_id);
            if let Some(ps) = &self.fanout_peers {
                ps.fanout_fresh_tx(tx_wire, Some(&self.peer));
            }
        } else if let Some(tx_id) = label.strip_prefix("accepted:") {
            log_gossip_tx(self.hid, &self.peer, "accepted", tx_id);
        } else if let Some(reason) = label.strip_prefix("rejected:") {
            log_gossip_tx(self.hid, &self.peer, reason, "none");
        }
        label
    }

    fn on_block_v1(&self, block_wire: &[u8]) -> String {
        let label = self.inner.on_block_v1(block_wire);
        if let Some(rest) = label.strip_prefix("applied:") {
            let height = rest.split(':').next().and_then(|s| s.parse::<u32>().ok());
            log_gossip_block(self.hid, &self.peer, "applied", height);
        } else if let Some(reason) = label.strip_prefix("rejected:") {
            log_gossip_block(self.hid, &self.peer, reason, None);
        }
        label
    }
}

fn log_blocks_reply(
    hid: u64,
    peer: &str,
    start_height: u32,
    requested: u32,
    returned: usize,
) {
    println!(
        "mfnd_p2p_blocks_reply hid={hid} peer={peer} start_height={start_height} requested={requested} returned={returned}"
    );
    let _ = std::io::stdout().flush();
}

struct InboundBlockSync {
    inner: BlockSyncHook,
    hid: u64,
    peer: String,
}

impl BlockSyncProvider for InboundBlockSync {
    fn blocks_from_height(&self, start_height: u32, count: u32) -> Vec<Vec<u8>> {
        let requested = count.min(crate::block_sync::MAX_BLOCKS_PER_GET_V1);
        let wires = self.inner.blocks_from_height(start_height, requested);
        log_blocks_reply(self.hid, &self.peer, start_height, count, wires.len());
        wires
    }
}

fn recv_inbound_gossip(
    sock: &mut TcpStream,
    hid: u64,
    peer: &str,
    handler: &GossipHook,
    fanout_peers: Option<&FanoutPeerSetHook>,
) {
    let _ = sock.set_read_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    let session = InboundGossip {
        inner: handler.clone(),
        hid,
        peer: peer.to_string(),
        fanout_peers: fanout_peers.cloned(),
    };
    match crate::gossip::recv_gossip_v1(sock, &session) {
        Ok(stats) => {
            if stats.tx_frames > 0 || stats.block_frames > 0 {
                log_gossip_end(hid, peer, &stats);
            }
        }
        Err(e) => eprintln!("mfnd_p2p_gossip_abort hid={hid} peer={peer} {e}"),
    }
}

fn recv_post_handshake(
    sock: &mut TcpStream,
    hid: u64,
    peer: &str,
    gossip: &GossipHook,
    block_sync: Option<&BlockSyncHook>,
    fanout_peers: Option<&FanoutPeerSetHook>,
) {
    let _ = sock.set_read_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    let session = InboundGossip {
        inner: gossip.clone(),
        hid,
        peer: peer.to_string(),
        fanout_peers: fanout_peers.cloned(),
    };
    let result = if let Some(sync) = block_sync {
        let logging = InboundBlockSync {
            inner: sync.clone(),
            hid,
            peer: peer.to_string(),
        };
        serve_post_handshake_v1(
            sock,
            &logging,
            &session,
            fanout_peers.map(|ps| ps.as_ref()),
        )
    } else {
        recv_inbound_gossip(sock, hid, peer, gossip, fanout_peers);
        return;
    };
    match result {
        Ok(Some(stats)) => {
            if stats.tx_frames > 0 || stats.block_frames > 0 {
                log_gossip_end(hid, peer, &stats);
            }
        }
        Ok(None) => {}
        Err(e) => eprintln!("mfnd_p2p_gossip_abort hid={hid} peer={peer} {e}"),
    }
}

/// Spawn the inbound P2P accept loop used by `mfnd serve --p2p-listen`.
pub fn spawn_inbound_handshake_loop(
    listener: TcpListener,
    genesis_id: [u8; 32],
    tip_cell: TipSnapshot,
    hid_counter: HidCounter,
    gossip: Option<GossipHook>,
    block_sync: Option<BlockSyncHook>,
    block_applier: Option<BlockSyncApplierHook>,
    fanout_peers: Option<FanoutPeerSetHook>,
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
                        if let Some(a) = &block_applier {
                            maybe_pull_blocks_if_behind(
                                &mut sock, hid, &peer_s, &local, &remote, a,
                            );
                        }
                        if let Some(h) = &gossip {
                            recv_post_handshake(
                                &mut sock,
                                hid,
                                &peer_s,
                                h,
                                block_sync.as_ref(),
                                fanout_peers.as_ref(),
                            );
                        }
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
    gossip: Option<GossipHook>,
    block_applier: Option<BlockSyncApplierHook>,
    fanout_peers: Option<FanoutPeerSetHook>,
    local_p2p_listen: Option<SocketAddr>,
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
                Ok((mut sock, remote)) => {
                    let hid = hid_counter.fetch_add(1, AtomicOrdering::Relaxed);
                    if let Some(ps) = &fanout_peers {
                        ps.register_peer(&addr);
                    }
                    println!("mfnd_p2p_dial_ok={addr}");
                    let _ = std::io::stdout().flush();
                    log_peer_tip(hid, addr.as_str(), &remote);
                    log_height_cmp(hid, addr.as_str(), local.height, &remote);
                    log_handshake_ms(hid, addr.as_str(), t0.elapsed());
                    if let Some(listen) = local_p2p_listen {
                        let _ = sock.set_read_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
                        let _ = sock.set_write_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
                        if let Err(e) = send_p2p_advertise_v1(&mut sock, &listen.to_string()) {
                            eprintln!("mfnd_p2p_advertise_abort hid={hid} peer={addr} {e}");
                        }
                    }
                    if let Some(a) = &block_applier {
                        maybe_pull_blocks_if_behind(
                            &mut sock, hid, addr.as_str(), &local, &remote, a,
                        );
                    }
                    if gossip.is_some() {
                        let _ = sock.set_read_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
                        let _ = sock.set_write_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
                        if let Err(e) = send_gossip_end_v1(&mut sock) {
                            eprintln!("mfnd_p2p_gossip_abort hid={hid} peer={addr} dial_send: {e}");
                        }
                    }
                }
                Err(e) => eprintln!("mfnd p2p dial `{addr}`: {e}"),
            }
        })
        .map_err(|e| format!("mfnd serve: spawn p2p dial thread: {e}"))?;
    Ok(())
}
