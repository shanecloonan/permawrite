//! `mfnd serve` P2P accept/dial threads and stdout harness lines (`mfnd_p2p_*`).

use std::cmp::Ordering;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crate::gossip::send_p2p_advertise_v1;
use crate::{
    exchange_chain_tip_v1_as_listener, exchange_goodbye_v1_as_listener, hello_v1_handshake,
    pull_blocks_to_tip, recv_ping_send_pong, serve_post_handshake_v1,
};
use crate::{
    tcp_connect_peer_v1_handshake_with_tip_exchange, BlockSyncApplier, BlockSyncProvider,
    ChainTipV1, GossipHandler, GossipRecvStats, HelloHandshakeError, PullBlocksError,
    PullBlocksStats, P2P_GOSSIP_IO_TIMEOUT, P2P_HANDSHAKE_IO_TIMEOUT,
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

fn handshake_failure_label(err: &HelloHandshakeError) -> String {
    match err {
        HelloHandshakeError::GenesisMismatch { expected, got } => format!(
            "genesis_mismatch expected={} got={}",
            hex32(expected),
            hex32(got)
        ),
        other => other.to_string(),
    }
}

fn sync_failure_label(err: &PullBlocksError) -> String {
    match err {
        PullBlocksError::NoProgress {
            requested_start,
            requested,
            local_height,
            remote_height,
        } => format!(
            "sync_no_progress start={requested_start} requested={requested} local_height={local_height} remote_height={remote_height}"
        ),
        PullBlocksError::TooManyResponseBlocks { requested, got } => {
            format!("sync_too_many_response_blocks requested={requested} got={got}")
        }
        PullBlocksError::NonSequentialHeight { expected, got } => {
            format!("sync_non_sequential_height expected={expected} got={got}")
        }
        other => format!("sync_abort {other}"),
    }
}

fn note_handshake_failure_for_scoring(
    fanout_peers: Option<&FanoutPeerSetHook>,
    peer: &str,
    err: &HelloHandshakeError,
) -> String {
    let reason = handshake_failure_label(err);
    if let Some(ps) = fanout_peers {
        ps.note_peer_failure(peer, &reason);
    }
    reason
}

fn note_sync_failure_for_scoring(
    fanout_peers: Option<&FanoutPeerSetHook>,
    peer: &str,
    err: &PullBlocksError,
) -> String {
    let reason = sync_failure_label(err);
    if let Some(ps) = fanout_peers {
        ps.note_peer_failure(peer, &reason);
    }
    reason
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

fn sync_tip_cell(tip_cell: &TipSnapshot, tip: &ChainTipV1) {
    if let Ok(mut g) = tip_cell.lock() {
        *g = (tip.height, tip.tip_id);
    }
}

/// Prefer the live chain tip from [`BlockSyncProvider`] so handshakes match RPC `get_tip`.
fn local_chain_tip(tip_cell: &TipSnapshot, block_sync: Option<&BlockSyncHook>) -> ChainTipV1 {
    if let Some(sync) = block_sync {
        let tip = sync.chain_tip_v1();
        sync_tip_cell(tip_cell, &tip);
        tip
    } else {
        let g = tip_cell.lock().unwrap_or_else(|e| e.into_inner());
        ChainTipV1 {
            height: g.0,
            tip_id: g.1,
        }
    }
}

fn maybe_pull_blocks_if_behind(
    sock: &mut TcpStream,
    hid: u64,
    peer: &str,
    local: &ChainTipV1,
    remote: &ChainTipV1,
    applier: &BlockSyncApplierHook,
    fanout_peers: Option<&FanoutPeerSetHook>,
) {
    if remote.height <= local.height {
        return;
    }
    log_sync_start(hid, peer, local.height, remote.height);
    let _ = sock.set_read_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    match pull_blocks_to_tip(sock, local.height, remote.height, applier.as_ref()) {
        Ok(stats) => log_sync_end(hid, peer, &stats),
        Err(e) => {
            let _ = note_sync_failure_for_scoring(fanout_peers, peer, &e);
            log_sync_abort(hid, peer, &e);
        }
    }
}

/// After gossip/production on a live session, pull any missing heights in order (**M2.3.26**).
///
/// Handshake tip can be stale when blocks arrive out-of-order over gossip; if we saw block
/// frames, also try pulling up to [`crate::block_sync::MAX_BLOCKS_PER_GET_V1`] heights ahead.
#[allow(clippy::too_many_arguments)]
fn post_session_catch_up(
    sock: &mut TcpStream,
    hid: u64,
    peer: &str,
    tip_cell: &TipSnapshot,
    block_sync: Option<&BlockSyncHook>,
    applier: &BlockSyncApplierHook,
    handshake_remote: &ChainTipV1,
    gossip_stats: Option<&GossipRecvStats>,
    fanout_peers: Option<&FanoutPeerSetHook>,
) {
    let local = local_chain_tip(tip_cell, block_sync);
    let max_extra = crate::block_sync::MAX_BLOCKS_PER_GET_V1;
    let mut target_height = handshake_remote.height;
    if gossip_stats.is_some_and(|s| s.block_frames > 0) {
        target_height = target_height.max(
            local
                .height
                .saturating_add(1)
                .min(local.height.saturating_add(max_extra)),
        );
    }
    if target_height > local.height {
        let probe = ChainTipV1 {
            height: target_height,
            tip_id: handshake_remote.tip_id,
        };
        maybe_pull_blocks_if_behind(sock, hid, peer, &local, &probe, applier, fanout_peers);
    }
    let local_after = local_chain_tip(tip_cell, block_sync);
    if handshake_remote.height > local_after.height {
        maybe_pull_blocks_if_behind(
            sock,
            hid,
            peer,
            &local_after,
            handshake_remote,
            applier,
            fanout_peers,
        );
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

/// Multi-validator proposal/vote handler (**M2.3.23**).
pub type ProductionHook = Arc<dyn crate::production::ProductionHandler>;

/// Light-wallet follow batch provider (**M4.13**).
pub type LightFollowHook = Arc<dyn crate::light_follow::LightFollowProvider>;

/// Optional hooks shared by inbound and outbound P2P sessions.
#[derive(Clone, Default)]
pub struct P2pSessionHooks {
    /// Mempool gossip admission (**M2.3.16**).
    pub gossip: Option<GossipHook>,
    /// Block-log query for inbound [`GetBlocksByHeightV1`] (**M2.3.18**).
    pub block_sync: Option<BlockSyncHook>,
    /// Catch-up apply for height pulls (**M2.3.19**).
    pub block_applier: Option<BlockSyncApplierHook>,
    /// Header + evolution rows for light clients (**M4.13**).
    pub light_follow: Option<LightFollowHook>,
    /// Peer registry for fan-out (**M2.3.20**).
    pub fanout_peers: Option<FanoutPeerSetHook>,
    /// Multi-validator proposal/vote (**M2.3.23**).
    pub production: Option<ProductionHook>,
}

/// Inbound `mfnd serve --p2p-listen` accept loop configuration.
pub struct InboundP2pLoop {
    /// Bound TCP listener for inbound peers.
    pub listener: TcpListener,
    /// Expected chain genesis id for hello handshake.
    pub genesis_id: [u8; 32],
    /// Shared tip snapshot for height exchange.
    pub tip_cell: TipSnapshot,
    /// Monotonic handshake id counter.
    pub hid_counter: HidCounter,
    /// Gossip, sync, and production hooks.
    pub hooks: P2pSessionHooks,
}

/// Outbound `mfnd serve --p2p-dial` thread configuration.
pub struct OutboundP2pDial {
    /// Peer dial address (`host:port`).
    pub addr: String,
    /// Expected chain genesis id for hello handshake.
    pub genesis_id: [u8; 32],
    /// Shared tip snapshot for height exchange.
    pub tip_cell: TipSnapshot,
    /// Monotonic handshake id counter.
    pub hid_counter: HidCounter,
    /// Gossip and fan-out hooks (sync/production unused on dial).
    pub hooks: P2pSessionHooks,
    /// Local listen address to advertise after handshake, if any.
    pub local_p2p_listen: Option<SocketAddr>,
}

struct InboundGossip {
    inner: GossipHook,
    hid: u64,
    peer: String,
    fanout_peers: Option<FanoutPeerSetHook>,
    gap_catch_up: Option<GapCatchUpOnGap>,
}

/// Dial saved peer listen addrs when gossip sees a block height gap (**M2.3.26**).
struct GapCatchUpOnGap {
    genesis_id: [u8; 32],
    tip_cell: TipSnapshot,
    hid_counter: HidCounter,
    block_sync: Option<BlockSyncHook>,
    block_applier: BlockSyncApplierHook,
    fanout_peers: FanoutPeerSetHook,
    local_p2p_listen: Option<SocketAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GapCatchUpPeerEvent {
    SkipSelf { peer: String },
    CapReached { count: u32, cap: u32 },
    Dial { peer: String },
}

fn is_self_peer_addr(peer_addr: &str, local_p2p_listen: Option<SocketAddr>) -> bool {
    let Some(local) = local_p2p_listen else {
        return false;
    };
    let trimmed = peer_addr.trim();
    if trimmed == local.to_string() {
        return true;
    }
    trimmed
        .parse::<SocketAddr>()
        .map(|peer| peer == local)
        .unwrap_or(false)
}

fn gap_catch_up_peer_addrs(
    inbound_peer: &str,
    boot_peer_addrs: Vec<String>,
    local_p2p_listen: Option<SocketAddr>,
) -> (Vec<String>, Vec<String>) {
    let mut addrs = Vec::new();
    let mut skipped_self = Vec::new();
    for addr in std::iter::once(inbound_peer.to_string()).chain(boot_peer_addrs) {
        if addrs.iter().any(|a| a == &addr) || skipped_self.iter().any(|a| a == &addr) {
            continue;
        }
        if is_self_peer_addr(&addr, local_p2p_listen) {
            skipped_self.push(addr);
        } else {
            addrs.push(addr);
        }
    }
    (addrs, skipped_self)
}

fn gap_catch_up_peer_events(
    inbound_peer: &str,
    boot_peer_addrs: Vec<String>,
    local_p2p_listen: Option<SocketAddr>,
    cap: u32,
) -> Vec<GapCatchUpPeerEvent> {
    let (addrs, skipped_self) =
        gap_catch_up_peer_addrs(inbound_peer, boot_peer_addrs, local_p2p_listen);
    let mut events = Vec::new();
    for peer in skipped_self {
        events.push(GapCatchUpPeerEvent::SkipSelf { peer });
    }
    let mut spawned = 0u32;
    for peer in addrs {
        if spawned >= cap {
            events.push(GapCatchUpPeerEvent::CapReached {
                count: spawned,
                cap,
            });
            break;
        }
        events.push(GapCatchUpPeerEvent::Dial { peer });
        spawned = spawned.saturating_add(1);
    }
    events
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
        } else if label.starts_with("rejected:gap:") {
            log_gossip_block(self.hid, &self.peer, "gap", None);
            if let Some(cfg) = &self.gap_catch_up {
                let events = gap_catch_up_peer_events(
                    &self.peer,
                    cfg.fanout_peers.boot_peer_addrs(),
                    cfg.local_p2p_listen,
                    cfg.fanout_peers.max_outbound_peers(),
                );
                for event in events {
                    match event {
                        GapCatchUpPeerEvent::SkipSelf { peer } => {
                            println!("mfnd_p2p_self_dial_skip peer={peer}");
                            let _ = std::io::stdout().flush();
                        }
                        GapCatchUpPeerEvent::CapReached { count, cap } => {
                            println!("mfnd_p2p_gap_catchup_cap_reached count={count} cap={cap}");
                            let _ = std::io::stdout().flush();
                            break;
                        }
                        GapCatchUpPeerEvent::Dial { peer } => {
                            let _ = spawn_catch_up_dial(
                                peer,
                                cfg.genesis_id,
                                Arc::clone(&cfg.tip_cell),
                                Arc::clone(&cfg.hid_counter),
                                cfg.block_sync.clone(),
                                Arc::clone(&cfg.block_applier),
                                Some(Arc::clone(&cfg.fanout_peers)),
                            );
                        }
                    }
                }
            }
        } else if let Some(reason) = label.strip_prefix("rejected:") {
            log_gossip_block(self.hid, &self.peer, reason, None);
        }
        label
    }

    fn on_chunk_v1(&self, commit_hash: &[u8; 32], chunk_index: u32, chunk_bytes: &[u8]) -> String {
        let label = self
            .inner
            .on_chunk_v1(commit_hash, chunk_index, chunk_bytes);
        if label.starts_with("stored:") {
            println!(
                "mfnd_p2p_chunk_stored hid={} peer={} index={chunk_index} bytes={}",
                self.hid,
                self.peer,
                chunk_bytes.len()
            );
            let _ = std::io::stdout().flush();
        } else if label.starts_with("rejected:") {
            eprintln!(
                "mfnd_p2p_chunk_rejected hid={} peer={} index={chunk_index} {label}",
                self.hid, self.peer
            );
        }
        label
    }
}

fn log_blocks_reply(hid: u64, peer: &str, start_height: u32, requested: u32, returned: usize) {
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
    fn chain_tip_v1(&self) -> ChainTipV1 {
        self.inner.chain_tip_v1()
    }

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
        gap_catch_up: None,
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

#[allow(clippy::too_many_arguments)]
fn recv_post_handshake(
    sock: &mut TcpStream,
    hid: u64,
    peer: &str,
    tip_cell: &TipSnapshot,
    hid_counter: &HidCounter,
    genesis_id: [u8; 32],
    handshake_remote: &ChainTipV1,
    gossip: &GossipHook,
    block_sync: Option<&BlockSyncHook>,
    block_applier: Option<&BlockSyncApplierHook>,
    light_follow: Option<&LightFollowHook>,
    fanout_peers: Option<&FanoutPeerSetHook>,
    production: Option<&ProductionHook>,
    local_p2p_listen: Option<SocketAddr>,
) {
    let _ = sock.set_read_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    let gap_catch_up = match (block_applier.as_ref(), fanout_peers) {
        (Some(a), Some(ps)) => Some(GapCatchUpOnGap {
            genesis_id,
            tip_cell: Arc::clone(tip_cell),
            hid_counter: Arc::clone(hid_counter),
            block_sync: block_sync.cloned(),
            block_applier: Arc::clone(a),
            fanout_peers: Arc::clone(ps),
            local_p2p_listen,
        }),
        _ => None,
    };
    let session = InboundGossip {
        inner: gossip.clone(),
        hid,
        peer: peer.to_string(),
        fanout_peers: fanout_peers.cloned(),
        gap_catch_up,
    };
    let Some(sync) = block_sync else {
        recv_inbound_gossip(sock, hid, peer, gossip, fanout_peers);
        return;
    };
    let logging = InboundBlockSync {
        inner: sync.clone(),
        hid,
        peer: peer.to_string(),
    };
    loop {
        let gossip_stats = match serve_post_handshake_v1(
            sock,
            peer,
            &logging,
            &session,
            fanout_peers.map(|ps| ps.as_ref()),
            production.map(|h| h.as_ref()),
            block_applier.map(|a| a.as_ref()),
            light_follow.map(|lf| lf.as_ref()),
        ) {
            Ok(Some(stats)) => {
                if stats.tx_frames > 0 || stats.block_frames > 0 {
                    log_gossip_end(hid, peer, &stats);
                }
                Some(stats)
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("mfnd_p2p_gossip_abort hid={hid} peer={peer} {e}");
                break;
            }
        };
        if let Some(a) = block_applier {
            post_session_catch_up(
                sock,
                hid,
                peer,
                tip_cell,
                block_sync,
                a,
                handshake_remote,
                gossip_stats.as_ref(),
                fanout_peers,
            );
        }
    }
}

/// Spawn the inbound P2P accept loop used by `mfnd serve --p2p-listen`.
pub fn spawn_inbound_handshake_loop(cfg: InboundP2pLoop) -> Result<(), String> {
    let InboundP2pLoop {
        listener,
        genesis_id,
        tip_cell,
        hid_counter,
        hooks:
            P2pSessionHooks {
                gossip,
                block_sync,
                block_applier,
                light_follow,
                fanout_peers,
                production,
            },
    } = cfg;
    let local_p2p_listen = listener.local_addr().ok();
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
            let local = local_chain_tip(&tip_cell, block_sync.as_ref());
            match exchange_chain_tip_v1_as_listener(&mut sock, &local) {
                Ok(remote) => match exchange_goodbye_v1_as_listener(&mut sock) {
                    Ok(()) => {
                        let peer_s = peer.to_string();
                        // Register before logging so a concurrent `--produce` seal cannot miss fan-out.
                        if let Some(ps) = &fanout_peers {
                            ps.register_ephemeral_peer(&peer_s);
                            if let Ok(clone) = sock.try_clone() {
                                ps.register_session(&peer_s, clone);
                                ps.on_session_registered(&peer_s);
                            }
                        }
                        log_peer_tip(hid, &peer_s, &remote);
                        log_height_cmp(hid, &peer_s, local.height, &remote);
                        log_handshake_ms(hid, &peer_s, t0.elapsed());
                        // Inbound peers may dial to send proposals/votes; do not start a height
                        // pull on this socket before reading their frames.
                        if gossip.is_some() || production.is_some() {
                            if let Some(h) = &gossip {
                                recv_post_handshake(
                                    &mut sock,
                                    hid,
                                    &peer_s,
                                    &tip_cell,
                                    &hid_counter,
                                    genesis_id,
                                    &remote,
                                    h,
                                    block_sync.as_ref(),
                                    block_applier.as_ref(),
                                    light_follow.as_ref(),
                                    fanout_peers.as_ref(),
                                    production.as_ref(),
                                    local_p2p_listen,
                                );
                            }
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

/// One-shot dial: handshake, pull missing blocks if behind, then close (**M2.3.25**).
pub fn spawn_catch_up_dial(
    addr: String,
    genesis_id: [u8; 32],
    tip_cell: TipSnapshot,
    hid_counter: HidCounter,
    block_sync: Option<BlockSyncHook>,
    block_applier: BlockSyncApplierHook,
    fanout_peers: Option<FanoutPeerSetHook>,
) -> Result<(), String> {
    thread::Builder::new()
        .name("mfnd-p2p-catchup".into())
        .spawn(move || {
            let local = local_chain_tip(&tip_cell, block_sync.as_ref());
            let t0 = Instant::now();
            match tcp_connect_peer_v1_handshake_with_tip_exchange(
                addr.as_str(),
                &genesis_id,
                &local,
            ) {
                Ok((mut sock, remote)) => {
                    if let Some(ps) = &fanout_peers {
                        ps.note_peer_success(addr.as_str());
                    }
                    let hid = hid_counter.fetch_add(1, AtomicOrdering::Relaxed);
                    log_peer_tip(hid, addr.as_str(), &remote);
                    log_height_cmp(hid, addr.as_str(), local.height, &remote);
                    log_handshake_ms(hid, addr.as_str(), t0.elapsed());
                    maybe_pull_blocks_if_behind(
                        &mut sock,
                        hid,
                        addr.as_str(),
                        &local,
                        &remote,
                        &block_applier,
                        fanout_peers.as_ref(),
                    );
                }
                Err(e) => {
                    let reason = note_handshake_failure_for_scoring(
                        fanout_peers.as_ref(),
                        addr.as_str(),
                        &e,
                    );
                    eprintln!("mfnd_p2p_catchup_dial_abort peer={addr} reason={reason}");
                }
            }
        })
        .map_err(|e| format!("mfnd serve: spawn p2p catch-up dial: {e}"))?;
    Ok(())
}

/// Spawn the outbound P2P dial thread used by `mfnd serve --p2p-dial`.
pub fn spawn_outbound_dial(cfg: OutboundP2pDial) -> Result<(), String> {
    let OutboundP2pDial {
        addr,
        genesis_id,
        tip_cell,
        hid_counter,
        hooks:
            P2pSessionHooks {
                gossip,
                block_sync,
                block_applier,
                light_follow,
                fanout_peers,
                production,
            },
        local_p2p_listen,
    } = cfg;
    thread::Builder::new()
        .name("mfnd-p2p-dial".into())
        .spawn(move || {
            let local = local_chain_tip(&tip_cell, block_sync.as_ref());
            let t0 = Instant::now();
            match tcp_connect_peer_v1_handshake_with_tip_exchange(
                addr.as_str(),
                &genesis_id,
                &local,
            ) {
                Ok((mut sock, remote)) => {
                    let hid = hid_counter.fetch_add(1, AtomicOrdering::Relaxed);
                    if let Some(ps) = &fanout_peers {
                        ps.register_peer(addr.as_str());
                        if let Ok(clone) = sock.try_clone() {
                            ps.register_session(addr.as_str(), clone);
                            ps.on_session_registered(addr.as_str());
                        }
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
                    // Pull missing blocks before blocking on inbound gossip; otherwise a
                    // behind dialer waits forever while the peer also waits (**M2.3.26**).
                    if let Some(a) = &block_applier {
                        if remote.height > local.height {
                            maybe_pull_blocks_if_behind(
                                &mut sock,
                                hid,
                                addr.as_str(),
                                &local,
                                &remote,
                                a,
                                fanout_peers.as_ref(),
                            );
                        }
                    }
                    if gossip.is_some() || production.is_some() {
                        if let Some(h) = &gossip {
                            recv_post_handshake(
                                &mut sock,
                                hid,
                                addr.as_str(),
                                &tip_cell,
                                &hid_counter,
                                genesis_id,
                                &remote,
                                h,
                                block_sync.as_ref(),
                                block_applier.as_ref(),
                                light_follow.as_ref(),
                                fanout_peers.as_ref(),
                                production.as_ref(),
                                local_p2p_listen,
                            );
                        }
                    } else if let Some(a) = &block_applier {
                        maybe_pull_blocks_if_behind(
                            &mut sock,
                            hid,
                            addr.as_str(),
                            &local,
                            &remote,
                            a,
                            fanout_peers.as_ref(),
                        );
                    }
                }
                Err(e) => {
                    let reason = note_handshake_failure_for_scoring(
                        fanout_peers.as_ref(),
                        addr.as_str(),
                        &e,
                    );
                    eprintln!("mfnd_p2p_dial_abort peer={addr} reason={reason}");
                }
            }
        })
        .map_err(|e| format!("mfnd serve: spawn p2p dial thread: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FanoutPeerSet;

    #[derive(Default)]
    struct RecordingFanoutPeerSet {
        failures: Mutex<Vec<(String, String)>>,
    }

    impl RecordingFanoutPeerSet {
        fn failures(&self) -> Vec<(String, String)> {
            self.failures.lock().expect("failures lock").clone()
        }
    }

    impl FanoutPeerSet for RecordingFanoutPeerSet {
        fn register_peer(&self, _peer_addr: &str) {}

        fn note_peer_failure(&self, peer_addr: &str, reason: &str) {
            self.failures
                .lock()
                .expect("failures lock")
                .push((peer_addr.to_string(), reason.to_string()));
        }

        fn fanout_fresh_tx(&self, _tx_wire: &[u8], _except_peer: Option<&str>) {}
    }

    #[test]
    fn handshake_failure_label_pins_genesis_mismatch_reason() {
        let expected = [0x11u8; 32];
        let got = [0x22u8; 32];
        let err = HelloHandshakeError::GenesisMismatch { expected, got };

        assert_eq!(
            handshake_failure_label(&err),
            "genesis_mismatch expected=1111111111111111111111111111111111111111111111111111111111111111 got=2222222222222222222222222222222222222222222222222222222222222222"
        );
    }

    #[test]
    fn handshake_failure_label_preserves_connect_io_reason_for_scoring() {
        let err = HelloHandshakeError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "connection timed out",
        ));

        assert_eq!(handshake_failure_label(&err), "connection timed out");
    }

    #[test]
    fn sync_failure_label_pins_no_progress_reason() {
        let err = PullBlocksError::NoProgress {
            requested_start: 12,
            requested: 8,
            local_height: 11,
            remote_height: 30,
        };

        assert_eq!(
            sync_failure_label(&err),
            "sync_no_progress start=12 requested=8 local_height=11 remote_height=30"
        );
    }

    #[test]
    fn sync_failure_label_pins_adversarial_response_reasons() {
        assert_eq!(
            sync_failure_label(&PullBlocksError::TooManyResponseBlocks {
                requested: 1,
                got: 2
            }),
            "sync_too_many_response_blocks requested=1 got=2"
        );
        assert_eq!(
            sync_failure_label(&PullBlocksError::NonSequentialHeight {
                expected: 4,
                got: 6
            }),
            "sync_non_sequential_height expected=4 got=6"
        );
    }

    #[test]
    fn catch_up_handshake_failure_feeds_peer_scoring_label() {
        let fanout = Arc::new(RecordingFanoutPeerSet::default());
        let hook: FanoutPeerSetHook = fanout.clone();
        let err = HelloHandshakeError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));

        let reason = note_handshake_failure_for_scoring(Some(&hook), "203.0.113.10:19001", &err);

        assert_eq!(reason, "connection refused");
        assert_eq!(
            fanout.failures(),
            vec![(
                "203.0.113.10:19001".to_string(),
                "connection refused".to_string(),
            )]
        );
    }

    #[test]
    fn gap_catch_up_sync_failure_feeds_peer_scoring_label() {
        let fanout = Arc::new(RecordingFanoutPeerSet::default());
        let hook: FanoutPeerSetHook = fanout.clone();
        let err = PullBlocksError::NoProgress {
            requested_start: 12,
            requested: 8,
            local_height: 11,
            remote_height: 30,
        };

        let reason = note_sync_failure_for_scoring(Some(&hook), "203.0.113.11:19001", &err);

        assert_eq!(
            reason,
            "sync_no_progress start=12 requested=8 local_height=11 remote_height=30"
        );
        assert_eq!(
            fanout.failures(),
            vec![(
                "203.0.113.11:19001".to_string(),
                "sync_no_progress start=12 requested=8 local_height=11 remote_height=30"
                    .to_string(),
            )]
        );
    }

    #[test]
    fn gap_catch_up_peer_addrs_skips_self_before_dialing() {
        let local = "127.0.0.1:19001".parse::<SocketAddr>().unwrap();

        let (addrs, skipped) = gap_catch_up_peer_addrs(
            "127.0.0.1:19001",
            vec!["127.0.0.1:19002".to_string()],
            Some(local),
        );

        assert_eq!(addrs, vec!["127.0.0.1:19002"]);
        assert_eq!(skipped, vec!["127.0.0.1:19001"]);
    }

    #[test]
    fn gap_catch_up_peer_addrs_dedupes_self_skips_and_dials() {
        let local = "127.0.0.1:19001".parse::<SocketAddr>().unwrap();

        let (addrs, skipped) = gap_catch_up_peer_addrs(
            "127.0.0.1:19002",
            vec![
                " 127.0.0.1:19001 ".to_string(),
                "127.0.0.1:19002".to_string(),
                "127.0.0.1:19003".to_string(),
                "127.0.0.1:19003".to_string(),
            ],
            Some(local),
        );

        assert_eq!(addrs, vec!["127.0.0.1:19002", "127.0.0.1:19003"]);
        assert_eq!(skipped, vec![" 127.0.0.1:19001 "]);
    }

    #[test]
    fn gap_catch_up_peer_events_preserve_self_skip_and_cap_order() {
        let local = "127.0.0.1:19001".parse::<SocketAddr>().unwrap();

        assert_eq!(
            gap_catch_up_peer_events(
                "127.0.0.1:19001",
                vec![
                    "127.0.0.1:19002".to_string(),
                    "127.0.0.1:19003".to_string(),
                    "127.0.0.1:19004".to_string(),
                ],
                Some(local),
                2,
            ),
            vec![
                GapCatchUpPeerEvent::SkipSelf {
                    peer: "127.0.0.1:19001".to_string(),
                },
                GapCatchUpPeerEvent::Dial {
                    peer: "127.0.0.1:19002".to_string(),
                },
                GapCatchUpPeerEvent::Dial {
                    peer: "127.0.0.1:19003".to_string(),
                },
                GapCatchUpPeerEvent::CapReached { count: 2, cap: 2 },
            ]
        );
    }

    #[test]
    fn gap_catch_up_peer_events_cap_after_quarantine_filtered_inputs() {
        assert_eq!(
            gap_catch_up_peer_events(
                "203.0.113.11:19001",
                vec![
                    "203.0.113.12:19001".to_string(),
                    "203.0.113.13:19001".to_string(),
                ],
                None,
                1,
            ),
            vec![
                GapCatchUpPeerEvent::Dial {
                    peer: "203.0.113.11:19001".to_string(),
                },
                GapCatchUpPeerEvent::CapReached { count: 1, cap: 1 },
            ]
        );
    }
}
