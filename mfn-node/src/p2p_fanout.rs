//! Mempool tx fan-out and persistent peer registry (**M2.3.20**, **M2.3.22**).

use std::collections::{BTreeMap, BTreeSet};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use mfn_consensus::{decode_transaction, tx_id};
use mfn_net::{
    push_block_gossip_to_peer, push_chunks_gossip_to_peer, push_proposal_v1_to_peer,
    push_tx_gossip_to_peer, push_vote_v1_to_peer, read_vote_v1_reply, send_block_v1, send_chunk_v1,
    send_gossip_end_v1, send_proposal_v1, send_vote_v1, spawn_catch_up_dial, spawn_outbound_dial,
    BlockSyncApplierHook, BlockSyncHook, ChainTipV1, FanoutPeerSet, GossipHook, HidCounter,
    OutboundP2pDial, P2pSessionHooks, ProductionHook, TipSnapshot,
};
use mfn_store::{load_peers, save_peers, DEFAULT_MAX_OUTBOUND_PEERS};

/// Peers that completed a successful P2P handshake (address strings suitable for `TcpStream::connect`).
#[derive(Clone)]
pub struct P2pPeerSet {
    genesis_id: [u8; 32],
    tip_cell: TipSnapshot,
    data_root: PathBuf,
    max_outbound_peers: u32,
    peers: Arc<Mutex<BTreeSet<String>>>,
    sessions: Arc<Mutex<BTreeMap<String, Arc<Mutex<TcpStream>>>>>,
    production: Arc<Mutex<Option<ProductionHook>>>,
    fanout_lock: Arc<Mutex<()>>,
}

impl P2pPeerSet {
    /// Build a fan-out registry; loads `peers.json` when present (**M2.3.22**).
    pub fn new(
        genesis_id: [u8; 32],
        tip_cell: TipSnapshot,
        data_root: impl Into<PathBuf>,
    ) -> Arc<Self> {
        let data_root = data_root.into();
        let (initial, max_outbound_peers) = load_peers(&data_root).unwrap_or_else(|e| {
            eprintln!("mfnd_peers_load_abort {e}");
            (BTreeSet::new(), DEFAULT_MAX_OUTBOUND_PEERS)
        });
        let count = initial.len();
        if count > 0 {
            println!("mfnd_peers_load_ok count={count} max_outbound_peers={max_outbound_peers}");
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
        Arc::new(Self {
            genesis_id,
            tip_cell,
            data_root,
            max_outbound_peers,
            peers: Arc::new(Mutex::new(initial)),
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            production: Arc::new(Mutex::new(None)),
            fanout_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Attach the production engine so proposal push can apply returned votes.
    pub fn attach_production(&self, production: ProductionHook) {
        if let Ok(mut g) = self.production.lock() {
            *g = Some(production);
        }
    }

    fn production_hook(&self) -> Option<ProductionHook> {
        self.production.lock().ok().and_then(|g| g.clone())
    }

    fn send_on_session(
        &self,
        peer: &str,
        send: impl FnOnce(&mut TcpStream) -> Result<(), mfn_net::FrameWriteError>,
    ) -> bool {
        let guard = match self.sessions.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let sock = match guard.get(peer) {
            Some(s) => Arc::clone(s),
            None => return false,
        };
        drop(guard);
        let mut sock = match sock.try_lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        send(&mut sock).is_ok()
    }

    /// Maximum outbound reconnect dials spawned on boot.
    #[must_use]
    pub fn max_outbound_peers(&self) -> u32 {
        self.max_outbound_peers
    }

    /// Snapshot dialable peer addresses.
    #[must_use]
    pub fn snapshot_peers(&self) -> Vec<String> {
        self.peers
            .lock()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Remember a peer after a successful handshake (inbound accept or outbound dial).
    pub fn register(&self, peer_addr: impl Into<String>) {
        let addr = peer_addr.into();
        let changed = match self.peers.lock() {
            Ok(mut g) => g.insert(addr),
            Err(_) => return,
        };
        if changed {
            self.persist();
        }
    }

    /// Write the current peer set to `peers.json` (e.g. on shutdown).
    pub fn persist(&self) {
        let peers = match self.peers.lock() {
            Ok(g) => g.clone(),
            Err(_) => return,
        };
        match save_peers(&self.data_root, &peers, self.max_outbound_peers) {
            Ok(()) => {
                println!("mfnd_peers_save_ok count={}", peers.len());
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
            Err(e) => eprintln!("mfnd_peers_save_abort {e}"),
        }
    }

    fn local_tip(&self) -> ChainTipV1 {
        let g = self.tip_cell.lock().unwrap_or_else(|e| e.into_inner());
        ChainTipV1 {
            height: g.0,
            tip_id: g.1,
        }
    }

    fn snapshot_peers_except(&self, except_peer: Option<&str>) -> Vec<String> {
        match self.peers.lock() {
            Ok(g) => g
                .iter()
                .filter(|p| except_peer.map(|ex| ex != *p).unwrap_or(true))
                .cloned()
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn snapshot_session_peers(&self) -> Vec<String> {
        match self.sessions.lock() {
            Ok(g) => g.keys().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Push `proposal_wire` to every registered peer except `except_peer` (**M2.3.23**).
    pub fn fanout_proposal(self: &Arc<Self>, proposal_wire: &[u8], except_peer: Option<&str>) {
        let peers = self.snapshot_peers_except(except_peer);
        if peers.is_empty() {
            return;
        }
        let wire = proposal_wire.to_vec();
        let genesis_id = self.genesis_id;
        let local = self.local_tip();
        let production = self.production_hook();
        let lock = Arc::clone(&self.fanout_lock);
        let peer_set = Arc::clone(self);
        thread::Builder::new()
            .name("mfnd-p2p-proposal-fanout".into())
            .spawn(move || {
                let _guard = match lock.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                for peer in peers {
                    let vote_body = peer_set
                        .push_proposal_collect_vote_on_session(&peer, &wire)
                        .or_else(|| {
                            push_proposal_v1_to_peer(&peer, &genesis_id, &local, &wire)
                                .ok()
                                .flatten()
                        });
                    if let Some(vote_body) = vote_body {
                        if let Some(h) = production.as_ref() {
                            let label = h.on_vote_v1(&vote_body);
                            println!("mfnd_p2p_proposal_vote_push peer={peer} {label}");
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    }
                }
            })
            .ok();
    }

    /// Send `ProposalV1` on a live session and read an optional `VoteV1` reply (**M2.3.30**).
    fn push_proposal_collect_vote_on_session(
        &self,
        peer: &str,
        proposal_wire: &[u8],
    ) -> Option<Vec<u8>> {
        let guard = self.sessions.lock().ok()?;
        let sock = guard.get(peer).cloned()?;
        drop(guard);
        let mut sock = sock.try_lock().ok()?;
        send_proposal_v1(&mut *sock, proposal_wire).ok()?;
        read_vote_v1_reply(&mut *sock).ok().flatten()
    }

    /// Push `vote_wire` to every registered peer except `except_peer` (**M2.3.23**).
    pub fn fanout_vote(&self, vote_wire: &[u8], except_peer: Option<&str>) {
        let peers = self.snapshot_peers_except(except_peer);
        if peers.is_empty() {
            return;
        }
        let wire = vote_wire.to_vec();
        let genesis_id = self.genesis_id;
        let local = self.local_tip();
        for peer in peers {
            if self.send_vote_on_session(&peer, &wire) {
                continue;
            }
            let wire = wire.clone();
            thread::Builder::new()
                .name("mfnd-p2p-vote-fanout".into())
                .spawn(move || {
                    if let Err(e) = push_vote_v1_to_peer(&peer, &genesis_id, &local, &wire) {
                        eprintln!("mfnd_p2p_vote_fanout_abort peer={peer} {e}");
                    }
                })
                .ok();
        }
    }

    /// Push complete `chunk-inbox/` sets for new on-chain uploads (**M7.5**).
    pub fn fanout_inbox_chunks_for_commits(
        self: &Arc<Self>,
        commits: &[([u8; 32], mfn_storage::StorageCommitment)],
        except_peer: Option<&str>,
    ) {
        if commits.is_empty() {
            return;
        }
        let session_peers = self.snapshot_session_peers();
        let dial_peers = self.snapshot_peers_except(except_peer);
        if session_peers.is_empty() && dial_peers.is_empty() {
            return;
        }
        let peer_set = Arc::clone(self);
        let commits = commits.to_vec();
        let except = except_peer.map(str::to_string);
        let lock = Arc::clone(&self.fanout_lock);
        thread::Builder::new()
            .name("mfnd-p2p-chunk-fanout".into())
            .spawn(move || {
                let _guard = match lock.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                let genesis_id = peer_set.genesis_id;
                let local = peer_set.local_tip();
                let data_root = peer_set.data_root.clone();
                for (commit_hash, commit) in commits {
                    let Some(chunks) = crate::p2p_chunk_fanout::load_complete_inbox_chunks(
                        &data_root,
                        &commit_hash,
                        &commit,
                    ) else {
                        continue;
                    };
                    let commit_hex = hex::encode(commit_hash);
                    let n = chunks.len();
                    let mut sent = BTreeSet::new();
                    for peer in session_peers.iter() {
                        if except.as_deref().is_some_and(|ex| ex == peer) {
                            continue;
                        }
                        if peer_set.push_chunks_on_session(peer, &commit_hash, &chunks) {
                            sent.insert(peer.clone());
                            println!(
                                "mfnd_p2p_chunk_fanout_ok peer={peer} commit={commit_hex} chunks={n} session=1"
                            );
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    }
                    for peer in &dial_peers {
                        if except.as_deref().is_some_and(|ex| ex == peer) || sent.contains(peer) {
                            continue;
                        }
                        let chunks = chunks.clone();
                        if peer_set.push_chunks_on_session(peer, &commit_hash, &chunks) {
                            sent.insert(peer.clone());
                            println!(
                                "mfnd_p2p_chunk_fanout_ok peer={peer} commit={commit_hex} chunks={n} session=1"
                            );
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                            continue;
                        }
                        if let Err(e) = push_chunks_gossip_to_peer(
                            peer,
                            &genesis_id,
                            &local,
                            &commit_hash,
                            &chunks,
                        ) {
                            eprintln!(
                                "mfnd_p2p_chunk_fanout_abort peer={peer} commit={commit_hex} chunks={n} {e}"
                            );
                        } else {
                            println!(
                                "mfnd_p2p_chunk_fanout_ok peer={peer} commit={commit_hex} chunks={n}"
                            );
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    }
                }
            })
            .ok();
    }

    fn push_chunks_on_session(
        &self,
        peer: &str,
        commit_hash: &[u8; 32],
        chunks: &[(u32, Vec<u8>)],
    ) -> bool {
        self.send_on_session(peer, |sock| {
            for (index, bytes) in chunks {
                send_chunk_v1(sock, commit_hash, *index, bytes)?;
            }
            send_gossip_end_v1(sock)?;
            Ok(())
        })
    }

    /// Push `block_wire` to every registered peer except `except_peer` (**M2.3.23**).
    pub fn fanout_block(self: &Arc<Self>, block_wire: &[u8], except_peer: Option<&str>) {
        let session_peers = self.snapshot_session_peers();
        let dial_peers = self.snapshot_peers_except(except_peer);
        if session_peers.is_empty() && dial_peers.is_empty() {
            return;
        }
        let wire = block_wire.to_vec();
        let genesis_id = self.genesis_id;
        let local = self.local_tip();
        let except = except_peer.map(str::to_string);
        let lock = Arc::clone(&self.fanout_lock);
        let peer_set = Arc::clone(self);
        thread::Builder::new()
            .name("mfnd-p2p-block-fanout".into())
            .spawn(move || {
                let _guard = match lock.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                let mut sent = BTreeSet::new();
                for peer in session_peers {
                    if except.as_deref().is_some_and(|ex| ex == peer) {
                        continue;
                    }
                    if peer_set.push_block_on_session(&peer, &wire) {
                        sent.insert(peer);
                    }
                }
                for peer in dial_peers {
                    if except.as_deref().is_some_and(|ex| ex == peer) || sent.contains(&peer) {
                        continue;
                    }
                    if peer_set.push_block_on_session(&peer, &wire) {
                        sent.insert(peer);
                        continue;
                    }
                    if let Err(e) = push_block_gossip_to_peer(&peer, &genesis_id, &local, &wire) {
                        eprintln!("mfnd_p2p_block_fanout_abort peer={peer} {e}");
                    }
                }
            })
            .ok();
    }

    fn push_block_on_session(&self, peer: &str, block_wire: &[u8]) -> bool {
        self.send_on_session(peer, |sock| send_block_v1(sock, block_wire))
    }

    /// Push `tx_wire` to every registered peer except `except_peer` (if any).
    fn broadcast_fresh_tx(&self, tx_wire: &[u8], except_peer: Option<&str>) {
        let peers = self.snapshot_peers_except(except_peer);
        if peers.is_empty() {
            return;
        }
        let tx_id = match decode_transaction(tx_wire) {
            Ok(t) => tx_id(&t),
            Err(_) => return,
        };
        let mut tx_id_hex = String::with_capacity(64);
        for b in tx_id {
            use std::fmt::Write as _;
            let _ = write!(tx_id_hex, "{b:02x}");
        }
        let wire = Arc::new(tx_wire.to_vec());
        let genesis_id = self.genesis_id;
        let local = self.local_tip();
        for peer in peers {
            let wire = Arc::clone(&wire);
            let tx_id_hex = tx_id_hex.clone();
            thread::Builder::new()
                .name("mfnd-p2p-tx-fanout".into())
                .spawn(
                    move || match push_tx_gossip_to_peer(&peer, &genesis_id, &local, &wire) {
                        Ok(()) => {
                            println!("mfnd_p2p_tx_fanout_ok peer={peer} tx_id={tx_id_hex}");
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                        Err(e) => {
                            eprintln!("mfnd_p2p_tx_fanout_abort peer={peer} tx_id={tx_id_hex} {e}");
                        }
                    },
                )
                .ok();
        }
    }
}

impl FanoutPeerSet for P2pPeerSet {
    fn register_peer(&self, peer_addr: &str) {
        self.register(peer_addr);
    }

    fn register_session(&self, peer_addr: &str, stream: TcpStream) {
        let _ = stream.set_nodelay(true);
        let Ok(mut guard) = self.sessions.lock() else {
            return;
        };
        guard.insert(peer_addr.to_string(), Arc::new(Mutex::new(stream)));
        println!("mfnd_p2p_session_register peer={peer_addr}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    fn send_proposal_on_session(&self, peer_addr: &str, proposal_wire: &[u8]) -> bool {
        let wire = proposal_wire.to_vec();
        self.send_on_session(peer_addr, |sock| send_proposal_v1(sock, &wire))
    }

    fn send_vote_on_session(&self, peer_addr: &str, vote_wire: &[u8]) -> bool {
        let wire = vote_wire.to_vec();
        self.send_on_session(peer_addr, |sock| send_vote_v1(sock, &wire))
    }

    fn fanout_fresh_tx(&self, tx_wire: &[u8], except_peer: Option<&str>) {
        self.broadcast_fresh_tx(tx_wire, except_peer);
    }

    fn boot_peer_addrs(&self) -> Vec<String> {
        self.snapshot_peers()
    }
}

/// Boot-time reconnect of peers from `peers.json` (**M2.3.22**).
pub struct ReconnectPeersBoot<'a> {
    /// Peer registry (loads `peers.json`).
    pub peer_set: &'a P2pPeerSet,
    /// Chain genesis id for hello handshake.
    pub genesis_id: [u8; 32],
    /// Shared tip snapshot for dial handshakes.
    pub tip_cell: TipSnapshot,
    /// Monotonic handshake id counter.
    pub hid_counter: HidCounter,
    /// Optional gossip admission hook.
    pub gossip: Option<GossipHook>,
    /// Block-log query for catch-up pulls (**M2.4.2**).
    pub block_sync: Option<BlockSyncHook>,
    /// Optional block catch-up applier.
    pub block_applier: Option<BlockSyncApplierHook>,
    /// Fan-out registry passed to outbound dials.
    pub fanout_hook: Option<Arc<dyn FanoutPeerSet>>,
    /// Local listen address to advertise after dial.
    pub local_p2p_listen: Option<std::net::SocketAddr>,
    /// Skip these peers (already dialed via `--p2p-dial` / manifest seeds — **M2.4.4**).
    pub skip_addrs: &'a [String],
}

/// Periodic height pull for `--committee-vote` followers (**M2.3.25**).
pub fn spawn_committee_catch_up_loop(
    peer_set: Arc<P2pPeerSet>,
    genesis_id: [u8; 32],
    tip_cell: TipSnapshot,
    hid_counter: HidCounter,
    block_sync: BlockSyncHook,
    block_applier: BlockSyncApplierHook,
    interval_ms: u64,
) -> Result<(), String> {
    thread::Builder::new()
        .name("mfnd-committee-catchup".into())
        .spawn(move || loop {
            for addr in peer_set.snapshot_peers() {
                let _ = spawn_catch_up_dial(
                    addr,
                    genesis_id,
                    Arc::clone(&tip_cell),
                    Arc::clone(&hid_counter),
                    Some(Arc::clone(&block_sync)),
                    Arc::clone(&block_applier),
                );
            }
            thread::sleep(Duration::from_millis(interval_ms));
        })
        .map_err(|e| format!("mfnd serve: spawn committee catch-up loop: {e}"))?;
    Ok(())
}

/// Dial up to [`P2pPeerSet::max_outbound_peers`] saved peers on boot (**M2.3.22**).
pub fn spawn_reconnect_saved_peers(cfg: ReconnectPeersBoot<'_>) -> Result<(), String> {
    let ReconnectPeersBoot {
        peer_set,
        genesis_id,
        tip_cell,
        hid_counter,
        gossip,
        block_sync,
        block_applier,
        fanout_hook,
        local_p2p_listen,
        skip_addrs,
    } = cfg;
    let mut spawned = 0u32;
    for addr in peer_set.snapshot_peers() {
        if skip_addrs.iter().any(|s| s == &addr) {
            continue;
        }
        if spawned >= peer_set.max_outbound_peers() {
            break;
        }
        println!("mfnd_p2p_reconnect_start peer={addr}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        spawn_outbound_dial(OutboundP2pDial {
            addr,
            genesis_id,
            tip_cell: Arc::clone(&tip_cell),
            hid_counter: Arc::clone(&hid_counter),
            hooks: P2pSessionHooks {
                gossip: gossip.clone(),
                block_sync: block_sync.clone(),
                block_applier: block_applier.clone(),
                light_follow: None,
                fanout_peers: fanout_hook.clone(),
                production: None,
            },
            local_p2p_listen,
        })?;
        spawned = spawned.saturating_add(1);
    }
    if spawned > 0 {
        println!("mfnd_p2p_reconnect_spawned count={spawned}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
    Ok(())
}
