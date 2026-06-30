//! Mempool tx fan-out and persistent peer registry (**M2.3.20**, **M2.3.22**).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use mfn_consensus::{decode_transaction, tx_id, StorageCommitment};
use mfn_net::{
    push_block_gossip_to_peer, push_chunks_gossip_to_peer, push_proposal_v1_to_peer,
    push_tx_gossip_to_peer, push_vote_v1_to_peer, read_vote_v1_reply, send_block_v1, send_chunk_v1,
    send_gossip_end_v1, send_proposal_v1, send_vote_v1, spawn_catch_up_dial, spawn_outbound_dial,
    BlockSyncApplierHook, BlockSyncHook, ChainTipV1, FanoutPeerSet, GossipHook, HidCounter,
    OutboundP2pDial, P2pSessionHooks, ProductionHook, TipSnapshot,
};
use mfn_runtime::Chain;
use mfn_store::{load_peers_with_report, save_peers, DEFAULT_MAX_OUTBOUND_PEERS};

const PEER_FAILURES_BEFORE_QUARANTINE: u32 = 3;
const PEER_QUARANTINE_DURATION: Duration = Duration::from_secs(5 * 60);

pub(crate) fn is_self_peer_addr(peer_addr: &str, local_p2p_listen: Option<SocketAddr>) -> bool {
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

fn should_drop_persistent_peer_on_failure(reason: &str) -> bool {
    reason == "genesis_mismatch" || reason.starts_with("genesis_mismatch ")
}

fn is_boot_dial_peer(peer_addr: &str, boot_dials: &[String]) -> bool {
    boot_dials.iter().any(|addr| addr == peer_addr)
}

fn reconnect_cap_reached(spawned: u32, cap: u32) -> bool {
    spawned >= cap
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CatchUpPeerAction {
    SkipSelf,
    CapReached,
    Dial,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CatchUpPeerEvent {
    SkipSelf { peer: String },
    CapReached { count: u32, cap: u32 },
    Dial { peer: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReconnectPeerEvent {
    SkipSelf { peer: String },
    SkipBootDial { peer: String },
    CapReached { count: u32, cap: u32 },
    Dial { peer: String },
}

fn catch_up_peer_action(
    peer_addr: &str,
    local_p2p_listen: Option<SocketAddr>,
    attempted: u32,
    cap: u32,
) -> CatchUpPeerAction {
    if is_self_peer_addr(peer_addr, local_p2p_listen) {
        return CatchUpPeerAction::SkipSelf;
    }
    if reconnect_cap_reached(attempted, cap) {
        return CatchUpPeerAction::CapReached;
    }
    CatchUpPeerAction::Dial
}

fn catch_up_peer_events(
    peers: Vec<String>,
    local_p2p_listen: Option<SocketAddr>,
    cap: u32,
) -> Vec<CatchUpPeerEvent> {
    let mut events = Vec::new();
    let mut attempted = 0u32;
    for addr in peers {
        match catch_up_peer_action(&addr, local_p2p_listen, attempted, cap) {
            CatchUpPeerAction::SkipSelf => {
                events.push(CatchUpPeerEvent::SkipSelf { peer: addr });
            }
            CatchUpPeerAction::CapReached => {
                events.push(CatchUpPeerEvent::CapReached {
                    count: attempted,
                    cap,
                });
                break;
            }
            CatchUpPeerAction::Dial => {
                events.push(CatchUpPeerEvent::Dial { peer: addr });
                attempted = attempted.saturating_add(1);
            }
        }
    }
    events
}

fn reconnect_peer_events(
    peers: Vec<String>,
    local_p2p_listen: Option<SocketAddr>,
    skip_addrs: &[String],
    cap: u32,
) -> Vec<ReconnectPeerEvent> {
    let mut events = Vec::new();
    let mut spawned = 0u32;
    for addr in peers {
        if is_self_peer_addr(&addr, local_p2p_listen) {
            events.push(ReconnectPeerEvent::SkipSelf { peer: addr });
            continue;
        }
        if is_boot_dial_peer(&addr, skip_addrs) {
            events.push(ReconnectPeerEvent::SkipBootDial { peer: addr });
            continue;
        }
        if reconnect_cap_reached(spawned, cap) {
            events.push(ReconnectPeerEvent::CapReached {
                count: spawned,
                cap,
            });
            break;
        }
        events.push(ReconnectPeerEvent::Dial { peer: addr });
        spawned = spawned.saturating_add(1);
    }
    events
}

#[derive(Clone, Debug)]
struct PeerPenalty {
    failures: u32,
    quarantined_until: Option<Instant>,
}

#[derive(Debug)]
struct PeerQuarantine {
    failures_before_quarantine: u32,
    quarantine_duration: Duration,
    penalties: BTreeMap<String, PeerPenalty>,
}

impl PeerQuarantine {
    fn new(failures_before_quarantine: u32, quarantine_duration: Duration) -> Self {
        Self {
            failures_before_quarantine: failures_before_quarantine.max(1),
            quarantine_duration,
            penalties: BTreeMap::new(),
        }
    }

    fn note_success(&mut self, peer: &str) {
        self.penalties.remove(peer);
    }

    fn note_failure(&mut self, peer: &str) -> Option<Duration> {
        let now = Instant::now();
        if let Some(remaining) = self.quarantine_remaining_at(peer, now) {
            return Some(remaining);
        }
        let penalty = self
            .penalties
            .entry(peer.to_string())
            .or_insert(PeerPenalty {
                failures: 0,
                quarantined_until: None,
            });
        penalty.failures = penalty.failures.saturating_add(1);
        if penalty.failures >= self.failures_before_quarantine {
            let until = now + self.quarantine_duration;
            penalty.quarantined_until = Some(until);
            return Some(self.quarantine_duration);
        }
        None
    }

    fn is_quarantined(&mut self, peer: &str) -> bool {
        self.quarantine_remaining_at(peer, Instant::now()).is_some()
    }

    fn quarantine_remaining_at(&mut self, peer: &str, now: Instant) -> Option<Duration> {
        let until = self.penalties.get(peer).and_then(|p| p.quarantined_until)?;
        if until > now {
            return Some(until.duration_since(now));
        }
        self.penalties.remove(peer);
        None
    }
}

/// Peers that completed a successful P2P handshake (address strings suitable for `TcpStream::connect`).
#[derive(Clone)]
pub struct P2pPeerSet {
    genesis_id: [u8; 32],
    tip_cell: TipSnapshot,
    data_root: PathBuf,
    max_outbound_peers: u32,
    peers: Arc<Mutex<BTreeSet<String>>>,
    sessions: Arc<Mutex<BTreeMap<String, Arc<Mutex<TcpStream>>>>>,
    quarantine: Arc<Mutex<PeerQuarantine>>,
    production: Arc<Mutex<Option<ProductionHook>>>,
    fanout_lock: Arc<Mutex<()>>,
    chain: Arc<Mutex<Chain>>,
    self_arc: Weak<Self>,
}

impl P2pPeerSet {
    /// Build a fan-out registry; loads `peers.json` when present (**M2.3.22**).
    pub fn new(
        genesis_id: [u8; 32],
        tip_cell: TipSnapshot,
        data_root: impl Into<PathBuf>,
        chain: Arc<Mutex<Chain>>,
    ) -> Arc<Self> {
        let data_root = data_root.into();
        let peer_report = load_peers_with_report(&data_root).unwrap_or_else(|e| {
            eprintln!("mfnd_peers_load_abort {e}");
            mfn_store::PeersLoadReport {
                peers: BTreeSet::new(),
                max_outbound_peers: DEFAULT_MAX_OUTBOUND_PEERS,
                raw_peer_count: 0,
                filtered_peer_count: 0,
            }
        });
        if peer_report.filtered_peer_count > 0 {
            eprintln!(
                "mfnd_peers_load_filtered raw={} kept={} filtered={}",
                peer_report.raw_peer_count,
                peer_report.peers.len(),
                peer_report.filtered_peer_count
            );
        }
        let initial = peer_report.peers;
        let max_outbound_peers = peer_report.max_outbound_peers;
        let count = initial.len();
        if count > 0 {
            println!("mfnd_peers_load_ok count={count} max_outbound_peers={max_outbound_peers}");
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
        Arc::new_cyclic(|weak| Self {
            genesis_id,
            tip_cell,
            data_root,
            max_outbound_peers,
            peers: Arc::new(Mutex::new(initial)),
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            quarantine: Arc::new(Mutex::new(PeerQuarantine::new(
                PEER_FAILURES_BEFORE_QUARANTINE,
                PEER_QUARANTINE_DURATION,
            ))),
            production: Arc::new(Mutex::new(None)),
            fanout_lock: Arc::new(Mutex::new(())),
            chain,
            self_arc: weak.clone(),
        })
    }

    /// Push complete operator inboxes for all anchored storage to every live session (**M7.5**).
    pub fn fanout_on_chain_storage_inboxes_to_all_sessions(self: &Arc<Self>) {
        for peer in self.snapshot_session_peers() {
            self.fanout_on_chain_storage_inboxes_to_peer(&peer);
        }
    }

    /// Push every on-chain storage commitment with a complete local `chunk-inbox/` to one peer (**M7.5**).
    pub fn fanout_on_chain_storage_inboxes_to_peer(self: &Arc<Self>, peer: &str) {
        let commits: Vec<([u8; 32], StorageCommitment)> = match self.chain.lock() {
            Ok(guard) => guard
                .state()
                .storage
                .iter()
                .map(|(hash, entry)| (*hash, entry.commit.clone()))
                .collect(),
            Err(_) => return,
        };
        if commits.is_empty() {
            return;
        }
        self.fanout_inbox_chunks_for_commits_to_peer(peer, &commits);
    }

    fn fanout_inbox_chunks_for_commits_to_peer(
        self: &Arc<Self>,
        peer: &str,
        commits: &[([u8; 32], StorageCommitment)],
    ) {
        if commits.is_empty() {
            return;
        }
        let peer_set = Arc::clone(self);
        let peer = peer.to_string();
        let commits = commits.to_vec();
        let lock = Arc::clone(&self.fanout_lock);
        thread::Builder::new()
            .name("mfnd-p2p-chunk-catchup".into())
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
                    if peer_set.push_chunks_on_session(&peer, &commit_hash, &chunks) {
                        eprintln!(
                            "mfnd_p2p_chunk_catchup_ok peer={peer} commit={commit_hex} chunks={n} session=1"
                        );
                        continue;
                    }
                    let mut sent_on_alias = false;
                    for alias in peer_set.snapshot_session_peers() {
                        if alias == peer {
                            continue;
                        }
                        if peer_set.push_chunks_on_session(&alias, &commit_hash, &chunks) {
                            eprintln!(
                                "mfnd_p2p_chunk_catchup_ok peer={peer} alias={alias} commit={commit_hex} chunks={n} session=1"
                            );
                            sent_on_alias = true;
                            break;
                        }
                    }
                    if sent_on_alias {
                        continue;
                    }
                    if let Err(e) = push_chunks_gossip_to_peer(
                        &peer,
                        &genesis_id,
                        &local,
                        &commit_hash,
                        &chunks,
                    ) {
                        peer_set.note_peer_failure(&peer, &e.to_string());
                        eprintln!(
                            "mfnd_p2p_chunk_catchup_abort peer={peer} commit={commit_hex} chunks={n} {e}"
                        );
                    } else {
                        eprintln!(
                            "mfnd_p2p_chunk_catchup_ok peer={peer} commit={commit_hex} chunks={n}"
                        );
                    }
                }
            })
            .ok();
    }

    fn write_inbox_chunks_for_commits_to_stream(
        &self,
        peer: &str,
        stream: &mut TcpStream,
        commits: &[([u8; 32], StorageCommitment)],
    ) {
        if commits.is_empty() {
            return;
        }
        for (commit_hash, commit) in commits {
            let Some(chunks) = crate::p2p_chunk_fanout::load_complete_inbox_chunks(
                &self.data_root,
                commit_hash,
                commit,
            ) else {
                continue;
            };
            let commit_hex = hex::encode(commit_hash);
            let n = chunks.len();
            let mut ok = true;
            for (index, bytes) in &chunks {
                if let Err(e) = send_chunk_v1(stream, commit_hash, *index, bytes) {
                    eprintln!(
                        "mfnd_p2p_chunk_catchup_stream_abort peer={peer} commit={commit_hex} chunks={n} {e}"
                    );
                    ok = false;
                    break;
                }
            }
            if ok {
                if let Err(e) = send_gossip_end_v1(stream) {
                    eprintln!(
                        "mfnd_p2p_chunk_catchup_stream_abort peer={peer} commit={commit_hex} chunks={n} {e}"
                    );
                } else {
                    eprintln!(
                        "mfnd_p2p_chunk_catchup_ok peer={peer} commit={commit_hex} chunks={n} stream=1"
                    );
                }
            }
        }
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

    fn snapshot_available_peers(&self) -> Vec<String> {
        let peers = self.snapshot_peers();
        let Ok(mut quarantine) = self.quarantine.lock() else {
            return peers;
        };
        peers
            .into_iter()
            .filter(|peer| !quarantine.is_quarantined(peer))
            .collect()
    }

    /// Remember a peer after a successful handshake (inbound accept or outbound dial).
    pub fn register(&self, peer_addr: impl Into<String>) {
        let addr = peer_addr.into();
        self.note_peer_success(&addr);
        let changed = match self.peers.lock() {
            Ok(mut g) => g.insert(addr),
            Err(_) => return,
        };
        if changed {
            self.persist();
        }
    }

    /// Track an inbound dialer for this process without writing it to `peers.json`.
    ///
    /// Inbound `peer_addr` values are usually ephemeral TCP source ports. They can be
    /// useful while a live socket is registered for fan-out, but they must not become
    /// durable boot/reconnect peers.
    pub fn register_ephemeral(&self, peer_addr: impl Into<String>) {
        let addr = peer_addr.into();
        self.note_peer_success(&addr);
        if let Ok(mut g) = self.peers.lock() {
            g.insert(addr);
        }
    }

    /// Clear transient score state after any successful peer exchange.
    pub fn note_peer_success(&self, peer_addr: &str) {
        if let Ok(mut q) = self.quarantine.lock() {
            q.note_success(peer_addr);
        }
    }

    /// Penalize a failed peer interaction; repeated failures temporarily quarantine the address.
    pub fn note_peer_failure(&self, peer_addr: &str, reason: &str) {
        if should_drop_persistent_peer_on_failure(reason) {
            self.drop_persistent_peer(peer_addr, reason);
        }
        let remaining = match self.quarantine.lock() {
            Ok(mut q) => q.note_failure(peer_addr),
            Err(_) => return,
        };
        if let Some(duration) = remaining {
            eprintln!(
                "mfnd_p2p_peer_quarantine peer={peer_addr} seconds={} reason={reason}",
                duration.as_secs()
            );
        }
    }

    fn drop_persistent_peer(&self, peer_addr: &str, reason: &str) {
        let peers = match self.peers.lock() {
            Ok(mut peers) => {
                if !peers.remove(peer_addr) {
                    return;
                }
                peers.clone()
            }
            Err(_) => return,
        };
        match save_peers(&self.data_root, &peers, self.max_outbound_peers) {
            Ok(()) => {
                eprintln!("mfnd_p2p_peer_drop peer={peer_addr} reason={reason}");
            }
            Err(e) => {
                eprintln!("mfnd_peers_save_abort {e}");
            }
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
        self.snapshot_available_peers()
            .into_iter()
            .filter(|p| except_peer.map(|ex| ex != *p).unwrap_or(true))
            .collect()
    }

    /// Snapshot peers with a currently registered live P2P session.
    #[must_use]
    pub fn snapshot_session_peers(&self) -> Vec<String> {
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
                    let vote_body = if let Some(vote) =
                        peer_set.push_proposal_collect_vote_on_session(&peer, &wire)
                    {
                        Some(vote)
                    } else {
                        match push_proposal_v1_to_peer(&peer, &genesis_id, &local, &wire) {
                            Ok(vote) => vote,
                            Err(e) => {
                                peer_set.note_peer_failure(&peer, &e.to_string());
                                None
                            }
                        }
                    };
                    if let Some(vote_body) = vote_body {
                        peer_set.note_peer_success(&peer);
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
            let peer_set = self.self_arc.clone();
            thread::Builder::new()
                .name("mfnd-p2p-vote-fanout".into())
                .spawn(move || {
                    if let Err(e) = push_vote_v1_to_peer(&peer, &genesis_id, &local, &wire) {
                        if let Some(peer_set) = peer_set.upgrade() {
                            peer_set.note_peer_failure(&peer, &e.to_string());
                        }
                        eprintln!("mfnd_p2p_vote_fanout_abort peer={peer} {e}");
                    } else if let Some(peer_set) = peer_set.upgrade() {
                        peer_set.note_peer_success(&peer);
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
                            eprintln!(
                                "mfnd_p2p_chunk_fanout_ok peer={peer} commit={commit_hex} chunks={n} session=1"
                            );
                        }
                    }
                    for peer in &dial_peers {
                        if except.as_deref().is_some_and(|ex| ex == peer) || sent.contains(peer) {
                            continue;
                        }
                        let chunks = chunks.clone();
                        if peer_set.push_chunks_on_session(peer, &commit_hash, &chunks) {
                            sent.insert(peer.clone());
                            eprintln!(
                                "mfnd_p2p_chunk_fanout_ok peer={peer} commit={commit_hex} chunks={n} session=1"
                            );
                            continue;
                        }
                        if let Err(e) = push_chunks_gossip_to_peer(
                            peer,
                            &genesis_id,
                            &local,
                            &commit_hash,
                            &chunks,
                        ) {
                            peer_set.note_peer_failure(peer, &e.to_string());
                            eprintln!(
                                "mfnd_p2p_chunk_fanout_abort peer={peer} commit={commit_hex} chunks={n} {e}"
                            );
                        } else {
                            peer_set.note_peer_success(peer);
                            eprintln!(
                                "mfnd_p2p_chunk_fanout_ok peer={peer} commit={commit_hex} chunks={n}"
                            );
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
                        peer_set.note_peer_failure(&peer, &e.to_string());
                        eprintln!("mfnd_p2p_block_fanout_abort peer={peer} {e}");
                    } else {
                        peer_set.note_peer_success(&peer);
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
            let peer_set = self.self_arc.clone();
            thread::Builder::new()
                .name("mfnd-p2p-tx-fanout".into())
                .spawn(
                    move || match push_tx_gossip_to_peer(&peer, &genesis_id, &local, &wire) {
                        Ok(()) => {
                            // A successful fresh-tx dial proves the peer is reachable again.
                            if let Some(peer_set) = peer_set.upgrade() {
                                peer_set.note_peer_success(&peer);
                            }
                            println!("mfnd_p2p_tx_fanout_ok peer={peer} tx_id={tx_id_hex}");
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                        Err(e) => {
                            if let Some(peer_set) = peer_set.upgrade() {
                                peer_set.note_peer_failure(&peer, &e.to_string());
                            }
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

    fn note_peer_success(&self, peer_addr: &str) {
        P2pPeerSet::note_peer_success(self, peer_addr);
    }

    fn note_peer_failure(&self, peer_addr: &str, reason: &str) {
        P2pPeerSet::note_peer_failure(self, peer_addr, reason);
    }

    fn register_ephemeral_peer(&self, peer_addr: &str) {
        self.register_ephemeral(peer_addr);
    }

    fn register_session(&self, peer_addr: &str, stream: TcpStream) {
        let _ = stream.set_nodelay(true);
        let Ok(mut guard) = self.sessions.lock() else {
            return;
        };
        guard.insert(peer_addr.to_string(), Arc::new(Mutex::new(stream)));
        eprintln!("mfnd_p2p_session_register peer={peer_addr}");
    }

    fn on_session_registered(&self, peer_addr: &str) {
        self.fanout_onchain_storage_chunks_to_peer(peer_addr);
    }

    fn fanout_onchain_storage_chunks_to_peer(&self, peer_addr: &str) {
        if let Some(ps) = self.self_arc.upgrade() {
            ps.fanout_on_chain_storage_inboxes_to_peer(peer_addr);
        }
    }

    fn write_onchain_storage_chunks_to_peer(&self, peer_addr: &str, stream: &mut TcpStream) {
        let commits: Vec<([u8; 32], StorageCommitment)> = match self.chain.lock() {
            Ok(guard) => guard
                .state()
                .storage
                .iter()
                .map(|(hash, entry)| (*hash, entry.commit.clone()))
                .collect(),
            Err(_) => return,
        };
        self.write_inbox_chunks_for_commits_to_stream(peer_addr, stream, &commits);
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
        self.snapshot_available_peers()
    }

    fn max_outbound_peers(&self) -> u32 {
        P2pPeerSet::max_outbound_peers(self)
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
pub struct CommitteeCatchUpLoop {
    /// Peer registry used for periodic catch-up dials.
    pub peer_set: Arc<P2pPeerSet>,
    /// Chain genesis id for hello handshakes.
    pub genesis_id: [u8; 32],
    /// Shared tip snapshot for dial handshakes.
    pub tip_cell: TipSnapshot,
    /// Monotonic handshake id counter.
    pub hid_counter: HidCounter,
    /// Block-log query for catch-up pulls.
    pub block_sync: BlockSyncHook,
    /// Block catch-up applier.
    pub block_applier: BlockSyncApplierHook,
    /// Local listen address to avoid self-dials.
    pub local_p2p_listen: Option<std::net::SocketAddr>,
    /// Sleep interval between catch-up sweeps.
    pub interval_ms: u64,
}

/// Periodic height pull for `--committee-vote` followers (**M2.3.25**).
pub fn spawn_committee_catch_up_loop(cfg: CommitteeCatchUpLoop) -> Result<(), String> {
    let CommitteeCatchUpLoop {
        peer_set,
        genesis_id,
        tip_cell,
        hid_counter,
        block_sync,
        block_applier,
        local_p2p_listen,
        interval_ms,
    } = cfg;
    thread::Builder::new()
        .name("mfnd-committee-catchup".into())
        .spawn(move || loop {
            let events = catch_up_peer_events(
                peer_set.snapshot_available_peers(),
                local_p2p_listen,
                peer_set.max_outbound_peers(),
            );
            for event in events {
                match event {
                    CatchUpPeerEvent::SkipSelf { peer } => {
                        println!("mfnd_p2p_self_dial_skip peer={peer}");
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                    }
                    CatchUpPeerEvent::CapReached { count, cap } => {
                        println!("mfnd_p2p_catchup_cap_reached count={count} cap={cap}");
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                        break;
                    }
                    CatchUpPeerEvent::Dial { peer } => {
                        let _ = spawn_catch_up_dial(
                            peer,
                            genesis_id,
                            Arc::clone(&tip_cell),
                            Arc::clone(&hid_counter),
                            Some(Arc::clone(&block_sync)),
                            Arc::clone(&block_applier),
                            Some(Arc::clone(&peer_set) as Arc<dyn FanoutPeerSet>),
                        );
                    }
                }
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
    let events = reconnect_peer_events(
        peer_set.snapshot_available_peers(),
        local_p2p_listen,
        skip_addrs,
        peer_set.max_outbound_peers(),
    );
    for event in events {
        match event {
            ReconnectPeerEvent::SkipSelf { peer } => {
                println!("mfnd_p2p_self_dial_skip peer={peer}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
            ReconnectPeerEvent::SkipBootDial { peer } => {
                println!("mfnd_p2p_reconnect_skip peer={peer} reason=boot_dial");
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
            ReconnectPeerEvent::CapReached { count, cap } => {
                println!("mfnd_p2p_reconnect_cap_reached count={count} cap={cap}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                break;
            }
            ReconnectPeerEvent::Dial { peer } => {
                println!("mfnd_p2p_reconnect_start peer={peer}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                spawn_outbound_dial(OutboundP2pDial {
                    addr: peer,
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
        }
    }
    if spawned > 0 {
        println!("mfnd_p2p_reconnect_spawned count={spawned}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_consensus::{
        ConsensusParams, GenesisConfig, DEFAULT_CONSENSUS_PARAMS, DEFAULT_EMISSION_PARAMS,
    };
    use mfn_runtime::ChainConfig;
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn empty_genesis_cfg() -> GenesisConfig {
        GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: ConsensusParams {
                expected_proposers_per_slot: 1.0,
                quorum_stake_bps: 6667,
                ..DEFAULT_CONSENSUS_PARAMS
            },
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        }
    }

    fn temp_dir(test: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "permawrite-p2p-fanout-{test}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn peer_quarantine_starts_after_threshold() {
        let mut q = PeerQuarantine::new(3, Duration::from_secs(60));
        assert_eq!(q.note_failure("127.0.0.1:9000"), None);
        assert_eq!(q.note_failure("127.0.0.1:9000"), None);

        let remaining = q
            .note_failure("127.0.0.1:9000")
            .expect("third failure quarantines");

        assert!(remaining <= Duration::from_secs(60));
        assert!(q.is_quarantined("127.0.0.1:9000"));
    }

    #[test]
    fn peer_quarantine_success_clears_penalty() {
        let mut q = PeerQuarantine::new(2, Duration::from_secs(60));
        let _ = q.note_failure("127.0.0.1:9000");
        assert!(q.note_failure("127.0.0.1:9000").is_some());
        assert!(q.is_quarantined("127.0.0.1:9000"));

        q.note_success("127.0.0.1:9000");

        assert!(!q.is_quarantined("127.0.0.1:9000"));
        assert_eq!(q.note_failure("127.0.0.1:9000"), None);
    }

    #[test]
    fn peer_quarantine_expiry_prunes_penalty() {
        let peer = "127.0.0.1:9000";
        let mut q = PeerQuarantine::new(2, Duration::from_secs(60));
        assert_eq!(q.note_failure(peer), None);
        assert!(q.note_failure(peer).is_some());
        let until = q
            .penalties
            .get(peer)
            .and_then(|penalty| penalty.quarantined_until)
            .expect("peer is quarantined");

        assert_eq!(
            q.quarantine_remaining_at(peer, until + Duration::from_nanos(1)),
            None
        );
        assert!(!q.penalties.contains_key(peer));
        assert_eq!(q.note_failure(peer), None);
    }

    #[test]
    fn self_peer_addr_matches_local_socket_addr() {
        let local: SocketAddr = "127.0.0.1:19001".parse().unwrap();
        assert!(is_self_peer_addr("127.0.0.1:19001", Some(local)));
        assert!(is_self_peer_addr(" 127.0.0.1:19001 ", Some(local)));
        assert!(!is_self_peer_addr("127.0.0.1:19002", Some(local)));
        assert!(!is_self_peer_addr("seed.example.org:19001", Some(local)));
        assert!(!is_self_peer_addr("127.0.0.1:19001", None));
    }

    #[test]
    fn self_peer_addr_matches_bracketed_ipv6() {
        let local: SocketAddr = "[::1]:19001".parse().unwrap();
        assert!(is_self_peer_addr("[::1]:19001", Some(local)));
        assert!(!is_self_peer_addr("[::1]:19002", Some(local)));
    }

    #[test]
    fn boot_dial_peer_matches_saved_addr_exactly() {
        let boot_dials = vec!["127.0.0.1:19001".to_string(), "127.0.0.1:19002".to_string()];
        assert!(is_boot_dial_peer("127.0.0.1:19001", &boot_dials));
        assert!(!is_boot_dial_peer("127.0.0.1:19003", &boot_dials));
        assert!(!is_boot_dial_peer(" 127.0.0.1:19001 ", &boot_dials));
    }

    #[test]
    fn reconnect_cap_reached_at_or_above_cap() {
        assert!(!reconnect_cap_reached(0, 1));
        assert!(!reconnect_cap_reached(7, 8));
        assert!(reconnect_cap_reached(8, 8));
        assert!(reconnect_cap_reached(9, 8));
    }

    #[test]
    fn reconnect_peer_events_preserve_skip_and_cap_order() {
        let local: SocketAddr = "127.0.0.1:19001".parse().unwrap();
        let peers = vec![
            "127.0.0.1:19001".to_string(),
            "127.0.0.1:19002".to_string(),
            "127.0.0.1:19003".to_string(),
            "127.0.0.1:19004".to_string(),
        ];
        let skip_addrs = vec!["127.0.0.1:19002".to_string()];

        assert_eq!(
            reconnect_peer_events(peers, Some(local), &skip_addrs, 1),
            vec![
                ReconnectPeerEvent::SkipSelf {
                    peer: "127.0.0.1:19001".to_string(),
                },
                ReconnectPeerEvent::SkipBootDial {
                    peer: "127.0.0.1:19002".to_string(),
                },
                ReconnectPeerEvent::Dial {
                    peer: "127.0.0.1:19003".to_string(),
                },
                ReconnectPeerEvent::CapReached { count: 1, cap: 1 },
            ]
        );
    }

    #[test]
    fn catch_up_peer_action_skips_self_before_cap() {
        let local: SocketAddr = "127.0.0.1:19001".parse().unwrap();

        assert_eq!(
            catch_up_peer_action("127.0.0.1:19001", Some(local), 8, 8),
            CatchUpPeerAction::SkipSelf
        );
    }

    #[test]
    fn catch_up_peer_action_respects_cap_for_non_self_peers() {
        let local: SocketAddr = "127.0.0.1:19001".parse().unwrap();

        assert_eq!(
            catch_up_peer_action("127.0.0.1:19002", Some(local), 7, 8),
            CatchUpPeerAction::Dial
        );
        assert_eq!(
            catch_up_peer_action("127.0.0.1:19002", Some(local), 8, 8),
            CatchUpPeerAction::CapReached
        );
    }

    #[test]
    fn catch_up_peer_events_preserve_self_skip_and_cap_order() {
        let local: SocketAddr = "127.0.0.1:19001".parse().unwrap();
        let peers = vec![
            "127.0.0.1:19001".to_string(),
            "127.0.0.1:19002".to_string(),
            "127.0.0.1:19003".to_string(),
        ];

        assert_eq!(
            catch_up_peer_events(peers, Some(local), 1),
            vec![
                CatchUpPeerEvent::SkipSelf {
                    peer: "127.0.0.1:19001".to_string(),
                },
                CatchUpPeerEvent::Dial {
                    peer: "127.0.0.1:19002".to_string(),
                },
                CatchUpPeerEvent::CapReached { count: 1, cap: 1 },
            ]
        );
    }

    #[test]
    fn genesis_mismatch_is_durable_peer_drop_reason() {
        assert!(should_drop_persistent_peer_on_failure(
            "genesis_mismatch expected=00 got=11"
        ));
        assert!(should_drop_persistent_peer_on_failure("genesis_mismatch"));
        assert!(!should_drop_persistent_peer_on_failure(
            "connection refused"
        ));
        assert!(!should_drop_persistent_peer_on_failure(
            "decode_error genesis_mismatch"
        ));
    }

    #[test]
    fn genesis_mismatch_removes_only_failed_peer_from_disk() {
        let dir = temp_dir("drop_foreign_peer");
        let foreign = "127.0.0.1:19001".to_string();
        let healthy = "127.0.0.1:19002".to_string();
        let mut peers = BTreeSet::new();
        peers.insert(foreign.clone());
        peers.insert(healthy.clone());
        save_peers(&dir, &peers, 4).expect("save peers");

        let chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis chain");
        let genesis_id = *chain.genesis_id();
        let peer_set = P2pPeerSet::new(
            genesis_id,
            Arc::new(Mutex::new((0, genesis_id))),
            dir.clone(),
            Arc::new(Mutex::new(chain)),
        );

        peer_set.note_peer_failure(&foreign, "genesis_mismatch expected=00 got=11");

        let (loaded, max_outbound) = mfn_store::load_peers(&dir).expect("load peers");
        assert!(!loaded.contains(&foreign));
        assert!(loaded.contains(&healthy));
        assert_eq!(max_outbound, 4);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn snapshot_available_peers_filters_quarantined_peer_until_success() {
        let dir = temp_dir("quarantine_snapshot");
        let flaky = "127.0.0.1:19001".to_string();
        let healthy = "127.0.0.1:19002".to_string();
        let mut peers = BTreeSet::new();
        peers.insert(flaky.clone());
        peers.insert(healthy.clone());
        save_peers(&dir, &peers, 4).expect("save peers");

        let chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis chain");
        let genesis_id = *chain.genesis_id();
        let peer_set = P2pPeerSet::new(
            genesis_id,
            Arc::new(Mutex::new((0, genesis_id))),
            dir.clone(),
            Arc::new(Mutex::new(chain)),
        );

        assert_eq!(
            peer_set.snapshot_available_peers(),
            vec![flaky.clone(), healthy.clone()]
        );

        peer_set.note_peer_failure(&flaky, "connection refused");
        peer_set.note_peer_failure(&flaky, "connection refused");
        peer_set.note_peer_failure(&flaky, "connection refused");

        assert_eq!(peer_set.snapshot_available_peers(), vec![healthy.clone()]);

        peer_set.note_peer_success(&flaky);

        assert_eq!(peer_set.snapshot_available_peers(), vec![flaky, healthy]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn boot_dial_connect_failures_quarantine_without_durable_drop() {
        let dir = temp_dir("boot_dial_connect_quarantine");
        let stale_seed = "203.0.113.10:19001".to_string();
        let healthy = "203.0.113.11:19001".to_string();
        let mut peers = BTreeSet::new();
        peers.insert(stale_seed.clone());
        peers.insert(healthy.clone());
        save_peers(&dir, &peers, 4).expect("save peers");

        let chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis chain");
        let genesis_id = *chain.genesis_id();
        let peer_set = P2pPeerSet::new(
            genesis_id,
            Arc::new(Mutex::new((0, genesis_id))),
            dir.clone(),
            Arc::new(Mutex::new(chain)),
        );

        let connect_failure = "connection timed out";
        peer_set.note_peer_failure(&stale_seed, connect_failure);
        peer_set.note_peer_failure(&stale_seed, connect_failure);
        peer_set.note_peer_failure(&stale_seed, connect_failure);

        assert_eq!(peer_set.snapshot_available_peers(), vec![healthy.clone()]);
        assert_eq!(peer_set.snapshot_peers_except(None), vec![healthy.clone()]);

        let (loaded, max_outbound) = mfn_store::load_peers(&dir).expect("load peers");
        assert!(
            loaded.contains(&stale_seed),
            "transient connect failures must not remove saved public seeds"
        );
        assert!(loaded.contains(&healthy));
        assert_eq!(max_outbound, 4);

        peer_set.note_peer_success(&stale_seed);
        assert_eq!(
            peer_set.snapshot_available_peers(),
            vec![stale_seed, healthy]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn boot_dial_connect_quarantine_filters_reconnect_before_cap_accounting() {
        let dir = temp_dir("boot_dial_reconnect_cap_quarantine");
        let stale_seed = "203.0.113.10:19001".to_string();
        let healthy_first = "203.0.113.11:19001".to_string();
        let healthy_second = "203.0.113.12:19001".to_string();
        let mut peers = BTreeSet::new();
        peers.insert(stale_seed.clone());
        peers.insert(healthy_first.clone());
        peers.insert(healthy_second.clone());
        save_peers(&dir, &peers, 1).expect("save peers");

        let chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis chain");
        let genesis_id = *chain.genesis_id();
        let peer_set = P2pPeerSet::new(
            genesis_id,
            Arc::new(Mutex::new((0, genesis_id))),
            dir.clone(),
            Arc::new(Mutex::new(chain)),
        );

        let connect_failure = "connection timed out";
        peer_set.note_peer_failure(&stale_seed, connect_failure);
        peer_set.note_peer_failure(&stale_seed, connect_failure);
        peer_set.note_peer_failure(&stale_seed, connect_failure);

        assert_eq!(
            reconnect_peer_events(
                peer_set.snapshot_available_peers(),
                None,
                &[],
                peer_set.max_outbound_peers(),
            ),
            vec![
                ReconnectPeerEvent::Dial {
                    peer: healthy_first,
                },
                ReconnectPeerEvent::CapReached { count: 1, cap: 1 },
            ]
        );

        let (loaded, max_outbound) = mfn_store::load_peers(&dir).expect("load peers");
        assert!(loaded.contains(&stale_seed));
        assert!(loaded.contains(&healthy_second));
        assert_eq!(max_outbound, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn quarantine_filters_committee_catch_up_before_cap_accounting() {
        let dir = temp_dir("committee_catchup_cap_quarantine");
        let stale_seed = "203.0.113.10:19001".to_string();
        let healthy_first = "203.0.113.11:19001".to_string();
        let healthy_second = "203.0.113.12:19001".to_string();
        let mut peers = BTreeSet::new();
        peers.insert(stale_seed.clone());
        peers.insert(healthy_first.clone());
        peers.insert(healthy_second.clone());
        save_peers(&dir, &peers, 1).expect("save peers");

        let chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis chain");
        let genesis_id = *chain.genesis_id();
        let peer_set = P2pPeerSet::new(
            genesis_id,
            Arc::new(Mutex::new((0, genesis_id))),
            dir.clone(),
            Arc::new(Mutex::new(chain)),
        );

        let catch_up_failure =
            "sync_no_progress start=1 requested=8 local_height=0 remote_height=9";
        peer_set.note_peer_failure(&stale_seed, catch_up_failure);
        peer_set.note_peer_failure(&stale_seed, catch_up_failure);
        peer_set.note_peer_failure(&stale_seed, catch_up_failure);

        assert_eq!(
            catch_up_peer_events(
                peer_set.snapshot_available_peers(),
                None,
                peer_set.max_outbound_peers(),
            ),
            vec![
                CatchUpPeerEvent::Dial {
                    peer: healthy_first,
                },
                CatchUpPeerEvent::CapReached { count: 1, cap: 1 },
            ]
        );

        let (loaded, max_outbound) = mfn_store::load_peers(&dir).expect("load peers");
        assert!(loaded.contains(&stale_seed));
        assert!(loaded.contains(&healthy_second));
        assert_eq!(max_outbound, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gap_catch_up_boot_peer_addrs_filter_quarantined_peers() {
        let dir = temp_dir("gap_catchup_boot_peer_quarantine");
        let stale_seed = "203.0.113.10:19001".to_string();
        let healthy = "203.0.113.11:19001".to_string();
        let mut peers = BTreeSet::new();
        peers.insert(stale_seed.clone());
        peers.insert(healthy.clone());
        save_peers(&dir, &peers, 4).expect("save peers");

        let chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis chain");
        let genesis_id = *chain.genesis_id();
        let peer_set = P2pPeerSet::new(
            genesis_id,
            Arc::new(Mutex::new((0, genesis_id))),
            dir.clone(),
            Arc::new(Mutex::new(chain)),
        );

        let gap_recovery_failure =
            "sync_no_progress start=1 requested=8 local_height=0 remote_height=9";
        peer_set.note_peer_failure(&stale_seed, gap_recovery_failure);
        peer_set.note_peer_failure(&stale_seed, gap_recovery_failure);
        peer_set.note_peer_failure(&stale_seed, gap_recovery_failure);

        assert_eq!(
            FanoutPeerSet::boot_peer_addrs(peer_set.as_ref()),
            vec![healthy]
        );
        assert_eq!(FanoutPeerSet::max_outbound_peers(peer_set.as_ref()), 4);

        let (loaded, max_outbound) = mfn_store::load_peers(&dir).expect("load peers");
        assert!(loaded.contains(&stale_seed));
        assert_eq!(max_outbound, 4);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn repeated_gap_catch_up_failures_do_not_delete_saved_peer() {
        let dir = temp_dir("gap_catchup_failures_no_durable_drop");
        let stale_seed = "203.0.113.10:19001".to_string();
        let healthy = "203.0.113.11:19001".to_string();
        let mut peers = BTreeSet::new();
        peers.insert(stale_seed.clone());
        peers.insert(healthy.clone());
        save_peers(&dir, &peers, 4).expect("save peers");

        let chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis chain");
        let genesis_id = *chain.genesis_id();
        let peer_set = P2pPeerSet::new(
            genesis_id,
            Arc::new(Mutex::new((0, genesis_id))),
            dir.clone(),
            Arc::new(Mutex::new(chain)),
        );

        let gap_recovery_failure =
            "sync_no_progress start=1 requested=8 local_height=0 remote_height=9";
        for _ in 0..6 {
            peer_set.note_peer_failure(&stale_seed, gap_recovery_failure);
        }

        assert_eq!(
            FanoutPeerSet::boot_peer_addrs(peer_set.as_ref()),
            vec![healthy]
        );

        let (loaded, max_outbound) = mfn_store::load_peers(&dir).expect("load peers");
        assert_eq!(loaded, peers);
        assert_eq!(max_outbound, 4);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gap_catch_up_success_clears_peer_scoring_penalty() {
        let dir = temp_dir("gap_catchup_success_clears_penalty");
        let recovered_seed = "203.0.113.10:19001".to_string();
        let healthy = "203.0.113.11:19001".to_string();
        let mut peers = BTreeSet::new();
        peers.insert(recovered_seed.clone());
        peers.insert(healthy.clone());
        save_peers(&dir, &peers, 4).expect("save peers");

        let chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis chain");
        let genesis_id = *chain.genesis_id();
        let peer_set = P2pPeerSet::new(
            genesis_id,
            Arc::new(Mutex::new((0, genesis_id))),
            dir.clone(),
            Arc::new(Mutex::new(chain)),
        );

        let gap_recovery_failure =
            "sync_no_progress start=1 requested=8 local_height=0 remote_height=9";
        peer_set.note_peer_failure(&recovered_seed, gap_recovery_failure);
        peer_set.note_peer_failure(&recovered_seed, gap_recovery_failure);
        peer_set.note_peer_failure(&recovered_seed, gap_recovery_failure);

        assert_eq!(
            FanoutPeerSet::boot_peer_addrs(peer_set.as_ref()),
            vec![healthy.clone()]
        );

        FanoutPeerSet::note_peer_success(peer_set.as_ref(), &recovered_seed);

        assert_eq!(
            FanoutPeerSet::boot_peer_addrs(peer_set.as_ref()),
            vec![recovered_seed.clone(), healthy]
        );

        let (loaded, max_outbound) = mfn_store::load_peers(&dir).expect("load peers");
        assert!(loaded.contains(&recovered_seed));
        assert_eq!(max_outbound, 4);
        std::fs::remove_dir_all(&dir).ok();
    }
}
