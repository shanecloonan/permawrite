//! Mempool tx fan-out and persistent peer registry (**M2.3.20**, **M2.3.22**).

use std::collections::{BTreeMap, BTreeSet};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::Duration;

use mfn_consensus::{decode_transaction, tx_id, StorageCommitment};
use mfn_net::{
    push_block_gossip_to_peer, push_chunks_gossip_to_peer, push_fraud_proof_gossip_to_peer,
    push_proposal_v1_to_peer, push_tx_gossip_to_peer, push_tx_stem_gossip_to_peer,
    push_vote_v1_to_peer, read_vote_v1_reply, send_block_v1, send_chunk_v2, send_fraud_proof_v1,
    send_gossip_end_v1, send_proposal_v1, send_vote_v1, spawn_catch_up_dial, spawn_outbound_dial,
    BlockSyncApplierHook, BlockSyncHook, ChainTipV1, FanoutPeerSet, GossipHook, HidCounter,
    OutboundP2pDial, P2pSessionHooks, ProductionHook, TipSnapshot,
};
use mfn_runtime::Chain;
use mfn_store::{load_peers_with_report, save_peers, DEFAULT_MAX_OUTBOUND_PEERS};

use crate::dandelion::{DandelionConfig, DandelionRelay, RelayAction};
use crate::p2p_peer_quarantine::{
    should_drop_persistent_peer_on_failure, PeerQuarantine, PEER_FAILURES_BEFORE_QUARANTINE,
    PEER_QUARANTINE_DURATION,
};
use crate::p2p_reconnect_plan::{
    catch_up_peer_events, is_self_peer_addr, reconnect_peer_events, CatchUpPeerEvent,
    ReconnectPeerEvent,
};

/// Dedup key for body-root fraud proof mesh fan-out (**F5** phase 1).
type FraudProofFanoutKey = ([u8; 32], u8);

/// Peers that completed a successful P2P handshake (address strings suitable for `TcpStream::connect`).
#[derive(Clone)]
pub struct P2pPeerSet {
    genesis_id: [u8; 32],
    tip_cell: TipSnapshot,
    data_root: PathBuf,
    max_outbound_peers: u32,
    peers: Arc<Mutex<BTreeSet<String>>>,
    durable_peers: Arc<Mutex<BTreeSet<String>>>,
    sessions: Arc<Mutex<BTreeMap<String, Arc<Mutex<TcpStream>>>>>,
    quarantine: Arc<Mutex<PeerQuarantine>>,
    production: Arc<Mutex<Option<ProductionHook>>>,
    fanout_lock: Arc<Mutex<()>>,
    fraud_proof_fanout_seen: Arc<Mutex<BTreeSet<FraudProofFanoutKey>>>,
    chain: Arc<Mutex<Chain>>,
    dandelion: Arc<Mutex<DandelionRelay>>,
    self_arc: Weak<Self>,
}

impl P2pPeerSet {
    /// Build a fan-out registry; loads `peers.json` when present (**M2.3.22**).
    pub fn new(
        genesis_id: [u8; 32],
        tip_cell: TipSnapshot,
        data_root: impl Into<PathBuf>,
        chain: Arc<Mutex<Chain>>,
        dandelion_config: DandelionConfig,
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
            peers: Arc::new(Mutex::new(initial.clone())),
            durable_peers: Arc::new(Mutex::new(initial)),
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            quarantine: Arc::new(Mutex::new(PeerQuarantine::new(
                PEER_FAILURES_BEFORE_QUARANTINE,
                PEER_QUARANTINE_DURATION,
            ))),
            production: Arc::new(Mutex::new(None)),
            fanout_lock: Arc::new(Mutex::new(())),
            fraud_proof_fanout_seen: Arc::new(Mutex::new(BTreeSet::new())),
            chain,
            dandelion: Arc::new(Mutex::new(DandelionRelay::new(
                dandelion_config,
                genesis_id,
            ))),
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
                    let Some(chunks) =
                        crate::p2p_chunk_fanout::load_complete_inbox_chunks_v2_wire(
                            &data_root,
                            &commit_hash,
                            &commit,
                        )
                    else {
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
            let Some(chunks) = crate::p2p_chunk_fanout::load_complete_inbox_chunks_v2_wire(
                &self.data_root,
                commit_hash,
                commit,
            ) else {
                continue;
            };
            let commit_hex = hex::encode(commit_hash);
            let n = chunks.len();
            let mut ok = true;
            for (index, bytes, proof_wire) in &chunks {
                if let Err(e) = send_chunk_v2(stream, commit_hash, *index, proof_wire, bytes) {
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

    #[cfg(test)]
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

    /// Durable peers suitable for committee catch-up / reconnect (excludes ephemeral inbound dialers).
    fn snapshot_durable_available_peers(&self) -> Vec<String> {
        let peers = match self.durable_peers.lock() {
            Ok(g) => g.iter().cloned().collect::<Vec<_>>(),
            Err(_) => return Vec::new(),
        };
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
        let changed = match (self.peers.lock(), self.durable_peers.lock()) {
            (Ok(mut peers), Ok(mut durable)) => {
                durable.insert(addr.clone());
                peers.insert(addr)
            }
            _ => return,
        };
        if changed {
            self.persist();
        }
    }

    /// Track an inbound dialer for this process without writing it to `peers.json`.
    ///
    /// Inbound `peer_addr` values are usually ephemeral TCP source ports. They may hold
    /// a live session for tx/chunk fan-out, but must not pollute production fan-out or
    /// durable boot/reconnect peer sets.
    pub fn register_ephemeral(&self, peer_addr: impl Into<String>) {
        let addr = peer_addr.into();
        self.note_peer_success(&addr);
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
        let peers = match (self.peers.lock(), self.durable_peers.lock()) {
            (Ok(mut peers), Ok(mut durable)) => {
                durable.remove(peer_addr);
                if !peers.remove(peer_addr) {
                    return;
                }
                durable.clone()
            }
            _ => return,
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

    /// Write the current durable peer set to `peers.json` (e.g. on shutdown).
    pub fn persist(&self) {
        let peers = match self.durable_peers.lock() {
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

    /// Current chain slot proxy for repair staleness (tip height until slot is on the tip cell).
    pub(crate) fn current_chain_slot(&self) -> u64 {
        let g = self.tip_cell.lock().unwrap_or_else(|e| e.into_inner());
        u64::from(g.0)
    }

    pub(crate) fn data_root(&self) -> &std::path::Path {
        &self.data_root
    }

    pub(crate) fn chain_storage_snapshot(&self) -> Option<Vec<([u8; 32], u64, StorageCommitment)>> {
        let guard = self.chain.lock().ok()?;
        Some(
            guard
                .state()
                .storage
                .iter()
                .map(|(hash, entry)| (*hash, entry.last_proven_slot, entry.commit.clone()))
                .collect(),
        )
    }

    fn snapshot_peers_except(&self, except_peer: Option<&str>) -> Vec<String> {
        self.snapshot_tx_fanout_peers_except(except_peer)
    }

    /// Durable committee/boot peers for proposal and vote fan-out.
    fn snapshot_production_fanout_peers_except(&self, except_peer: Option<&str>) -> Vec<String> {
        let durable = self.snapshot_durable_available_peers();
        let peers = if durable.is_empty() {
            // Before P2P advertise registers committee listen addrs, fan out on live sessions.
            self.snapshot_session_peers()
        } else {
            durable
        };
        peers
            .into_iter()
            .filter(|p| except_peer.map(|ex| ex != *p).unwrap_or(true))
            .collect()
    }

    /// Durable peers plus any live inbound session keys for tx/chunk gossip.
    fn snapshot_tx_fanout_peers_except(&self, except_peer: Option<&str>) -> Vec<String> {
        let mut peers: BTreeSet<String> = self
            .snapshot_durable_available_peers()
            .into_iter()
            .collect();
        if let Ok(sessions) = self.sessions.lock() {
            for peer in sessions.keys() {
                peers.insert(peer.clone());
            }
        }
        peers
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

    /// Live session peer diversity snapshot (**P31** phase 0).
    #[must_use]
    pub fn peer_diversity_snapshot(&self) -> mfn_net::PeerDiversitySnapshot {
        mfn_net::peer_diversity_snapshot(&self.snapshot_session_peers())
    }

    /// Diverse session + durable peers for checkpoint anchor export (**F12** phase 0).
    #[must_use]
    pub fn snapshot_checkpoint_anchor_peers(&self, max_peers: usize) -> Vec<String> {
        mfn_net::checkpoint_anchor_peer_candidates(
            &self.snapshot_session_peers(),
            &self.snapshot_durable_available_peers(),
            max_peers,
        )
    }

    fn maybe_warn_peer_diversity(&self) {
        let min = match mfn_net::min_distinct_ipv4_prefix16_from_env() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("mfnd_p2p_diversity_config_error {e}");
                return;
            }
        };
        let peers = self.snapshot_session_peers();
        if let Some(warning) = mfn_net::peer_diversity_warning(&peers, min) {
            eprintln!("{warning}");
        }
    }

    /// True when every durable peer has a live session (skip redundant catch-up dials).
    #[must_use]
    pub fn periodic_catch_up_idle(&self) -> bool {
        let local = self.local_tip();
        if local.height == 0 {
            return false;
        }
        let durable = self.snapshot_durable_available_peers();
        if durable.is_empty() {
            return false;
        }
        let sessions: BTreeSet<String> = self.snapshot_session_peers().into_iter().collect();
        durable.iter().all(|p| sessions.contains(p))
    }

    fn push_proposal_collect_votes_on_peers(
        self: &Arc<Self>,
        peers: &[String],
        proposal_wire: &[u8],
        production: Option<ProductionHook>,
    ) {
        let genesis_id = self.genesis_id;
        let local = self.local_tip();
        for peer in peers {
            let vote_body = if let Some(vote) =
                self.push_proposal_collect_vote_on_session(peer, proposal_wire)
            {
                Some(vote)
            } else {
                match push_proposal_v1_to_peer(peer, &genesis_id, &local, proposal_wire) {
                    Ok(vote) => vote,
                    Err(e) => {
                        self.note_peer_failure(peer, &e.to_string());
                        None
                    }
                }
            };
            if let Some(vote_body) = vote_body {
                self.note_peer_success(peer);
                if let Some(h) = production.as_ref() {
                    let label = h.on_vote_v1(&vote_body);
                    println!("mfnd_p2p_proposal_vote_push peer={peer} {label}");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
            }
        }
    }

    /// Push `proposal_wire` synchronously and ingest inline vote replies (**M2.4.64**).
    pub fn fanout_proposal_sync(self: &Arc<Self>, proposal_wire: &[u8], except_peer: Option<&str>) {
        let peers = self.snapshot_production_fanout_peers_except(except_peer);
        if peers.is_empty() {
            return;
        }
        let _guard = match self.fanout_lock.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let production = self.production_hook();
        self.push_proposal_collect_votes_on_peers(&peers, proposal_wire, production);
    }

    /// Push `proposal_wire` to every registered peer except `except_peer` (**M2.3.23**).
    pub fn fanout_proposal(self: &Arc<Self>, proposal_wire: &[u8], except_peer: Option<&str>) {
        let peers = self.snapshot_production_fanout_peers_except(except_peer);
        if peers.is_empty() {
            return;
        }
        let wire = proposal_wire.to_vec();
        let lock = Arc::clone(&self.fanout_lock);
        let peer_set = Arc::clone(self);
        let production = self.production_hook();
        thread::Builder::new()
            .name("mfnd-p2p-proposal-fanout".into())
            .spawn(move || {
                let _guard = match lock.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                peer_set.push_proposal_collect_votes_on_peers(&peers, &wire, production);
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
        let peers = self.snapshot_production_fanout_peers_except(except_peer);
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
                    let Some(chunks) =
                        crate::p2p_chunk_fanout::load_complete_inbox_chunks_v2_wire(
                            &data_root,
                            &commit_hash,
                            &commit,
                        )
                    else {
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
        chunks: &[(u32, Vec<u8>, Vec<u8>)],
    ) -> bool {
        self.send_on_session(peer, |sock| {
            for (index, bytes, proof_wire) in chunks {
                send_chunk_v2(sock, commit_hash, *index, proof_wire, bytes)?;
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

    /// Push a verified body-root fraud proof to every registered peer except `except_peer` (**F5**).
    pub fn fanout_fraud_proof(&self, consensus_wire: &[u8], except_peer: Option<&str>) {
        let fanout_key = match mfn_consensus::fraud_proof_fanout_key(consensus_wire) {
            Some(k) => k,
            None => return,
        };
        let already_seen = match self.fraud_proof_fanout_seen.lock() {
            Ok(mut seen) => !seen.insert(fanout_key),
            Err(_) => return,
        };
        if already_seen {
            return;
        }
        let Some(peer_set) = self.self_arc.upgrade() else {
            return;
        };
        let session_peers = peer_set.snapshot_session_peers();
        let dial_peers = peer_set.snapshot_peers_except(except_peer);
        if session_peers.is_empty() && dial_peers.is_empty() {
            return;
        }
        let wire = consensus_wire.to_vec();
        let genesis_id = peer_set.genesis_id;
        let local = peer_set.local_tip();
        let except = except_peer.map(str::to_string);
        let lock = Arc::clone(&peer_set.fanout_lock);
        thread::Builder::new()
            .name("mfnd-p2p-fraud-proof-fanout".into())
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
                    if peer_set.push_fraud_proof_on_session(&peer, &wire) {
                        sent.insert(peer);
                    }
                }
                for peer in dial_peers {
                    if except.as_deref().is_some_and(|ex| ex == peer) || sent.contains(&peer) {
                        continue;
                    }
                    if peer_set.push_fraud_proof_on_session(&peer, &wire) {
                        sent.insert(peer);
                        continue;
                    }
                    if let Err(e) =
                        push_fraud_proof_gossip_to_peer(&peer, &genesis_id, &local, &wire)
                    {
                        peer_set.note_peer_failure(&peer, &e.to_string());
                        eprintln!("mfnd_p2p_fraud_proof_fanout_abort peer={peer} {e}");
                    } else {
                        peer_set.note_peer_success(&peer);
                    }
                }
            })
            .ok();
    }

    fn push_fraud_proof_on_session(&self, peer: &str, consensus_wire: &[u8]) -> bool {
        self.send_on_session(peer, |sock| send_fraud_proof_v1(sock, consensus_wire))
    }

    /// Push `tx_wire` to registered peers (**B7**: stem single-peer or fluff fan-out).
    fn broadcast_fresh_tx(&self, tx_wire: &[u8], except_peer: Option<&str>) {
        let peers = self.snapshot_peers_except(except_peer);
        if peers.is_empty() {
            return;
        }
        let tx = match decode_transaction(tx_wire) {
            Ok(t) => t,
            Err(_) => return,
        };
        let id = tx_id(&tx);
        let mut tx_id_hex = String::with_capacity(64);
        for b in id {
            use std::fmt::Write as _;
            let _ = write!(tx_id_hex, "{b:02x}");
        }
        let (enabled, action) = match self.dandelion.lock() {
            Ok(mut relay) => {
                let enabled = relay.is_enabled();
                let action = relay.decide(id, &peers, std::time::Instant::now());
                (enabled, action)
            }
            Err(_) => (false, RelayAction::Fluff),
        };
        match (enabled, action) {
            (true, RelayAction::Fluff) => {
                println!(
                    "mfnd_dandelion_fluff tx_id={tx_id_hex} peers={}",
                    peers.len()
                );
                let _ = std::io::Write::flush(&mut std::io::stdout());
                self.broadcast_fresh_tx_parallel(tx_wire, &peers, &tx_id_hex);
            }
            (false, RelayAction::Fluff) => {
                self.broadcast_fresh_tx_parallel(tx_wire, &peers, &tx_id_hex);
            }
            (true, RelayAction::Stem { peer }) => {
                println!("mfnd_dandelion_stem tx_id={tx_id_hex} peer={peer}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                self.spawn_tx_push_to_peer(&peer, tx_wire, &tx_id_hex, true);
            }
            (false, RelayAction::Stem { peer }) => {
                self.spawn_tx_push_to_peer(&peer, tx_wire, &tx_id_hex, false);
            }
        }
    }

    fn broadcast_fresh_tx_parallel(&self, tx_wire: &[u8], peers: &[String], tx_id_hex: &str) {
        let wire = Arc::new(tx_wire.to_vec());
        let genesis_id = self.genesis_id;
        let local = self.local_tip();
        for peer in peers {
            let wire = Arc::clone(&wire);
            let tx_id_hex = tx_id_hex.to_string();
            let peer_set = self.self_arc.clone();
            let peer = peer.clone();
            thread::Builder::new()
                .name("mfnd-p2p-tx-fanout".into())
                .spawn(
                    move || match push_tx_gossip_to_peer(&peer, &genesis_id, &local, &wire) {
                        Ok(()) => {
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

    fn spawn_tx_push_to_peer(&self, peer: &str, tx_wire: &[u8], tx_id_hex: &str, stem_wire: bool) {
        let wire = Arc::new(tx_wire.to_vec());
        let genesis_id = self.genesis_id;
        let local = self.local_tip();
        let peer = peer.to_string();
        let tx_id_hex = tx_id_hex.to_string();
        let peer_set = self.self_arc.clone();
        thread::Builder::new()
            .name(if stem_wire {
                "mfnd-p2p-tx-stem".into()
            } else {
                "mfnd-p2p-tx-fanout".into()
            })
            .spawn(move || {
                let push = if stem_wire {
                    push_tx_stem_gossip_to_peer(&peer, &genesis_id, &local, &wire)
                } else {
                    push_tx_gossip_to_peer(&peer, &genesis_id, &local, &wire)
                };
                match push {
                    Ok(()) => {
                        if let Some(peer_set) = peer_set.upgrade() {
                            peer_set.note_peer_success(&peer);
                        }
                        if stem_wire {
                            println!("mfnd_p2p_tx_stem_ok peer={peer} tx_id={tx_id_hex}");
                        } else {
                            println!("mfnd_p2p_tx_fanout_ok peer={peer} tx_id={tx_id_hex}");
                        }
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                    }
                    Err(e) => {
                        if let Some(peer_set) = peer_set.upgrade() {
                            peer_set.note_peer_failure(&peer, &e.to_string());
                        }
                        eprintln!("mfnd_p2p_tx_fanout_abort peer={peer} tx_id={tx_id_hex} {e}");
                    }
                }
            })
            .ok();
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
        drop(guard);
        self.maybe_warn_peer_diversity();
    }

    fn unregister_session(&self, peer_addr: &str) {
        let Ok(mut guard) = self.sessions.lock() else {
            return;
        };
        if guard.remove(peer_addr).is_some() {
            eprintln!("mfnd_p2p_session_unregister peer={peer_addr}");
        }
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

    fn fanout_fraud_proof(&self, consensus_wire: &[u8], except_peer: Option<&str>) {
        P2pPeerSet::fanout_fraud_proof(self, consensus_wire, except_peer);
    }

    fn boot_peer_addrs(&self) -> Vec<String> {
        self.snapshot_durable_available_peers()
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
            if peer_set.periodic_catch_up_idle() {
                thread::sleep(Duration::from_millis(interval_ms));
                continue;
            }
            let events = catch_up_peer_events(
                peer_set.snapshot_durable_available_peers(),
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

/// Periodic redial when IPv4 /16 session diversity is low (**P31** phase 1).
pub struct PeerDiversityRedialLoop {
    /// Peer registry.
    pub peer_set: Arc<P2pPeerSet>,
    /// Chain genesis id for hello handshake.
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
    /// Sleep interval between diversity sweeps.
    pub interval_ms: u64,
}

/// Spawn a background loop that dials durable peers in underrepresented /16 buckets.
pub fn spawn_peer_diversity_redial_loop(cfg: PeerDiversityRedialLoop) -> Result<(), String> {
    let PeerDiversityRedialLoop {
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
        .name("mfnd-p2p-diversity-redial".into())
        .spawn(move || loop {
            let min_prefix16 = match mfn_net::min_distinct_ipv4_prefix16_from_env() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("mfnd_p2p_diversity_config_error {e}");
                    thread::sleep(Duration::from_millis(interval_ms));
                    continue;
                }
            };
            let redial_enabled = match mfn_net::peer_diversity_redial_enabled_from_env() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("mfnd_p2p_diversity_config_error {e}");
                    thread::sleep(Duration::from_millis(interval_ms));
                    continue;
                }
            };
            if min_prefix16 == 0 || !redial_enabled {
                thread::sleep(Duration::from_millis(interval_ms));
                continue;
            }
            let sessions = peer_set.snapshot_session_peers();
            let candidates = peer_set.snapshot_durable_available_peers();
            let max_per_sweep = peer_set
                .max_outbound_peers()
                .min(mfn_net::DEFAULT_DIVERSITY_REDIAL_PER_SWEEP);
            let picks = mfn_net::peer_diversity_redial_candidates(
                &sessions,
                &candidates,
                min_prefix16,
                max_per_sweep,
            );
            for peer in picks {
                if is_self_peer_addr(&peer, local_p2p_listen) {
                    println!("mfnd_p2p_self_dial_skip peer={peer}");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    continue;
                }
                println!("mfnd_p2p_diversity_redial_start peer={peer}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
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
            thread::sleep(Duration::from_millis(interval_ms));
        })
        .map_err(|e| format!("mfnd serve: spawn peer diversity redial loop: {e}"))?;
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
        peer_set.snapshot_durable_available_peers(),
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
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: ConsensusParams {
                expected_proposers_per_slot: 1.0,
                quorum_stake_bps: 6667,
                ..DEFAULT_CONSENSUS_PARAMS
            },
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
            header_version: 1,
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
            DandelionConfig::default(),
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
            DandelionConfig::default(),
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
            DandelionConfig::default(),
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
            DandelionConfig::default(),
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
            DandelionConfig::default(),
        );

        let catch_up_failure =
            "sync_no_progress start=1 requested=8 local_height=0 remote_height=9";
        peer_set.note_peer_failure(&stale_seed, catch_up_failure);
        peer_set.note_peer_failure(&stale_seed, catch_up_failure);
        peer_set.note_peer_failure(&stale_seed, catch_up_failure);

        assert_eq!(
            catch_up_peer_events(
                peer_set.snapshot_durable_available_peers(),
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
    fn ephemeral_peers_are_excluded_from_committee_catch_up() {
        let dir = temp_dir("committee_catchup_ephemeral_exclude");
        let durable = "203.0.113.20:19001".to_string();
        let ephemeral = "127.0.0.1:50612".to_string();
        let mut peers = BTreeSet::new();
        peers.insert(durable.clone());
        save_peers(&dir, &peers, 2).expect("save peers");

        let chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis chain");
        let genesis_id = *chain.genesis_id();
        let peer_set = P2pPeerSet::new(
            genesis_id,
            Arc::new(Mutex::new((0, genesis_id))),
            dir.clone(),
            Arc::new(Mutex::new(chain)),
            DandelionConfig::default(),
        );

        peer_set.register_ephemeral(&ephemeral);
        assert!(!peer_set.snapshot_available_peers().contains(&ephemeral));
        assert!(!peer_set
            .snapshot_production_fanout_peers_except(None)
            .contains(&ephemeral));
        assert!(!peer_set
            .snapshot_durable_available_peers()
            .contains(&ephemeral));

        assert_eq!(
            catch_up_peer_events(
                peer_set.snapshot_durable_available_peers(),
                None,
                peer_set.max_outbound_peers(),
            ),
            vec![CatchUpPeerEvent::Dial {
                peer: durable.clone(),
            }]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unregister_session_drops_live_session_count() {
        use mfn_net::FanoutPeerSet;
        use std::net::{TcpListener, TcpStream};

        let dir = temp_dir("session_unregister");
        let chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis chain");
        let genesis_id = *chain.genesis_id();
        let peer_set = P2pPeerSet::new(
            genesis_id,
            Arc::new(Mutex::new((0, genesis_id))),
            dir.clone(),
            Arc::new(Mutex::new(chain)),
            DandelionConfig::default(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let listen_addr = listener.local_addr().expect("local_addr");
        let client = thread::spawn(move || TcpStream::connect(listen_addr).expect("connect"));
        let (stream, peer_addr) = listener.accept().expect("accept");
        let _ = client.join().expect("client join");
        let peer_key = peer_addr.to_string();

        peer_set.register_session(&peer_key, stream);
        assert_eq!(peer_set.snapshot_session_peers(), vec![peer_key.clone()]);
        peer_set.unregister_session(&peer_key);
        assert!(peer_set.snapshot_session_peers().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn peer_diversity_snapshot_reflects_live_sessions() {
        use mfn_net::FanoutPeerSet;
        use std::net::{TcpListener, TcpStream};

        let dir = temp_dir("diversity_snapshot");
        let chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis chain");
        let genesis_id = *chain.genesis_id();
        let peer_set = P2pPeerSet::new(
            genesis_id,
            Arc::new(Mutex::new((0, genesis_id))),
            dir.clone(),
            Arc::new(Mutex::new(chain)),
            DandelionConfig::default(),
        );

        let listener_a = TcpListener::bind("127.0.0.1:0").expect("bind a");
        let listener_b = TcpListener::bind("127.0.0.1:0").expect("bind b");
        let addr_a = listener_a.local_addr().expect("addr a");
        let addr_b = listener_b.local_addr().expect("addr b");
        let client_a = thread::spawn(move || TcpStream::connect(addr_a).expect("connect a"));
        let client_b = thread::spawn(move || TcpStream::connect(addr_b).expect("connect b"));
        let (stream_a, peer_a) = listener_a.accept().expect("accept a");
        let (stream_b, peer_b) = listener_b.accept().expect("accept b");
        let _ = client_a.join().expect("join a");
        let _ = client_b.join().expect("join b");

        peer_set.register_session(&peer_a.to_string(), stream_a);
        peer_set.register_session(&peer_b.to_string(), stream_b);
        let snap = peer_set.peer_diversity_snapshot();
        assert_eq!(snap.session_count, 2);
        assert_eq!(snap.ipv4_session_count, 2);
        assert_eq!(snap.distinct_ipv4_prefix16, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn periodic_catch_up_idle_when_all_durable_peers_have_sessions() {
        use std::net::{TcpListener, TcpStream};

        let dir = temp_dir("catch_up_idle");
        let peer_a = "203.0.113.30:19001".to_string();
        let peer_b = "203.0.113.31:19001".to_string();
        let mut peers = BTreeSet::new();
        peers.insert(peer_a.clone());
        peers.insert(peer_b.clone());
        save_peers(&dir, &peers, 4).expect("save peers");

        let chain =
            Chain::from_genesis(ChainConfig::new(empty_genesis_cfg())).expect("genesis chain");
        let genesis_id = *chain.genesis_id();
        let peer_set = P2pPeerSet::new(
            genesis_id,
            Arc::new(Mutex::new((1, genesis_id))),
            dir.clone(),
            Arc::new(Mutex::new(chain)),
            DandelionConfig::default(),
        );

        assert!(!peer_set.periodic_catch_up_idle());

        let listener_a = TcpListener::bind("127.0.0.1:0").expect("bind a");
        let addr_a = listener_a.local_addr().expect("local a");
        peer_set.register_session(&peer_a, TcpStream::connect(addr_a).expect("connect a"));
        let _ = listener_a.accept().expect("accept a");

        assert!(!peer_set.periodic_catch_up_idle());

        let listener_b = TcpListener::bind("127.0.0.1:0").expect("bind b");
        let addr_b = listener_b.local_addr().expect("local b");
        peer_set.register_session(&peer_b, TcpStream::connect(addr_b).expect("connect b"));
        let _ = listener_b.accept().expect("accept b");

        assert!(peer_set.periodic_catch_up_idle());

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
            DandelionConfig::default(),
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
            DandelionConfig::default(),
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
            DandelionConfig::default(),
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
