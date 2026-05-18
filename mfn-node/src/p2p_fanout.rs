//! Mempool tx fan-out and persistent peer registry (**M2.3.20**, **M2.3.22**).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use mfn_consensus::{decode_transaction, tx_id};
use mfn_net::{
    push_block_gossip_to_peer, push_proposal_v1_to_peer, push_tx_gossip_to_peer,
    push_vote_v1_to_peer, spawn_outbound_dial, BlockSyncApplierHook, ChainTipV1, FanoutPeerSet,
    GossipHook, HidCounter, OutboundP2pDial, P2pSessionHooks, TipSnapshot,
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
        })
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

    /// Push `proposal_wire` to every registered peer except `except_peer` (**M2.3.23**).
    pub fn fanout_proposal(&self, proposal_wire: &[u8], except_peer: Option<&str>) {
        let peers = self.snapshot_peers_except(except_peer);
        if peers.is_empty() {
            return;
        }
        let wire = Arc::new(proposal_wire.to_vec());
        let genesis_id = self.genesis_id;
        let local = self.local_tip();
        for peer in peers {
            let wire = Arc::clone(&wire);
            thread::Builder::new()
                .name("mfnd-p2p-proposal-fanout".into())
                .spawn(move || {
                    if let Err(e) = push_proposal_v1_to_peer(&peer, &genesis_id, &local, &wire) {
                        eprintln!("mfnd_p2p_proposal_fanout_abort peer={peer} {e}");
                    }
                })
                .ok();
        }
    }

    /// Push `vote_wire` to every registered peer except `except_peer` (**M2.3.23**).
    pub fn fanout_vote(&self, vote_wire: &[u8], except_peer: Option<&str>) {
        let peers = self.snapshot_peers_except(except_peer);
        if peers.is_empty() {
            return;
        }
        let wire = Arc::new(vote_wire.to_vec());
        let genesis_id = self.genesis_id;
        let local = self.local_tip();
        for peer in peers {
            let wire = Arc::clone(&wire);
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

    /// Push `block_wire` to every registered peer except `except_peer` (**M2.3.23**).
    pub fn fanout_block(&self, block_wire: &[u8], except_peer: Option<&str>) {
        let peers = self.snapshot_peers_except(except_peer);
        if peers.is_empty() {
            return;
        }
        let wire = Arc::new(block_wire.to_vec());
        let genesis_id = self.genesis_id;
        let local = self.local_tip();
        for peer in peers {
            let wire = Arc::clone(&wire);
            thread::Builder::new()
                .name("mfnd-p2p-block-fanout".into())
                .spawn(move || {
                    if let Err(e) = push_block_gossip_to_peer(&peer, &genesis_id, &local, &wire) {
                        eprintln!("mfnd_p2p_block_fanout_abort peer={peer} {e}");
                    }
                })
                .ok();
        }
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

    fn fanout_fresh_tx(&self, tx_wire: &[u8], except_peer: Option<&str>) {
        self.broadcast_fresh_tx(tx_wire, except_peer);
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
    /// Optional block catch-up applier.
    pub block_applier: Option<BlockSyncApplierHook>,
    /// Fan-out registry passed to outbound dials.
    pub fanout_hook: Option<Arc<dyn FanoutPeerSet>>,
    /// Local listen address to advertise after dial.
    pub local_p2p_listen: Option<std::net::SocketAddr>,
    /// Skip this peer (e.g. already dialed via `--p2p-dial`).
    pub skip_addr: Option<&'a str>,
}

/// Dial up to [`P2pPeerSet::max_outbound_peers`] saved peers on boot (**M2.3.22**).
pub fn spawn_reconnect_saved_peers(cfg: ReconnectPeersBoot<'_>) -> Result<(), String> {
    let ReconnectPeersBoot {
        peer_set,
        genesis_id,
        tip_cell,
        hid_counter,
        gossip,
        block_applier,
        fanout_hook,
        local_p2p_listen,
        skip_addr,
    } = cfg;
    let mut spawned = 0u32;
    for addr in peer_set.snapshot_peers() {
        if skip_addr.is_some_and(|s| s == addr) {
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
                block_applier: block_applier.clone(),
                fanout_peers: fanout_hook.clone(),
                ..Default::default()
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
