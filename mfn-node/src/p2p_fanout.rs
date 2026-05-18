//! Mempool tx fan-out to known P2P peers (**M2.3.20**).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::thread;

use mfn_consensus::{decode_transaction, tx_id};
use mfn_net::{push_tx_gossip_to_peer, ChainTipV1, FanoutPeerSet, TipSnapshot};

/// Peers that completed a successful P2P handshake (address strings suitable for `TcpStream::connect`).
#[derive(Clone)]
pub struct P2pPeerSet {
    genesis_id: [u8; 32],
    tip_cell: TipSnapshot,
    peers: Arc<Mutex<BTreeSet<String>>>,
}

impl P2pPeerSet {
    /// Build a fan-out registry bound to this chain's genesis id and live tip snapshot.
    pub fn new(genesis_id: [u8; 32], tip_cell: TipSnapshot) -> Arc<Self> {
        Arc::new(Self {
            genesis_id,
            tip_cell,
            peers: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    /// Remember a peer after a successful handshake (inbound accept or outbound dial).
    pub fn register(&self, peer_addr: impl Into<String>) {
        let addr = peer_addr.into();
        if let Ok(mut g) = self.peers.lock() {
            g.insert(addr);
        }
    }

    /// Push `tx_wire` to every registered peer except `except_peer` (if any).
    fn broadcast_fresh_tx(&self, tx_wire: &[u8], except_peer: Option<&str>) {
        let peers: Vec<String> = match self.peers.lock() {
            Ok(g) => g
                .iter()
                .filter(|p| except_peer.is_none_or(|ex| ex != *p))
                .cloned()
                .collect(),
            Err(_) => return,
        };
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
        let tip_cell = Arc::clone(&self.tip_cell);
        for peer in peers {
            let wire = Arc::clone(&wire);
            let tx_id_hex = tx_id_hex.clone();
            let tip_cell = Arc::clone(&tip_cell);
            thread::Builder::new()
                .name("mfnd-p2p-tx-fanout".into())
                .spawn(move || {
                    let local = {
                        let g = tip_cell.lock().unwrap_or_else(|e| e.into_inner());
                        ChainTipV1 {
                            height: g.0,
                            tip_id: g.1,
                        }
                    };
                    match push_tx_gossip_to_peer(&peer, &genesis_id, &local, &wire) {
                        Ok(()) => {
                            println!("mfnd_p2p_tx_fanout_ok peer={peer} tx_id={tx_id_hex}");
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                        Err(e) => {
                            eprintln!("mfnd_p2p_tx_fanout_abort peer={peer} tx_id={tx_id_hex} {e}");
                        }
                    }
                })
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
