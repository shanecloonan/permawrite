//! P2P gossip admission: decode consensus wire bytes into mempool / chain apply.

use std::sync::{Arc, Mutex};

use mfn_consensus::{decode_block, decode_transaction, tx_id};
use mfn_net::{GossipHandler, TipSnapshot};
use mfn_runtime::{AdmitError, AdmitOutcome, Chain, Mempool};
use mfn_store::ChainPersistence;

/// Shared chain + mempool + store for inbound gossip (**M2.3.16**).
pub struct P2pGossipHandler {
    chain: Arc<Mutex<Chain>>,
    pool: Arc<Mutex<Mempool>>,
    store: Arc<dyn ChainPersistence + Send + Sync>,
    tip_cell: TipSnapshot,
}

impl P2pGossipHandler {
    /// Build a handler wired to the live `mfnd serve` chain/mempool.
    pub fn new(
        chain: Arc<Mutex<Chain>>,
        pool: Arc<Mutex<Mempool>>,
        store: Arc<dyn ChainPersistence + Send + Sync>,
        tip_cell: TipSnapshot,
    ) -> Arc<Self> {
        Arc::new(Self {
            chain,
            pool,
            store,
            tip_cell,
        })
    }

    fn refresh_tip_cell(&self, chain: &Chain) {
        if let Ok(mut g) = self.tip_cell.lock() {
            let height = chain.tip_height().unwrap_or(0);
            let tip_id = chain
                .tip_id()
                .copied()
                .unwrap_or_else(|| *chain.genesis_id());
            *g = (height, tip_id);
        }
    }
}

impl GossipHandler for P2pGossipHandler {
    fn on_tx_v1(&self, tx_wire: &[u8]) -> String {
        let tx = match decode_transaction(tx_wire) {
            Ok(t) => t,
            Err(e) => return format!("rejected:decode:{e}"),
        };
        let id = tx_id(&tx);
        let mut id_hex = String::with_capacity(64);
        for b in id {
            use std::fmt::Write as _;
            let _ = write!(id_hex, "{b:02x}");
        }
        let chain = match self.chain.lock() {
            Ok(g) => g,
            Err(_) => return "rejected:chain_mutex".to_string(),
        };
        let mut pool = match self.pool.lock() {
            Ok(g) => g,
            Err(_) => return format!("rejected:pool_mutex tx_id={id_hex}"),
        };
        match pool.admit(tx, chain.state()) {
            Ok(
                AdmitOutcome::Fresh { .. }
                | AdmitOutcome::ReplacedByFee { .. }
                | AdmitOutcome::EvictedLowest { .. },
            ) => format!("accepted:{id_hex}"),
            Err(AdmitError::DuplicateTx { .. }) => format!("rejected:duplicate:{id_hex}"),
            Err(e) => format!("rejected:admit:{e}:{id_hex}"),
        }
    }

    fn on_block_v1(&self, block_wire: &[u8]) -> String {
        let block = match decode_block(block_wire) {
            Ok(b) => b,
            Err(e) => return format!("rejected:decode:{e}"),
        };
        let height = block.header.height;
        let mut chain = match self.chain.lock() {
            Ok(g) => g,
            Err(_) => return "rejected:chain_mutex".to_string(),
        };
        match chain.apply(&block) {
            Ok(bid) => {
                if let Err(e) = self.store.append_block(&block) {
                    return format!("rejected:store:{e}:height={height}");
                }
                if let Ok(mut pool) = self.pool.lock() {
                    let _ = pool.remove_mined(&block);
                }
                self.refresh_tip_cell(&chain);
                let mut bid_hex = String::with_capacity(64);
                for b in bid {
                    use std::fmt::Write as _;
                    let _ = write!(bid_hex, "{b:02x}");
                }
                format!("applied:{height}:{bid_hex}")
            }
            Err(e) => format!("rejected:apply:{e}:height={height}"),
        }
    }
}
