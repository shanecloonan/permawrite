//! P2P gossip admission: decode consensus wire bytes into mempool / chain apply.

use std::sync::{Arc, Mutex};

use mfn_consensus::{decode_block, decode_transaction, tx_id};
use mfn_net::{BlockSyncApplier, GossipHandler, TipSnapshot};
use mfn_runtime::{AdmitError, AdmitOutcome, Chain, Mempool, ProofPool};
use mfn_store::ChainPersistence;

/// Shared chain + mempool + store for inbound gossip (**M2.3.16**).
pub struct P2pGossipHandler {
    chain: Arc<Mutex<Chain>>,
    pool: Arc<Mutex<Mempool>>,
    proof_pool: Arc<Mutex<ProofPool>>,
    store: Arc<dyn ChainPersistence + Send + Sync>,
    tip_cell: TipSnapshot,
}

impl P2pGossipHandler {
    /// Build a handler wired to the live `mfnd serve` chain/mempool.
    pub fn new(
        chain: Arc<Mutex<Chain>>,
        pool: Arc<Mutex<Mempool>>,
        proof_pool: Arc<Mutex<ProofPool>>,
        store: Arc<dyn ChainPersistence + Send + Sync>,
        tip_cell: TipSnapshot,
    ) -> Arc<Self> {
        Arc::new(Self {
            chain,
            pool,
            proof_pool,
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

impl BlockSyncApplier for P2pGossipHandler {
    fn apply_synced_block(&self, block_wire: &[u8]) -> Result<u32, String> {
        let label = self.on_block_v1(block_wire);
        if let Some(rest) = label.strip_prefix("applied:") {
            let height = rest
                .split(':')
                .next()
                .ok_or_else(|| label.clone())?
                .parse::<u32>()
                .map_err(|_| label.clone())?;
            Ok(height)
        } else {
            Err(label)
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
            Ok(AdmitOutcome::Fresh { .. }) => format!("fresh:{id_hex}"),
            Ok(AdmitOutcome::ReplacedByFee { .. } | AdmitOutcome::EvictedLowest { .. }) => {
                format!("accepted:{id_hex}")
            }
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
        let local_height = chain.tip_height().unwrap_or(0);
        let next_height = local_height.saturating_add(1);
        if height != next_height {
            if height <= local_height {
                return format!("rejected:stale:local={local_height}:got={height}");
            }
            return format!("rejected:gap:local={local_height}:got={height}");
        }
        match chain.apply(&block) {
            Ok(bid) => {
                if let Err(e) = self.store.append_block(&block) {
                    return format!("rejected:store:{e}:height={height}");
                }
                if let Ok(mut pool) = self.pool.lock() {
                    let _ = pool.remove_mined(&block);
                }
                if let Ok(mut proof_pool) = self.proof_pool.lock() {
                    let mined: Vec<[u8; 32]> =
                        block.storage_proofs.iter().map(|p| p.commit_hash).collect();
                    let _ = proof_pool.remove_mined(mined);
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use mfn_consensus::{
        build_genesis, build_unsealed_header, encode_block, seal_block, GenesisConfig,
        DEFAULT_CONSENSUS_PARAMS, DEFAULT_EMISSION_PARAMS,
    };
    use mfn_net::GossipHandler;
    use mfn_runtime::{ChainConfig, Mempool, MempoolConfig, ProofPool, ProofPoolConfig};
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;
    use mfn_store::ChainStore;

    use super::P2pGossipHandler;

    fn handler_at_height_1() -> (Arc<P2pGossipHandler>, Vec<u8>) {
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let _genesis = build_genesis(&cfg);
        let dir = std::env::temp_dir().join(format!(
            "permawrite-p2p-gossip-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let store: Arc<dyn mfn_store::ChainPersistence + Send + Sync> =
            Arc::new(ChainStore::new(&dir));
        let chain_cfg = ChainConfig::new(cfg.clone());
        let chain = Arc::new(Mutex::new(
            store.load_or_genesis(chain_cfg).expect("genesis"),
        ));
        let pool = Arc::new(Mutex::new(Mempool::new(MempoolConfig::default())));
        let proof_pool = Arc::new(Mutex::new(ProofPool::new(ProofPoolConfig::default())));

        let mut guard = chain.lock().expect("chain");
        let st = guard.state();
        let height = 1u32;
        let unsealed = build_unsealed_header(st, &[], &[], &[], &[], height, 1_000);
        let block = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        guard.apply(&block).expect("block 1");
        let _ = store.append_block(&block);
        let wire = encode_block(&block);
        let tip_id = *guard.tip_id().expect("tip");
        drop(guard);

        let tip_cell = Arc::new(Mutex::new((height, tip_id)));
        let handler = P2pGossipHandler::new(chain, pool, proof_pool, store, tip_cell);
        (handler, wire)
    }

    #[test]
    fn rejects_stale_block_reapply() {
        let (handler, wire) = handler_at_height_1();
        let label = handler.on_block_v1(&wire);
        assert!(
            label.starts_with("rejected:stale:"),
            "expected stale reject, got {label}"
        );
    }

    #[test]
    fn rejects_height_gap_without_apply() {
        let (handler, _) = handler_at_height_1();
        let block = {
            let guard = handler.chain.lock().expect("chain");
            assert_eq!(guard.tip_height(), Some(1));
            let mut header = build_unsealed_header(guard.state(), &[], &[], &[], &[], 0, 3_000);
            header.height = 4;
            seal_block(
                header,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
        };
        let wire = encode_block(&block);
        let label = handler.on_block_v1(&wire);
        assert!(
            label.starts_with("rejected:gap:"),
            "expected gap reject, got {label}"
        );
    }
}
