//! P2P gossip admission: decode consensus wire bytes into mempool / chain apply.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use mfn_consensus::{
    block_id, decode_block, decode_transaction, fraud_proof_contested_block,
    fraud_proof_producer_slash_hint, tx_id, verify_interactive_fraud_proof,
    verify_validity_proof_v1, CoinbaseAmountFraudVerdict, FraudProofVerdict,
    InteractiveFraudVerdict, TxFraudVerdict, ValidityProofVerdict, DEFAULT_EMISSION_PARAMS,
};
use mfn_net::{BlockSyncApplier, GossipHandler, TipSnapshot};
use mfn_runtime::{AdmitError, AdmitOutcome, Chain, Mempool, ProofPool};
use mfn_store::ChainPersistence;

use crate::fraud_contest::{
    new_fraud_contest_registry, FraudContestEntry, FraudContestRegistryCell,
};
use crate::p2p_chunk_fanout::new_storage_commits_in_block;
use crate::p2p_fanout::P2pPeerSet;

fn fraud_label_with_slash_hint(base: String, consensus_wire: &[u8]) -> String {
    if let Some(hint) = fraud_proof_producer_slash_hint(consensus_wire) {
        format!(
            "{base}:slash_height={}:slash_producer={}",
            hint.height, hint.producer_index
        )
    } else {
        base
    }
}

/// Shared chain + mempool + store for inbound gossip (**M2.3.16**).
pub struct P2pGossipHandler {
    chain: Arc<Mutex<Chain>>,
    pool: Arc<Mutex<Mempool>>,
    proof_pool: Arc<Mutex<ProofPool>>,
    store: Arc<dyn ChainPersistence + Send + Sync>,
    tip_cell: TipSnapshot,
    peers: Option<Arc<P2pPeerSet>>,
    contests: FraudContestRegistryCell,
}

impl P2pGossipHandler {
    /// Build a handler wired to the live `mfnd serve` chain/mempool.
    pub fn new(
        chain: Arc<Mutex<Chain>>,
        pool: Arc<Mutex<Mempool>>,
        proof_pool: Arc<Mutex<ProofPool>>,
        store: Arc<dyn ChainPersistence + Send + Sync>,
        tip_cell: TipSnapshot,
        peers: Option<Arc<P2pPeerSet>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            chain,
            pool,
            proof_pool,
            store,
            tip_cell,
            peers,
            contests: new_fraud_contest_registry(),
        })
    }

    /// Shared fraud contest registry for RPC [`list_fraud_contests`].
    pub fn contests(&self) -> FraudContestRegistryCell {
        Arc::clone(&self.contests)
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

    fn store_gossip_chunk(
        &self,
        commit_hash: &[u8; 32],
        chunk_index: u32,
        chunk_bytes: &[u8],
        merkle_proof_wire: Option<&[u8]>,
    ) -> String {
        let mut hex = String::with_capacity(64);
        for b in commit_hash {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        // (M7.12 / B2) Peers are untrusted: only chunks for an anchored
        // on-chain commitment, with geometry checks and (for v2) Merkle
        // inclusion against `data_root`, reach disk.
        let chain = match self.chain.lock() {
            Ok(g) => g,
            Err(_) => return "rejected:chain_mutex".to_string(),
        };
        let commit = match chain.state().storage.get(commit_hash) {
            Some(entry) => entry.commit.clone(),
            None => return format!("rejected:unknown_commit:commit={hex}:index={chunk_index}"),
        };
        let validation = match merkle_proof_wire {
            Some(proof_wire) => crate::p2p_chunk_inbox::validate_gossip_chunk_v2(
                &commit,
                chunk_index,
                chunk_bytes,
                proof_wire,
            ),
            None => {
                crate::p2p_chunk_inbox::validate_gossip_chunk(&commit, chunk_index, chunk_bytes)
            }
        };
        if let Err(reason) = validation {
            return format!("rejected:chunk_invalid:commit={hex}:index={chunk_index}:{reason:?}");
        }
        // Never overwrite an existing same-length chunk: a malicious peer
        // must not be able to corrupt bytes an operator already holds and
        // will be challenged on. (A wrong-length leftover may be repaired.)
        let expected_len = crate::p2p_chunk_inbox::expected_chunk_len(&commit, chunk_index);
        let existing = mfn_store::chunk_inbox_path(self.store.root(), &hex, chunk_index);
        if let Ok(meta) = std::fs::metadata(&existing) {
            if meta.len() == expected_len {
                return format!("skipped:already_present:commit={hex}:index={chunk_index}");
            }
        }
        let max_bytes = match crate::p2p_chunk_inbox::chunk_inbox_max_bytes_from_env() {
            Ok(v) => v,
            Err(e) => return format!("rejected:chunk_inbox_env:{e}"),
        };
        match crate::p2p_chunk_inbox::save_chunk_inbox_with_quota(
            self.store.root(),
            &chain.state().storage,
            commit_hash,
            chunk_index,
            chunk_bytes,
            max_bytes,
        ) {
            Ok(path) => {
                format!(
                    "stored:commit={hex}:index={chunk_index}:bytes={}:path={}",
                    chunk_bytes.len(),
                    path.display()
                )
            }
            Err(e) => format!("rejected:chunk_inbox:{e}"),
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
    fn on_chunk_v1(&self, commit_hash: &[u8; 32], chunk_index: u32, chunk_bytes: &[u8]) -> String {
        self.store_gossip_chunk(commit_hash, chunk_index, chunk_bytes, None)
    }

    fn on_chunk_v2(
        &self,
        commit_hash: &[u8; 32],
        chunk_index: u32,
        chunk_bytes: &[u8],
        merkle_proof_wire: &[u8],
    ) -> String {
        self.store_gossip_chunk(
            commit_hash,
            chunk_index,
            chunk_bytes,
            Some(merkle_proof_wire),
        )
    }

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
        let known_storage: HashSet<[u8; 32]> = chain.state().storage.keys().copied().collect();
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
                if let Some(ps) = &self.peers {
                    let new_commits = new_storage_commits_in_block(&block, &known_storage);
                    ps.fanout_inbox_chunks_for_commits(&new_commits, None);
                }
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

    fn on_fraud_proof_v1(&self, consensus_wire: &[u8]) -> String {
        let label = match verify_interactive_fraud_proof(consensus_wire, &DEFAULT_EMISSION_PARAMS) {
            Ok(InteractiveFraudVerdict::BodyRoot(FraudProofVerdict::ValidFraud {
                kind, ..
            })) => {
                if let Ok(p) = mfn_consensus::decode_body_root_fraud_proof(consensus_wire) {
                    let bid = block_id(&p.block.header);
                    let mut bid_hex = String::with_capacity(64);
                    for b in bid {
                        use std::fmt::Write as _;
                        let _ = write!(bid_hex, "{b:02x}");
                    }
                    format!(
                        "valid_fraud:{kind:?}:height={}:block_id={bid_hex}",
                        p.block.header.height
                    )
                } else {
                    "valid_fraud:body_root".into()
                }
            }
            Ok(InteractiveFraudVerdict::CoinbaseAmount(
                CoinbaseAmountFraudVerdict::ValidFraud { height, .. },
            )) => {
                if let Ok(p) = mfn_consensus::decode_coinbase_amount_fraud_proof(consensus_wire) {
                    let bid = block_id(&p.block.header);
                    let mut bid_hex = String::with_capacity(64);
                    for b in bid {
                        use std::fmt::Write as _;
                        let _ = write!(bid_hex, "{b:02x}");
                    }
                    format!("valid_fraud:CoinbaseAmount:height={height}:block_id={bid_hex}")
                } else {
                    format!("valid_fraud:CoinbaseAmount:height={height}")
                }
            }
            Ok(InteractiveFraudVerdict::Tx(TxFraudVerdict::InvalidClsag(v))) => {
                format!(
                    "valid_fraud:InvalidClsag:tx_index={}:errors={}",
                    v.tx_index,
                    v.verify_errors.len()
                )
            }
            Ok(InteractiveFraudVerdict::Tx(TxFraudVerdict::InvalidSpora(v))) => {
                format!(
                    "valid_fraud:InvalidSpora:proof_index={}:reason={:?}",
                    v.proof_index, v.reason
                )
            }
            Ok(InteractiveFraudVerdict::Tx(TxFraudVerdict::RingMember(v))) => {
                format!(
                    "valid_fraud:RingMember:tx={}:input={}:ring={}:reason={:?}",
                    v.tx_index, v.input_index, v.ring_index, v.reason
                )
            }
            Err(e) => format!("rejected:verify:{e}"),
        };
        if label.starts_with("valid_fraud:") {
            if let Some((height, block_id, producer_index)) =
                fraud_proof_contested_block(consensus_wire)
            {
                if let Ok(mut g) = self.contests.lock() {
                    g.record(FraudContestEntry {
                        block_id,
                        height,
                        producer_index: producer_index.unwrap_or(u32::MAX),
                        label: label.clone(),
                    });
                }
            }
            fraud_label_with_slash_hint(label, consensus_wire)
        } else {
            label
        }
    }

    fn on_validity_proof_v1(&self, consensus_wire: &[u8]) -> String {
        match verify_validity_proof_v1(consensus_wire) {
            Ok(ValidityProofVerdict::ValidAccept { height }) => {
                format!("valid_validity:height={height}")
            }
            Err(e) => format!("rejected:verify:{e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use mfn_consensus::{
        build_apply_block_replay_validity_proof, build_genesis,
        build_stark_digest_stub_validity_proof, build_unsealed_header, encode_block,
        encode_validity_proof_v1, seal_block, GenesisConfig, DEFAULT_CONSENSUS_PARAMS,
        DEFAULT_EMISSION_PARAMS,
    };
    use mfn_net::GossipHandler;
    use mfn_runtime::{ChainConfig, Mempool, MempoolConfig, ProofPool, ProofPoolConfig};
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;
    use mfn_store::ChainStore;

    use super::P2pGossipHandler;

    fn handler_at_height_1() -> (Arc<P2pGossipHandler>, Vec<u8>) {
        handler_at_height_1_with_storage(Vec::new())
    }

    fn handler_at_height_1_with_storage(
        initial_storage: Vec<mfn_consensus::storage::StorageCommitment>,
    ) -> (Arc<P2pGossipHandler>, Vec<u8>) {
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage,
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
            header_version: 1,
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
        let handler = P2pGossipHandler::new(chain, pool, proof_pool, store, tip_cell, None);
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
    fn on_chunk_v1_rejects_unknown_commit_without_disk_write() {
        // (M7.12) Untrusted peers cannot fill the inbox with bytes for
        // commitments the chain never anchored.
        let (handler, _) = handler_at_height_1();
        let hash = [0x33u8; 32];
        let label = handler.on_chunk_v1(&hash, 1, b"chunk-bytes");
        assert!(label.starts_with("rejected:unknown_commit:"), "got {label}");
        let path = handler
            .store
            .root()
            .join(mfn_store::CHUNK_INBOX_DIR)
            .join(hex::encode(hash))
            .join("1.bin");
        assert!(!path.exists(), "unexpected write at {}", path.display());
    }

    #[test]
    fn on_chunk_v1_validates_anchored_chunks_and_protects_existing_bytes() {
        // Anchor a real 3-chunk commitment at genesis, then exercise the
        // full M7.12 gossip gate: true chunks store; bad index / bad
        // length / (single-file) overwrite attempts are refused.
        let payload: Vec<u8> = mfn_storage::pad_to_storage_size_bucket(
            &(0u32..2_500).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
        );
        let built = mfn_storage::build_storage_commitment(&payload, 1_000, Some(1_024), 3, None)
            .expect("build commitment");
        let hash = mfn_storage::storage_commitment_hash(&built.commit);
        let chunks = mfn_storage::chunk_data(&payload, 1_024).expect("chunks");
        assert_eq!(chunks.len(), 4);

        let (handler, _) = handler_at_height_1_with_storage(vec![built.commit.clone()]);

        // True chunks are accepted.
        for (i, c) in chunks.iter().enumerate() {
            let label = handler.on_chunk_v1(&hash, i as u32, c);
            assert!(label.starts_with("stored:commit="), "chunk {i}: {label}");
        }
        let path = handler
            .store
            .root()
            .join(mfn_store::CHUNK_INBOX_DIR)
            .join(hex::encode(hash))
            .join("0.bin");
        assert_eq!(std::fs::read(&path).expect("read"), chunks[0]);

        // Out-of-range index is refused.
        let label = handler.on_chunk_v1(&hash, 4, &vec![0u8; 1_024]);
        assert!(label.starts_with("rejected:chunk_invalid:"), "got {label}");

        // Wrong-length body is refused.
        let label = handler.on_chunk_v1(&hash, 0, b"short");
        assert!(label.starts_with("rejected:chunk_invalid:"), "got {label}");

        // A correct-length resend cannot overwrite the bytes already held.
        let forged = vec![0xffu8; 1_024];
        let label = handler.on_chunk_v1(&hash, 0, &forged);
        assert!(label.starts_with("skipped:already_present:"), "got {label}");
        assert_eq!(std::fs::read(&path).expect("re-read"), chunks[0]);
    }

    #[test]
    fn on_chunk_v1_fully_verifies_single_chunk_commitments() {
        // With one chunk the Merkle root IS the leaf hash, so forged
        // bytes of the right length are still refused outright.
        let payload = mfn_storage::pad_to_storage_size_bucket(&vec![9u8; 500]);
        let built = mfn_storage::build_storage_commitment(&payload, 1_000, Some(1_024), 3, None)
            .expect("build commitment");
        let hash = mfn_storage::storage_commitment_hash(&built.commit);
        let (handler, _) = handler_at_height_1_with_storage(vec![built.commit.clone()]);

        let mut forged = payload.clone();
        forged[0] ^= 0xff;
        let label = handler.on_chunk_v1(&hash, 0, &forged);
        assert!(label.starts_with("rejected:chunk_invalid:"), "got {label}");

        let label = handler.on_chunk_v1(&hash, 0, &payload);
        assert!(label.starts_with("stored:commit="), "got {label}");
    }

    #[test]
    fn on_chunk_v2_validates_merkle_proofs_for_multi_chunk_commitments() {
        let payload: Vec<u8> = mfn_storage::pad_to_storage_size_bucket(
            &(0u32..2_500).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
        );
        let built = mfn_storage::build_storage_commitment(&payload, 1_000, Some(1_024), 3, None)
            .expect("build commitment");
        let hash = mfn_storage::storage_commitment_hash(&built.commit);
        let chunks = mfn_storage::chunk_data(&payload, 1_024).expect("chunks");
        let (handler, _) = handler_at_height_1_with_storage(vec![built.commit.clone()]);

        for (i, c) in chunks.iter().enumerate() {
            let proof = mfn_crypto::merkle::merkle_proof(&built.tree, i).expect("proof");
            let wire = mfn_storage::encode_merkle_proof_wire(&proof);
            let label = handler.on_chunk_v2(&hash, i as u32, c, &wire);
            assert!(label.starts_with("stored:commit="), "chunk {i}: {label}");
        }

        let proof = mfn_crypto::merkle::merkle_proof(&built.tree, 0).expect("proof");
        let wire = mfn_storage::encode_merkle_proof_wire(&proof);
        let forged = vec![0xffu8; 1_024];
        let label = handler.on_chunk_v2(&hash, 0, &forged, &wire);
        assert!(label.starts_with("rejected:chunk_invalid:"), "got {label}");

        let path = handler
            .store
            .root()
            .join(mfn_store::CHUNK_INBOX_DIR)
            .join(hex::encode(hash))
            .join("0.bin");
        assert_eq!(std::fs::read(&path).expect("read"), chunks[0]);
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

    #[test]
    fn rejects_next_height_fork_without_apply_or_store_append() {
        let (handler, _) = handler_at_height_1();
        let block = {
            let guard = handler.chain.lock().expect("chain");
            assert_eq!(guard.tip_height(), Some(1));
            let mut header = build_unsealed_header(guard.state(), &[], &[], &[], &[], 2, 3_000);
            header.prev_hash[0] ^= 0xff;
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
            label.starts_with("rejected:apply:"),
            "expected apply reject, got {label}"
        );

        let guard = handler.chain.lock().expect("chain");
        assert_eq!(guard.tip_height(), Some(1));
        let stored = handler.store.read_block_log().expect("block log");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].header.height, 1);
    }

    #[test]
    fn accepts_valid_tx_root_fraud_proof() {
        let (handler, _) = handler_at_height_1();
        let mut block = {
            let guard = handler.chain.lock().expect("chain");
            let header = build_unsealed_header(guard.state(), &[], &[], &[], &[], 2, 3_000);
            seal_block(
                header,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
        };
        block.header.tx_root = [0xAB; 32];
        let proof = mfn_consensus::tx_root_fraud_proof(block);
        let wire = mfn_consensus::encode_body_root_fraud_proof(&proof);
        let label = handler.on_fraud_proof_v1(&wire);
        assert!(
            label.starts_with("valid_fraud:TxRoot:"),
            "expected valid fraud, got {label}"
        );
        let contests_cell = handler.contests();
        let contests = contests_cell.lock().expect("contests");
        assert_eq!(contests.len(), 1, "valid fraud should register a contest");
    }

    #[test]
    fn rejects_consistent_block_as_not_fraud() {
        let (handler, _) = handler_at_height_1();
        let block = {
            let guard = handler.chain.lock().expect("chain");
            let header = build_unsealed_header(guard.state(), &[], &[], &[], &[], 2, 3_000);
            seal_block(
                header,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
        };
        let proof = mfn_consensus::tx_root_fraud_proof(block);
        let wire = mfn_consensus::encode_body_root_fraud_proof(&proof);
        let label = handler.on_fraud_proof_v1(&wire);
        assert!(
            label.starts_with("rejected:verify:"),
            "expected verify reject, got {label}"
        );
    }

    #[test]
    fn accepts_valid_apply_block_replay_validity_proof() {
        let (handler, _) = handler_at_height_1();
        let (parent, genesis_id, block) = {
            let guard = handler.chain.lock().expect("chain");
            let st = guard.state().clone();
            let gid = *guard.genesis_id();
            let unsealed = build_unsealed_header(&st, &[], &[], &[], &[], 2, 2_000);
            let block = seal_block(
                unsealed,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            );
            (st, gid, block)
        };
        let proof = build_apply_block_replay_validity_proof(genesis_id, &parent, &block);
        let wire = encode_validity_proof_v1(&proof);
        let label = handler.on_validity_proof_v1(&wire);
        assert!(
            label.starts_with("valid_validity:height=2"),
            "expected valid validity, got {label}"
        );
    }

    #[test]
    fn accepts_valid_stark_digest_stub_validity_proof() {
        let (handler, _) = handler_at_height_1();
        let (parent, genesis_id, block) = {
            let guard = handler.chain.lock().expect("chain");
            let st = guard.state().clone();
            let gid = *guard.genesis_id();
            let unsealed = build_unsealed_header(&st, &[], &[], &[], &[], 2, 2_000);
            let block = seal_block(
                unsealed,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            );
            (st, gid, block)
        };
        let proof = build_stark_digest_stub_validity_proof(genesis_id, &parent, &block);
        let wire = encode_validity_proof_v1(&proof);
        let label = handler.on_validity_proof_v1(&wire);
        assert!(
            label.starts_with("valid_validity:height=2"),
            "expected valid stark stub validity, got {label}"
        );
    }
}
