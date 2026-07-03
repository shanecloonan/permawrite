//! Slot-driven multi-validator block production (**M2.3.23**).

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use mfn_bls::CommitteeVote;
use mfn_consensus::{
    build_coinbase, encode_block, pick_winner, producer_coinbase_amount,
    storage_proof_coinbase_bonus, verify_producer_proof, ConsensusCheck, ConsensusParams,
    PayoutAddress, ProducerProof, Validator, ValidatorSecrets,
};
use mfn_net::production::ProductionHandler;
use mfn_net::TipSnapshot;
use mfn_runtime::{
    build_proposal, decode_block_proposal, decode_committee_vote, encode_block_proposal,
    encode_committee_vote, seal_proposal, verify_committee_vote_sig, vote_on_proposal, BlockInputs,
    BlockProposal, Chain, Mempool, ProducerError, ProofPool,
};
use mfn_store::{save_proof_pool, ChainPersistence};

use crate::p2p_chunk_fanout::new_storage_commits_in_block;
use crate::p2p_fanout::P2pPeerSet;

const MFND_MEMPOOL_DRAIN_MAX: usize = 256;
const PENDING_PROPOSAL_REBROADCAST_LIMIT: u8 = 12;
/// When the local validator is not VRF-eligible, advance slot numbers within one wall-clock
/// tick before waiting for the next `--slot-duration-ms` interval. Public-devnet validator 0
/// is known ineligible at slot 1; without this scan the hub can stall at genesis for many slots.
const MAX_SLOT_ELIGIBILITY_SCANS: u32 = 128;

/// Local validator keys + slot timer for `mfnd serve --produce`.
#[derive(Clone)]
pub struct ProduceConfig {
    /// Validator row from genesis matching env seeds.
    pub validator: Validator,
    /// VRF + BLS secrets for this validator.
    pub secrets: ValidatorSecrets,
    /// Milliseconds between slot ticks.
    pub slot_duration_ms: u64,
}

struct PendingProposal {
    proposal: BlockProposal,
    votes: Vec<CommitteeVote>,
    indices: BTreeSet<usize>,
    rebroadcasts: u8,
}

/// Dependencies for [`ProductionEngine::new`].
pub struct ProductionEngineDeps {
    /// Live chain state (mutex-protected).
    pub chain: Arc<Mutex<Chain>>,
    /// Mempool for block proposals.
    pub pool: Arc<Mutex<Mempool>>,
    /// SPoRA proof queue drained into produced blocks (**M3.22**).
    pub proof_pool: Arc<Mutex<ProofPool>>,
    /// Block log + checkpoint persistence.
    pub store: Arc<dyn ChainPersistence + Send + Sync>,
    /// Shared tip for P2P height exchange.
    pub tip_cell: TipSnapshot,
    /// Genesis wall-clock timestamp for slot timing.
    pub genesis_timestamp: u64,
    /// Local validator keys and slot duration.
    pub local: ProduceConfig,
    /// Peer registry for proposal/vote/block fan-out.
    pub peers: Arc<P2pPeerSet>,
}

/// Shared production state for P2P + slot loop.
pub struct ProductionEngine {
    chain: Arc<Mutex<Chain>>,
    pool: Arc<Mutex<Mempool>>,
    proof_pool: Arc<Mutex<ProofPool>>,
    store: Arc<dyn ChainPersistence + Send + Sync>,
    tip_cell: TipSnapshot,
    genesis_timestamp: u64,
    local: ProduceConfig,
    peers: Arc<P2pPeerSet>,
    pending: Mutex<Option<PendingProposal>>,
    next_slot: Mutex<u32>,
}

impl ProductionEngine {
    /// Wire production to a running `mfnd serve` instance.
    pub fn new(deps: ProductionEngineDeps) -> Arc<Self> {
        Arc::new(Self {
            chain: deps.chain,
            pool: deps.pool,
            proof_pool: deps.proof_pool,
            store: deps.store,
            tip_cell: deps.tip_cell,
            genesis_timestamp: deps.genesis_timestamp,
            local: deps.local,
            peers: deps.peers,
            pending: Mutex::new(None),
            next_slot: Mutex::new(0),
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

    fn params(&self, chain: &Chain) -> ConsensusParams {
        chain.state().params
    }

    fn quorum_reached(&self, signing_stake: u64, total_stake: u64, quorum_bps: u32) -> bool {
        u128::from(signing_stake) * 10_000 >= u128::from(total_stake) * u128::from(quorum_bps)
    }

    fn signing_stake(&self, votes: &[CommitteeVote], validators: &[Validator]) -> u64 {
        votes
            .iter()
            .filter_map(|v| validators.get(v.index).map(|x| x.stake))
            .sum()
    }

    fn reserve_next_slot(&self, height: u32) -> Result<u32, String> {
        let mut guard = self
            .next_slot
            .lock()
            .map_err(|_| "slot cursor mutex poisoned".to_string())?;
        let slot = guard.saturating_add(1).max(height);
        *guard = slot;
        Ok(slot)
    }

    fn clear_pending_at_or_below_tip(&self, tip_height: u32) {
        if let Ok(mut guard) = self.pending.lock() {
            if guard
                .as_ref()
                .is_some_and(|p| p.proposal.ctx.height <= tip_height)
            {
                *guard = None;
            }
        }
    }

    fn clear_pending_below_height(&self, height: u32) {
        if let Ok(mut guard) = self.pending.lock() {
            if guard
                .as_ref()
                .is_some_and(|p| p.proposal.ctx.height < height)
            {
                *guard = None;
            }
        }
    }

    fn block_inputs_for_next(
        &self,
        chain: &Chain,
        pool: &mut Mempool,
        proof_pool: &mut ProofPool,
    ) -> Result<BlockInputs, String> {
        let tip = chain
            .tip_height()
            .ok_or_else(|| "missing tip height".to_string())?;
        let height = tip
            .checked_add(1)
            .ok_or_else(|| "tip height overflow".to_string())?;
        let slot = self.reserve_next_slot(height)?;
        let timestamp = self.genesis_timestamp.saturating_add(u64::from(slot));
        let emission_params = chain.state().emission_params;
        let drained = pool.select_for_block(MFND_MEMPOOL_DRAIN_MAX);
        let mut fee_sum: u128 = 0;
        for t in &drained {
            fee_sum = fee_sum.saturating_add(u128::from(t.fee));
        }
        let prev = chain
            .tip_id()
            .copied()
            .unwrap_or_else(|| *chain.genesis_id());
        let storage_proofs = proof_pool.drain_verified(chain.state(), &prev, height);
        let st = chain.state();
        let storage_bonus = storage_proof_coinbase_bonus(
            &storage_proofs,
            &st.storage,
            height,
            &st.endowment_params,
        );
        let coinbase_amount = producer_coinbase_amount(
            u64::from(height),
            &emission_params,
            fee_sum,
            storage_proofs.len(),
            storage_bonus,
        );
        let payout = self
            .local
            .validator
            .payout
            .as_ref()
            .ok_or_else(|| "validator has no payout for coinbase".to_string())?;
        let cb_payout = PayoutAddress {
            view_pub: payout.view_pub,
            spend_pub: payout.spend_pub,
        };
        let cb = build_coinbase(u64::from(height), coinbase_amount, &cb_payout)
            .map_err(|e| format!("build_coinbase: {e}"))?;
        let mut txs = Vec::with_capacity(1 + drained.len());
        txs.push(cb);
        txs.extend(drained);
        Ok(BlockInputs {
            height,
            slot,
            timestamp,
            txs,
            bond_ops: Vec::new(),
            slashings: Vec::new(),
            storage_proofs,
        })
    }

    fn verify_proposal(&self, proposal: &BlockProposal, chain: &Chain) -> Result<(), String> {
        let expected_height = chain.tip_height().map(|h| h.saturating_add(1)).unwrap_or(0);
        if proposal.ctx.height != expected_height {
            return Err(format!(
                "height mismatch want={expected_height} got={}",
                proposal.ctx.height
            ));
        }
        let validators = chain.validators();
        let producer = validators
            .iter()
            .find(|v| v.index == proposal.producer_proof.validator_index)
            .ok_or_else(|| "producer not in validator set".to_string())?;
        let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
        let params = self.params(chain);
        let check = verify_producer_proof(
            &proposal.ctx,
            &proposal.producer_proof,
            producer,
            total_stake,
            params.expected_proposers_per_slot,
            &proposal.header_hash,
        );
        if check != ConsensusCheck::Ok {
            return Err(format!("producer proof: {check:?}"));
        }
        Ok(())
    }

    fn try_vote_locally(&self, proposal: &BlockProposal) -> Option<CommitteeVote> {
        let chain = self.chain.lock().ok()?;
        let params = self.params(&chain);
        let producer = chain
            .validators()
            .iter()
            .find(|v| v.index == proposal.producer_proof.validator_index)?;
        vote_on_proposal(
            proposal,
            chain.state(),
            &self.local.validator,
            &self.local.secrets,
            producer,
            params,
        )
        .ok()
    }

    fn ingest_vote(&self, header_hash: [u8; 32], vote: CommitteeVote) -> Result<(), String> {
        let mut guard = self
            .pending
            .lock()
            .map_err(|_| "pending mutex poisoned".to_string())?;
        let pending = guard
            .as_mut()
            .ok_or_else(|| "no pending proposal".to_string())?;
        if pending.proposal.header_hash != header_hash {
            return Err("vote for unknown header_hash".into());
        }
        if pending.indices.contains(&vote.index) {
            return Ok(());
        }
        let chain = self
            .chain
            .lock()
            .map_err(|_| "chain mutex poisoned".to_string())?;
        let validators = chain.validators();
        let Some(v) = validators.get(vote.index) else {
            return Err("vote index out of range".into());
        };
        if !verify_committee_vote_sig(&header_hash, &vote, &v.bls_pk) {
            return Err("invalid vote signature".into());
        }
        pending.indices.insert(vote.index);
        pending.votes.push(vote);
        let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
        let params = self.params(&chain);
        let signing = self.signing_stake(&pending.votes, validators);
        if !self.quorum_reached(signing, total_stake, params.quorum_stake_bps) {
            return Ok(());
        }
        let proposal = pending.proposal.clone();
        // Only the block proposer seals locally; committee peers apply the fan-out block.
        if proposal.producer_proof.validator_index != self.local.validator.index {
            *guard = None;
            return Ok(());
        }
        let votes = pending.votes.clone();
        let validators_len = validators.len();
        *guard = None;
        drop(chain);
        drop(guard);
        self.seal_and_apply(proposal, votes, validators_len, signing)?;
        Ok(())
    }

    fn seal_and_apply(
        &self,
        proposal: BlockProposal,
        votes: Vec<CommitteeVote>,
        validators_len: usize,
        signing_stake: u64,
    ) -> Result<(), String> {
        let block = seal_proposal(proposal, &votes, validators_len, signing_stake)
            .map_err(|e| format!("seal: {e}"))?;
        let height = block.header.height;
        let vote_count = votes.len();
        let mut chain = self
            .chain
            .lock()
            .map_err(|_| "chain mutex poisoned".to_string())?;
        let known_storage: HashSet<[u8; 32]> = chain.state().storage.keys().copied().collect();
        chain.apply(&block).map_err(|e| format!("apply: {e}"))?;
        if let Ok(mut pool) = self.pool.lock() {
            let _ = pool.remove_mined(&block);
        }
        if let Ok(mut proof_pool) = self.proof_pool.lock() {
            let mined: Vec<[u8; 32]> = block.storage_proofs.iter().map(|p| p.commit_hash).collect();
            let _ = proof_pool.remove_mined(mined);
            if let Err(e) = save_proof_pool(self.store.as_ref(), &proof_pool) {
                eprintln!("mfnd_proof_pool_save_abort {e}");
            }
        }
        self.store
            .append_block(&block)
            .map_err(|e| format!("store: {e}"))?;
        self.refresh_tip_cell(&chain);
        let new_commits = new_storage_commits_in_block(&block, &known_storage);
        let wire = encode_block(&block);
        drop(chain);
        self.peers.fanout_block(&wire, None);
        self.peers
            .fanout_inbox_chunks_for_commits(&new_commits, None);
        println!("mfnd_producer_sealed height={height} votes={vote_count}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        Ok(())
    }

    /// When two validators propose the same height, keep the smallest-`beta` proof
    /// (same rule as [`pick_winner`]) so all nodes converge on one pending block.
    /// When the same producer advances to a later slot after releasing a timed-out
    /// pending proposal, always accept the newer slot so committee votes track the
    /// live hub proposal instead of stale header hashes.
    fn reconcile_pending(
        existing: &PendingProposal,
        incoming: &BlockProposal,
    ) -> Result<(), String> {
        if existing.proposal.header_hash == incoming.header_hash {
            return Ok(());
        }
        if existing.proposal.ctx.height != incoming.ctx.height {
            return Err(format!(
                "busy:height={} incoming_height={}",
                existing.proposal.ctx.height, incoming.ctx.height
            ));
        }
        let a: &ProducerProof = &existing.proposal.producer_proof;
        let b: &ProducerProof = &incoming.producer_proof;
        if a.validator_index == b.validator_index && incoming.ctx.slot > existing.proposal.ctx.slot
        {
            return Ok(());
        }
        let candidates = [a.clone(), b.clone()];
        let winner = pick_winner(&candidates).expect("two candidates");
        if winner.validator_index == a.validator_index && winner.beta == a.beta {
            return Err(format!("competing:height={}", incoming.ctx.height));
        }
        Ok(())
    }

    fn adopt_proposal(&self, proposal: BlockProposal) -> String {
        let chain = match self.chain.lock() {
            Ok(g) => g,
            Err(_) => return "rejected:chain_mutex".into(),
        };
        if let Err(e) = self.verify_proposal(&proposal, &chain) {
            return format!("rejected:proposal:{e}");
        }
        drop(chain);
        self.clear_pending_below_height(proposal.ctx.height);
        {
            let mut guard = match self.pending.lock() {
                Ok(g) => g,
                Err(_) => return "rejected:pending_mutex".into(),
            };
            if let Some(existing) = guard.as_ref() {
                match Self::reconcile_pending(existing, &proposal) {
                    Ok(()) => {
                        if existing.proposal.header_hash != proposal.header_hash {
                            *guard = Some(PendingProposal {
                                proposal: proposal.clone(),
                                votes: Vec::new(),
                                indices: BTreeSet::new(),
                                rebroadcasts: 0,
                            });
                        }
                    }
                    Err(reason) => return format!("rejected:{reason}"),
                }
            } else {
                *guard = Some(PendingProposal {
                    proposal: proposal.clone(),
                    votes: Vec::new(),
                    indices: BTreeSet::new(),
                    rebroadcasts: 0,
                });
            }
        }
        // Fan out immediately so committee voters can reply on the same slot tick;
        // waiting for the next tick lets pending advance slots before votes arrive.
        if proposal.producer_proof.validator_index == self.local.validator.index {
            let wire = encode_block_proposal(&proposal);
            self.peers.fanout_proposal(&wire, None);
        }
        // The original producer owns proposal fan-out and bounded rebroadcast.
        // Committee voters keep a local pending proposal only to vote; re-gossiping
        // from every voter can keep stale proposals alive after catch-up advances.
        if let Some(vote) = self.try_vote_locally(&proposal) {
            let _ = self.ingest_vote(proposal.header_hash, vote);
            let vote_wire = encode_committee_vote(&proposal.header_hash, &vote);
            self.peers.fanout_vote(&vote_wire, None);
        }
        format!("accepted:height={}", proposal.ctx.height)
    }

    fn adopt_pending_for_direct_vote(&self, proposal: &BlockProposal) -> Result<(), String> {
        let chain = self.chain.lock().map_err(|_| "chain_mutex".to_string())?;
        self.verify_proposal(proposal, &chain)
            .map_err(|e| format!("proposal:{e}"))?;
        drop(chain);
        self.clear_pending_below_height(proposal.ctx.height);

        let mut guard = self
            .pending
            .lock()
            .map_err(|_| "pending_mutex".to_string())?;
        if let Some(existing) = guard.as_ref() {
            Self::reconcile_pending(existing, proposal)?;
            if existing.proposal.header_hash == proposal.header_hash {
                return Ok(());
            }
        }
        *guard = Some(PendingProposal {
            proposal: proposal.clone(),
            votes: Vec::new(),
            indices: BTreeSet::new(),
            rebroadcasts: 0,
        });
        Ok(())
    }

    /// One slot tick: try to propose when locally eligible.
    pub fn on_slot_tick(&self) {
        let tip_height = self
            .chain
            .lock()
            .ok()
            .and_then(|chain| chain.tip_height())
            .unwrap_or(0);
        self.clear_pending_at_or_below_tip(tip_height);
        if let Ok(mut guard) = self.pending.lock() {
            if let Some(pending) = guard.as_mut() {
                let chain = match self.chain.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                let validators = chain.validators();
                let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
                let params = self.params(&chain);
                let signing = self.signing_stake(&pending.votes, validators);
                if self.quorum_reached(signing, total_stake, params.quorum_stake_bps) {
                    if pending.proposal.producer_proof.validator_index == self.local.validator.index
                    {
                        let proposal = pending.proposal.clone();
                        let votes = pending.votes.clone();
                        let validators_len = validators.len();
                        *guard = None;
                        drop(chain);
                        drop(guard);
                        match self.seal_and_apply(proposal, votes, validators_len, signing) {
                            Ok(()) => return,
                            Err(e) => {
                                eprintln!("mfnd_producer_seal_tick_abort {e}");
                                return;
                            }
                        }
                    }
                    return;
                }
                let wire = encode_block_proposal(&pending.proposal);
                self.peers.fanout_proposal(&wire, None);
                pending.rebroadcasts = pending.rebroadcasts.saturating_add(1);
                if pending.rebroadcasts >= PENDING_PROPOSAL_REBROADCAST_LIMIT {
                    println!(
                        "mfnd_producer_pending_released height={} slot={} votes={}",
                        pending.proposal.ctx.height,
                        pending.proposal.ctx.slot,
                        pending.votes.len()
                    );
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    *guard = None;
                }
                return;
            }
        }
        let mut last_skip: Option<(u32, u32)> = None;
        let mut adopted = false;
        for _ in 0..MAX_SLOT_ELIGIBILITY_SCANS {
            let inputs = {
                let chain = match self.chain.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                let mut pool = match self.pool.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                let mut proof_pool = match self.proof_pool.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                match self.block_inputs_for_next(&chain, &mut pool, &mut proof_pool) {
                    Ok(i) => i,
                    Err(e) => {
                        eprintln!("mfnd_producer_slot_abort build_inputs {e}");
                        return;
                    }
                }
            };
            let proposal = {
                let chain = match self.chain.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                let params = self.params(&chain);
                match build_proposal(
                    chain.state(),
                    &self.local.validator,
                    &self.local.secrets,
                    params,
                    inputs,
                ) {
                    Ok(p) => p,
                    Err(ProducerError::NotSlotEligible { height, slot }) => {
                        last_skip = Some((height, slot));
                        continue;
                    }
                    Err(e) => {
                        eprintln!("mfnd_producer_slot_abort build_proposal {e}");
                        return;
                    }
                }
            };
            if let Some((height, from_slot)) = last_skip {
                if proposal.ctx.height == height && proposal.ctx.slot > from_slot {
                    println!(
                        "mfnd_producer_slot_advance height={height} from_slot={from_slot} to_slot={}",
                        proposal.ctx.slot
                    );
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
            }
            println!(
                "mfnd_producer_proposal height={} slot={}",
                proposal.ctx.height, proposal.ctx.slot
            );
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let _ = self.adopt_proposal(proposal);
            adopted = true;
            break;
        }
        if !adopted {
            if let Some((height, slot)) = last_skip {
                println!(
                    "mfnd_producer_slot_skip height={height} slot={slot} scans_exhausted={MAX_SLOT_ELIGIBILITY_SCANS}"
                );
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
        }
    }
}

impl ProductionHandler for ProductionEngine {
    fn on_proposal_v1(&self, proposal_wire: &[u8]) -> String {
        let proposal = match decode_block_proposal(proposal_wire) {
            Ok(p) => p,
            Err(e) => return format!("rejected:decode:{e}"),
        };
        let label = self.adopt_proposal(proposal);
        if !label.starts_with("accepted:") {
            println!("mfnd_producer_adopt {label}");
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
        label
    }

    fn proposal_vote_reply_v1(&self, proposal_wire: &[u8]) -> Option<Vec<u8>> {
        let proposal = decode_block_proposal(proposal_wire).ok()?;
        if proposal.producer_proof.validator_index == self.local.validator.index {
            return None;
        }
        if let Err(e) = self.adopt_pending_for_direct_vote(&proposal) {
            println!("mfnd_producer_vote_reply_reject {e}");
            let _ = std::io::Write::flush(&mut std::io::stdout());
            return None;
        }
        let vote = self.try_vote_locally(&proposal)?;
        let mut frame = Vec::with_capacity(1 + 128);
        frame.push(mfn_net::VOTE_V1_TAG);
        frame.extend_from_slice(&encode_committee_vote(&proposal.header_hash, &vote));
        println!(
            "mfnd_producer_vote_reply height={} voter={}",
            proposal.ctx.height, vote.index
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
        Some(frame)
    }

    fn on_vote_v1(&self, vote_wire: &[u8]) -> String {
        let (header_hash, vote) = match decode_committee_vote(vote_wire) {
            Ok(v) => v,
            Err(e) => return format!("rejected:decode:{e}"),
        };
        match self.ingest_vote(header_hash, vote) {
            Ok(()) => "accepted:vote".into(),
            Err(e) => format!("rejected:vote:{e}"),
        }
    }
}

/// Spawn the slot timer thread; returns immediately.
pub fn spawn_slot_producer_loop(engine: Arc<ProductionEngine>) {
    let slot_ms = engine.local.slot_duration_ms;
    thread::Builder::new()
        .name("mfnd-producer".into())
        .spawn(move || {
            // Wait one slot before the first tick so inbound `--p2p-dial` peers can
            // finish handshake + block-sync (M7.8 auto fan-out smokes, devnet boot).
            thread::sleep(Duration::from_millis(slot_ms));
            loop {
                engine.on_slot_tick();
                thread::sleep(Duration::from_millis(slot_ms));
            }
        })
        .expect("spawn mfnd-producer thread");
}

/// Resolve `--produce` validator keys from env against genesis validators.
pub fn produce_config_from_env(
    validators: &[Validator],
    slot_duration_ms: u64,
) -> Result<ProduceConfig, String> {
    use mfn_runtime::hex_seed32;
    let idx_s = std::env::var("MFND_VALIDATOR_INDEX")
        .map_err(|_| "mfnd serve --produce: set MFND_VALIDATOR_INDEX".to_string())?;
    let index: u32 = idx_s
        .parse()
        .map_err(|_| format!("invalid MFND_VALIDATOR_INDEX `{idx_s}`"))?;
    let vrf_hex = std::env::var("MFND_VRF_SEED_HEX")
        .or_else(|_| std::env::var("MFND_SOLO_VRF_SEED_HEX"))
        .map_err(|_| "set MFND_VRF_SEED_HEX (or MFND_SOLO_VRF_SEED_HEX)".to_string())?;
    let bls_hex = std::env::var("MFND_BLS_SEED_HEX")
        .or_else(|_| std::env::var("MFND_SOLO_BLS_SEED_HEX"))
        .map_err(|_| "set MFND_BLS_SEED_HEX (or MFND_SOLO_BLS_SEED_HEX)".to_string())?;
    let vrf_seed = hex_seed32("MFND_VRF_SEED_HEX", &vrf_hex).map_err(|e| e.to_string())?;
    let bls_seed = hex_seed32("MFND_BLS_SEED_HEX", &bls_hex).map_err(|e| e.to_string())?;
    let vrf =
        mfn_crypto::vrf::vrf_keygen_from_seed(&vrf_seed).map_err(|e| format!("vrf keygen: {e}"))?;
    let bls = mfn_bls::bls_keygen_from_seed(&bls_seed);
    let validator = validators
        .iter()
        .find(|v| v.index == index)
        .ok_or_else(|| format!("no genesis validator with index {index}"))?
        .clone();
    if vrf.pk != validator.vrf_pk || bls.pk != validator.bls_pk {
        return Err("env seeds do not match genesis validator keys".into());
    }
    Ok(ProduceConfig {
        validator,
        secrets: ValidatorSecrets { index, vrf, bls },
        slot_duration_ms,
    })
}
