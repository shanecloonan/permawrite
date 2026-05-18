//! Slot-driven multi-validator block production (**M2.3.23**).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use mfn_bls::CommitteeVote;
use mfn_consensus::{
    build_coinbase, emission_at_height, encode_block, verify_producer_proof, ConsensusCheck,
    ConsensusParams, PayoutAddress, Validator, ValidatorSecrets,
};
use mfn_net::production::ProductionHandler;
use mfn_net::TipSnapshot;
use mfn_runtime::{
    build_proposal, decode_block_proposal, decode_committee_vote, encode_block_proposal,
    encode_committee_vote, seal_proposal, verify_committee_vote_sig, vote_on_proposal,
    BlockInputs, BlockProposal, Chain, Mempool, ProducerError,
};
use mfn_store::ChainPersistence;

use crate::p2p_fanout::P2pPeerSet;

const MFND_MEMPOOL_DRAIN_MAX: usize = 256;
const DEFAULT_SLOT_DURATION_MS: u64 = 1000;

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
}

/// Shared production state for P2P + slot loop.
pub struct ProductionEngine {
    chain: Arc<Mutex<Chain>>,
    pool: Arc<Mutex<Mempool>>,
    store: Arc<dyn ChainPersistence + Send + Sync>,
    tip_cell: TipSnapshot,
    genesis_id: [u8; 32],
    genesis_timestamp: u64,
    local: ProduceConfig,
    peers: Arc<P2pPeerSet>,
    pending: Mutex<Option<PendingProposal>>,
}

impl ProductionEngine {
    /// Wire production to a running `mfnd serve` instance.
    pub fn new(
        chain: Arc<Mutex<Chain>>,
        pool: Arc<Mutex<Mempool>>,
        store: Arc<dyn ChainPersistence + Send + Sync>,
        tip_cell: TipSnapshot,
        genesis_id: [u8; 32],
        genesis_timestamp: u64,
        local: ProduceConfig,
        peers: Arc<P2pPeerSet>,
    ) -> Arc<Self> {
        Arc::new(Self {
            chain,
            pool,
            store,
            tip_cell,
            genesis_id,
            genesis_timestamp,
            local,
            peers,
            pending: Mutex::new(None),
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

    fn producer_fee_share(fee_sum: u128, fee_to_treasury_bps: u16) -> u64 {
        let treasury = fee_sum * u128::from(fee_to_treasury_bps) / 10_000;
        let producer = fee_sum.saturating_sub(treasury);
        u64::try_from(producer).unwrap_or(u64::MAX)
    }

    fn block_inputs_for_next(&self, chain: &Chain, pool: &mut Mempool) -> Result<BlockInputs, String> {
        let tip = chain
            .tip_height()
            .ok_or_else(|| "missing tip height".to_string())?;
        let height = tip
            .checked_add(1)
            .ok_or_else(|| "tip height overflow".to_string())?;
        let slot = height;
        let timestamp = self.genesis_timestamp.saturating_add(u64::from(height));
        let emission_params = chain.state().emission_params;
        let drained = pool.drain(MFND_MEMPOOL_DRAIN_MAX);
        let mut fee_sum: u128 = 0;
        for t in &drained {
            fee_sum = fee_sum.saturating_add(u128::from(t.fee));
        }
        let producer_extra =
            Self::producer_fee_share(fee_sum, emission_params.fee_to_treasury_bps);
        let emission = emission_at_height(u64::from(height), &emission_params);
        let coinbase_amount = emission.saturating_add(producer_extra);
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
            storage_proofs: Vec::new(),
        })
    }

    fn verify_proposal(&self, proposal: &BlockProposal, chain: &Chain) -> Result<(), String> {
        let expected_height = chain
            .tip_height()
            .map(|h| h.saturating_add(1))
            .unwrap_or(0);
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
        chain
            .apply(&block)
            .map_err(|e| format!("apply: {e}"))?;
        if let Ok(mut pool) = self.pool.lock() {
            let _ = pool.remove_mined(&block);
        }
        self.store
            .append_block(&block)
            .map_err(|e| format!("store: {e}"))?;
        self.refresh_tip_cell(&chain);
        let wire = encode_block(&block);
        drop(chain);
        self.peers.fanout_block(&wire, None);
        println!("mfnd_producer_sealed height={height} votes={vote_count}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
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
        {
            let mut guard = match self.pending.lock() {
                Ok(g) => g,
                Err(_) => return "rejected:pending_mutex".into(),
            };
            *guard = Some(PendingProposal {
                proposal: proposal.clone(),
                votes: Vec::new(),
                indices: BTreeSet::new(),
            });
        }
        let wire = encode_block_proposal(&proposal);
        self.peers.fanout_proposal(&wire, None);
        if let Some(vote) = self.try_vote_locally(&proposal) {
            let _ = self.ingest_vote(proposal.header_hash, vote.clone());
            let vote_wire = encode_committee_vote(&proposal.header_hash, &vote);
            self.peers.fanout_vote(&vote_wire, None);
        }
        format!("accepted:height={}", proposal.ctx.height)
    }

    /// One slot tick: try to propose when locally eligible.
    pub fn on_slot_tick(&self) {
        let inputs = {
            let chain = match self.chain.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let mut pool = match self.pool.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            match self.block_inputs_for_next(&chain, &mut pool) {
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
                Err(ProducerError::NotSlotEligible { .. }) => return,
                Err(e) => {
                    eprintln!("mfnd_producer_slot_abort build_proposal {e}");
                    return;
                }
            }
        };
        println!(
            "mfnd_producer_proposal height={} slot={}",
            proposal.ctx.height, proposal.ctx.slot
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let _ = self.adopt_proposal(proposal);
    }
}

impl ProductionHandler for ProductionEngine {
    fn on_proposal_v1(&self, proposal_wire: &[u8]) -> String {
        let proposal = match decode_block_proposal(proposal_wire) {
            Ok(p) => p,
            Err(e) => return format!("rejected:decode:{e}"),
        };
        self.adopt_proposal(proposal)
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
            loop {
                thread::sleep(Duration::from_millis(slot_ms));
                engine.on_slot_tick();
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
    let vrf_seed =
        hex_seed32("MFND_VRF_SEED_HEX", &vrf_hex).map_err(|e| e.to_string())?;
    let bls_seed =
        hex_seed32("MFND_BLS_SEED_HEX", &bls_hex).map_err(|e| e.to_string())?;
    let vrf = mfn_crypto::vrf::vrf_keygen_from_seed(&vrf_seed)
        .map_err(|e| format!("vrf keygen: {e}"))?;
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
        secrets: ValidatorSecrets {
            index,
            vrf,
            bls,
        },
        slot_duration_ms,
    })
}
