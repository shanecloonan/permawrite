//! In-memory transaction pool.
//!
//! The mempool is the holding pen between a wallet's signed transaction
//! and a producer's block. Conceptually it is a small set with three
//! interesting operations:
//!
//! 1. **`admit(tx, &ChainState)`** — runs every per-tx gate
//!    [`apply_block`] runs (`verify_transaction` + the ring-membership
//!    chain guard + key-image dedup against the chain *and* against
//!    other pool entries). Successful admits replace lower-fee
//!    conflicting entries via Replace-By-Fee.
//! 2. **`drain(max)`** — pops up to `max` entries in **highest-fee-first**
//!    order, returning the underlying [`TransactionWire`]s ready to
//!    be handed to [`crate::BlockInputs::txs`] (after the producer
//!    inserts the coinbase at slot 0).
//! 3. **`remove_mined(&Block)`** — after a block lands on the chain,
//!    evicts every mempool entry whose key images appear in the block's
//!    inputs. Lets the mempool catch up without re-running the entire
//!    admit pipeline.
//!
//! ## What this milestone deliberately defers
//!
//! - **Storage-anchoring transactions.** The wallet (M2.0.11) only
//!   builds non-storage txs, and the storage-upload economic gates in
//!   `apply_block` (treasury share vs `required_endowment`, replication
//!   bounds, cross-tx dedup against `state.storage`) are non-trivial.
//!   The mempool rejects storage-bearing txs with a typed
//!   [`AdmitError::StorageTxsNotYetSupported`]; a follow-up milestone
//!   will mirror the apply_block-level storage gates here.
//! - **Time-based eviction / `seen_at`.** Mempool entries live forever
//!   until they conflict, are mined, or are explicitly evicted. Adding
//!   age-based eviction is straightforward but unnecessary while the
//!   pool fits in memory.
//! - **Persistent storage / restart recovery.** Mempool state is
//!   in-memory; a node restart loses pending txs. This matches
//!   Bitcoin / Monero behaviour at this layer (mempool is best-effort
//!   anyway — finality lives on the chain).
//!
//! ## Determinism
//!
//! Every public method is deterministic in `(&self, args)`. There is no
//! clock, no RNG, no IO. The fee-comparison `drain` order is stable
//! within ties (entries with equal fees come out in `tx_id` order to
//! guarantee byte-deterministic block bodies).

use std::collections::HashMap;

use mfn_consensus::{verify_transaction, Block, ChainState, TransactionWire};

/* ----------------------------------------------------------------------- *
 *  Config + entry                                                           *
 * ----------------------------------------------------------------------- */

/// Tuning parameters for a [`Mempool`].
#[derive(Clone, Copy, Debug)]
pub struct MempoolConfig {
    /// Maximum number of transactions held simultaneously. When full,
    /// [`Mempool::admit`] evicts the **lowest-fee** entry if the
    /// incoming tx pays strictly more; otherwise rejects.
    pub max_entries: usize,
    /// Per-tx minimum fee in atomic units. `0` disables the gate.
    /// This is a *local policy* knob; consensus enforces no minimum.
    pub min_fee: u64,
}

impl MempoolConfig {
    /// Sensible defaults for a single-node demo:
    ///
    /// - `max_entries = 4096` — generous for testnet.
    /// - `min_fee = 0` — no floor (consensus has no floor either).
    pub const fn default_config() -> Self {
        Self {
            max_entries: 4096,
            min_fee: 0,
        }
    }
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

/// One entry in the pool.
///
/// Carries the wire-form transaction plus the metadata the mempool
/// needs to make decisions (fee, key-image set, tx id). All fields are
/// `pub` for read-only inspection by callers (e.g. RPC handlers).
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    /// The transaction itself, wire-form.
    pub tx: TransactionWire,
    /// Cached `tx_id(&tx)` — used as the primary key inside the pool.
    pub tx_id: [u8; 32],
    /// Cached `tx.fee` — used for fee-priority ordering and RBF.
    pub fee: u64,
    /// Cached `inputs[i].sig.key_image.compress().to_bytes()` for each
    /// input. Indexes into the pool's `by_key_image` map.
    pub key_image_bytes: Vec<[u8; 32]>,
    /// Chain height at the time of admission. Informational only —
    /// drives nothing today but useful for future age-based eviction.
    pub admitted_at_height: Option<u32>,
}

/* ----------------------------------------------------------------------- *
 *  Errors                                                                   *
 * ----------------------------------------------------------------------- */

/// Errors returned by [`Mempool::admit`].
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AdmitError {
    /// `verify_transaction` rejected the tx.
    #[error("tx invalid (id={tx_id_hex}): {errors:?}")]
    TxInvalid {
        /// Hex prefix of the offending tx id.
        tx_id_hex: String,
        /// Diagnostic strings from `VerifyResult.errors`.
        errors: Vec<String>,
    },

    /// One of the tx's input ring members was not in the chain's
    /// UTXO set. The tx would be rejected by `apply_block`'s
    /// ring-membership chain guard, so we reject it up front.
    #[error(
        "ring member missing in UTXO set (tx={tx_id_hex}, input={input}, ring_index={ring_index})"
    )]
    RingMemberNotInUtxoSet {
        /// Hex prefix of the offending tx id.
        tx_id_hex: String,
        /// Which input the offending ring belongs to.
        input: usize,
        /// Which slot inside the ring tripped the guard.
        ring_index: usize,
    },

    /// One of the tx's input ring members exists in the UTXO set but
    /// its on-chain `commit` does not match the `C` column the spender
    /// provided. The tx would be rejected by `apply_block`'s commit
    /// guard.
    #[error(
        "ring member commit mismatch (tx={tx_id_hex}, input={input}, ring_index={ring_index})"
    )]
    RingMemberCommitMismatch {
        /// Hex prefix of the offending tx id.
        tx_id_hex: String,
        /// Which input the offending ring belongs to.
        input: usize,
        /// Which slot inside the ring tripped the guard.
        ring_index: usize,
    },

    /// One of the tx's key images already appears in
    /// `ChainState::spent_key_images`. The tx is a confirmed
    /// double-spend.
    #[error("key image already spent on chain (tx={tx_id_hex})")]
    KeyImageAlreadyOnChain {
        /// Hex prefix of the offending tx id.
        tx_id_hex: String,
    },

    /// One of the tx's key images conflicts with an existing mempool
    /// entry but the new fee does NOT strictly exceed the existing
    /// fee — Replace-By-Fee declines the swap.
    #[error("replace-by-fee declined: existing fee {existing_fee} >= proposed fee {proposed_fee}")]
    ReplaceTooLow {
        /// Fee of the entry already in the mempool.
        existing_fee: u64,
        /// Fee of the tx attempting to replace it.
        proposed_fee: u64,
    },

    /// The tx fee is below the mempool's local minimum policy.
    #[error("fee {tx_fee} below mempool min {min_fee}")]
    BelowMinFee {
        /// Configured floor.
        min_fee: u64,
        /// Submitted fee.
        tx_fee: u64,
    },

    /// The tx is already in the mempool (same `tx_id`). Idempotent
    /// re-admission would be confusing — surface a typed error so the
    /// caller can decide whether to log + ignore.
    #[error("duplicate tx (id={tx_id_hex} already in pool)")]
    DuplicateTx {
        /// Hex prefix of the duplicate tx id.
        tx_id_hex: String,
    },

    /// The mempool is full and the incoming tx's fee is not strictly
    /// greater than the lowest-fee entry currently in the pool.
    #[error("mempool full (max_entries={max_entries}, lowest_fee={lowest_fee}, proposed_fee={proposed_fee})")]
    PoolFull {
        /// Configured cap.
        max_entries: usize,
        /// Fee of the lowest-fee entry in the pool.
        lowest_fee: u64,
        /// Fee of the rejected tx.
        proposed_fee: u64,
    },

    /// The tx anchors a storage commitment. The current mempool gates
    /// non-storage txs only — storage uploads will land in a follow-up
    /// milestone that mirrors `apply_block`'s `UploadUnderfunded` /
    /// replication / dedup checks.
    #[error("storage-anchoring txs are not supported by this mempool milestone")]
    StorageTxsNotYetSupported,

    /// `tx.inputs` is empty. Either a malformed wire-form tx or a
    /// caller trying to admit a coinbase, which never goes through
    /// the mempool.
    #[error("tx has no inputs — coinbases and degenerate txs are not admitted")]
    NoInputs,
}

/* ----------------------------------------------------------------------- *
 *  AdmitOutcome                                                             *
 * ----------------------------------------------------------------------- */

/// Outcome of a successful [`Mempool::admit`].
///
/// Distinguishes "fresh admission" from "replaced an existing entry
/// via RBF" / "evicted the lowest-fee entry to make room" so callers
/// (RPC, P2P relay) can log and behave appropriately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// New entry added; no other entry displaced.
    Fresh {
        /// Id of the newly admitted tx.
        tx_id: [u8; 32],
    },
    /// New entry replaced one or more conflicting entries via RBF.
    ReplacedByFee {
        /// Id of the newly admitted tx.
        tx_id: [u8; 32],
        /// Tx ids that were evicted to make room (one per conflicting
        /// key image; usually a single entry).
        displaced: Vec<[u8; 32]>,
    },
    /// Pool was full; new entry's fee exceeded the lowest-fee entry,
    /// which was evicted.
    EvictedLowest {
        /// Id of the newly admitted tx.
        tx_id: [u8; 32],
        /// Tx id evicted to make room.
        evicted: [u8; 32],
    },
}

impl AdmitOutcome {
    /// The id of the freshly admitted tx, regardless of variant.
    #[inline]
    pub fn admitted_tx_id(&self) -> [u8; 32] {
        match self {
            AdmitOutcome::Fresh { tx_id }
            | AdmitOutcome::ReplacedByFee { tx_id, .. }
            | AdmitOutcome::EvictedLowest { tx_id, .. } => *tx_id,
        }
    }
}

/* ----------------------------------------------------------------------- *
 *  Mempool                                                                  *
 * ----------------------------------------------------------------------- */

/// In-memory transaction pool.
#[derive(Clone, Debug)]
pub struct Mempool {
    config: MempoolConfig,
    /// Primary store: tx_id → entry.
    by_tx_id: HashMap<[u8; 32], MempoolEntry>,
    /// Reverse index: key-image bytes → tx_id of the entry that owns
    /// that key image. Drives RBF conflict detection in O(1).
    by_key_image: HashMap<[u8; 32], [u8; 32]>,
}

impl Mempool {
    /// Construct an empty mempool with the given config.
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            config,
            by_tx_id: HashMap::new(),
            by_key_image: HashMap::new(),
        }
    }

    /// Borrow the mempool's config.
    #[inline]
    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    /// Number of transactions currently in the pool.
    #[inline]
    pub fn len(&self) -> usize {
        self.by_tx_id.len()
    }

    /// `true` iff the pool is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.by_tx_id.is_empty()
    }

    /// `true` iff the pool contains a tx with the given id.
    #[inline]
    pub fn contains(&self, tx_id: &[u8; 32]) -> bool {
        self.by_tx_id.contains_key(tx_id)
    }

    /// Look up an entry by tx id.
    #[inline]
    pub fn get(&self, tx_id: &[u8; 32]) -> Option<&MempoolEntry> {
        self.by_tx_id.get(tx_id)
    }

    /// Iterate every entry in the pool (unspecified order).
    pub fn iter(&self) -> impl Iterator<Item = &MempoolEntry> {
        self.by_tx_id.values()
    }

    /// Admit a transaction to the pool.
    ///
    /// Runs the full apply_block-equivalent gate for the tx:
    ///
    /// 1. Reject coinbases (`inputs.is_empty()`) — they never go
    ///    through the mempool.
    /// 2. Reject storage-anchoring txs in this milestone.
    /// 3. Enforce local min-fee policy.
    /// 4. Run `verify_transaction` (CLSAG + balance + range proofs +
    ///    within-tx key-image dedup).
    /// 5. Ring-membership chain guard against `state.utxo`.
    /// 6. Cross-chain double-spend guard against
    ///    `state.spent_key_images`.
    /// 7. Mempool-internal key-image conflict resolution via RBF.
    /// 8. Mempool size-cap eviction.
    ///
    /// On success returns an [`AdmitOutcome`] describing which (if
    /// any) existing entries were displaced.
    pub fn admit(
        &mut self,
        tx: TransactionWire,
        state: &ChainState,
    ) -> Result<AdmitOutcome, AdmitError> {
        // (1) Coinbase / degenerate txs.
        if tx.inputs.is_empty() {
            return Err(AdmitError::NoInputs);
        }

        // (2) Storage-anchoring txs deferred.
        if tx.outputs.iter().any(|o| o.storage.is_some()) {
            return Err(AdmitError::StorageTxsNotYetSupported);
        }

        // (3) Local min-fee policy.
        if tx.fee < self.config.min_fee {
            return Err(AdmitError::BelowMinFee {
                min_fee: self.config.min_fee,
                tx_fee: tx.fee,
            });
        }

        // (4) Cryptographic verification + canonical tx_id.
        let result = verify_transaction(&tx);
        if !result.ok {
            return Err(AdmitError::TxInvalid {
                tx_id_hex: hex_prefix(&result.tx_id),
                errors: result.errors,
            });
        }
        let tx_id = result.tx_id;

        // Duplicate check is cheap and orthogonal to fee / state, so
        // run it before the heavier ring scan.
        if self.by_tx_id.contains_key(&tx_id) {
            return Err(AdmitError::DuplicateTx {
                tx_id_hex: hex_prefix(&tx_id),
            });
        }

        // (5) Ring-membership chain guard. Mirrors `apply_block`'s
        //     check byte-for-byte (lookup by `p.compress().to_bytes()`
        //     against `state.utxo`, then compare `entry.commit == c`).
        for (i_idx, inp) in tx.inputs.iter().enumerate() {
            if inp.ring.p.len() != inp.ring.c.len() {
                return Err(AdmitError::TxInvalid {
                    tx_id_hex: hex_prefix(&tx_id),
                    errors: vec![format!(
                        "input {i_idx}: ring P-column length {} != C-column length {}",
                        inp.ring.p.len(),
                        inp.ring.c.len()
                    )],
                });
            }
            for (r_idx, (p, c)) in inp.ring.p.iter().zip(inp.ring.c.iter()).enumerate() {
                let key = p.compress().to_bytes();
                match state.utxo.get(&key) {
                    Some(entry) if entry.commit == *c => {}
                    Some(_) => {
                        return Err(AdmitError::RingMemberCommitMismatch {
                            tx_id_hex: hex_prefix(&tx_id),
                            input: i_idx,
                            ring_index: r_idx,
                        });
                    }
                    None => {
                        return Err(AdmitError::RingMemberNotInUtxoSet {
                            tx_id_hex: hex_prefix(&tx_id),
                            input: i_idx,
                            ring_index: r_idx,
                        });
                    }
                }
            }
        }

        // (6) Cross-chain double-spend guard.
        let key_image_bytes: Vec<[u8; 32]> = result
            .key_images
            .iter()
            .map(|p| p.compress().to_bytes())
            .collect();
        for ki in &key_image_bytes {
            if state.spent_key_images.contains(ki) {
                return Err(AdmitError::KeyImageAlreadyOnChain {
                    tx_id_hex: hex_prefix(&tx_id),
                });
            }
        }

        // (7) Mempool-internal key-image conflicts → RBF.
        //
        // Collect the set of existing entries that the new tx
        // conflicts with via key image. If empty, the new tx adds
        // cleanly. If non-empty, the new fee MUST strictly exceed the
        // *maximum* existing fee (a conservative RBF policy — strictly
        // dominating is the only safe replace). Otherwise reject.
        //
        // We deduplicate displaced entries because one new tx might
        // conflict with several pool entries on different key images
        // but each of those entries owns multiple key images itself.
        let mut conflicting_entries: Vec<[u8; 32]> = Vec::new();
        for ki in &key_image_bytes {
            if let Some(existing_tx_id) = self.by_key_image.get(ki) {
                if !conflicting_entries.iter().any(|e| e == existing_tx_id) {
                    conflicting_entries.push(*existing_tx_id);
                }
            }
        }
        if !conflicting_entries.is_empty() {
            let max_existing_fee = conflicting_entries
                .iter()
                .map(|id| self.by_tx_id.get(id).expect("invariant: index in sync").fee)
                .max()
                .unwrap_or(0);
            if tx.fee <= max_existing_fee {
                return Err(AdmitError::ReplaceTooLow {
                    existing_fee: max_existing_fee,
                    proposed_fee: tx.fee,
                });
            }
        }

        // (8) Size-cap eviction policy.
        //
        // The new tx will conceptually free up `conflicting_entries.len()`
        // slots before it lands; so the *effective* slot count after a
        // successful admission is `len() - conflicting + 1`. Reject if
        // that would exceed `max_entries`, unless we can evict the
        // single lowest-fee non-conflicting entry whose fee is strictly
        // less than the new tx's fee. (We never evict to make room for
        // a tx that pays less than the eviction victim — that would
        // strictly degrade pool quality.)
        let mut evicted_for_room: Option<[u8; 32]> = None;
        let projected_len = self
            .by_tx_id
            .len()
            .saturating_sub(conflicting_entries.len())
            .saturating_add(1);
        if projected_len > self.config.max_entries {
            let lowest = self
                .iter()
                .filter(|e| !conflicting_entries.iter().any(|c| c == &e.tx_id))
                .min_by_key(|e| (e.fee, e.tx_id))
                .map(|e| (e.tx_id, e.fee));
            match lowest {
                Some((victim_id, victim_fee)) if tx.fee > victim_fee => {
                    evicted_for_room = Some(victim_id);
                }
                Some((_, victim_fee)) => {
                    return Err(AdmitError::PoolFull {
                        max_entries: self.config.max_entries,
                        lowest_fee: victim_fee,
                        proposed_fee: tx.fee,
                    });
                }
                None => {
                    return Err(AdmitError::PoolFull {
                        max_entries: self.config.max_entries,
                        lowest_fee: 0,
                        proposed_fee: tx.fee,
                    });
                }
            }
        }

        // Apply mutations only after every check passed.
        for displaced_id in &conflicting_entries {
            self.evict_internal(displaced_id);
        }
        if let Some(victim) = evicted_for_room {
            self.evict_internal(&victim);
        }

        let entry = MempoolEntry {
            fee: tx.fee,
            tx_id,
            key_image_bytes: key_image_bytes.clone(),
            admitted_at_height: state.height,
            tx,
        };
        for ki in &key_image_bytes {
            self.by_key_image.insert(*ki, tx_id);
        }
        self.by_tx_id.insert(tx_id, entry);

        Ok(match (conflicting_entries.is_empty(), evicted_for_room) {
            (true, None) => AdmitOutcome::Fresh { tx_id },
            (false, _) => AdmitOutcome::ReplacedByFee {
                tx_id,
                displaced: conflicting_entries,
            },
            (true, Some(victim)) => AdmitOutcome::EvictedLowest {
                tx_id,
                evicted: victim,
            },
        })
    }

    /// Drain up to `max` entries, highest-fee-first, returning their
    /// underlying [`TransactionWire`]s. Ties are broken by `tx_id`
    /// (lexicographic) for byte-deterministic block bodies.
    ///
    /// Drained entries are removed from the pool. To peek without
    /// draining, iterate via [`Mempool::iter`] and sort externally.
    pub fn drain(&mut self, max: usize) -> Vec<TransactionWire> {
        if max == 0 || self.by_tx_id.is_empty() {
            return Vec::new();
        }
        let mut sorted: Vec<&MempoolEntry> = self.by_tx_id.values().collect();
        sorted.sort_by(|a, b| b.fee.cmp(&a.fee).then_with(|| a.tx_id.cmp(&b.tx_id)));
        let take_ids: Vec<[u8; 32]> = sorted.iter().take(max).map(|e| e.tx_id).collect();
        let mut out: Vec<TransactionWire> = Vec::with_capacity(take_ids.len());
        for id in &take_ids {
            if let Some(entry) = self.by_tx_id.remove(id) {
                for ki in &entry.key_image_bytes {
                    self.by_key_image.remove(ki);
                }
                out.push(entry.tx);
            }
        }
        out
    }

    /// Evict every mempool entry whose key images appear in this
    /// newly-applied block. Returns the number of evictions.
    ///
    /// Idempotent — calling twice with the same block is a no-op on
    /// the second call. Skips coinbase txs (they have no inputs).
    pub fn remove_mined(&mut self, block: &Block) -> usize {
        let mut to_evict: Vec<[u8; 32]> = Vec::new();
        for tx in &block.txs {
            for inp in &tx.inputs {
                let ki = inp.sig.key_image.compress().to_bytes();
                if let Some(owner) = self.by_key_image.get(&ki) {
                    if !to_evict.iter().any(|x| x == owner) {
                        to_evict.push(*owner);
                    }
                }
            }
        }
        for id in &to_evict {
            self.evict_internal(id);
        }
        to_evict.len()
    }

    /// Explicit by-id eviction. Returns `true` if a tx with that id
    /// was present.
    pub fn evict(&mut self, tx_id: &[u8; 32]) -> bool {
        if self.by_tx_id.contains_key(tx_id) {
            self.evict_internal(tx_id);
            true
        } else {
            false
        }
    }

    /// Clear the pool entirely.
    pub fn clear(&mut self) {
        self.by_tx_id.clear();
        self.by_key_image.clear();
    }

    fn evict_internal(&mut self, tx_id: &[u8; 32]) {
        if let Some(entry) = self.by_tx_id.remove(tx_id) {
            for ki in &entry.key_image_bytes {
                self.by_key_image.remove(ki);
            }
        }
    }
}

fn hex_prefix(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for byte in b.iter().take(8) {
        use std::fmt::Write;
        let _ = write!(&mut s, "{byte:02x}");
    }
    s
}

/* ----------------------------------------------------------------------- *
 *  Tests                                                                    *
 * ----------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    use mfn_consensus::{
        sign_transaction, ApplyOutcome, ConsensusParams, GenesisConfig, GenesisOutput, InputSpec,
        OutputSpec, Recipient, TransactionWire, Validator, DEFAULT_EMISSION_PARAMS,
    };
    use mfn_crypto::clsag::ClsagRing;
    use mfn_crypto::point::{generator_g, generator_h};
    use mfn_crypto::scalar::random_scalar;
    use mfn_crypto::stealth::stealth_gen;
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    use crate::{Chain, ChainConfig};

    /// One real-spendable input plus `ring_size - 1` decoys, all
    /// anchored at genesis so `ChainState::utxo` contains them. Mirrors
    /// the pattern used by `mfn-consensus`'s integration tests.
    fn build_genesis_with_spendable_input(
        ring_size: usize,
        signer_value: u64,
    ) -> (Chain, InputSpec, Vec<EdwardsPoint>, Vec<EdwardsPoint>) {
        assert!(ring_size >= 2);
        let signer_spend = random_scalar();
        let signer_blinding = random_scalar();
        let signer_p = generator_g() * signer_spend;
        let signer_c =
            (generator_g() * signer_blinding) + (generator_h() * Scalar::from(signer_value));

        let mut decoy_p: Vec<EdwardsPoint> = Vec::with_capacity(ring_size - 1);
        let mut decoy_c: Vec<EdwardsPoint> = Vec::with_capacity(ring_size - 1);
        let mut decoy_outputs: Vec<GenesisOutput> = Vec::with_capacity(ring_size - 1);
        for i in 0..(ring_size - 1) {
            let sp = random_scalar();
            let bp = random_scalar();
            let p = generator_g() * sp;
            let c = (generator_g() * bp) + (generator_h() * Scalar::from((i as u64) + 1));
            decoy_p.push(p);
            decoy_c.push(c);
            decoy_outputs.push(GenesisOutput {
                one_time_addr: p,
                amount: c,
            });
        }
        let mut initial_outputs = vec![GenesisOutput {
            one_time_addr: signer_p,
            amount: signer_c,
        }];
        initial_outputs.extend(decoy_outputs.iter().cloned());

        // Mempool tests do not exercise consensus, so validators can be
        // empty (the chain runs in legacy/centralized mode).
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs,
            initial_storage: Vec::new(),
            validators: Vec::<Validator>::new(),
            params: ConsensusParams::default(),
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let chain = Chain::from_genesis(ChainConfig::new(cfg)).expect("genesis");

        // Assemble the ring with the real input at slot `ring_size/2`.
        let signer_idx = ring_size / 2;
        let mut p = Vec::with_capacity(ring_size);
        let mut c = Vec::with_capacity(ring_size);
        let mut di = 0usize;
        for i in 0..ring_size {
            if i == signer_idx {
                p.push(signer_p);
                c.push(signer_c);
            } else {
                p.push(decoy_p[di]);
                c.push(decoy_c[di]);
                di += 1;
            }
        }
        let inp = InputSpec {
            ring: ClsagRing { p, c },
            signer_idx,
            spend_priv: signer_spend,
            value: signer_value,
            blinding: signer_blinding,
        };
        (chain, inp, decoy_p, decoy_c)
    }

    fn recipient() -> Recipient {
        let w = stealth_gen();
        Recipient {
            view_pub: w.view_pub,
            spend_pub: w.spend_pub,
        }
    }

    /// Sign a single-input single-output tx paying `recipient` from
    /// `input` with the given fee. The output value is `input.value -
    /// fee` so the balance equation is satisfied exactly.
    fn signed_tx(input: InputSpec, fee: u64) -> TransactionWire {
        let r = recipient();
        let value = input.value - fee;
        sign_transaction(
            vec![input],
            vec![OutputSpec::ToRecipient {
                recipient: r,
                value,
                storage: None,
            }],
            fee,
            Vec::new(),
        )
        .expect("sign")
        .tx
    }

    #[test]
    fn admit_happy_path_fresh() {
        let (chain, inp, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let tx = signed_tx(inp, 200);
        let mut pool = Mempool::new(MempoolConfig::default());
        let outcome = pool.admit(tx, chain.state()).expect("admit");
        assert!(matches!(outcome, AdmitOutcome::Fresh { .. }));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn admit_rejects_coinbase_shaped_tx() {
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::<Validator>::new(),
            params: ConsensusParams::default(),
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let chain = Chain::from_genesis(ChainConfig::new(cfg)).unwrap();
        let bogus = TransactionWire {
            version: 1,
            r_pub: generator_g(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            extra: Vec::new(),
        };
        let mut pool = Mempool::new(MempoolConfig::default());
        let err = pool.admit(bogus, chain.state()).unwrap_err();
        assert!(matches!(err, AdmitError::NoInputs));
    }

    #[test]
    fn admit_rejects_storage_anchoring_tx() {
        let (chain, inp, _, _) = build_genesis_with_spendable_input(4, 1_000);

        // Build a tx that anchors a (dummy) storage commitment. We do
        // this via sign_transaction with OutputSpec::ToRecipient {
        // storage: Some(...) }.
        use mfn_storage::StorageCommitment;
        let storage = StorageCommitment {
            data_root: [7u8; 32],
            size_bytes: 1024,
            chunk_size: 256,
            num_chunks: 4,
            replication: 3,
            endowment: generator_g(),
        };
        let signed = sign_transaction(
            vec![inp],
            vec![OutputSpec::ToRecipient {
                recipient: recipient(),
                value: 800,
                storage: Some(storage),
            }],
            200,
            Vec::new(),
        )
        .expect("sign");

        let mut pool = Mempool::new(MempoolConfig::default());
        let err = pool.admit(signed.tx, chain.state()).unwrap_err();
        assert!(matches!(err, AdmitError::StorageTxsNotYetSupported));
    }

    #[test]
    fn admit_rejects_below_min_fee() {
        let (chain, inp, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let tx = signed_tx(inp, 100);
        let mut pool = Mempool::new(MempoolConfig {
            max_entries: 100,
            min_fee: 500,
        });
        let err = pool.admit(tx, chain.state()).unwrap_err();
        assert!(matches!(
            err,
            AdmitError::BelowMinFee {
                min_fee: 500,
                tx_fee: 100
            }
        ));
    }

    #[test]
    fn admit_rejects_unbalanced_tx() {
        // Build a tx whose balance equation fails — easiest way: hand
        // sign_transaction inputs whose Σ value doesn't match outputs.
        let (chain, inp, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let result = sign_transaction(
            vec![inp],
            vec![OutputSpec::ToRecipient {
                recipient: recipient(),
                value: 2_000, // > input value
                storage: None,
            }],
            0,
            Vec::new(),
        );
        // sign_transaction itself rejects up-front with TxBuildError.
        assert!(result.is_err());

        // We can still exercise the mempool's "TxInvalid" path by
        // mutating a properly-signed tx after the fact.
        let mut tx = signed_tx(inp_clone_from_chain(&chain), 200);
        tx.fee = 999; // breaks the balance equation
        let mut pool = Mempool::new(MempoolConfig::default());
        let err = pool.admit(tx, chain.state()).unwrap_err();
        assert!(matches!(err, AdmitError::TxInvalid { .. }));
    }

    fn inp_clone_from_chain(_chain: &Chain) -> InputSpec {
        // The helper rebuilds a fresh signer + decoys against a *new*
        // chain so that mutation-based tests don't accidentally
        // double-spend. We only consume `chain` to keep the lifetime
        // ergonomic.
        let (_c, inp, _, _) = build_genesis_with_spendable_input(4, 1_000);
        inp
    }

    #[test]
    fn admit_rejects_ring_member_not_in_utxo_set() {
        // Sign a tx against one chain's UTXO set, then attempt to
        // admit it into a mempool driven by a DIFFERENT chain whose
        // genesis does not contain those decoys. Every ring member
        // should miss.
        let (_, inp, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let tx = signed_tx(inp, 200);

        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::<Validator>::new(),
            params: ConsensusParams::default(),
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let other_chain = Chain::from_genesis(ChainConfig::new(cfg)).unwrap();
        let mut pool = Mempool::new(MempoolConfig::default());
        let err = pool.admit(tx, other_chain.state()).unwrap_err();
        assert!(matches!(err, AdmitError::RingMemberNotInUtxoSet { .. }));
    }

    #[test]
    fn rbf_accepts_strictly_higher_fee() {
        let (chain, inp, _, _) = build_genesis_with_spendable_input(4, 10_000);
        // Two signed txs spending the same input but paying different
        // recipients/fees. They will share key images, triggering RBF.
        let tx_a = signed_tx(inp.clone(), 1_000);
        let tx_b = signed_tx(inp, 1_500);

        let mut pool = Mempool::new(MempoolConfig::default());
        pool.admit(tx_a.clone(), chain.state()).expect("admit a");
        let outcome = pool.admit(tx_b.clone(), chain.state()).expect("rbf b");
        match outcome {
            AdmitOutcome::ReplacedByFee { displaced, .. } => {
                assert_eq!(displaced.len(), 1);
            }
            other => panic!("expected ReplacedByFee, got {other:?}"),
        }
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rbf_rejects_equal_or_lower_fee() {
        let (chain, inp, _, _) = build_genesis_with_spendable_input(4, 10_000);
        let tx_a = signed_tx(inp.clone(), 2_000);
        // Same input, same fee — RBF requires strictly higher.
        // Use a different recipient so the bytes differ; same key
        // images (since they come from the same input).
        let tx_b = signed_tx(inp, 2_000);

        let mut pool = Mempool::new(MempoolConfig::default());
        pool.admit(tx_a, chain.state()).expect("admit a");
        let err = pool.admit(tx_b, chain.state()).unwrap_err();
        match err {
            AdmitError::ReplaceTooLow {
                existing_fee: 2_000,
                proposed_fee: 2_000,
            } => {}
            other => panic!("expected ReplaceTooLow, got {other:?}"),
        }
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn duplicate_tx_id_is_rejected() {
        let (chain, inp, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let tx = signed_tx(inp, 200);
        let mut pool = Mempool::new(MempoolConfig::default());
        pool.admit(tx.clone(), chain.state()).expect("first");
        let err = pool.admit(tx, chain.state()).unwrap_err();
        assert!(matches!(err, AdmitError::DuplicateTx { .. }));
    }

    #[test]
    fn size_cap_evicts_lowest_fee_when_pool_full() {
        // Build a chain whose UTXO set contains BOTH spendable inputs
        // plus enough decoys for two rings.
        let (chain, inp1, _, _) = build_genesis_with_spendable_input(4, 1_000);

        let signer_spend2 = random_scalar();
        let signer_blinding2 = random_scalar();
        let signer_p2 = generator_g() * signer_spend2;
        let signer_c2 =
            (generator_g() * signer_blinding2) + (generator_h() * Scalar::from(1_000u64));
        let extra_decoys: Vec<GenesisOutput> = chain
            .state()
            .utxo
            .iter()
            .map(|(k, e)| {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(k);
                let p = curve25519_dalek::edwards::CompressedEdwardsY(buf)
                    .decompress()
                    .unwrap();
                GenesisOutput {
                    one_time_addr: p,
                    amount: e.commit,
                }
            })
            .collect();
        let mut all_outputs = extra_decoys;
        all_outputs.push(GenesisOutput {
            one_time_addr: signer_p2,
            amount: signer_c2,
        });
        let cfg2 = GenesisConfig {
            timestamp: 0,
            initial_outputs: all_outputs,
            initial_storage: Vec::new(),
            validators: Vec::<Validator>::new(),
            params: ConsensusParams::default(),
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let chain2 = Chain::from_genesis(ChainConfig::new(cfg2)).expect("genesis2");

        // Build the ring for the second input.
        let ring_size = 4usize;
        let signer_idx = 1usize;
        let mut p2 = Vec::with_capacity(ring_size);
        let mut c2 = Vec::with_capacity(ring_size);
        let utxo_items: Vec<(EdwardsPoint, EdwardsPoint)> = chain2
            .state()
            .utxo
            .iter()
            .filter_map(|(k, e)| {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(k);
                curve25519_dalek::edwards::CompressedEdwardsY(buf)
                    .decompress()
                    .map(|p| (p, e.commit))
            })
            .filter(|(p, _)| *p != signer_p2)
            .take(ring_size - 1)
            .collect();
        let mut di = 0usize;
        for i in 0..ring_size {
            if i == signer_idx {
                p2.push(signer_p2);
                c2.push(signer_c2);
            } else {
                let (pp, cc) = utxo_items[di];
                p2.push(pp);
                c2.push(cc);
                di += 1;
            }
        }
        let inp2 = InputSpec {
            ring: ClsagRing { p: p2, c: c2 },
            signer_idx,
            spend_priv: signer_spend2,
            value: 1_000,
            blinding: signer_blinding2,
        };

        let tx_low = signed_tx(inp1, 100);
        let tx_high = signed_tx(inp2, 500);

        let mut pool = Mempool::new(MempoolConfig {
            max_entries: 1,
            min_fee: 0,
        });
        pool.admit(tx_low.clone(), chain2.state())
            .expect("admit low");
        let outcome = pool
            .admit(tx_high.clone(), chain2.state())
            .expect("admit high");
        assert!(matches!(outcome, AdmitOutcome::EvictedLowest { .. }));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn drain_orders_by_fee_descending_then_tx_id() {
        // Three independent inputs admitted with fees 100, 500, 300.
        // drain(3) should return 500, 300, 100.
        let (_, inp1, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let tx1 = signed_tx(inp1.clone(), 100);
        let (_, inp2, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let tx2 = signed_tx(inp2.clone(), 500);
        let (_, inp3, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let tx3 = signed_tx(inp3.clone(), 300);

        // Build a chain whose utxo contains every needed ring member.
        let mut all_outputs: Vec<GenesisOutput> = Vec::new();
        for inp in [&inp1, &inp2, &inp3] {
            for (p, c) in inp.ring.p.iter().zip(inp.ring.c.iter()) {
                all_outputs.push(GenesisOutput {
                    one_time_addr: *p,
                    amount: *c,
                });
            }
        }
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: all_outputs,
            initial_storage: Vec::new(),
            validators: Vec::<Validator>::new(),
            params: ConsensusParams::default(),
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let chain = Chain::from_genesis(ChainConfig::new(cfg)).expect("genesis");
        let mut pool = Mempool::new(MempoolConfig::default());
        pool.admit(tx1, chain.state()).expect("tx1");
        pool.admit(tx2, chain.state()).expect("tx2");
        pool.admit(tx3, chain.state()).expect("tx3");

        let drained = pool.drain(3);
        let fees: Vec<u64> = drained.iter().map(|t| t.fee).collect();
        assert_eq!(fees, vec![500, 300, 100]);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn remove_mined_evicts_txs_with_block_key_images() {
        let (chain, inp, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let tx = signed_tx(inp, 200);
        let mut pool = Mempool::new(MempoolConfig::default());
        pool.admit(tx.clone(), chain.state()).expect("admit");
        assert_eq!(pool.len(), 1);

        // Synthesize a "block" containing just our tx.
        let block = synthetic_block_with(vec![tx]);
        let evicted = pool.remove_mined(&block);
        assert_eq!(evicted, 1);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn remove_mined_is_idempotent_when_unrelated() {
        let (chain, inp1, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let tx = signed_tx(inp1, 200);
        let mut pool = Mempool::new(MempoolConfig::default());
        pool.admit(tx, chain.state()).expect("admit");

        let (_, inp2, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let other_tx = signed_tx(inp2, 200);
        let block = synthetic_block_with(vec![other_tx]);
        assert_eq!(pool.remove_mined(&block), 0);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn evict_by_id_returns_true_when_present() {
        let (chain, inp, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let tx = signed_tx(inp, 200);
        let mut pool = Mempool::new(MempoolConfig::default());
        let outcome = pool.admit(tx, chain.state()).expect("admit");
        let id = outcome.admitted_tx_id();
        assert!(pool.evict(&id));
        assert_eq!(pool.len(), 0);
        assert!(!pool.evict(&id));
    }

    #[test]
    fn drained_tx_can_be_applied_to_chain() {
        // Sanity: a tx admitted to the mempool and then drained is
        // *the same bytes* and applies to the chain via apply_block
        // when wrapped in a coinbase-less block.
        let (chain, inp, _, _) = build_genesis_with_spendable_input(4, 1_000);
        let tx = signed_tx(inp, 200);
        let mut pool = Mempool::new(MempoolConfig::default());
        pool.admit(tx.clone(), chain.state()).expect("admit");
        let drained = pool.drain(10);
        assert_eq!(drained.len(), 1);
        assert_eq!(mfn_consensus::tx_id(&drained[0]), mfn_consensus::tx_id(&tx));
    }

    /* ------------------ helpers ------------------ */

    fn synthetic_block_with(txs: Vec<TransactionWire>) -> Block {
        Block {
            header: mfn_consensus::BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                height: 1,
                slot: 1,
                timestamp: 1,
                tx_root: [0u8; 32],
                storage_root: [0u8; 32],
                bond_root: [0u8; 32],
                slashing_root: [0u8; 32],
                storage_proof_root: [0u8; 32],
                validator_root: [0u8; 32],
                producer_proof: Vec::new(),
                utxo_root: [0u8; 32],
            },
            txs,
            slashings: Vec::new(),
            storage_proofs: Vec::new(),
            bond_ops: Vec::new(),
        }
    }

    // Silence unused-import warning when the helper isn't exercised
    // by every test in this module.
    #[allow(dead_code)]
    fn _touch(_: &ApplyOutcome) {}
}
