//! Top-level [`Wallet`] state container.
//!
//! Wraps [`crate::keys::WalletKeys`] with a local UTXO database and
//! provides the high-level lifecycle:
//!
//! 1. `Wallet::from_seed(seed)` / `Wallet::from_keys(keys)` — bootstrap.
//! 2. `wallet.ingest_block(&block)` — advance scan state by one block.
//! 3. `wallet.balance()` / `wallet.owned()` — read state.
//! 4. `wallet.build_transfer(...)` — produce a signed *privacy transfer*
//!    tx (Monero-style RingCT to one or more recipients).
//! 5. `wallet.build_storage_upload(...)` — produce a signed *permanence
//!    upload* tx (RingCT + a StorageCommitment anchored in the tx's
//!    first output, with a fee whose treasury slice covers the
//!    chain-required upfront endowment).
//!
//! All mutation goes through `ingest_block` and `build_transfer`, so an
//! `&Wallet` reference is safe to share across threads for read-only
//! work (`Sync` via inherited `Sync` of `WalletKeys` + `HashMap`).

use std::collections::{HashMap, HashSet};

use curve25519_dalek::scalar::Scalar;
use mfn_consensus::{build_mfex_extra, Block, ChainState, Recipient, SignedTransaction};
use mfn_crypto::authorship::{build_signed_claim, AuthorshipClaim, MAX_CLAIM_MESSAGE_LEN};
use mfn_storage::{build_storage_commitment, required_endowment, storage_commitment_hash};

use crate::claiming::ClaimingIdentity;
use crate::decoy::build_decoy_pool;
use crate::error::WalletError;
use crate::keys::{wallet_from_seed, WalletKeys};
use crate::owned::{owned_balance, OwnedOutput};
use crate::scan::{scan_block, BlockScan};
use crate::spend::{build_transfer, TransferPlan, TransferRecipient};
use crate::stored::StoredOwnedOutput;
use crate::upload::{build_storage_upload, StorageUploadPlan, UploadArtifacts};

/// A confidential wallet — keys plus owned-output bookkeeping.
///
/// The wallet does not own a chain; it consumes [`Block`]s through
/// [`Wallet::ingest_block`]. This makes it usable in three deployment
/// shapes:
///
/// - **Co-located full node** — caller drives the wallet from inside
///   `mfn_node::Chain`, feeding each newly-applied block.
/// - **Light client** — caller drives the wallet from
///   [`mfn_light::LightChain`], which verifies block bodies before
///   handing them off.
/// - **Standalone backup** — caller streams archived blocks from disk
///   to recover state on a fresh device.
#[derive(Debug)]
pub struct Wallet {
    keys: WalletKeys,
    /// `one_time_addr.compress().to_bytes() → OwnedOutput`. Storing by
    /// the same key the chain uses lets coin-selection look up against
    /// `ChainState::utxo` in O(1).
    owned: HashMap<[u8; 32], OwnedOutput>,
    /// Reverse index `key_image.compress().to_bytes() → utxo_key` so
    /// spend detection during scan is O(1).
    by_key_image: HashMap<[u8; 32], [u8; 32]>,
    /// Last block height applied via `ingest_block`. `None` before any
    /// blocks have been ingested.
    scan_height: Option<u32>,
}

impl Wallet {
    /// Construct from arbitrary [`WalletKeys`].
    pub fn from_keys(keys: WalletKeys) -> Self {
        Self {
            keys,
            owned: HashMap::new(),
            by_key_image: HashMap::new(),
            scan_height: None,
        }
    }

    /// Construct from a 32-byte seed (deterministic — see
    /// [`wallet_from_seed`]).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::from_keys(wallet_from_seed(seed))
    }

    /// Borrow the wallet's keys.
    #[inline]
    pub fn keys(&self) -> &WalletKeys {
        &self.keys
    }

    /// The wallet's public-facing recipient: its view-pub + spend-pub
    /// packaged as a [`Recipient`] ready to plug into
    /// [`crate::TransferRecipient`] or any other API that takes a
    /// recipient.
    ///
    /// This is the canonical "send to self" handle and is heavily used
    /// in storage uploads, where the anchor output and change output
    /// typically both go back to the uploader.
    #[inline]
    pub fn recipient(&self) -> Recipient {
        Recipient {
            view_pub: self.keys.view_pub(),
            spend_pub: self.keys.spend_pub(),
        }
    }

    /// Snapshot of the wallet's spendable balance (sum of unspent
    /// owned outputs).
    #[inline]
    pub fn balance(&self) -> u64 {
        owned_balance(self.owned.values())
    }

    /// Authorship key firewall (F5:P10): refuse to sign a claim whose
    /// public claiming key equals this wallet's view or spend pubkey.
    ///
    /// [`ClaimingIdentity`] can only be built through the canonical
    /// domain-separated derivation, so this cannot trigger for
    /// seed-derived identities; it is defense in depth against any
    /// future constructor (or foreign frontend) that lets financial key
    /// material cross into the authorship domain, where it would become
    /// a stable public label linking the wallet's on-chain activity.
    fn assert_claim_key_firewall(&self, identity: &ClaimingIdentity) -> Result<(), WalletError> {
        let claim_pub = identity.claim_pubkey();
        if claim_pub == self.keys.view_pub() || claim_pub == self.keys.spend_pub() {
            return Err(WalletError::ClaimKeyReusesWalletKey);
        }
        Ok(())
    }

    /// Number of unspent owned outputs.
    #[inline]
    pub fn owned_count(&self) -> usize {
        self.owned.len()
    }

    /// Iterate every unspent owned output. Order is unspecified —
    /// callers that need a stable order should collect + sort.
    pub fn owned(&self) -> impl Iterator<Item = &OwnedOutput> {
        self.owned.values()
    }

    /// Height of the most-recently ingested block.
    #[inline]
    pub fn scan_height(&self) -> Option<u32> {
        self.scan_height
    }

    /// Replace the in-memory UTXO set from a persisted snapshot (**M3.6**).
    ///
    /// `scan_height` must match the height through which these outputs were
    /// accumulated. Callers resume chain sync at `scan_height + 1`.
    pub fn load_owned_snapshot(
        &mut self,
        stored: &[StoredOwnedOutput],
        scan_height: u32,
    ) -> Result<(), WalletError> {
        self.owned.clear();
        self.by_key_image.clear();
        for entry in stored {
            let o = entry.to_owned()?;
            let utxo_key = o.utxo_key();
            let ki_bytes = o.key_image.compress().to_bytes();
            self.by_key_image.insert(ki_bytes, utxo_key);
            self.owned.insert(utxo_key, o);
        }
        self.scan_height = Some(scan_height);
        Ok(())
    }

    /// Export every unspent owned output for persistence.
    pub fn export_owned_snapshot(&self) -> Vec<StoredOwnedOutput> {
        self.owned
            .values()
            .map(StoredOwnedOutput::from_owned)
            .collect()
    }

    /// Set of precomputed key-image bytes for currently owned outputs.
    /// Used by the scanner to detect cross-device spends.
    pub fn key_image_bytes(&self) -> HashSet<[u8; 32]> {
        self.by_key_image.keys().copied().collect()
    }

    /// Ingest one block: scan for incoming payments + remove any owned
    /// outputs that this block consumes.
    ///
    /// The function is **idempotent within a single scan** but does
    /// NOT check for replay (blocks at earlier heights or duplicated
    /// blocks). The caller is expected to feed blocks in monotonic
    /// height order — typically from a verified chain follower such as
    /// `mfn_node::Chain` or `mfn_light::LightChain`.
    pub fn ingest_block(&mut self, block: &Block) -> BlockScan {
        let key_images = self.key_image_bytes();
        let scan = scan_block(block, &self.keys, &key_images);

        for (_tx_id, tx_scan) in scan.txs.iter() {
            for ki in tx_scan.spent_key_images.iter() {
                if let Some(utxo_key) = self.by_key_image.remove(ki) {
                    self.owned.remove(&utxo_key);
                }
            }
            for o in tx_scan.recovered.iter() {
                let utxo_key = o.utxo_key();
                let ki_bytes = o.key_image.compress().to_bytes();
                self.by_key_image.insert(ki_bytes, utxo_key);
                self.owned.insert(utxo_key, o.clone());
            }
        }

        self.scan_height = Some(block.header.height);
        scan
    }

    /// Mark an owned output as spent locally without consulting the
    /// chain. Used after this wallet successfully broadcasts a
    /// transfer; once the tx mines, [`ingest_block`] will idempotently
    /// re-do the eviction.
    ///
    /// Returns `true` if the output was present and removed.
    pub fn mark_spent_by_utxo_key(&mut self, key: &[u8; 32]) -> bool {
        if let Some(o) = self.owned.remove(key) {
            self.by_key_image.remove(&o.key_image.compress().to_bytes());
            true
        } else {
            false
        }
    }

    /// Age-band coin-selection (`PRIVACY_HARDENING.md` §B2): pick a small
    /// set of owned outputs whose values sum to `>= target`, preferring
    /// outputs from the **same age band**.
    ///
    /// Returns the selected outputs and the actual sum. Returns
    /// [`WalletError::InsufficientFunds`] if the wallet does not hold
    /// enough.
    ///
    /// ## Why age bands
    ///
    /// The gamma decoy distribution makes each *ring* age-plausible, but
    /// input *sets* leak too: a tx that consumes one very old and one very
    /// fresh output advertises a wallet consolidating across its history,
    /// and largest-first selection deterministically drains the biggest
    /// UTXOs, correlating spends over time. Grouping candidates into
    /// exponential age bands (`floor(log2(age + 1))` blocks since
    /// confirmation) and spending within one band makes the consumed set
    /// look like any other same-era spend.
    ///
    /// ## Algorithm (deterministic — no RNG in the signature)
    ///
    /// 1. Group spendable outputs by age band relative to `scan_height`.
    /// 2. If any single band can cover `target`, use the band that does so
    ///    with the fewest inputs (largest-first within the band; ties
    ///    prefer the **newest** band — recent outputs are the most
    ///    plausible spends).
    /// 3. Otherwise spill across bands newest-first, draining each band
    ///    before touching the next (band-cohesive consolidation).
    ///
    /// Within a band, equal-value ties break on the UTXO key bytes so the
    /// choice is stable regardless of `HashMap` iteration order.
    pub fn select_inputs(&self, target: u64) -> Result<(Vec<&OwnedOutput>, u64), WalletError> {
        let total = self.balance();
        if total < target {
            return Err(WalletError::InsufficientFunds {
                requested: target,
                available: total,
            });
        }
        let current = self.scan_height.unwrap_or(0);

        // Group by age band; sort each band largest-first (key-byte tie-break).
        let mut bands: std::collections::BTreeMap<u32, Vec<&OwnedOutput>> =
            std::collections::BTreeMap::new();
        for o in self.owned.values() {
            let age = u64::from(current.saturating_sub(o.height));
            let band = 63 - (age + 1).leading_zeros();
            bands.entry(band).or_default().push(o);
        }
        for members in bands.values_mut() {
            members.sort_by_key(|c| (std::cmp::Reverse(c.value), c.utxo_key()));
        }

        // Prefer a single band: fewest inputs, ties to the newest band.
        // (BTreeMap iterates ascending band index == newest era first.)
        let mut best: Option<(usize, Vec<&OwnedOutput>, u64)> = None;
        for members in bands.values() {
            let mut sum: u64 = 0;
            let mut chosen: Vec<&OwnedOutput> = Vec::new();
            for c in members {
                if sum >= target {
                    break;
                }
                sum = sum.saturating_add(c.value);
                chosen.push(c);
            }
            let improves = match &best {
                None => true,
                Some((n, _, _)) => chosen.len() < *n,
            };
            if sum >= target && improves {
                best = Some((chosen.len(), chosen, sum));
            }
        }
        if let Some((_, chosen, sum)) = best {
            return Ok((chosen, sum));
        }

        // No single band suffices: drain bands newest-first.
        let mut chosen: Vec<&OwnedOutput> = Vec::new();
        let mut sum: u64 = 0;
        'outer: for members in bands.values() {
            for c in members {
                if sum >= target {
                    break 'outer;
                }
                sum = sum.saturating_add(c.value);
                chosen.push(c);
            }
        }
        Ok((chosen, sum))
    }

    /// Coin selection for reference transfers/uploads: [`Self::select_inputs`]
    /// plus the [`crate::WALLET_MIN_TX_INPUTS`] privacy floor when possible.
    fn select_inputs_for_tx(&self, target: u64) -> Result<(Vec<&OwnedOutput>, u64), WalletError> {
        let (mut chosen, mut sum) = self.select_inputs(target)?;
        self.pad_inputs_to_floor(&mut chosen, &mut sum);
        Ok((chosen, sum))
    }

    /// Pad `chosen` up to [`crate::WALLET_MIN_TX_INPUTS`] with additional
    /// real UTXOs from this wallet when available.
    ///
    /// Prefers a pad UTXO from the same age band as the newest input already
    /// chosen; ties break on smallest value (minimises unnecessary change).
    fn pad_inputs_to_floor<'a>(&'a self, chosen: &mut Vec<&'a OwnedOutput>, sum: &mut u64) {
        if chosen.len() >= crate::WALLET_MIN_TX_INPUTS {
            return;
        }
        let current = self.scan_height.unwrap_or(0);
        let ref_band = chosen
            .iter()
            .map(|o| age_band(current, o.height))
            .min()
            .unwrap_or(0);

        let mut chosen_keys: HashSet<[u8; 32]> = chosen.iter().map(|o| o.utxo_key()).collect();

        while chosen.len() < crate::WALLET_MIN_TX_INPUTS {
            let mut candidates: Vec<&OwnedOutput> = self
                .owned
                .values()
                .filter(|o| !chosen_keys.contains(&o.utxo_key()))
                .collect();
            if candidates.is_empty() {
                break;
            }
            candidates.sort_by_key(|o| {
                let band = age_band(current, o.height);
                let band_penalty = u8::from(band != ref_band);
                (band_penalty, o.value, o.utxo_key())
            });
            let pad = candidates[0];
            chosen_keys.insert(pad.utxo_key());
            chosen.push(pad);
            *sum = sum.saturating_add(pad.value);
        }
    }

    /// High-level transfer: pick inputs greedily, build a decoy pool
    /// from `chain_state`, and produce a signed transfer tx with one
    /// implicit change output back to the wallet.
    ///
    /// If `Σ inputs > Σ recipients + fee`, the difference is paid back
    /// to this wallet as an additional output (the "change"). This is
    /// the standard wallet behaviour and is needed for `sign_transaction`
    /// to balance (it requires `Σ inputs == Σ outputs + fee` exactly).
    ///
    /// # Errors
    ///
    /// See [`WalletError`].
    pub fn build_transfer<R>(
        &mut self,
        recipients: &[TransferRecipient],
        fee: u64,
        ring_size: usize,
        chain_state: &ChainState,
        extra: &[u8],
        rng: &mut R,
    ) -> Result<SignedTransaction, WalletError>
    where
        R: FnMut() -> f64,
    {
        if recipients.is_empty() {
            return Err(WalletError::NoRecipients);
        }
        let target = recipients
            .iter()
            .map(|r| r.value)
            .fold(0u64, u64::saturating_add)
            .saturating_add(fee);

        let (chosen_refs, input_sum) = self.select_inputs_for_tx(target)?;
        let chosen_keys: Vec<[u8; 32]> = chosen_refs.iter().map(|o| o.utxo_key()).collect();

        // Clone the OwnedOutputs so we don't hold a borrow into
        // `self.owned` across the mutable mark-spent step below.
        let chosen_owned: Vec<OwnedOutput> = chosen_refs.iter().map(|o| (*o).clone()).collect();

        let change_value = input_sum.saturating_sub(target);
        let mut all_recipients: Vec<TransferRecipient> = recipients.to_vec();
        if change_value > 0 {
            all_recipients.push(TransferRecipient {
                recipient: mfn_consensus::Recipient {
                    view_pub: self.keys.view_pub(),
                    spend_pub: self.keys.spend_pub(),
                },
                value: change_value,
            });
        }

        // Privacy floor: never broadcast a single-output transfer. A lone
        // output reveals a no-change sweep / exact-amount payment, which
        // fingerprints the spend and shrinks its plausible-recipient set.
        // Pad to `WALLET_MIN_TX_OUTPUTS` with zero-value outputs back to
        // this wallet; amounts are Pedersen-committed, so the padding is
        // indistinguishable on-chain and does not disturb the balance
        // equation (it contributes value 0).
        while all_recipients.len() < crate::WALLET_MIN_TX_OUTPUTS {
            all_recipients.push(TransferRecipient {
                recipient: mfn_consensus::Recipient {
                    view_pub: self.keys.view_pub(),
                    spend_pub: self.keys.spend_pub(),
                },
                value: 0,
            });
        }

        let chosen_refs2: Vec<&OwnedOutput> = chosen_owned.iter().collect();

        let pool = build_decoy_pool(chain_state, chosen_keys.iter().copied());

        let current_height = u64::from(self.scan_height.unwrap_or(0));

        let plan = TransferPlan {
            inputs: &chosen_refs2,
            recipients: &all_recipients,
            fee,
            extra,
            ring_size,
            decoy_pool: &pool,
            current_height,
            rng,
        };
        let signed = build_transfer(plan)?;

        // Mark each consumed input spent locally so a follow-up call
        // doesn't double-spend before the tx lands on-chain.
        for k in chosen_keys {
            self.mark_spent_by_utxo_key(&k);
        }

        Ok(signed)
    }

    /// Publish an on-chain **authorship claim** binding `message` (≤
    /// [`MAX_CLAIM_MESSAGE_LEN`] bytes) to `data_root` under
    /// `identity`'s public claiming key. The claim is packed into
    /// `tx.extra` as MFEX-wrapped MFCL; the spend is a minimal
    /// self-payment (`1` unit) plus `fee`, with the remainder returned as
    /// change — the same RingCT path as [`Self::build_transfer`].
    #[allow(clippy::too_many_arguments)]
    pub fn publish_claim_tx<R>(
        &mut self,
        identity: &ClaimingIdentity,
        data_root: [u8; 32],
        commit_hash: [u8; 32],
        message: &[u8],
        fee: u64,
        ring_size: usize,
        chain_state: &ChainState,
        rng: &mut R,
    ) -> Result<SignedTransaction, WalletError>
    where
        R: FnMut() -> f64,
    {
        if message.len() > MAX_CLAIM_MESSAGE_LEN {
            return Err(WalletError::ClaimMessageTooLong {
                max: MAX_CLAIM_MESSAGE_LEN,
                got: message.len(),
            });
        }
        self.assert_claim_key_firewall(identity)?;
        let claim = build_signed_claim(data_root, commit_hash, message, identity.keypair())?;
        let extra = build_mfex_extra(std::slice::from_ref(&claim))?;
        let recipients = vec![TransferRecipient {
            recipient: self.recipient(),
            value: 1,
        }];
        self.build_transfer(&recipients, fee, ring_size, chain_state, &extra, rng)
    }

    /// High-level **storage upload**: pick inputs greedily, build the
    /// decoy pool from `chain_state`, construct a `StorageCommitment`
    /// over `data` at `replication`, anchor it in the tx's first output
    /// (paying `anchor_value` to `anchor_recipient`), and return back
    /// any leftover MFN as a change output to **this wallet**.
    ///
    /// The returned [`UploadArtifacts`] holds the signed tx (submit it
    /// to a mempool) **and** the [`mfn_storage::BuiltCommitment`]
    /// (Merkle tree + endowment blinding) that the uploader must retain
    /// to serve SPoRA chunks later.
    ///
    /// ## Common patterns
    ///
    /// **Anchor to self** — most uploads. Pass
    /// `anchor_recipient = self.recipient()`:
    ///
    /// ```ignore
    /// let art = wallet.build_storage_upload(
    ///     data,
    ///     /* replication */ 3,
    ///     /* fee */ wallet.upload_min_fee(data.len() as u64, 3, chain_state)?,
    ///     /* anchor_recipient */ wallet.recipient(),
    ///     /* anchor_value */ 1_000,         // tiny self-payment
    ///     /* chunk_size */ None,
    ///     /* ring_size */ 4,
    ///     chain_state,
    ///     b"my-upload",
    ///     &mut rng,
    /// )?;
    /// mempool.admit(art.signed.tx, chain_state)?;
    /// ```
    ///
    /// **Anchor to a third party** — the recipient gets the anchor
    /// UTXO and the storage commitment is on the chain. The
    /// **uploader** still keeps the Merkle tree (`art.built.tree`) so
    /// they can answer SPoRA chunk audits on behalf of the data.
    ///
    /// ## Fee
    ///
    /// `fee` must satisfy the chain's UploadUnderfunded gate
    /// (`fee · fee_to_treasury_bps / 10000 ≥ required_endowment(...)`).
    /// Use [`crate::estimate_minimum_fee_for_upload`] or
    /// [`Wallet::upload_min_fee`] to compute the floor.
    ///
    /// # Errors
    ///
    /// See [`WalletError`]. Every storage-specific reason the mempool
    /// would reject is hoisted to a typed wallet error so the caller
    /// learns the failure mode *before* signing.
    #[allow(clippy::too_many_arguments)]
    pub fn build_storage_upload<R>(
        &mut self,
        data: &[u8],
        replication: u8,
        fee: u64,
        anchor_recipient: Recipient,
        anchor_value: u64,
        chunk_size: Option<usize>,
        ring_size: usize,
        chain_state: &ChainState,
        extra: &[u8],
        rng: &mut R,
    ) -> Result<UploadArtifacts, WalletError>
    where
        R: FnMut() -> f64,
    {
        self.build_storage_upload_with_claims_and_extra(
            data,
            replication,
            fee,
            anchor_recipient,
            anchor_value,
            chunk_size,
            ring_size,
            chain_state,
            &[],
            extra,
            None,
            rng,
        )
    }

    /// Same as [`Self::build_storage_upload`] but attaches a Schnorr-signed
    /// MFCL authorship claim bound to this upload's `data_root` and
    /// `storage_commitment_hash` in `tx.extra` (MFEX envelope).
    ///
    /// Cannot be combined with a custom `extra` memo — the wire `extra`
    /// field is exactly the claim envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn build_storage_upload_with_authorship<R>(
        &mut self,
        data: &[u8],
        replication: u8,
        fee: u64,
        anchor_recipient: Recipient,
        anchor_value: u64,
        chunk_size: Option<usize>,
        ring_size: usize,
        chain_state: &ChainState,
        message: &[u8],
        identity: &ClaimingIdentity,
        rng: &mut R,
    ) -> Result<UploadArtifacts, WalletError>
    where
        R: FnMut() -> f64,
    {
        if message.len() > MAX_CLAIM_MESSAGE_LEN {
            return Err(WalletError::ClaimMessageTooLong {
                max: MAX_CLAIM_MESSAGE_LEN,
                got: message.len(),
            });
        }
        self.assert_claim_key_firewall(identity)?;

        let padded = mfn_storage::pad_to_storage_size_bucket(data);
        let burden = required_endowment(
            padded.len() as u64,
            replication,
            &chain_state.endowment_params,
        )?;
        if burden > u128::from(u64::MAX) {
            return Err(WalletError::UploadEndowmentExceedsU64 { burden });
        }
        let endowment_amount = burden as u64;
        let preview =
            build_storage_commitment(&padded, endowment_amount, chunk_size, replication, None)?;
        let commit_hash = storage_commitment_hash(&preview.commit);
        let claim = build_signed_claim(
            preview.commit.data_root,
            commit_hash,
            message,
            identity.keypair(),
        )?;
        let claims = [claim];
        self.build_storage_upload_with_claims_and_extra(
            data,
            replication,
            fee,
            anchor_recipient,
            anchor_value,
            chunk_size,
            ring_size,
            chain_state,
            &claims,
            &[],
            Some(preview.blinding),
            rng,
        )
    }

    /// [`Self::build_storage_upload`] with explicit pre-signed MFCL claims.
    ///
    /// `extra` must be empty when `authorship_claims` is non-empty.
    #[allow(clippy::too_many_arguments)]
    pub fn build_storage_upload_with_claims<R>(
        &mut self,
        data: &[u8],
        replication: u8,
        fee: u64,
        anchor_recipient: Recipient,
        anchor_value: u64,
        chunk_size: Option<usize>,
        ring_size: usize,
        chain_state: &ChainState,
        authorship_claims: &[AuthorshipClaim],
        rng: &mut R,
    ) -> Result<UploadArtifacts, WalletError>
    where
        R: FnMut() -> f64,
    {
        self.build_storage_upload_with_claims_and_extra(
            data,
            replication,
            fee,
            anchor_recipient,
            anchor_value,
            chunk_size,
            ring_size,
            chain_state,
            authorship_claims,
            &[],
            None,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_storage_upload_with_claims_and_extra<R>(
        &mut self,
        data: &[u8],
        replication: u8,
        fee: u64,
        anchor_recipient: Recipient,
        anchor_value: u64,
        chunk_size: Option<usize>,
        ring_size: usize,
        chain_state: &ChainState,
        authorship_claims: &[AuthorshipClaim],
        extra: &[u8],
        endowment_blinding: Option<Scalar>,
        rng: &mut R,
    ) -> Result<UploadArtifacts, WalletError>
    where
        R: FnMut() -> f64,
    {
        if !authorship_claims.is_empty() && !extra.is_empty() {
            return Err(WalletError::UploadExtraConflictsWithAuthorshipClaims);
        }
        if !authorship_claims.is_empty() {
            let _ = build_mfex_extra(authorship_claims)?;
        }
        let target = anchor_value.saturating_add(fee);
        let (chosen_refs, input_sum) = self.select_inputs_for_tx(target)?;
        let chosen_keys: Vec<[u8; 32]> = chosen_refs.iter().map(|o| o.utxo_key()).collect();
        let chosen_owned: Vec<OwnedOutput> = chosen_refs.iter().map(|o| (*o).clone()).collect();

        let change_value = input_sum.saturating_sub(target);
        let mut change_recipients: Vec<TransferRecipient> = Vec::new();
        if change_value > 0 {
            change_recipients.push(TransferRecipient {
                recipient: self.recipient(),
                value: change_value,
            });
        }

        let chosen_refs2: Vec<&OwnedOutput> = chosen_owned.iter().collect();
        let pool = build_decoy_pool(chain_state, chosen_keys.iter().copied());
        let current_height = u64::from(self.scan_height.unwrap_or(0));

        let plan = StorageUploadPlan {
            inputs: &chosen_refs2,
            anchor: TransferRecipient {
                recipient: anchor_recipient,
                value: anchor_value,
            },
            data,
            replication,
            chunk_size,
            endowment_blinding,
            endowment_params: &chain_state.endowment_params,
            fee_to_treasury_bps: chain_state.emission_params.fee_to_treasury_bps,
            change_recipients: &change_recipients,
            fee,
            extra,
            authorship_claims,
            ring_size,
            decoy_pool: &pool,
            current_height,
            rng,
        };
        let art = build_storage_upload(plan)?;

        for k in chosen_keys {
            self.mark_spent_by_utxo_key(&k);
        }

        Ok(art)
    }

    /// Compute the minimum fee that satisfies the chain's storage
    /// underfunded gate for an upload of `data_len` bytes at the given
    /// `replication`, reading both the endowment params and the
    /// fee-to-treasury bps from `chain_state`.
    ///
    /// Convenience wrapper around
    /// [`crate::estimate_minimum_fee_for_upload`]; equivalent to
    /// `estimate_minimum_fee_for_upload(data_len, replication,
    /// &chain_state.endowment_params,
    /// chain_state.emission_params.fee_to_treasury_bps)`.
    pub fn upload_min_fee(
        &self,
        data_len: u64,
        replication: u8,
        chain_state: &ChainState,
    ) -> Result<u64, WalletError> {
        crate::estimate_minimum_fee_for_upload(
            data_len,
            replication,
            &chain_state.endowment_params,
            chain_state.emission_params.fee_to_treasury_bps,
        )
    }

    /// Same as [`Wallet::build_storage_upload`] but pins the Pedersen
    /// blinding scalar used for `StorageCommitment.endowment`.
    ///
    /// Intended for tests and for callers that want **deterministic
    /// uploads** (re-running with the same inputs produces the same
    /// `StorageCommitment` bytewise, which is occasionally useful for
    /// reproducible audit trails). Production callers should prefer
    /// [`Wallet::build_storage_upload`], which draws a fresh scalar.
    #[allow(clippy::too_many_arguments)]
    pub fn build_storage_upload_with_blinding<R>(
        &mut self,
        data: &[u8],
        replication: u8,
        fee: u64,
        anchor_recipient: Recipient,
        anchor_value: u64,
        chunk_size: Option<usize>,
        ring_size: usize,
        endowment_blinding: Scalar,
        chain_state: &ChainState,
        extra: &[u8],
        rng: &mut R,
    ) -> Result<UploadArtifacts, WalletError>
    where
        R: FnMut() -> f64,
    {
        let target = anchor_value.saturating_add(fee);
        let (chosen_refs, input_sum) = self.select_inputs_for_tx(target)?;
        let chosen_keys: Vec<[u8; 32]> = chosen_refs.iter().map(|o| o.utxo_key()).collect();
        let chosen_owned: Vec<OwnedOutput> = chosen_refs.iter().map(|o| (*o).clone()).collect();

        let change_value = input_sum.saturating_sub(target);
        let mut change_recipients: Vec<TransferRecipient> = Vec::new();
        if change_value > 0 {
            change_recipients.push(TransferRecipient {
                recipient: self.recipient(),
                value: change_value,
            });
        }

        let chosen_refs2: Vec<&OwnedOutput> = chosen_owned.iter().collect();
        let pool = build_decoy_pool(chain_state, chosen_keys.iter().copied());
        let current_height = u64::from(self.scan_height.unwrap_or(0));

        let plan = StorageUploadPlan {
            inputs: &chosen_refs2,
            anchor: TransferRecipient {
                recipient: anchor_recipient,
                value: anchor_value,
            },
            data,
            replication,
            chunk_size,
            endowment_blinding: Some(endowment_blinding),
            endowment_params: &chain_state.endowment_params,
            fee_to_treasury_bps: chain_state.emission_params.fee_to_treasury_bps,
            change_recipients: &change_recipients,
            fee,
            extra,
            authorship_claims: &[],
            ring_size,
            decoy_pool: &pool,
            current_height,
            rng,
        };
        let art = build_storage_upload(plan)?;

        for k in chosen_keys {
            self.mark_spent_by_utxo_key(&k);
        }

        Ok(art)
    }
}

impl Clone for Wallet {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            owned: self.owned.clone(),
            by_key_image: self.by_key_image.clone(),
            scan_height: self.scan_height,
        }
    }
}

/// Exponential age band index for coin-selection cohesion (§B2).
fn age_band(current: u32, output_height: u32) -> u32 {
    let age = u64::from(current.saturating_sub(output_height));
    63 - (age + 1).leading_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use mfn_consensus::{
        build_coinbase, sign_transaction, BlockHeader, InputSpec, OutputSpec, PayoutAddress,
        TransactionWire,
    };
    use mfn_crypto::clsag::ClsagRing;
    use mfn_crypto::point::{generator_g, generator_h};
    use mfn_crypto::scalar::random_scalar;
    use mfn_crypto::stealth::stealth_gen;

    fn fake_input(value: u64, ring_size: usize) -> InputSpec {
        let signer_idx = ring_size / 2;
        let mut p = Vec::with_capacity(ring_size);
        let mut c = Vec::with_capacity(ring_size);
        let signer_spend = random_scalar();
        let signer_blinding = random_scalar();
        p.push(generator_g() * signer_spend);
        c.push((generator_g() * signer_blinding) + (generator_h() * Scalar::from(value)));
        for i in 1..ring_size {
            let s = random_scalar();
            let cs = (generator_g() * random_scalar()) + (generator_h() * Scalar::from(i as u64));
            p.push(generator_g() * s);
            c.push(cs);
        }
        p.swap(0, signer_idx);
        c.swap(0, signer_idx);
        InputSpec {
            ring: ClsagRing { p, c },
            signer_idx,
            spend_priv: signer_spend,
            value,
            blinding: signer_blinding,
        }
    }

    fn zero_header(height: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            height,
            slot: height,
            timestamp: 0,
            tx_root: [0u8; 32],
            storage_root: [0u8; 32],
            bond_root: [0u8; 32],
            slashing_root: [0u8; 32],
            storage_proof_root: [0u8; 32],
            validator_root: [0u8; 32],
            claims_root: [0u8; 32],
            producer_proof: Vec::new(),
            utxo_root: [0u8; 32],
        }
    }

    fn mk_block(height: u32, txs: Vec<TransactionWire>) -> Block {
        Block {
            header: zero_header(height),
            txs,
            slashings: Vec::new(),
            storage_proofs: Vec::new(),
            bond_ops: Vec::new(),
        }
    }

    #[test]
    fn claim_key_firewall_rejects_wallet_spend_key_reuse() {
        // F5:P10 — an identity wrapping the wallet's own financial keys
        // must be refused at signing time, even though the public
        // constructor cannot produce one.
        use mfn_crypto::schnorr::SchnorrKeypair;
        let wallet = Wallet::from_seed(&[11u8; 32]);
        let spend_kp = SchnorrKeypair {
            priv_key: wallet.keys().inner().spend_priv,
            pub_key: wallet.keys().spend_pub(),
        };
        let reused = ClaimingIdentity::from_keypair_for_tests(spend_kp);
        assert!(matches!(
            wallet.assert_claim_key_firewall(&reused),
            Err(WalletError::ClaimKeyReusesWalletKey)
        ));
        let view_kp = SchnorrKeypair {
            priv_key: wallet.keys().view_priv(),
            pub_key: wallet.keys().view_pub(),
        };
        let reused_view = ClaimingIdentity::from_keypair_for_tests(view_kp);
        assert!(matches!(
            wallet.assert_claim_key_firewall(&reused_view),
            Err(WalletError::ClaimKeyReusesWalletKey)
        ));
    }

    #[test]
    fn claim_key_firewall_accepts_seed_derived_identity() {
        // Sharing the wallet's backup seed is the supported flow: the
        // domain-separated derivation guarantees a disjoint keypair.
        let wallet = Wallet::from_seed(&[12u8; 32]);
        let identity = ClaimingIdentity::from_seed(&[12u8; 32]);
        assert!(wallet.assert_claim_key_firewall(&identity).is_ok());
    }

    #[test]
    fn ingest_block_credits_coinbase() {
        let mut wallet = Wallet::from_seed(&[1u8; 32]);
        let payout = PayoutAddress {
            view_pub: wallet.keys().view_pub(),
            spend_pub: wallet.keys().spend_pub(),
        };
        let cb = build_coinbase(1, 50_000_000, &payout).expect("cb");
        let block = mk_block(1, vec![cb]);
        let scan = wallet.ingest_block(&block);

        assert_eq!(scan.gross_received, 50_000_000);
        assert_eq!(wallet.balance(), 50_000_000);
        assert_eq!(wallet.owned_count(), 1);
        assert_eq!(wallet.scan_height(), Some(1));
    }

    #[test]
    fn ingest_block_idempotent_for_unrelated_blocks() {
        let mut wallet = Wallet::from_seed(&[2u8; 32]);
        let other = stealth_gen();
        let payout = PayoutAddress {
            view_pub: other.view_pub,
            spend_pub: other.spend_pub,
        };
        let cb = build_coinbase(1, 1, &payout).expect("cb");
        let block = mk_block(1, vec![cb]);
        wallet.ingest_block(&block);
        assert_eq!(wallet.balance(), 0);
        assert_eq!(wallet.scan_height(), Some(1));
    }

    #[test]
    fn ingest_two_blocks_accumulates() {
        let mut wallet = Wallet::from_seed(&[3u8; 32]);
        let payout = PayoutAddress {
            view_pub: wallet.keys().view_pub(),
            spend_pub: wallet.keys().spend_pub(),
        };
        let cb1 = build_coinbase(1, 100, &payout).expect("cb1");
        let cb2 = build_coinbase(2, 200, &payout).expect("cb2");
        wallet.ingest_block(&mk_block(1, vec![cb1]));
        wallet.ingest_block(&mk_block(2, vec![cb2]));
        assert_eq!(wallet.balance(), 300);
        assert_eq!(wallet.owned_count(), 2);
        assert_eq!(wallet.scan_height(), Some(2));
    }

    #[test]
    fn select_inputs_covers_with_single_output_when_possible() {
        let mut wallet = Wallet::from_seed(&[4u8; 32]);
        let payout = PayoutAddress {
            view_pub: wallet.keys().view_pub(),
            spend_pub: wallet.keys().spend_pub(),
        };
        wallet.ingest_block(&mk_block(1, vec![build_coinbase(1, 100, &payout).unwrap()]));
        wallet.ingest_block(&mk_block(
            2,
            vec![build_coinbase(2, 1_000, &payout).unwrap()],
        ));
        wallet.ingest_block(&mk_block(3, vec![build_coinbase(3, 10, &payout).unwrap()]));

        let (chosen, sum) = wallet.select_inputs(500).expect("select");
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].value, 1_000);
        assert_eq!(sum, 1_000);
    }

    #[test]
    fn select_inputs_can_combine_multiple_outputs() {
        let mut wallet = Wallet::from_seed(&[5u8; 32]);
        let payout = PayoutAddress {
            view_pub: wallet.keys().view_pub(),
            spend_pub: wallet.keys().spend_pub(),
        };
        wallet.ingest_block(&mk_block(1, vec![build_coinbase(1, 100, &payout).unwrap()]));
        wallet.ingest_block(&mk_block(2, vec![build_coinbase(2, 200, &payout).unwrap()]));
        wallet.ingest_block(&mk_block(3, vec![build_coinbase(3, 300, &payout).unwrap()]));

        let (chosen, sum) = wallet.select_inputs(450).expect("select");
        assert!(sum >= 450);
        // No single age band covers 450, so the selector spills
        // newest-first: 300 (band 0) + 200 (band 1) = 500.
        assert_eq!(chosen.len(), 2);
        assert_eq!(sum, 500);
    }

    /// §B2 age-band cohesion: when both an old era and a recent era can
    /// cover the target with the same input count, the selector must
    /// spend entirely within the **newest** band instead of mixing eras
    /// (largest-first would pick the old 600 + the new 550).
    #[test]
    fn select_inputs_prefers_one_age_band_over_mixing_eras() {
        let mut wallet = Wallet::from_seed(&[8u8; 32]);
        let payout = PayoutAddress {
            view_pub: wallet.keys().view_pub(),
            spend_pub: wallet.keys().spend_pub(),
        };
        // Old era (height 10/11 — ages ~90 at scan height 100).
        wallet.ingest_block(&mk_block(
            10,
            vec![build_coinbase(10, 600, &payout).unwrap()],
        ));
        wallet.ingest_block(&mk_block(
            11,
            vec![build_coinbase(11, 500, &payout).unwrap()],
        ));
        // Recent era (heights 98/99 — ages 1..2).
        wallet.ingest_block(&mk_block(
            98,
            vec![build_coinbase(98, 500, &payout).unwrap()],
        ));
        wallet.ingest_block(&mk_block(
            99,
            vec![build_coinbase(99, 550, &payout).unwrap()],
        ));
        // Advance the scan height without adding outputs.
        wallet.ingest_block(&mk_block(100, Vec::new()));

        let (chosen, sum) = wallet.select_inputs(1_000).expect("select");
        assert_eq!(chosen.len(), 2, "both bands cover with two inputs");
        assert_eq!(sum, 1_050, "newest band pays 550 + 500");
        assert!(
            chosen.iter().all(|o| o.height >= 98),
            "selection must stay within the newest age band; got heights {:?}",
            chosen.iter().map(|o| o.height).collect::<Vec<_>>()
        );
    }

    /// §B2: a band that covers the target with fewer inputs beats a
    /// newer band that needs more.
    #[test]
    fn select_inputs_prefers_fewest_inputs_across_bands() {
        let mut wallet = Wallet::from_seed(&[9u8; 32]);
        let payout = PayoutAddress {
            view_pub: wallet.keys().view_pub(),
            spend_pub: wallet.keys().spend_pub(),
        };
        // Old era: one big output covers the target alone.
        wallet.ingest_block(&mk_block(
            10,
            vec![build_coinbase(10, 2_000, &payout).unwrap()],
        ));
        // Recent era: covering the target needs two outputs.
        wallet.ingest_block(&mk_block(
            98,
            vec![build_coinbase(98, 600, &payout).unwrap()],
        ));
        wallet.ingest_block(&mk_block(
            99,
            vec![build_coinbase(99, 600, &payout).unwrap()],
        ));
        wallet.ingest_block(&mk_block(100, Vec::new()));

        let (chosen, sum) = wallet.select_inputs(1_000).expect("select");
        assert_eq!(chosen.len(), 1, "single old output beats two new ones");
        assert_eq!(sum, 2_000);
        assert_eq!(chosen[0].height, 10);
    }

    #[test]
    fn select_inputs_reports_insufficient_funds() {
        let mut wallet = Wallet::from_seed(&[6u8; 32]);
        let payout = PayoutAddress {
            view_pub: wallet.keys().view_pub(),
            spend_pub: wallet.keys().spend_pub(),
        };
        wallet.ingest_block(&mk_block(1, vec![build_coinbase(1, 100, &payout).unwrap()]));
        let err = wallet.select_inputs(1_000).unwrap_err();
        match err {
            WalletError::InsufficientFunds {
                requested,
                available,
            } => {
                assert_eq!(requested, 1_000);
                assert_eq!(available, 100);
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }

    #[test]
    fn select_inputs_for_tx_pads_to_two_when_second_utxo_exists() {
        let mut wallet = Wallet::from_seed(&[10u8; 32]);
        let payout = PayoutAddress {
            view_pub: wallet.keys().view_pub(),
            spend_pub: wallet.keys().spend_pub(),
        };
        wallet.ingest_block(&mk_block(
            1,
            vec![build_coinbase(1, 1_000, &payout).unwrap()],
        ));
        wallet.ingest_block(&mk_block(2, vec![build_coinbase(2, 10, &payout).unwrap()]));

        let (chosen, sum) = wallet.select_inputs_for_tx(500).expect("select");
        assert_eq!(
            chosen.len(),
            2,
            "must pad to two inputs when a second UTXO exists"
        );
        assert_eq!(sum, 1_010);
    }

    #[test]
    fn select_inputs_for_tx_single_utxo_cannot_pad() {
        let mut wallet = Wallet::from_seed(&[11u8; 32]);
        let payout = PayoutAddress {
            view_pub: wallet.keys().view_pub(),
            spend_pub: wallet.keys().spend_pub(),
        };
        wallet.ingest_block(&mk_block(
            1,
            vec![build_coinbase(1, 1_000, &payout).unwrap()],
        ));

        let (chosen, sum) = wallet.select_inputs_for_tx(500).expect("select");
        assert_eq!(chosen.len(), 1, "only one UTXO — floor cannot be reached");
        assert_eq!(sum, 1_000);
    }

    #[test]
    fn mark_spent_removes_owned_output_and_its_key_image() {
        let mut wallet = Wallet::from_seed(&[7u8; 32]);
        let payout = PayoutAddress {
            view_pub: wallet.keys().view_pub(),
            spend_pub: wallet.keys().spend_pub(),
        };
        wallet.ingest_block(&mk_block(1, vec![build_coinbase(1, 100, &payout).unwrap()]));
        let key = wallet.owned().next().map(|o| o.utxo_key()).unwrap();
        assert!(wallet.mark_spent_by_utxo_key(&key));
        assert_eq!(wallet.balance(), 0);
        assert!(wallet.key_image_bytes().is_empty());
        // Idempotent on second call:
        assert!(!wallet.mark_spent_by_utxo_key(&key));
    }

    #[test]
    fn ingest_detects_external_spend_of_owned_utxo() {
        // Recipient B's key images are NOT exposed to A, so the
        // canonical cross-device path is:
        //   - A scans a block paying it → adds an OwnedOutput
        //   - Another instance of A spends that output on another
        //     device → tx.inputs[0].sig.key_image equals A's
        //     precomputed key image → A's scanner reports it spent.
        //
        // We simulate this by signing a real tx whose `key_image`
        // we *plant* into the wallet's local store. Then we feed
        // the block containing that tx and expect the planted
        // entry to be evicted.
        let mut wallet = Wallet::from_seed(&[8u8; 32]);
        let target = stealth_gen();
        let r_target = mfn_consensus::Recipient {
            view_pub: target.view_pub,
            spend_pub: target.spend_pub,
        };
        let signed = sign_transaction(
            vec![fake_input(1_000_000, 4)],
            vec![OutputSpec::ToRecipient {
                recipient: r_target,
                value: 999_000,
                storage: None,
            }],
            1_000,
            Vec::new(),
        )
        .expect("sign");

        // Plant a fake owned output keyed by the real input's
        // one_time_addr, with the *real* key image from the tx so
        // ingest_block can match it.
        let real_ki = signed.tx.inputs[0].sig.key_image;
        let real_one_time = signed.tx.inputs[0].ring.p[signed.tx.inputs[0].sig.s.len() / 2];
        let owned = OwnedOutput {
            one_time_addr: real_one_time,
            commit: generator_g(),
            value: 42,
            blinding: Scalar::ONE,
            one_time_spend: Scalar::ONE,
            key_image: real_ki,
            tx_id: [0u8; 32],
            output_idx: 0,
            height: 0,
        };
        wallet.owned.insert(owned.utxo_key(), owned.clone());
        wallet
            .by_key_image
            .insert(real_ki.compress().to_bytes(), owned.utxo_key());

        assert_eq!(wallet.balance(), 42);
        wallet.ingest_block(&mk_block(2, vec![signed.tx]));
        assert_eq!(
            wallet.balance(),
            0,
            "owned UTXO whose key image appears on-chain must be marked spent"
        );
    }
}
